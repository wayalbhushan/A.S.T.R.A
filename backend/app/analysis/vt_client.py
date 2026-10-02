"""
ASTRA VirusTotal v3 API Client
Integrates static antivirus detection analysis and dynamic sandbox execution logs.
"""

from datetime import datetime, timezone
import os
import time
import uuid
import requests
import structlog

from app.extensions import redis_client

logger = structlog.get_logger()

VT_API_KEY = os.environ.get("VT_API_KEY", "")
BASE_URL = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": VT_API_KEY, "Accept": "application/json"}

VT_REQUESTS_PER_MINUTE = int(os.environ.get("VT_REQUESTS_PER_MINUTE", 4))
VT_MAX_WAIT_SECONDS = int(os.environ.get("VT_MAX_WAIT_SECONDS", 20))
VT_WINDOW_SECONDS = 60
VT_REDIS_KEY = "vt:request_log"

if not VT_API_KEY:
    logger.warning("VT_API_KEY environment variable is not defined. VirusTotal calls will fail authentication.")


def acquire_vt_slot() -> bool:
    """Acquires a rate limit slot using Redis sliding-window log.
    
    Returns True if request can proceed, False if rate limited.
    Fails open (returns True) on Redis errors.
    """
    try:
        for _ in range(2):
            now = time.time()
            redis_client.zremrangebyscore(VT_REDIS_KEY, 0, now - VT_WINDOW_SECONDS)
            count = redis_client.zcard(VT_REDIS_KEY)
            if count < VT_REQUESTS_PER_MINUTE:
                redis_client.zadd(VT_REDIS_KEY, {uuid.uuid4().hex: now})
                redis_client.expire(VT_REDIS_KEY, VT_WINDOW_SECONDS + 5)
                return True
            else:
                entries = redis_client.zrange(VT_REDIS_KEY, 0, 0, withscores=True)
                if not entries:
                    redis_client.zadd(VT_REDIS_KEY, {uuid.uuid4().hex: now})
                    redis_client.expire(VT_REDIS_KEY, VT_WINDOW_SECONDS + 5)
                    return True
                oldest = float(entries[0][1])
                wait = oldest + VT_WINDOW_SECONDS - now + 0.5
                if wait > VT_MAX_WAIT_SECONDS:
                    logger.warning("vt_rate_limit_skip", wait_seconds=round(wait, 2))
                    return False
                else:
                    logger.info("vt_rate_limit_wait", wait_seconds=round(wait, 2))
                    if wait > 0:
                        time.sleep(wait)
        return False
    except Exception as e:
        logger.warning("Redis operation failed in acquire_vt_slot, failing open", error=str(e))
        return True


def parse_date(timestamp) -> str:
    """Parses a UNIX timestamp float/int into a UTC ISO 8601 string representation."""
    if not timestamp:
        return None
    try:
        return datetime.fromtimestamp(int(timestamp), timezone.utc).isoformat()
    except Exception as e:
        logger.warning("Failed parsing date timestamp", timestamp=timestamp, error=str(e))
        return None


def get_file_report(file_hash: str) -> dict:
    """Retrieves antivirus detection reports from VirusTotal for a file hash.
    
    Args:
        file_hash: Target file SHA-256 hash.
        
    Returns:
        dict containing antivirus counts, detection ratio, and engine verdicts.
    """
    url = f"{BASE_URL}/files/{file_hash}"
    
    fallback = {
        "found": False,
        "detection_ratio": "0/0",
        "malicious_count": 0,
        "suspicious_count": 0,
        "harmless_count": 0,
        "undetected_count": 0,
        "engine_verdicts": [],
        "first_submission": None,
        "last_analysis_date": None,
    }

    if not acquire_vt_slot():
        return {**fallback, "rate_limited": True}

    try:
        response = requests.get(url, headers=HEADERS, timeout=15)
        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            results = attributes.get("last_analysis_results", {})
            
            # Filter positive engines
            engine_verdicts = []
            for engine, verdict in results.items():
                if verdict.get("category") == "malicious":
                    engine_verdicts.append({
                        "engine": engine,
                        "result": verdict.get("result", "malicious")
                    })
            
            malicious = stats.get("malicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            suspicious = stats.get("suspicious", 0)
            total = malicious + harmless + undetected + suspicious
            
            detection_ratio = f"{malicious}/{total}" if total > 0 else "0/0"
            first_sub = parse_date(attributes.get("first_submission_date"))
            last_anal = parse_date(attributes.get("last_analysis_date"))
            
            return {
                "found": True,
                "detection_ratio": detection_ratio,
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "harmless_count": harmless,
                "undetected_count": undetected,
                "engine_verdicts": engine_verdicts,
                "first_submission": first_sub,
                "last_analysis_date": last_anal,
            }
        elif response.status_code == 404:
            return fallback
        elif response.status_code == 429:
            logger.warning("vt_quota_exceeded")
            return {**fallback, "rate_limited": True}
        else:
            logger.error("VirusTotal API returned error code", status=response.status_code, response=response.text)
            return {**fallback, "error": f"API error status: {response.status_code}"}
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
        logger.warning("VirusTotal network error", error=str(e))
        return {**fallback, "vt_unavailable": True}
    except Exception as e:
        logger.exception("Failed querying file report from VirusTotal", error=str(e))
        return {**fallback, "error": str(e)}


def get_sandbox_report(file_hash: str) -> dict:
    """Aggregates multi-sandbox execution behavior reports from VirusTotal files behaviours.
    
    Args:
        file_hash: Target file SHA-256 hash.
        
    Returns:
        dict containing aggregated sandbox behaviors, files written, network events, 
        and severity scores.
    """
    url = f"{BASE_URL}/files/{file_hash}/behaviours"
    
    empty_result = {
        "sandbox_count": 0,
        "sandbox_names": [],
        "files_written": [],
        "files_deleted": [],
        "permissions_requested": [],
        "processes_created": [],
        "tls_fingerprints": [],
        "mitre_attacks": [],
        "threats": [],
        "severity_score": 0,
        "has_network_activity": False,
        "has_file_activity": False
    }

    if not acquire_vt_slot():
        return {**empty_result, "rate_limited": True}

    try:
        response = requests.get(url, headers=HEADERS, timeout=15)
        if response.status_code == 200:
            data = response.json()
            sandbox_reports = data.get("data", [])
            
            if not sandbox_reports:
                return empty_result
            
            files_written = set()
            files_deleted = set()
            permissions_requested = set()
            processes_created = set()
            tls_fingerprints = []
            mitre_attacks = {}
            threats = []
            sandbox_names = []
            
            for report in sandbox_reports:
                name = report.get("sandbox_name", "unknown")
                sandbox_names.append(name)
                
                # File System Events
                for f in report.get("files_written", []):
                    files_written.add(f)
                for f in report.get("files_deleted", []):
                    files_deleted.add(f)
                for p in report.get("permissions_requested", []):
                    permissions_requested.add(p)
                for proc in report.get("processes_created", []):
                    processes_created.add(proc)
                    
                # JA3 TLS Signatures
                for ja3 in report.get("ja3_fingerprints", []):
                    if isinstance(ja3, str):
                        tls_fingerprints.append({"ja3": ja3})
                    elif isinstance(ja3, dict) and "ja3" in ja3:
                        tls_fingerprints.append({"ja3": ja3["ja3"]})
                        
                # MITRE Techniques
                for tech in report.get("mitre_attack_techniques", []):
                    tech_id = tech.get("id")
                    if tech_id:
                        severity = tech.get("signature_severity", "IMPACT_SEVERITY_INFO")
                        mitre_attacks[tech_id] = {
                            "id": tech_id,
                            "description": tech.get("description", ""),
                            "severity": severity
                        }
                        
                # Threat Alert Matches
                for match in report.get("signature_matches", []):
                    threat_name = match.get("name")
                    if threat_name:
                        threats.append({
                            "engine": name,
                            "result": threat_name
                        })
                        
            # Compute severity score
            severity_map = {
                "IMPACT_SEVERITY_CRITICAL": 3,
                "IMPACT_SEVERITY_HIGH": 2,
                "IMPACT_SEVERITY_MEDIUM": 1,
                "IMPACT_SEVERITY_INFO": 0
            }
            severity_score = sum(severity_map.get(m.get("severity"), 0) for m in mitre_attacks.values())
            
            # Check activity flags
            has_network = bool(tls_fingerprints or processes_created)
            has_file = bool(files_written)
            
            return {
                "sandbox_count": len(sandbox_reports),
                "sandbox_names": list(set(sandbox_names)),
                "files_written": list(files_written),
                "files_deleted": list(files_deleted),
                "permissions_requested": list(permissions_requested),
                "processes_created": list(processes_created),
                "tls_fingerprints": tls_fingerprints,
                "mitre_attacks": list(mitre_attacks.values()),
                "threats": threats,
                "severity_score": severity_score,
                "has_network_activity": has_network,
                "has_file_activity": has_file
            }
        elif response.status_code == 404:
            return empty_result
        elif response.status_code == 429:
            logger.warning("vt_quota_exceeded")
            return {**empty_result, "rate_limited": True}
        else:
            logger.error("VirusTotal Sandbox API returned error", status=response.status_code)
            return empty_result
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
        logger.warning("VirusTotal network error", error=str(e))
        return {**empty_result, "vt_unavailable": True}
    except Exception as e:
        logger.exception("Failed querying sandbox reports from VirusTotal", error=str(e))
        return empty_result


def submit_file(file_path: str) -> dict:
    """Submits a physical file to VirusTotal scanning endpoint.
    
    Args:
        file_path: File system path of file to submit.
        
    Returns:
        dict containing submission ID status.
    """
    url = f"{BASE_URL}/files"
    if not acquire_vt_slot():
        return {"submitted": False, "rate_limited": True}
    try:
        with open(file_path, "rb") as f:
            files = {"file": f}
            response = requests.post(url, headers={"x-apikey": VT_API_KEY}, files=files, timeout=15)
            if response.status_code == 200:
                data = response.json()
                sub_id = data.get("data", {}).get("id")
                return {"submission_id": sub_id, "submitted": True}
            elif response.status_code == 429:
                logger.warning("vt_quota_exceeded")
                return {"submitted": False, "rate_limited": True}
            else:
                logger.error("VirusTotal file submission failed", status=response.status_code, body=response.text)
                return {"submitted": False, "error": f"API error: {response.status_code}"}
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
        logger.warning("VirusTotal network error", error=str(e))
        return {"submitted": False, "vt_unavailable": True}
    except Exception as e:
        logger.exception("Exception occurred during VirusTotal file submission", error=str(e))
        return {"submitted": False, "error": str(e)}

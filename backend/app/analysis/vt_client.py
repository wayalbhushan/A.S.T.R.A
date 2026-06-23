"""
ASTRA VirusTotal v3 API Client
Integrates static antivirus detection analysis and dynamic sandbox execution logs.
"""

from datetime import datetime, timezone
import os
import time
import requests
import structlog

logger = structlog.get_logger()

VT_API_KEY = os.environ.get("VT_API_KEY", "")
BASE_URL = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": VT_API_KEY, "Accept": "application/json"}

if not VT_API_KEY:
    logger.warning("VT_API_KEY environment variable is not defined. VirusTotal calls will fail authentication.")


def sleep_for_rate_limit():
    """Enforces a 15-second delay before every API call to respect free-tier rate limits."""
    logger.info("Enforcing VirusTotal rate-limiting delay of 15 seconds")
    time.sleep(15)


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
    
    for attempt in range(2):
        sleep_for_rate_limit()
        try:
            response = requests.get(url, headers=HEADERS, timeout=30)
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
                return {
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
            elif response.status_code == 429:
                if attempt == 0:
                    logger.warning("VirusTotal API rate limit hit (429). Retrying in 60s...")
                    time.sleep(60)
                    continue
                else:
                    return {"found": False, "error": "Rate limit exceeded"}
            else:
                logger.error("VirusTotal API returned error code", status=response.status_code, response=response.text)
                return {"found": False, "error": f"API error status: {response.status_code}"}
        except Exception as e:
            logger.exception("Failed querying file report from VirusTotal", error=str(e))
            return {"found": False, "error": str(e)}

    return {"found": False, "error": "Request failed"}


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

    for attempt in range(2):
        sleep_for_rate_limit()
        try:
            response = requests.get(url, headers=HEADERS, timeout=30)
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
                if attempt == 0:
                    logger.warning("VirusTotal Sandbox API rate limit hit (429). Retrying in 60s...")
                    time.sleep(60)
                    continue
                else:
                    return empty_result
            else:
                logger.error("VirusTotal Sandbox API returned error", status=response.status_code)
                return empty_result
        except Exception as e:
            logger.exception("Failed querying sandbox reports from VirusTotal", error=str(e))
            return empty_result

    return empty_result


def submit_file(file_path: str) -> dict:
    """Submits a physical file to VirusTotal scanning endpoint.
    
    Args:
        file_path: File system path of file to submit.
        
    Returns:
        dict containing submission ID status.
    """
    url = f"{BASE_URL}/files"
    sleep_for_rate_limit()
    try:
        with open(file_path, "rb") as f:
            files = {"file": f}
            response = requests.post(url, headers={"x-apikey": VT_API_KEY}, files=files, timeout=60)
            if response.status_code == 200:
                data = response.json()
                sub_id = data.get("data", {}).get("id")
                return {"submission_id": sub_id, "submitted": True}
            else:
                logger.error("VirusTotal file submission failed", status=response.status_code, body=response.text)
                return {"submitted": False, "error": f"API error: {response.status_code}"}
    except Exception as e:
        logger.exception("Exception occurred during VirusTotal file submission", error=str(e))
        return {"submitted": False, "error": str(e)}

"""
ASTRA VirusTotal v3 API Client
Integrates static antivirus detection analysis, threat intelligence parsing,
Redis caching by hash, and dynamic sandbox execution logs.
"""

from datetime import datetime, timezone
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional
import requests
import structlog

# Ensure backend root is on sys.path when invoked directly
backend_root = str(Path(__file__).resolve().parent.parent.parent)
if backend_root not in sys.path:
    sys.path.insert(0, backend_root)

from app.extensions import redis_client

logger = structlog.get_logger()

# Ensure redis_client uses CACHE_REDIS_URL when running outside Flask application context
cache_url = os.environ.get("CACHE_REDIS_URL")
if cache_url:
    try:
        if getattr(redis_client, "connection_pool", None) and redis_client.connection_pool.connection_kwargs.get("host") == "localhost":
            import redis
            redis_client.connection_pool = redis.ConnectionPool.from_url(cache_url, decode_responses=True)
    except Exception:
        pass

BASE_URL = "https://www.virustotal.com/api/v3"
VT_WINDOW_SECONDS = 60
VT_REDIS_KEY = "vt:request_log"


def _get_api_key() -> str:
    """Retrieves VT_API_KEY from environment at call time."""
    return os.environ.get("VT_API_KEY", "").strip()


def _is_vt_enabled() -> bool:
    """Checks if VirusTotal integration is enabled and configured."""
    api_key = _get_api_key()
    enabled_str = os.environ.get("VT_ENABLED", "true").lower()
    return enabled_str == "true" and bool(api_key)


def _get_cache_ttl_ok() -> int:
    """Retrieves cache TTL for successful results."""
    try:
        return int(os.environ.get("VT_CACHE_TTL_OK", 86400))
    except (ValueError, TypeError):
        return 86400


def _is_upload_allowed() -> bool:
    """Checks if sample file upload is permitted."""
    return os.environ.get("VT_ALLOW_UPLOAD", "false").lower() == "true"


def _get_requests_per_minute() -> int:
    """Retrieves rate limit per minute."""
    try:
        return int(os.environ.get("VT_REQUESTS_PER_MINUTE", 4))
    except (ValueError, TypeError):
        return 4


def _get_max_wait_seconds() -> int:
    """Retrieves max wait seconds for rate limiter."""
    try:
        return int(os.environ.get("VT_MAX_WAIT_SECONDS", 20))
    except (ValueError, TypeError):
        return 20


def acquire_vt_slot() -> bool:
    """Acquires a rate limit slot using Redis sliding-window log.
    
    Returns True if request can proceed, False if rate limited.
    Fails open (returns True) on Redis errors.
    """
    try:
        req_limit = _get_requests_per_minute()
        max_wait = _get_max_wait_seconds()
        for _ in range(2):
            now = time.time()
            redis_client.zremrangebyscore(VT_REDIS_KEY, 0, now - VT_WINDOW_SECONDS)
            count = redis_client.zcard(VT_REDIS_KEY)
            if count < req_limit:
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
                if wait > max_wait:
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


def parse_date(timestamp) -> Optional[str]:
    """Parses a UNIX timestamp float/int into a UTC ISO 8601 string representation."""
    if not timestamp:
        return None
    try:
        return datetime.fromtimestamp(int(timestamp), timezone.utc).isoformat()
    except Exception as e:
        logger.warning("Failed parsing date timestamp", timestamp=timestamp, error=str(e))
        return None


def _parse_intel(attributes: dict) -> dict:
    """Defensively parses threat intelligence from VirusTotal file attributes.
    Every access uses .get or safe type conversion, ignores wrong types, and never raises.
    """
    if not isinstance(attributes, dict):
        attributes = {}

    # names: up to 5 strings (attributes.names, fallback meaningful_name)
    names_raw = attributes.get("names")
    names: List[str] = []
    if isinstance(names_raw, list):
        for n in names_raw:
            if isinstance(n, str) and n.strip():
                names.append(n.strip())
            if len(names) >= 5:
                break
    if not names:
        m_name = attributes.get("meaningful_name")
        if isinstance(m_name, str) and m_name.strip():
            names.append(m_name.strip())

    first_sub = parse_date(attributes.get("first_submission_date"))
    last_anal = parse_date(attributes.get("last_analysis_date"))

    times_sub = attributes.get("times_submitted")
    if not (isinstance(times_sub, int) and not isinstance(times_sub, bool)):
        times_sub = None

    reputation = attributes.get("reputation")
    if not (isinstance(reputation, int) and not isinstance(reputation, bool)):
        reputation = None

    tags_raw = attributes.get("tags")
    tags: List[str] = []
    if isinstance(tags_raw, list):
        for t in tags_raw:
            if isinstance(t, str) and t.strip():
                tags.append(t.strip())
            if len(tags) >= 10:
                break

    type_tag_raw = attributes.get("type_tag")
    type_tag = type_tag_raw.strip() if isinstance(type_tag_raw, str) and type_tag_raw.strip() else None

    # threat: {"label", "category", "names"} or None
    ptc = attributes.get("popular_threat_classification")
    threat = None
    if isinstance(ptc, dict):
        label = ptc.get("suggested_threat_label")
        if not isinstance(label, str) or not label.strip():
            label = None
        else:
            label = label.strip()

        cat_raw = ptc.get("popular_threat_category")
        category = None
        if isinstance(cat_raw, list) and len(cat_raw) > 0:
            first_cat = cat_raw[0]
            if isinstance(first_cat, dict):
                val = first_cat.get("value")
                if isinstance(val, str) and val.strip():
                    category = val.strip()
            elif isinstance(first_cat, str) and first_cat.strip():
                category = first_cat.strip()

        names_raw = ptc.get("popular_threat_name")
        threat_names: List[str] = []
        if isinstance(names_raw, list):
            for item in names_raw:
                if isinstance(item, dict):
                    val = item.get("value")
                    if isinstance(val, str) and val.strip():
                        threat_names.append(val.strip())
                elif isinstance(item, str) and item.strip():
                    threat_names.append(item.strip())
                if len(threat_names) >= 3:
                    break

        if label is not None or category is not None or len(threat_names) > 0:
            threat = {
                "label": label,
                "category": category,
                "names": threat_names,
            }

    # sandbox_verdicts: up to 5 items {"sandbox": key, "category", "confidence", "malware_names": up to 3}
    sb_verdicts_raw = attributes.get("sandbox_verdicts")
    sandbox_verdicts: List[Dict[str, Any]] = []
    if isinstance(sb_verdicts_raw, dict):
        for sb_key, sb_val in sb_verdicts_raw.items():
            if isinstance(sb_val, dict):
                mn_raw = sb_val.get("malware_names")
                malware_names: List[str] = []
                if isinstance(mn_raw, list):
                    for mn in mn_raw:
                        if isinstance(mn, str) and mn.strip():
                            malware_names.append(mn.strip())
                        if len(malware_names) >= 3:
                            break
                sandbox_verdicts.append({
                    "sandbox": str(sb_key),
                    "category": sb_val.get("category"),
                    "confidence": sb_val.get("confidence"),
                    "malware_names": malware_names,
                })
            if len(sandbox_verdicts) >= 5:
                break
    elif isinstance(sb_verdicts_raw, list):
        for sb_val in sb_verdicts_raw:
            if isinstance(sb_val, dict):
                sb_key = sb_val.get("sandbox") or sb_val.get("sandbox_name") or "unknown"
                mn_raw = sb_val.get("malware_names")
                malware_names = []
                if isinstance(mn_raw, list):
                    for mn in mn_raw:
                        if isinstance(mn, str) and mn.strip():
                            malware_names.append(mn.strip())
                        if len(malware_names) >= 3:
                            break
                sandbox_verdicts.append({
                    "sandbox": str(sb_key),
                    "category": sb_val.get("category"),
                    "confidence": sb_val.get("confidence"),
                    "malware_names": malware_names,
                })
            if len(sandbox_verdicts) >= 5:
                break

    # yara: up to 5 items {"rule": rule_name, "source", "ruleset": ruleset_name}
    yara_raw = (
        attributes.get("crowdsourced_yara_results")
        or attributes.get("yara")
        or attributes.get("yara_results")
        or attributes.get("crowdsourced_yara")
    )
    yara_list: List[Dict[str, Any]] = []
    if isinstance(yara_raw, list):
        for item in yara_raw:
            if isinstance(item, dict):
                rule = item.get("rule_name") or item.get("rule")
                ruleset = item.get("ruleset_name") or item.get("ruleset")
                source = item.get("source")
                yara_list.append({
                    "rule": rule,
                    "source": source,
                    "ruleset": ruleset,
                })
            if len(yara_list) >= 5:
                break

    # available_fields: names of the fields above that were not empty
    available_fields: List[str] = []
    field_checks = [
        ("names", names),
        ("first_submission_date", first_sub),
        ("last_analysis_date", last_anal),
        ("times_submitted", times_sub),
        ("reputation", reputation),
        ("tags", tags),
        ("type_tag", type_tag),
        ("threat", threat),
        ("sandbox_verdicts", sandbox_verdicts),
        ("yara", yara_list),
    ]
    for field_name, field_val in field_checks:
        if field_val is not None and field_val != "" and field_val != []:
            available_fields.append(field_name)

    return {
        "source": "virustotal",
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "names": names,
        "first_submission_date": first_sub,
        "last_analysis_date": last_anal,
        "times_submitted": times_sub,
        "reputation": reputation,
        "tags": tags,
        "type_tag": type_tag,
        "threat": threat,
        "sandbox_verdicts": sandbox_verdicts,
        "yara": yara_list,
        "available_fields": available_fields,
    }


def get_file_report(file_hash: str, refresh: bool = False) -> dict:
    """Retrieves antivirus detection reports and threat intelligence from VirusTotal.
    
    Args:
        file_hash: Target file SHA-256 hash.
        refresh: If True, bypasses cache read and fetches fresh data from VirusTotal.
        
    Returns:
        dict containing antivirus counts, detection ratio, engine verdicts, intel, and status.
    """
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

    if not _is_vt_enabled():
        return {**fallback, "status": "disabled"}

    cache_key = f"vt:file:{file_hash}"
    if not refresh:
        try:
            cached = redis_client.get(cache_key)
            if cached:
                data = json.loads(cached)
                data["cached"] = True
                return data
        except Exception as e:
            logger.warning("vt_cache_read_failed", key=cache_key, error=str(e))

    if not acquire_vt_slot():
        return {**fallback, "rate_limited": True, "status": "rate_limited"}

    api_key = _get_api_key()
    headers = {"x-apikey": api_key, "Accept": "application/json"}
    url = f"{BASE_URL}/files/{file_hash}"

    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            results = attributes.get("last_analysis_results", {})

            engine_verdicts = []
            if isinstance(results, dict):
                for engine, verdict in results.items():
                    if isinstance(verdict, dict) and verdict.get("category") == "malicious":
                        engine_verdicts.append({
                            "engine": engine,
                            "result": verdict.get("result", "malicious")
                        })

            malicious = stats.get("malicious", 0) if isinstance(stats, dict) else 0
            harmless = stats.get("harmless", 0) if isinstance(stats, dict) else 0
            undetected = stats.get("undetected", 0) if isinstance(stats, dict) else 0
            suspicious = stats.get("suspicious", 0) if isinstance(stats, dict) else 0
            total = malicious + harmless + undetected + suspicious

            detection_ratio = f"{malicious}/{total}" if total > 0 else "0/0"
            first_sub = parse_date(attributes.get("first_submission_date"))
            last_anal = parse_date(attributes.get("last_analysis_date"))

            intel = _parse_intel(attributes)

            result = {
                "found": True,
                "status": "ok",
                "detection_ratio": detection_ratio,
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "harmless_count": harmless,
                "undetected_count": undetected,
                "engine_verdicts": engine_verdicts,
                "first_submission": first_sub,
                "last_analysis_date": last_anal,
                "intel": intel,
            }

            ttl = _get_cache_ttl_ok()
            try:
                redis_client.setex(cache_key, ttl, json.dumps(result))
            except Exception as e:
                logger.warning("vt_cache_write_failed", key=cache_key, error=str(e))

            return result

        elif response.status_code == 404:
            result = {**fallback, "status": "not_found"}
            try:
                redis_client.setex(cache_key, 900, json.dumps(result))
            except Exception as e:
                logger.warning("vt_cache_write_failed", key=cache_key, error=str(e))
            return result

        elif response.status_code == 429:
            logger.warning("vt_quota_exceeded")
            return {**fallback, "rate_limited": True, "status": "rate_limited"}

        else:
            logger.error("VirusTotal API returned error code", status=response.status_code)
            return {**fallback, "error": f"API error status: {response.status_code}", "status": "unavailable"}

    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
        logger.warning("VirusTotal network error", error=str(e))
        return {**fallback, "vt_unavailable": True, "status": "unavailable"}
    except Exception as e:
        logger.exception("Failed querying file report from VirusTotal", error=str(e))
        return {**fallback, "error": str(e), "status": "unavailable"}


def get_sandbox_report(file_hash: str, refresh: bool = False) -> dict:
    """Aggregates multi-sandbox execution behavior reports from VirusTotal files behaviours.
    
    Args:
        file_hash: Target file SHA-256 hash.
        refresh: If True, bypasses cache read and fetches fresh data from VirusTotal.
        
    Returns:
        dict containing aggregated sandbox behaviors, severity scores, and status.
    """
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
        "has_file_activity": False,
    }

    if not _is_vt_enabled():
        return {**empty_result, "status": "disabled"}

    cache_key = f"vt:sandbox:{file_hash}"
    if not refresh:
        try:
            cached = redis_client.get(cache_key)
            if cached:
                data = json.loads(cached)
                data["cached"] = True
                return data
        except Exception as e:
            logger.warning("vt_sandbox_cache_read_failed", key=cache_key, error=str(e))

    if not acquire_vt_slot():
        return {**empty_result, "rate_limited": True, "status": "rate_limited"}

    api_key = _get_api_key()
    headers = {"x-apikey": api_key, "Accept": "application/json"}
    url = f"{BASE_URL}/files/{file_hash}/behaviours"

    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json()
            sandbox_reports = data.get("data", [])

            if not sandbox_reports:
                result = {**empty_result, "status": "ok"}
                ttl = _get_cache_ttl_ok()
                try:
                    redis_client.setex(cache_key, ttl, json.dumps(result))
                except Exception as e:
                    logger.warning("vt_sandbox_cache_write_failed", key=cache_key, error=str(e))
                return result

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

                for f in report.get("files_written", []):
                    files_written.add(f)
                for f in report.get("files_deleted", []):
                    files_deleted.add(f)
                for p in report.get("permissions_requested", []):
                    permissions_requested.add(p)
                for proc in report.get("processes_created", []):
                    processes_created.add(proc)

                for ja3 in report.get("ja3_fingerprints", []):
                    if isinstance(ja3, str):
                        tls_fingerprints.append({"ja3": ja3})
                    elif isinstance(ja3, dict) and "ja3" in ja3:
                        tls_fingerprints.append({"ja3": ja3["ja3"]})

                for tech in report.get("mitre_attack_techniques", []):
                    tech_id = tech.get("id")
                    if tech_id:
                        severity = tech.get("signature_severity", "IMPACT_SEVERITY_INFO")
                        mitre_attacks[tech_id] = {
                            "id": tech_id,
                            "description": tech.get("description", ""),
                            "severity": severity,
                        }

                for match in report.get("signature_matches", []):
                    threat_name = match.get("name")
                    if threat_name:
                        threats.append({
                            "engine": name,
                            "result": threat_name,
                        })

            severity_map = {
                "IMPACT_SEVERITY_CRITICAL": 3,
                "IMPACT_SEVERITY_HIGH": 2,
                "IMPACT_SEVERITY_MEDIUM": 1,
                "IMPACT_SEVERITY_INFO": 0,
            }
            severity_score = sum(severity_map.get(m.get("severity"), 0) for m in mitre_attacks.values())

            has_network = bool(tls_fingerprints or processes_created)
            has_file = bool(files_written)

            result = {
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
                "has_file_activity": has_file,
                "status": "ok",
            }

            ttl = _get_cache_ttl_ok()
            try:
                redis_client.setex(cache_key, ttl, json.dumps(result))
            except Exception as e:
                logger.warning("vt_sandbox_cache_write_failed", key=cache_key, error=str(e))

            return result

        elif response.status_code == 404:
            return {**empty_result, "status": "not_found"}
        elif response.status_code == 429:
            logger.warning("vt_quota_exceeded")
            return {**empty_result, "rate_limited": True, "status": "rate_limited"}
        else:
            logger.error("VirusTotal Sandbox API returned error", status=response.status_code)
            return {**empty_result, "status": "unavailable"}

    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
        logger.warning("VirusTotal network error", error=str(e))
        return {**empty_result, "vt_unavailable": True, "status": "unavailable"}
    except Exception as e:
        logger.exception("Failed querying sandbox reports from VirusTotal", error=str(e))
        return {**empty_result, "status": "unavailable"}


def submit_file(file_path: str) -> dict:
    """Submits a physical file to VirusTotal scanning endpoint.
    
    Args:
        file_path: File system path of file to submit.
        
    Returns:
        dict containing submission ID status and normalized status.
    """
    url = f"{BASE_URL}/files"

    if not _is_upload_allowed():
        return {"submitted": False, "status": "disabled", "reason": "upload_disabled"}

    if not _is_vt_enabled():
        return {"submitted": False, "status": "disabled"}

    if not acquire_vt_slot():
        return {"submitted": False, "rate_limited": True, "status": "rate_limited"}

    api_key = _get_api_key()
    try:
        with open(file_path, "rb") as f:
            files = {"file": f}
            response = requests.post(url, headers={"x-apikey": api_key}, files=files, timeout=15)
            if response.status_code == 200:
                data = response.json()
                sub_id = data.get("data", {}).get("id")
                return {"submission_id": sub_id, "submitted": True, "status": "ok"}
            elif response.status_code == 429:
                logger.warning("vt_quota_exceeded")
                return {"submitted": False, "rate_limited": True, "status": "rate_limited"}
            else:
                logger.error("VirusTotal file submission failed", status=response.status_code)
                return {"submitted": False, "error": f"API error: {response.status_code}", "status": "unavailable"}
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
        logger.warning("VirusTotal network error", error=str(e))
        return {"submitted": False, "vt_unavailable": True, "status": "unavailable"}
    except Exception as e:
        logger.exception("Exception occurred during VirusTotal file submission", error=str(e))
        return {"submitted": False, "error": str(e), "status": "unavailable"}


if __name__ == "__main__":
    from unittest.mock import MagicMock, patch

    print("Running ASTRA VirusTotal Client Test Suite...")
    total_tests = 9
    passed_tests = 0

    orig_env = dict(os.environ)

    try:
        # Base setup for mock testing
        os.environ["VT_ENABLED"] = "true"
        os.environ["VT_API_KEY"] = "mock_test_key_12345"
        os.environ["VT_ALLOW_UPLOAD"] = "false"
        os.environ["VT_REQUESTS_PER_MINUTE"] = "100"
        try:
            redis_client.delete(VT_REDIS_KEY)
        except Exception:
            pass

        # a. Fixture with full intel fields
        fixture_a_attrs = {
            "names": ["malicious.apk", "sample.apk", "app1.apk", "app2.apk", "app3.apk", "app4.apk"],
            "first_submission_date": 1609459200,
            "last_analysis_date": 1612137600,
            "times_submitted": 42,
            "reputation": -50,
            "tags": ["apk", "trojan", "spyware"],
            "type_tag": "apk",
            "popular_threat_classification": {
                "suggested_threat_label": "trojan.spyloan",
                "popular_threat_category": [{"value": "trojan", "count": 10}],
                "popular_threat_name": [{"value": "spyloan", "count": 15}, {"value": "agent", "count": 3}]
            },
            "sandbox_verdicts": {
                "Zenbox": {
                    "category": "malicious",
                    "confidence": 90,
                    "malware_names": ["SpyLoan", "TrojanSpy"]
                }
            },
            "crowdsourced_yara_results": [
                {
                    "rule_name": "spyloan_rule",
                    "source": "community",
                    "ruleset_name": "ruleset_1"
                }
            ],
            "last_analysis_stats": {"malicious": 10, "suspicious": 1, "harmless": 2, "undetected": 50},
            "last_analysis_results": {"Engine1": {"category": "malicious", "result": "trojan"}}
        }
        mock_resp_a = MagicMock()
        mock_resp_a.status_code = 200
        mock_resp_a.json.return_value = {"data": {"attributes": fixture_a_attrs}}

        test_hash_a = "a" * 64
        try:
            redis_client.delete(f"vt:file:{test_hash_a}")
        except Exception:
            pass

        with patch("requests.get", return_value=mock_resp_a):
            res_a = get_file_report(test_hash_a)

        intel_a = res_a.get("intel", {})
        threat_a = intel_a.get("threat") or {}
        cond_a = (
            res_a.get("status") == "ok"
            and len(intel_a.get("names", [])) == 5
            and intel_a.get("times_submitted") == 42
            and intel_a.get("reputation") == -50
            and threat_a.get("label") == "trojan.spyloan"
            and threat_a.get("category") == "trojan"
            and len(threat_a.get("names", [])) == 2
            and len(intel_a.get("sandbox_verdicts", [])) == 1
            and len(intel_a.get("yara", [])) == 1
            and "names" in intel_a.get("available_fields", [])
            and "threat" in intel_a.get("available_fields", [])
        )
        if cond_a:
            print("PASS: Test a - Fixture response parsed correctly with right counts and label")
            passed_tests += 1
        else:
            print("FAIL: Test a - Fixture parsing failed")

        # b. Fixture without those fields
        fixture_b_attrs = {
            "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 10, "undetected": 5},
            "last_analysis_results": {}
        }
        mock_resp_b = MagicMock()
        mock_resp_b.status_code = 200
        mock_resp_b.json.return_value = {"data": {"attributes": fixture_b_attrs}}

        test_hash_b = "b" * 64
        try:
            redis_client.delete(f"vt:file:{test_hash_b}")
        except Exception:
            pass

        with patch("requests.get", return_value=mock_resp_b):
            res_b = get_file_report(test_hash_b)

        intel_b = res_b.get("intel", {})
        cond_b = (
            res_b.get("status") == "ok"
            and intel_b.get("names") == []
            and intel_b.get("first_submission_date") is None
            and intel_b.get("last_analysis_date") is None
            and intel_b.get("times_submitted") is None
            and intel_b.get("reputation") is None
            and intel_b.get("tags") == []
            and intel_b.get("type_tag") is None
            and intel_b.get("threat") is None
            and intel_b.get("sandbox_verdicts") == []
            and intel_b.get("yara") == []
            and intel_b.get("available_fields") == []
        )
        if cond_b:
            print("PASS: Test b - Empty fixture parsed safely with None and empty lists")
            passed_tests += 1
        else:
            print(f"FAIL: Test b - Empty fixture parsing failed: {intel_b}")

        # c. VT_ENABLED=false
        os.environ["VT_ENABLED"] = "false"
        with patch("requests.get") as mock_get_c:
            res_c = get_file_report("c" * 64)
            cond_c = (res_c.get("status") == "disabled" and mock_get_c.call_count == 0)
        if cond_c:
            print("PASS: Test c - VT_ENABLED=false returns status disabled and makes no network call")
            passed_tests += 1
        else:
            print("FAIL: Test c - VT_ENABLED=false failed")

        # d. Blank VT_API_KEY
        os.environ["VT_ENABLED"] = "true"
        os.environ["VT_API_KEY"] = ""
        with patch("requests.get") as mock_get_d:
            res_d = get_file_report("d" * 64)
            cond_d = (res_d.get("status") == "disabled" and mock_get_d.call_count == 0)
        if cond_d:
            print("PASS: Test d - Blank VT_API_KEY returns status disabled and makes no network call")
            passed_tests += 1
        else:
            print("FAIL: Test d - Blank VT_API_KEY failed")

        # Restore valid key for subsequent tests
        os.environ["VT_API_KEY"] = "mock_test_key_12345"

        # e. HTTP 404, 429, and Timeout error status mappings
        mock_404 = MagicMock(status_code=404)
        mock_429 = MagicMock(status_code=429)

        try:
            redis_client.delete(f"vt:file:{'e1' * 32}")
            redis_client.delete(f"vt:file:{'e2' * 32}")
            redis_client.delete(f"vt:file:{'e3' * 32}")
        except Exception:
            pass

        with patch("requests.get", return_value=mock_404):
            res_404 = get_file_report("e1" * 32)
        with patch("requests.get", return_value=mock_429):
            res_429 = get_file_report("e2" * 32)
        with patch("requests.get", side_effect=requests.exceptions.Timeout("Connection timeout")):
            res_timeout = get_file_report("e3" * 32)

        cond_e = (
            res_404.get("status") == "not_found"
            and res_429.get("status") == "rate_limited"
            and res_timeout.get("status") == "unavailable"
        )
        if cond_e:
            print("PASS: Test e - 404 gives not_found, 429 gives rate_limited, Timeout gives unavailable")
            passed_tests += 1
        else:
            print(f"FAIL: Test e - Status mapping failed (404: {res_404.get('status')}, 429: {res_429.get('status')}, timeout: {res_timeout.get('status')})")

        # f. Redis caching by hash
        test_hash_f = "f" * 64
        cache_key_f = f"vt:file:{test_hash_f}"
        try:
            redis_client.delete(cache_key_f)
        except Exception:
            pass

        mock_resp_f = MagicMock()
        mock_resp_f.status_code = 200
        mock_resp_f.json.return_value = {"data": {"attributes": {"names": ["cached_app.apk"]}}}

        with patch("requests.get", return_value=mock_resp_f) as mock_get_f:
            first_call = get_file_report(test_hash_f)
            second_call = get_file_report(test_hash_f)

            cond_f = (
                mock_get_f.call_count == 1
                and second_call.get("cached") is True
                and second_call.get("status") == "ok"
            )

        try:
            redis_client.delete(cache_key_f)
            redis_client.delete(f"vt:file:{test_hash_a}")
            redis_client.delete(f"vt:file:{test_hash_b}")
            redis_client.delete(f"vt:file:{'e1' * 32}")
        except Exception:
            pass

        if cond_f:
            print("PASS: Test f - Hash cached in Redis, requests.get called once, second result has cached=True")
            passed_tests += 1
        else:
            print(f"FAIL: Test f - Caching verification failed (calls={mock_get_f.call_count}, cached={second_call.get('cached')})")

        # g. submit_file with VT_ALLOW_UPLOAD false
        os.environ["VT_ALLOW_UPLOAD"] = "false"
        with patch("requests.post") as mock_post_g:
            res_g = submit_file("dummy.apk")
            cond_g = (
                res_g.get("status") == "disabled"
                and res_g.get("reason") == "upload_disabled"
                and mock_post_g.call_count == 0
            )

        if cond_g:
            print("PASS: Test g - submit_file with VT_ALLOW_UPLOAD false returns status disabled without network call")
            passed_tests += 1
        else:
            print(f"FAIL: Test g - submit_file disabled check failed: {res_g}")

        # h. refresh=True calls requests.get again and resets entry TTL to VT_CACHE_TTL_OK
        test_hash_h = "h" * 64
        cache_key_h = f"vt:file:{test_hash_h}"
        try:
            redis_client.delete(cache_key_h)
        except Exception:
            pass

        mock_resp_h = MagicMock()
        mock_resp_h.status_code = 200
        mock_resp_h.json.return_value = {"data": {"attributes": {"names": ["app_h.apk"]}}}

        with patch("requests.get", return_value=mock_resp_h) as mock_get_h:
            first_h = get_file_report(test_hash_h, refresh=False)
            try:
                redis_client.expire(cache_key_h, 300)
            except Exception:
                pass

            second_h = get_file_report(test_hash_h, refresh=True)
            ttl_h = 0
            try:
                ttl_h = redis_client.ttl(cache_key_h)
            except Exception:
                pass

            cond_h = (
                mock_get_h.call_count == 2
                and second_h.get("cached") is not True
                and second_h.get("status") == "ok"
                and ttl_h > 300
            )

        try:
            redis_client.delete(cache_key_h)
        except Exception:
            pass

        if cond_h:
            print("PASS: Test h - refresh=True calls requests.get again and resets entry TTL")
            passed_tests += 1
        else:
            print(f"FAIL: Test h - refresh=True test failed (calls={mock_get_h.call_count}, cached={second_h.get('cached')}, ttl={ttl_h})")

        # i. Default TTL equals 86400 when env var unset
        saved_ttl_env = os.environ.pop("VT_CACHE_TTL_OK", None)
        try:
            default_ttl = _get_cache_ttl_ok()
            cond_i = (default_ttl == 86400)
        finally:
            if saved_ttl_env is not None:
                os.environ["VT_CACHE_TTL_OK"] = saved_ttl_env

        if cond_i:
            print("PASS: Test i - Default TTL equals 86400 with env var unset")
            passed_tests += 1
        else:
            print(f"FAIL: Test i - Default TTL test failed (expected 86400, got {default_ttl})")

    finally:
        os.environ.clear()
        os.environ.update(orig_env)

    print(f"\nFinal Result: {passed_tests}/{total_tests} tests passed.")

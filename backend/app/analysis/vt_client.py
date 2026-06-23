"""
ASTRA VirusTotal v3 API Client
Integrates static antivirus detection analysis reports.
"""
import os
import time
import requests
import structlog
from datetime import datetime, timezone

logger = structlog.get_logger()

VT_API_KEY = os.environ.get("VT_API_KEY", "")
BASE_URL = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": VT_API_KEY, "Accept": "application/json"}

def sleep_for_rate_limit():
    """Enforces 15s delay to stay within rate limit."""
    time.sleep(15)

def parse_date(timestamp) -> str:
    if not timestamp: return None
    return datetime.fromtimestamp(int(timestamp), timezone.utc).isoformat()

def get_file_report(file_hash: str) -> dict:
    """Retrieves antivirus detection reports from VirusTotal."""
    url = f"{BASE_URL}/files/{file_hash}"
    sleep_for_rate_limit()
    response = requests.get(url, headers=HEADERS, timeout=30)
    if response.status_code == 200:
        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())
        return {
            "found": True,
            "detection_ratio": f"{malicious}/{total}" if total > 0 else "0/0",
            "malicious_count": malicious,
            "engine_verdicts": [],
            "first_submission": parse_date(attributes.get("first_submission_date")),
            "last_analysis_date": parse_date(attributes.get("last_analysis_date"))
        }
    return {"found": False}

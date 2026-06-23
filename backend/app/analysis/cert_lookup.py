"""
ASTRA Certificate Lookup Module
Checks certificate hashes against the database of 34 trusted Indian banking app certs.
"""

import json
from pathlib import Path
import structlog

logger = structlog.get_logger()

# Path to signature database (Task 1)
CERTS_PATH = Path(__file__).resolve().parent.parent.parent / "ml" / "trusted_certs.json"

TRUSTED_HASHES = set()
CERT_METADATA = {}

# Build lookup structures defensively at load time (Task 1)
if CERTS_PATH.exists():
    try:
        with open(CERTS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        trusted_list = data.get("trusted_certificates", [])
        
        TRUSTED_HASHES = {cert["cert_hash"] for cert in trusted_list}
        CERT_METADATA = {cert["cert_hash"]: cert for cert in trusted_list}
        logger.info("Certificate lookup database loaded successfully", count=len(TRUSTED_HASHES))
    except Exception as e:
        logger.warning("Failed to load trusted_certs.json at import time", error=str(e))
else:
    logger.warning("trusted_certs.json database file not found at path", path=str(CERTS_PATH))


def lookup(cert_hash: str) -> dict:
    """Returns the signature database verdict for a certificate hash.
    
    Args:
        cert_hash: SHA-256 certificate signature hash string.
        
    Returns:
        dict containing verdict (TRUSTED or UNKNOWN) and associated app metadata.
    """
    if not cert_hash:
        return {
            "verdict": "UNKNOWN",
            "app_name": None,
            "package_name": None,
            "issuer": None
        }

    if cert_hash in TRUSTED_HASHES:
        meta = CERT_METADATA[cert_hash]
        return {
            "verdict": "TRUSTED",
            "app_name": meta.get("app_name"),
            "package_name": meta.get("package_name"),
            "issuer": meta.get("issuer")
        }

    return {
        "verdict": "UNKNOWN",
        "app_name": None,
        "package_name": None,
        "issuer": None
    }

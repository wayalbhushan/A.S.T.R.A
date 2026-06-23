"""
ASTRA Static APK Analysis Module
Uses Androguard to parse APK metadata, permissions, activities, and services.
"""
import hashlib
import structlog
from androguard.misc import AnalyzeAPK

logger = structlog.get_logger()

def compute_file_hash(apk_path: str) -> str:
    """Calculates the SHA-256 hash of the target APK file."""
    sha256 = hashlib.sha256()
    with open(apk_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def extract(apk_path: str) -> dict:
    """Ingests and parses an APK, returning base metadata features."""
    try:
        a, d, dx = AnalyzeAPK(apk_path)
    except Exception as e:
        raise ValueError(f"Failed to parse APK: {str(e)}")
    
    return {
        "apk_hash": compute_file_hash(apk_path),
        "package_name": a.get_package(),
        "app_name": a.get_app_name(),
        "version_name": str(a.get_androidversion_name()),
        "version_code": str(a.get_androidversion_code()),
        "permissions": list(a.get_permissions())
    }

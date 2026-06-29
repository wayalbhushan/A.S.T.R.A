"""
ASTRA Static APK Analysis Module
Uses Androguard to parse APK metadata, permissions, certificates, string entropy, and APIs.
"""

from collections import Counter
import hashlib
import math
from statistics import mean
import OpenSSL
import structlog
from androguard.misc import AnalyzeAPK

logger = structlog.get_logger()

DANGEROUS_PERMISSIONS = [
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.READ_PHONE_STATE",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.SYSTEM_ALERT_WINDOW",
]

SENSITIVE_APIS = [
    "getDeviceId", "getSubscriberId", "getSimSerialNumber",
    "getLine1Number", "getVoiceMailNumber",
    "sendTextMessage", "sendMultipartTextMessage",
    "getContactsbyPhone", "query",
    "Runtime.exec", "ProcessBuilder",
    "loadLibrary", "loadClass",
    "createFromPdu", "SmsMessage",
    "TelephonyManager", "getNetworkOperator",
]


def shannon_entropy(data: str) -> float:
    """Computes the Shannon entropy of a given string.
    
    Entropy acts as a signal for string obfuscation or encryption.
    """
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def extract_certificate(a) -> dict:
    """Extracts APK signer certificate attributes using OpenSSL.
    
    Tries V2 DER format first, falling back to V1 list, parsing DN components
    and computing SHA-256 cert hashes.
    """
    try:
        certs_der = []
        if hasattr(a, "get_certificates_der_v2"):
            certs_der = a.get_certificates_der_v2()
            
        if not certs_der and hasattr(a, "get_certificates"):
            certs = a.get_certificates()
            for c in certs:
                if isinstance(c, bytes):
                    certs_der.append(c)
                elif hasattr(c, "public_bytes"):
                    from cryptography.hazmat.primitives import serialization
                    certs_der.append(c.public_bytes(serialization.Encoding.DER))
                elif hasattr(c, "get_der"):
                    certs_der.append(c.get_der())

        if certs_der:
            cert_der = certs_der[0]
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_der)
            
            # Formulate Issuer CN
            issuer_cn = cert.get_issuer().CN
            if not issuer_cn:
                issuer_cn = "/".join(
                    [f"{k.decode('utf-8') if isinstance(k, bytes) else k}={v.decode('utf-8') if isinstance(v, bytes) else v}"
                     for k, v in cert.get_issuer().get_components()]
                )
            elif isinstance(issuer_cn, bytes):
                issuer_cn = issuer_cn.decode("utf-8")

            # Formulate Subject CN
            subject_cn = cert.get_subject().CN
            if not subject_cn:
                subject_cn = "/".join(
                    [f"{k.decode('utf-8') if isinstance(k, bytes) else k}={v.decode('utf-8') if isinstance(v, bytes) else v}"
                     for k, v in cert.get_subject().get_components()]
                )
            elif isinstance(subject_cn, bytes):
                subject_cn = subject_cn.decode("utf-8")

            # Formulate Timestamps
            not_before = cert.get_notBefore()
            if isinstance(not_before, bytes):
                not_before = not_before.decode("utf-8")
            not_after = cert.get_notAfter()
            if isinstance(not_after, bytes):
                not_after = not_after.decode("utf-8")

            cert_hash = hashlib.sha256(cert_der).hexdigest()

            return {
                "cert_hash": cert_hash,
                "issuer": issuer_cn,
                "subject": subject_cn,
                "serial_number": str(cert.get_serial_number()),
                "not_before": not_before,
                "not_after": not_after
            }
    except Exception as e:
        logger.warning("Certificate extraction failed or not present", error=str(e))
        
    return {}


def compute_file_hash(apk_path: str) -> str:
    """Calculates the SHA-256 hash of the target APK file."""
    sha256 = hashlib.sha256()
    with open(apk_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def extract(apk_path: str) -> dict:
    """Ingests and parses an APK, returning all static analysis attributes.
    
    Args:
        apk_path: Absolute file system path to target APK file.
        
    Returns:
        dict containing package name, certificate info, APIs list, and string entropy.
        
    Raises:
        ValueError: If Androguard fails to parse the APK format.
    """
    logger.info("Starting static analysis on APK", path=apk_path)
    
    try:
        a, d, dx = AnalyzeAPK(apk_path)
    except Exception as e:
        logger.exception("Androguard failed to parse APK", path=apk_path, error=str(e))
        raise ValueError(f"Failed to parse APK: {str(e)}")

    # 1. Base Metadata Extraction
    package_name = a.get_package()
    try:
        app_name = a.get_app_name()
    except Exception:
        app_name = a.get_package() or "Unknown"

    try:
        version_name = a.get_androidversion_name()
    except Exception:
        version_name = "Unknown"

    try:
        version_code = a.get_androidversion_code()
    except Exception:
        version_code = "0"

    min_sdk = a.get_min_sdk_version()
    target_sdk = a.get_target_sdk_version()

    permissions = list(a.get_permissions())
    declared_permissions = list(a.get_declared_permissions())
    activities = list(a.get_activities())
    services = list(a.get_services())
    receivers = list(a.get_receivers())
    providers = list(a.get_providers())

    # 2. Certificate Extraction
    certificate_data = extract_certificate(a)

    # 3. Dangerous Permissions
    dangerous_found = [p for p in permissions if p in DANGEROUS_PERMISSIONS]
    dangerous_count = len(dangerous_found)

    # 4. Shannon Entropy
    strings = [s.get_value() for s in dx.get_strings()]
    avg_entropy = 0.0
    high_entropy_count = 0
    if strings:
        entropies = [shannon_entropy(s) for s in strings]
        avg_entropy = float(mean(entropies))
        high_entropy_count = sum(1 for e in entropies if e > 4.5)

    # 5. Sensitive API Calls via cross-references (xref)
    sensitive_apis_found = set()
    for method in dx.get_methods():
        for _, call, _ in method.get_xref_to():
            call_name = getattr(call, "name", None)
            if call_name and isinstance(call_name, str):
                if any(api in call_name for api in SENSITIVE_APIS):
                    sensitive_apis_found.add(call_name)
    sensitive_apis_list = list(sensitive_apis_found)
    sensitive_api_count = len(sensitive_apis_list)

    # 6. File Hash
    apk_hash = compute_file_hash(apk_path)

    logger.info(
        "Static analysis completed successfully", 
        package=package_name, 
        permissions_count=len(permissions), 
        dangerous_count=dangerous_count
    )

    return {
        "apk_hash": apk_hash,
        "package_name": package_name,
        "app_name": app_name,
        "version_name": str(version_name) if version_name else "",
        "version_code": str(version_code) if version_code else "",
        "min_sdk": str(min_sdk) if min_sdk else "",
        "target_sdk": str(target_sdk) if target_sdk else "",
        "permissions": permissions,
        "dangerous_permissions": dangerous_found,
        "dangerous_count": dangerous_count,
        "activities": activities,
        "services": services,
        "receivers": receivers,
        "providers": providers,
        "certificate": certificate_data,
        "sensitive_apis": sensitive_apis_list,
        "sensitive_api_count": sensitive_api_count,
        "avg_string_entropy": round(avg_entropy, 4),
        "high_entropy_string_count": high_entropy_count,
        "string_count": len(strings)
    }


def extract_static_features(apk_path: str, static_feature_names: list) -> dict:
    """Extract binary feature vector matching TUANDROMD format.
    
    Returns dict mapping each feature name to 0 or 1.
    Used as input to the static ML model.
    """
    logger.info("Extracting static TUANDROMD features from APK", path=apk_path)
    try:
        a, d, dx = AnalyzeAPK(apk_path)
        
        # Extract permissions
        raw_permissions = set(a.get_permissions())
        permissions_short = set()
        for p in raw_permissions:
            p_clean = p
            for prefix in ["android.permission.", "com.android.", "com.google.android."]:
                if p_clean.startswith(prefix):
                    p_clean = p_clean[len(prefix):]
            permissions_short.add(p_clean.upper())

        # Extract API calls using cross-references
        api_calls_found = set()
        for method in dx.get_methods():
            for _, call, _ in method.get_xref_to():
                sig = f"{call.class_name}->{call.name}"
                api_calls_found.add(sig)

        # Build binary feature vector
        feature_vector = {}
        for feature_name in static_feature_names:
            if ";" not in feature_name and "/" not in feature_name:
                feature_vector[feature_name] = (
                    1 if feature_name in permissions_short else 0
                )
            elif "->" in feature_name and "L" in feature_name:
                feature_vector[feature_name] = (
                    1 if feature_name in api_calls_found else 0
                )
            else:
                feature_vector[feature_name] = 0

        return feature_vector

    except Exception as e:
        logger.warning("Androguard static feature extraction failed, returning zero vector", error=str(e))
        return {name: 0 for name in static_feature_names}

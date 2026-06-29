"""
ASTRA Signal Correlation Engine
Aggregates risk metrics from static analysis, ML models, AV reports, and certificate signatures.
"""

import re
import structlog

logger = structlog.get_logger()

# Constants
STATIC_ML_WEIGHT = 0.25
DYNAMIC_ML_WEIGHT = 0.25
VT_WEIGHT = 0.20
SANDBOX_WEIGHT = 0.15
SIGNATURE_WEIGHT = 0.15


def extract_c2_ips(processes_created: list) -> list:
    """Uses regex pattern matching to extract IPv4 addresses from spawned processes."""
    ip_pattern = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
    c2_ips = set()
    for proc in processes_created:
        for ip in ip_pattern.findall(proc):
            c2_ips.add(ip)
    return list(c2_ips)


def build_threat_summary(
    verdict: str, 
    risk_score: float, 
    confidence_level: str, 
    malware_family: str, 
    vt_report: dict, 
    sandbox_report: dict, 
    signature_verdict: str
) -> str:
    """Builds a human-readable one-line threat summary of the correlation analysis."""
    summary_parts = []
    
    if verdict in ["MALICIOUS", "SUSPICIOUS"]:
        family_name = malware_family if malware_family != "Benign" else "Malicious behavior"
        summary_parts.append(f"{family_name} detected with {confidence_level} confidence (Risk Score: {risk_score}/100)")
    else:
        summary_parts.append(f"Clean application (Risk Score: {risk_score}/100)")

    details = []
    
    # VirusTotal Detections
    if vt_report.get("found"):
        mal = vt_report.get("malicious_count", 0)
        harmless = vt_report.get("harmless_count", 0)
        undetected = vt_report.get("undetected_count", 0)
        suspicious = vt_report.get("suspicious_count", 0)
        total = mal + harmless + undetected + suspicious
        details.append(f"{mal}/{total} AV engines flagged")
        
    # Signature Verdict
    if signature_verdict == "TRUSTED":
        details.append("trusted certificate")
    elif signature_verdict == "SUSPICIOUS":
        details.append("suspicious certificate signature")
        
    # Sandbox MITRE Detections
    mitre_list = sandbox_report.get("mitre_attacks", [])
    if mitre_list:
        first_mitre = mitre_list[0]
        details.append(f"MITRE {first_mitre.get('id')} {first_mitre.get('description')} detected in sandbox")

    if details:
        threat_summary = f"{summary_parts[0]} — {', '.join(details)}"
    else:
        threat_summary = summary_parts[0]
        
    return threat_summary


def correlate(
    androguard_data: dict,
    ml_result: dict,
    static_ml_result: dict,
    vt_report: dict,
    sandbox_report: dict,
    signature_verdict: str
) -> dict:
    """Aggregates all threat signals to compute a final risk score (0-100) and threat verdict.
    
    Args:
        androguard_data: Dict returned by Androguard static analyzer.
        ml_result: Dict returned by the ML model inference engine.
        static_ml_result: Dict returned by the static RF model inference engine.
        vt_report: Dict returned by the VirusTotal AV query.
        sandbox_report: Dict returned by the VirusTotal sandbox behavior query.
        signature_verdict: String verdict matching "TRUSTED", "UNKNOWN", or "SUSPICIOUS".
        
    Returns:
        dict detailing aggregated signal scores, verdict, confidence, and IOCs.
    """
    logger.info("Starting signal correlation engine")

    # 1. Static ML Sub-score calculation
    static_ml_confidence = static_ml_result.get("confidence", 0.0)
    static_ml_class = static_ml_result.get("class_name", "Goodware")
    if static_ml_class == "Goodware":
        static_ml_score = (1.0 - static_ml_confidence) * 100.0
    else:
        static_ml_score = static_ml_confidence * 100.0

    # 2. Dynamic ML Sub-score calculation
    ml_confidence = ml_result.get("confidence", 0.0)
    ml_family = ml_result.get("class_name", "Benign")
    if ml_family == "Benign":
        dynamic_ml_score = (1.0 - ml_confidence) * 100.0
    else:
        dynamic_ml_score = ml_confidence * 100.0

    # 3. VirusTotal AV Sub-score calculation
    if not vt_report.get("found"):
        vt_score = 50.0  # Unknown, default to neutral risk
    else:
        malicious = vt_report.get("malicious_count", 0)
        harmless = vt_report.get("harmless_count", 0)
        undetected = vt_report.get("undetected_count", 0)
        suspicious = vt_report.get("suspicious_count", 0)
        total = malicious + harmless + undetected + suspicious
        
        if total == 0:
            vt_score = 50.0
        else:
            vt_score = (malicious / total) * 100.0

    # 4. Sandbox Sub-score calculation
    severity_score = sandbox_report.get("severity_score", 0)
    sandbox_score = min(severity_score * 10.0, 100.0)

    # 5. Signature Sub-score calculation
    if signature_verdict == "TRUSTED":
        signature_score = 0.0
    elif signature_verdict == "SUSPICIOUS":
        signature_score = 80.0
    else:
        signature_score = 40.0  # UNKNOWN default

    # 6. Final Risk Score Computation
    risk_score = (
        static_ml_score * STATIC_ML_WEIGHT +
        dynamic_ml_score * DYNAMIC_ML_WEIGHT +
        vt_score * VT_WEIGHT +
        sandbox_score * SANDBOX_WEIGHT +
        signature_score * SIGNATURE_WEIGHT
    )
    risk_score = round(risk_score, 1)

    # 7. Verdict Determination
    if risk_score >= 70.0:
        verdict = "MALICIOUS"
    elif risk_score >= 40.0:
        verdict = "SUSPICIOUS"
    elif risk_score >= 20.0:
        verdict = "LOW RISK"
    else:
        verdict = "CLEAN"

    # 8. Confidence Level Agreement Counting (score > 50 flags malicious)
    flagged_signals = 0
    if static_ml_score > 50.0:
        flagged_signals += 1
    if dynamic_ml_score > 50.0:
        flagged_signals += 1
    if vt_score > 50.0:
        flagged_signals += 1
    if sandbox_score > 50.0:
        flagged_signals += 1
    if signature_score > 50.0:
        flagged_signals += 1

    if flagged_signals >= 4:
        confidence_level = "HIGH"
    elif flagged_signals == 3:
        confidence_level = "MEDIUM"
    elif flagged_signals == 2:
        confidence_level = "LOW"
    else:
        confidence_level = "INSUFFICIENT DATA"

    # Model agreement determination
    static_is_malicious = static_ml_class == "Malware"
    dynamic_is_malicious = ml_family != "Benign"
    if static_is_malicious and dynamic_is_malicious:
        model_agreement = "BOTH_MALICIOUS"
    elif not static_is_malicious and not dynamic_is_malicious:
        model_agreement = "BOTH_BENIGN"
    else:
        model_agreement = "DISAGREEMENT"

    # 9. IOC Extraction
    processes = sandbox_report.get("processes_created", [])
    c2_ips = extract_c2_ips(processes)
    
    iocs = {
        "apk_hash": androguard_data.get("apk_hash"),
        "cert_hash": androguard_data.get("certificate", {}).get("cert_hash"),
        "c2_ips": c2_ips,
        "domains": [],  # URL extraction from raw strings is not available (not part of androguard data payload)
        "mitre_technique_ids": [m.get("id") for m in sandbox_report.get("mitre_attacks", []) if m.get("id")],
        "malware_family": ml_family,
        "engine_detections": vt_report.get("engine_verdicts", [])
    }

    # 10. Dynamic Threat Summary
    threat_summary = build_threat_summary(
        verdict, 
        risk_score, 
        confidence_level, 
        ml_family, 
        vt_report, 
        sandbox_report, 
        signature_verdict
    )

    logger.info("Signal correlation completed", risk_score=risk_score, verdict=verdict, confidence=confidence_level)

    return {
        "risk_score": float(risk_score),
        "verdict": verdict,
        "confidence_level": confidence_level,
        "signal_scores": {
            "static_ml_score": round(float(static_ml_score), 2),
            "dynamic_ml_score": round(float(dynamic_ml_score), 2),
            "vt_score": round(float(vt_score), 2),
            "sandbox_score": round(float(sandbox_score), 2),
            "signature_score": round(float(signature_score), 2)
        },
        "malware_family": ml_family,
        "ml_confidence": round(float(ml_confidence), 4),
        "ml_explanation": ml_result.get("top_features", []),
        "mitre_attacks": sandbox_report.get("mitre_attacks", []),
        "iocs": iocs,
        "dangerous_permissions": androguard_data.get("dangerous_permissions", []),
        "sensitive_apis": androguard_data.get("sensitive_apis", []),
        "threat_summary": threat_summary,
        "model_agreement": model_agreement,
        "static_ml_result": static_ml_result,
        "static_ml_score": round(float(static_ml_score), 2),
        "dynamic_ml_score": round(float(dynamic_ml_score), 2)
    }

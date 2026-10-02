"""
ASTRA Signal Correlation Engine
Aggregates risk metrics from static analysis, ML models, AV reports, and certificate signatures.
"""

import re
import structlog

logger = structlog.get_logger()

# Constants - Base Weights
STATIC_ML_WEIGHT = 0.40
VT_WEIGHT = 0.30
SANDBOX_WEIGHT = 0.15
SIGNATURE_WEIGHT = 0.15


def extract_c2_ips(processes_created: list) -> list:
    """Uses regex pattern matching to extract IPv4 addresses from spawned processes."""
    if not processes_created:
        return []
    ip_pattern = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
    c2_ips = set()
    for proc in processes_created:
        if isinstance(proc, str):
            for ip in ip_pattern.findall(proc):
                c2_ips.add(ip)
    return list(c2_ips)


def build_threat_summary(
    verdict: str,
    risk_score: float,
    signals_used: int,
    signals_total: int,
    static_ml_result: dict,
    static_ml_score,
    vt_report: dict,
    vt_score,
    sandbox_report: dict,
    sandbox_score,
    signature_verdict: str,
    signature_score,
) -> str:
    """Builds a human-readable one-line threat summary of the correlation analysis."""
    if verdict in ["MALICIOUS", "SUSPICIOUS"]:
        lead = f"{verdict.capitalize()} application (risk {risk_score}/100)"
    elif verdict == "LOW RISK":
        lead = f"Low risk application (risk {risk_score}/100)"
    else:
        lead = f"Clean application (risk {risk_score}/100)"

    used_desc = []
    no_data_desc = []

    # 1. Static ML
    if static_ml_score is not None:
        cls_name = static_ml_result.get("class_name", "Unknown") if static_ml_result else "Unknown"
        conf = int(round(static_ml_result.get("confidence", 0.0) * 100)) if static_ml_result else 0
        used_desc.append(f"static ML says {cls_name} ({conf}%)")
    else:
        no_data_desc.append("static ML")

    # 2. VirusTotal
    if vt_score is not None:
        mal = vt_report.get("malicious_count", 0) if vt_report else 0
        harmless = vt_report.get("harmless_count", 0) if vt_report else 0
        undetected = vt_report.get("undetected_count", 0) if vt_report else 0
        total = mal + harmless + undetected
        used_desc.append(f"{mal}/{total} VirusTotal detections")
    else:
        no_data_desc.append("VirusTotal")

    # 3. Sandbox
    if sandbox_score is not None:
        sb_cnt = sandbox_report.get("sandbox_count", 0) if sandbox_report else 0
        sev = sandbox_report.get("severity_score", 0) if sandbox_report else 0
        used_desc.append(f"sandbox report ({sb_cnt} sandboxes, severity {sev})")
    else:
        no_data_desc.append("sandbox")

    # 4. Certificate
    if signature_score is not None:
        used_desc.append(f"{str(signature_verdict).lower()} certificate")
    else:
        no_data_desc.append("certificate")

    if signals_used > 0:
        summary = f"{lead}. Based on {signals_used} of {signals_total} signals: {', '.join(used_desc)}."
        if no_data_desc:
            summary += f" No data: {', '.join(no_data_desc)}."
    else:
        summary = f"{lead}. No data: {', '.join(no_data_desc)}."

    return summary


def correlate(
    androguard_data: dict,
    static_ml_result: dict,
    vt_report: dict,
    sandbox_report: dict,
    signature_verdict: str
) -> dict:
    """Aggregates all threat signals to compute a final risk score (0-100) and threat verdict.
    
    Args:
        androguard_data: Dict returned by Androguard static analyzer.
        static_ml_result: Dict returned by the static RF model inference engine.
        vt_report: Dict returned by the VirusTotal AV query.
        sandbox_report: Dict returned by the VirusTotal sandbox behavior query.
        signature_verdict: String verdict matching "TRUSTED", "UNKNOWN", or "SUSPICIOUS".
        
    Returns:
        dict detailing aggregated signal scores, verdict, confidence, and IOCs.
    """
    logger.info("Starting signal correlation engine")

    if not isinstance(androguard_data, dict):
        androguard_data = {}
    if not isinstance(static_ml_result, dict):
        static_ml_result = {}
    if not isinstance(vt_report, dict):
        vt_report = {}
    if not isinstance(sandbox_report, dict):
        sandbox_report = {}

    # 1. Static ML Sub-score calculation
    static_ml_class = static_ml_result.get("class_name")
    static_ml_confidence = static_ml_result.get("confidence")
    if static_ml_class is not None and static_ml_confidence is not None:
        if static_ml_class == "Goodware":
            static_ml_score = (1.0 - float(static_ml_confidence)) * 100.0
        else:
            static_ml_score = float(static_ml_confidence) * 100.0
    else:
        static_ml_score = None

    # 2. VirusTotal AV Sub-score calculation
    if (
        vt_report.get("found") is not True
        or vt_report.get("rate_limited") is True
        or vt_report.get("vt_unavailable") is True
    ):
        vt_score = None
    else:
        malicious = vt_report.get("malicious_count", 0)
        harmless = vt_report.get("harmless_count", 0)
        undetected = vt_report.get("undetected_count", 0)
        total = malicious + harmless + undetected
        if total == 0:
            vt_score = None
        else:
            vt_score = (malicious / total) * 100.0

    # 3. Sandbox Sub-score calculation
    if sandbox_report.get("sandbox_count", 0) == 0:
        sandbox_score = None
    else:
        severity_score = sandbox_report.get("severity_score", 0)
        sandbox_score = float(min(severity_score * 10.0, 100.0))

    # 4. Signature Sub-score calculation
    if signature_verdict == "TRUSTED":
        signature_score = 0.0
    elif signature_verdict == "SUSPICIOUS":
        signature_score = 80.0
    else:
        signature_score = None

    # 5. Final Risk Score Computation
    signals = [
        (static_ml_score, STATIC_ML_WEIGHT),
        (vt_score, VT_WEIGHT),
        (sandbox_score, SANDBOX_WEIGHT),
        (signature_score, SIGNATURE_WEIGHT),
    ]

    active_signals = [(s, w) for s, w in signals if s is not None]
    signals_used = len(active_signals)
    signals_total = 4

    if signals_used == 0:
        risk_score = 0.0
    else:
        total_score_weight = sum(s * w for s, w in active_signals)
        total_weight = sum(w for s, w in active_signals)
        risk_score = round(total_score_weight / total_weight, 1)

    # 6. Verdict Determination
    if risk_score >= 70.0:
        verdict = "MALICIOUS"
    elif risk_score >= 40.0:
        verdict = "SUSPICIOUS"
    elif risk_score >= 20.0:
        verdict = "LOW RISK"
    else:
        verdict = "CLEAN"

    # 7. Confidence Level Determination
    if signals_used == 0:
        confidence_level = "INSUFFICIENT DATA"
    elif signals_used == 1:
        confidence_level = "LOW"
    else:
        active_scores = [s for s, _ in active_signals]
        all_agree = all(s >= 50.0 for s in active_scores) or all(s < 50.0 for s in active_scores)
        if all_agree:
            confidence_level = "MEDIUM" if signals_used == 2 else "HIGH"
        else:
            confidence_level = "LOW"

    # 8. IOC Extraction
    processes = sandbox_report.get("processes_created", [])
    c2_ips = extract_c2_ips(processes)
    extracted_domains = (
        androguard_data.get("extracted_iocs", {})
        .get("network", {})
        .get("domains", [])
    )

    iocs = {
        "apk_hash": androguard_data.get("apk_hash"),
        "cert_hash": androguard_data.get("certificate", {}).get("cert_hash"),
        "c2_ips": c2_ips,
        "domains": extracted_domains,
        "mitre_technique_ids": [m.get("id") for m in sandbox_report.get("mitre_attacks", []) if m.get("id")],
        "malware_family": None,
        "engine_detections": vt_report.get("engine_verdicts", [])
    }

    # 9. Dynamic Threat Summary
    threat_summary = build_threat_summary(
        verdict=verdict,
        risk_score=risk_score,
        signals_used=signals_used,
        signals_total=signals_total,
        static_ml_result=static_ml_result,
        static_ml_score=static_ml_score,
        vt_report=vt_report,
        vt_score=vt_score,
        sandbox_report=sandbox_report,
        sandbox_score=sandbox_score,
        signature_verdict=signature_verdict,
        signature_score=signature_score,
    )

    logger.info(
        "Signal correlation completed",
        risk_score=risk_score,
        verdict=verdict,
        confidence=confidence_level,
        signals_used=signals_used
    )

    return {
        "risk_score": float(risk_score),
        "verdict": verdict,
        "confidence_level": confidence_level,
        "signals_used": signals_used,
        "signals_total": signals_total,
        "signal_scores": {
            "static_ml_score": round(float(static_ml_score), 2) if static_ml_score is not None else None,
            "vt_score": round(float(vt_score), 2) if vt_score is not None else None,
            "sandbox_score": round(float(sandbox_score), 2) if sandbox_score is not None else None,
            "signature_score": round(float(signature_score), 2) if signature_score is not None else None,
        },
        "malware_family": None,
        "ml_confidence": None,
        "ml_explanation": [],
        "mitre_attacks": sandbox_report.get("mitre_attacks", []),
        "iocs": iocs,
        "dangerous_permissions": androguard_data.get("dangerous_permissions", []),
        "sensitive_apis": androguard_data.get("sensitive_apis", []),
        "threat_summary": threat_summary,
        "static_ml_result": static_ml_result,
        "static_ml_score": round(float(static_ml_score), 2) if static_ml_score is not None else None,
    }

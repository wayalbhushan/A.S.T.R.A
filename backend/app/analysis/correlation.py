"""
ASTRA Signal Correlation Engine
Aggregates risk metrics from static analysis, ML models, AV reports, and certificate signatures.
"""

import os
import re
import structlog

logger = structlog.get_logger()

# Constants - Base Weights
STATIC_ML_WEIGHT = 0.40
VT_WEIGHT = 0.30
SANDBOX_WEIGHT = 0.15
SIGNATURE_WEIGHT = 0.15

HIGH_RISK_CATEGORIES = {
    "trojan", "ransomware", "backdoor", "banker", "spyware",
    "stealer", "worm", "virus", "dropper", "downloader", "rat"
}


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


DEFAULT_NONE_IMPERSONATION = {
    "verdict": "NONE",
    "confidence": None,
    "brand_id": None,
    "brand_name": None,
    "reasons": [],
    "evidence": {}
}


def _safe_int(val, default=0) -> int:
    try:
        return int(val) if val is not None else default
    except (ValueError, TypeError):
        return default


def vt_floor(vt_report: dict, signature_verdict: str, impersonation: dict = None) -> dict | None:
    """Computes VirusTotal evidence floor based on engine detections and threat category.
    Never raises; wrong types count as 0.
    """
    if not isinstance(vt_report, dict):
        return None

    status = vt_report.get("status")
    if status is not None:
        if status != "ok":
            return None
    else:
        if not (vt_report.get("found") is True and not vt_report.get("rate_limited") and not vt_report.get("vt_unavailable")):
            return None

    m = _safe_int(vt_report.get("malicious_count"), 0)
    total_raw = vt_report.get("total_engines")
    if isinstance(total_raw, int) and total_raw > 0:
        total = total_raw
    else:
        susp = _safe_int(vt_report.get("suspicious_count"), 0)
        harm = _safe_int(vt_report.get("harmless_count"), 0)
        undet = _safe_int(vt_report.get("undetected_count"), 0)
        total = m + susp + harm + undet

    threat = (vt_report.get("intel") or {}).get("threat") or {}
    if not isinstance(threat, dict):
        threat = {}
    cat_val = threat.get("category")
    category = str(cat_val).lower() if cat_val else None
    label = threat.get("label")

    known_signer = (signature_verdict == "TRUSTED") or (
        isinstance(impersonation, dict) and impersonation.get("verdict") == "GENUINE"
    )

    vt_floor_malicious_engines = int(os.environ.get("VT_FLOOR_MALICIOUS_ENGINES", 10))
    vt_floor_category_engines = int(os.environ.get("VT_FLOOR_CATEGORY_ENGINES", 5))
    vt_floor_suspicious_engines = int(os.environ.get("VT_FLOOR_SUSPICIOUS_ENGINES", 3))
    vt_floor_malicious = float(os.environ.get("VT_FLOOR_MALICIOUS", 85))
    vt_floor_suspicious = float(os.environ.get("VT_FLOOR_SUSPICIOUS", 45))

    is_malicious = (m >= vt_floor_malicious_engines) or (
        category in HIGH_RISK_CATEGORIES and m >= vt_floor_category_engines
    )

    if is_malicious:
        return {
            "floor": vt_floor_malicious,
            "tier": "malicious",
            "malicious": m,
            "total": total,
            "label": label,
            "category": category,
        }
    elif m >= vt_floor_suspicious_engines and not known_signer:
        return {
            "floor": vt_floor_suspicious,
            "tier": "suspicious",
            "malicious": m,
            "total": total,
            "label": label,
            "category": category,
        }
    return None


def build_evidence_sentence(
    static_ml_result: dict,
    static_ml_score,
    vt_report: dict,
    vt_score,
    sandbox_report: dict,
    sandbox_score,
    signature_verdict: str,
    signature_score,
) -> str:
    """Builds the evidence sentence from per-signal scores in fixed order:
    static ML, VirusTotal, sandbox, certificate.
    """
    phrases = []
    missing_names = []

    # 1. static ML
    if static_ml_score is not None:
        cls_name = static_ml_result.get("class_name", "Unknown") if isinstance(static_ml_result, dict) else "Unknown"
        conf_val = static_ml_result.get("confidence", 0.0) if isinstance(static_ml_result, dict) else 0.0
        conf = int(round(conf_val * 100)) if (conf_val is not None and conf_val <= 1.0) else int(round(conf_val or 0))
        phrases.append(f"static ML says {cls_name} ({conf}%)")
    else:
        missing_names.append("static ML")

    # 2. VirusTotal
    if vt_score is not None:
        vt_ratio = vt_report.get("detection_ratio") if isinstance(vt_report, dict) else None
        if vt_ratio:
            phrases.append(f"{vt_ratio} VirusTotal detections")
        else:
            phrases.append(f"VirusTotal score {round(vt_score, 1)}")
    else:
        missing_names.append("VirusTotal")

    # 3. sandbox
    if sandbox_score is not None:
        sb_cnt = sandbox_report.get("sandbox_count", 0) if isinstance(sandbox_report, dict) else 0
        sev = sandbox_report.get("severity_score", 0) if isinstance(sandbox_report, dict) else 0
        phrases.append(f"sandbox report ({sb_cnt} sandboxes, severity {sev})")
    else:
        missing_names.append("sandbox")

    # 4. certificate
    if signature_score is not None:
        if signature_verdict == "TRUSTED":
            phrases.append("signer is a known bank certificate")
        elif signature_verdict == "SUSPICIOUS":
            phrases.append("signer flagged as suspicious")
        else:
            phrases.append(f"signer {str(signature_verdict).lower()}")
    else:
        missing_names.append("certificate")

    n = len(phrases)
    if n == 0:
        return "No usable signals were available."

    sentence = f"Based on {n} of 4 signals: {', '.join(phrases)}."
    if missing_names:
        sentence += f" No data: {', '.join(missing_names)}."

    return sentence


def build_threat_summary(
    verdict: str,
    risk_score: float,
    static_ml_result: dict,
    static_ml_score,
    vt_report: dict,
    vt_score,
    sandbox_report: dict,
    sandbox_score,
    signature_verdict: str,
    signature_score,
    impersonation: dict = None,
    strong_corroboration: bool = False,
    signals_used: int = 0,
    signals_total: int = 4,
    risk_floor_applied: float = None,
    risk_floor_reason: str = None,
    vt_floor_info: dict = None,
) -> str:
    """Builds a human-readable threat summary of the correlation analysis."""
    evidence_sentence = build_evidence_sentence(
        static_ml_result=static_ml_result,
        static_ml_score=static_ml_score,
        vt_report=vt_report,
        vt_score=vt_score,
        sandbox_report=sandbox_report,
        sandbox_score=sandbox_score,
        signature_verdict=signature_verdict,
        signature_score=signature_score,
    )

    imp = impersonation or {}
    if not isinstance(imp, dict):
        imp = {}

    evidence = imp.get("evidence") or {}
    corr = set(evidence.get("corroboration") or [])
    is_strong = strong_corroboration or ("exfil" in corr or "other_brand_cert" in corr)

    imp_verdict = imp.get("verdict")

    # Safe extraction of VT malicious and total
    vt_dict = vt_report if isinstance(vt_report, dict) else {}
    if vt_floor_info and "malicious" in vt_floor_info and "total" in vt_floor_info:
        vt_m = vt_floor_info["malicious"]
        vt_tot = vt_floor_info["total"]
    else:
        vt_m = _safe_int(vt_dict.get("malicious_count"), 0)
        tot_raw = vt_dict.get("total_engines")
        if isinstance(tot_raw, int) and tot_raw > 0:
            vt_tot = tot_raw
        else:
            vt_tot = vt_m + _safe_int(vt_dict.get("suspicious_count"), 0) + _safe_int(vt_dict.get("harmless_count"), 0) + _safe_int(vt_dict.get("undetected_count"), 0)

    # 1. Lead sentence
    if imp_verdict == "IMPERSONATION":
        brand_name = imp.get("brand_name") or "banking"
        if is_strong:
            lead = f"Likely fake {brand_name} app (risk {risk_score}/100)."
        else:
            lead = f"Possible fake {brand_name} app (risk {risk_score}/100)."

        reasons_list = imp.get("reasons") or []
        reasons_text = (" ".join(str(r) for r in reasons_list[:2])) if reasons_list else ""
        if reasons_text:
            lead_sentence = f"{lead} {reasons_text}"
        else:
            lead_sentence = lead
    elif vt_floor_info is not None:
        vt_lbl = vt_floor_info.get("label")
        lbl_str = f", label {vt_lbl}" if vt_lbl else ""
        if vt_floor_info.get("tier") == "malicious":
            lead_sentence = f"Flagged as malicious by VirusTotal ({vt_m} of {vt_tot} engines{lbl_str})."
        else:
            lead_sentence = f"Flagged by {vt_m} of {vt_tot} VirusTotal engines{lbl_str}."
    else:
        if verdict in ["MALICIOUS", "SUSPICIOUS"]:
            lead_sentence = f"{verdict.capitalize()} application (risk {risk_score}/100)."
        elif verdict == "LOW RISK":
            lead_sentence = f"Low risk application (risk {risk_score}/100)."
        else:
            lead_sentence = f"Clean application (risk {risk_score}/100)."

    # 2. VirusTotal also flags (only for IMPERSONATION when vt_floor exists)
    vt_also_sentence = None
    if imp_verdict == "IMPERSONATION" and vt_floor_info is not None:
        vt_also_sentence = f"VirusTotal also flags this file ({vt_m} of {vt_tot} engines)."

    # 3. Advisory or Caveat
    advisory_or_caveat = None
    if verdict in ["CLEAN", "LOW RISK"] and risk_floor_applied is None:
        vt_st = vt_dict.get("status")
        if vt_st == "ok":
            if vt_m in (1, 2):
                advisory_or_caveat = f"{vt_m} of {vt_tot} VirusTotal engines flag this file. Single detections are often false positives, but review it."
        else:
            status_map = {
                "not_found": "VirusTotal has no record of this file",
                "disabled": "lookup is turned off",
                "rate_limited": "quota reached",
                "unavailable": "it could not be reached",
            }
            reason_phrase = status_map.get(vt_st, "no result")
            advisory_or_caveat = f"Not checked against VirusTotal ({reason_phrase}). A new or targeted sample may not be detected yet."

    # 4. Floor sentence
    floor_sentence = None
    if risk_floor_applied is not None:
        floor_val = int(risk_floor_applied) if risk_floor_applied == int(risk_floor_applied) else risk_floor_applied
        if imp_verdict == "IMPERSONATION":
            has_imp = bool(risk_floor_reason and "impersonation" in risk_floor_reason)
            has_vt = bool(risk_floor_reason and "virustotal" in risk_floor_reason)
            if has_imp and has_vt:
                floor_sentence = f"The risk score was raised to {floor_val} by the impersonation finding and VirusTotal detections."
            elif has_vt:
                floor_sentence = f"The risk score was raised to {floor_val} by VirusTotal detections."
            elif has_imp:
                floor_sentence = f"The risk score was raised to {floor_val} by the impersonation finding."
            else:
                floor_sentence = f"The risk score was raised to {floor_val} by an evidence rule."
        else:
            floor_sentence = f"The risk score was raised to {floor_val} by VirusTotal detections."

    # 5. Last sentence (claim or key-rotation)
    last_sentence = None
    if imp_verdict == "IMPERSONATION" and not is_strong:
        last_sentence = "The signer differs from the key ASTRA has on file, and a legitimate app can also change keys, so verify before acting."
    elif imp_verdict == "UNVERIFIED_CLAIM":
        brand_name = imp.get("brand_name") or "a known brand"
        last_sentence = f"Claims to be {brand_name}, but its signer is not in ASTRA's registry. Compare it with the official app."

    components = [lead_sentence, evidence_sentence]
    if vt_also_sentence:
        components.append(vt_also_sentence)
    if advisory_or_caveat:
        components.append(advisory_or_caveat)
    if floor_sentence:
        components.append(floor_sentence)
    if last_sentence:
        components.append(last_sentence)

    return " ".join(c.strip() for c in components if c and c.strip())


def correlate(
    androguard_data: dict,
    static_ml_result: dict,
    vt_report: dict,
    sandbox_report: dict,
    signature_verdict: str,
    impersonation: dict = None
) -> dict:
    """Aggregates all threat signals to compute a final risk score (0-100) and threat verdict.
    
    Args:
        androguard_data: Dict returned by Androguard static analyzer.
        static_ml_result: Dict returned by the static RF model inference engine.
        vt_report: Dict returned by the VirusTotal AV query.
        sandbox_report: Dict returned by the VirusTotal sandbox behavior query.
        signature_verdict: String verdict matching "TRUSTED", "UNKNOWN", or "SUSPICIOUS".
        impersonation: Dict returned by brand impersonation assessment (optional).
        
    Returns:
        dict detailing aggregated signal scores, verdict, confidence, impersonation, and IOCs.
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

    # 6. Base Verdict Determination
    if risk_score >= 70.0:
        verdict = "MALICIOUS"
    elif risk_score >= 40.0:
        verdict = "SUSPICIOUS"
    elif risk_score >= 20.0:
        verdict = "LOW RISK"
    else:
        verdict = "CLEAN"

    # 7. Confidence Level Determination (sides)
    if signals_used == 0:
        confidence_level = "INSUFFICIENT DATA"
    elif signals_used == 1:
        confidence_level = "LOW"
    else:
        active_scores = [s for s, _ in active_signals]
        any_uncertain = any(25.0 <= s < 50.0 for s in active_scores)
        has_clean = any(s < 25.0 for s in active_scores)
        has_malicious = any(s >= 50.0 for s in active_scores)

        if any_uncertain or (has_clean and has_malicious):
            confidence_level = "LOW"
        elif all(s < 25.0 for s in active_scores) or all(s >= 50.0 for s in active_scores):
            confidence_level = "MEDIUM" if signals_used == 2 else "HIGH"
        else:
            confidence_level = "LOW"

    # 7.5. Evidence Floors
    floors = []
    imp = impersonation or {}
    if not isinstance(imp, dict):
        imp = {}
    imp_to_return = imp if imp else DEFAULT_NONE_IMPERSONATION
    strong_corroboration = False

    if imp.get("verdict") == "IMPERSONATION":
        evidence = imp.get("evidence") or {}
        corr = set(evidence.get("corroboration") or [])
        strong_corroboration = "exfil" in corr or "other_brand_cert" in corr
        imp_floor = 75.0 if strong_corroboration else 45.0
        floors.append((imp_floor, "impersonation"))

    vt_floor_info = vt_floor(vt_report, signature_verdict, imp)
    if vt_floor_info is not None:
        floors.append((vt_floor_info["floor"], "virustotal"))

    base_score = risk_score
    if floors:
        final_floor = max(val for val, _ in floors)
        risk_score = max(base_score, final_floor)
        applied_reasons = [reason for val, reason in floors if val > base_score]
        if applied_reasons:
            risk_floor_applied = final_floor
            risk_floor_reason = "+".join(sorted(applied_reasons))
        else:
            risk_floor_applied = None
            risk_floor_reason = None
    else:
        final_floor = None
        risk_floor_applied = None
        risk_floor_reason = None

    # Recompute verdict from the final score with the same thresholds
    if risk_score >= 70.0:
        verdict = "MALICIOUS"
    elif risk_score >= 40.0:
        verdict = "SUSPICIOUS"
    elif risk_score >= 20.0:
        verdict = "LOW RISK"
    else:
        verdict = "CLEAN"

    # Adjust confidence level with floor rules (never lower confidence)
    CONF_RANK = {"INSUFFICIENT DATA": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
    RANK_TO_CONF = {0: "INSUFFICIENT DATA", 1: "LOW", 2: "MEDIUM", 3: "HIGH"}

    current_rank = CONF_RANK.get(confidence_level, 0)
    target_rank = current_rank

    if imp.get("verdict") == "IMPERSONATION":
        target_rank = max(target_rank, 3 if strong_corroboration else 2)

    if vt_floor_info is not None:
        if vt_floor_info["tier"] == "malicious":
            target_rank = max(target_rank, 3)
        elif vt_floor_info["tier"] == "suspicious":
            target_rank = max(target_rank, 2)

    confidence_level = RANK_TO_CONF[target_rank]

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

    # 9. Dynamic Threat Summary (built AFTER override)
    if signals_used == 0 and risk_floor_applied is None:
        verdict = "INCONCLUSIVE"
        risk_score = 0.0
        confidence_level = "INSUFFICIENT DATA"
        threat_summary = "No verdict: no usable signals were available."
    else:
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
            impersonation=imp,
            strong_corroboration=strong_corroboration,
            risk_floor_applied=risk_floor_applied,
            risk_floor_reason=risk_floor_reason,
            vt_floor_info=vt_floor_info,
        )

    logger.info(
        "Signal correlation completed",
        risk_score=risk_score,
        verdict=verdict,
        confidence=confidence_level,
        signals_used=signals_used,
        risk_floor_applied=risk_floor_applied,
        risk_floor_reason=risk_floor_reason,
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
        "impersonation": imp_to_return,
        "risk_floor_applied": risk_floor_applied,
        "risk_floor_reason": risk_floor_reason,
    }


def run_tests():
    """Runs test cases a through j and prints PASS/FAIL per line with actual values."""
    androguard_data = {"extracted_iocs": {"network": {"domains": []}}}
    no_sandbox = {"sandbox_count": 0}

    # a. REAL REPLAY: static Goodware 0.6467, vt {status ok, found True, malicious_count 28, suspicious_count 0,
    #    harmless_count 0, undetected_count 39, detection_ratio "28/67", intel {threat {category "trojan", label "trojan.metasploit/fnaa"}}},
    #    sandbox {sandbox_count 3, severity_score 0}, UNKNOWN, no impersonation:
    #    85.0, MALICIOUS, HIGH, floor 85, reason "virustotal", summary starts "Flagged as malicious by VirusTotal (28 of 67".
    static_a = {"class_name": "Goodware", "confidence": 0.6467}
    vt_a = {
        "status": "ok",
        "found": True,
        "malicious_count": 28,
        "suspicious_count": 0,
        "harmless_count": 0,
        "undetected_count": 39,
        "detection_ratio": "28/67",
        "intel": {
            "threat": {
                "category": "trojan",
                "label": "trojan.metasploit/fnaa"
            }
        }
    }
    sandbox_a = {"sandbox_count": 3, "severity_score": 0}
    res_a = correlate(androguard_data, static_a, vt_a, sandbox_a, "UNKNOWN", impersonation=None)
    pass_a = (
        res_a["risk_score"] == 85.0 and
        res_a["verdict"] == "MALICIOUS" and
        res_a["confidence_level"] == "HIGH" and
        res_a["risk_floor_applied"] == 85.0 and
        res_a["risk_floor_reason"] == "virustotal" and
        res_a["threat_summary"].startswith("Flagged as malicious by VirusTotal (28 of 67")
    )
    print(f"{'PASS' if pass_a else 'FAIL'} a: score={res_a['risk_score']}, verdict={res_a['verdict']}, confidence={res_a['confidence_level']}, floor={res_a['risk_floor_applied']}, reason={res_a['risk_floor_reason']}, summary={res_a['threat_summary'][:60]}")

    # b. 12 detections, no category: malicious tier.
    vt_b = {"status": "ok", "found": True, "malicious_count": 12, "undetected_count": 50}
    floor_b = vt_floor(vt_b, "UNKNOWN", None)
    pass_b = floor_b is not None and floor_b.get("tier") == "malicious"
    print(f"{'PASS' if pass_b else 'FAIL'} b: tier={floor_b.get('tier') if floor_b else None}, floor={floor_b.get('floor') if floor_b else None}")

    # c. category trojan with 5 detections: malicious tier. Category trojan with 4: suspicious tier.
    vt_c1 = {"status": "ok", "found": True, "malicious_count": 5, "undetected_count": 50, "intel": {"threat": {"category": "trojan"}}}
    floor_c1 = vt_floor(vt_c1, "UNKNOWN", None)
    vt_c2 = {"status": "ok", "found": True, "malicious_count": 4, "undetected_count": 50, "intel": {"threat": {"category": "trojan"}}}
    floor_c2 = vt_floor(vt_c2, "UNKNOWN", None)
    pass_c = (
        floor_c1 is not None and floor_c1.get("tier") == "malicious" and
        floor_c2 is not None and floor_c2.get("tier") == "suspicious"
    )
    print(f"{'PASS' if pass_c else 'FAIL'} c: c1_tier={floor_c1.get('tier') if floor_c1 else None}, c2_tier={floor_c2.get('tier') if floor_c2 else None}")

    # d. 3 detections, no category, UNKNOWN: 45.0, SUSPICIOUS, confidence at least MEDIUM.
    static_d = {"class_name": "Goodware", "confidence": 0.90}
    vt_d = {"status": "ok", "found": True, "malicious_count": 3, "undetected_count": 60}
    res_d = correlate(androguard_data, static_d, vt_d, no_sandbox, "UNKNOWN", impersonation=None)
    pass_d = (
        res_d["risk_score"] == 45.0 and
        res_d["verdict"] == "SUSPICIOUS" and
        res_d["confidence_level"] in ["MEDIUM", "HIGH"]
    )
    print(f"{'PASS' if pass_d else 'FAIL'} d: score={res_d['risk_score']}, verdict={res_d['verdict']}, confidence={res_d['confidence_level']}, floor={res_d['risk_floor_applied']}, reason={res_d['risk_floor_reason']}")

    # e. 3 detections with TRUSTED: no floor. 12 detections with TRUSTED: malicious tier still applies.
    vt_e1 = {"status": "ok", "found": True, "malicious_count": 3, "undetected_count": 60}
    floor_e1 = vt_floor(vt_e1, "TRUSTED", None)
    vt_e2 = {"status": "ok", "found": True, "malicious_count": 12, "undetected_count": 50}
    floor_e2 = vt_floor(vt_e2, "TRUSTED", None)
    pass_e = floor_e1 is None and floor_e2 is not None and floor_e2.get("tier") == "malicious"
    print(f"{'PASS' if pass_e else 'FAIL'} e: floor_e1={floor_e1}, floor_e2_tier={floor_e2.get('tier') if floor_e2 else None}")

    # f. 1 detection (undetected 65): no floor, the advisory sentence is present, verdict unchanged.
    static_f = {"class_name": "Goodware", "confidence": 0.90}
    vt_f = {"status": "ok", "found": True, "malicious_count": 1, "undetected_count": 65}
    res_f = correlate(androguard_data, static_f, vt_f, no_sandbox, "UNKNOWN", impersonation=None)
    pass_f = (
        res_f["risk_floor_applied"] is None and
        "1 of 66 VirusTotal engines flag this file. Single detections are often false positives, but review it." in res_f["threat_summary"] and
        res_f["verdict"] == "CLEAN"
    )
    print(f"{'PASS' if pass_f else 'FAIL'} f: floor={res_f['risk_floor_applied']}, verdict={res_f['verdict']}, advisory_present={'1 of 66' in res_f['threat_summary']}")

    # g. VT not_found, static Goodware 0.87: CLEAN, caveat sentence present.
    static_g = {"class_name": "Goodware", "confidence": 0.87}
    vt_g = {"status": "not_found", "found": False}
    res_g = correlate(androguard_data, static_g, vt_g, no_sandbox, "UNKNOWN", impersonation=None)
    caveat_text = "Not checked against VirusTotal (VirusTotal has no record of this file). A new or targeted sample may not be detected yet."
    pass_g = (
        res_g["verdict"] == "CLEAN" and
        caveat_text in res_g["threat_summary"]
    )
    print(f"{'PASS' if pass_g else 'FAIL'} g: verdict={res_g['verdict']}, caveat_present={caveat_text in res_g['threat_summary']}")

    # h. malicious-tier VT plus weak impersonation (lure only): 85.0,
    #    reason "impersonation+virustotal", summary contains "by the impersonation finding and VirusTotal detections".
    static_h = {"class_name": "Goodware", "confidence": 0.70}
    vt_h = {
        "status": "ok",
        "found": True,
        "malicious_count": 28,
        "undetected_count": 39,
        "intel": {"threat": {"category": "trojan"}}
    }
    imp_h = {
        "verdict": "IMPERSONATION",
        "confidence": "MEDIUM",
        "brand_id": "sbi",
        "brand_name": "State Bank of India",
        "reasons": [
            "App name 'SBI Update' matches State Bank of India (keyword 'sbi').",
            "Signing certificate is not one of the known State Bank of India certificates.",
            "Contains lure word 'update'."
        ],
        "evidence": {"corroboration": ["lure"]}
    }
    res_h = correlate(androguard_data, static_h, vt_h, no_sandbox, "UNKNOWN", impersonation=imp_h)
    target_str = "by the impersonation finding and VirusTotal detections"
    pass_h = (
        res_h["risk_score"] == 85.0 and
        res_h["risk_floor_reason"] == "impersonation+virustotal" and
        target_str in res_h["threat_summary"]
    )
    print(f"{'PASS' if pass_h else 'FAIL'} h: score={res_h['risk_score']}, reason={res_h['risk_floor_reason']}, summary_has_target={target_str in res_h['threat_summary']}")

    # i. Confidence: static Goodware 0.6467 (35.33) with VT malicious 2 of 5 (40.0): confidence LOW.
    #    Static Goodware 0.87, VT 0/66, sandbox 2 sandboxes severity 0, TRUSTED: still HIGH.
    static_i1 = {"class_name": "Goodware", "confidence": 0.6467}
    vt_i1 = {"status": "ok", "found": True, "malicious_count": 2, "undetected_count": 3, "harmless_count": 0}
    res_i1 = correlate(androguard_data, static_i1, vt_i1, no_sandbox, "UNKNOWN", impersonation=None)
    
    static_i2 = {"class_name": "Goodware", "confidence": 0.87}
    vt_i2 = {"status": "ok", "found": True, "malicious_count": 0, "undetected_count": 66, "harmless_count": 0}
    sandbox_i2 = {"sandbox_count": 2, "severity_score": 0}
    res_i2 = correlate(androguard_data, static_i2, vt_i2, sandbox_i2, "TRUSTED", impersonation=None)
    pass_i = res_i1["confidence_level"] == "LOW" and res_i2["confidence_level"] == "HIGH"
    print(f"{'PASS' if pass_i else 'FAIL'} i: i1_conf={res_i1['confidence_level']}, i2_conf={res_i2['confidence_level']}")

    # j. Regression: re-run every earlier scoring case. Scores and verdicts
    #    must be unchanged EXCEPT this one: static Malware 0.95, VT 50 malicious and 16 undetected,
    #    sandbox severity 5, was 80.3 and is now 85.0 (VT floor applies).
    #    The lure-only impersonation case with the same VT numbers stays at 86.8.
    #    Also check an empty vt report, empty dicts and None inputs do not raise.
    static_malware = {"class_name": "Malware", "confidence": 0.95}
    vt_50_16 = {"status": "ok", "found": True, "malicious_count": 50, "undetected_count": 16, "harmless_count": 0}
    sandbox_sev5 = {"sandbox_count": 1, "severity_score": 5}
    res_j_changed = correlate(androguard_data, static_malware, vt_50_16, sandbox_sev5, "UNKNOWN", impersonation=None)
    res_j_lure = correlate(androguard_data, static_malware, vt_50_16, no_sandbox, "UNKNOWN", impersonation=imp_h)

    # Empty and None inputs test
    res_empty_vt = correlate(androguard_data, static_malware, {}, no_sandbox, "UNKNOWN")
    res_empty_all = correlate({}, {}, {}, {}, "UNKNOWN")
    res_none_imp = correlate(None, None, None, None, None, impersonation=None)

    # Earlier impersonation regression cases from test_c2b
    static_goodware = {"class_name": "Goodware", "confidence": 0.87}
    no_vt = {"found": False}
    imp_exfil = {
        "verdict": "IMPERSONATION", "confidence": "HIGH", "brand_id": "sbi", "brand_name": "State Bank of India",
        "reasons": ["SBI Fake match.", "Unknown cert.", "Telegram token."], "evidence": {"corroboration": ["exfil", "lure"]}
    }
    r_exfil = correlate(androguard_data, static_goodware, no_vt, no_sandbox, "UNKNOWN", impersonation=imp_exfil)
    
    imp_unverified = {
        "verdict": "UNVERIFIED_CLAIM", "confidence": "LOW", "brand_id": "cbi", "brand_name": "Central Bank of India",
        "reasons": ["Cent Digi Pay match.", "Signer not in registry."], "evidence": {"corroboration": []}
    }
    r_unver = correlate(androguard_data, static_goodware, no_vt, no_sandbox, "UNKNOWN", impersonation=imp_unverified)

    pass_j = (
        res_j_changed["risk_score"] == 85.0 and res_j_changed["verdict"] == "MALICIOUS" and
        res_j_lure["risk_score"] == 86.8 and res_j_lure["verdict"] == "MALICIOUS" and
        r_exfil["risk_score"] == 75.0 and r_exfil["verdict"] == "MALICIOUS" and
        r_unver["risk_score"] == 13.0 and r_unver["verdict"] == "CLEAN" and
        r_unver["threat_summary"].endswith("Compare it with the official app.") and
        res_empty_vt is not None and res_empty_all is not None and res_none_imp is not None
    )
    print(f"{'PASS' if pass_j else 'FAIL'} j: changed_score={res_j_changed['risk_score']} (expected 85.0), lure_score={res_j_lure['risk_score']} (expected 86.8), exfil_score={r_exfil['risk_score']} (expected 75.0), unver_score={r_unver['risk_score']} (expected 13.0)")


if __name__ == "__main__":
    run_tests()

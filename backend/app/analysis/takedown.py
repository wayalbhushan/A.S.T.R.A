"""
ASTRA Takedown Evidence Pack Generator
Turns a stored scan record into a structured takedown evidence pack,
containing technical indicators, sample metadata, and draft abuse
and incident reporting notices for impacted entities and service providers.
Fully offline analysis: no WHOIS or network lookups.
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse
import structlog

logger = structlog.get_logger()

# Safe fallback contact channels in case filesystem json is missing
DEFAULT_CHANNELS = {
    "telegram": {
        "label": "Telegram abuse team",
        "channel": "abuse@telegram.org",
        "verified": False,
    },
    "discord": {
        "label": "Discord Trust and Safety",
        "channel": "Discord abuse report form (find the current URL on discord.com)",
        "verified": False,
    },
    "firebase_google": {
        "label": "Google Cloud / Firebase abuse team",
        "channel": "Google Cloud abuse report form (find the current URL in Google Cloud support)",
        "verified": False,
    },
    "cert_in": {
        "label": "CERT-In",
        "channel": "incident@cert-in.org.in",
        "verified": False,
    },
    "i4c_ncrp": {
        "label": "I4C / National Cyber Crime Reporting Portal",
        "channel": "cybercrime.gov.in, helpline 1930",
        "verified": False,
    },
    "bank": {
        "label": "Impacted bank fraud and security team",
        "channel": "The bank's official fraud reporting contact",
        "verified": False,
    },
}


def _load_channels() -> Dict[str, Dict[str, Any]]:
    """Loads takedown contact channels from takedown_channels.json."""
    candidates = [
        Path(__file__).resolve().parent.parent.parent / "ml" / "takedown_channels.json",
        Path(__file__).resolve().parent.parent / "ml" / "takedown_channels.json",
        Path("/app/ml/takedown_channels.json"),
    ]
    for p in candidates:
        if p.exists():
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    channels = data.get("channels")
                    if isinstance(channels, dict):
                        return channels
            except Exception as e:
                logger.warning("takedown_channels_load_failed", path=str(p), error=str(e))
    return DEFAULT_CHANNELS


def mask_secret(s: Optional[str], keep: int = 4) -> str:
    """Returns the first `keep` characters of a secret followed by '****'.
    Returns an empty string for empty or None input.
    """
    if not s:
        return ""
    val = str(s)
    if len(val) <= keep:
        return val + "****"
    return val[:keep] + "****"


def defang(s: Optional[str]) -> str:
    """Defangs a URL, IP, or hostname string by replacing http(s) schemes
    with hxxp(s) and replacing '.' with '[.]'. Safe on None.
    """
    if not s:
        return ""
    val = str(s).replace("https://", "hxxps://").replace("http://", "hxxp://")
    return val.replace(".", "[.]")


def is_eligible(scan: Optional[dict]) -> Tuple[bool, str]:
    """Determines whether a scan qualifies for a takedown evidence pack.
    Returns (True, 'Eligible') if verdict is MALICIOUS or SUSPICIOUS, or
    impersonation.verdict is 'IMPERSONATION'. Otherwise returns (False, reason).
    """
    if not isinstance(scan, dict):
        return False, "No takedown pack: this scan has no malicious or impersonation finding."

    verdict = scan.get("verdict")
    imp = scan.get("impersonation")
    imp_verdict = imp.get("verdict") if isinstance(imp, dict) else None

    if verdict in ["MALICIOUS", "SUSPICIOUS"] or imp_verdict == "IMPERSONATION":
        return True, "Eligible"

    return False, "No takedown pack: this scan has no malicious or impersonation finding."


def evidence_strength(scan: Optional[dict]) -> str:
    """Returns 'STRONG' when impersonation corroboration contains 'exfil' or
    'other_brand_cert', or the verdict is MALICIOUS with risk_floor None,
    or risk_floor_reason contains 'virustotal' and risk_floor >= 75.
    Otherwise returns 'PARTIAL'.
    """
    if not isinstance(scan, dict):
        return "PARTIAL"

    imp = scan.get("impersonation")
    if isinstance(imp, dict):
        evidence = imp.get("evidence") or {}
        corr = set(evidence.get("corroboration") or [])
        if "exfil" in corr or "other_brand_cert" in corr:
            return "STRONG"

    verdict = scan.get("verdict")
    risk_floor = scan.get("risk_floor")
    if verdict == "MALICIOUS" and risk_floor is None:
        return "STRONG"

    risk_floor_reason = str(scan.get("risk_floor_reason") or "")
    if "virustotal" in risk_floor_reason and isinstance(risk_floor, (int, float)) and risk_floor >= 75:
        return "STRONG"

    return "PARTIAL"


def _build_defanged_indicators_summary(indicators: dict) -> str:
    """Produces a compact defanged summary of extracted indicators for notices."""
    parts = []
    tb = indicators.get("telegram_bots") or []
    if tb:
        bot_ids = [b["bot_id"] for b in tb if b.get("bot_id")]
        if bot_ids:
            parts.append(f"Telegram Bot ID: {', '.join(bot_ids)}")

    dw = indicators.get("discord_webhooks") or []
    if dw:
        wh_ids = [w["webhook_id"] for w in dw if w.get("webhook_id")]
        if wh_ids:
            parts.append(f"Discord Webhook ID: {', '.join(wh_ids)}")

    fp = indicators.get("firebase_projects") or []
    if fp:
        fb_urls = [defang(p.get("url")) for p in fp if p.get("url")]
        if fb_urls:
            parts.append(f"Firebase: {', '.join(fb_urls)}")

    urls = indicators.get("urls") or []
    if urls:
        parts.append(f"URLs: {', '.join([defang(u) for u in urls[:3]])}")

    domains = indicators.get("domains") or []
    if domains:
        parts.append(f"Domains: {', '.join([defang(d) for d in domains[:3]])}")

    ips = indicators.get("ips") or []
    if ips:
        parts.append(f"IPs: {', '.join([defang(ip) for ip in ips[:3]])}")

    if not parts:
        return "No external network indicators recovered from static strings."
    return "; ".join(parts)


def _build_telegram_notice(
    channels: dict,
    sample: dict,
    verdict_info: dict,
    brand: Optional[str],
    telegram_bots: list,
    strength: str,
) -> dict:
    ch = channels.get("telegram", {})
    bot_ids = [b["bot_id"] for b in telegram_bots if b.get("bot_id")]
    bot_list = ", ".join(bot_ids) if bot_ids else "Unknown"
    file_name = sample.get("file_name") or "Unknown"
    pkg = sample.get("package_name") or "Unknown"
    sha = sample.get("sha256") or "Unknown"

    lines = [
        "[ANALYST: confirm before sending]",
    ]
    if strength == "PARTIAL":
        lines.append("Evidence strength is PARTIAL. Verify against the official app before sending.")
    lines.extend([
        "Dear Telegram Abuse Team,",
        "We identified an Android mobile application utilizing Telegram Bot infrastructure suspected of being used for data exfiltration.",
        f"Sample: {file_name} (Package: {pkg}, SHA-256: {sha})",
        f"Impersonated Target: {brand}" if brand else f"Classification: {verdict_info.get('verdict')} (Risk Score: {verdict_info.get('risk_score')}/100)",
        f"Observed Telegram Bot ID: {bot_list}",
        f"Please review and, if it violates your terms, disable the bot with ID {bot_list} suspected of being used for data exfiltration by an Android app.",
        "Source: ASTRA automated static analysis, unreviewed.",
    ])
    return {
        "key": "telegram",
        "label": ch.get("label", "Telegram abuse team"),
        "channel": ch.get("channel", "abuse@telegram.org"),
        "verified": ch.get("verified", False),
        "subject": f"[Abuse Report] Telegram Bot {bot_list} suspected of being used for data exfiltration by Android APK",
        "body": "\n".join(lines),
    }


def _build_discord_notice(
    channels: dict,
    sample: dict,
    verdict_info: dict,
    brand: Optional[str],
    discord_webhooks: list,
    strength: str,
) -> dict:
    ch = channels.get("discord", {})
    wh_ids = [w["webhook_id"] for w in discord_webhooks if w.get("webhook_id")]
    wh_list = ", ".join(wh_ids) if wh_ids else "Unknown"
    file_name = sample.get("file_name") or "Unknown"
    pkg = sample.get("package_name") or "Unknown"
    sha = sample.get("sha256") or "Unknown"

    lines = [
        "[ANALYST: confirm before sending]",
    ]
    if strength == "PARTIAL":
        lines.append("Evidence strength is PARTIAL. Verify against the official app before sending.")
    lines.extend([
        "Dear Discord Trust and Safety,",
        "We identified an Android mobile application configured with a Discord webhook suspected of being used for data exfiltration.",
        f"Sample: {file_name} (Package: {pkg}, SHA-256: {sha})",
        f"Impersonated Target: {brand}" if brand else f"Classification: {verdict_info.get('verdict')} (Risk Score: {verdict_info.get('risk_score')}/100)",
        f"Observed Discord Webhook ID: {wh_list}",
        f"Please review and, if it violates your terms, disable the webhook with ID {wh_list} suspected of being used for data exfiltration by an Android app.",
        "Source: ASTRA automated static analysis, unreviewed.",
    ])
    return {
        "key": "discord",
        "label": ch.get("label", "Discord Trust and Safety"),
        "channel": ch.get("channel", "Discord abuse report form (find the current URL on discord.com)"),
        "verified": ch.get("verified", False),
        "subject": f"[Abuse Report] Discord Webhook {wh_list} suspected of being used for data exfiltration by Android APK",
        "body": "\n".join(lines),
    }


def _build_firebase_notice(
    channels: dict,
    sample: dict,
    verdict_info: dict,
    brand: Optional[str],
    firebase_projects: list,
    strength: str,
) -> dict:
    ch = channels.get("firebase_google", {})
    proj_names = ", ".join([p["project"] for p in firebase_projects]) or "Unknown"
    defanged_urls = ", ".join([defang(p.get("url")) for p in firebase_projects]) or "None"
    file_name = sample.get("file_name") or "Unknown"
    pkg = sample.get("package_name") or "Unknown"
    sha = sample.get("sha256") or "Unknown"

    lines = [
        "[ANALYST: confirm before sending]",
    ]
    if strength == "PARTIAL":
        lines.append("Evidence strength is PARTIAL. Verify against the official app before sending.")
    lines.extend([
        "Dear Google Cloud / Firebase Abuse Team,",
        "We identified an Android application routing data to a Firebase Realtime Database project suspected of being used for data exfiltration.",
        f"Sample: {file_name} (Package: {pkg}, SHA-256: {sha})",
        f"Impersonated Target: {brand}" if brand else f"Classification: {verdict_info.get('verdict')} (Risk Score: {verdict_info.get('risk_score')}/100)",
        f"Firebase Database URL: {defanged_urls}",
        f"Please review project \"{proj_names}\" (database URL defanged) suspected of being used for data exfiltration by a fraudulent Android app.",
        "Source: ASTRA automated static analysis, unreviewed.",
    ])
    return {
        "key": "firebase_google",
        "label": ch.get("label", "Google Cloud / Firebase abuse team"),
        "channel": ch.get("channel", "Google Cloud abuse report form (find the current URL in Google Cloud support)"),
        "verified": ch.get("verified", False),
        "subject": f"[Abuse Report] Firebase project {proj_names} suspected of being used for data exfiltration by fraudulent Android application",
        "body": "\n".join(lines),
    }


def _format_vt_notice_line(verdict_info: dict) -> Optional[str]:
    """Formats a third-party VirusTotal detection line if ratio has > 0 detections."""
    ratio = verdict_info.get("virustotal_ratio")
    label = verdict_info.get("virustotal_label")
    if not ratio or not isinstance(ratio, str):
        return None
    parts = ratio.split("/")
    if not parts or not parts[0].strip().isdigit() or int(parts[0].strip()) <= 0:
        return None
    label_part = f", label {label}" if label else ""
    return f"Third-party detections (VirusTotal, not an ASTRA finding): {ratio}{label_part}."


def _build_notice_indicator_lines(indicators: dict) -> List[str]:
    """Builds notice indicator lines: suspected exfiltration channels or
    absence message, followed by candidate counts if any > 0.
    Does NOT list raw URLs, domains, or IPs.
    """
    lines = []
    exfil_parts = []

    tb = indicators.get("telegram_bots") or []
    bot_ids = [b["bot_id"] for b in tb if b.get("bot_id")]
    if bot_ids:
        exfil_parts.append(f"Telegram Bot ID: {', '.join(bot_ids)}")

    dw = indicators.get("discord_webhooks") or []
    wh_ids = [w["webhook_id"] for w in dw if w.get("webhook_id")]
    if wh_ids:
        exfil_parts.append(f"Discord Webhook ID: {', '.join(wh_ids)}")

    fp = indicators.get("firebase_projects") or []
    fb_urls = [defang(p.get("url")) for p in fp if p.get("url")]
    if fb_urls:
        exfil_parts.append(f"Firebase: {', '.join(fb_urls)}")

    if exfil_parts:
        lines.append(f"Suspected exfiltration channels: {'; '.join(exfil_parts)}")
    else:
        lines.append(
            "ASTRA static analysis did not identify an exfiltration channel (Telegram bot, Discord webhook or Firebase project)."
        )

    counts = indicators.get("counts") or {}
    u = counts.get("urls", 0)
    d = counts.get("domains", 0)
    i = counts.get("ips", 0)
    if (u + d + i) > 0:
        lines.append(
            f"Unreviewed candidates in the attached report: {u} URLs, {d} domains, {i} IPs. These may include legitimate services."
        )

    return lines


def _build_cert_in_notice(
    channels: dict,
    sample: dict,
    verdict_info: dict,
    brand: Optional[str],
    has_brand: bool,
    indicators: dict,
    strength: str,
) -> dict:
    ch = channels.get("cert_in", {})
    file_name = sample.get("file_name") or "Unknown"
    pkg = sample.get("package_name") or "Unknown"
    sha = sample.get("sha256") or "Unknown"
    verdict = verdict_info.get("verdict") or "UNKNOWN"
    risk = verdict_info.get("risk_score")

    if has_brand:
        subject = f"[Incident Report] Malicious Banking APK: {pkg}"
        intro = "We are reporting an incident summary for a malicious Android banking application."
    else:
        subject = f"[Incident Report] Malicious Android APK: {pkg}"
        intro = "We are reporting a malicious Android application identified through third-party antivirus detections and automated static analysis."

    lines = [
        "[ANALYST: confirm before sending]",
    ]
    if strength == "PARTIAL":
        lines.append("Evidence strength is PARTIAL. Verify against the official app before sending.")
    lines.extend([
        "To: Incident Response Team, CERT-In,",
        intro,
        f"Sample: {file_name} (Package: {pkg}, SHA-256: {sha})",
        f"Verdict: {verdict}, Risk Score: {risk}/100",
    ])
    vt_line = _format_vt_notice_line(verdict_info)
    if vt_line:
        lines.append(vt_line)
    if has_brand and brand:
        lines.append(f"Impersonated Brand: {brand}")
    lines.extend(_build_notice_indicator_lines(indicators))
    lines.extend([
        "We request guidance and coordination for incident mitigation and ecosystem alerting.",
        "Source: ASTRA automated static analysis, unreviewed.",
    ])
    return {
        "key": "cert_in",
        "label": ch.get("label", "CERT-In"),
        "channel": ch.get("channel", "incident@cert-in.org.in"),
        "verified": ch.get("verified", False),
        "subject": subject,
        "body": "\n".join(lines),
    }


def _build_i4c_notice(
    channels: dict,
    sample: dict,
    verdict_info: dict,
    brand: Optional[str],
    has_brand: bool,
    indicators: dict,
    strength: str,
) -> dict:
    ch = channels.get("i4c_ncrp", {})
    file_name = sample.get("file_name") or "Unknown"
    pkg = sample.get("package_name") or "Unknown"
    sha = sample.get("sha256") or "Unknown"
    verdict = verdict_info.get("verdict") or "UNKNOWN"
    risk = verdict_info.get("risk_score")

    if has_brand:
        subject = f"[Cyber Crime Complaint] Fraudulent Banking APK: {pkg}"
        intro = "Cyber crime complaint regarding distribution of fraudulent Android malware."
    else:
        subject = f"[Cyber Crime Complaint] Malicious Android APK: {pkg}"
        intro = "We are reporting a malicious Android application identified through third-party antivirus detections and automated static analysis."

    lines = [
        "[ANALYST: confirm before sending]",
    ]
    if strength == "PARTIAL":
        lines.append("Evidence strength is PARTIAL. Verify against the official app before sending.")
    lines.extend([
        "To: National Cyber Crime Reporting Portal (I4C),",
        intro,
        f"Sample: {file_name} (Package: {pkg}, SHA-256: {sha})",
        f"Verdict: {verdict}, Risk Score: {risk}/100",
    ])
    vt_line = _format_vt_notice_line(verdict_info)
    if vt_line:
        lines.append(vt_line)
    if has_brand and brand:
        lines.append(f"Claimed Brand: {brand}")
    lines.extend(_build_notice_indicator_lines(indicators))
    lines.extend([
        "Requesting recording of this complaint and coordinated inter-agency action.",
        "Source: ASTRA automated static analysis, unreviewed.",
    ])
    return {
        "key": "i4c_ncrp",
        "label": ch.get("label", "I4C / National Cyber Crime Reporting Portal"),
        "channel": ch.get("channel", "cybercrime.gov.in, helpline 1930"),
        "verified": ch.get("verified", False),
        "subject": subject,
        "body": "\n".join(lines),
    }


def _build_bank_notice(
    channels: dict,
    sample: dict,
    verdict_info: dict,
    brand: Optional[str],
    indicators_summary: str,
    strength: str,
) -> dict:
    ch = channels.get("bank", {})
    file_name = sample.get("file_name") or "Unknown"
    pkg = sample.get("package_name") or "Unknown"
    sha = sample.get("sha256") or "Unknown"

    lines = [
        "[ANALYST: confirm before sending]",
    ]
    if strength == "PARTIAL":
        lines.append("Evidence strength is PARTIAL. Verify against the official app before sending.")

    if brand:
        brand_line = f"We detected an app impersonating {brand} targeting mobile banking users."
    else:
        brand_line = "We detected a fraudulent mobile application targeting banking customers."

    lines.extend([
        "Dear Fraud and Information Security Team,",
        brand_line,
        f"Sample: {file_name} (Package: {pkg}, SHA-256: {sha})",
        f"Observed Indicators: {indicators_summary}",
        "We suggest blocking these indicators across perimeter controls and warning customers.",
        "Please let us know if additional technical artifacts are required.",
        "Source: ASTRA automated static analysis, unreviewed.",
    ])
    subj_brand = brand if brand else "Financial Services"
    return {
        "key": "bank",
        "label": ch.get("label", "Impacted bank fraud and security team"),
        "channel": ch.get("channel", "The bank's official fraud reporting contact"),
        "verified": ch.get("verified", False),
        "subject": f"[Threat Alert] Fraudulent Android Application targeting {subj_brand}",
        "body": "\n".join(lines),
    }


def build_takedown_data(scan: Optional[dict]) -> dict:
    """Builds the complete takedown evidence pack dictionary from a scan dict.
    Never raises; returns safe defaults for missing or malformed inputs.
    """
    if not isinstance(scan, dict):
        scan = {}

    try:
        channels = _load_channels()

        androguard_data = scan.get("androguard_data") or {}
        if not isinstance(androguard_data, dict):
            androguard_data = {}

        cert = androguard_data.get("certificate") or {}
        if not isinstance(cert, dict):
            cert = {}

        extracted_iocs = androguard_data.get("extracted_iocs") or {}
        if not isinstance(extracted_iocs, dict):
            extracted_iocs = {}

        secrets = extracted_iocs.get("secrets") or {}
        if not isinstance(secrets, dict):
            secrets = {}

        network = extracted_iocs.get("network") or {}
        if not isinstance(network, dict):
            network = {}

        # 1. Telegram Bots (digits before ':', token masked)
        telegram_bots = []
        for tok in secrets.get("telegram_bot_tokens") or []:
            if not tok or not isinstance(tok, str):
                continue
            if ":" in tok:
                bot_id, secret_part = tok.split(":", 1)
            else:
                bot_id, secret_part = "", tok
            telegram_bots.append({
                "bot_id": bot_id,
                "token_masked": mask_secret(secret_part),
            })

        # 2. Discord Webhooks (webhook_id, token masked)
        discord_webhooks = []
        for wh in secrets.get("discord_webhooks") or []:
            if not wh or not isinstance(wh, str):
                continue
            match = re.search(r'/api/webhooks/(\d+)/([a-zA-Z0-9_-]+)', wh)
            if match:
                discord_webhooks.append({
                    "webhook_id": match.group(1),
                    "token_masked": mask_secret(match.group(2)),
                })
            else:
                discord_webhooks.append({
                    "webhook_id": "",
                    "token_masked": mask_secret(wh),
                })

        # 3. Firebase Projects (first host label, url)
        # Never include Firebase API keys (AIza...)
        firebase_projects = []
        for fb_url in secrets.get("firebase_urls") or []:
            if not fb_url or not isinstance(fb_url, str):
                continue
            parsed = urlparse(fb_url)
            host = parsed.hostname or fb_url
            project = host.split(".")[0]
            firebase_projects.append({
                "project": project,
                "url": fb_url,
            })

        # 4. AWS Keys Masked
        aws_keys_masked = [
            mask_secret(k)
            for k in (secrets.get("aws_access_keys") or [])
            if k and isinstance(k, str)
        ]

        # 5. URLs, Domains, IPs (first 25 each, full counts)
        raw_urls = network.get("urls") or []
        raw_domains = network.get("domains") or []
        raw_ips = network.get("ips") or []

        urls_25 = raw_urls[:25] if isinstance(raw_urls, list) else []
        domains_25 = raw_domains[:25] if isinstance(raw_domains, list) else []
        ips_25 = raw_ips[:25] if isinstance(raw_ips, list) else []

        counts = {
            "telegram_bots": len(telegram_bots),
            "discord_webhooks": len(discord_webhooks),
            "firebase_projects": len(firebase_projects),
            "aws_keys": len(aws_keys_masked),
            "urls": len(raw_urls) if isinstance(raw_urls, list) else 0,
            "domains": len(raw_domains) if isinstance(raw_domains, list) else 0,
            "ips": len(raw_ips) if isinstance(raw_ips, list) else 0,
        }

        indicators = {
            "telegram_bots": telegram_bots,
            "discord_webhooks": discord_webhooks,
            "firebase_projects": firebase_projects,
            "aws_keys_masked": aws_keys_masked,
            "urls": urls_25,
            "domains": domains_25,
            "ips": ips_25,
            "counts": counts,
            "note": "URLs, domains and IPs are unreviewed candidates and may include legitimate services.",
        }

        # Sample Details
        sample = {
            "file_name": scan.get("file_name"),
            "package_name": scan.get("package_name") or androguard_data.get("package_name"),
            "app_label": androguard_data.get("app_name"),
            "sha256": scan.get("file_hash") or androguard_data.get("apk_hash"),
            "signer_sha256": cert.get("cert_hash"),
            "signer_issuer": cert.get("issuer"),
            "signer_subject": cert.get("subject"),
            "version_name": androguard_data.get("version_name"),
        }

        # Verdict Details
        vt_label = (
            scan.get("vt_threat_label")
            or scan.get("virustotal_label")
            or (((scan.get("vt_data") or {}).get("intel") or {}).get("threat") or {}).get("label")
        )
        verdict_info = {
            "verdict": scan.get("verdict"),
            "risk_score": scan.get("risk_score"),
            "risk_floor": scan.get("risk_floor"),
            "risk_floor_reason": scan.get("risk_floor_reason"),
            "confidence_level": scan.get("confidence_level"),
            "summary": scan.get("threat_summary"),
            "signals_used": scan.get("signals_used"),
            "signature_verdict": scan.get("signature_verdict"),
            "virustotal_ratio": scan.get("vt_detection_ratio") or scan.get("virustotal_ratio"),
            "virustotal_label": vt_label,
        }

        strength = evidence_strength(scan)

        # Impersonation Details
        imp = scan.get("impersonation")
        impersonation_dict = imp if isinstance(imp, dict) else None
        brand_name = impersonation_dict.get("brand_name") if impersonation_dict else None
        has_brand = bool(impersonation_dict and impersonation_dict.get("verdict") == "IMPERSONATION" and brand_name)

        # Dangerous Permissions
        dangerous_permissions = (
            scan.get("dangerous_permissions")
            or androguard_data.get("dangerous_permissions")
            or []
        )

        # Recommended Actions
        recommended_actions = []
        if has_brand:
            recommended_actions.append(
                f"Notify the official fraud and security team of {brand_name} regarding active mobile application impersonation."
            )

        if telegram_bots:
            recommended_actions.append(
                f"Submit abuse takedown requests to Telegram to disable {len(telegram_bots)} identified bot account(s)."
            )
        if discord_webhooks:
            recommended_actions.append(
                f"Submit abuse takedown requests to Discord Trust & Safety to disable {len(discord_webhooks)} webhook endpoint(s)."
            )
        if firebase_projects:
            recommended_actions.append(
                f"Submit abuse reports to Google Cloud / Firebase to suspend {len(firebase_projects)} project database(s)."
            )
        if aws_keys_masked:
            recommended_actions.append("Immediately revoke and rotate exposed AWS credentials.")
        if raw_ips or raw_domains:
            recommended_actions.append(
                "Block identified IP addresses and network domains across enterprise firewalls and secure DNS resolvers."
            )
        recommended_actions.append(
            "Coordinate incident reporting with CERT-In and submit a complaint via the National Cyber Crime Reporting Portal (cybercrime.gov.in)."
        )

        # Notices Generation
        indicators_summary = _build_defanged_indicators_summary(indicators)
        notices = []

        if telegram_bots:
            notices.append(
                _build_telegram_notice(channels, sample, verdict_info, brand_name, telegram_bots, strength)
            )

        if discord_webhooks:
            notices.append(
                _build_discord_notice(channels, sample, verdict_info, brand_name, discord_webhooks, strength)
            )

        if firebase_projects:
            notices.append(
                _build_firebase_notice(channels, sample, verdict_info, brand_name, firebase_projects, strength)
            )

        # Regulatory and bank notices
        notices.append(
            _build_cert_in_notice(channels, sample, verdict_info, brand_name, has_brand, indicators, strength)
        )
        notices.append(
            _build_i4c_notice(channels, sample, verdict_info, brand_name, has_brand, indicators, strength)
        )
        if has_brand:
            notices.append(
                _build_bank_notice(channels, sample, verdict_info, brand_name, indicators_summary, strength)
            )

        # Case Metadata
        case = {
            "scan_id": str(scan.get("id")) if scan.get("id") else None,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "engine_version": scan.get("engine_version"),
            "prepared_by": "ASTRA automated analysis",
            "analyst_review": "PENDING",
        }

        return {
            "case": case,
            "evidence_strength": strength,
            "sample": sample,
            "verdict": verdict_info,
            "impersonation": impersonation_dict,
            "indicators": indicators,
            "dangerous_permissions": dangerous_permissions,
            "recommended_actions": recommended_actions,
            "notices": notices,
            "disclaimer": "Generated by automated static analysis. Not reviewed by a human. Confirm the findings before acting on or sending any part of this report.",
        }

    except Exception as e:
        logger.error("build_takedown_data_failed", error=str(e))
        return {
            "case": {
                "scan_id": str(scan.get("id")) if scan.get("id") else None,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "engine_version": scan.get("engine_version"),
                "prepared_by": "ASTRA automated analysis",
                "analyst_review": "PENDING",
            },
            "evidence_strength": "PARTIAL",
            "sample": {},
            "verdict": {},
            "impersonation": None,
            "indicators": {
                "telegram_bots": [],
                "discord_webhooks": [],
                "firebase_projects": [],
                "aws_keys_masked": [],
                "urls": [],
                "domains": [],
                "ips": [],
                "counts": {
                    "telegram_bots": 0,
                    "discord_webhooks": 0,
                    "firebase_projects": 0,
                    "aws_keys": 0,
                    "urls": 0,
                    "domains": 0,
                    "ips": 0,
                },
                "note": "URLs, domains and IPs are unreviewed candidates and may include legitimate services.",
            },
            "dangerous_permissions": [],
            "recommended_actions": [],
            "notices": [],
            "disclaimer": "Generated by automated static analysis. Not reviewed by a human. Confirm the findings before acting on or sending any part of this report.",
        }


# Strong impersonation scan fixture for testing and reuse
tg_secret = "AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"
dc_secret = "abcDEF_ghiJKL-mnoPQR"
fb_api_key = "AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBc"

TEST_SCAN_STRONG = {
    "id": "11111111-1111-1111-1111-111111111111",
    "file_name": "fake_sbi.apk",
    "file_hash": "a" * 64,
    "package_name": "com.sbi.fakeapp",
    "verdict": "MALICIOUS",
    "risk_score": 75.0,
    "risk_floor": 75.0,
    "impersonation": {
        "verdict": "IMPERSONATION",
        "brand_name": "State Bank of India",
        "evidence": {
            "corroboration": ["exfil", "lure"]
        }
    },
    "androguard_data": {
        "package_name": "com.sbi.fakeapp",
        "app_name": "SBI Rewards",
        "extracted_iocs": {
            "secrets": {
                "telegram_bot_tokens": [f"123456789:{tg_secret}"],
                "discord_webhooks": [f"https://discord.com/api/webhooks/1234567890/{dc_secret}"],
                "firebase_urls": ["https://mybankapp-fake.firebaseio.com"],
                "firebase_api_keys": [fb_api_key]
            },
            "network": {
                "urls": ["https://exfil-api.com/steal"],
                "domains": ["exfil-api.com"],
                "ips": ["198.51.100.1"]
            }
        }
    }
}

TEST_SCAN_TROJAN = {
    "id": "6ba02096-3bcb-49fe-a982-b7d171bace98",
    "file_name": "flappybird2.apk",
    "package_name": "com.dotgears.flappybird",
    "verdict": "MALICIOUS",
    "risk_score": 85.0,
    "risk_floor": 85.0,
    "risk_floor_reason": "virustotal",
    "vt_detection_ratio": "28/67",
    "vt_threat_label": "trojan.metasploit/fnaa",
    "threat_summary": "Flagged as malicious by VirusTotal (28 of 67 engines, label trojan.metasploit/fnaa).",
    "confidence_level": "HIGH",
    "signals_used": 2,
    "impersonation": None,
    "androguard_data": {
        "extracted_iocs": {
            "network": {
                "urls": [
                    "http://www.amazon.com/x",
                    "https://badad.googleplex.com/y",
                    "http://hostname/?"
                ],
                "domains": [
                    "googlesyndication.com"
                ],
                "ips": []
            }
        }
    }
}


if __name__ == "__main__":
    print("Running ASTRA Takedown Evidence Pack Test Suite...")
    total_tests = 8
    passed_tests = 0

    scan_1 = TEST_SCAN_STRONG

    t1_eligible, _ = is_eligible(scan_1)
    t1_strength = evidence_strength(scan_1)
    pack_1 = build_takedown_data(scan_1)
    pack_1_json = json.dumps(pack_1)

    notice_keys_1 = {n["key"] for n in pack_1.get("notices", [])}
    t1_notices_present = {"telegram", "discord", "firebase_google", "cert_in", "i4c_ncrp", "bank"}.issubset(notice_keys_1)
    t1_no_raw_secrets = (
        tg_secret not in pack_1_json
        and dc_secret not in pack_1_json
        and fb_api_key not in pack_1_json
    )
    t1_has_bot_id = "123456789" in pack_1_json
    fb_projects = pack_1.get("indicators", {}).get("firebase_projects", [])
    t1_fb_proj_ok = len(fb_projects) > 0 and fb_projects[0].get("project") == "mybankapp-fake"
    t1_no_http_body = not any("http://" in n["body"] or "https://" in n["body"] for n in pack_1.get("notices", []))
    t1_has_hxxps = any("hxxps" in n["body"] for n in pack_1.get("notices", []))

    if (
        t1_eligible
        and t1_strength == "STRONG"
        and t1_notices_present
        and t1_no_raw_secrets
        and t1_has_bot_id
        and t1_fb_proj_ok
        and t1_no_http_body
        and t1_has_hxxps
    ):
        print("PASS: Test 1 - Strong impersonation scan with all indicators")
        passed_tests += 1
    else:
        print(f"FAIL: Test 1 - Strong impersonation (eligible={t1_eligible}, strength={t1_strength}, notices={t1_notices_present}, no_secrets={t1_no_raw_secrets}, bot_id={t1_has_bot_id}, fb_proj={t1_fb_proj_ok}, no_http={t1_no_http_body}, has_hxxps={t1_has_hxxps})")

    # Test 2: Weak impersonation (corroboration ["lure"]), no indicators
    scan_2 = {
        "id": "22222222-2222-2222-2222-222222222222",
        "file_name": "weak_lure.apk",
        "package_name": "com.hdfc.fakelure",
        "verdict": "SUSPICIOUS",
        "risk_score": 45.0,
        "risk_floor": 45.0,
        "impersonation": {
            "verdict": "IMPERSONATION",
            "brand_name": "HDFC Bank",
            "evidence": {
                "corroboration": ["lure"]
            }
        },
        "androguard_data": {}
    }

    t2_eligible, _ = is_eligible(scan_2)
    t2_strength = evidence_strength(scan_2)
    pack_2 = build_takedown_data(scan_2)
    notice_keys_2 = {n["key"] for n in pack_2.get("notices", [])}
    t2_only_standard_notices = notice_keys_2 == {"cert_in", "i4c_ncrp", "bank"}
    t2_all_bodies_partial = all("Evidence strength is PARTIAL" in n["body"] for n in pack_2.get("notices", []))

    if t2_eligible and t2_strength == "PARTIAL" and t2_only_standard_notices and t2_all_bodies_partial:
        print("PASS: Test 2 - Weak impersonation with PARTIAL strength and standard notices")
        passed_tests += 1
    else:
        print(f"FAIL: Test 2 - Weak impersonation (eligible={t2_eligible}, strength={t2_strength}, only_std={t2_only_standard_notices}, partial_bodies={t2_all_bodies_partial})")

    # Test 3: CLEAN scan with UNVERIFIED_CLAIM
    scan_3 = {
        "verdict": "CLEAN",
        "impersonation": {
            "verdict": "UNVERIFIED_CLAIM",
            "brand_name": "Central Bank of India"
        }
    }
    t3_eligible, _ = is_eligible(scan_3)
    if not t3_eligible:
        print("PASS: Test 3 - CLEAN scan with UNVERIFIED_CLAIM is not eligible")
        passed_tests += 1
    else:
        print(f"FAIL: Test 3 - Expected not eligible for CLEAN scan with UNVERIFIED_CLAIM")

    # Test 4: {} and None: no exception, not eligible
    t4_empty_ok = not is_eligible({})[0] and isinstance(build_takedown_data({}), dict)
    t4_none_ok = not is_eligible(None)[0] and isinstance(build_takedown_data(None), dict)
    if t4_empty_ok and t4_none_ok:
        print("PASS: Test 4 - Empty dict and None handle gracefully without exceptions")
        passed_tests += 1
    else:
        print(f"FAIL: Test 4 - Empty or None handling failed (empty={t4_empty_ok}, none={t4_none_ok})")

    # Test 5: MALICIOUS from signals (no impersonation, risk_floor None)
    scan_5 = {
        "id": "55555555-5555-5555-5555-555555555555",
        "file_name": "malware_no_brand.apk",
        "package_name": "com.unknown.trojan",
        "verdict": "MALICIOUS",
        "risk_score": 85.0,
        "risk_floor": None,
        "impersonation": None,
        "androguard_data": {}
    }
    t5_eligible, _ = is_eligible(scan_5)
    t5_strength = evidence_strength(scan_5)
    pack_5 = build_takedown_data(scan_5)
    notice_keys_5 = {n["key"] for n in pack_5.get("notices", [])}
    t5_notices_ok = notice_keys_5 == {"cert_in", "i4c_ncrp"}
    t5_no_bank_notice = not any(n["key"] == "bank" for n in pack_5.get("notices", []))
    t5_no_bank_in_actions = not any("bank" in act.lower() for act in pack_5.get("recommended_actions", []))
    t5_no_bank_in_bodies = not any("bank" in n["body"].lower() for n in pack_5.get("notices", []))

    if t5_eligible and t5_strength == "STRONG" and t5_notices_ok and t5_no_bank_notice and t5_no_bank_in_actions and t5_no_bank_in_bodies:
        print("PASS: Test 5 - Signal MALICIOUS with no brand has no bank notice, only cert_in and i4c_ncrp")
        passed_tests += 1
    else:
        print(f"FAIL: Test 5 - Signal MALICIOUS (eligible={t5_eligible}, strength={t5_strength}, keys={notice_keys_5}, no_bank={t5_no_bank_notice}, no_bank_act={t5_no_bank_in_actions}, no_bank_body={t5_no_bank_in_bodies})")

    # Test 6 (Test a): Generic trojan fixture with network indicators
    scan_6 = TEST_SCAN_TROJAN
    t6_eligible, _ = is_eligible(scan_6)
    t6_strength = evidence_strength(scan_6)
    pack_6 = build_takedown_data(scan_6)
    pack_6_json_lower = json.dumps(pack_6).lower()
    notice_keys_6 = {n["key"] for n in pack_6.get("notices", [])}
    t6_keys_ok = notice_keys_6 == {"cert_in", "i4c_ncrp"}

    t6_no_bank_in_pack = "bank" not in pack_6_json_lower
    t6_no_c2_in_notices = not any(
        "c2" in n.get("subject", "").lower() or "c2" in n.get("body", "").lower()
        for n in pack_6.get("notices", [])
    )
    t6_no_amazon_in_notices = not any(
        "amazon" in n.get("subject", "").lower() or "amazon" in n.get("body", "").lower()
        for n in pack_6.get("notices", [])
    )
    t6_no_googleplex_in_notices = not any(
        "googleplex" in n.get("subject", "").lower() or "googleplex" in n.get("body", "").lower()
        for n in pack_6.get("notices", [])
    )
    t6_bodies_did_not_id = all(
        "did not identify an exfiltration channel" in n["body"]
        for n in pack_6.get("notices", [])
    )
    t6_bodies_unreviewed = all(
        "Unreviewed candidates" in n["body"]
        for n in pack_6.get("notices", [])
    )
    t6_bodies_ratio = all(
        "28/67" in n["body"]
        for n in pack_6.get("notices", [])
    )

    scan_6_partial = dict(scan_6)
    scan_6_partial["risk_floor_reason"] = "impersonation"
    scan_6_partial["risk_floor"] = 45.0
    t6_partial_strength = evidence_strength(scan_6_partial)

    if (
        t6_eligible
        and t6_strength == "STRONG"
        and t6_keys_ok
        and t6_no_bank_in_pack
        and t6_no_c2_in_notices
        and t6_no_amazon_in_notices
        and t6_no_googleplex_in_notices
        and t6_bodies_did_not_id
        and t6_bodies_unreviewed
        and t6_bodies_ratio
        and t6_partial_strength == "PARTIAL"
    ):
        print("PASS: Test 6 (Test a) - Generic trojan fixture has neutral wording, no bank, no C2/amazon/googleplex, unreviewed candidate counts")
        passed_tests += 1
    else:
        print(f"FAIL: Test 6 (eligible={t6_eligible}, strength={t6_strength}, keys={notice_keys_6}, no_bank={t6_no_bank_in_pack}, no_c2={t6_no_c2_in_notices}, no_amazon={t6_no_amazon_in_notices}, no_gp={t6_no_googleplex_in_notices}, did_not_id={t6_bodies_did_not_id}, unrev={t6_bodies_unreviewed}, ratio={t6_bodies_ratio}, partial={t6_partial_strength})")

    # Test 7 (Test b): No brand but Telegram token present (MALICIOUS from signals)
    scan_7 = {
        "id": "77777777-7777-7777-7777-777777777777",
        "file_name": "malware_tg.apk",
        "package_name": "com.unknown.tgmalware",
        "verdict": "MALICIOUS",
        "risk_score": 80.0,
        "risk_floor": None,
        "impersonation": None,
        "androguard_data": {
            "extracted_iocs": {
                "secrets": {
                    "telegram_bot_tokens": ["987654321:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"]
                }
            }
        }
    }
    pack_7 = build_takedown_data(scan_7)
    notices_7 = {n["key"]: n for n in pack_7.get("notices", [])}
    t7_cert_body = notices_7.get("cert_in", {}).get("body", "")
    t7_i4c_body = notices_7.get("i4c_ncrp", {}).get("body", "")
    t7_ok = (
        "987654321" in t7_cert_body
        and "987654321" in t7_i4c_body
        and "did not identify" not in t7_cert_body
        and "did not identify" not in t7_i4c_body
    )
    if t7_ok:
        print("PASS: Test 7 (Test b) - No brand but Telegram token lists bot ID and does not say 'did not identify'")
        passed_tests += 1
    else:
        print(f"FAIL: Test 7 (Test b) - Telegram bot ID in bodies: cert_has={'987654321' in t7_cert_body}, i4c_has={'987654321' in t7_i4c_body}, no_dn_id={'did not identify' not in t7_cert_body})")

    # Test 8 (Test c): Strong impersonation fixture names brand and mentions bank, exfil notices exist
    scan_8 = TEST_SCAN_STRONG
    pack_8 = build_takedown_data(scan_8)
    notices_8 = {n["key"]: n for n in pack_8.get("notices", [])}
    t8_cert_body = notices_8.get("cert_in", {}).get("body", "")
    t8_has_brand_name = "State Bank of India" in t8_cert_body
    t8_mentions_bank = "banking" in t8_cert_body.lower() or "bank" in t8_cert_body.lower()
    t8_has_exfil_notices = {"telegram", "discord", "firebase_google"}.issubset(set(notices_8.keys()))

    if t8_has_brand_name and t8_mentions_bank and t8_has_exfil_notices:
        print("PASS: Test 8 (Test c) - Strong impersonation fixture names brand, mentions bank, and includes exfil notices")
        passed_tests += 1
    else:
        print(f"FAIL: Test 8 (Test c) - brand_in_cert={t8_has_brand_name}, bank_in_cert={t8_mentions_bank}, exfil_notices={t8_has_exfil_notices})")

    print(f"\nFinal Result: {passed_tests}/{total_tests} tests passed.")

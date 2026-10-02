"""
ASTRA Brand Impersonation Detector.

Detects impersonation of Indian banking brands by analyzing APK metadata
(application label, package name, certificate hash, extracted secrets).
Differentiates between GENUINE applications, confirmed IMPERSONATION,
UNVERIFIED_CLAIM, and NONE.
"""

from __future__ import annotations

import difflib
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple

import structlog

logger = structlog.get_logger()

# Character normalization for confusable characters (lookalikes)
CONFUSABLE_TRANS = str.maketrans("1l|0", "iioo")


def to_confusable(text: str) -> str:
    """Maps confusable visually similar characters (1, l, | -> i, 0 -> o)."""
    return text.translate(CONFUSABLE_TRANS)


# Load registry once at import
REGISTRY_PATH = Path(__file__).resolve().parent.parent.parent / "ml" / "brand_registry.json"

try:
    with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
        REGISTRY: Dict[str, Any] = json.load(f)
except Exception as e:
    logger.warning("failed_to_load_brand_registry", path=str(REGISTRY_PATH), error=str(e))
    REGISTRY = {"context_words": [], "lure_words": [], "brands": []}


def _tokenize_label(text: str) -> List[str]:
    """Splits label into tokens on non-alphanumerics while preserving '&'."""
    if not text:
        return []
    return [t for t in re.split(r'[^a-zA-Z0-9&]+', text) if t]


def _is_fuzzy_match(token: str, keyword: str) -> bool:
    """Fuzzy match between a label token and a single-word keyword when both len >= 5."""
    if len(token) >= 5 and len(keyword) >= 5 and " " not in keyword:
        return difflib.SequenceMatcher(None, token, keyword).ratio() >= 0.88
    return False


def _check_distinctive_keyword_match(
    kw: str,
    label_lower: str,
    label_conf: str,
    label_tokens: List[str],
    label_tokens_conf: List[str],
    pkg_segments: List[str],
    pkg_segments_conf: List[str],
    context_words: List[str],
) -> bool:
    """Checks whether a distinctive keyword matches via token, phrase, package segment, or fuzzy."""
    kw_norm = kw.lower()
    kw_conf = to_confusable(kw_norm)

    # 1. Whole token in label
    if kw_norm in label_tokens or kw_conf in label_tokens_conf:
        return True

    # 2. Whole phrase in label (word boundaries)
    boundary_norm = rf'(?<![a-zA-Z0-9&]){re.escape(kw_norm)}(?![a-zA-Z0-9&])'
    if re.search(boundary_norm, label_lower):
        return True

    boundary_conf = rf'(?<![a-zA-Z0-9&]){re.escape(kw_conf)}(?![a-zA-Z0-9&])'
    if re.search(boundary_conf, label_conf):
        return True

    # 3. Equals a package segment
    if kw_norm in pkg_segments or kw_conf in pkg_segments_conf:
        return True

    # 4. Fuzzy match: between label token and single-word keyword when both len >= 5
    # (Skip tokens that are generic context words like 'mobile' or 'banking')
    ctx_set = {w.lower() for w in context_words}
    for t in label_tokens:
        if t not in ctx_set and _is_fuzzy_match(t, kw_norm):
            return True
    for t_conf in label_tokens_conf:
        if t_conf not in ctx_set and _is_fuzzy_match(t_conf, kw_conf):
            return True

    return False


def _check_weak_keyword_match(
    wkw: str,
    label_lower: str,
    label_conf: str,
    label_tokens: List[str],
    label_tokens_conf: List[str],
    pkg_segments: List[str],
    pkg_segments_conf: List[str],
) -> bool:
    """Checks whether a weak keyword matches exactly via token, phrase, or package segment."""
    wkw_norm = wkw.lower()
    wkw_conf = to_confusable(wkw_norm)

    # 1. Whole token in label
    if wkw_norm in label_tokens or wkw_conf in label_tokens_conf:
        return True

    # 2. Whole phrase in label (word boundaries)
    boundary_norm = rf'(?<![a-zA-Z0-9&]){re.escape(wkw_norm)}(?![a-zA-Z0-9&])'
    if re.search(boundary_norm, label_lower):
        return True

    boundary_conf = rf'(?<![a-zA-Z0-9&]){re.escape(wkw_conf)}(?![a-zA-Z0-9&])'
    if re.search(boundary_conf, label_conf):
        return True

    # 3. Equals a package segment
    if wkw_norm in pkg_segments or wkw_conf in pkg_segments_conf:
        return True

    return False


def _has_context_word(
    label_tokens: List[str],
    label_tokens_conf: List[str],
    pkg_segments: List[str],
    pkg_segments_conf: List[str],
    pkg_tokens: List[str],
    pkg_tokens_conf: List[str],
    context_words: List[str],
) -> bool:
    """Checks if label or package contains any context word as a separate token or segment."""
    ctx_norm_set = {w.lower() for w in context_words}
    ctx_conf_set = {to_confusable(w.lower()) for w in context_words}

    for t in label_tokens:
        if t in ctx_norm_set:
            return True
    for t in label_tokens_conf:
        if t in ctx_conf_set:
            return True
    for s in pkg_segments:
        if s in ctx_norm_set:
            return True
    for s in pkg_segments_conf:
        if s in ctx_conf_set:
            return True
    for t in pkg_tokens:
        if t in ctx_norm_set:
            return True
    for t in pkg_tokens_conf:
        if t in ctx_conf_set:
            return True

    return False


def assess_impersonation(
    app_label: Optional[str],
    package_name: Optional[str],
    cert_hash: Optional[str],
    secrets: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Assesses whether an APK claims or impersonates a registered banking brand.

    Args:
        app_label: The display name / application label.
        package_name: The Android package name (e.g. com.example.app).
        cert_hash: The SHA-256 certificate signature hash.
        secrets: Extracted secrets dictionary (e.g. androguard_data['extracted_iocs']['secrets']).

    Returns:
        dict: Assessment result containing verdict, confidence, brand_id, brand_name,
              reasons, evidence, and registry_certs_for_brand.
    """
    try:
        label = (app_label or "").strip()
        pkg = (package_name or "").strip()
        cert = (cert_hash or "").strip().lower()

        label_lower = label.lower()
        label_conf = to_confusable(label_lower)
        label_tokens = _tokenize_label(label_lower)
        label_tokens_conf = _tokenize_label(label_conf)

        pkg_lower = pkg.lower()
        pkg_conf = to_confusable(pkg_lower)
        pkg_segments = [s for s in pkg_lower.split(".") if s]
        pkg_segments_conf = [s for s in pkg_conf.split(".") if s]
        pkg_tokens = _tokenize_label(pkg_lower)
        pkg_tokens_conf = _tokenize_label(pkg_conf)

        context_words: List[str] = REGISTRY.get("context_words", [])
        lure_words: List[str] = REGISTRY.get("lure_words", [])
        brands: List[Dict[str, Any]] = REGISTRY.get("brands", [])

        has_context = _has_context_word(
            label_tokens, label_tokens_conf,
            pkg_segments, pkg_segments_conf,
            pkg_tokens, pkg_tokens_conf,
            context_words
        )

        # Step 1: Find matching brands
        brand_matches: List[Tuple[Dict[str, Any], str, List[str]]] = []

        for b in brands:
            matched_kws: List[str] = []

            # Check distinctive keywords
            for kw in b.get("keywords", []):
                if _check_distinctive_keyword_match(
                    kw, label_lower, label_conf,
                    label_tokens, label_tokens_conf,
                    pkg_segments, pkg_segments_conf,
                    context_words,
                ):
                    matched_kws.append(kw)

            # Check weak keywords only if context word is present
            if has_context:
                for wkw in b.get("weak_keywords", []):
                    if _check_weak_keyword_match(
                        wkw, label_lower, label_conf,
                        label_tokens, label_tokens_conf,
                        pkg_segments, pkg_segments_conf,
                    ):
                        matched_kws.append(wkw)

            if matched_kws:
                longest = max(matched_kws, key=len)
                brand_matches.append((b, longest, matched_kws))

        # Step 3: No claim -> verdict NONE
        if not brand_matches:
            return {
                "verdict": "NONE",
                "confidence": None,
                "brand_id": None,
                "brand_name": None,
                "reasons": [],
                "evidence": {
                    "label": app_label,
                    "package": package_name,
                    "cert_hash": cert_hash,
                    "matched_keyword": None,
                    "corroboration": [],
                },
                "registry_certs_for_brand": 0,
            }

        # Step 2: Resolve multiple brand matches
        # Keep the one whose matched keyword is longest; on a tie, the one with most matches
        brand_matches.sort(key=lambda item: (len(item[1]), len(item[2])), reverse=True)
        claimed_brand, matched_kw, all_matched_kws = brand_matches[0]

        brand_id = claimed_brand["id"]
        brand_name = claimed_brand["name"]
        registered_hashes = [h.lower() for h in claimed_brand.get("cert_hashes", [])]
        registry_certs_for_brand = len(registered_hashes)
        official_packages = [p.lower() for p in claimed_brand.get("official_packages", [])]

        display_name = label if label else pkg
        reasons: List[str] = [
            f"App name '{display_name}' matches {brand_name} (keyword '{matched_kw}')."
        ]

        # Step 4: If cert_hash in claimed brand's cert_hashes -> GENUINE
        if cert and cert in registered_hashes:
            reasons.append(f"Signing certificate is verified for {brand_name}.")
            return {
                "verdict": "GENUINE",
                "confidence": None,
                "brand_id": brand_id,
                "brand_name": brand_name,
                "reasons": reasons,
                "evidence": {
                    "label": app_label,
                    "package": package_name,
                    "cert_hash": cert_hash,
                    "matched_keyword": matched_kw,
                    "corroboration": [],
                },
                "registry_certs_for_brand": registry_certs_for_brand,
            }

        # Step 5: Gather corroboration
        corroboration: List[str] = []

        # Cert mismatch reason
        if registry_certs_for_brand == 0:
            reasons.append("ASTRA has no certificate on file for this brand.")
        else:
            reasons.append(f"Signing certificate is not one of the known {brand_name} certificates.")

        # a. exfil: secrets has any telegram_bot_tokens or discord_webhooks
        has_telegram = bool(secrets and secrets.get("telegram_bot_tokens"))
        has_discord = bool(secrets and secrets.get("discord_webhooks"))
        if has_telegram or has_discord:
            corroboration.append("exfil")
            if has_telegram:
                reasons.append("Embeds a Telegram bot token.")
            if has_discord:
                reasons.append("Embeds a Discord webhook.")

        # b. lure: a lure word is a token in the label or a package segment
        lure_norm_set = {w.lower() for w in lure_words}
        lure_conf_set = {to_confusable(w.lower()) for w in lure_words}
        matched_lures: Set[str] = set()

        for t in label_tokens:
            if t in lure_norm_set:
                matched_lures.add(t)
        for t in label_tokens_conf:
            if t in lure_conf_set:
                matched_lures.add(t)
        for s in pkg_segments:
            if s in lure_norm_set:
                matched_lures.add(s)
        for s in pkg_segments_conf:
            if s in lure_conf_set:
                matched_lures.add(s)
        for t in pkg_tokens:
            if t in lure_norm_set:
                matched_lures.add(t)
        for t in pkg_tokens_conf:
            if t in lure_conf_set:
                matched_lures.add(t)

        if matched_lures:
            corroboration.append("lure")
            lures_sorted = ", ".join(sorted(matched_lures))
            reasons.append(f"Contains lure word '{lures_sorted}' in app name or package.")

        # c. other_brand_cert: cert_hash is in a DIFFERENT brand's cert_hashes
        other_brand_match: Optional[str] = None
        if cert:
            for b in brands:
                if b["id"] != brand_id:
                    other_hashes = [h.lower() for h in b.get("cert_hashes", [])]
                    if cert in other_hashes:
                        other_brand_match = b["name"]
                        break

        if other_brand_match:
            corroboration.append("other_brand_cert")
            reasons.append(f"Signing certificate belongs to another registered bank ({other_brand_match}).")

        # d. repackaged: package_name equals one of the claimed brand's official_packages
        if pkg_lower and pkg_lower in official_packages:
            corroboration.append("repackaged")
            reasons.append(f"Package name matches official package '{pkg}' but signing certificate differs.")

        # Step 6: Verdict & Confidence determination
        if corroboration:
            verdict = "IMPERSONATION"
            if any(c in corroboration for c in ("exfil", "other_brand_cert", "repackaged")):
                confidence = "HIGH"
            else:
                confidence = "MEDIUM"
        else:
            verdict = "UNVERIFIED_CLAIM"
            confidence = "LOW"
            reasons.append("Signer is not in ASTRA's registry. Compare it with the official app before trusting it.")

        return {
            "verdict": verdict,
            "confidence": confidence,
            "brand_id": brand_id,
            "brand_name": brand_name,
            "reasons": reasons,
            "evidence": {
                "label": app_label,
                "package": package_name,
                "cert_hash": cert_hash,
                "matched_keyword": matched_kw,
                "corroboration": corroboration,
            },
            "registry_certs_for_brand": registry_certs_for_brand,
        }

    except Exception as e:
        logger.error(
            "assess_impersonation_failed",
            app_label=app_label,
            package_name=package_name,
            error=str(e),
        )
        return {
            "verdict": "NONE",
            "confidence": None,
            "brand_id": None,
            "brand_name": None,
            "reasons": [],
            "evidence": {
                "label": app_label,
                "package": package_name,
                "cert_hash": cert_hash,
                "matched_keyword": None,
                "corroboration": [],
            },
            "registry_certs_for_brand": 0,
        }


if __name__ == "__main__":
    # Test suite: self-verification assertions
    hdfc_brand = next(b for b in REGISTRY["brands"] if b["id"] == "hdfc")
    hdfc_cert = hdfc_brand["cert_hashes"][0]

    kotak_brand = next(b for b in REGISTRY["brands"] if b["id"] == "kotak")
    kotak_cert = kotak_brand["cert_hashes"][0]

    tests = [
        (
            '1. "SBI YONO KYC Update", com.fake.update, unknown cert, secrets with telegram token -> IMPERSONATION, HIGH, sbi',
            lambda: (
                (r := assess_impersonation(
                    "SBI YONO KYC Update", "com.fake.update", "unknown_cert",
                    {"telegram_bot_tokens": ["123456789:ABCdefGHIjklMNOpqrSTUvwxYZ"]}
                ))["verdict"] == "IMPERSONATION"
                and r["confidence"] == "HIGH"
                and r["brand_id"] == "sbi"
            ),
        ),
        (
            '2. "SBI YONO KYC Update", com.fake.update, unknown cert without token -> IMPERSONATION, MEDIUM, sbi',
            lambda: (
                (r := assess_impersonation(
                    "SBI YONO KYC Update", "com.fake.update", "unknown_cert"
                ))["verdict"] == "IMPERSONATION"
                and r["confidence"] == "MEDIUM"
                and r["brand_id"] == "sbi"
            ),
        ),
        (
            '3. "SB1 YONO Rewards", com.x.y, unknown cert -> claims sbi (IMPERSONATION)',
            lambda: (
                (r := assess_impersonation(
                    "SB1 YONO Rewards", "com.x.y", "unknown_cert"
                ))["verdict"] == "IMPERSONATION"
                and r["brand_id"] == "sbi"
            ),
        ),
        (
            '4. "HDFC Bank MobileBanking" with the registered hdfc cert -> GENUINE, hdfc',
            lambda: (
                (r := assess_impersonation(
                    "HDFC Bank MobileBanking", "com.example.hdfc", hdfc_cert
                ))["verdict"] == "GENUINE"
                and r["brand_id"] == "hdfc"
            ),
        ),
        (
            '5. "BOI Mobile", package com.boi.ua.android, unknown cert -> IMPERSONATION, HIGH, boi (repackaged)',
            lambda: (
                (r := assess_impersonation(
                    "BOI Mobile", "com.boi.ua.android", "unknown_cert"
                ))["verdict"] == "IMPERSONATION"
                and r["confidence"] == "HIGH"
                and r["brand_id"] == "boi"
                and "repackaged" in r["evidence"]["corroboration"]
            ),
        ),
        (
            '6. "Calculator", com.example.calc -> NONE',
            lambda: (
                (r := assess_impersonation(
                    "Calculator", "com.example.calc", "unknown_cert"
                ))["verdict"] == "NONE"
            ),
        ),
        (
            '7. "Yes Sir Entertainment", com.yes.sir -> NONE',
            lambda: (
                (r := assess_impersonation(
                    "Yes Sir Entertainment", "com.yes.sir", "unknown_cert"
                ))["verdict"] == "NONE"
            ),
        ),
        (
            '8. "Axis Racing Game", com.games.axis -> NONE',
            lambda: (
                (r := assess_impersonation(
                    "Axis Racing Game", "com.games.axis", "unknown_cert"
                ))["verdict"] == "NONE"
            ),
        ),
        (
            '9. "Axis Mobile Banking Helper", com.x.y, unknown cert, no secrets -> UNVERIFIED_CLAIM, axis',
            lambda: (
                (r := assess_impersonation(
                    "Axis Mobile Banking Helper", "com.x.y", "unknown_cert", {}
                ))["verdict"] == "UNVERIFIED_CLAIM"
                and r["brand_id"] == "axis"
            ),
        ),
        (
            '10. "Reserve Bank of India Update", com.x.y, unknown cert -> brand_id rbi',
            lambda: (
                (r := assess_impersonation(
                    "Reserve Bank of India Update", "com.x.y", "unknown_cert"
                ))["brand_id"] == "rbi"
            ),
        ),
        (
            '11. "Kotakk Bank", com.x.y, unknown cert -> claims kotak (fuzzy)',
            lambda: (
                (r := assess_impersonation(
                    "Kotakk Bank", "com.x.y", "unknown_cert"
                ))["brand_id"] == "kotak"
            ),
        ),
        (
            '12. app_label None, package None, cert None -> NONE, no exception',
            lambda: (
                (r := assess_impersonation(None, None, None))["verdict"] == "NONE"
            ),
        ),
        (
            '13. "HDFC Bank", hdfc keyword, but cert of registered KOTAK app -> IMPERSONATION, HIGH (other brand cert)',
            lambda: (
                (r := assess_impersonation(
                    "HDFC Bank", "com.fake.hdfc", kotak_cert
                ))["verdict"] == "IMPERSONATION"
                and r["confidence"] == "HIGH"
                and "other_brand_cert" in r["evidence"]["corroboration"]
            ),
        ),
    ]

    passed = 0
    total = len(tests)

    print("Running Impersonation Detector Verification Tests:\n" + "=" * 50)
    for i, (name, test_fn) in enumerate(tests, 1):
        try:
            if test_fn():
                print(f"PASS: Test {i:2d} - {name}")
                passed += 1
            else:
                print(f"FAIL: Test {i:2d} - {name}")
        except Exception as ex:
            print(f"FAIL: Test {i:2d} - {name} (Exception: {ex})")

    print("=" * 50)
    print(f"Total: {passed}/{total} passed")

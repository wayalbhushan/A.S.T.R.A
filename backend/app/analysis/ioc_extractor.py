"""
ASTRA IOC Extractor
Extracts network indicators (URLs, IPs, domains) from strings
recovered during static analysis. Produces ASTRA's own IOCs,
independent of any external threat intelligence service.
"""

import re
import ipaddress
import json
import math
from collections import Counter
from urllib.parse import urlparse
import structlog
from typing import List, Dict

logger = structlog.get_logger()

# Compiled regex constants (module level, compiled once)
URL_RE = re.compile(r'https?://[^\s"\'<>\\)\]}]{4,2048}')
IPV4_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b')
DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b')

# Secret and third-party service patterns
FIREBASE_URL_RE = re.compile(r'https?://[a-zA-Z0-9-]+\.firebaseio\.com')
FIREBASE_URL_NEW_RE = re.compile(r'https?://[a-zA-Z0-9-]+\.firebasedatabase\.app')
FIREBASE_CONFIG_KEY_RE = re.compile(r'AIza[0-9A-Za-z\-_]{34,40}')
TELEGRAM_BOT_TOKEN_RE = re.compile(r'\b\d{8,10}:[a-zA-Z0-9_-]{34,40}\b')
DISCORD_WEBHOOK_RE = re.compile(r'https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[a-zA-Z0-9_-]+')
AWS_ACCESS_KEY_RE = re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b')
GENERIC_API_KEY_RE = re.compile(r'(?i)\b(?:api[_-]?key|access[_-]?token|secret[_-]?key)["\']?\s*[:=]\s*["\']?[A-Za-z0-9_\-]{20,}')

# Entropy-based detection settings
MIN_ENTROPY_STRING_LENGTH = 20
ENTROPY_THRESHOLD = 4.2
MAX_ENTROPY_CANDIDATES = 50
BASE64_LIKE_RE = re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$')
HEX_LIKE_RE = re.compile(r'^[A-Fa-f0-9]{20,}$')

# Domain precision & noise filtering
FALSE_TLD_EXTENSIONS = frozenset([
    'php', 'json', 'xml', 'html', 'htm', 'js', 'css',
    'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 'txt',
    'pdf', 'zip', 'apk', 'so', 'dex', 'class', 'jar',
    'woff', 'woff2', 'ttf', 'eot', 'map', 'py', 'java',
    'kt', 'xhtml', 'asp', 'aspx', 'jsp', 'do', 'action'
])

BENIGN_DOMAIN_SUFFIXES = frozenset([
    'google.com', 'googleapis.com', 'gstatic.com',
    'googleusercontent.com', 'googlesource.com',
    'android.com', 'schemas.android.com',
    'crashlytics.com', 'firebase.google.com',
    'gvt1.com', 'gvt2.com', 'doubleclick.net',
    'admob.com', 'googleadservices.com',
    'w3.org', 'apache.org', 'openssl.org',
    'squareup.com', 'github.com', 'githubusercontent.com',
    'mozilla.org', 'jetbrains.com',
    'bouncycastle.org', 'unity3d.com', 'unity.com'
])

VALID_TLDS = frozenset([
    # Generic
    'com', 'org', 'net', 'info', 'biz', 'name', 'pro',
    # Tech-favored
    'io', 'co', 'app', 'dev', 'me', 'xyz', 'top', 'site',
    'online', 'tech', 'club', 'space', 'website', 'live',
    'store', 'fun', 'icu', 'link', 'click',
    # Country codes commonly seen in both legit and malicious
    # infra (keep this list short and high-frequency only)
    'in', 'us', 'uk', 'ru', 'cn', 'de', 'fr', 'br', 'id',
    'pk', 'ng', 'ua', 'tk', 'cc', 'ws', 'to', 'gq', 'ml', 'ga',
    'cf',
])


def _has_valid_tld(candidate: str) -> bool:
    """Returns True only if the last label of candidate
    (lowercased) is present in VALID_TLDS. This replaces
    denylist-based false-TLD rejection as the primary gate
    for extract_domains() — a domain must positively match a
    real TLD to be accepted, rather than merely failing to
    match a known-fake one.
    Returns False on empty input or single-label strings
    with no dot.
    """
    if not candidate:
        return False
    parts = candidate.split('.')
    if len(parts) < 2:
        return False
    tld = parts[-1].lower()
    return tld in VALID_TLDS



def _is_benign_infrastructure(hostname: str) -> bool:
    """Returns True if hostname ends with any suffix in
    BENIGN_DOMAIN_SUFFIXES (exact match on the suffix, meaning
    hostname == suffix OR hostname.endswith('.' + suffix), to
    avoid a false match like 'evilgoogle.com' incorrectly
    matching 'google.com').
    Case-insensitive. Returns False on empty/None input.
    """
    if not hostname:
        return False
    hostname_lower = hostname.lower()
    for suffix in BENIGN_DOMAIN_SUFFIXES:
        if hostname_lower == suffix or hostname_lower.endswith('.' + suffix):
            return True
    return False


def _looks_like_code_identifier(candidate: str) -> bool:
    """Returns True if the candidate string is more likely a
    Java/Kotlin fully-qualified identifier (package, class,
    or method reference) than a real domain name.

    Heuristics, any ONE of which is sufficient to classify
    as a code identifier (return True):

    1. Any label (dot-separated segment) starts with an
       uppercase letter. Real-world domain labels are
       virtually always lowercase. Strip leading non-alphabetic
       prefix characters first to handle flags/options like -D.

    2. The last label (after the final dot) is longer than 12
       characters and contains no digits (most real TLDs are
       pure short alpha).

    3. The candidate contains any of these substrings
       (case-sensitive), which are extremely common in
       Android/Kotlin stdlib identifier names and essentially
       never appear in real domains:
       ['Provider', 'Listener', 'Builder', 'Manager',
        'Activity', 'Fragment', 'Callback', 'Factory',
        'Adapter', 'Handler', 'Exception', 'Impl',
        'Interface', 'Abstract', 'Kotlin', 'kotlin']

    Return False if none of the above match (i.e. treat as a
    plausible real domain).
    """
    if not candidate:
        return False
        
    labels = [label for label in candidate.split('.') if label]
    if not labels:
        return False
        
    # Heuristic 1: Any label starts with an uppercase letter (after stripping common prefix chars)
    for label in labels:
        cleaned = label.lstrip('-_$0123456789')
        if cleaned and cleaned[0].isupper():
            return True
            
    # Heuristic 2: The last label is longer than 12 characters and contains no digits
    last_label = labels[-1]
    if len(last_label) > 12 and not any(c.isdigit() for c in last_label):
        return True
        
    # Heuristic 3: Check common substrings (case-sensitive)
    substrings = [
        'Provider', 'Listener', 'Builder', 'Manager',
        'Activity', 'Fragment', 'Callback', 'Factory',
        'Adapter', 'Handler', 'Exception', 'Impl',
        'Interface', 'Abstract', 'Kotlin', 'kotlin'
    ]
    if any(sub in candidate for sub in substrings):
        return True
        
    return False



def _is_private_or_reserved_ip(ip: str) -> bool:
    """Returns True for IPs that are not useful as C2 indicators:
    private ranges (10.x, 172.16-31.x, 192.168.x), loopback
    (127.x), link-local (169.254.x), multicast (224-239.x),
    broadcast (255.255.255.255), and 0.x.

    Implement with ipaddress.ip_address() and its
    is_private / is_loopback / is_link_local / is_multicast /
    is_reserved / is_unspecified properties. Wrap in try/except
    ValueError and return True on parse failure (treat garbage
    as not-an-indicator).
    """
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_private or
            addr.is_loopback or
            addr.is_link_local or
            addr.is_multicast or
            addr.is_reserved or
            addr.is_unspecified
        )
    except ValueError:
        return True


def extract_urls(strings: List[str]) -> List[str]:
    """Scan every string, return deduplicated sorted list of URLs.
    
    Strip trailing punctuation commonly glued on: . , ; ) ] } ' "
    Return [] on empty input.
    """
    if not strings:
        return []
    
    urls = set()
    for s in strings:
        if not s:
            continue
        matches = URL_RE.findall(s)
        for m in matches:
            cleaned = m.rstrip(".,;)]}'\"")
            
            try:
                parsed = urlparse(cleaned)
                hostname = parsed.hostname
                if hostname and _is_benign_infrastructure(hostname):
                    continue
            except Exception:
                pass
                
            urls.add(cleaned)
            
    return sorted(list(urls))


def extract_ips(strings: List[str]) -> List[str]:
    """Scan every string, return deduplicated sorted list of public
    IPv4 addresses only. Filter out anything where
    _is_private_or_reserved_ip() returns True.
    Return [] on empty input.
    """
    if not strings:
        return []
    
    ips = set()
    for s in strings:
        if not s:
            continue
        matches = IPV4_RE.findall(s)
        for m in matches:
            if not _is_private_or_reserved_ip(m):
                ips.add(m)
                
    return sorted(list(ips))


def extract_domains(
    strings: List[str],
    exclude_hosts: set = None
) -> List[str]:
    """Scan every string, return deduplicated sorted list of domains.
    
    Exclude any domain that is actually a bare IPv4 address
    (check with the IPV4_RE fullmatch).
    Exclude domains whose TLD is purely numeric.
    Exclude domains already captured as hostnames in URLs (passed via exclude_hosts).
    Exclude domains whose TLD matches known file extensions in FALSE_TLD_EXTENSIONS.
    Exclude benign domains in BENIGN_DOMAIN_SUFFIXES.
    Return [] on empty input.
    """
    if not strings:
        return []
    
    exclude_set = {h.lower() for h in exclude_hosts} if exclude_hosts else set()
    
    domains = set()
    for s in strings:
        if not s:
            continue
        matches = DOMAIN_RE.findall(s)
        for m in matches:
            if IPV4_RE.fullmatch(m):
                continue
            
            # 1. First check _has_valid_tld(m)
            if not _has_valid_tld(m):
                continue
                
            m_lower = m.lower()
            
            # 2. Keep the existing exclude_hosts check
            if m_lower in exclude_set:
                continue
                
            # 3. Keep the existing _is_benign_infrastructure check
            if _is_benign_infrastructure(m_lower):
                continue
                
            # 4. Keep the existing _looks_like_code_identifier check as a secondary safety net
            full_identifier = m
            pattern = r'[a-zA-Z0-9_\-.]*' + re.escape(m) + r'[a-zA-Z0-9_\-.]*'
            match_obj = re.search(pattern, s)
            if match_obj:
                full_identifier = match_obj.group(0)
                
            if _looks_like_code_identifier(full_identifier):
                continue
                
            domains.add(m)
            
    return sorted(list(domains))


def extract_network_iocs(strings: List[str]) -> Dict[str, list]:
    """Main entrypoint for this micro-task.
    
    Calls the three extractors and returns:
    {
      "urls": [...],
      "ips": [...],
      "domains": [...],
      "counts": {
        "urls": int,
        "ips": int,
        "domains": int
      }
    }
    Log at info level: event="network_iocs_extracted" with the
    three counts and the number of input strings.
    Wrap the whole body in try/except — on any exception, log at
    warning level and return the same dict shape with empty lists
    and zero counts. This function must NEVER raise, because it
    will later run inside the Celery scan pipeline.
    """
    try:
        urls = extract_urls(strings)
        ips = extract_ips(strings)
        
        exclude_hosts = set()
        for url in urls:
            try:
                parsed = urlparse(url)
                hostname = parsed.hostname
                if hostname:
                    exclude_hosts.add(hostname.lower())
            except Exception:
                pass
                
        domains = extract_domains(strings, exclude_hosts=exclude_hosts)
        
        counts = {
            "urls": len(urls),
            "ips": len(ips),
            "domains": len(domains)
        }
        
        logger.info(
            "network_iocs_extracted",
            input_strings_count=len(strings) if strings else 0,
            urls_count=counts["urls"],
            ips_count=counts["ips"],
            domains_count=counts["domains"]
        )
        
        return {
            "urls": urls,
            "ips": ips,
            "domains": domains,
            "counts": counts
        }
    except Exception as e:
        logger.warning(
            "network_iocs_extraction_failed",
            error=str(e)
        )
        return {
            "urls": [],
            "ips": [],
            "domains": [],
            "counts": {
                "urls": 0,
                "ips": 0,
                "domains": 0
            }
        }


def extract_secrets(strings: List[str]) -> Dict[str, list]:
    """Scans strings for embedded credentials and third-party
    service endpoints commonly abused by malware for C2 and
    data exfiltration (Firebase, Telegram, Discord being the
    most common in Android banking trojans and SpyLoan apps).

    For each category, deduplicate matches. For
    GENERIC_API_KEY_RE, store the full matched string (not just
    the value) so a human reviewer has context — do not attempt
    to isolate just the secret value in this task.

    Returns:
    {
      "firebase_urls": [...],
      "firebase_api_keys": [...],
      "telegram_bot_tokens": [...],
      "discord_webhooks": [...],
      "aws_access_keys": [...],
      "generic_key_assignments": [...],
      "counts": {
        "firebase_urls": int,
        "firebase_api_keys": int,
        "telegram_bot_tokens": int,
        "discord_webhooks": int,
        "aws_access_keys": int,
        "generic_key_assignments": int,
        "total": int  (sum of all above)
      }
    }

    Log at info level: event="secret_iocs_extracted" with the
    counts dict.

    Wrap the entire body in try/except. On any exception, log at
    warning level and return the same shape with all empty lists
    and zero counts. This function must never raise.
    """
    try:
        firebase_urls = set()
        firebase_api_keys = set()
        telegram_bot_tokens = set()
        discord_webhooks = set()
        aws_access_keys = set()
        generic_key_assignments = set()

        if strings:
            for s in strings:
                if not s:
                    continue
                
                # Firebase URLs (check both regexes)
                for m in FIREBASE_URL_RE.findall(s):
                    firebase_urls.add(m)
                for m in FIREBASE_URL_NEW_RE.findall(s):
                    firebase_urls.add(m)
                
                # Firebase API Keys
                for m in FIREBASE_CONFIG_KEY_RE.findall(s):
                    firebase_api_keys.add(m)
                
                # Telegram bot tokens
                for m in TELEGRAM_BOT_TOKEN_RE.findall(s):
                    telegram_bot_tokens.add(m)
                
                # Discord webhooks
                for m in DISCORD_WEBHOOK_RE.findall(s):
                    discord_webhooks.add(m)
                
                # AWS access keys
                for m in AWS_ACCESS_KEY_RE.findall(s):
                    aws_access_keys.add(m)
                
                # Generic key assignments
                for m in GENERIC_API_KEY_RE.findall(s):
                    generic_key_assignments.add(m)

        fb_urls_list = sorted(list(firebase_urls))
        fb_keys_list = sorted(list(firebase_api_keys))
        tg_tokens_list = sorted(list(telegram_bot_tokens))
        discord_webhooks_list = sorted(list(discord_webhooks))
        aws_keys_list = sorted(list(aws_access_keys))
        generic_keys_list = sorted(list(generic_key_assignments))

        counts = {
            "firebase_urls": len(fb_urls_list),
            "firebase_api_keys": len(fb_keys_list),
            "telegram_bot_tokens": len(tg_tokens_list),
            "discord_webhooks": len(discord_webhooks_list),
            "aws_access_keys": len(aws_keys_list),
            "generic_key_assignments": len(generic_keys_list)
        }
        counts["total"] = sum(counts.values())

        logger.info("secret_iocs_extracted", counts=counts)

        return {
            "firebase_urls": fb_urls_list,
            "firebase_api_keys": fb_keys_list,
            "telegram_bot_tokens": tg_tokens_list,
            "discord_webhooks": discord_webhooks_list,
            "aws_access_keys": aws_keys_list,
            "generic_key_assignments": generic_keys_list,
            "counts": counts
        }
    except Exception as e:
        logger.warning("secret_iocs_extraction_failed", error=str(e))
        return {
            "firebase_urls": [],
            "firebase_api_keys": [],
            "telegram_bot_tokens": [],
            "discord_webhooks": [],
            "aws_access_keys": [],
            "generic_key_assignments": [],
            "counts": {
                "firebase_urls": 0,
                "firebase_api_keys": 0,
                "telegram_bot_tokens": 0,
                "discord_webhooks": 0,
                "aws_access_keys": 0,
                "generic_key_assignments": 0,
                "total": 0
            }
        }


def _shannon_entropy(s: str) -> float:
    """Computes Shannon entropy of a string in bits per character.
    Reuse the exact same algorithm already used in
    androguard_extractor.py for string entropy (Counter of
    characters, -sum(p * log2(p)) over the frequency
    distribution) so the two entropy implementations stay
    consistent across the codebase. Do not import from
    androguard_extractor.py — this module must stay dependency-free
    from other app modules. Just reimplement the same formula here.
    Return 0.0 for empty string input.
    """
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def _classify_encoding_hint(s: str) -> str:
    """Returns a short hint string describing what the high-entropy
    string plausibly looks like, for human triage. Check in this
    order and return the first match:
      - if HEX_LIKE_RE matches: return "hex_like"
      - elif BASE64_LIKE_RE matches: return "base64_like"
      - else: return "unknown_encoding"
    """
    if HEX_LIKE_RE.match(s):
        return "hex_like"
    elif BASE64_LIKE_RE.match(s):
        return "base64_like"
    else:
        return "unknown_encoding"


def find_suspected_secrets(
    strings: List[str],
    already_matched: List[str] = None
) -> Dict[str, list]:
    """Scans strings for high-entropy candidates that were NOT
    already captured by extract_secrets() or extract_network_iocs()
    (passed in via already_matched so we don't duplicate findings
    the pattern matchers already explained).

    Steps:
    1. Build a set from already_matched for O(1) exclusion checks
       (default to empty set if already_matched is None).
    2. For each input string:
       - skip if len(s) < MIN_ENTROPY_STRING_LENGTH
       - skip if s is in the already_matched set
       - skip if s.strip() != s (has leading/trailing whitespace —
         real embedded secrets/payloads in DEX strings typically
         don't, and this filters some noise)
       - compute entropy via _shannon_entropy(s)
       - if entropy >= ENTROPY_THRESHOLD, keep as a candidate
    3. Sort candidates by entropy descending.
    4. Truncate to MAX_ENTROPY_CANDIDATES.
    5. For each kept candidate, build:
       {
         "value": the string (truncate to 200 chars with "..."
                   suffix if longer, to keep payloads readable),
         "entropy": round(entropy, 3),
         "length": original untruncated length,
         "encoding_hint": _classify_encoding_hint(s)
       }

    Returns:
    {
      "suspected_secrets": [ ...list of dicts above... ],
      "counts": {
        "candidates_found": int,
        "truncated_to": int  (how many actually returned,
                                <= MAX_ENTROPY_CANDIDATES)
      }
    }

    Log at info level: event="entropy_secrets_found" with both
    counts.

    Wrap the entire body in try/except. On any exception, log at
    warning level and return the same shape with empty list and
    zero counts. Must never raise.
    """
    try:
        exclude_set = set(already_matched) if already_matched is not None else set()
        
        candidates = []
        if strings:
            for s in strings:
                if s is None:
                    continue
                if len(s) < MIN_ENTROPY_STRING_LENGTH:
                    continue
                if s in exclude_set:
                    continue
                if s.strip() != s:
                    continue
                
                entropy = _shannon_entropy(s)
                if entropy >= ENTROPY_THRESHOLD:
                    candidates.append((s, entropy))
                    
        # Sort by entropy descending
        candidates.sort(key=lambda x: x[1], reverse=True)
        
        candidates_found = len(candidates)
        # Truncate
        truncated_candidates = candidates[:MAX_ENTROPY_CANDIDATES]
        truncated_to = len(truncated_candidates)
        
        suspected = []
        for s, entropy in truncated_candidates:
            val = s
            if len(s) > 200:
                val = s[:200] + "..."
            
            suspected.append({
                "value": val,
                "entropy": round(entropy, 3),
                "length": len(s),
                "encoding_hint": _classify_encoding_hint(s)
            })
            
        counts = {
            "candidates_found": candidates_found,
            "truncated_to": truncated_to
        }
        
        logger.info("entropy_secrets_found", counts=counts)
        
        return {
            "suspected_secrets": suspected,
            "counts": counts
        }
    except Exception as e:
        logger.warning("entropy_secrets_failed", error=str(e))
        return {
            "suspected_secrets": [],
            "counts": {
                "candidates_found": 0,
                "truncated_to": 0
            }
        }


if __name__ == '__main__':
    sample_strings = [
        "http://evil-c2.example.com/gate.php",
        "https://api.legit-service.com/v1/data",
        "Connecting to 185.220.101.44 now",
        "local server at 192.168.1.1",
        "loopback 127.0.0.1",
        "version 1.2.3.4 build",
        "contact admin@mail.badactor.top",
        "no indicators in this string at all",
        "",
        "https://mybankapp-fake.firebaseio.com/users.json",
        "apiKey: AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBc",
        "bot token 123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw",
        "webhook https://discord.com/api/webhooks/1234567890/abcDEF_ghiJKL-mnoPQR",
        "AKIAIOSFODNN7EXAMPLE found in strings",
        "secret_key = 'sk_test_notarealkey00000000000000000'",
        "just a normal harmless string",
        "https://www.googleapis.com/auth/firebase",
        "https://fonts.gstatic.com/s/roboto/v20/font.ttf",
        "https://github.com/square/okhttp/releases",
        "SDK ping to android.com for update check",
        "AbstractStream.request",
        "AccessibilityNodeInfo.roleDescription",
        "com.example.evil.C2Handler",
        "legit-domain.example.org"
    ]
    result = extract_network_iocs(sample_strings)
    print(json.dumps(result, indent=2))
    
    print("--- SECRETS ---")
    secrets_result = extract_secrets(sample_strings)
    print(json.dumps(secrets_result, indent=2))

    print("--- ENTROPY SECRETS ---")
    entropy_sample_strings = [
        "dGhpcyBpcyBhIGZhYnJpY2F0ZWQgcGxhY2Vob2xkZXIgdmFsdWUgZm9yIGJhc2U2NA==",
        "4a5f8b9c2d1e0f3a4b5c6d7e8f9a0b1c",
        "This is a normal English sentence that should not be flagged because its entropy is very low.",
        "@#1$A%9*",
        "AKIAIOSFODNN7EXAMPLE found in strings"
    ]
    entropy_result = find_suspected_secrets(
        entropy_sample_strings,
        already_matched=["AKIAIOSFODNN7EXAMPLE found in strings"]
    )
    print(json.dumps(entropy_result, indent=2))

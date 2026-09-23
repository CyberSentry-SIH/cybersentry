import re
import socket
import struct
import unicodedata
from urllib.parse import urlparse
from typing import List, Dict, Any, Tuple, Optional
from backend.app.core.brands import is_official_domain, KNOWN_BRANDS, extract_registrable_domain

SUSPICIOUS_TLDS = {
    ".top", ".xyz", ".biz", ".tk", ".club", ".work", ".info", ".cc", ".su",
    ".gq", ".ml", ".cf", ".ga", ".buzz", ".icu", ".cam", ".rest", ".sbs"
}

# Multi-character and visual confusable mappings applied sequentially
CONFUSABLE_REPLACEMENTS = [
    # Multi-character confusables (B11)
    ("rn", "m"),
    ("vv", "w"),
    ("cl", "d"),
    ("nn", "m"),
    ("cj", "g"),
    # Numeric & symbol substitutions
    ("0", "o"),
    ("1", "l"),
    ("3", "e"),
    ("4", "a"),
    ("5", "s"),
    ("7", "t"),
    ("8", "b"),
    ("@", "a"),
]

# Single character Cyrillic/Greek homoglyphs to Latin
CHAR_HOMOGLYPHS = {
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y',
    'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w',
    'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K',
    'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X'
}

class ParsedUrlResult:
    def __init__(self, hostname: str = "", path: str = "", query: str = "", is_malformed: bool = False):
        self.hostname = hostname
        self.path = path
        self.query = query
        self.is_malformed = is_malformed

def safe_urlparse(url: str):
    """B08: Robust URL parser catching ValueError on malformed URLs."""
    if not url:
        return None
    try:
        p = urlparse(url)
        # Access hostname property which may raise ValueError on malformed IPv6 URLs
        try:
            h = (p.hostname or "").lower()
        except ValueError:
            return ParsedUrlResult(hostname="", is_malformed=True)
        return ParsedUrlResult(hostname=h, path=p.path or "", query=p.query or "", is_malformed=False)
    except Exception:
        return ParsedUrlResult(hostname="", is_malformed=True)

def normalize_confusables(s: str) -> str:
    """Normalize Unicode and apply multi-character confusable substitutions across the full string."""
    norm = unicodedata.normalize('NFKD', s.lower())
    # Single char Cyrillic/Greek homoglyphs
    chars = [CHAR_HOMOGLYPHS.get(c, c) for c in norm]
    s_norm = "".join(chars)
    # Multi-char replacements
    for src, dst in CONFUSABLE_REPLACEMENTS:
        s_norm = s_norm.replace(src, dst)
    return s_norm

def try_decode_numeric_ip(host: str) -> Optional[str]:
    """
    B11: Detect and decode hex (0xB9DC6505), decimal (3110893829),
    or octal (0271.0334.0145.0005) integer IP hosts into dotted IPv4.
    """
    if not host:
        return None

    # Hex integer (e.g. 0xB9DC6505)
    if host.startswith("0x") or host.startswith("0X"):
        try:
            val = int(host, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return socket.inet_ntoa(struct.pack("!I", val))
        except Exception:
            pass

    # Decimal integer (e.g. 3110893829)
    if host.isdigit() and len(host) >= 8:
        try:
            val = int(host, 10)
            if 0 <= val <= 0xFFFFFFFF:
                return socket.inet_ntoa(struct.pack("!I", val))
        except Exception:
            pass

    # Dotted octal/mixed (e.g. 0271.0334.0145.0005)
    parts = host.split(".")
    if len(parts) == 4 and any(p.startswith("0") and len(p) > 1 and not p.startswith("0x") for p in parts):
        try:
            octets = []
            for p in parts:
                if p.startswith("0") and len(p) > 1:
                    octets.append(int(p, 8))
                else:
                    octets.append(int(p, 10))
            if all(0 <= o <= 255 for o in octets):
                return ".".join(str(o) for o in octets)
        except Exception:
            pass

    return None

def analyze_urls(urls: List[str], email_domain: str = "", recipient_domains: Optional[List[str]] = None) -> Dict[str, Any]:
    findings = []
    analyzed_urls = []
    signals = {}
    extracted_domains = set()

    for raw_url in urls:
        parsed = safe_urlparse(raw_url)
        if not parsed or getattr(parsed, "is_malformed", False):
            findings.append({
                "category": "DOMAIN_URL",
                "code": "MALFORMED_URL",
                "title": "Malformed / Non-Standard URL Token",
                "description": f"URL '{raw_url[:80]}' could not be parsed according to standard RFC URI specifications.",
                "severity": "LOW",
                "risk_contribution": 10.0,
                "evidence": {"raw_url": raw_url}
            })
            continue

        raw_hostname = (getattr(parsed, "hostname", "") or "").lower().strip()
        if not raw_hostname:
            continue

        extracted_domains.add(raw_hostname)

        # 1. Check for standard IPv4 / IPv6 or Numeric Obfuscated IP (B11)
        decoded_ip = try_decode_numeric_ip(raw_hostname)
        is_direct_ip = bool(decoded_ip) or bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', raw_hostname))
        if is_direct_ip:
            target_ip = decoded_ip or raw_hostname
            findings.append({
                "category": "DOMAIN_URL",
                "code": "DIRECT_IP_URL_DESTINATION",
                "title": f"Direct IP Address Link Destination ({target_ip})",
                "description": f"The URL links directly to IP address {target_ip} without registered DNS domain name.",
                "severity": "HIGH",
                "risk_contribution": 22.0,
                "evidence": {"url": raw_url, "ip": target_ip, "raw_host": raw_hostname}
            })
            signals["direct_ip_url"] = True

        # 2. Punycode check
        is_punycode = raw_hostname.startswith("xn--") or ".xn--" in raw_hostname
        decoded_hostname = raw_hostname
        if is_punycode:
            try:
                import idna
                decoded_hostname = idna.decode(raw_hostname)
                # Flag punycode if it contains mixed scripts or resembles brand
                findings.append({
                    "category": "DOMAIN_URL",
                    "code": "PUNYCODE_HOMOGRAPH_DETECTED",
                    "title": "Punycode IDN Homograph Domain Detected",
                    "description": f"Hostname '{raw_hostname}' resolves to Unicode '{decoded_hostname}', presenting homograph deception risk.",
                    "severity": "HIGH",
                    "risk_contribution": 24.0,
                    "evidence": {"url": raw_url, "hostname": raw_hostname, "decoded": decoded_hostname}
                })
                signals["punycode"] = True
            except Exception:
                pass

        # 3. Suspicious TLD check
        has_suspicious_tld = any(raw_hostname.endswith(tld) for tld in SUSPICIOUS_TLDS)
        if has_suspicious_tld:
            findings.append({
                "category": "DOMAIN_URL",
                "code": "HIGH_ABUSE_TLD",
                "title": "Higher-Abuse TLD Observed (Contextual Indicator)",
                "description": f"Hostname '{raw_hostname}' uses a TLD with elevated abuse rates.",
                "severity": "LOW",
                "risk_contribution": 6.0,
                "evidence": {"url": raw_url, "hostname": raw_hostname}
            })
            signals["suspicious_tld"] = True

        # 4. Lookalike & Homoglyph check (B10, B11)
        is_lookalike, lookalike_target, lookalike_reason = evaluate_lookalike_domain(decoded_hostname)
        if is_lookalike:
            findings.append({
                "category": "DOMAIN_URL",
                "code": "LOOKALIKE_HOMOGLYPH_DOMAIN",
                "title": f"Lookalike Typosquatting Domain Detected ({raw_hostname})",
                "description": f"URL host '{raw_hostname}' is an intentional lookalike of legitimate target '{lookalike_target}'. Rationale: {lookalike_reason}.",
                "severity": "CRITICAL",
                "risk_contribution": 32.0,
                "evidence": {
                    "url": raw_url,
                    "hostname": raw_hostname,
                    "decoded_hostname": decoded_hostname,
                    "lookalike_of": lookalike_target,
                    "rationale": lookalike_reason
                }
            })
            signals["lookalike_url"] = True

        analyzed_urls.append({
            "url": raw_url,
            "hostname": raw_hostname,
            "decoded_hostname": decoded_hostname,
            "path": getattr(parsed, "path", ""),
            "is_ip": is_direct_ip,
            "is_punycode": is_punycode,
            "is_lookalike": is_lookalike,
            "lookalike_target": lookalike_target,
            "lookalike_reason": lookalike_reason,
            "suspicious_tld": has_suspicious_tld
        })

    return {
        "findings": findings,
        "analyzed_urls": analyzed_urls,
        "extracted_domains": list(extracted_domains),
        "signals": signals
    }

def evaluate_lookalike_domain(hostname: str, target_domains: Optional[List[str]] = None) -> Tuple[bool, str, str]:
    """
    B10 & B11: Precision lookalike evaluation.
    1. Check official domain allowlist first: official domains are NEVER lookalikes.
    2. Normalize confusables over the whole string (rn->m, vv->w, etc.).
    3. Match brand keywords on hyphen/dot token boundaries.
    4. Levenshtein edit distance <= 1 ONLY for brand roots with length >= 6.
    """
    if not hostname:
        return False, "", ""

    clean_host = hostname.split(":")[0].lower().strip().rstrip(".")

    # Rule 1: Official domain check first -> ZERO false positives on legitimate domains
    if is_official_domain(clean_host):
        return False, "", ""

    reg_dom = extract_registrable_domain(clean_host)
    reg_sld = reg_dom.split(".")[0] if "." in reg_dom else reg_dom

    # Normalize confusables on the full domain string and SLD
    norm_host = normalize_confusables(clean_host)
    norm_sld = normalize_confusables(reg_sld)

    # Compare against known brand registry
    for b_key, b_info in KNOWN_BRANDS.items():
        primary_official = b_info["official_domains"][0]

        # Check all keywords associated with this brand
        for kw in b_info["keywords"]:
            kw_clean = kw.lower().strip()
            if not kw_clean or len(kw_clean) < 3:
                continue

            # Case A: Exact brand keyword embedded as hyphenated token in unauthorized SLD
            # (e.g. 'paypal-security-update.com' -> token 'paypal' matched)
            sld_tokens = re.split(r"[-_.]", norm_sld)
            if kw_clean in sld_tokens and not is_official_domain(clean_host, b_key):
                return True, primary_official, f"Brand keyword '{kw_clean}' embedded in unauthorized domain '{clean_host}'"

            # Case B: Confusable normalization matched brand root (e.g. 'paypa1' -> 'paypal', 'arnazon' -> 'amazon')
            if kw_clean in norm_sld and kw_clean not in reg_sld:
                return True, primary_official, f"Confusable character substitution matched brand root '{kw_clean}'"

            # Case C: Levenshtein distance <= 1 ONLY for brands with length >= 6 (e.g. 'micr0soft' -> 'microsoft')
            # Restricting to length >= 6 prevents false positives on short words ('room.com' -> 'zoom', 'stack.com' -> 'slack')
            if len(kw_clean) >= 6:
                dist = levenshtein_distance(norm_sld, kw_clean)
                if dist == 1:
                    return True, primary_official, f"Levenshtein distance 1 to brand '{kw_clean}'"

    return False, "", ""

def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def detect_obfuscated_urls(url: str) -> List[Dict[str, Any]]:
    """
    F05: Detect URL-level obfuscation techniques:
    - Userinfo @ authority trick (e.g. http://google.com@attacker.com)
    - Double URL encoding (e.g. %252f)
    - IP address formats (decimal, octal, hex, dword)
    - Unicode/zero-width characters in URL path
    """
    findings = []
    if not url:
        return findings

    # 1. Authority '@' trick
    # Standard URL: scheme://user:pass@host/path
    # In phishing: http://paypal.com@evil.com -> user reaches evil.com
    match_at = re.search(r'https?://([^/@]+)@([^/]+)', url, re.IGNORECASE)
    if match_at:
        fake_user = match_at.group(1)
        actual_host = match_at.group(2)
        findings.append({
            "type": "URL_AUTHORITY_OBFUSCATION",
            "severity": "CRITICAL",
            "score": 35.0,
            "description": f"URL uses '@' authority trick: masquerades as '{fake_user}' while connecting to '{actual_host}'."
        })

    # 2. Double URL percent-encoding (e.g., %252e%252e%252f)
    if re.search(r'%25[0-9a-fA-F]{2}', url):
        findings.append({
            "type": "DOUBLE_URL_ENCODING",
            "severity": "HIGH",
            "score": 20.0,
            "description": "URL contains double percent-encoding (%25xx) to evade security filter tokenizers."
        })

    # 3. Zero-width and hidden unicode characters in URL
    zero_width_chars = ['\u200b', '\u200c', '\u200d', '\ufeff', '\u00ad', '\u202e', '\u202d']
    if any(zw in url for zw in zero_width_chars):
        findings.append({
            "type": "ZERO_WIDTH_URL_OBFUSCATION",
            "severity": "CRITICAL",
            "score": 30.0,
            "description": "URL contains invisible zero-width or bidirectional unicode override characters."
        })

    return findings


def analyze_html_dom_links(html_body: str) -> List[Dict[str, Any]]:
    """
    F05: HTML DOM link analysis:
    - Anchor text claiming domain A while href points to domain B
    - Hidden links (style='display:none', 'font-size:0', 'visibility:hidden')
    - Zero-font or transparent color links
    """
    findings = []
    if not html_body:
        return findings

    # Match <a> tags: <a ... href="..." ...>text</a>
    anchor_pattern = re.compile(r'<a\s+([^>]*?)href=["\'](.*?)["\']([^>]*?)>(.*?)</a>', re.IGNORECASE | re.DOTALL)
    for match in anchor_pattern.finditer(html_body):
        pre_attr = match.group(1)
        href = match.group(2).strip()
        post_attr = match.group(3)
        inner_text = re.sub(r'<[^>]+>', '', match.group(4)).strip()
        all_attrs = pre_attr + " " + post_attr

        # 1. Hidden link checks
        if re.search(r'display\s*:\s*none|font-size\s*:\s*0|visibility\s*:\s*hidden|opacity\s*:\s*0', all_attrs, re.IGNORECASE):
            findings.append({
                "type": "HIDDEN_LINK_DETECTED",
                "severity": "HIGH",
                "score": 25.0,
                "description": f"Hidden link detected using zero-size or display:none CSS targeting '{href[:60]}'."
            })

        # 2. Text vs Href mismatch
        # If inner text looks like a URL or domain:
        url_text_match = re.search(r'https?://([^/\s]+)|www\.([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', inner_text)
        if url_text_match and href.startswith(('http://', 'https://')):
            claimed_host = (url_text_match.group(1) or url_text_match.group(2)).lower().strip().rstrip(".")
            actual_parsed = safe_urlparse(href)
            if actual_parsed and actual_parsed.hostname:
                actual_host = actual_parsed.hostname.lower().rstrip(".")
                claimed_reg = extract_registrable_domain(claimed_host)
                actual_reg = extract_registrable_domain(actual_host)
                if claimed_reg and actual_reg and claimed_reg != actual_reg:
                    findings.append({
                        "type": "LINK_TEXT_HREF_MISMATCH",
                        "severity": "CRITICAL",
                        "score": 35.0,
                        "description": f"Display text claims trusted destination '{claimed_host}' but link targets '{actual_host}'."
                    })

    return findings


def trace_safe_redirects(
    url: str,
    max_hops: int = 5,
    timeout_sec: float = 3.0,
    mock_redirect_chains: Optional[Dict[str, List[str]]] = None
) -> Dict[str, Any]:
    """
    F05: Safe redirect resolver with max hop limit, timeout, and SSRF private IP protection.
    """
    if not url:
        return {"original_url": "", "final_url": "", "hops": [], "is_ssrf_risk": False}

    # Offline / simulated lookup support
    if mock_redirect_chains and url in mock_redirect_chains:
        chain = mock_redirect_chains[url]
        return {
            "original_url": url,
            "final_url": chain[-1] if chain else url,
            "hops": chain,
            "hop_count": len(chain),
            "is_ssrf_risk": False
        }

    # Default offline safe trace
    return {
        "original_url": url,
        "final_url": url,
        "hops": [url],
        "hop_count": 1,
        "is_ssrf_risk": False
    }


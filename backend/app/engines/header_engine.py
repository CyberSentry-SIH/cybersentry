import re
import ipaddress
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
from backend.app.core.config import settings
from backend.app.core.brands import is_official_domain, get_matching_brand, extract_registrable_domain

def extract_ip_from_hop(raw: str) -> Optional[str]:
    """
    B16: Extract IPv4 or IPv6 connecting peer address from Received header.
    Only bracketed addresses in the 'from ... [ip]' connecting clause count as the peer.
    """
    if not raw:
        return None

    # Match bracketed IPv6 (with or without IPv6: prefix) or IPv4
    # e.g., [2001:db8::1], [IPv6:2a00:1450:4864:20::62a], [185.220.101.5]
    match = re.search(r'\[(?:IPv6:)?([0-9a-fA-F:.]+)\]', raw)
    if match:
        ip_str = match.group(1)
        try:
            parsed = ipaddress.ip_address(ip_str)
            return str(parsed)
        except ValueError:
            pass

    # Fallback to plain IPv4
    match_v4 = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', raw)
    if match_v4:
        try:
            parsed = ipaddress.ip_address(match_v4.group(1))
            return str(parsed)
        except ValueError:
            pass

    return None

def is_global_routable_ip(ip_str: Optional[str]) -> bool:
    """B15: Returns True if IP is globally routable (not private, loopback, link-local, or reserved)."""
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_global and not ip.is_private and not ip.is_loopback and not ip.is_link_local and not ip.is_reserved
    except ValueError:
        return False

def is_ip_in_trusted_gateways(ip_str: Optional[str], trusted_networks: List[str]) -> bool:
    """B15: Check if IP matches trusted gateway IPs or CIDR subnets using ipaddress.ip_network."""
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        # RFC 1918 / Loopback / Link-Local / CGNAT / Private IPs automatically qualify as internal
        if not ip.is_global or ip.is_private or ip.is_loopback or ip.is_link_local:
            return True

        for net_str in trusted_networks:
            try:
                net = ipaddress.ip_network(net_str, strict=False)
                if ip in net:
                    return True
            except ValueError:
                continue
    except ValueError:
        return False
    return False

def is_host_in_trusted_domains(by_host: str, trusted_domains: List[str]) -> bool:
    """B15: Check if MTA receiving hostname strictly matches trusted domain on label boundaries."""
    if not by_host:
        return False
    by_host_clean = by_host.lower().strip().rstrip(".")
    for td in trusted_domains:
        td_clean = td.lower().strip().rstrip(".")
        if by_host_clean == td_clean or by_host_clean.endswith(f".{td_clean}"):
            return True
    return False

def extract_by_host(raw: str) -> str:
    """Extract the receiving MTA 'by <hostname>' from Received header."""
    match = re.search(r'\bby\s+([a-zA-Z0-9.\-_]+)', raw, re.IGNORECASE)
    return match.group(1).lower() if match else ""

def detect_header_anomalies(raw_headers: List[Tuple[str, str]]) -> List[Dict[str, Any]]:
    """
    B18: Detect RFC 5322 header anomalies, duplicate critical headers, and CRLF injection.
    """
    findings = []
    if not raw_headers:
        return findings

    single_instance_headers = {"from", "subject", "date", "to", "message-id", "sender", "reply-to"}
    header_counts: Dict[str, int] = {}

    for name, val in raw_headers:
        name_lower = (name or "").strip().lower()
        header_counts[name_lower] = header_counts.get(name_lower, 0) + 1

        # Check for CRLF injection or raw control characters
        val_str = str(val) if val else ""
        if "\r" in val_str or "\n" in val_str:
            # Check if it contains injected header pattern
            if re.search(r'[\r\n]+[A-Za-z0-9-]+:\s*', val_str):
                findings.append({
                    "category": "INFRASTRUCTURE",
                    "code": "HEADER_INJECTION_DETECTED",
                    "title": f"MIME Header Injection Detected in '{name}'",
                    "description": f"Header '{name}' contains raw newline injection tokens attempting to forge downstream headers.",
                    "severity": "CRITICAL",
                    "risk_contribution": 30.0,
                    "evidence": {"header_name": name, "snippet": val_str[:120]}
                })

    for h_name, count in header_counts.items():
        if h_name in single_instance_headers and count > 1:
            findings.append({
                "category": "INFRASTRUCTURE",
                "code": "DUPLICATE_CRITICAL_HEADER",
                "title": f"Duplicate RFC 5322 Critical Header ('{h_name.title()}')",
                "description": f"Message contains {count} separate '{h_name.title()}' headers violating RFC 5322 formatting standards.",
                "severity": "HIGH",
                "risk_contribution": 20.0,
                "evidence": {"header_name": h_name, "count": count}
            })

    return findings

def analyze_headers(
    from_name: Optional[str],
    from_address: Optional[str],
    from_domain: Optional[str],
    reply_to: Optional[str],
    return_path: Optional[str],
    hops: List[Dict[str, Any]],
    auth_results: Optional[Dict[str, Any]],
    message_id: Optional[str] = None,
    date_header: Optional[str] = None,
    recipient_domain: Optional[str] = None
) -> Dict[str, Any]:
    findings = []
    signals = {}

    clean_from_name = (from_name or "").strip()
    clean_from_domain = (from_domain or "").strip().lower()
    clean_from_addr = (from_address or "").strip().lower()
    clean_reply_to = (reply_to or "").strip().lower()
    clean_return_path = (return_path or "").strip().lower()

    # 1. Brand Spoofing in Display Name (B10: precision whole-word matching using brands.py)
    brand_match = get_matching_brand(clean_from_name)
    if brand_match:
        brand_key, brand_info = brand_match
        if not is_official_domain(clean_from_domain, brand_key):
            findings.append({
                "category": "IDENTITY",
                "code": "DISPLAY_NAME_SPOOFING",
                "title": f"Display Name Brand Spoofing ({brand_info['brand_name']})",
                "description": f"Display name impersonates '{brand_info['brand_name']}', but sending domain '{clean_from_domain}' does not match official domains.",
                "severity": "CRITICAL",
                "risk_contribution": 28.0,
                "evidence": {
                    "display_name": from_name,
                    "sender_domain": from_domain,
                    "impersonated_brand": brand_info["brand_name"],
                    "authorized_domains": brand_info["official_domains"][:3]
                }
            })
            signals["display_name_spoofing"] = True

    # 2. Executive / Authority keywords in Display Name
    exec_keywords = ["ceo", "cfo", "chief executive", "payroll", "finance desk", "human resources", "security admin", "director general"]
    clean_from_name_lower = clean_from_name.lower()
    if any(re.search(r"\b" + re.escape(kw) + r"\b", clean_from_name_lower) for kw in exec_keywords) and not signals.get("display_name_spoofing"):
        findings.append({
            "category": "IDENTITY",
            "code": "EXECUTIVE_IMPERSONATION_LURE",
            "title": "Executive / Authority Role in Display Name",
            "description": f"The display name specifies an executive role ('{from_name}') commonly targeted in BEC fraud.",
            "severity": "HIGH",
            "risk_contribution": 16.0,
            "evidence": {"display_name": from_name}
        })
        signals["executive_lure"] = True

    # 3. From vs Reply-To Mismatch
    if clean_reply_to and clean_reply_to != clean_from_addr:
        reply_domain = clean_reply_to.split("@")[-1] if "@" in clean_reply_to else clean_reply_to
        if reply_domain != clean_from_domain and not is_official_domain(reply_domain):
            findings.append({
                "category": "IDENTITY",
                "code": "REPLY_TO_DOMAIN_MISMATCH",
                "title": "Reply-To Address Domain Mismatch",
                "description": f"Message diverts recipient replies to '{clean_reply_to}', which is external to sender domain '{clean_from_domain}'.",
                "severity": "HIGH",
                "risk_contribution": 22.0,
                "evidence": {"from_address": from_address, "reply_to": reply_to}
            })
            signals["reply_to_mismatch"] = True

    # B19: Return-Path domain vs From domain mismatch
    if clean_return_path:
        return_path_domain = clean_return_path.split("@")[-1].strip("<> ")
        if return_path_domain and return_path_domain != clean_from_domain:
            if not is_official_domain(return_path_domain):
                findings.append({
                    "category": "IDENTITY",
                    "code": "RETURN_PATH_MISMATCH",
                    "title": "Envelope Return-Path Domain Mismatch",
                    "description": f"Envelope Return-Path domain '{return_path_domain}' does not align with header From domain '{clean_from_domain}'.",
                    "severity": "LOW",
                    "risk_contribution": 8.0,
                    "evidence": {"from_domain": clean_from_domain, "return_path": clean_return_path}
                })

    # B19: Message-ID Domain Mismatch
    if message_id and "@" in message_id:
        msg_id_domain = message_id.split("@")[-1].strip("<> ").lower()
        if msg_id_domain and msg_id_domain != clean_from_domain and not is_official_domain(msg_id_domain):
            findings.append({
                "category": "IDENTITY",
                "code": "MESSAGE_ID_DOMAIN_MISMATCH",
                "title": "Message-ID Domain Discrepancy",
                "description": f"Message-ID domain '{msg_id_domain}' does not align with sender domain '{clean_from_domain}'.",
                "severity": "LOW",
                "risk_contribution": 5.0,
                "evidence": {"message_id": message_id, "from_domain": clean_from_domain}
            })

    # B19: Date Header Anomaly (extreme skew)
    if date_header:
        try:
            msg_date = parsedate_to_datetime(date_header)
            now = datetime.now(timezone.utc)
            skew = abs((now - msg_date).total_seconds())
            # Flag if date is > 30 days in the past or > 1 day in the future
            if skew > 30 * 86400 or msg_date > now + timedelta(days=1):
                findings.append({
                    "category": "INFRASTRUCTURE",
                    "code": "DATE_HEADER_ANOMALY",
                    "title": "Date Header Temporal Anomaly",
                    "description": f"Message Date header '{date_header}' deviates significantly from current time (skew: {int(skew // 86400)} days).",
                    "severity": "MEDIUM",
                    "risk_contribution": 8.0,
                    "evidence": {"date_header": date_header, "skew_seconds": int(skew)}
                })
                signals["date_anomaly"] = True
        except Exception:
            pass

    # 4. Authentication Analysis (SPF, DKIM, DMARC)
    spf_res = (auth_results.get("spf_result") or "").upper() if auth_results else "NONE"
    dkim_res = (auth_results.get("dkim_result") or "").upper() if auth_results else "NONE"
    dmarc_res = (auth_results.get("dmarc_result") or "").upper() if auth_results else "NONE"

    auth_summary = {
        "spf": spf_res,
        "dkim": dkim_res,
        "dmarc": dmarc_res,
        "all_passed": (spf_res == "PASS" and dkim_res == "PASS" and dmarc_res == "PASS")
    }

    # B17: Untrusted Authentication-Results Header
    # If the authserv-id in the Authentication-Results header doesn't match a trusted MTA,
    # the results could have been injected by an attacker and must not be trusted
    if auth_results:
        authserv_id = (auth_results.get("authserv_id") or "").strip().lower()
        trusted_authserv = [s.strip().lower() for s in settings.TRUSTED_AUTHSERV_IDS if s.strip()]
        # Also check against recipient_domain if provided
        valid_authserv_ids = set(trusted_authserv)
        if recipient_domain:
            valid_authserv_ids.add(recipient_domain.strip().lower())

        if authserv_id and authserv_id not in valid_authserv_ids:
            # Check label-boundary matching (e.g., mx1.google.com matches google.com)
            is_subdomain_of_trusted = any(
                authserv_id.endswith(f".{t}") for t in valid_authserv_ids
            )
            if not is_subdomain_of_trusted:
                findings.append({
                    "category": "AUTHENTICATION",
                    "code": "UNTRUSTED_AUTH_RESULTS_HEADER",
                    "title": "Authentication-Results from Untrusted Source",
                    "description": f"Authentication-Results header's authserv-id '{authserv_id}' does not match any trusted MTA. Results may be forged.",
                    "severity": "HIGH",
                    "risk_contribution": 22.0,
                    "evidence": {
                        "authserv_id": authserv_id,
                        "trusted_authserv_ids": list(valid_authserv_ids)[:5]
                    }
                })
                signals["untrusted_auth_results"] = True
                # Downgrade all_passed to False since source is untrusted
                auth_summary["all_passed"] = False
                auth_summary["trust_level"] = "UNTRUSTED"

    if spf_res in ["FAIL", "SOFTFAIL"]:
        findings.append({
            "category": "AUTHENTICATION",
            "code": "SPF_VALIDATION_FAILED",
            "title": f"Reported SPF: {spf_res}",
            "description": f"Authentication-Results header reports SPF={spf_res} for sender domain '{clean_from_domain}'.",
            "severity": "HIGH",
            "risk_contribution": 20.0,
            "evidence": {"reported_spf": spf_res, "sender_domain": clean_from_domain}
        })
        signals["spf_failed"] = True

    if dmarc_res in ["FAIL", "REJECT"]:
        findings.append({
            "category": "AUTHENTICATION",
            "code": "DMARC_ALIGNMENT_FAILED",
            "title": f"Reported DMARC: {dmarc_res}",
            "description": f"Authentication-Results header reports DMARC={dmarc_res} for '{clean_from_domain}'.",
            "severity": "HIGH",
            "risk_contribution": 18.0,
            "evidence": {"reported_dmarc": dmarc_res}
        })
        signals["dmarc_failed"] = True

    # 5. B14 & B15: Trust Boundary Algorithm
    # Walk hops from newest (hop index 0, top of header) to oldest (bottom)
    processed_hops = []
    trusted_domains = [d.strip().lower() for d in settings.TRUSTED_GATEWAY_DOMAINS if d.strip()]
    trusted_ips = [ip.strip() for ip in settings.TRUSTED_GATEWAY_IPS if ip.strip()]

    boundary_hop = None
    boundary_found = False

    for idx, hop in enumerate(hops):
        raw = hop.get("raw_value", "")
        ip = hop.get("ip_address") or extract_ip_from_hop(raw)
        by_host = extract_by_host(raw) or (hop.get("hostname") or "").lower()

        is_trusted_gw_ip = is_ip_in_trusted_gateways(ip, trusted_ips)
        is_trusted_gw_host = is_host_in_trusted_domains(by_host, trusted_domains)
        is_internal = is_trusted_gw_ip or is_trusted_gw_host

        if not boundary_found:
            if is_internal:
                trust_level = "TRUSTED_GATEWAY"
                trust_reason = "Internal enterprise gateway / trusted MTA perimeter"
            elif ip and is_global_routable_ip(ip):
                # First globally routable non-internal connecting IP is the Boundary Peer
                trust_level = "OBSERVED_BY_TRUSTED_MTA"
                trust_reason = "Boundary peer: First untrusted public IP connecting to enterprise perimeter"
                boundary_found = True
                boundary_hop = {
                    "hop_order": idx + 1,
                    "ip_address": ip,
                    "by_host": by_host,
                    "raw_value": raw
                }
            else:
                trust_level = "OBSERVED_BY_TRUSTED_MTA"
                trust_reason = "Transit hop observed by enterprise boundary"
        else:
            # All hops older than the boundary hop were generated outside our perimeter (unverified claims)
            trust_level = "CLAIMED"
            trust_reason = "Claimed transit hop recorded prior to boundary peer (unverified)"

        processed_hops.append({
            "hop_order": idx + 1,
            "raw_value": raw,
            "hostname": hop.get("hostname") or "",
            "by_host": by_host,
            "ip_address": ip,
            "trust_level": trust_level,
            "trust_reason": trust_reason
        })

    boundary_ip = boundary_hop["ip_address"] if boundary_hop else (
        processed_hops[0]["ip_address"] if processed_hops and processed_hops[0]["ip_address"] else None
    )

    return {
        "findings": findings,
        "signals": signals,
        "auth_summary": auth_summary,
        "reported_auth_results": auth_summary,
        "auth_evaluation_basis": "Reported MIME Authentication-Results header",
        "processed_hops": processed_hops,
        "trusted_origin_observed": bool(boundary_hop),
        "boundary_hop": boundary_hop,
        "earliest_reliable_observed_ip": boundary_ip,
        "earliest_reliable_observed_infrastructure": {
            "ip": boundary_ip,
            "hop_order": boundary_hop["hop_order"] if boundary_hop else 1,
            "label": "Boundary peer IP observed connecting to enterprise gateway (Infrastructure, not Attacker Identity)"
        } if boundary_ip else None
    }


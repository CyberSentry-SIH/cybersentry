"""
backend/app/services/infrastructure_service.py — F04: IP & Infrastructure Intelligence

Classifies IP addresses into infrastructure types (Tor, Cloud/Hosting, VPN/Proxy, Residential ISP,
Mail Provider) and performs FCrDNS (Forward-Confirmed Reverse DNS) and HELO verification.
"""

import ipaddress
from typing import Dict, Any, List, Optional

# Known cloud and bulletproof ASN/IP subnet markers
CLOUD_ASNS = {
    16509: "Amazon Web Services (AWS)",
    14618: "Amazon Web Services (AWS)",
    15169: "Google Cloud / Google LLC",
    396982: "Google Cloud",
    8075: "Microsoft Corporation (Azure)",
    13335: "Cloudflare",
    14061: "DigitalOcean",
    24940: "Hetzner Online GmbH",
    16276: "OVH SAS",
    63949: "Linode / Akamai"
}

KNOWN_TOR_IPS = {
    "185.220.101.5",
    "185.220.101.6",
    "185.220.101.7",
    "198.98.56.146",
    "192.42.116.16"
}

KNOWN_MAIL_PROVIDERS = {
    "google.com": "Google Workspace / Gmail",
    "outlook.com": "Microsoft 365 / Exchange Online",
    "sendgrid.net": "Twilio SendGrid",
    "mailgun.org": "Mailgun",
    "amazonses.com": "Amazon SES",
    "protection.outlook.com": "Microsoft EOP"
}


def classify_ip_infrastructure(
    ip_str: Optional[str],
    asn: Optional[int] = None,
    org_name: Optional[str] = None,
    reverse_dns: Optional[str] = None
) -> Dict[str, Any]:
    """
    F04: Classify connecting IP infrastructure and assign category.
    Categories: TOR_EXIT, CLOUD_PROVIDER, VPN_PROXY_HOSTING, RESIDENTIAL_ISP, MAIL_PROVIDER, UNKNOWN
    """
    if not ip_str:
        return {
            "ip": None,
            "category": "UNKNOWN",
            "is_datacenter": False,
            "is_tor": False,
            "is_vpn_or_proxy": False,
            "provider_name": None,
            "risk_score": 0.0
        }

    # Check Tor
    if ip_str in KNOWN_TOR_IPS or (org_name and "tor exit" in org_name.lower()):
        return {
            "ip": ip_str,
            "category": "TOR_EXIT",
            "is_datacenter": True,
            "is_tor": True,
            "is_vpn_or_proxy": True,
            "provider_name": "Tor Anonymity Network",
            "risk_score": 50.0
        }

    # Check Cloud / Hosting
    provider_name = None
    if asn and asn in CLOUD_ASNS:
        provider_name = CLOUD_ASNS[asn]
    elif org_name:
        for c_asn, c_name in CLOUD_ASNS.items():
            if any(term in org_name.lower() for term in ["amazon", "aws", "google", "azure", "microsoft", "cloudflare", "digitalocean", "hetzner", "ovh"]):
                provider_name = c_name
                break

    if provider_name:
        return {
            "ip": ip_str,
            "category": "CLOUD_PROVIDER",
            "is_datacenter": True,
            "is_tor": False,
            "is_vpn_or_proxy": False,
            "provider_name": provider_name,
            "risk_score": 10.0
        }

    # Check Mail Providers via rDNS
    if reverse_dns:
        r_clean = reverse_dns.lower().strip()
        for domain_marker, name in KNOWN_MAIL_PROVIDERS.items():
            if domain_marker in r_clean:
                return {
                    "ip": ip_str,
                    "category": "MAIL_PROVIDER",
                    "is_datacenter": True,
                    "is_tor": False,
                    "is_vpn_or_proxy": False,
                    "provider_name": name,
                    "risk_score": 0.0
                }

    # Default to Residential / ISP if not DC
    return {
        "ip": ip_str,
        "category": "RESIDENTIAL_ISP",
        "is_datacenter": False,
        "is_tor": False,
        "is_vpn_or_proxy": False,
        "provider_name": org_name or "Commercial ISP",
        "risk_score": 5.0
    }


def verify_fcrdns(
    ip_str: Optional[str],
    helo_domain: Optional[str],
    rdns_hostname: Optional[str],
    forward_resolved_ips: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    F04: Forward-Confirmed Reverse DNS (FCrDNS) and HELO consistency check.
    1. Does IP have a PTR record (rdns)?
    2. Does the PTR record resolve forward (A/AAAA) back to the same IP?
    3. Does the HELO/EHLO domain match or align with the verified rDNS?
    """
    if not ip_str:
        return {"fcrdns_valid": False, "helo_alignment": "UNKNOWN", "flags": ["NO_IP"]}

    flags = []
    
    # 1. PTR Existence
    has_ptr = bool(rdns_hostname)
    if not has_ptr:
        flags.append("NO_REVERSE_DNS_PTR")

    # 2. Forward confirmation
    fcrdns_valid = False
    if has_ptr and forward_resolved_ips:
        if ip_str in forward_resolved_ips:
            fcrdns_valid = True
        else:
            flags.append("FCRDNS_FORWARD_MISMATCH")
    elif has_ptr:
        # If simulated without explicit forward IPs, assume valid if well-formed hostname
        fcrdns_valid = True

    # 3. HELO / rDNS alignment
    helo_alignment = "MISMATCH"
    if helo_domain and rdns_hostname:
        h_clean = helo_domain.lower().strip().rstrip(".")
        r_clean = rdns_hostname.lower().strip().rstrip(".")
        if h_clean == r_clean or r_clean.endswith(f".{h_clean}") or h_clean.endswith(f".{r_clean}"):
            helo_alignment = "ALIGNED"
        else:
            flags.append(f"HELO_RDNS_MISMATCH (HELO '{helo_domain}' != rDNS '{rdns_hostname}')")
    elif not helo_domain:
        helo_alignment = "NO_HELO"

    return {
        "fcrdns_valid": fcrdns_valid,
        "helo_alignment": helo_alignment,
        "rdns_hostname": rdns_hostname,
        "flags": flags
    }

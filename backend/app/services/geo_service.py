"""
geo_service.py — IPGeolocation.io Enrichment & Standalone Lookup
Enriches IP addresses with country, city, ASN, ISP, timezone, coordinates, currency, and threat data.
"""

import requests
import socket
from typing import Dict, Any, Optional
from backend.app.core.config import settings

# In-process cache to avoid duplicate API calls within the same session
_geo_cache: Dict[str, Dict[str, Any]] = {}

IPGEO_BASE_URL = "https://api.ipgeolocation.io/ipgeo"

def enrich_ip_geolocation(target: str) -> Dict[str, Any]:
    """
    Lookup and enrich an IP address or hostname with geolocation and threat data using IPGeolocation.io.
    """
    if not target or not settings.IPGEOLOCATION_API_KEY:
        return _empty_geo(target)

    target_clean = target.strip().replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

    # Resolve domain to IP if a domain name was provided
    resolved_ip = target_clean
    try:
        if not _is_valid_ip(target_clean):
            resolved_ip = socket.gethostbyname(target_clean)
    except Exception:
        resolved_ip = target_clean

    # Handle same-server / loopback (127.0.0.1, ::1, localhost)
    if resolved_ip in ("127.0.0.1", "::1", "localhost", "0.0.0.0") or target_clean in ("127.0.0.1", "::1", "localhost", "0.0.0.0"):
        return {
            "ip": resolved_ip,
            "query": target_clean,
            "hostname": "localhost (Same Server)",
            "country_name": "Host Mail Server (Local Origin)",
            "country_name_official": "Local Host Origin Mail Server",
            "country_code2": "LOCAL",
            "country_code3": "LOC",
            "country_flag": "🖥️",
            "country_emoji": "🖥️",
            "city": "Same-Server Mailbox",
            "state_prov": "Internal Host System",
            "district": "Local Loopback (No External Hop)",
            "zipcode": "Localhost",
            "isp": "Local MTA / Unix Mail Daemon",
            "organization": "CyberSentry Host Environment",
            "asn": "Loopback MTA",
            "latitude": None,
            "longitude": None,
            "location_note": "Email processed and sent internally on the same mail server without external transit hops.",
            "timezone": "UTC / Local System Time",
            "continent_name": "Local Host",
            "currency": {"code": "N/A", "name": "Local", "symbol": ""},
            "threat": {"is_tor": False, "is_proxy": False, "is_anonymous": False, "threat_score": 0},
            "enriched": True,
            "source": "SAME_SERVER_LOOPBACK"
        }

    # Private / reserved IP ranges — return private range metadata.
    if _is_private_ip(resolved_ip):
        return {
            "ip": resolved_ip,
            "query": target_clean,
            "hostname": f"Internal Node ({resolved_ip})",
            "country_name": "Private Enterprise Network",
            "country_name_official": "Internal RFC1918 Enterprise Network",
            "country_code2": "INT",
            "country_code3": "INT",
            "country_flag": "🏢",
            "country_emoji": "🏢",
            "city": "Internal Relay / Subnet",
            "state_prov": "Enterprise Perimeter",
            "district": "Private Subnet",
            "zipcode": "Internal",
            "isp": "Enterprise Internal Network Infrastructure",
            "organization": "Corporate Mail Gateway",
            "asn": "Private AS Space",
            "latitude": None,
            "longitude": None,
            "location_note": "Internal non-routable IP address within enterprise network perimeter.",
            "timezone": "Internal Network Time",
            "continent_name": "Enterprise Intranet",
            "currency": {"code": "N/A", "name": "N/A", "symbol": ""},
            "threat": {"is_tor": False, "is_proxy": False, "is_anonymous": False, "threat_score": 0},
            "enriched": True,
            "source": "PRIVATE_ENTERPRISE_RANGE"
        }

    if resolved_ip in _geo_cache:
        cached = dict(_geo_cache[resolved_ip])
        cached["query"] = target_clean
        return cached

    try:
        resp = requests.get(
            IPGEO_BASE_URL,
            params={
                "apiKey": settings.IPGEOLOCATION_API_KEY,
                "ip": resolved_ip,
            },
            timeout=8
        )
        resp.raise_for_status()
        data = resp.json()

        threat_raw = data.get("threat")
        threat = threat_raw if isinstance(threat_raw, dict) else {}
        time_zone = data.get("time_zone")
        tz_name = time_zone.get("name", "") if isinstance(time_zone, dict) else ""
        currency_raw = data.get("currency")
        currency = currency_raw if isinstance(currency_raw, dict) else {"code": "USD", "name": "US Dollar", "symbol": "$"}

        result = {
            "ip": resolved_ip,
            "query": target_clean,
            "hostname": data.get("hostname", target_clean),
            "continent_code": data.get("continent_code", ""),
            "continent_name": data.get("continent_name", ""),
            "country_name": data.get("country_name", "Unknown"),
            "country_name_official": data.get("country_name_official", ""),
            "country_code2": data.get("country_code2", "XX"),
            "country_code3": data.get("country_code3", "XXX"),
            "country_flag": data.get("country_flag", ""),
            "country_emoji": data.get("country_emoji", "🌐"),
            "country_capital": data.get("country_capital", ""),
            "state_prov": data.get("state_prov", ""),
            "district": data.get("district", ""),
            "city": data.get("city", ""),
            "zipcode": data.get("zipcode", ""),
            "latitude": str(data.get("latitude", "")),
            "longitude": str(data.get("longitude", "")),
            "is_eu": data.get("is_eu", False),
            "calling_code": data.get("calling_code", ""),
            "country_tld": data.get("country_tld", ""),
            "languages": data.get("languages", ""),
            "isp": data.get("isp", ""),
            "organization": data.get("organization", ""),
            "asn": data.get("asn", ""),
            "timezone": tz_name,
            "currency": currency,
            "threat": {
                "is_tor": threat.get("is_tor", False),
                "is_proxy": threat.get("is_proxy", False),
                "is_anonymous": threat.get("is_anonymous", False),
                "threat_score": threat.get("threat_score", 0)
            },
            "enriched": True,
            "source": "IPGEOLOCATION_IO"
        }
        _geo_cache[resolved_ip] = result
        return result

    except Exception as e:
        # Secondary fallback: ip-api.com (free, high-reliability fallback)
        try:
            fb_resp = requests.get(f"http://ip-api.com/json/{resolved_ip}", timeout=5)
            if fb_resp.ok:
                fb_data = fb_resp.json()
                if fb_data.get("status") == "success":
                    result = {
                        "ip": resolved_ip,
                        "query": target_clean,
                        "hostname": target_clean,
                        "continent_code": "",
                        "continent_name": "",
                        "country_name": fb_data.get("country", "Unknown"),
                        "country_name_official": fb_data.get("country", "Unknown"),
                        "country_code2": fb_data.get("countryCode", "XX"),
                        "country_code3": "",
                        "country_flag": f"https://ipgeolocation.io/static/flags/{fb_data.get('countryCode', 'xx').lower()}_64.png",
                        "country_emoji": "🌐",
                        "country_capital": "",
                        "state_prov": fb_data.get("regionName", ""),
                        "district": fb_data.get("region", ""),
                        "city": fb_data.get("city", ""),
                        "zipcode": fb_data.get("zip", ""),
                        "latitude": str(fb_data.get("lat", "")),
                        "longitude": str(fb_data.get("lon", "")),
                        "is_eu": False,
                        "calling_code": "",
                        "country_tld": "",
                        "languages": "",
                        "isp": fb_data.get("isp", ""),
                        "organization": fb_data.get("org", ""),
                        "asn": fb_data.get("as", ""),
                        "timezone": fb_data.get("timezone", "UTC"),
                        "currency": {"code": "USD", "name": "US Dollar", "symbol": "$"},
                        "threat": {"is_tor": False, "is_proxy": False, "is_anonymous": False, "threat_score": 0},
                        "enriched": True,
                        "source": "IP_API_FALLBACK"
                    }
                    _geo_cache[resolved_ip] = result
                    return result
        except Exception:
            pass

        fallback = _empty_geo(target_clean)
        fallback["error"] = str(e)
        return fallback


def _is_valid_ip(target: str) -> bool:
    """Check if string is a valid IPv4 or IPv6 address."""
    import ipaddress
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _is_private_ip(ip: str) -> bool:
    """Check if the IP address belongs to private/reserved ranges."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast
    except ValueError:
        return False


def _empty_geo(ip: str) -> Dict[str, Any]:
    """Return a stub geo dict when enrichment is unavailable."""
    return {
        "ip": ip,
        "query": ip,
        "country_name": "Unknown",
        "country_code2": "XX",
        "country_flag": "🌐",
        "country_emoji": "🌐",
        "city": "",
        "state_prov": "",
        "isp": "",
        "organization": "",
        "asn": "",
        "latitude": None,
        "longitude": None,
        "timezone": "",
        "threat": {"is_tor": False, "is_proxy": False, "is_anonymous": False, "threat_score": 0},
        "enriched": False,
        "source": "UNAVAILABLE"
    }

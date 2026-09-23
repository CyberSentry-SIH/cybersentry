from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, Query, Request
from backend.app.services.geo_service import enrich_ip_geolocation
from backend.app.api.deps import get_current_user
from backend.app.models import User

router = APIRouter(prefix="/geo", tags=["IP Geolocation Intelligence"])

@router.get("/lookup")
def lookup_ip_geolocation(
    ip: str = Query(..., description="IPv4, IPv6 address or domain hostname to geolocate"),
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Perform a direct, real-time IP Geolocation lookup using the IPGeolocation.io API.
    Returns country, flag, city, state, coordinates, ISP, ASN, timezone, currency, and threat intel.
    """
    return enrich_ip_geolocation(ip)

@router.get("/sample-ips")
def get_sample_threat_ips(
    current_user: User = Depends(get_current_user)
):
    """
    Return curated sample IPs for quick testing and forensic demonstration.
    """
    return [
        {"ip": "185.220.101.5", "label": "Tor Exit Relay / Bulletproof Hosting (Germany)", "type": "SUSPICIOUS_RELAY"},
        {"ip": "8.8.8.8", "label": "Google DNS Anycast (United States)", "type": "PUBLIC_RESOLVER"},
        {"ip": "1.1.1.1", "label": "Cloudflare DNS (Australia/Global)", "type": "PUBLIC_RESOLVER"},
        {"ip": "194.26.29.112", "label": "Suspicious Phishing Origin (Netherlands)", "type": "PHISHING_HOST"},
        {"ip": "117.99.94.128", "label": "Broadband Dynamic Node (India)", "type": "CONSUMER_ISP"},
    ]

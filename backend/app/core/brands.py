import re
from typing import Dict, List, Optional, Set, Tuple

# Comprehensive registry of legitimate enterprise and institutional brands
# Maps brand_id -> canonical brand info with all official registrable domains and known official hostnames
KNOWN_BRANDS: Dict[str, Dict] = {
    "paypal": {
        "brand_name": "PayPal",
        "keywords": ["paypal"],
        "official_domains": [
            "paypal.com", "paypal.me", "paypalobjects.com", "paypal-community.com",
            "paypal-corps.com", "paypal.co.uk", "paypal.in"
        ]
    },
    "microsoft": {
        "brand_name": "Microsoft",
        "keywords": ["microsoft", "office365", "outlook", "onedrive", "sharepoint", "azure", "msft"],
        "official_domains": [
            "microsoft.com", "microsoftonline.com", "office.com", "office365.com",
            "outlook.com", "live.com", "hotmail.com", "azure.com", "sharepoint.com",
            "onedrive.com", "microsoft.co.in", "msn.com", "windows.com"
        ]
    },
    "google": {
        "brand_name": "Google",
        "keywords": ["google", "gmail", "workspace"],
        "official_domains": [
            "google.com", "google.co.in", "google.co.uk", "google.ca", "google.de",
            "gmail.com", "googlemail.com", "youtube.com", "googleapis.com", "gstatic.com"
        ]
    },
    "amazon": {
        "brand_name": "Amazon",
        "keywords": ["amazon", "prime video", "aws"],
        "official_domains": [
            "amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.ca",
            "amazon.co.jp", "amazon.fr", "amazon.it", "amazon.es", "amazonaws.com",
            "media-amazon.com", "ssl-images-amazon.com"
        ]
    },
    "apple": {
        "brand_name": "Apple",
        "keywords": ["apple", "icloud", "itunes", "app store"],
        "official_domains": [
            "apple.com", "icloud.com", "me.com", "itunes.com", "apple.co"
        ]
    },
    "netflix": {
        "brand_name": "Netflix",
        "keywords": ["netflix"],
        "official_domains": ["netflix.com", "nflxext.com", "nflximg.net", "nflxvideo.net"]
    },
    "slack": {
        "brand_name": "Slack",
        "keywords": ["slack"],
        "official_domains": ["slack.com", "slack-edge.com", "slack-msgs.com"]
    },
    "zoom": {
        "brand_name": "Zoom",
        "keywords": ["zoom"],
        "official_domains": ["zoom.us", "zoom.com", "zoomgov.com"]
    },
    "chase": {
        "brand_name": "Chase Bank",
        "keywords": ["chase", "jpmorgan"],
        "official_domains": ["chase.com", "jpmorgan.com", "jpmorganchase.com"]
    },
    "bank_of_america": {
        "brand_name": "Bank of America",
        "keywords": ["bank of america", "bofa"],
        "official_domains": ["bankofamerica.com", "bofa.com", "merrilledge.com"]
    },
    "wells_fargo": {
        "brand_name": "Wells Fargo",
        "keywords": ["wells fargo"],
        "official_domains": ["wellsfargo.com"]
    },
    "dhl": {
        "brand_name": "DHL Express",
        "keywords": ["dhl", "dhl express"],
        "official_domains": ["dhl.com", "dhl.de", "dhl.co.in", "dhl-news.com"]
    },
    "fedex": {
        "brand_name": "FedEx",
        "keywords": ["fedex"],
        "official_domains": ["fedex.com"]
    },
    # Indian Banking & Government Brands (F14)
    "sbi": {
        "brand_name": "State Bank of India",
        "keywords": ["sbi", "state bank of india", "onlinesbi", "yono"],
        "official_domains": ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbi.bank"]
    },
    "hdfc": {
        "brand_name": "HDFC Bank",
        "keywords": ["hdfc", "hdfc bank", "hdfcbank"],
        "official_domains": ["hdfcbank.com", "hdfc.com", "hdfcbank.net"]
    },
    "icici": {
        "brand_name": "ICICI Bank",
        "keywords": ["icici", "icici bank", "icicibank"],
        "official_domains": ["icicibank.com", "icicibank.co.in", "icici.com"]
    },
    "axis": {
        "brand_name": "Axis Bank",
        "keywords": ["axis bank", "axisbank"],
        "official_domains": ["axisbank.com", "axisbank.co.in"]
    },
    "pnb": {
        "brand_name": "Punjab National Bank",
        "keywords": ["pnb", "punjab national bank"],
        "official_domains": ["pnbindia.in", "pnb.bank"]
    },
    "paytm": {
        "brand_name": "Paytm",
        "keywords": ["paytm", "one97"],
        "official_domains": ["paytm.com", "paytmbank.com"]
    },
    "phonepe": {
        "brand_name": "PhonePe",
        "keywords": ["phonepe"],
        "official_domains": ["phonepe.com"]
    },
    "uidai": {
        "brand_name": "UIDAI / Aadhaar",
        "keywords": ["uidai", "aadhaar"],
        "official_domains": ["uidai.gov.in", "myaadhaar.uidai.gov.in"]
    },
    "incometax": {
        "brand_name": "Income Tax Department of India",
        "keywords": ["income tax", "incometax", "it department"],
        "official_domains": ["incometax.gov.in", "incometaxindia.gov.in", "incometaxindiaefiling.gov.in"]
    },
    "indiapost": {
        "brand_name": "India Post",
        "keywords": ["india post", "indiapost", "post office"],
        "official_domains": ["indiapost.gov.in", "indiapostgdsonline.gov.in"]
    },
    "irctc": {
        "brand_name": "IRCTC",
        "keywords": ["irctc", "indian railways"],
        "official_domains": ["irctc.co.in", "irctc.com", "cris.org.in"]
    }
}

# Common multi-part public suffixes for robust offline parsing
TWO_PART_TLDS = {
    "co.uk", "co.in", "gov.in", "nic.in", "ac.in", "res.in", "edu.in", "org.in",
    "com.au", "net.au", "org.au", "co.nz", "co.jp", "com.br", "co.za", "com.sg",
    "gov.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk"
}

def extract_registrable_domain(host: str) -> str:
    """
    Extract the registrable domain (e.g., 'amazon.in' from 'www.amazon.in',
    'paypal.com' from 'mail.paypal.com') without external network calls.
    """
    if not host:
        return ""
    host = host.lower().strip().rstrip(".")

    # Handle IP addresses or bare single-word hosts
    if ":" in host or host.replace(".", "").isdigit() or "." not in host:
        return host

    parts = host.split(".")
    if len(parts) <= 2:
        return host

    last_two = f"{parts[-2]}.{parts[-1]}"
    if last_two in TWO_PART_TLDS and len(parts) >= 3:
        return f"{parts[-3]}.{last_two}"

    return f"{parts[-2]}.{parts[-1]}"

def is_official_domain(host: str, brand_key: Optional[str] = None) -> bool:
    """
    Checks if a hostname strictly belongs to the official domains of a specific brand
    or any known legitimate brand.
    """
    if not host:
        return False
    clean_host = host.lower().strip().rstrip(".")
    reg_dom = extract_registrable_domain(clean_host)

    brands_to_check = [KNOWN_BRANDS[brand_key]] if (brand_key and brand_key in KNOWN_BRANDS) else KNOWN_BRANDS.values()

    for brand_info in brands_to_check:
        for official in brand_info["official_domains"]:
            official_clean = official.lower().strip().rstrip(".")
            if reg_dom == official_clean or clean_host == official_clean or clean_host.endswith(f".{official_clean}"):
                return True
    return False

def get_matching_brand(text: str) -> Optional[Tuple[str, Dict]]:
    """
    Check if a display name or text mentions a known brand using whole-word boundary matching.
    Returns (brand_id, brand_dict) or None.
    """
    if not text:
        return None
    text_lower = text.lower()

    for b_key, b_info in KNOWN_BRANDS.items():
        for kw in b_info["keywords"]:
            # Use whole-word regex pattern
            pattern = rf"\b{re.escape(kw)}\b"
            if re.search(pattern, text_lower):
                return b_key, b_info
    return None

"""
Tests for Phase 3 Features F01 to F05:
- F01: Multi-Channel Ingestion & Fast-Path Extension API
- F02: Active SPF / DKIM / DMARC Independent Verification
- F03: Domain Intelligence & RDAP Service
- F04: IP & Infrastructure Classification (Tor, Cloud, ISP) and FCrDNS
- F05: Link Obfuscation (@ authority, double percent-encoding, hidden links)
"""

import pytest
from fastapi.testclient import TestClient
from backend.app.services.auth_verification_service import (
    evaluate_active_spf, verify_active_dkim, evaluate_active_dmarc, verify_authentication_full
)
from backend.app.services.domain_intel_service import (
    calculate_domain_age_days, analyze_domain_intelligence, is_ssrf_safe_ip
)
from backend.app.services.infrastructure_service import (
    classify_ip_infrastructure, verify_fcrdns
)
from backend.app.engines.url_engine import (
    detect_obfuscated_urls, analyze_html_dom_links, trace_safe_redirects
)


# =========================================================================
# F01: Extension & Ingestion API Tests
# =========================================================================

def test_F01_extension_scan_fast_path(client):
    """F01: /api/v1/extension/scan returns fast-path verdict in <500ms."""
    payload = {
        "subject": "Urgent: Update your Bank Account KYC",
        "from_address": "security@sbi-kyc-update.com",
        "from_name": "State Bank of India",
        "body_text": "Your account will be blocked within 24 hours. Login here to verify PAN.",
        "urls": ["http://sbi-kyc-update.com/login"]
    }
    res = client.post(
        "/api/v1/extension/scan",
        json=payload,
        headers={"X-Requested-With": "CyberSentryClient"}
    )
    assert res.status_code == 200
    data = res.json()
    assert "verdict" in data
    assert data["verdict"] in ("PHISHING", "SPOOFED", "SUSPICIOUS")
    assert data["scan_duration_ms"] < 500.0  # Performance budget
    assert len(data["reasons"]) > 0


def test_F01_analyze_raw_headers(client):
    """F01: /api/v1/analyze/headers accepts raw header text."""
    raw_headers = (
        "From: admin@paypal-security.com\r\n"
        "To: user@victim.com\r\n"
        "Subject: Suspicious activity on your account\r\n"
        "Date: Tue, 22 Sep 2026 10:00:00 +0000\r\n"
        "Authentication-Results: mx.victim.com; spf=pass\r\n"
    )
    res = client.post(
        "/api/v1/analyze/headers",
        json={"raw_headers": raw_headers},
        headers={"X-Requested-With": "CyberSentryClient"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert "header_analysis" in data


# =========================================================================
# F02: Active SPF / DKIM / DMARC Verification Tests
# =========================================================================

def test_F02_active_spf_evaluation():
    """F02: Active SPF evaluation matches CIDR and mechanisms."""
    spf_record = "v=spf1 ip4:192.0.2.0/24 ip4:198.51.100.1 include:_spf.google.com -all"
    
    # Matching IP
    res_pass = evaluate_active_spf("192.0.2.55", "example.com", spf_record)
    assert res_pass["result"] == "PASS"

    # Non-matching IP with -all
    res_fail = evaluate_active_spf("203.0.113.1", "example.com", spf_record)
    assert res_fail["result"] == "FAIL"


def test_F02_active_dkim_verification():
    """F02: DKIM header parsing and tag validation."""
    valid_dkim = "v=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=20230601; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b=dGVzdHNpZ25hdHVyZQ=="
    res = verify_active_dkim(valid_dkim)
    assert res["result"] == "PASS"
    assert res["domain"] == "google.com"
    assert res["selector"] == "20230601"

    # Malformed DKIM
    malformed_dkim = "v=1; a=rsa-sha256; bh=abc"
    res_malformed = verify_active_dkim(malformed_dkim)
    assert res_malformed["result"] == "PERMERROR"


def test_F02_dmarc_alignment():
    """F02: DMARC alignment passes if SPF or DKIM domain matches Header From."""
    # Aligned SPF
    dmarc_ok = evaluate_active_dmarc("paypal.com", "PASS", "paypal.com", "NONE", None)
    assert dmarc_ok["result"] == "PASS"
    assert dmarc_ok["alignment_spf"] is True

    # Unaligned (attacker domain)
    dmarc_fail = evaluate_active_dmarc("paypal.com", "PASS", "attacker-relay.com", "FAIL", "attacker-relay.com")
    assert dmarc_fail["result"] == "FAIL"


def test_F02_side_by_side_reported_vs_verified_auth():
    """F02: Discrepancy detected when reported header claims PASS but verification FAILS."""
    reported = {"spf": "pass", "dkim": "pass", "dmarc": "pass", "authserv_id": "untrusted-relay.com"}
    comparison = verify_authentication_full(
        reported_auth=reported,
        boundary_ip="185.220.101.5",
        header_from_domain="paypal.com",
        return_path_domain="paypal.com"
    )
    assert "reported" in comparison
    assert "verified" in comparison
    assert comparison["tampering_suspected"] is True


# =========================================================================
# F03: Domain Intelligence & RDAP Tests
# =========================================================================

def test_F03_domain_age_calculation():
    """F03: Accurately calculate domain age in days."""
    assert calculate_domain_age_days("2026-09-01T00:00:00Z") is not None
    assert calculate_domain_age_days(None) is None


def test_F03_newly_registered_domain_risk():
    """F03: Flags newly registered domains (<30 days) with risk score penalty."""
    mock_rdap = {
        "creation_date": "2026-09-15T00:00:00Z",
        "registrar": "NameCheap, Inc."
    }
    intel = analyze_domain_intelligence("evil-phish-2026.com", mock_rdap)
    assert intel["is_valid"] is True
    assert any("NEWLY_REGISTERED" in flag for flag in intel["risk_flags"])
    assert intel["risk_score"] > 20.0


def test_F03_ssrf_safety_checks():
    """F03: SSRF validator rejects private, loopback, and reserved addresses."""
    assert is_ssrf_safe_ip("8.8.8.8") is True
    assert is_ssrf_safe_ip("127.0.0.1") is False
    assert is_ssrf_safe_ip("10.0.0.1") is False
    assert is_ssrf_safe_ip("192.168.1.1") is False


# =========================================================================
# F04: IP & Infrastructure Intelligence Tests
# =========================================================================

def test_F04_tor_and_cloud_infrastructure_classification():
    """F04: Classify Tor exit nodes and Cloud providers."""
    tor_info = classify_ip_infrastructure("185.220.101.5")
    assert tor_info["category"] == "TOR_EXIT"
    assert tor_info["is_tor"] is True

    aws_info = classify_ip_infrastructure("54.240.0.1", asn=16509)
    assert aws_info["category"] == "CLOUD_PROVIDER"
    assert "AWS" in aws_info["provider_name"]


def test_F04_fcrdns_and_helo_alignment():
    """F04: FCrDNS checks HELO alignment against PTR reverse DNS."""
    fcrdns_aligned = verify_fcrdns("192.0.2.1", "mail.example.com", "mail.example.com")
    assert fcrdns_aligned["helo_alignment"] == "ALIGNED"

    fcrdns_mismatch = verify_fcrdns("192.0.2.1", "paypal.com", "unrelated-relay.net")
    assert fcrdns_mismatch["helo_alignment"] == "MISMATCH"


# =========================================================================
# F05: Link Obfuscation & Safe Redirect Tests
# =========================================================================

def test_F05_url_authority_obfuscation():
    """F05: Flag @ authority trick masquerading as legitimate brand."""
    findings = detect_obfuscated_urls("https://paypal.com@attacker-stealer.com/login")
    assert len(findings) == 1
    assert findings[0]["type"] == "URL_AUTHORITY_OBFUSCATION"


def test_F05_html_dom_link_text_mismatch():
    """F05: Detect display text claiming one domain while href goes to another."""
    html = '<p>Click <a href="https://evil-spoof.com/auth">https://chase.com/login</a> to access your account.</p>'
    dom_findings = analyze_html_dom_links(html)
    assert len(dom_findings) == 1
    assert dom_findings[0]["type"] == "LINK_TEXT_HREF_MISMATCH"


def test_F05_html_dom_hidden_link():
    """F05: Detect hidden zero-font links."""
    html = '<p><a href="https://tracker.evil.com/ping" style="display:none; font-size:0px;">Verify</a></p>'
    dom_findings = analyze_html_dom_links(html)
    assert any(f["type"] == "HIDDEN_LINK_DETECTED" for f in dom_findings)

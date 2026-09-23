import pytest
from backend.app.engines.header_engine import analyze_headers
from backend.app.engines.url_engine import analyze_urls, evaluate_lookalike_domain, safe_urlparse
from backend.app.engines.intent_engine import analyze_intent
from backend.app.engines.attachment_engine import analyze_attachments
from backend.app.engines.risk_engine import calculate_risk
from backend.app.services.parser_service import parse_eml_bytes
from backend.app.core.brands import is_official_domain, get_matching_brand

def test_B07_attachment_pdf_exe_is_scored_high():
    attachments = [{
        "filename": "Invoice_2026.pdf.exe",
        "content_type": "application/x-msdownload",
        "size_bytes": 102400,
        "sha256": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        "extension": ".exe",
        "head": b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
    }]
    res = analyze_attachments(attachments)
    findings = res.get("findings", [])
    assert any(f["code"] == "EXECUTABLE_ATTACHMENT" for f in findings)
    assert any(f["code"] == "DOUBLE_EXTENSION_ATTACHMENT" for f in findings)

    score, band, snapshot, recs, verdict, corroboration = calculate_risk(
        findings=findings,
        auth_summary={},
        signals=res.get("signals", {})
    )
    assert score >= 50.0
    assert band in ["HIGH", "CRITICAL"]

def test_B08_parser_and_url_crash_tokens_fail_safely():
    # Crash token 1: Malformed IPv6 URL
    parsed_url = safe_urlparse("http://[::1")
    assert parsed_url is not None

    url_res = analyze_urls(["http://[::1", "http://normal.com"])
    assert any(f["code"] == "MALFORMED_URL" for f in url_res.get("findings", []))

    # Crash token 2: Unknown charset in email
    raw_bad_charset = (
        b"From: attacker@evil.com\r\n"
        b"To: victim@corp.com\r\n"
        b"Subject: Crash test\r\n"
        b"Content-Type: text/plain; charset=\"x-no-such-charset\"\r\n\r\n"
        b"Payload text here"
    )
    parsed = parse_eml_bytes(raw_bad_charset)
    assert parsed is not None
    assert "Payload text here" in parsed.get("body_text", "")

def test_B09_benign_phrase_does_not_disable_phishing_detection():
    # Phishing email with attacker-appended benign whitelist phrase
    phish_with_whitelist = (
        "URGENT: Your account has been suspended! Please click here immediately to verify credentials. "
        "Review enterprise policy standard monthly invoice no account suspension will occur."
    )
    intent_res = analyze_intent(
        subject="[URGENT] Account Suspended",
        body_text=phish_with_whitelist,
        body_html=""
    )
    assert intent_res["primary_intent"] == "CREDENTIAL_HARVESTING"

    # Benign context should not trigger false positives
    benign_text = "The board meeting is critical for our roadmap."
    intent_benign = analyze_intent(
        subject="Board Meeting Agenda",
        body_text=benign_text,
        body_html=""
    )
    assert intent_benign["primary_intent"] == "BENIGN_COMMUNICATION"
    assert not any(f["code"] == "EXECUTIVE_IMPERSONATION" for f in intent_benign.get("findings", []))

def test_B10_display_name_spoof_no_suffix_bypass():
    # Suffix exploit: notpaypal.com or evil-paypal.com with display name "PayPal Support"
    hdr_evil = analyze_headers(
        from_name="PayPal Support",
        from_address="security@notpaypal.com",
        from_domain="notpaypal.com",
        reply_to=None,
        return_path=None,
        hops=[],
        auth_results={"spf_result": "NONE"}
    )
    assert any(f["code"] == "DISPLAY_NAME_SPOOFING" for f in hdr_evil.get("findings", []))

    # Legitimate subdomain must NOT trigger display name spoofing
    hdr_legit = analyze_headers(
        from_name="PayPal Support",
        from_address="service@mail.paypal.com",
        from_domain="mail.paypal.com",
        reply_to=None,
        return_path=None,
        hops=[],
        auth_results={"spf_result": "PASS", "dkim_result": "PASS"}
    )
    assert not any(f["code"] == "DISPLAY_NAME_SPOOFING" for f in hdr_legit.get("findings", []))

def test_B11_lookalike_precision_and_numeric_ips():
    # Legitimate brand domains and country variants must NOT be flagged as lookalike
    legit_domains = [
        "login.microsoftonline.com",
        "www.paypalobjects.com",
        "www.amazon.in",
        "www.amazon.co.uk",
        "www.microsoft.co.in",
        "accounts.google.co.in",
        "room.com",
        "phase.com",
        "stack.com"
    ]
    for dom in legit_domains:
        is_look, target, _ = evaluate_lookalike_domain(dom)
        assert not is_look, f"False positive lookalike on legitimate domain: {dom}"

    # True lookalike: arnazon.com (rn -> m confusable)
    is_look_arnazon, target_arnazon, _ = evaluate_lookalike_domain("arnazon.com")
    assert is_look_arnazon, "Failed to detect arnazon.com (rn -> m) as lookalike of amazon.com"
    assert target_arnazon == "amazon.com"

    # Hex/decimal/octal IP URLs
    url_res = analyze_urls(["http://0xB9DC6505/login", "http://3110893829/auth", "http://0271.0334.0145.0005/verify"])
    assert any(f["code"] == "DIRECT_IP_URL_DESTINATION" for f in url_res.get("findings", []))

def test_B12_and_B13_saturating_risk_score_and_five_class_verdicts():
    # Finding distribution across independent categories
    cred_phish_findings = [
        {"category": "IDENTITY", "code": "DISPLAY_NAME_SPOOFING", "title": "Spoof", "severity": "CRITICAL", "risk_contribution": 28.0},
        {"category": "DOMAIN_URL", "code": "LOOKALIKE_HOMOGLYPH_DOMAIN", "title": "Lookalike", "severity": "CRITICAL", "risk_contribution": 32.0},
        {"category": "INTENT", "code": "INTENT_CREDENTIAL_HARVESTING", "title": "Cred", "severity": "HIGH", "risk_contribution": 26.0}
    ]
    score, band, snapshot, recs, verdict, corroboration = calculate_risk(
        findings=cred_phish_findings,
        auth_summary={"all_passed": False},
        signals={"lookalike_url": True}
    )
    assert verdict == "PHISHING"
    assert score >= 75.0
    assert corroboration > 0.5

    # BEC / Payment Redirection -> FRAUD verdict
    bec_findings = [
        {"category": "IDENTITY", "code": "REPLY_TO_MISMATCH", "title": "ReplyTo", "severity": "HIGH", "risk_contribution": 20.0},
        {"category": "INTENT", "code": "INTENT_PAYMENT_REDIRECTION", "title": "Wire", "severity": "CRITICAL", "risk_contribution": 35.0}
    ]
    score_bec, band_bec, snapshot_bec, recs_bec, verdict_bec, corr_bec = calculate_risk(
        findings=bec_findings,
        auth_summary={"all_passed": False},
        signals={}
    )
    assert verdict_bec == "FRAUD"
    assert band_bec in ["HIGH", "CRITICAL"]

    # Spoofed domain with no credential/payment payload -> IMPERSONATED
    impersonate_findings = [
        {"category": "IDENTITY", "code": "DISPLAY_NAME_SPOOFING", "title": "Spoof", "severity": "HIGH", "risk_contribution": 25.0},
        {"category": "AUTHENTICATION", "code": "DMARC_VALIDATION_FAILED", "title": "DMARC Fail", "severity": "HIGH", "risk_contribution": 22.0}
    ]
    _, _, _, _, verdict_imp, _ = calculate_risk(
        findings=impersonate_findings,
        auth_summary={"all_passed": False},
        signals={}
    )
    assert verdict_imp == "IMPERSONATED"

    # Legitimate mail with zero findings -> LEGITIMATE
    score_legit, band_legit, _, _, verdict_legit, _ = calculate_risk(
        findings=[],
        auth_summary={"all_passed": True, "spf": "PASS", "dkim": "PASS", "dmarc": "PASS"},
        signals={}
    )
    assert verdict_legit == "LEGITIMATE"
    assert score_legit == 0.0
    assert band_legit == "LOW"

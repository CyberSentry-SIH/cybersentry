import pytest
from backend.app.engines.header_engine import analyze_headers
from backend.app.engines.url_engine import analyze_urls
from backend.app.engines.intent_engine import analyze_intent
from backend.app.engines.phishdna_engine import generate_phishdna, calculate_phishdna_similarity
from backend.app.engines.risk_engine import calculate_risk

def test_header_display_name_spoofing():
    res = analyze_headers(
        from_name="PayPal Support",
        from_address="evil@attacker-domain.xyz",
        from_domain="attacker-domain.xyz",
        reply_to="evil@attacker-domain.xyz",
        return_path="bounce@attacker-domain.xyz",
        hops=[],
        auth_results={"spf_result": "FAIL", "dkim_result": "NONE", "dmarc_result": "FAIL"}
    )
    assert any(f["code"] == "DISPLAY_NAME_SPOOFING" for f in res["findings"])
    assert any(f["code"] == "SPF_VALIDATION_FAILED" for f in res["findings"])

def test_url_lookalike_and_ip():
    res = analyze_urls(["https://paypa1-security-update.com/verify", "http://194.26.29.112/admin"])
    assert any(f["code"] == "LOOKALIKE_HOMOGLYPH_DOMAIN" for f in res["findings"])
    assert any(f["code"] == "DIRECT_IP_URL_DESTINATION" for f in res["findings"])

def test_intent_credential_harvesting():
    res = analyze_intent(
        subject="[URGENT] Account Suspended",
        body_text="Please confirm credentials immediately or account will be suspended within 24 hours.",
        body_html=""
    )
    assert res["primary_intent"] == "CREDENTIAL_HARVESTING"
    assert res["urgency_detected"] is True

def test_phishdna_and_similarity():
    dna1 = generate_phishdna(
        sender_domain="paypa1-security-update.com",
        from_name="PayPal Security",
        from_address="service@paypa1-security-update.com",
        subject="Action Required: Verify Account",
        body_text="Urgent verification needed.",
        body_html="<html><body><a href='https://paypa1-security-update.com'>click</a></body></html>",
        urls=["https://paypa1-security-update.com/auth"],
        hops=[{"ip_address": "185.220.101.5", "trust_level": "OBSERVED"}],
        auth_results={"spf_result": "FAIL"},
        attachments=[],
        primary_intent="CREDENTIAL_HARVESTING"
    )

    dna2 = generate_phishdna(
        sender_domain="paypa1-security-update.com",
        from_name="PayPal Protection",
        from_address="alerts@paypa1-security-update.com",
        subject="Suspension Warning: Confirm Identity",
        body_text="Urgent verification required.",
        body_html="<html><body><a href='https://paypa1-security-update.com'>click</a></body></html>",
        urls=["https://paypa1-security-update.com/verify"],
        hops=[{"ip_address": "185.220.101.5", "trust_level": "OBSERVED"}],
        auth_results={"spf_result": "FAIL"},
        attachments=[],
        primary_intent="CREDENTIAL_HARVESTING"
    )

    similarity = calculate_phishdna_similarity(dna1, dna2)
    assert similarity >= 75.0  # Shared intent, domain, and origin IP!

def test_risk_scoring_bands():
    findings = [
        {"category": "IDENTITY", "code": "DISPLAY_NAME_SPOOFING", "title": "Spoof", "severity": "CRITICAL", "risk_contribution": 28.0},
        {"category": "DOMAIN", "code": "LOOKALIKE_HOMOGLYPH_DOMAIN", "title": "Lookalike", "severity": "CRITICAL", "risk_contribution": 32.0},
        {"category": "INTENT", "code": "INTENT_CREDENTIAL_HARVESTING", "title": "Cred", "severity": "HIGH", "risk_contribution": 26.0}
    ]
    score, band, snapshot, recs, verdict, corr = calculate_risk(findings, {"all_passed": False}, {"lookalike_url": True})
    assert score >= 75.0
    assert band == "CRITICAL"
    assert verdict == "PHISHING"
    assert len(recs) > 0

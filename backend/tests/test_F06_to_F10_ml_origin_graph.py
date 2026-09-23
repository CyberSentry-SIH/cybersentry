"""
Tests for Phase 3 Features F06 to F10:
- F06: ML Phishing Classifier & Feature Extraction
- F07: Origin Traceability & Attribution-Support Assessment
- F08: Forensic Graph & Threat Intel IOC Matching (STIX/CSV)
- F09: Real-Time Alerting Engine & Webhook HMAC Signatures
- F10: Trace Map & Hop Telemetry
"""

import pytest
from backend.app.ml.classifier import PhishingClassifier, PhishingFeatureExtractor
from backend.app.engines.origin_engine import assess_email_origin
from backend.app.services.intel_service import lookup_indicator, import_indicators_from_csv, import_indicators_from_stix
from backend.app.services.alert_service import evaluate_and_dispatch_alert, generate_webhook_signature, get_recent_alerts


# =========================================================================
# F06: ML Classifier Tests
# =========================================================================

def test_F06_feature_extraction():
    """F06: Feature extractor extracts lexical & structural metrics."""
    extractor = PhishingFeatureExtractor()
    feats = extractor.extract_features(
        subject="URGENT: Verify your account immediately",
        body_text="Your password has expired. Click here to reset your login credentials.",
        signals={"display_name_spoofed": True, "lookalike_domain_detected": True},
        auth_summary={"spf": "FAIL", "dmarc": "FAIL"}
    )
    assert feats["count_urgency"] >= 2.0
    assert feats["count_credential"] >= 2.0
    assert feats["spf_fail"] == 1.0
    assert feats["display_name_spoof"] == 1.0


def test_F06_classifier_phishing_vs_benign():
    """F06: Classifier assigns high probability to phish and low to benign."""
    classifier = PhishingClassifier()

    phish_eval = classifier.evaluate_email(
        subject="URGENT: Action Required on your account",
        body_text="Verify password and reset login credentials immediately within 24 hours.",
        signals={"display_name_spoofed": True, "lookalike_domain_detected": True},
        auth_summary={"spf": "FAIL", "dmarc": "FAIL"}
    )
    assert phish_eval["probability"] > 0.70
    assert phish_eval["classification"] in ("HIGH_CONFIDENCE_PHISH", "SUSPICIOUS")

    benign_eval = classifier.evaluate_email(
        subject="Meeting agenda for next Tuesday",
        body_text="Hi team, attached is the revised agenda for our quarterly sync.",
        signals={},
        auth_summary={"spf": "PASS", "dmarc": "PASS"}
    )
    assert benign_eval["probability"] < 0.35
    assert benign_eval["classification"] == "BENIGN"


# =========================================================================
# F07: Origin Traceability & Attribution Assessment Tests
# =========================================================================

def test_F07_origin_tor_exit_verdict():
    """F07: Detect Tor exit node and produce ANONYMIZED_INFRA verdict."""
    assessment = assess_email_origin(
        boundary_ip="185.220.101.5",
        hops=[],
        auth_summary={"spf": "FAIL", "dkim": "FAIL"},
        signals={},
        infra_classification={"is_tor": True, "category": "TOR_EXIT"},
        from_domain="target-bank.com"
    )
    assert assessment["attribution_verdict"] == "ANONYMIZED_INFRA"
    assert assessment["confidence_score"] >= 80.0
    assert "legal attribution" in assessment["attribution_disclaimer"].lower()


def test_F07_origin_compromised_account_verdict():
    """F07: Valid SPF/DKIM on authentic domain with malware -> COMPROMISED_ACCOUNT."""
    assessment = assess_email_origin(
        boundary_ip="54.240.0.1",
        hops=[],
        auth_summary={"spf": "PASS", "dkim": "PASS", "dmarc": "PASS"},
        signals={"credential_harvesting": True, "dangerous_attachment_detected": True},
        from_domain="partner-company.com"
    )
    assert assessment["attribution_verdict"] == "COMPROMISED_ACCOUNT"


# =========================================================================
# F08: Threat Intel & STIX/CSV Importer Tests
# =========================================================================

def test_F08_csv_threat_intel_import(db_session):
    """F08: Import IOC indicators from CSV."""
    csv_data = "type,value,verdict,confidence,notes\nDOMAIN,stealer-c2-domain.com,MALICIOUS,0.95,C2 Command and Control\nIPV4,198.51.100.99,MALICIOUS,0.90,Known brute-force bot\n"
    res = import_indicators_from_csv(db_session, csv_data, source_label="CSV_TEST")
    assert res["imported"] == 2
    assert len(res["errors"]) == 0

    lookup = lookup_indicator(db_session, "DOMAIN", "stealer-c2-domain.com")
    assert lookup["status"] == "MALICIOUS"
    assert lookup["source"] == "CSV_TEST"


def test_F08_stix_bundle_threat_intel_import(db_session):
    """F08: Import STIX 2.1 JSON bundle indicators."""
    stix_json = """{
        "type": "bundle",
        "id": "bundle--123",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--abc",
                "name": "Cobalt Strike C2",
                "pattern": "[domain-name:value = 'apt29-relay-node.com']",
                "description": "APT29 infrastructure"
            }
        ]
    }"""
    res = import_indicators_from_stix(db_session, stix_json)
    assert res["imported"] == 1

    lookup = lookup_indicator(db_session, "DOMAIN", "apt29-relay-node.com")
    assert lookup["status"] == "MALICIOUS"


# =========================================================================
# F09: Alerting Engine & Webhook HMAC Tests
# =========================================================================

def test_F09_webhook_hmac_signature():
    """F09: Generates RFC-compliant HMAC-SHA256 signatures."""
    payload = b'{"event":"THREAT_DETECTED","score":95.0}'
    sig = generate_webhook_signature(payload, "secret-test-key")
    assert sig.startswith("sha256=")
    assert len(sig) == 7 + 64  # sha256= + 64 hex chars


def test_F09_alert_dispatch_and_cooldown():
    """F09: Dispatches high-severity alert and respects cooldown."""
    alert = evaluate_and_dispatch_alert(
        email_id="eml-101",
        subject="Wire transfer request",
        from_address="ceo-fake@company-corp.com",
        risk_score=85.0,
        verdict="PHISHING",
        findings=[{"type": "DISPLAY_NAME_SPOOF", "severity": "CRITICAL"}],
        webhook_url="https://hooks.soc.com/alerts",
        webhook_secret="sec123"
    )
    assert alert is not None
    assert alert["verdict"] == "PHISHING"
    assert alert["webhook_dispatched"] is True

    # Immediate second call is suppressed by cooldown
    alert2 = evaluate_and_dispatch_alert(
        email_id="eml-102",
        subject="Wire transfer request 2",
        from_address="ceo-fake@company-corp.com",
        risk_score=85.0,
        verdict="PHISHING",
        findings=[]
    )
    assert alert2 is None  # Cooldown active

"""
Tests for Phase 3 Features F11 to F14:
- F11: Forensic Report v2 (JSON/PDF self-hashing, custody logs)
- F12: Case & Evidence Management
- F13: Evidence Encryption at Rest (AES-256/Fernet)
- F14: India Threat Coverage & Hinglish Lures (KYC, Tax, Electricity, Brands)
"""

import os
import yaml
import pytest
from backend.app.privacy.encryption import encrypt_evidence_payload, decrypt_evidence_payload
from backend.app.services.report_service import generate_json_report, generate_pdf_report
from backend.app.services.parser_service import parse_eml_bytes
from backend.app.engines.intent_engine import analyze_intent


# =========================================================================
# F11: Forensic Report v2 Tests
# =========================================================================

def test_F11_json_report_generation_with_self_hash(db_session):
    """F11: JSON report includes evidence integrity, custody chain, and disclaimer."""
    from backend.app.models import Evidence
    ev = db_session.query(Evidence).first()
    if ev:
        report = generate_json_report(db_session, ev.id, record_custody=False)
        assert "evidence_integrity" in report
        assert "custody_chain" in report["evidence_integrity"]
        assert "disclaimer" in report
        assert report["evidence_integrity"]["sha256"] == ev.sha256


# =========================================================================
# F13: Evidence Encryption at Rest Tests
# =========================================================================

def test_F13_evidence_encryption_decryption_roundtrip():
    """F13: Raw EML payload encrypts and decrypts symmetrically."""
    plain_bytes = b"From: attacker@evil.com\r\nSubject: Test Malicious Payload\r\n\r\nMalware text"
    encrypted = encrypt_evidence_payload(plain_bytes)
    assert encrypted != plain_bytes
    assert len(encrypted) > len(plain_bytes)

    decrypted = decrypt_evidence_payload(encrypted)
    assert decrypted == plain_bytes


def test_F13_empty_payload_safety():
    """F13: Empty payload returns empty bytes safely."""
    assert encrypt_evidence_payload(b"") == b""
    assert decrypt_evidence_payload(b"") == b""


# =========================================================================
# F14: India-Specific Threat Coverage & Hinglish Lure Tests
# =========================================================================

def test_F14_india_lures_yaml_validity():
    """F14: data/rules/india_lures.yaml is present and contains required categories."""
    rules_path = os.path.join(os.path.dirname(__file__), "../../data/rules/india_lures.yaml")
    assert os.path.exists(rules_path), "india_lures.yaml must exist"
    with open(rules_path, "r") as f:
        data = yaml.safe_load(f)
    assert "lures" in data
    categories = [l["id"] for l in data["lures"]]
    assert "IN_KYC_UPDATE" in categories
    assert "IN_INCOME_TAX_REFUND" in categories
    assert "IN_ELECTRICITY_BILL" in categories


def test_F14_india_brands_yaml_validity():
    """F14: data/rules/india_brands.yaml contains Indian financial & government institutions."""
    brands_path = os.path.join(os.path.dirname(__file__), "../../data/rules/india_brands.yaml")
    assert os.path.exists(brands_path), "india_brands.yaml must exist"
    with open(brands_path, "r") as f:
        data = yaml.safe_load(f)
    assert "brands" in data
    brand_ids = [b["id"] for b in data["brands"]]
    assert "sbi" in brand_ids
    assert "hdfc" in brand_ids
    assert "incometax" in brand_ids


def test_F14_hinglish_kyc_lure_detection():
    """F14: Hinglish phrases trigger high urgency / credential threat signals."""
    subject = "Urgent: Turant KYC update karein"
    body = "Aapka khata band ho jayega agar aaj hi pan card link nahi kiya toh. Update now."
    intent_res = analyze_intent(subject, body, "")
    assert intent_res["urgency_detected"] is True
    assert intent_res["semantic_profile"]["urgency_pattern"] == "HIGH_TIME_PRESSURE"

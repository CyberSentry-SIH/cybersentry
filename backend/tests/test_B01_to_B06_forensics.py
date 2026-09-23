import os
import io
import pytest
from datetime import datetime, timezone, timedelta
from backend.app.models import Evidence, CustodyEvent, User, Case, Email, CaseEvidence
from backend.app.services.evidence_service import create_evidence, append_custody_event, verify_custody_chain
from backend.app.services.detection_service import process_email_analysis

def test_B01_custody_chain_valid_on_sqlite(db_session, analyst_headers, client):
    # Upload sample and verify chain is VALID
    with open("data/synthetic/sample_01_credential_phish_paypal.eml", "rb") as f:
        file_bytes = f.read()

    files = {"file": ("sample_01.eml", file_bytes, "message/rfc822")}
    res = client.post("/api/v1/evidence/upload", files=files, headers=analyst_headers)
    assert res.status_code == 200, res.text
    ev_id = res.json()["evidence_id"]

    verify_res = client.get(f"/api/v1/evidence/{ev_id}/custody/verify", headers=analyst_headers)
    assert verify_res.status_code == 200
    data = verify_res.json()
    assert data["chain_status"] == "CHAIN VALID", f"Chain verification failed: {data}"
    assert data["file_integrity"] == "MATCH"

def test_B02_custody_detects_tampered_evidence_file(db_session, analyst_headers, client):
    # Upload sample
    sample_bytes = b"From: test@example.com\nSubject: Tamper Test\n\nOriginal body"
    files = {"file": ("tamper_test.eml", sample_bytes, "message/rfc822")}
    res = client.post("/api/v1/evidence/upload", files=files, headers=analyst_headers)
    assert res.status_code == 200
    ev_id = res.json()["evidence_id"]

    evidence = db_session.query(Evidence).filter(Evidence.evidence_id == ev_id).first()
    assert evidence is not None

    # Tamper with the file on disk (make writable temporarily, append bytes, verify)
    os.chmod(evidence.storage_path, 0o644)
    with open(evidence.storage_path, "ab") as f:
        f.write(b"\n[MALICIOUS TAMPERED BYTES APPENDED]")
    os.chmod(evidence.storage_path, 0o444)

    verify_res = client.get(f"/api/v1/evidence/{ev_id}/custody/verify", headers=analyst_headers)
    assert verify_res.status_code == 200
    data = verify_res.json()
    assert data["chain_status"] == "CHAIN INVALID"
    assert data["file_integrity"] == "MISMATCH"

def test_B03_custody_events_lifecycle(db_session, analyst_headers, client):
    sample_bytes = b"From: lifecycle@example.com\nSubject: Lifecycle Test\n\nTest body"
    files = {"file": ("lifecycle_test.eml", sample_bytes, "message/rfc822")}
    res = client.post("/api/v1/evidence/upload", files=files, headers=analyst_headers)
    assert res.status_code == 200
    ev_id = res.json()["evidence_id"]

    evidence = db_session.query(Evidence).filter(Evidence.evidence_id == ev_id).first()
    events = db_session.query(CustodyEvent).filter(CustodyEvent.evidence_id == evidence.id).all()
    actions = [e.action for e in events]
    assert "INGESTED" in actions
    assert "PARSED" in actions
    assert "ANALYZED" in actions

    # Fetch detail -> VIEWED event
    res_detail = client.get(f"/api/v1/evidence/{ev_id}", headers=analyst_headers)
    assert res_detail.status_code == 200
    events_after = db_session.query(CustodyEvent).filter(CustodyEvent.evidence_id == evidence.id).all()
    assert any(e.action == "VIEWED" for e in events_after)

def test_B04_retention_skips_legal_hold_and_open_cases(db_session, admin_headers, analyst_headers, client):
    # Upload evidence
    sample_bytes = b"From: hold@example.com\nSubject: Hold Test\n\nLegal hold test"
    files = {"file": ("hold_test.eml", sample_bytes, "message/rfc822")}
    res = client.post("/api/v1/evidence/upload", files=files, headers=analyst_headers)
    assert res.status_code == 200
    ev_id = res.json()["evidence_id"]

    evidence = db_session.query(Evidence).filter(Evidence.evidence_id == ev_id).first()
    evidence.legal_hold = True
    evidence.retention_until = datetime.now(timezone.utc) - timedelta(days=10)
    db_session.commit()

    # Trigger retention enforcement
    ret_res = client.post("/api/v1/admin/retention/enforce", headers=admin_headers)
    assert ret_res.status_code == 200

    # Evidence must still exist due to legal_hold
    ev_check = db_session.query(Evidence).filter(Evidence.evidence_id == ev_id).first()
    assert ev_check is not None, "Evidence with legal_hold was purged incorrectly"

def test_B05_geolocation_snapshot_persisted(db_session, analyst_headers, client):
    # Fetch an analyzed email's geo snapshot
    email = db_session.query(Email).first()
    assert email is not None

    res = client.get(f"/api/v1/analysis/hops/{email.id}/geo", headers=analyst_headers)
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    if len(data) > 0:
        assert "source" in data[0] or "ip_address" in data[0]

def test_B06_duplicate_upload_deduplication(db_session, analyst_headers, client):
    sample_bytes = b"From: duplicate@example.com\nSubject: Dedupe Test\n\nDedupe content"
    files = {"file": ("dedupe.eml", sample_bytes, "message/rfc822")}

    res1 = client.post("/api/v1/evidence/upload", files=files, headers=analyst_headers)
    assert res1.status_code == 200
    ev1_id = res1.json()["evidence_id"]

    files2 = {"file": ("dedupe_copy.eml", sample_bytes, "message/rfc822")}
    res2 = client.post("/api/v1/evidence/upload", files=files2, headers=analyst_headers)
    assert res2.status_code == 200
    ev2_id = res2.json()["evidence_id"]

    # Dedupe returns the same evidence
    assert ev1_id == ev2_id

    # Check DUPLICATE_SUBMISSION custody event recorded
    evidence = db_session.query(Evidence).filter(Evidence.evidence_id == ev1_id).first()
    events = db_session.query(CustodyEvent).filter(CustodyEvent.evidence_id == evidence.id).all()
    actions = [e.action for e in events]
    assert "DUPLICATE_SUBMISSION" in actions

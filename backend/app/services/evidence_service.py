import os
import hmac
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Tuple, Optional, Dict, Any
from sqlalchemy.orm import Session
from backend.app.core.config import settings
from backend.app.models import Evidence, CustodyEvent, User

GENESIS_HASH = "GENESIS-0000000000000000000000000000000000000000000000000000000000000000"

def format_canonical_utc(dt: Optional[datetime]) -> str:
    """Canonicalize datetime to UTC ISO-8601 string for tamper-proof hashing."""
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat()

def compute_chain_head_hmac(latest_event_hash: str) -> str:
    """Compute an HMAC over the chain head using server SECRET_KEY."""
    return hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        latest_event_hash.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

def create_evidence(
    db: Session,
    filename: str,
    file_bytes: bytes,
    collector_user: Optional[User] = None
) -> Tuple[Evidence, CustodyEvent]:
    """
    Ingests evidence with deduplication (B06), read-only permissions (B02),
    and cryptographic chain-of-custody genesis event (B01, B02).
    Returns (evidence, latest_custody_event).
    """
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()

    # Deduplicate against existing evidence by SHA-256
    existing = db.query(Evidence).filter(Evidence.sha256 == sha256_hash).first()
    if existing:
        dup_event = append_custody_event(
            db=db,
            evidence=existing,
            action="DUPLICATE_SUBMISSION",
            actor=collector_user,
            details={
                "attempted_filename": filename,
                "size_bytes": len(file_bytes),
                "sha256": sha256_hash,
                "submitted_by": collector_user.email if collector_user else "anonymous"
            }
        )
        return existing, dup_event

    unique_suffix = uuid.uuid4().hex[:10].upper()
    evidence_id = f"EV-{datetime.now(timezone.utc).year}-{unique_suffix}"

    # Save file safely to storage directory and lock permissions (chmod 0o444)
    file_path = os.path.join(settings.EVIDENCE_STORAGE_PATH, f"{evidence_id}_{sha256_hash[:12]}.eml")
    with open(file_path, "wb") as f:
        f.write(file_bytes)
    try:
        os.chmod(file_path, 0o444)
    except Exception:
        pass

    evidence = Evidence(
        evidence_id=evidence_id,
        original_filename=filename,
        mime_type="message/rfc822",
        size_bytes=len(file_bytes),
        sha256=sha256_hash,
        storage_path=file_path,
        source_type="USER_UPLOAD",
        collected_at=datetime.now(timezone.utc),
        collected_by=collector_user.id if collector_user else None,
        legal_hold=False
    )
    db.add(evidence)
    db.flush()

    # Create Initial Ingested Custody Event in Hash Chain
    custody_event = append_custody_event(
        db=db,
        evidence=evidence,
        action="INGESTED",
        actor=collector_user,
        details={
            "original_filename": filename,
            "size_bytes": len(file_bytes),
            "sha256": sha256_hash,
            "storage_path": file_path
        }
    )

    return evidence, custody_event

def append_custody_event(
    db: Session,
    evidence: Evidence,
    action: str,
    actor: Optional[User] = None,
    details: Optional[dict] = None
) -> CustodyEvent:
    if details is None:
        details = {}

    # Find the most recent custody event for this evidence
    prev_event = (
        db.query(CustodyEvent)
        .filter(CustodyEvent.evidence_id == evidence.id)
        .order_by(CustodyEvent.event_time.desc())
        .first()
    )
    prev_hash = prev_event.event_hash if prev_event else GENESIS_HASH

    now = datetime.now(timezone.utc)
    metadata_json = json.dumps(details, sort_keys=True)
    metadata_hash = hashlib.sha256(metadata_json.encode("utf-8")).hexdigest()

    # Canonical UTC timestamp string
    now_str = format_canonical_utc(now)

    # Event hash chains previous event hash + action + timestamp + metadata hash + evidence sha256
    raw_chain_string = f"{prev_hash}:{action}:{now_str}:{metadata_hash}:{evidence.sha256}"
    event_hash = hashlib.sha256(raw_chain_string.encode("utf-8")).hexdigest()

    custody_event = CustodyEvent(
        evidence_id=evidence.id,
        actor_id=actor.id if actor else None,
        action=action,
        event_time=now,
        metadata_hash=metadata_hash,
        previous_event_hash=prev_hash,
        event_hash=event_hash,
        details=details
    )
    db.add(custody_event)
    
    # Update chain head HMAC on evidence
    evidence.chain_head_hmac = compute_chain_head_hmac(event_hash)
    db.commit()
    db.refresh(custody_event)
    return custody_event

def verify_custody_chain(db: Session, evidence: Evidence) -> Dict[str, Any]:
    """
    B01 & B02: Full evidentiary verification.
    1. Re-hashes the evidence file on disk to verify physical integrity.
    2. Re-walks every custody event hash from GENESIS_HASH.
    3. Verifies the chain-head HMAC.
    """
    file_integrity = "MISSING"
    if os.path.exists(evidence.storage_path):
        try:
            with open(evidence.storage_path, "rb") as f:
                disk_bytes = f.read()
            disk_sha = hashlib.sha256(disk_bytes).hexdigest()
            file_integrity = "MATCH" if disk_sha == evidence.sha256 else "MISMATCH"
        except Exception:
            file_integrity = "ERROR_READING_FILE"

    events = (
        db.query(CustodyEvent)
        .filter(CustodyEvent.evidence_id == evidence.id)
        .order_by(CustodyEvent.event_time.asc())
        .all()
    )

    expected_prev_hash = GENESIS_HASH
    broken_at_event_id = None
    broken_reason = None

    for ev in events:
        recomputed_metadata_hash = hashlib.sha256(
            json.dumps(ev.details or {}, sort_keys=True).encode("utf-8")
        ).hexdigest()

        if recomputed_metadata_hash != ev.metadata_hash:
            broken_at_event_id, broken_reason = ev.id, "metadata_hash mismatch (details were altered)"
            break

        if (ev.previous_event_hash or GENESIS_HASH) != expected_prev_hash:
            broken_at_event_id, broken_reason = ev.id, "previous_event_hash does not match prior event (chain link broken)"
            break

        ev_time_str = format_canonical_utc(ev.event_time)
        raw_chain_string = f"{expected_prev_hash}:{ev.action}:{ev_time_str}:{recomputed_metadata_hash}:{evidence.sha256}"
        recomputed_event_hash = hashlib.sha256(raw_chain_string.encode("utf-8")).hexdigest()

        if recomputed_event_hash != ev.event_hash:
            broken_at_event_id, broken_reason = ev.id, "event_hash mismatch (action/timestamp/details tampered)"
            break

        expected_prev_hash = ev.event_hash

    # Verify chain-head HMAC if events exist and HMAC is present
    if not broken_at_event_id and events and evidence.chain_head_hmac:
        expected_hmac = compute_chain_head_hmac(events[-1].event_hash)
        if evidence.chain_head_hmac != expected_hmac:
            broken_at_event_id = events[-1].id
            broken_reason = "chain_head_hmac mismatch (unauthorized database modification of custody history)"

    # Verify physical file integrity
    if not broken_at_event_id and file_integrity != "MATCH":
        broken_reason = f"Evidence file integrity failure ({file_integrity}): expected {evidence.sha256}"

    is_valid = (broken_at_event_id is None) and (file_integrity == "MATCH")

    return {
        "evidence_id": evidence.evidence_id,
        "chain_status": "CHAIN VALID" if is_valid else "CHAIN INVALID",
        "file_integrity": file_integrity,
        "events_checked": len(events),
        "broken_at_event_id": broken_at_event_id,
        "broken_reason": broken_reason
    }

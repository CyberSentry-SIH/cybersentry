import os
from datetime import datetime, timezone, timedelta
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from backend.app.core.config import settings
from backend.app.core.database import get_db
from backend.app.core.security import get_password_hash
from backend.app.models import User, ThreatIntelEntry, AuditEvent, Evidence, Case, CaseEvidence, CustodyEvent
from backend.app.schemas import UserResponse, UserCreateRequest
from backend.app.api.deps import require_admin

router = APIRouter(prefix="/admin", tags=["Administration"])

@router.get("/users", response_model=List[UserResponse])
def list_users(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    users = db.query(User).all()
    return [UserResponse.model_validate(u) for u in users]

@router.post("/users", response_model=UserResponse)
def create_user(req: UserCreateRequest, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    existing = db.query(User).filter(User.email == req.email.strip().lower()).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered.")

    role_val = req.role.upper()
    if role_val not in ("ADMINISTRATOR", "ANALYST", "VIEWER"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid role. Must be ADMINISTRATOR, ANALYST, or VIEWER.")

    if len(req.password) < 12:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password must be at least 12 characters.")

    new_user = User(
        email=req.email.strip().lower(),
        password_hash=get_password_hash(req.password),
        full_name=req.full_name,
        role=role_val,
        is_active=True
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return UserResponse.model_validate(new_user)

@router.get("/audit-events")
def list_audit_events(limit: int = 100, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    events = db.query(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(limit).all()
    return [
        {
            "id": e.id,
            "actor_id": e.actor_id,
            "action": e.action,
            "object_type": e.object_type,
            "object_id": e.object_id,
            "created_at": e.created_at,
            "metadata": e.metadata_json
        }
        for e in events
    ]

@router.get("/threat-intel")
def list_threat_intel(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    entries = db.query(ThreatIntelEntry).all()
    return [
        {
            "id": en.id,
            "indicator_type": en.indicator_type,
            "canonical_value": en.canonical_value,
            "verdict": en.verdict,
            "source": en.source,
            "confidence": float(en.confidence or 0.9),
            "notes": en.notes,
            "created_at": en.created_at
        }
        for en in entries
    ]

@router.post("/retention/enforce")
def enforce_retention_policy(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    """
    B04: Operational retention policy enforcement with Legal Hold protection.
    Skips evidence with legal_hold=True or attached to OPEN/INVESTIGATING cases.
    Preserves custody event summaries in AuditEvent before deletion.
    """
    now = datetime.now(timezone.utc)
    retention_cutoff = now - timedelta(days=settings.RETENTION_DAYS)
    candidates = db.query(Evidence).filter(
        (Evidence.retention_until.isnot(None) & (Evidence.retention_until <= now)) |
        (Evidence.retention_until.is_(None) & (Evidence.created_at <= retention_cutoff))
    ).all()

    purged_records = []
    skipped_records = []

    for ev in candidates:
        # Check legal hold
        if ev.legal_hold:
            skipped_records.append({"evidence_id": ev.evidence_id, "reason": "LEGAL_HOLD"})
            continue

        # Check attached cases
        active_case = (
            db.query(Case)
            .join(CaseEvidence, Case.id == CaseEvidence.case_id)
            .filter(
                CaseEvidence.evidence_id == ev.id,
                Case.status.in_(["OPEN", "INVESTIGATING"])
            )
            .first()
        )
        if active_case:
            skipped_records.append({
                "evidence_id": ev.evidence_id,
                "reason": f"ACTIVE_CASE_{active_case.case_key}"
            })
            continue

        # Preserve custody history summary
        custody_summary = [
            {"action": c.action, "time": c.event_time.isoformat(), "hash": c.event_hash}
            for c in ev.custody_events
        ]

        ev_id = ev.evidence_id
        storage_path = ev.storage_path
        if storage_path and os.path.exists(storage_path):
            try:
                os.remove(storage_path)
            except OSError:
                pass

        purged_records.append({
            "evidence_id": ev_id,
            "sha256": ev.sha256,
            "custody_summary": custody_summary
        })
        db.delete(ev)

    audit_entry = AuditEvent(
        actor_id=admin.id,
        action="RETENTION_POLICY_ENFORCED",
        object_type="Evidence",
        object_id="BATCH",
        metadata_json={
            "retention_days": settings.RETENTION_DAYS,
            "purged_count": len(purged_records),
            "skipped_count": len(skipped_records),
            "purged_items": purged_records,
            "skipped_items": skipped_records,
            "enforced_at": now.isoformat()
        }
    )
    db.add(audit_entry)
    db.commit()

    return {
        "status": "success",
        "message": f"Retention policy enforced. Purged {len(purged_records)} expired records. Skipped {len(skipped_records)} records under legal hold/active cases.",
        "purged_count": len(purged_records),
        "skipped_count": len(skipped_records),
        "retention_days": settings.RETENTION_DAYS
    }

@router.delete("/evidence/{evidence_id}")
def delete_evidence_controlled(evidence_id: str, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    """Controlled deletion workflow with legal hold check."""
    ev = db.query(Evidence).filter((Evidence.evidence_id == evidence_id) | (Evidence.id == evidence_id)).first()
    if not ev:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Evidence {evidence_id} not found.")

    if ev.legal_hold:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete evidence with active LEGAL HOLD. Release the legal hold first."
        )

    active_case = (
        db.query(Case)
        .join(CaseEvidence, Case.id == CaseEvidence.case_id)
        .filter(
            CaseEvidence.evidence_id == ev.id,
            Case.status.in_(["OPEN", "INVESTIGATING"])
        )
        .first()
    )
    if active_case:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot delete evidence attached to active case {active_case.case_key}."
        )

    target_id = ev.evidence_id
    target_sha256 = ev.sha256
    storage_path = ev.storage_path

    if storage_path and os.path.exists(storage_path):
        try:
            os.remove(storage_path)
        except OSError:
            pass

    db.delete(ev)

    audit_entry = AuditEvent(
        actor_id=admin.id,
        action="CONTROLLED_EVIDENCE_DELETION",
        object_type="Evidence",
        object_id=target_id,
        metadata_json={
            "evidence_id": target_id,
            "sha256": target_sha256,
            "purged_by": admin.email,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    )
    db.add(audit_entry)
    db.commit()

    return {
        "status": "success",
        "evidence_id": target_id,
        "message": f"Evidence {target_id} permanently purged. Audit trail recorded."
    }


@router.get("/dataset-stats")
def get_kaggle_dataset_statistics(db: Session = Depends(get_db)):
    from backend.app.services.kaggle_dataset_service import get_dataset_stats
    return get_dataset_stats(db=db)


@router.post("/sync-kaggle-dataset")
def sync_kaggle_dataset(limit: int = 1500, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    from backend.app.services.kaggle_dataset_service import ingest_kaggle_phishing_indicators
    count = ingest_kaggle_phishing_indicators(db=db, sample_limit=limit)
    return {
        "status": "success",
        "ingested_count": count,
        "message": f"Successfully synced {count} threat intelligence indicators from Kaggle phishing dataset."
    }

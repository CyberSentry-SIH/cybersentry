import logging
from typing import List
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from sqlalchemy.orm import Session
from backend.app.core.database import get_db
from backend.app.core.config import settings
from backend.app.models import Evidence, User
from backend.app.schemas import EvidenceResponse, CustodyEventResponse
from backend.app.services.evidence_service import create_evidence, verify_custody_chain, append_custody_event
from backend.app.services.detection_service import process_email_analysis
from backend.app.api.deps import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/evidence", tags=["Evidence Intake"])

@router.post("/upload", response_model=EvidenceResponse)
async def upload_eml(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported file type. CyberSentry V1 accepts only .eml files."
        )

    chunk_size = 1024 * 1024  # 1MB
    total_read = 0
    chunks = []
    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break
        total_read += len(chunk)
        if total_read > settings.MAX_UPLOAD_SIZE_BYTES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File exceeds maximum allowed size of {settings.MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)}MB."
            )
        chunks.append(chunk)
    file_bytes = b"".join(chunks)

    if len(file_bytes) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty."
        )

    head = file_bytes[:4096]
    try:
        head_text = head.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        try:
            head_text = head.decode("latin-1")
        except Exception:
            head_text = ""
    plausible_email_header = any(
        marker in head_text for marker in ("Received:", "From:", "Subject:", "Return-Path:", "Message-ID:", "Delivered-To:")
    )
    if not plausible_email_header:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File does not appear to be a valid RFC 5322 email message."
        )

    safe_filename = "".join(ch for ch in file.filename if ch.isprintable())[:255] or "unnamed.eml"
    evidence, custody_event = create_evidence(
        db=db,
        filename=safe_filename,
        file_bytes=file_bytes,
        collector_user=current_user
    )

    # If new evidence (not duplicate), automatically trigger pipeline processing
    if custody_event.action != "DUPLICATE_SUBMISSION":
        try:
            run = process_email_analysis(db=db, evidence=evidence, actor_user=current_user)
            # Automatically create an active investigation case for the uploading user
            try:
                from backend.app.services.case_service import create_case
                sev = "MEDIUM"
                if run and run.risk_score:
                    sev = run.risk_score.band or "MEDIUM"
                subj = evidence.email.subject if evidence.email else safe_filename
                create_case(
                    db=db,
                    title=f"Investigation: {subj or safe_filename}",
                    severity=sev,
                    created_by=current_user,
                    summary=f"Incident case opened for evidence {evidence.evidence_id} ({safe_filename}).",
                    evidence_ids=[evidence.id]
                )
            except Exception as case_err:
                logger.warning("Could not auto-create case: %s", case_err)
        except Exception as e:
            logger.exception(
                "Analysis pipeline failed for evidence_id=%s: %s",
                evidence.evidence_id, e
            )

    db.refresh(evidence)
    return EvidenceResponse.model_validate(evidence)

@router.get("", response_model=List[EvidenceResponse])
@router.get("/", response_model=List[EvidenceResponse], include_in_schema=False)
def list_evidence(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    items = db.query(Evidence).order_by(Evidence.collected_at.desc()).all()
    return [EvidenceResponse.model_validate(e) for e in items]

@router.get("/{evidence_id}", response_model=EvidenceResponse)
def get_evidence(evidence_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    item = db.query(Evidence).filter(
        (Evidence.id == evidence_id) | (Evidence.evidence_id == evidence_id)
    ).first()
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found.")
    
    # B03: Record VIEWED custody event
    append_custody_event(
        db=db,
        evidence=item,
        action="VIEWED",
        actor=current_user,
        details={"viewed_by": current_user.email, "interface": "API_OR_UI"}
    )
    db.refresh(item)
    return EvidenceResponse.model_validate(item)

@router.get("/{evidence_id}/custody", response_model=List[CustodyEventResponse])
def get_custody_history(evidence_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    item = db.query(Evidence).filter(
        (Evidence.id == evidence_id) | (Evidence.evidence_id == evidence_id)
    ).first()
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found.")
    return [CustodyEventResponse.model_validate(c) for c in item.custody_events]

@router.get("/{evidence_id}/custody/verify")
def verify_custody_history(evidence_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    item = db.query(Evidence).filter(
        (Evidence.id == evidence_id) | (Evidence.evidence_id == evidence_id)
    ).first()
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found.")
    return verify_custody_chain(db=db, evidence=item)

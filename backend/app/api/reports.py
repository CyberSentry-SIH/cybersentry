from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session
from backend.app.core.database import get_db
from backend.app.models import Evidence, User
from backend.app.services.report_service import generate_json_report, generate_pdf_report
from backend.app.api.deps import get_current_user

router = APIRouter(prefix="/reports", tags=["Forensic Reports"])

@router.get("/{evidence_id}/json")
def get_forensic_json_report(
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    ev = db.query(Evidence).filter(
        (Evidence.id == evidence_id) | (Evidence.evidence_id == evidence_id)
    ).first()
    if not ev:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found.")

    try:
        report_data = generate_json_report(db, ev.id)
        return report_data
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

@router.get("/{evidence_id}/pdf")
def get_forensic_pdf_report(
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    ev = db.query(Evidence).filter(
        (Evidence.id == evidence_id) | (Evidence.evidence_id == evidence_id)
    ).first()
    if not ev:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found.")

    try:
        pdf_bytes = generate_pdf_report(db, ev.id)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="cybersentry_report_{ev.evidence_id}.pdf"'}
        )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from backend.app.core.database import get_db
from backend.app.models import Case, User, AnalystDecision
from backend.app.schemas import (
    CaseCreateRequest, CaseUpdateRequest, CaseResponse,
    AnalystDecisionRequest, AnalystDecisionResponse
)
from backend.app.services.case_service import create_case, record_analyst_decision
from backend.app.api.deps import get_current_user

router = APIRouter(prefix="/cases", tags=["Incident Cases"])

@router.get("", response_model=List[CaseResponse])
@router.get("/", response_model=List[CaseResponse], include_in_schema=False)
def list_cases(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    cases = db.query(Case).order_by(Case.created_at.desc()).all()
    results = []
    for c in cases:
        decisions_data = []
        for d in c.decisions:
            decisions_data.append(AnalystDecisionResponse(
                id=d.id,
                case_id=d.case_id,
                analyst_name=d.analyst.full_name if d.analyst else "SOC Analyst",
                decision=d.decision,
                comment=d.comment,
                score_at_decision=float(d.score_at_decision) if d.score_at_decision else None,
                created_at=d.created_at
            ))

        results.append(CaseResponse(
            id=c.id,
            case_key=c.case_key,
            title=c.title,
            severity=c.severity,
            status=c.status,
            owner_name=c.owner.full_name if c.owner else "Unassigned",
            created_by_name=c.creator.full_name if c.creator else "SOC Team",
            summary=c.summary,
            created_at=c.created_at,
            updated_at=c.updated_at,
            closed_at=c.closed_at,
            evidence_count=len(c.evidences),
            decisions=decisions_data
        ))
    return results

@router.post("/", response_model=CaseResponse)
def create_new_case(
    req: CaseCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    case = create_case(
        db=db,
        title=req.title,
        severity=req.severity,
        created_by=current_user,
        summary=req.summary,
        evidence_ids=req.evidence_ids
    )
    return CaseResponse(
        id=case.id,
        case_key=case.case_key,
        title=case.title,
        severity=case.severity,
        status=case.status,
        owner_name=current_user.full_name,
        created_by_name=current_user.full_name,
        summary=case.summary,
        created_at=case.created_at,
        updated_at=case.updated_at,
        closed_at=case.closed_at,
        evidence_count=len(case.evidences),
        decisions=[]
    )

@router.post("/{case_id}/decision", response_model=AnalystDecisionResponse)
def submit_decision(
    case_id: str,
    req: AnalystDecisionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        decision = record_analyst_decision(
            db=db,
            case_id=case_id,
            analyst=current_user,
            decision=req.decision,
            comment=req.comment
        )
        return AnalystDecisionResponse(
            id=decision.id,
            case_id=decision.case_id,
            analyst_name=current_user.full_name,
            decision=decision.decision,
            comment=decision.comment,
            score_at_decision=float(decision.score_at_decision) if decision.score_at_decision else None,
            created_at=decision.created_at
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

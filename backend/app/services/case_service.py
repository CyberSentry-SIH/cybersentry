import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from backend.app.models import Case, CaseEvidence, AnalystDecision, Evidence, User
from backend.app.services.evidence_service import append_custody_event

def create_case(
    db: Session,
    title: str,
    severity: str,
    created_by: User,
    summary: Optional[str] = None,
    evidence_ids: Optional[List[str]] = None
) -> Case:
    unique_suffix = uuid.uuid4().hex[:8].upper()
    case_key = f"CS-{datetime.now(timezone.utc).year}-{unique_suffix}"

    case = Case(
        case_key=case_key,
        title=title,
        severity=severity.upper(),
        status="OPEN",
        created_by=created_by.id,
        owner_id=created_by.id,
        summary=summary,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc)
    )
    db.add(case)
    db.flush()

    if evidence_ids:
        for eid in evidence_ids:
            ev = db.query(Evidence).filter((Evidence.id == eid) | (Evidence.evidence_id == eid)).first()
            if ev:
                db.add(CaseEvidence(
                    case_id=case.id,
                    evidence_id=ev.id,
                    added_by=created_by.id,
                    added_at=datetime.now(timezone.utc)
                ))

    db.commit()
    db.refresh(case)
    return case

def record_analyst_decision(
    db: Session,
    case_id: str,
    analyst: User,
    decision: str,
    comment: Optional[str] = None
) -> AnalystDecision:
    case = db.query(Case).filter((Case.id == case_id) | (Case.case_key == case_id)).first()
    if not case:
        raise ValueError("Case not found")

    # Fetch score from primary evidence
    score = None
    if case.evidences:
        first_ev = case.evidences[0].evidence
        if first_ev and first_ev.email and first_ev.email.analysis_run and first_ev.email.analysis_run.risk_score:
            score = float(first_ev.email.analysis_run.risk_score.score)

    dec = AnalystDecision(
        case_id=case.id,
        analyst_id=analyst.id,
        decision=decision.upper(),
        comment=comment,
        score_at_decision=score,
        created_at=datetime.now(timezone.utc)
    )
    db.add(dec)

    if decision.upper() == "CONFIRMED_PHISHING":
        case.status = "CONTAINED"
    elif decision.upper() == "FALSE_POSITIVE":
        case.status = "CLOSED"
        case.closed_at = datetime.now(timezone.utc)
    else:
        case.status = "INVESTIGATING"

    case.updated_at = datetime.now(timezone.utc)

    # B03: Record DECISION_RECORDED custody event for all attached evidence
    for ce in case.evidences:
        if ce.evidence:
            append_custody_event(
                db=db,
                evidence=ce.evidence,
                action="DECISION_RECORDED",
                actor=analyst,
                details={
                    "case_key": case.case_key,
                    "decision": decision.upper(),
                    "comment": comment,
                    "case_status": case.status
                }
            )

    db.commit()
    db.refresh(dec)
    return dec

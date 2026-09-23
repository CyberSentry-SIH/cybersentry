from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from backend.app.core.database import get_db
from backend.app.models import AnalysisRun, Email, Evidence, User, ReceivedHop
from backend.app.schemas import (
    AnalysisDetailResponse, FindingResponse, RiskScoreResponse,
    PhishDNAResponse, RecommendedActionResponse, DashboardStatsResponse
)
from backend.app.api.deps import get_current_user
from backend.app.services.geo_service import enrich_ip_geolocation
from backend.app.services.evidence_service import append_custody_event

router = APIRouter(prefix="/analysis", tags=["Threat Analysis"])

@router.get("/dashboard-stats", response_model=DashboardStatsResponse)
def get_dashboard_stats(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    from backend.app.models import Finding, Case, Campaign

    total_analyzed = db.query(Email).count()
    critical_findings = db.query(Finding).filter(Finding.severity == "CRITICAL").count()
    high_findings = db.query(Finding).filter(Finding.severity == "HIGH").count()
    open_cases = db.query(Case).filter(Case.status.in_(["OPEN", "INVESTIGATING"])).count()
    active_campaigns = db.query(Campaign).filter(Campaign.state.in_(["EMERGING", "ACTIVE", "EXPANDING"])).count()

    recent_runs = db.query(AnalysisRun).order_by(AnalysisRun.started_at.desc()).limit(10).all()
    recent_list = []
    for r in recent_runs:
        if r.email:
            camp_name = None
            if r.email.campaign_memberships:
                camp_name = r.email.campaign_memberships[0].campaign.name if r.email.campaign_memberships[0].campaign else None

            recent_list.append({
                "id": r.id,
                "email_id": r.email.id,
                "evidence_id": r.email.evidence.evidence_id if r.email.evidence else "",
                "subject": r.email.subject or "No Subject",
                "sender": r.email.from_address or "Unknown",
                "risk_score": float(r.risk_score.score) if r.risk_score else 0.0,
                "risk_band": r.risk_score.band if r.risk_score else "UNKNOWN",
                "campaign": camp_name,
                "intent": r.phishdna.content_dna.get("intent") if r.phishdna else "UNKNOWN",
                "analyzed_at": r.started_at
            })

    return DashboardStatsResponse(
        total_analyzed=total_analyzed,
        critical_findings=critical_findings,
        high_findings=high_findings,
        open_cases=open_cases,
        active_campaigns=active_campaigns,
        recent_analyses=recent_list
    )

@router.get("/hops/{email_id}/geo", response_model=List[Dict[str, Any]])
def get_hop_geolocation(
    email_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Return geo-enriched hop data for an email's received chain.
    B05: Reads from persisted hop.geo_snapshot for reproducibility, falling back to live lookup if empty.
    """
    hops = db.query(ReceivedHop).filter(ReceivedHop.email_id == email_id).order_by(ReceivedHop.hop_order).all()
    result = []
    for hop in hops:
        geo = hop.geo_snapshot if hop.geo_snapshot else (enrich_ip_geolocation(hop.ip_address) if hop.ip_address else None)
        result.append({
            "hop_order": hop.hop_order,
            "hostname": hop.hostname,
            "ip_address": hop.ip_address,
            "raw_value": hop.raw_value,
            "trust_level": hop.trust_level,
            "geo": geo,
            "source": geo.get("source", "PERSISTED_SNAPSHOT") if isinstance(geo, dict) else "UNKNOWN"
        })
    return result

@router.get("/{analysis_or_email_id}", response_model=AnalysisDetailResponse)
def get_analysis_detail(
    analysis_or_email_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    analysis = (
        db.query(AnalysisRun)
        .filter(
            (AnalysisRun.id == analysis_or_email_id) |
            (AnalysisRun.email_id == analysis_or_email_id)
        )
        .first()
    )

    if not analysis:
        # Try finding by evidence ID
        ev = db.query(Evidence).filter(
            (Evidence.id == analysis_or_email_id) |
            (Evidence.evidence_id == analysis_or_email_id)
        ).first()
        if ev and ev.email and ev.email.analysis_run:
            analysis = ev.email.analysis_run

    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Analysis record not found."
        )

    # B03: Record VIEWED custody event on evidence
    if analysis.email and analysis.email.evidence:
        append_custody_event(
            db=db,
            evidence=analysis.email.evidence,
            action="VIEWED",
            actor=current_user,
            details={"viewed_by": current_user.email, "analysis_id": analysis.id}
        )

    return AnalysisDetailResponse(
        id=analysis.id,
        email_id=analysis.email_id,
        evidence_id=analysis.email.evidence_id if analysis.email else "",
        status=analysis.status,
        engine_version=analysis.engine_version,
        started_at=analysis.started_at,
        completed_at=analysis.completed_at,
        llm_used=analysis.llm_used,
        external_intel_used=analysis.external_intel_used,
        risk_score=RiskScoreResponse.model_validate(analysis.risk_score) if analysis.risk_score else None,
        phishdna=PhishDNAResponse.model_validate(analysis.phishdna) if analysis.phishdna else None,
        findings=[FindingResponse.model_validate(f) for f in analysis.findings],
        recommended_actions=[RecommendedActionResponse.model_validate(r) for r in analysis.recommended_actions],
        llm_analysis=analysis.llm_analysis,
        email=analysis.email
    )

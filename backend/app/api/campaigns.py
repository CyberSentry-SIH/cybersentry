from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from backend.app.core.database import get_db
from backend.app.models import Campaign, CampaignMember, User, Email, Evidence
from backend.app.schemas import CampaignResponse, CampaignEvolutionEventResponse, WhatChangedResponse
from backend.app.services.campaign_service import compare_emails_what_changed
from backend.app.services.investigation_service import get_campaign_investigation
from backend.app.api.deps import get_current_user
from backend.app.core.strength import relationship_strength_label

router = APIRouter(prefix="/campaigns", tags=["Attack Campaigns"])

@router.get("", response_model=List[CampaignResponse])
@router.get("/", response_model=List[CampaignResponse], include_in_schema=False)
def list_campaigns(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    campaigns = db.query(Campaign).order_by(Campaign.last_seen.desc()).all()
    results = []
    for c in campaigns:
        members_data = []
        for m in c.members:
            members_data.append({
                "email_id": m.email_id,
                "similarity_score": float(m.similarity_score) if m.similarity_score is not None else None,
                "relationship_reason": m.relationship_reason,
                "subject": m.email.subject if m.email else "No Subject",
                "sender": m.email.from_address if m.email else "Unknown"
            })
        
        events_data = [CampaignEvolutionEventResponse.model_validate(e) for e in c.events]

        results.append(CampaignResponse(
            id=c.id,
            campaign_key=c.campaign_key,
            name=c.name,
            confidence=float(c.confidence or 0.9),
            relationship_strength=relationship_strength_label(float(c.confidence or 0.9)),
            first_seen=c.first_seen,
            last_seen=c.last_seen,
            primary_intent=c.primary_intent,
            state=c.state,
            risk_trend=c.risk_trend,
            status=c.status,
            member_count=len(members_data),
            members=members_data,
            events=events_data
        ))
    return results

@router.get("/compare", response_model=WhatChangedResponse)
def compare_emails(
    email_a: str = Query(..., description="First email ID or Evidence ID"),
    email_b: str = Query(..., description="Second email ID or Evidence ID"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    def resolve_email_id(val: str) -> str:
        # Try direct Email table lookup
        email = db.query(Email).filter(Email.id == val).first()
        if email:
            return email.id
        # Try Evidence UUID or evidence_id string (e.g. "EV-2026-00015")
        evidence = db.query(Evidence).filter(
            (Evidence.id == val) | (Evidence.evidence_id == val)
        ).first()
        if evidence and evidence.email:
            return evidence.email.id
        raise HTTPException(status_code=404, detail=f"Email or Evidence ID '{val}' not found")

    try:
        resolved_a = resolve_email_id(email_a)
        resolved_b = resolve_email_id(email_b)
        diff_data = compare_emails_what_changed(db, resolved_a, resolved_b)
        return WhatChangedResponse(**diff_data)
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.get("/{campaign_id_or_key}", response_model=CampaignResponse)
def get_campaign(
    campaign_id_or_key: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    c = db.query(Campaign).filter(
        (Campaign.id == campaign_id_or_key) |
        (Campaign.campaign_key == campaign_id_or_key)
    ).first()

    if not c:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Campaign not found."
        )

    members_data = []
    for m in c.members:
        members_data.append({
            "email_id": m.email_id,
            "similarity_score": float(m.similarity_score) if m.similarity_score is not None else None,
            "relationship_reason": m.relationship_reason,
            "subject": m.email.subject if m.email else "No Subject",
            "sender": m.email.from_address if m.email else "Unknown"
        })

    events_data = [CampaignEvolutionEventResponse.model_validate(e) for e in c.events]

    return CampaignResponse(
        id=c.id,
        campaign_key=c.campaign_key,
        name=c.name,
        confidence=float(c.confidence or 0.9),
        relationship_strength=relationship_strength_label(float(c.confidence or 0.9)),
        first_seen=c.first_seen,
        last_seen=c.last_seen,
        primary_intent=c.primary_intent,
        state=c.state,
        risk_trend=c.risk_trend,
        status=c.status,
        member_count=len(members_data),
        members=members_data,
        events=events_data
    )


@router.get("/{campaign_id_or_key}/investigation")
def get_campaign_investigation_view(
    campaign_id_or_key: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    The unified Campaign Investigation workflow. One call returns
    everything that previously required separately hitting Campaign
    Intelligence and Variance Comparison: related emails, retained attack
    invariants, a step-by-step variance timeline, extracted indicators,
    the campaign's evolution timeline (including automated LLM similarity
    assessments), and the evidence IDs ready for per-message forensic
    reports.
    """
    try:
        return get_campaign_investigation(db=db, campaign_id_or_key=campaign_id_or_key)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))

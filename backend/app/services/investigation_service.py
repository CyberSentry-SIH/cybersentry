"""
investigation_service.py — Unified Campaign Investigation Workflow

Before this file existed, CyberSentry exposed two separate features that
an analyst had to run by hand, one at a time:

  1. Campaign Intelligence (GET /campaigns/)      -- decide which emails
                                                      are related
  2. Variance Comparison (GET /campaigns/compare) -- explain what changed
                                                      between two emails

But these aren't independent capabilities -- they're two stages of the
SAME investigation, always run in the same order: you correlate evidence
into a campaign, then explain how the campaign's members differ.
Presenting them as separate dashboard tools made the product look
fragmented and made the analyst do the orchestration that the software
should be doing.

This module is the single orchestration function the fix calls for. It
does NOT reimplement the variance engine -- it calls the existing,
already-correct campaign/variance code in sequence and stitches the
results into one `Campaign Investigation` payload:

    Campaign Investigation
        ├── Related Emails        (from Campaign Intelligence)
        ├── Attack Invariants     (from Variance Comparison)
        ├── What Changed          (from Variance Comparison, per step)
        ├── Indicators            (extracted from campaign member emails)
        ├── Campaign Timeline     (from CampaignEvolutionEvent, including
        │                         the automated LLM similarity assessments
        │                         produced by campaign_intelligence_service)
        └── Evidence & Report     (evidence_ids, ready for /reports/{id})
"""
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from backend.app.models import Campaign, Email
from backend.app.services.campaign_service import compare_emails_what_changed
from backend.app.core.strength import relationship_strength_label


def _extract_indicators_for_emails(emails: List[Email]) -> Dict[str, List[str]]:
    """
    Stage: Indicator Extraction. Pulls the underlying evidence fields
    (sender domain/address, received-hop IPs, URL-linked domains from
    PhishDNA's url_dna, PhishDNA fingerprints, attachment hashes) scoped
    to one campaign's members.
    """
    domains, sender_addresses, ips, url_domains, fingerprints, attachment_hashes = (
        set(), set(), set(), set(), set(), set()
    )

    for em in emails:
        if em.from_domain:
            domains.add(em.from_domain)
        if em.from_address:
            sender_addresses.add(em.from_address)

        for hop in (em.hops or []):
            if hop.ip_address:
                ips.add(hop.ip_address)

        for att in (em.attachments or []):
            if att.sha256:
                attachment_hashes.add(att.sha256)

        analysis = em.analysis_run
        if analysis and analysis.phishdna:
            if analysis.phishdna.fingerprint:
                fingerprints.add(analysis.phishdna.fingerprint)
            for d in (analysis.phishdna.url_dna or {}).get("domains", []):
                url_domains.add(d)

    return {
        "sender_domains": sorted(domains),
        "sender_addresses": sorted(sender_addresses),
        "infrastructure_ips": sorted(ips),
        "url_linked_domains": sorted(url_domains),
        "phishdna_fingerprints": sorted(fingerprints),
        "attachment_hashes": sorted(attachment_hashes),
    }


def get_campaign_investigation(db: Session, campaign_id_or_key: str) -> Dict[str, Any]:
    """
    The single entry point for the unified workflow:
    Detect -> Correlate -> Explain Variants -> Extract Indicators -> Report.
    A campaign already exists (Detect + Correlate happened when its members
    were added); this assembles the rest into one investigation view.
    """
    campaign = db.query(Campaign).filter(
        (Campaign.id == campaign_id_or_key) | (Campaign.campaign_key == campaign_id_or_key)
    ).first()
    if not campaign:
        raise ValueError(f"Campaign '{campaign_id_or_key}' not found.")

    members = sorted(
        campaign.members,
        key=lambda m: (m.email.sent_at or m.created_at) if m.email else m.created_at
    )
    member_emails = [m.email for m in members if m.email]

    # Stage: Related Emails (already correlated by Campaign Intelligence;
    # we're just exposing the correlation evidence that put them here)
    related_emails = [
        {
            "email_id": m.email_id,
            "evidence_id": m.email.evidence.evidence_id if (m.email and m.email.evidence) else None,
            "subject": m.email.subject if m.email else None,
            "from_address": m.email.from_address if m.email else None,
            "sent_at": m.email.sent_at.isoformat() if (m.email and m.email.sent_at) else None,
            "relationship_reason": m.relationship_reason or []
        }
        for m in members
    ]

    # Stage: Variant / Variance Analysis, run across every consecutive pair
    # so the investigation shows evolution over time, not just one diff.
    variance_timeline = []
    attack_invariants = []
    infrastructure_relationships = []

    for i in range(1, len(member_emails)):
        try:
            diff = compare_emails_what_changed(db, member_emails[i - 1].id, member_emails[i].id)
            variance_timeline.append({
                "from_email_id": member_emails[i - 1].id,
                "from_evidence_id": member_emails[i - 1].evidence.evidence_id if member_emails[i - 1].evidence else None,
                "to_email_id": member_emails[i].id,
                "to_evidence_id": member_emails[i].evidence.evidence_id if member_emails[i].evidence else None,
                "similarity_score": diff.get("similarity_score"),
                "relationship_strength": diff.get("relationship_strength"),
                "mutated_surface_features": diff.get("mutated_surface_features", []),
                "differences": diff.get("differences", {})
            })
            if not attack_invariants:
                attack_invariants = diff.get("retained_attack_invariants", [])
            if not infrastructure_relationships:
                infrastructure_relationships = diff.get("infrastructure_relationships", [])
        except ValueError:
            continue

    # Stage: Indicator Extraction, scoped to this campaign
    indicators = _extract_indicators_for_emails(member_emails)

    # Stage: Campaign Timeline (state transitions, new infra observed, etc.)
    timeline = [
        {
            "event_type": ev.event_type,
            "event_time": ev.event_time.isoformat(),
            "summary": ev.summary
        }
        for ev in sorted(campaign.events, key=lambda e: e.event_time)
    ]

    # Stage: Evidence & Report — evidence IDs ready to hand to
    # /reports/{evidence_id}/pdf for a per-message forensic report.
    evidence_refs = [
        m.email.evidence.evidence_id
        for m in members
        if m.email and m.email.evidence
    ]

    return {
        "campaign_id": campaign.id,
        "campaign_key": campaign.campaign_key,
        "name": campaign.name,
        "state": campaign.state,
        "risk_trend": campaign.risk_trend,
        "relationship_strength": relationship_strength_label(float(campaign.confidence or 0.9)),
        "member_count": len(members),
        "related_emails": related_emails,
        "attack_invariants": attack_invariants,
        "infrastructure_relationships": infrastructure_relationships,
        "variance_timeline": variance_timeline,
        "indicators": indicators,
        "campaign_timeline": timeline,
        "evidence_refs": evidence_refs
    }

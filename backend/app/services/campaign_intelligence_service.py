"""
campaign_intelligence_service.py — Automated LLM Email Similarity Analysis

This is a backend-only extension of Campaign Intelligence. It is NOT a
separate feature and has NO dedicated API route or frontend page: it runs
automatically inside the analysis pipeline (see detection_service.py)
every time a new email is ingested, and its findings are written directly
into the campaign's evolution timeline (CampaignEvolutionEvent) so they
appear inline with the rest of Campaign Intelligence's output.

Why this exists alongside the deterministic PhishDNA correlation engine
(campaign_engine.py) and the deterministic "What Changed?" Variant
Comparison (campaign_service.compare_emails_what_changed):

  - campaign_engine.correlate_campaign() decides campaign membership using
    normalized feature-vector cosine similarity, shared domains/IPs, etc.
    It is fast and deterministic, but purely numeric.
  - This module asks an LLM to read the new email against the strongest
    prior candidates the way a human analyst would, and to judge
    similarity against the SAME evidence categories the deterministic
    Variant Comparison view already reports (attack intent, impersonation
    target, social-engineering strategy, requested action, and the usual
    surface mutations: sender mailbox/domain, subject, landing domains,
    reply-to). That keeps its output consistent with, and additive to,
    the existing Campaign Intelligence / Variant Comparison surfaces
    without duplicating or replacing either of them.

If no LLM is configured (settings.ENABLE_LLM is false / no API key), this
module quietly does nothing -- callers should always wrap it in a
try/except and never let it block the core analysis pipeline.
"""
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.models import Email, PhishDNA
from backend.app.engines.phishdna_engine import calculate_phishdna_similarity
from backend.app.providers.llm_provider import analyze_email_similarity_with_llm

# How many of the closest prior emails (by cheap deterministic PhishDNA
# pre-filter) get escalated to the more expensive LLM comparison. Keeps
# LLM spend bounded as the evidence corpus grows.
MAX_LLM_CANDIDATES = 3

# Only bother the LLM with candidates that already show at least some
# deterministic resemblance -- comparing against completely unrelated
# emails wastes a call and adds noise to the campaign timeline.
MIN_PREFILTER_SIMILARITY = 20.0


def _build_email_context(email: Email, phishdna_data: Dict[str, Any]) -> Dict[str, Any]:
    url_dna = phishdna_data.get("url_dna") or {}
    content_dna = phishdna_data.get("content_dna") or {}
    return {
        "evidence_id": email.evidence.evidence_id if email.evidence else email.id,
        "subject": email.subject,
        "from_name": email.from_name,
        "from_address": email.from_address,
        "from_domain": email.from_domain,
        "reply_to": email.reply_to,
        "domains": url_dna.get("domains", []),
        "intent": content_dna.get("intent"),
        "body_text": email.body_text or "",
    }


def _dna_dict_for(dna: Optional[PhishDNA]) -> Dict[str, Any]:
    if not dna:
        return {}
    return {
        "header_dna": dna.header_dna or {},
        "identity_auth_dna": dna.identity_auth_dna or {},
        "content_dna": dna.content_dna or {},
        "url_dna": dna.url_dna or {},
        "infrastructure_dna": dna.infrastructure_dna or {},
        "behavioral_dna": dna.behavioral_dna or {},
        "normalized_features": dna.normalized_features or {},
    }


def run_llm_campaign_similarity_analysis(
    db: Session,
    current_email: Email,
    current_phishdna_data: Dict[str, Any],
    campaign_id: Optional[str]
) -> List[Dict[str, Any]]:
    """
    Automatically compares `current_email` (the email that was just
    uploaded and analyzed) against previously analyzed emails using the
    LLM, and returns a list of structured assessment dicts ready to be
    persisted as CampaignEvolutionEvent rows by the caller.

    Returns an empty list (never raises) if the LLM is disabled, there
    are no prior emails to compare against, or the LLM call fails --
    this must never be allowed to break the core analysis pipeline.
    """
    if not settings.ENABLE_LLM or not settings.GEMINI_API_KEY:
        return []

    prior_emails: List[Email] = (
        db.query(Email)
        .filter(Email.id != current_email.id)
        .filter(Email.analysis_run.has())
        .order_by(Email.created_at.desc())
        .limit(200)  # bounded scan window; cheap pre-filter narrows further
        .all()
    )
    if not prior_emails:
        return []

    # Cheap deterministic pre-filter so we only spend LLM calls on emails
    # that already show some resemblance.
    scored: List[tuple] = []
    for prior in prior_emails:
        prior_dna = prior.analysis_run.phishdna if prior.analysis_run else None
        if not prior_dna:
            continue
        prior_dna_dict = _dna_dict_for(prior_dna)
        sim = calculate_phishdna_similarity(current_phishdna_data, prior_dna_dict)
        if sim >= MIN_PREFILTER_SIMILARITY:
            scored.append((sim, prior, prior_dna_dict))

    if not scored:
        return []

    scored.sort(key=lambda t: t[0], reverse=True)
    top_candidates = scored[:MAX_LLM_CANDIDATES]

    current_ctx = _build_email_context(current_email, current_phishdna_data)

    assessments: List[Dict[str, Any]] = []
    for prefilter_sim, prior_email, prior_dna_dict in top_candidates:
        try:
            prior_ctx = _build_email_context(prior_email, prior_dna_dict)
            result = analyze_email_similarity_with_llm(current_ctx, prior_ctx)
        except Exception as e:
            result = None

        if not result or result.get("status") != "SUCCESS":
            continue

        assessments.append({
            "compared_email_id": prior_email.id,
            "compared_evidence_id": prior_ctx["evidence_id"],
            "prefilter_similarity": round(prefilter_sim, 1),
            "llm_result": result,
        })

    return assessments

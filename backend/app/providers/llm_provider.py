import json
import re
from typing import Dict, Any, Optional
from backend.app.core.config import settings
from backend.app.privacy.masker import mask_indian_pii, sanitize_url_query

def mask_pii_for_external_analysis(text: str) -> str:
    """
    Problem 16: this is "Basic PII pattern masking" -- an honest label, not
    a claim of comprehensive redaction. It catches structured identifiers
    via regex (card numbers, phone numbers, SSN-like patterns, email
    addresses, long account/ID-like digit sequences).

    It deliberately does NOT attempt to detect names or physical addresses:
    reliably finding those requires named-entity recognition (NER), and
    regex patterns for "looks like a person's name" produce so many false
    positives/negatives that shipping it would be worse than not claiming
    it at all. A masking feature that silently misses most real names is
    more dangerous than one that's upfront about only covering structured
    patterns. If full name/address redaction is required, that needs a
    proper NER-based redaction service, not string patterns.
    """
    if not text:
        return ""
    # B22: Delegate to comprehensive Indian-context masker
    masked = mask_indian_pii(text)
    # Additional non-Indian patterns
    masked = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[REDACTED_SSN]', masked)
    return masked

def analyze_email_similarity_with_llm(
    email_a_ctx: Dict[str, Any],
    email_b_ctx: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """
    Backend-only Campaign Intelligence helper (not exposed as its own
    frontend feature). This is a *semantic, LLM-driven* companion to the
    deterministic PhishDNA comparison already performed by
    campaign_service.compare_emails_what_changed(): instead of comparing
    normalized feature vectors, it asks the model to read two emails the
    way an analyst would and judge whether they look like the same
    campaign, using the exact same evidence categories the deterministic
    "What Changed?" engine already reports on (so results stay consistent
    with the rest of Campaign Intelligence / Variant Comparison):

      - Attack Intent
      - Impersonation Target
      - Social Engineering Strategy
      - Requested Action / Call-to-Action
      - Sender Mailbox / Sender Domain / Subject Line / Landing Domains /
        Reply-To routing (candidate surface mutations)

    Runs automatically as part of the analysis pipeline in
    detection_service.py; there is no dedicated API route for it and no
    frontend surface -- results are written into the campaign's evolution
    timeline (CampaignEvolutionEvent) where they show up naturally
    alongside the rest of Campaign Intelligence.
    """
    if not settings.ENABLE_LLM or not settings.GEMINI_API_KEY:
        return None

    def _fmt(ctx: Dict[str, Any]) -> str:
        safe_body = mask_pii_for_external_analysis((ctx.get("body_text") or "")[:1200]) if settings.ENABLE_PII_MASKING else (ctx.get("body_text") or "")[:1200]
        return (
            f'Evidence ID: {ctx.get("evidence_id")}\n'
            f'Subject: {ctx.get("subject")}\n'
            f'From: "{ctx.get("from_name")}" <{ctx.get("from_address")}>\n'
            f'Sender Domain: {ctx.get("from_domain")}\n'
            f'Reply-To: {ctx.get("reply_to")}\n'
            f'Landing / Linked Domains: {json.dumps(ctx.get("domains") or [])}\n'
            f'Detected Intent: {ctx.get("intent")}\n'
            f'Body snippet:\n{safe_body}'
        )

    try:
        import google.generativeai as genai
        genai.configure(api_key=settings.GEMINI_API_KEY)
        model = genai.GenerativeModel(settings.LLM_MODEL)

        prompt = f"""
You are an expert digital forensics email analyst performing campaign
correlation. Compare EMAIL A (a newly ingested message) against EMAIL B
(a previously analyzed message already on file) and judge whether they
plausibly belong to the same phishing/attack campaign, even if surface
details (sender address, domain, subject wording, landing URL) were
deliberately varied by the attacker to evade detection.

Return ONLY a valid JSON object strictly matching this schema, with no
markdown decoration:

{{
  "similarity_score": 0 to 100,
  "same_campaign_likely": true | false,
  "confidence": 0.0 to 1.0,
  "retained_invariants": {{
    "attack_intent_matches": true | false,
    "impersonation_target_matches": true | false,
    "social_engineering_strategy_matches": true | false,
    "requested_action_matches": true | false
  }},
  "mutated_surface_features": {{
    "sender_mailbox_changed": true | false,
    "sender_domain_changed": true | false,
    "subject_line_changed": true | false,
    "landing_domains_changed": true | false,
    "reply_to_changed": true | false
  }},
  "narrative": "one or two sentence forensic explanation of the relationship"
}}

EMAIL A:
{_fmt(email_a_ctx)}

EMAIL B:
{_fmt(email_b_ctx)}
"""
        response = model.generate_content(prompt)
        text = response.text.strip()
        if text.startswith("```json"):
            text = text[7:]
        if text.endswith("```"):
            text = text[:-3]
        data = json.loads(text.strip())
        data["provider"] = "google_gemini"
        data["model"] = settings.LLM_MODEL
        data["status"] = "SUCCESS"
        return data
    except Exception as e:
        return {
            "provider": "google_gemini",
            "model": settings.LLM_MODEL,
            "similarity_score": None,
            "same_campaign_likely": None,
            "confidence": 0.0,
            "retained_invariants": {},
            "mutated_surface_features": {},
            "narrative": f"LLM similarity analysis skipped: {str(e)}",
            "status": "FAILED"
        }


def analyze_with_llm(
    subject: str,
    from_name: str,
    from_address: str,
    body_text: str,
    urls: list
) -> Optional[Dict[str, Any]]:
    if not settings.ENABLE_LLM or not settings.GEMINI_API_KEY:
        return None

    try:
        import google.generativeai as genai
        genai.configure(api_key=settings.GEMINI_API_KEY)
        model = genai.GenerativeModel(settings.LLM_MODEL)

        # B22: Delimit input size to prevent prompt injection via oversized bodies
        MAX_LLM_INPUT_CHARS = 2000
        safe_body = mask_pii_for_external_analysis(body_text[:MAX_LLM_INPUT_CHARS]) if settings.ENABLE_PII_MASKING else body_text[:MAX_LLM_INPUT_CHARS]

        prompt = f"""
You are an expert digital forensics email analyst. Analyze this email metadata and content.
Extract structured semantic phishing indicators and social engineering tactics.
Return ONLY a valid JSON object strictly matching this schema with no markdown decoration:

{{
  "intent_categories": ["string"],
  "impersonation_target": "string or null",
  "urgency_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "social_engineering_strategy": "string",
  "requested_action": "string",
  "social_engineering_indicators": ["string"],
  "semantic_risk": 0 to 100,
  "confidence": 0.0 to 1.0,
  "explanation": ["string"]
}}

EMAIL METADATA & CONTENT (Basic PII Pattern Masking Applied -- see mask_pii_for_external_analysis):
From: "{from_name}" <{from_address}>
Subject: {subject}
URLs Found: {json.dumps(urls)}
Body snippet:
{safe_body}
"""
        response = model.generate_content(prompt)
        text = response.text.strip()
        if text.startswith("```json"):
            text = text[7:]
        if text.endswith("```"):
            text = text[:-3]
        data = json.loads(text.strip())
        data["provider"] = "google_gemini"
        data["model"] = settings.LLM_MODEL
        data["prompt_version"] = "2.0.0"
        data["status"] = "SUCCESS"
        return data
    except Exception as e:
        return {
            "provider": "google_gemini",
            "model": settings.LLM_MODEL,
            "prompt_version": "2.0.0",
            "intent_categories": [],
            "impersonation_target": None,
            "urgency_level": "UNKNOWN",
            "social_engineering_strategy": "UNKNOWN",
            "requested_action": "UNKNOWN",
            "social_engineering_indicators": [],
            "semantic_risk": None,
            "confidence": 0.0,
            "explanation": [f"LLM analysis skipped: {str(e)}"],
            "status": "FAILED"
        }

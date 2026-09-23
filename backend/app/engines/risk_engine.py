from typing import List, Dict, Any, Tuple
from backend.app.core.risk_config import RISK_WEIGHTS, POSITIVE_MITIGATIONS

CATEGORIES = [
    "IDENTITY",
    "AUTHENTICATION",
    "DOMAIN_URL",
    "INTENT",
    "ATTACHMENT",
    "INFRASTRUCTURE",
    "INTEL"
]

def calculate_risk(
    findings: List[Dict[str, Any]],
    auth_summary: Dict[str, Any],
    signals: Dict[str, Any]
) -> Tuple[float, str, Dict[str, Any], List[Dict[str, Any]], str, float]:
    """
    B12 & B13: Saturating categorical risk scoring and five-class verdict derivation.
    Groups findings by category, takes intra-category maximum, and combines across
    independent categories via saturating noisy-OR formula.
    Returns (final_score, band, signal_snapshot, recommended_actions, verdict, corroboration_level).
    """
    category_findings: Dict[str, List[Dict[str, Any]]] = {cat: [] for cat in CATEGORIES}
    positive_signals = []
    negative_signals = []

    for finding in findings:
        cat = finding.get("category", "DOMAIN_URL")
        # Map legacy categories if needed
        if cat in ("DOMAIN", "URL"):
            cat = "DOMAIN_URL"
        elif cat not in CATEGORIES:
            cat = "DOMAIN_URL"

        code = finding.get("code", "UNKNOWN")
        config_entry = RISK_WEIGHTS.get(code)
        weight = float(finding.get("risk_contribution") or (config_entry["weight"] if config_entry else 0.0))
        severity = finding.get("severity", config_entry["severity"] if config_entry else "INFO")

        if weight > 0:
            item = {
                "category": cat,
                "code": code,
                "title": finding.get("title"),
                "weight": weight,
                "severity": severity,
                "rationale": config_entry.get("rationale") if config_entry else finding.get("description", "")
            }
            category_findings[cat].append(item)
            positive_signals.append(item)

    # Intra-category scoring:
    # 1. Deduplicate by finding code (max weight per unique code in category)
    # 2. Combine distinct codes within the category via Noisy-OR
    category_scores: Dict[str, float] = {}
    for cat, items in category_findings.items():
        if items:
            code_weights: Dict[str, float] = {}
            for item in items:
                c = item["code"]
                code_weights[c] = max(code_weights.get(c, 0.0), item["weight"])
            
            prob_cat = 1.0
            for w in code_weights.values():
                prob_cat *= (1.0 - min(w, 100.0) / 100.0)
            category_scores[cat] = round((1.0 - prob_cat) * 100.0, 4)

    # Inter-category saturating combination (Noisy-OR: 1 - Prod(1 - cat_score / 100))
    if category_scores:
        prob_prod = 1.0
        for cat, c_score in category_scores.items():
            prob_prod *= (1.0 - min(c_score, 100.0) / 100.0)
        base_score = (1.0 - prob_prod) * 100.0

        # Corroboration multiplier: if multiple independent categories detect significant threats (>= 15.0),
        # scale the score up to reflect corroborating evidence across vectors
        significant_cats = [c for c, s in category_scores.items() if s >= 15.0]
        if len(significant_cats) > 1:
            multiplier = 1.0 + 0.15 * (len(significant_cats) - 1)
            raw_score = min(100.0, base_score * multiplier)
        else:
            raw_score = base_score
    else:
        raw_score = 0.0

    # Clean authentication mitigation rule: If email has no high/critical findings and clean auth
    has_severe_findings = any(s["severity"] in ["HIGH", "CRITICAL"] for s in positive_signals)
    if auth_summary.get("all_passed") and not has_severe_findings:
        mitigation = POSITIVE_MITIGATIONS.get("AUTH_CLEAN_ALL_PASS", {"weight": -15.0, "rationale": "Clean authenticated origin"})
        raw_score = max(0.0, raw_score + mitigation["weight"])
        negative_signals.append({
            "category": "AUTHENTICATION",
            "code": "AUTH_CLEAN_ALL_PASS",
            "title": "Full Authentication Alignment (SPF, DKIM, DMARC)",
            "weight": mitigation["weight"],
            "severity": "INFO",
            "rationale": mitigation["rationale"]
        })

    final_score = max(0.0, min(100.0, round(raw_score, 1)))

    if final_score < 25.0:
        band = "LOW"
    elif final_score < 50.0:
        band = "MEDIUM"
    elif final_score < 75.0:
        band = "HIGH"
    else:
        band = "CRITICAL"

    # Compute honest corroboration level (number of independent corroborating categories)
    active_corroborating_cats = [c for c, w in category_scores.items() if w >= 15.0]
    corroboration_level = min(1.0, round(len(active_corroborating_cats) / 3.0, 2)) if active_corroborating_cats else 0.0

    # B13: 5-Class Verdict Derivation
    finding_codes = {f.get("code") for f in findings}
    if final_score < 15.0 or (auth_summary.get("all_passed") and len(findings) == 0):
        verdict = "LEGITIMATE"
    elif "INTENT_PAYMENT_REDIRECTION" in finding_codes or "INTENT_INVOICE_FRAUD" in finding_codes:
        verdict = "FRAUD"
    elif (
        "INTENT_CREDENTIAL_HARVESTING" in finding_codes
        or "INTENT_PASSWORD_MFA_MANIPULATION" in finding_codes
        or "LOOKALIKE_HOMOGLYPH_DOMAIN" in finding_codes
        or "DIRECT_IP_URL_DESTINATION" in finding_codes
        or "EXECUTABLE_ATTACHMENT" in finding_codes
        or "MAGIC_BYTE_MISMATCH" in finding_codes
        or "DOUBLE_EXTENSION_ATTACHMENT" in finding_codes
        or signals.get("lookalike_url")
    ):
        verdict = "PHISHING"
    elif "DISPLAY_NAME_SPOOFING" in finding_codes or "EXECUTIVE_IMPERSONATION_LURE" in finding_codes or signals.get("display_name_spoofing"):
        verdict = "IMPERSONATED"
    else:
        verdict = "SUSPICIOUS"

    signal_snapshot = {
        "final_score": final_score,
        "band": band,
        "verdict": verdict,
        "corroboration_level": corroboration_level,
        "evidence_count": len(positive_signals),
        "corroborating_categories_count": len(active_corroborating_cats),
        "category_breakdown": category_scores,
        "scoring_methodology": "Explainable Categorical Saturating Risk Scoring (SIH PS-26106)",
        "methodology_disclaimer": "Score computed via category max-pooling and noisy-OR combination; heuristic prioritization, not calibrated statistical probability.",
        "positive_signals": positive_signals,
        "negative_signals": negative_signals,
        "total_positive_weight": sum(s["weight"] for s in positive_signals),
        "auth_status": auth_summary
    }

    # Generate recommended defensive actions
    recommended_actions = generate_recommended_actions(final_score, band, findings, signals)

    return final_score, band, signal_snapshot, recommended_actions, verdict, corroboration_level

def generate_recommended_actions(
    score: float,
    band: str,
    findings: List[Dict[str, Any]],
    signals: Dict[str, Any]
) -> List[Dict[str, Any]]:
    actions = []

    if band in ["CRITICAL", "HIGH"]:
        actions.append({
            "priority": "HIGH",
            "action_code": "RECOMMEND_QUARANTINE",
            "title": "Recommend Quarantine & Sender Domain Restriction",
            "explanation": "CyberSentry analyzed this message in isolation. Recommend the mail administrator isolate the message across mailboxes via the mail gateway.",
            "evidence_refs": ["RISK_SCORE", band]
        })

        if signals.get("lookalike_url") or any(f.get("category") in ("DOMAIN", "DOMAIN_URL") for f in findings):
            actions.append({
                "priority": "HIGH",
                "action_code": "RECOMMEND_BLOCKLIST_DOMAIN_URL",
                "title": "Recommend Perimeter Blocking of Phishing Domains/URLs",
                "explanation": "Push detected landing hosts and lookalike domains to Secure Web Gateway (SWG) and DNS policy blocklists.",
                "evidence_refs": ["LOOKALIKE_DOMAIN"]
            })

        if signals.get("executive_lure") or any(f.get("code") == "INTENT_PAYMENT_REDIRECTION" for f in findings):
            actions.append({
                "priority": "HIGH",
                "action_code": "RECOMMEND_OUT_OF_BAND_VERIFICATION",
                "title": "Recommend Out-of-Band Payment & Authorization Verification",
                "explanation": "Contact the purported executive/vendor through a verified primary voice directory before approving financial disbursement.",
                "evidence_refs": ["PAYMENT_FRAUD_LURE"]
            })

        if any("CREDENTIAL" in f.get("code", "") for f in findings):
            actions.append({
                "priority": "MEDIUM",
                "action_code": "RECOMMEND_CREDENTIAL_AUDIT",
                "title": "Recommend Recipient Credential Audit & Session Invalidation",
                "explanation": "If recipient interacted with this message, trigger an immediate password reset and invalidate active SSO tokens.",
                "evidence_refs": ["CREDENTIAL_HARVESTING"]
            })
    elif band == "MEDIUM":
        actions.append({
            "priority": "MEDIUM",
            "action_code": "RECOMMEND_ANALYST_TRIAGE",
            "title": "Recommend In-Depth Manual Analyst Triage",
            "explanation": "Review sender routing and message intent before releasing to recipient.",
            "evidence_refs": ["MEDIUM_RISK"]
        })
    else:
        actions.append({
            "priority": "LOW",
            "action_code": "NO_HIGH_PRIORITY_ESCALATION",
            "title": "No High-Priority Hostile Indicators Detected",
            "explanation": "No immediate escalation recommended based on current forensic indicators.",
            "evidence_refs": ["LOW_RISK"]
        })

    return actions

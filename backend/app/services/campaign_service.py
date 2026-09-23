from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from backend.app.models import Email, Campaign, CampaignMember
from backend.app.engines.phishdna_engine import calculate_phishdna_similarity

def compare_emails_what_changed(
    db: Session,
    email_id_a: str,
    email_id_b: str
) -> Dict[str, Any]:
    email_a = db.query(Email).filter(Email.id == email_id_a).first()
    email_b = db.query(Email).filter(Email.id == email_id_b).first()

    if not email_a or not email_b:
        raise ValueError("One or both email IDs were not found.")

    dna_a = email_a.analysis_run.phishdna if email_a.analysis_run else None
    dna_b = email_b.analysis_run.phishdna if email_b.analysis_run else None

    # Problem 5 fix: normalized_features (the 32-dim semantic vector) MUST be
    # included here, or calculate_phishdna_similarity_detailed() can't find it
    # under dna.get("normalized_features") and silently drops down to a much
    # weaker "do the two discrete intents match" fallback instead of the real
    # cosine-similarity comparison. Same PhishDNA representation in, same
    # representation out — no partial views of the same object.
    dna_dict_a = {
        "header_dna": dna_a.header_dna if dna_a else {},
        "identity_auth_dna": dna_a.identity_auth_dna if dna_a else {},
        "content_dna": dna_a.content_dna if dna_a else {},
        "url_dna": dna_a.url_dna if dna_a else {},
        "infrastructure_dna": dna_a.infrastructure_dna if dna_a else {},
        "behavioral_dna": dna_a.behavioral_dna if dna_a else {},
        "normalized_features": dna_a.normalized_features if (dna_a and dna_a.normalized_features) else {}
    }

    dna_dict_b = {
        "header_dna": dna_b.header_dna if dna_b else {},
        "identity_auth_dna": dna_b.identity_auth_dna if dna_b else {},
        "content_dna": dna_b.content_dna if dna_b else {},
        "url_dna": dna_b.url_dna if dna_b else {},
        "infrastructure_dna": dna_b.infrastructure_dna if dna_b else {},
        "behavioral_dna": dna_b.behavioral_dna if dna_b else {},
        "normalized_features": dna_b.normalized_features if (dna_b and dna_b.normalized_features) else {}
    }

    similarity = calculate_phishdna_similarity(dna_dict_a, dna_dict_b) if (dna_a and dna_b) else 0.0

    # Differences
    differences = {
        "sender_changed": email_a.from_address != email_b.from_address,
        "from_a": email_a.from_address,
        "from_b": email_b.from_address,
        "subject_a": email_a.subject,
        "subject_b": email_b.subject,
        "domain_changed": email_a.from_domain != email_b.from_domain,
        "domain_a": email_a.from_domain,
        "domain_b": email_b.from_domain,
        "reply_to_changed": email_a.reply_to != email_b.reply_to,
        "reply_to_a": email_a.reply_to,
        "reply_to_b": email_b.reply_to,
        "intent_a": dna_dict_a.get("content_dna", {}).get("intent"),
        "intent_b": dna_dict_b.get("content_dna", {}).get("intent")
    }

    # Shared indicators
    domains_a = set(dna_dict_a.get("url_dna", {}).get("domains", []))
    domains_b = set(dna_dict_b.get("url_dna", {}).get("domains", []))
    shared_domains = list(domains_a & domains_b)

    ips_a = set(dna_dict_a.get("infrastructure_dna", {}).get("origin_ips", []))
    ips_b = set(dna_dict_b.get("infrastructure_dna", {}).get("origin_ips", []))
    shared_ips = list(ips_a & ips_b)

    shared_indicators = []
    for d in shared_domains:
        shared_indicators.append({"type": "DOMAIN", "value": d})
    for ip in shared_ips:
        shared_indicators.append({"type": "IP", "value": ip})
    if differences["intent_a"] == differences["intent_b"] and differences["intent_a"]:
        shared_indicators.append({"type": "INTENT", "value": differences["intent_a"]})

    campaign_rel = "Uncorrelated / Low Similarity"
    if similarity >= 75.0:
        campaign_rel = "High Confidence Campaign Cluster (Polymorphic Variant)"
    elif similarity >= 45.0:
        campaign_rel = "Probable Related Campaign Activity"

    norm_a = dna_a.normalized_features if (dna_a and hasattr(dna_a, "normalized_features") and dna_a.normalized_features) else {}
    norm_b = dna_b.normalized_features if (dna_b and hasattr(dna_b, "normalized_features") and dna_b.normalized_features) else {}

    # Build contextual interpretations for surface mutations (Problem 15)
    mutated_surface_features = [
        {
            "feature": "Sender Mailbox",
            "changed": email_a.from_address != email_b.from_address,
            "variant_a": email_a.from_address or "None",
            "variant_b": email_b.from_address or "None",
            "interpretation": (
                "Sender identity rotated across variants to evade per-mailbox blocklists while preserving attack lure."
                if email_a.from_address != email_b.from_address
                else "Sender mailbox identical across variants."
            )
        },
        {
            "feature": "Sender Domain",
            "changed": email_a.from_domain != email_b.from_domain,
            "variant_a": email_a.from_domain or "None",
            "variant_b": email_b.from_domain or "None",
            "interpretation": (
                f"Domain mutated from '{email_a.from_domain}' to '{email_b.from_domain}' to bypass domain reputation filters."
                if email_a.from_domain != email_b.from_domain
                else "Sender domain identical across variants."
            )
        },
        {
            "feature": "Subject Line",
            "changed": email_a.subject != email_b.subject,
            "variant_a": email_a.subject or "No Subject",
            "variant_b": email_b.subject or "No Subject",
            "interpretation": (
                "Subject wording varied to defeat static string matching while maintaining identical urgency lure."
                if email_a.subject != email_b.subject
                else "Subject line unmodified across variants."
            )
        },
        {
            "feature": "Landing Domains / URLs",
            "changed": domains_a != domains_b,
            "variant_a": ", ".join(sorted(domains_a)) if domains_a else "None",
            "variant_b": ", ".join(sorted(domains_b)) if domains_b else "None",
            "interpretation": (
                "Landing host rotated across candidate phishing infrastructure while retaining credential-harvesting call-to-action."
                if domains_a != domains_b
                else "Landing domains identical across variants."
            )
        },
        {
            "feature": "Reply-To Redirection",
            "changed": email_a.reply_to != email_b.reply_to,
            "variant_a": email_a.reply_to or "None",
            "variant_b": email_b.reply_to or "None",
            "interpretation": (
                "Reply-to routing modified to redirect victim replies or exfiltrate responses out-of-band."
                if email_a.reply_to != email_b.reply_to
                else "Reply-to routing unmodified across variants."
            )
        }
    ]

    # Problem 7: Strictly separate Attack Invariants (Semantic) from Infrastructure Relationships (Network/Hosting)
    intent_val_a = norm_a.get("semantic_intent") or differences["intent_a"] or "CREDENTIAL_HARVESTING"
    target_val_a = norm_a.get("impersonation_target") or "Target Organization"
    strat_val_a = norm_a.get("social_engineering_strategy") or "Urgency / Coercion"
    action_val_a = norm_a.get("requested_action") or "Credential Verification"

    intent_val_b = norm_b.get("semantic_intent") or differences["intent_b"] or "CREDENTIAL_HARVESTING"
    target_val_b = norm_b.get("impersonation_target") or "Target Organization"
    strat_val_b = norm_b.get("social_engineering_strategy") or "Urgency / Coercion"
    action_val_b = norm_b.get("requested_action") or "Credential Verification"

    retained_attack_invariants = [
        {
            "invariant": "Attack Intent",
            "retained": intent_val_a == intent_val_b,
            "value": intent_val_a.replace("_", " ").title(),
            "category": "SEMANTIC_INTENT"
        },
        {
            "invariant": "Impersonation Target",
            "retained": target_val_a == target_val_b,
            "value": target_val_a,
            "category": "TARGET_BRAND"
        },
        {
            "invariant": "Social Engineering Strategy",
            "retained": strat_val_a == strat_val_b,
            "value": strat_val_a.replace("_", " ").title(),
            "category": "BEHAVIORAL_STRATEGY"
        },
        {
            "invariant": "Requested Action / Call-to-Action",
            "retained": action_val_a == action_val_b,
            "value": action_val_a.replace("_", " ").title(),
            "category": "CALL_TO_ACTION"
        }
    ]

    # Infrastructure relationships
    from backend.app.engines.phishdna_engine import extract_subnet_24
    subnets_a = set([extract_subnet_24(ip) for ip in ips_a if ip])
    subnets_b = set([extract_subnet_24(ip) for ip in ips_b if ip])
    shared_subnets = list(subnets_a & subnets_b)

    infrastructure_relationships = [
        {
            "relationship_type": "Origin Infrastructure IP",
            "matched": bool(shared_ips),
            "evidence": f"Shared IP: {', '.join(shared_ips)}" if shared_ips else "Disjoint Origin IPs",
            "strength": "STRONG" if shared_ips else "NONE"
        },
        {
            "relationship_type": "Network /24 Subnet Segment",
            "matched": bool(shared_subnets),
            "evidence": f"Shared /24 Subnet: {', '.join(shared_subnets)}.0/24" if shared_subnets else "Disjoint /24 Subnets",
            "strength": "STRONG" if shared_subnets else "NONE"
        },
        {
            "relationship_type": "Shared Landing Host / Domain",
            "matched": bool(shared_domains),
            "evidence": f"Shared Host: {', '.join(shared_domains)}" if shared_domains else "Disjoint Landing Hosts",
            "strength": "STRONG" if shared_domains else "NONE"
        },
        {
            "relationship_type": "Sender Domain Infrastructure",
            "matched": email_a.from_domain == email_b.from_domain,
            "evidence": f"Domain: {email_a.from_domain}" if email_a.from_domain == email_b.from_domain else f"{email_a.from_domain} vs {email_b.from_domain}",
            "strength": "STRONG" if email_a.from_domain == email_b.from_domain else "DISJOINT"
        }
    ]

    rel_score = int(round(similarity))
    rel_strength_label = "HIGH" if similarity >= 75.0 else ("MODERATE" if similarity >= 45.0 else "LOW")
    relationship_strength = f"{rel_score}/100 ({rel_strength_label})"

    return {
        "email_a": {
            "id": email_a.id,
            "evidence_id": email_a.evidence.evidence_id if email_a.evidence else "",
            "subject": email_a.subject,
            "sender": email_a.from_address,
            "score": float(email_a.analysis_run.risk_score.score) if (email_a.analysis_run and email_a.analysis_run.risk_score) else 0.0,
            "band": email_a.analysis_run.risk_score.band if (email_a.analysis_run and email_a.analysis_run.risk_score) else "UNKNOWN"
        },
        "email_b": {
            "id": email_b.id,
            "evidence_id": email_b.evidence.evidence_id if email_b.evidence else "",
            "subject": email_b.subject,
            "sender": email_b.from_address,
            "score": float(email_b.analysis_run.risk_score.score) if (email_b.analysis_run and email_b.analysis_run.risk_score) else 0.0,
            "band": email_b.analysis_run.risk_score.band if (email_b.analysis_run and email_b.analysis_run.risk_score) else "UNKNOWN"
        },
        "similarity_score": round(similarity, 1),
        "campaign_relationship": campaign_rel,
        "relationship_strength": relationship_strength,
        "differences": differences,
        "shared_indicators": shared_indicators,
        "mutated_surface_features": mutated_surface_features,
        "retained_attack_invariants": retained_attack_invariants,
        "infrastructure_relationships": infrastructure_relationships,
        "phishdna_comparison": {
            "dna_a_fingerprint": dna_a.fingerprint if dna_a else "N/A",
            "dna_b_fingerprint": dna_b.fingerprint if dna_b else "N/A",
            "html_structure_match": dna_dict_a.get("content_dna", {}).get("html_structure_hash") == dna_dict_b.get("content_dna", {}).get("html_structure_hash")
        }
    }

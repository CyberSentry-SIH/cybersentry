from typing import Dict, Any, List, Optional
import uuid

def correlate_campaign(
    current_email_id: str,
    current_evidence_id: str,
    current_analysis_id: str,
    current_phishdna: Dict[str, Any],
    current_risk_score: float,
    current_intent: str,
    existing_campaigns: List[Dict[str, Any]],
    all_analyzed_emails: List[Dict[str, Any]]
) -> Optional[Dict[str, Any]]:
    """
    Evidence-Based Campaign Correlation Engine
    -------------------------------------------
    Correlates newly ingested email payloads with existing threat campaigns using
    multi-family evidence corroboration:
    1. Semantic Intent & Lure Tactics (Normalized Feature Vector Cosine Similarity)
    2. URL & Landing Domain Structure
    3. Infrastructure & Network /24 Subnet (Supporting/Corroborating Evidence)
    4. HTML DOM Structural Layout

    State Lifecycle (Campaign Activity State):
    - CANDIDATE: Initial malicious payload anchor established baseline.
    - EMERGING: First polymorphic variant / related infrastructure corroborated (2 members).
    - ACTIVE: Sustained campaign activity across corroborated infrastructure.
    - EXPANDING: Active evolution with new mutated domains, sending IPs, or diverse lures.
    """
    best_campaign = None
    best_similarity = 0.0
    matching_reasons = []

    current_domains = set(
        current_phishdna.get("exact_features", {}).get("exact_canonical_hosts") or
        current_phishdna.get("url_dna", {}).get("domains", [])
    )
    current_ips = set(
        current_phishdna.get("exact_features", {}).get("exact_origin_ips") or
        current_phishdna.get("infrastructure_dna", {}).get("origin_ips", [])
    )
    current_sender_domain = (
        current_phishdna.get("exact_features", {}).get("exact_sender_domain") or
        current_phishdna.get("header_dna", {}).get("sender_domain", "")
    )

    # Compare against existing campaigns and their members
    for camp in existing_campaigns:
        camp_score = 0.0
        reasons = []
        triggered_families = set()

        # 1. Intent match
        if camp.get("primary_intent") == current_intent and current_intent != "BENIGN_COMMUNICATION":
            camp_score += 25.0
            reasons.append(f"Matching attack intent: {current_intent.replace('_', ' ').title()}")
            triggered_families.add("SEMANTIC_INTENT")

        # 2. Shared landing domains
        camp_domains = set(camp.get("shared_domains", []))
        common_domains = current_domains & camp_domains
        if common_domains:
            camp_score += 25.0
            reasons.append(f"Shared landing domains ({', '.join(common_domains)})")
            triggered_families.add("URL_DOMAIN_INFRASTRUCTURE")

        # 3. Shared infrastructure IPs (Corroborating evidence)
        camp_ips = set(camp.get("shared_ips", []))
        common_ips = current_ips & camp_ips
        if common_ips:
            camp_score += 20.0
            reasons.append(f"Shared infrastructure IP ({', '.join(common_ips)})")
            triggered_families.add("NETWORK_HOSTING")

        # 4. Pairwise PhishDNA similarity across campaign members
        from backend.app.engines.phishdna_engine import calculate_phishdna_similarity_detailed
        best_member_sim = 0.0
        for member in camp.get("members", []):
            m_dna = member.get("phishdna", {})
            sim, pair_reasons = calculate_phishdna_similarity_detailed(current_phishdna, m_dna)
            if sim > best_member_sim:
                best_member_sim = sim
            if sim >= 45.0:
                triggered_families.add("PHISHDNA_FEATURE_VECTOR")
                for pr in pair_reasons:
                    if pr not in reasons:
                        reasons.append(pr)

        effective_score = max(camp_score, best_member_sim)

        # Multi-family requirement: Must have score >= 50.0 AND span at least 2 distinct evidence families
        # This prevents isolated shared IPs or shared domains from gaming campaign correlation
        if effective_score >= 50.0 and len(triggered_families) >= 2 and effective_score > best_similarity:
            best_similarity = effective_score
            best_campaign = camp
            reasons.append(f"Corroborated by independent evidence families: {', '.join(sorted(triggered_families))}")
            matching_reasons = reasons

    # Case A: No existing campaign match, but email has malicious score -> Create CANDIDATE Campaign
    if not best_campaign and current_risk_score >= 50.0 and current_intent != "BENIGN_COMMUNICATION":
        new_key = f"CAMP-{uuid.uuid4().hex[:8].upper()}"
        camp_name = f"Campaign Candidate: {current_intent.replace('_', ' ').title()} [{current_sender_domain or 'Multi-Source'}]"

        return {
            "is_new": True,
            "campaign_key": new_key,
            "name": camp_name,
            "primary_intent": current_intent,
            "state": "CANDIDATE",
            "risk_trend": "STABLE",
            "similarity_score": None,  # Anchor has no prior member to compare against
            "relationship_confidence": None,
            "relationship_strength": None,
            "relationship_reason": ["Initial observed campaign anchor baseline"],
            "events": [
                {
                    "event_type": "CAMPAIGN_CANDIDATE_ESTABLISHED",
                    "summary": f"Initial evidence anchor '{current_evidence_id}' established campaign candidate baseline. Awaiting polymorphic mutation.",
                    "confidence": 0.80
                }
            ]
        }

    # Case B: Correlated with existing campaign
    if best_campaign:
        prev_member_count = len(best_campaign.get("members", []))
        new_domains = current_domains - set(best_campaign.get("shared_domains", []))
        new_ips = current_ips - set(best_campaign.get("shared_ips", []))
        has_new_infra = bool(new_domains or new_ips)

        # Multidimensional Campaign Activity State evaluation
        if prev_member_count == 1:
            new_state = "EMERGING"
        elif has_new_infra and prev_member_count >= 2:
            new_state = "EXPANDING"
        elif prev_member_count >= 3:
            new_state = "ACTIVE"
        else:
            new_state = "ACTIVE"

        rel_strength_score = int(round(best_similarity))
        rel_tier = "HIGH" if best_similarity >= 75.0 else ("MODERATE" if best_similarity >= 50.0 else "WEAK")
        rel_strength_display = f"{rel_strength_score}/100 ({rel_tier})"
        calibrated_rel_confidence = round(min(0.95, max(0.65, best_similarity / 100.0)), 2)

        events = [
            {
                "event_type": "RELATED_EMAIL_OBSERVED",
                "summary": f"Correlated new email variant with {best_similarity:.1f}% PhishDNA multi-family similarity.",
                "confidence": calibrated_rel_confidence
            }
        ]

        if new_domains:
            events.append({
                "event_type": "NEW_DOMAIN_OBSERVED",
                "summary": f"Observed new campaign landing domain(s): {', '.join(new_domains)}",
                "confidence": 0.88
            })

        if new_ips:
            events.append({
                "event_type": "NEW_IP_OBSERVED",
                "summary": f"Observed new sending infrastructure IP: {', '.join(new_ips)}",
                "confidence": 0.88
            })

        if new_state != best_campaign.get("state"):
            events.append({
                "event_type": "CAMPAIGN_STATE_CHANGED",
                "summary": f"Campaign activity state escalated from {best_campaign.get('state')} to {new_state}.",
                "confidence": 0.90
            })

        return {
            "is_new": False,
            "campaign_id": best_campaign.get("id"),
            "campaign_key": best_campaign.get("campaign_key"),
            "name": best_campaign.get("name"),
            "state": new_state,
            "risk_trend": "INCREASING" if new_state == "EXPANDING" else "STABLE",
            "similarity_score": round(best_similarity, 1),
            "relationship_confidence": calibrated_rel_confidence,
            "relationship_strength": rel_strength_display,
            "relationship_reason": matching_reasons,
            "events": events
        }

    return None

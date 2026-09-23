import pytest
from backend.app.services.parser_service import parse_eml_bytes
from backend.app.engines.header_engine import analyze_headers
from backend.app.engines.url_engine import analyze_urls, evaluate_lookalike_domain
from backend.app.engines.intent_engine import analyze_intent
from backend.app.engines.phishdna_engine import generate_phishdna, calculate_phishdna_similarity_detailed, calculate_phishdna_similarity
from backend.app.engines.campaign_engine import correlate_campaign
from backend.app.engines.risk_engine import calculate_risk

def load_sample_parsed(file_path: str):
    with open(file_path, "rb") as f:
        content = f.read()
    parsed = parse_eml_bytes(content)
    header_res = analyze_headers(
        from_name=parsed.get("from_name"),
        from_address=parsed.get("from_address"),
        from_domain=parsed.get("from_domain"),
        reply_to=parsed.get("reply_to"),
        return_path=parsed.get("return_path"),
        hops=parsed.get("hops", []),
        auth_results=parsed.get("auth_results", {})
    )
    url_res = analyze_urls(parsed.get("urls", []), email_domain=parsed.get("from_domain", ""))
    intent_res = analyze_intent(parsed.get("subject", ""), parsed.get("body_text", ""), parsed.get("body_html", ""))
    
    phishdna = generate_phishdna(
        sender_domain=parsed.get("from_domain", ""),
        from_name=parsed.get("from_name", ""),
        from_address=parsed.get("from_address", ""),
        subject=parsed.get("subject", ""),
        body_text=parsed.get("body_text", ""),
        body_html=parsed.get("body_html", ""),
        urls=parsed.get("urls", []),
        hops=header_res.get("processed_hops", []),
        auth_results=parsed.get("auth_results", {}),
        attachments=parsed.get("attachments", []),
        primary_intent=intent_res.get("primary_intent", "BENIGN_COMMUNICATION"),
        semantic_profile=intent_res.get("semantic_profile", {})
    )
    
    findings = header_res.get("findings", []) + url_res.get("findings", []) + intent_res.get("findings", [])
    signals = {**header_res.get("signals", {}), **url_res.get("signals", {})}
    score, band, snapshot, recs, verdict, corr = calculate_risk(findings, header_res.get("auth_summary", {}), signals)

    return {
        "parsed": parsed,
        "header_res": header_res,
        "url_res": url_res,
        "intent_res": intent_res,
        "phishdna": phishdna,
        "risk_score": score,
        "risk_band": band,
        "verdict": verdict
    }

def test_polymorphic_variant_high_correlation():
    """
    Test Problem 1 & 11: Email A (Sample 1) ↔ Email B (Sample 2)
    Polymorphic variants must yield HIGH similarity (>75%) and correlate into the same campaign.
    """
    sample_a = load_sample_parsed("data/synthetic/sample_01_credential_phish_paypal.eml")
    sample_b = load_sample_parsed("data/synthetic/sample_02_credential_phish_paypal_variant.eml")

    sim_score, reasons = calculate_phishdna_similarity_detailed(sample_a["phishdna"], sample_b["phishdna"])
    assert sim_score >= 75.0, f"Expected high similarity between polymorphic variants, got {sim_score}"
    assert len(reasons) >= 3, f"Expected at least 3 matching reasons, got {reasons}"
    assert any("intent" in r.lower() or "host" in r.lower() or "infrastructure" in r.lower() for r in reasons)

def test_hard_negative_low_correlation():
    """
    Test Problem 11: Email A (Sample 1) ↔ Email C (Sample 6 Hard Negative)
    Legitimate internal notice containing urgency/security keywords must have LOW similarity (<20%)
    and NEVER be correlated into the malicious campaign.
    """
    sample_a = load_sample_parsed("data/synthetic/sample_01_credential_phish_paypal.eml")
    sample_c = load_sample_parsed("data/synthetic/sample_06_hard_negative_security_notice.eml")

    sim_score, reasons = calculate_phishdna_similarity_detailed(sample_a["phishdna"], sample_c["phishdna"])
    assert sim_score <= 20.0, f"Expected low similarity between phish and hard negative, got {sim_score}"

    # Verify hard negative has clean risk score
    assert sample_c["risk_band"] in ["LOW", "MEDIUM"]
    assert sample_c["risk_score"] < 30.0

def test_legitimate_invoice_zero_correlation():
    """
    Test Problem 11: Email A (Sample 1) ↔ Sample 5 (Benign Invoice)
    """
    sample_a = load_sample_parsed("data/synthetic/sample_01_credential_phish_paypal.eml")
    sample_5 = load_sample_parsed("data/synthetic/sample_05_legitimate_monthly_invoice.eml")

    sim_score, _ = calculate_phishdna_similarity_detailed(sample_a["phishdna"], sample_5["phishdna"])
    assert sim_score <= 15.0

def test_campaign_candidate_and_anchor_lifecycle():
    """
    Test Problem 4 & 6:
    First email arrives -> Creates CANDIDATE campaign with similarity_score = None (Anchor baseline).
    Second correlated email arrives -> Escalates to EMERGING/ACTIVE with similarity_score >= 75.0.
    """
    sample_a = load_sample_parsed("data/synthetic/sample_01_credential_phish_paypal.eml")
    sample_b = load_sample_parsed("data/synthetic/sample_02_credential_phish_paypal_variant.eml")

    # Step 1: Ingest Email A into empty campaign repository
    res1 = correlate_campaign(
        current_email_id="email-001",
        current_evidence_id="EV-001",
        current_analysis_id="an-001",
        current_phishdna=sample_a["phishdna"],
        current_risk_score=sample_a["risk_score"],
        current_intent=sample_a["intent_res"]["primary_intent"],
        existing_campaigns=[],
        all_analyzed_emails=[]
    )
    assert res1 is not None
    assert res1["is_new"] is True
    assert res1["state"] == "CANDIDATE"
    assert res1["similarity_score"] is None  # Anchor baseline has no similarity score!

    # Step 2: Ingest Email B against existing campaign
    existing_campaign = {
        "id": "camp-123",
        "campaign_key": res1["campaign_key"],
        "name": res1["name"],
        "primary_intent": res1["primary_intent"],
        "state": "CANDIDATE",
        "risk_trend": "STABLE",
        "members": [
            {
                "email_id": "email-001",
                "phishdna": sample_a["phishdna"]
            }
        ],
        "shared_domains": list(sample_a["phishdna"]["exact_features"]["exact_canonical_hosts"]),
        "shared_ips": list(sample_a["phishdna"]["exact_features"]["exact_origin_ips"])
    }

    res2 = correlate_campaign(
        current_email_id="email-002",
        current_evidence_id="EV-002",
        current_analysis_id="an-002",
        current_phishdna=sample_b["phishdna"],
        current_risk_score=sample_b["risk_score"],
        current_intent=sample_b["intent_res"]["primary_intent"],
        existing_campaigns=[existing_campaign],
        all_analyzed_emails=[]
    )
    assert res2 is not None
    assert res2["is_new"] is False
    assert res2["state"] in ["EMERGING", "ACTIVE"]
    assert res2["similarity_score"] is not None
    assert res2["similarity_score"] >= 75.0
    assert len(res2["relationship_reason"]) >= 2

def test_generalized_lookalike_engine():
    """
    Test Problem 9: Generalized lookalike detection with confusable replacement and Levenshtein distance.
    """
    is_look, target, reason = evaluate_lookalike_domain("paypa1-security-update.com", ["paypal.com", "microsoft.com"])
    assert is_look is True
    assert target == "paypal.com"

    is_look2, target2, reason2 = evaluate_lookalike_domain("micr0soft-portal.com", ["paypal.com", "microsoft.com"])
    assert is_look2 is True
    assert target2 == "microsoft.com"

    # Legitimate corporate subdomain must NOT be flagged as lookalike
    is_look3, _, _ = evaluate_lookalike_domain("internal.company-corp.com", ["company-corp.com"])
    assert is_look3 is False

def test_evaluation_matrix_full():
    """
    Test Problem 21: 4-Email Evaluation Matrix & Hard Negative Rejection Gate
    - Email A (Sample 1) ↔ Email B (Sample 2 Polymorphic Variant): High similarity (>75%)
    - Email A (Sample 1) ↔ Email C (Sample 3 BEC Wire Transfer): Low similarity (<35%)
    - Email A (Sample 1) ↔ Email D (Sample 5 Benign Invoice): Very low similarity (<15%)
    - Email A (Sample 1) ↔ Email E (Sample 6 Urgent Internal Security Notice): Very low similarity (<20%)
    """
    sample_a = load_sample_parsed("data/synthetic/sample_01_credential_phish_paypal.eml")
    sample_b = load_sample_parsed("data/synthetic/sample_02_credential_phish_paypal_variant.eml")
    sample_c = load_sample_parsed("data/synthetic/sample_03_bec_wire_transfer_cfo.eml")
    sample_d = load_sample_parsed("data/synthetic/sample_05_legitimate_monthly_invoice.eml")
    sample_e = load_sample_parsed("data/synthetic/sample_06_hard_negative_security_notice.eml")

    # 1. Email A ↔ Email B (Polymorphic variant)
    sim_ab, reasons_ab = calculate_phishdna_similarity_detailed(sample_a["phishdna"], sample_b["phishdna"])
    assert sim_ab >= 75.0, f"Expected high similarity between variants, got {sim_ab}"
    assert len(reasons_ab) >= 2

    # 2. Email A ↔ Email C (BEC / Different Technique)
    sim_ac, reasons_ac = calculate_phishdna_similarity_detailed(sample_a["phishdna"], sample_c["phishdna"])
    assert sim_ac <= 35.0, f"Expected low similarity between different phish types, got {sim_ac}"

    # 3. Email A ↔ Email D (Benign Invoice)
    sim_ad, _ = calculate_phishdna_similarity_detailed(sample_a["phishdna"], sample_d["phishdna"])
    assert sim_ad <= 15.0, f"Expected very low similarity between phish and invoice, got {sim_ad}"

    # 4. Email A ↔ Email E (Hard Negative: Urgent Internal Notice)
    sim_ae, _ = calculate_phishdna_similarity_detailed(sample_a["phishdna"], sample_e["phishdna"])
    assert sim_ae <= 20.0, f"Expected very low similarity between phish and hard negative, got {sim_ae}"

def test_variance_invariants_and_infrastructure_separation(db_session):
    """
    Test Problem 7 & 15: Retained Attack Invariants vs Infrastructure Relationships in Compare Service
    """
    from backend.app.models import Email
    from backend.app.services.campaign_service import compare_emails_what_changed

    emails = db_session.query(Email).all()
    if len(emails) >= 2:
        email_a = emails[0]
        email_b = emails[1]
        diff_res = compare_emails_what_changed(db_session, email_a.id, email_b.id)

        assert "retained_attack_invariants" in diff_res
        assert "infrastructure_relationships" in diff_res
        assert "mutated_surface_features" in diff_res

        # Verify mutated features contain forensic interpretations
        for m in diff_res["mutated_surface_features"]:
            assert "interpretation" in m
            assert len(m["interpretation"]) > 0

        # Verify invariants are distinct from infrastructure
        inv_keys = [i["invariant"] for i in diff_res["retained_attack_invariants"]]
        assert "Attack Intent" in inv_keys
        assert "Impersonation Target" in inv_keys

        infra_types = [inf["relationship_type"] for inf in diff_res["infrastructure_relationships"]]
        assert "Origin Infrastructure IP" in infra_types
        assert "Network /24 Subnet Segment" in infra_types

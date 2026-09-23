"""
backend/app/engines/origin_engine.py — F07: Origin Traceability & Attribution-Support Assessment

Synthesizes hop-by-hop transmission telemetry, trust boundaries, geolocation, active authentication,
and threat intelligence to assess email origin and generate attribution-support intelligence.
"""

from typing import Dict, Any, List, Optional


def assess_email_origin(
    boundary_ip: Optional[str],
    hops: List[Dict[str, Any]],
    auth_summary: Dict[str, Any],
    signals: Dict[str, Any],
    geo_snapshot: Optional[Dict[str, Any]] = None,
    infra_classification: Optional[Dict[str, Any]] = None,
    from_domain: Optional[str] = None
) -> Dict[str, Any]:
    """
    F07: Computes origin assessment, attribution verdict, confidence level, and disclaimer.
    Attribution verdicts:
    - SPOOFED_DOMAIN
    - COMPROMISED_ACCOUNT
    - ANONYMIZED_INFRA
    - DIRECT_MALICIOUS_INFRA
    - LEGITIMATE_INFRA
    - INDETERMINATE
    """
    reasoning: List[str] = []
    confidence_score = 50.0

    spf_res = (auth_summary.get("spf") or "UNKNOWN").upper()
    dkim_res = (auth_summary.get("dkim") or "UNKNOWN").upper()
    dmarc_res = (auth_summary.get("dmarc") or "UNKNOWN").upper()
    
    is_tor = bool(infra_classification and infra_classification.get("is_tor"))
    is_dc = bool(infra_classification and infra_classification.get("is_datacenter"))
    infra_cat = (infra_classification.get("category") if infra_classification else "UNKNOWN")

    is_lookalike = bool(signals.get("lookalike_domain_detected"))
    is_display_spoof = bool(signals.get("display_name_spoofed"))
    untrusted_authserv = bool(signals.get("untrusted_authserv_header"))

    # 1. Determine Attribution Verdict
    if is_tor:
        verdict = "ANONYMIZED_INFRA"
        confidence_score = 90.0
        reasoning.append(f"Connecting boundary IP {boundary_ip} verified as an active Tor anonymity exit relay.")
        reasoning.append("True origin IP is anonymized by multi-hop onion routing.")

    elif is_display_spoof or (spf_res in ("FAIL", "SOFTFAIL") and dkim_res == "FAIL" and not is_lookalike):
        verdict = "SPOOFED_DOMAIN"
        confidence_score = 85.0
        reasoning.append(f"Sender claimed identity '{from_domain}', but boundary IP {boundary_ip} failed SPF and DKIM authentication.")
        reasoning.append("Message originated outside the authorized mail infrastructure of the claimed sender domain.")

    elif is_lookalike:
        verdict = "DIRECT_MALICIOUS_INFRA"
        confidence_score = 92.0
        reasoning.append(f"Origin infrastructure registered specifically under typosquat/lookalike domain '{from_domain}'.")
        reasoning.append("Direct malicious infrastructure configured for targeted impersonation.")

    elif spf_res == "PASS" and dkim_res == "PASS" and (signals.get("credential_harvesting") or signals.get("dangerous_attachment_detected")):
        verdict = "COMPROMISED_ACCOUNT"
        confidence_score = 80.0
        reasoning.append(f"Authentication passed for authentic domain '{from_domain}', but email payload contains malicious threats.")
        reasoning.append("Indicates sender credentials or mail account were compromised to send malicious campaigns.")

    elif spf_res == "PASS" and (dkim_res == "PASS" or dmarc_res == "PASS") and not signals.get("high_risk_findings"):
        verdict = "LEGITIMATE_INFRA"
        confidence_score = 90.0
        reasoning.append(f"Email originated from authorized mail servers for '{from_domain}' with verified SPF/DKIM/DMARC.")

    else:
        verdict = "INDETERMINATE"
        confidence_score = 45.0
        reasoning.append("Telemetry insufficient to establish high-confidence attribution.")

    # 2. Extract Claimed Path vs Boundary Hop
    claimed_hops = [h.get("hop_string", "") for h in hops if h.get("trust_level") == "CLAIMED"]
    observed_hops = [h.get("hop_string", "") for h in hops if h.get("trust_level") in ("TRUSTED_GATEWAY", "OBSERVED_BY_TRUSTED_MTA")]

    return {
        "attribution_verdict": verdict,
        "confidence_score": round(min(100.0, max(10.0, confidence_score)), 1),
        "boundary_ip": boundary_ip,
        "infrastructure_category": infra_cat,
        "geolocation_origin": geo_snapshot or {},
        "reasoning": reasoning,
        "claimed_hops_count": len(claimed_hops),
        "observed_hops_count": len(observed_hops),
        "attribution_disclaimer": (
            "Origin assessment provides probabilistic forensic intelligence based on technical header structures "
            "and active DNS/IP corroboration. Legal attribution requires corroboration with ISP subpoena logs."
        )
    }

from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from sqlalchemy.orm import Session
from backend.app.models import (
    Evidence, Email, EmailRecipient, ReceivedHop, AuthenticationResult,
    Attachment, Indicator, EmailIndicator, Enrichment, AnalysisRun, Finding,
    RiskScore, LLMAnalysis, PhishDNA, Campaign, CampaignMember,
    CampaignModelSnapshot, CampaignEvolutionEvent, RecommendedAction, User
)
from backend.app.services.parser_service import parse_eml_bytes
from backend.app.services.evidence_service import append_custody_event
from backend.app.services.intel_service import lookup_indicator
from backend.app.services.graph_service import build_attack_graph_for_email
from backend.app.services.geo_service import enrich_ip_geolocation
from backend.app.services.virustotal_service import scan_url_virustotal, scan_hash_virustotal
from backend.app.providers.llm_provider import analyze_with_llm
from backend.app.engines.header_engine import analyze_headers
from backend.app.engines.url_engine import analyze_urls
from backend.app.engines.intent_engine import analyze_intent
from backend.app.engines.phishdna_engine import generate_phishdna
from backend.app.engines.risk_engine import calculate_risk
from backend.app.engines.campaign_engine import correlate_campaign
from backend.app.services.campaign_intelligence_service import run_llm_campaign_similarity_analysis

def process_email_analysis(
    db: Session,
    evidence: Evidence,
    actor_user: Optional[User] = None
) -> AnalysisRun:
    try:
        # 1. Read original bytes from evidence vault
        with open(evidence.storage_path, "rb") as f:
            file_bytes = f.read()

        # 2. Safe MIME & RFC 5322 Parsing
        parsed = parse_eml_bytes(file_bytes)

        # Create Email entity
        email_obj = Email(
            evidence_id=evidence.id,
            message_id=parsed.get("message_id"),
            subject=parsed.get("subject"),
            from_name=parsed.get("from_name"),
            from_address=parsed.get("from_address"),
            from_domain=parsed.get("from_domain"),
            reply_to=parsed.get("reply_to"),
            return_path=parsed.get("return_path"),
            sent_at=parsed.get("sent_at"),
            received_at=datetime.now(timezone.utc),
            body_text=parsed.get("body_text"),
            body_html=parsed.get("body_html"),
            parser_status=parsed.get("parser_status", "SUCCESS")
        )
        db.add(email_obj)
        db.flush()

        # B03: Record PARSED custody event
        append_custody_event(
            db=db,
            evidence=evidence,
            action="PARSED",
            actor=actor_user,
            details={
                "message_id": parsed.get("message_id"),
                "subject": parsed.get("subject"),
                "from_address": parsed.get("from_address"),
                "parser_status": parsed.get("parser_status", "SUCCESS")
            }
        )

        # Store recipients
        recipient_emails = []
        for rec in parsed.get("recipients", []):
            db.add(EmailRecipient(
                email_id=email_obj.id,
                address=rec["address"],
                recipient_type=rec["recipient_type"]
            ))
            recipient_emails.append(rec["address"])

        # 3. Pure Forensic Engines Execution
        auth_data = parsed.get("auth_results", {})
        header_res = analyze_headers(
            from_name=parsed.get("from_name"),
            from_address=parsed.get("from_address"),
            from_domain=parsed.get("from_domain"),
            reply_to=parsed.get("reply_to"),
            return_path=parsed.get("return_path"),
            hops=parsed.get("hops", []),
            auth_results=auth_data
        )

        # Store hops with evaluated trust level and geo enrichment snapshot (B05)
        hop_geo_enrichments = {}
        for h in header_res.get("processed_hops", []):
            ip = h.get("ip_address")
            geo_data = None
            if ip:
                geo_data = enrich_ip_geolocation(ip)
                hop_geo_enrichments[ip] = geo_data
            db.add(ReceivedHop(
                email_id=email_obj.id,
                hop_order=h["hop_order"],
                raw_value=h["raw_value"],
                hostname=h.get("hostname"),
                ip_address=ip,
                trust_level=h.get("trust_level", "OBSERVED_BY_TRUSTED_MTA"),
                trust_reason=h.get("trust_reason"),
                geo_snapshot=geo_data or {}
            ))

        # Store reported authentication results (MIME Authentication-Results Header)
        db.add(AuthenticationResult(
            email_id=email_obj.id,
            spf_result=auth_data.get("spf_result"),
            dkim_result=auth_data.get("dkim_result"),
            dmarc_result=auth_data.get("dmarc_result"),
            raw_header=auth_data.get("raw_header"),
            source="PARSED_HEADER"
        ))

        # Store static attachments (metadata and hash reputation analysis)
        for att in parsed.get("attachments", []):
            db.add(Attachment(
                email_id=email_obj.id,
                filename=att["filename"],
                content_type=att.get("content_type"),
                size_bytes=att["size_bytes"],
                sha256=att["sha256"],
                extension=att.get("extension"),
                static_risk=att.get("static_risk", "UNKNOWN"),
                metadata_json=att.get("metadata_json", {})
            ))

        # Create AnalysisRun
        analysis_run = AnalysisRun(
            email_id=email_obj.id,
            engine_version="1.0.0",
            status="RUNNING",
            started_at=datetime.now(timezone.utc)
        )
        db.add(analysis_run)
        db.flush()

        from backend.app.engines.attachment_engine import analyze_attachments

        attachment_res = analyze_attachments(parsed.get("attachments", []))

        url_res = analyze_urls(
            urls=parsed.get("urls", []),
            email_domain=parsed.get("from_domain", "")
        )

        intent_res = analyze_intent(
            subject=parsed.get("subject", ""),
            body_text=parsed.get("body_text", ""),
            body_html=parsed.get("body_html", "")
        )

        # 3b. Optional LLM Semantic Analysis (Non-authoritative for technical facts, authoritative for deep NLP semantics)
        llm_res = analyze_with_llm(
            subject=parsed.get("subject", ""),
            from_name=parsed.get("from_name", ""),
            from_address=parsed.get("from_address", ""),
            body_text=parsed.get("body_text", ""),
            urls=parsed.get("urls", [])
        )

        # Semantic Profile Fusion: LLM semantic output feeds into semantic profile when available
        semantic_profile = dict(intent_res.get("semantic_profile", {}))
        if llm_res and llm_res.get("status") == "SUCCESS":
            db.add(LLMAnalysis(
                analysis_id=analysis_run.id,
                provider=llm_res.get("provider", "google_gemini"),
                model=llm_res.get("model", "gemini-3.6-flash"),
                prompt_version="2.0.0",
                intent_categories=llm_res.get("intent_categories", []),
                impersonation_target=llm_res.get("impersonation_target"),
                urgency_level=llm_res.get("urgency_level"),
                social_engineering_indicators=llm_res.get("social_engineering_indicators", []),
                semantic_risk=llm_res.get("semantic_risk"),
                confidence=llm_res.get("confidence"),
                explanation=llm_res.get("explanation", []),
                status="SUCCESS"
            ))
            analysis_run.llm_used = True

            # Enrich semantic profile with LLM findings
            if llm_res.get("impersonation_target"):
                semantic_profile["impersonation_target"] = llm_res["impersonation_target"]
            if llm_res.get("social_engineering_strategy"):
                semantic_profile["social_engineering_strategy"] = llm_res["social_engineering_strategy"]
            if llm_res.get("requested_action"):
                semantic_profile["requested_action"] = llm_res["requested_action"]

        # 3c. VirusTotal URL & Attachment Hash Scanning (capped for rate limits)
        vt_url_results = {}
        for url in parsed.get("urls", [])[:10]:
            vt_url_results[url] = scan_url_virustotal(url)

        vt_attachment_results = {}
        for att in parsed.get("attachments", []):
            sha = att.get("sha256")
            if sha:
                vt_attachment_results[sha] = scan_hash_virustotal(sha)

        # 4. Threat Intel Enrichment
        intel_findings = []
        for domain in url_res.get("extracted_domains", []):
            intel = lookup_indicator(db, "DOMAIN", domain)
            if intel.get("status") == "KNOWN_MALICIOUS":
                intel_findings.append({
                    "category": "DOMAIN_URL",
                    "code": "THREAT_INTEL_MALICIOUS_DOMAIN",
                    "title": f"Domain Confirmed Malicious in Threat Intel ({domain})",
                    "description": intel.get("notes") or "Domain exists in active adversary threat intelligence blacklist.",
                    "severity": "CRITICAL",
                    "risk_contribution": 35.0,
                    "evidence": intel
                })

        for hop in parsed.get("hops", []):
            ip = hop.get("ip_address")
            if ip:
                intel = lookup_indicator(db, "IP", ip)
                if intel.get("status") == "KNOWN_MALICIOUS":
                    intel_findings.append({
                        "category": "INFRASTRUCTURE",
                        "code": "THREAT_INTEL_MALICIOUS_IP",
                        "title": f"Observed Sending IP Confirmed Malicious ({ip})",
                        "description": intel.get("notes") or "Sending IP observed in adversary attack infrastructure.",
                        "severity": "CRITICAL",
                        "risk_contribution": 30.0,
                        "evidence": intel
                    })
                geo = hop_geo_enrichments.get(ip, {})
                geo_threat = geo.get("threat", {})
                if geo_threat.get("is_tor") or geo_threat.get("is_proxy"):
                    threat_type = "Tor Exit Node" if geo_threat.get("is_tor") else "Anonymous Proxy"
                    intel_findings.append({
                        "category": "INFRASTRUCTURE",
                        "code": "GEO_THREAT_ANONYMIZATION",
                        "title": f"Sending IP Routes Through {threat_type} ({ip})",
                        "description": f"IP {ip} ({geo.get('country_name', 'Unknown')}) identified as {threat_type} by IPGeolocation threat telemetry.",
                        "severity": "HIGH",
                        "risk_contribution": 20.0,
                        "evidence": geo
                    })

        for url, vt in vt_url_results.items():
            if vt.get("verdict") in ("MALICIOUS", "SUSPICIOUS"):
                severity = "CRITICAL" if vt["verdict"] == "MALICIOUS" else "HIGH"
                risk_contrib = 40.0 if vt["verdict"] == "MALICIOUS" else 20.0
                intel_findings.append({
                    "category": "DOMAIN_URL",
                    "code": f"VIRUSTOTAL_{vt['verdict']}_URL",
                    "title": f"URL Flagged {vt['verdict']} by VirusTotal ({vt.get('detection_ratio', '?/?')} engines)",
                    "description": f"VirusTotal: {vt.get('malicious', 0)} malicious out of {vt.get('total_engines', 0)} engines for {url[:80]}",
                    "severity": severity,
                    "risk_contribution": risk_contrib,
                    "evidence": vt
                })

        for sha, vt in vt_attachment_results.items():
            if vt.get("verdict") in ("MALICIOUS", "SUSPICIOUS"):
                severity = "CRITICAL" if vt["verdict"] == "MALICIOUS" else "HIGH"
                risk_contrib = 50.0 if vt["verdict"] == "MALICIOUS" else 25.0
                intel_findings.append({
                    "category": "ATTACHMENT",
                    "code": f"VIRUSTOTAL_{vt['verdict']}_ATTACHMENT",
                    "title": f"Attachment Flagged {vt['verdict']} by VirusTotal",
                    "description": f"SHA-256: {sha[:16]}... | {vt.get('malicious', 0)} malicious engine detections.",
                    "severity": severity,
                    "risk_contribution": risk_contrib,
                    "evidence": vt
                })

        # Combine all findings
        all_findings_raw = (
            header_res.get("findings", []) +
            url_res.get("findings", []) +
            intent_res.get("findings", []) +
            attachment_res.get("findings", []) +
            intel_findings
        )

        combined_signals = {
            **header_res.get("signals", {}),
            **url_res.get("signals", {}),
            **attachment_res.get("signals", {}),
            "primary_intent": intent_res.get("primary_intent")
        }

        # 5. PhishDNA Generation (Dual-Layer Architecture)
        phishdna_data = generate_phishdna(
            sender_domain=parsed.get("from_domain", ""),
            from_name=parsed.get("from_name", ""),
            from_address=parsed.get("from_address", ""),
            subject=parsed.get("subject", ""),
            body_text=parsed.get("body_text", ""),
            body_html=parsed.get("body_html", ""),
            urls=parsed.get("urls", []),
            hops=header_res.get("processed_hops", []),
            auth_results=auth_data,
            attachments=parsed.get("attachments", []),
            primary_intent=intent_res.get("primary_intent", "BENIGN_COMMUNICATION"),
            semantic_profile=semantic_profile
        )

        # 6. Risk Scoring (Saturating Categorical Engine with 5-Class Verdict)
        score, band, signal_snapshot, recommended_actions, verdict, corroboration_level = calculate_risk(
            findings=all_findings_raw,
            auth_summary=header_res.get("auth_summary", {}),
            signals=combined_signals
        )

        # Persist Findings with categorical evidence strength
        for f in all_findings_raw:
            sev = f.get("severity", "MEDIUM")
            evidence_tier = "STRONG" if sev in ("CRITICAL", "HIGH") else ("MODERATE" if sev == "MEDIUM" else "WEAK")
            db.add(Finding(
                analysis_id=analysis_run.id,
                category=f.get("category", "DOMAIN_URL"),
                code=f.get("code", "UNKNOWN"),
                title=f.get("title", ""),
                description=f.get("description", ""),
                severity=sev,
                risk_contribution=f.get("risk_contribution", 0.0),
                confidence=corroboration_level,
                provenance={"engine": "CYBERSENTRY_V2_CORE", "evidence_strength": evidence_tier},
                evidence=f.get("evidence", {})
            ))

        # Persist RiskScore
        db.add(RiskScore(
            analysis_id=analysis_run.id,
            score=score,
            band=band,
            verdict=verdict,
            corroboration_level=corroboration_level,
            confidence=corroboration_level,
            signal_snapshot=signal_snapshot,
            engine_version="2.0.0"
        ))

        # Persist PhishDNA
        db.add(PhishDNA(
            analysis_id=analysis_run.id,
            fingerprint=phishdna_data["fingerprint"],
            header_dna=phishdna_data["header_dna"],
            identity_auth_dna=phishdna_data["identity_auth_dna"],
            content_dna=phishdna_data["content_dna"],
            url_dna=phishdna_data["url_dna"],
            infrastructure_dna=phishdna_data["infrastructure_dna"],
            behavioral_dna=phishdna_data["behavioral_dna"],
            attachment_dna=phishdna_data["attachment_dna"],
            normalized_features=phishdna_data["normalized_features"]
        ))

        # Persist Recommended Defensive Actions
        for ra in recommended_actions:
            db.add(RecommendedAction(
                analysis_id=analysis_run.id,
                priority=ra["priority"],
                action_code=ra["action_code"],
                title=ra["title"],
                explanation=ra["explanation"],
                evidence_refs=ra.get("evidence_refs", [])
            ))

        # 7. Multi-Family Campaign Correlation
        existing_campaigns = get_campaigns_context(db)
        correlation_res = correlate_campaign(
            current_email_id=email_obj.id,
            current_evidence_id=evidence.evidence_id,
            current_analysis_id=analysis_run.id,
            current_phishdna=phishdna_data,
            current_risk_score=score,
            current_intent=intent_res.get("primary_intent", "BENIGN_COMMUNICATION"),
            existing_campaigns=existing_campaigns,
            all_analyzed_emails=[]
        )

        campaign_key = None
        if correlation_res:
            if correlation_res.get("is_new"):
                camp = Campaign(
                    campaign_key=correlation_res["campaign_key"],
                    name=correlation_res["name"],
                    confidence=0.85,
                    first_seen=datetime.now(timezone.utc),
                    last_seen=datetime.now(timezone.utc),
                    primary_intent=correlation_res["primary_intent"],
                    state=correlation_res["state"],  # "CANDIDATE"
                    risk_trend=correlation_res["risk_trend"]
                )
                db.add(camp)
                db.flush()
                campaign_id = camp.id
                campaign_key = camp.campaign_key
            else:
                campaign_id = correlation_res["campaign_id"]
                camp = db.query(Campaign).filter(Campaign.id == campaign_id).first()
                if camp:
                    camp.state = correlation_res["state"]
                    camp.risk_trend = correlation_res["risk_trend"]
                    camp.last_seen = datetime.now(timezone.utc)
                    campaign_key = camp.campaign_key

            # Add member with calibrated similarity
            db.add(CampaignMember(
                campaign_id=campaign_id,
                email_id=email_obj.id,
                similarity_score=correlation_res.get("similarity_score"),
                relationship_reason=correlation_res.get("relationship_reason", [])
            ))
            # Problem 12 fix: flush explicitly so the new member is guaranteed to
            # exist in the DB before we count members below. Relying on whether
            # SQLAlchemy's autoflush happens to have run yet -- and then patching
            # the gap with "+ 1" -- means the count is only right by coincidence.
            db.flush()

            # Add timeline evolution events
            for ev in correlation_res.get("events", []):
                db.add(CampaignEvolutionEvent(
                    campaign_id=campaign_id,
                    event_type=ev["event_type"],
                    event_time=datetime.now(timezone.utc),
                    triggering_analysis_id=analysis_run.id,
                    triggering_evidence_id=evidence.id,
                    summary=ev["summary"],
                    confidence=ev.get("confidence", 0.88),
                    provenance={"source": "PHISHDNA_CAMPAIGN_CORRELATION"}
                ))

            # Persist Campaign Model Snapshot
            db.add(CampaignModelSnapshot(
                campaign_id=campaign_id,
                state=correlation_res["state"],
                confidence=0.88,
                risk_score=score,
                risk_trend=correlation_res["risk_trend"],
                dominant_intent=intent_res.get("primary_intent"),
                message_count=db.query(CampaignMember).filter(CampaignMember.campaign_id == campaign_id).count(),
                infrastructure_count=len(phishdna_data.get("exact_features", {}).get("exact_origin_ips", [])),
                evolution_event=correlation_res.get("events", [{}])[0],
                triggered_by_analysis_id=analysis_run.id
            ))

        # 7b. Automated LLM Campaign Similarity Analysis (backend-only).
        # Compares this email against previously ingested emails using the
        # LLM and records the findings on the campaign's evolution
        # timeline. Purely additive to the deterministic correlation
        # above; never allowed to break the core pipeline if it fails.
        if campaign_key is not None:
            try:
                llm_assessments = run_llm_campaign_similarity_analysis(
                    db=db,
                    current_email=email_obj,
                    current_phishdna_data=phishdna_data,
                    campaign_id=campaign_id
                )
                for assessment in llm_assessments:
                    llm_result = assessment["llm_result"]
                    narrative = llm_result.get("narrative") or (
                        f"LLM similarity assessment vs {assessment['compared_evidence_id']}: "
                        f"{llm_result.get('similarity_score')}% estimated similarity."
                    )
                    db.add(CampaignEvolutionEvent(
                        campaign_id=campaign_id,
                        event_type="AI_SIMILARITY_ASSESSMENT",
                        event_time=datetime.now(timezone.utc),
                        triggering_analysis_id=analysis_run.id,
                        triggering_evidence_id=evidence.id,
                        summary=narrative,
                        previous_value=None,
                        new_value=llm_result,
                        confidence=llm_result.get("confidence", 0.6),
                        provenance={
                            "source": "LLM_CAMPAIGN_SIMILARITY",
                            "compared_email_id": assessment["compared_email_id"],
                            "compared_evidence_id": assessment["compared_evidence_id"],
                            "prefilter_similarity": assessment["prefilter_similarity"],
                            "model": llm_result.get("model")
                        }
                    ))
            except Exception:
                # Automated similarity enrichment is best-effort and must
                # never block or fail the core analysis pipeline.
                pass

        # 8. Build Attack Intent Graph with Explainable Edge Proofs
        build_attack_graph_for_email(
            db=db,
            email_id=email_obj.id,
            subject=parsed.get("subject", ""),
            from_address=parsed.get("from_address", ""),
            from_domain=parsed.get("from_domain", ""),
            recipients=recipient_emails,
            urls=parsed.get("urls", []),
            hops=header_res.get("processed_hops", []),
            attachments=parsed.get("attachments", []),
            intent=intent_res.get("primary_intent", "BENIGN_COMMUNICATION"),
            campaign_key=campaign_key
        )

        # 9. Finalize AnalysisRun & Append Immutable Custody Event
        analysis_run.status = "COMPLETED"
        analysis_run.completed_at = datetime.now(timezone.utc)
        db.commit()

        append_custody_event(
            db=db,
            evidence=evidence,
            action="ANALYZED",
            actor=actor_user,
            details={
                "analysis_id": analysis_run.id,
                "risk_score": score,
                "risk_band": band,
                "findings_count": len(all_findings_raw),
                "phishdna_fingerprint": phishdna_data["fingerprint"],
                "campaign_key": campaign_key
            }
        )

        return analysis_run
    except Exception as e:
        # Problem 10 fix: previously any failure inside this pipeline was
        # invisible -- the caller (api/evidence.py) wrapped this whole call
        # in `except Exception: pass`, so an analyst had no way to know
        # analysis silently failed vs. genuinely found nothing wrong.
        # We roll back the partial/corrupted analysis attempt (the Email,
        # AnalysisRun, Findings etc. staged above never get committed), then
        # record an explicit ANALYSIS_FAILED custody event on the evidence
        # itself -- the evidence file and its DB row are untouched -- and
        # re-raise so the API layer also knows this request did not succeed.
        db.rollback()
        append_custody_event(
            db=db,
            evidence=evidence,
            action="ANALYSIS_FAILED",
            actor=actor_user,
            details={
                "error": str(e),
                "error_type": type(e).__name__
            }
        )
        raise

def get_campaigns_context(db: Session) -> List[Dict[str, Any]]:
    campaigns = db.query(Campaign).all()
    results = []
    for c in campaigns:
        members_data = []
        shared_domains = set()
        shared_ips = set()
        for m in c.members:
            if m.email and m.email.analysis_run and m.email.analysis_run.phishdna:
                pd = m.email.analysis_run.phishdna
                members_data.append({
                    "email_id": m.email_id,
                    "phishdna": {
                        "exact_features": {
                            "exact_canonical_hosts": pd.url_dna.get("domains", []),
                            "exact_origin_ips": pd.infrastructure_dna.get("origin_ips", []),
                            "exact_sender_domain": pd.header_dna.get("sender_domain", "")
                        },
                        "normalized_features": pd.normalized_features or {},
                        "header_dna": pd.header_dna,
                        "identity_auth_dna": pd.identity_auth_dna,
                        "content_dna": pd.content_dna,
                        "url_dna": pd.url_dna,
                        "infrastructure_dna": pd.infrastructure_dna,
                        "behavioral_dna": pd.behavioral_dna
                    }
                })
                for d in pd.url_dna.get("domains", []):
                    shared_domains.add(d)
                for ip in pd.infrastructure_dna.get("origin_ips", []):
                    shared_ips.add(ip)

        results.append({
            "id": c.id,
            "campaign_key": c.campaign_key,
            "name": c.name,
            "primary_intent": c.primary_intent,
            "state": c.state,
            "risk_trend": c.risk_trend,
            "members": members_data,
            "shared_domains": list(shared_domains),
            "shared_ips": list(shared_ips)
        })
    return results

import io
import re
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from xml.sax.saxutils import escape as xml_escape
from sqlalchemy.orm import Session
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from backend.app.models import Evidence, Email, AnalysisRun


def _safe(value: Any) -> str:
    """
    Problem 17 fix: ReportLab's Paragraph() parses a small XML-like markup
    subset out of whatever string you give it (that's how our own <strong>
    tags below render as bold). If we interpolate raw attacker-controlled or
    LLM-generated text -- an email subject, a sender name, a Gemini
    explanation -- straight into an f-string passed to Paragraph(), any '<',
    '>' or '&' in that text gets parsed as markup instead of displayed as
    text. This escapes exactly those three characters (the same job
    html.escape does) so dynamic data always renders as literal text. We
    call this on every piece of dynamic data below -- never on the literal
    tags we write ourselves.
    """
    if value is None:
        return ""
    return xml_escape(str(value))


import hashlib
import json
from backend.app.services.evidence_service import append_custody_event

def generate_json_report(db: Session, evidence_id: str, record_custody: bool = True) -> Dict[str, Any]:
    evidence = db.query(Evidence).filter((Evidence.id == evidence_id) | (Evidence.evidence_id == evidence_id)).first()
    if not evidence:
        raise ValueError("Evidence record not found")

    email = evidence.email
    analysis = email.analysis_run if email else None

    report = {
        "report_metadata": {
            "platform": "CyberSentry V2 - AI Threat Detection & Forensic Intelligence",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target": "Forensic Intelligence & Attribution Support",
            "standards": "Tamper-Evident SHA-256 Forensic Record & Custody Audit Trail",
            "legal_note": "Admissibility depends on applicable jurisdiction, collection procedures, organizational controls, and judicial review."
        },
        "evidence_integrity": {
            "evidence_id": evidence.evidence_id,
            "original_filename": evidence.original_filename,
            "sha256": evidence.sha256,
            "size_bytes": evidence.size_bytes,
            "source_type": evidence.source_type,
            "collected_at": evidence.collected_at.isoformat() if evidence.collected_at else None,
            "custody_chain": [
                {
                    "action": ce.action,
                    "event_time": ce.event_time.isoformat(),
                    "event_hash": ce.event_hash,
                    "previous_event_hash": ce.previous_event_hash
                }
                for ce in evidence.custody_events
            ]
        },
        "email_metadata": {
            "subject": email.subject if email else None,
            "from_name": email.from_name if email else None,
            "from_address": email.from_address if email else None,
            "from_domain": email.from_domain if email else None,
            "reply_to": email.reply_to if email else None,
            "sent_at": email.sent_at.isoformat() if (email and email.sent_at) else None,
            "auth_results": {
                "spf": email.auth_result.spf_result if (email and email.auth_result) else "NONE",
                "dkim": email.auth_result.dkim_result if (email and email.auth_result) else "NONE",
                "dmarc": email.auth_result.dmarc_result if (email and email.auth_result) else "NONE"
            } if email else {}
        },
        "analysis_results": {
            "risk_score": float(analysis.risk_score.score) if (analysis and analysis.risk_score) else None,
            "risk_band": analysis.risk_score.band if (analysis and analysis.risk_score) else None,
            "phishdna_fingerprint": analysis.phishdna.fingerprint if (analysis and analysis.phishdna) else "N/A",
            "findings": [
                {
                    "category": f.category,
                    "code": f.code,
                    "title": f.title,
                    "severity": f.severity,
                    "risk_contribution": float(f.risk_contribution),
                    "description": f.description
                }
                for f in (analysis.findings if analysis else [])
            ],
            "recommended_actions": [
                {
                    "priority": ra.priority,
                    "action_code": ra.action_code,
                    "title": ra.title,
                    "explanation": ra.explanation
                }
                for ra in (analysis.recommended_actions if analysis else [])
            ]
        },
        # Problem 18 fix: the LLM's contribution was stored in the DB during
        # analysis but never surfaced in the report an analyst actually
        # reads. If Gemini semantic analysis influenced this investigation,
        # the report needs to show exactly what it found and say so plainly
        # -- labeled non-authoritative, since it's a language model's
        # interpretation, not a verified technical fact like an SPF result.
        "llm_analysis": (
            {
                "label": "LLM-generated semantic interpretation — non-authoritative",
                "provider": analysis.llm_analysis.provider,
                "model": analysis.llm_analysis.model,
                "status": analysis.llm_analysis.status,
                "intent_categories": analysis.llm_analysis.intent_categories,
                "impersonation_target": analysis.llm_analysis.impersonation_target,
                "urgency_level": analysis.llm_analysis.urgency_level,
                "social_engineering_indicators": analysis.llm_analysis.social_engineering_indicators,
                "semantic_risk": analysis.llm_analysis.semantic_risk,
                "explanation": analysis.llm_analysis.explanation
            }
            if (analysis and analysis.llm_analysis) else None
        ),
        "disclaimer": "Forensic Disclaimer: Infrastructure location indicates server/relay transit hosting and does not establish physical actor identity. Risk scores represent heuristic triage prioritization, not probability. Evidence admissibility depends on applicable jurisdiction, collection procedures, organizational controls, and judicial review."
    }

    if record_custody:
        report_bytes = json.dumps(report, sort_keys=True).encode("utf-8")
        report_sha = hashlib.sha256(report_bytes).hexdigest()
        append_custody_event(
            db=db,
            evidence=evidence,
            action="EXPORTED",
            actor=None,
            details={"format": "JSON", "report_sha256": report_sha}
        )

    return report

def generate_pdf_report(db: Session, evidence_id: str) -> bytes:
    data = generate_json_report(db, evidence_id, record_custody=False)
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleStyle", parent=styles["Heading1"], fontSize=16, textColor=colors.HexColor("#0f172a"), spaceAfter=6)
    h2_style = ParagraphStyle("H2Style", parent=styles["Heading2"], fontSize=11, textColor=colors.HexColor("#1e293b"), spaceBefore=10, spaceAfter=4)
    body_style = ParagraphStyle("BodyStyle", parent=styles["Normal"], fontSize=8.5, textColor=colors.HexColor("#334155"), leading=11)
    mono_style = ParagraphStyle("MonoStyle", parent=styles["Normal"], fontName="Courier", fontSize=8, textColor=colors.HexColor("#0f172a"))
    warning_style = ParagraphStyle("WarnStyle", parent=styles["Normal"], fontSize=7.5, textColor=colors.HexColor("#64748b"), italic=True)

    story = []

    # Title & Header
    story.append(Paragraph("CYBERSENTRY TAMPER-EVIDENT FORENSIC INVESTIGATION REPORT", title_style))
    story.append(Paragraph(f"Evidence ID: <strong>{_safe(data['evidence_integrity']['evidence_id'])}</strong> | Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", body_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2563eb"), spaceBefore=6, spaceAfter=10))

    # Executive Summary Table
    ev_data = data["evidence_integrity"]
    an_data = data["analysis_results"]
    summary_table_data = [
        ["Risk Prioritization Score", _safe(f"{an_data.get('risk_band', 'UNKNOWN')} ({an_data.get('risk_score', 0)}/100 - Heuristic Prioritization)")],
        ["PhishDNA™ Fingerprint", _safe(an_data.get("phishdna_fingerprint", "N/A"))],
        ["SHA-256 Digest", _safe(ev_data.get("sha256"))],
        ["Subject", _safe(data["email_metadata"].get("subject") or "No Subject")],
        ["Purported Sender", _safe(f"{data['email_metadata'].get('from_name') or ''} <{data['email_metadata'].get('from_address') or ''}>")],
        ["Reported Auth (MIME)", _safe(f"SPF: {data['email_metadata'].get('auth_results', {}).get('spf', 'NONE')} | DKIM: {data['email_metadata'].get('auth_results', {}).get('dkim', 'NONE')} | DMARC: {data['email_metadata'].get('auth_results', {}).get('dmarc', 'NONE')}")]
    ]
    t = Table(summary_table_data, colWidths=[140, 400])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#f1f5f9')),
        ('TEXTCOLOR', (0,0), (-1,-1), colors.HexColor('#0f172a')),
        ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 8),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t)
    story.append(Spacer(1, 8))

    # Key Findings
    story.append(Paragraph("Key Forensic Findings (Explainable Evidence)", h2_style))
    total_findings = len(an_data.get("findings", []))
    findings_data = [["Category", "Severity", "Finding Title", "Contribution"]]
    for f in an_data.get("findings", [])[:8]:
        findings_data.append([
            _safe(f.get("category", "")),
            _safe(f.get("severity", "")),
            _safe(f.get("title", "")),
            _safe(f"+{f.get('risk_contribution', 0)}")
        ])
    if len(findings_data) > 1:
        ft = Table(findings_data, colWidths=[80, 60, 320, 80])
        ft.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('PADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(ft)
        if total_findings > 8:
            story.append(Spacer(1, 4))
            story.append(Paragraph(f"<i>Note: Top 8 of {total_findings} findings shown; complete forensic telemetry available in JSON report.</i>", warning_style))
    else:
        story.append(Paragraph("No high-priority hostile indicators detected by current analysis engines.", body_style))

    story.append(Spacer(1, 8))

    # Recommended Defensive Actions
    story.append(Paragraph("Recommended Defensive Actions (Advisory)", h2_style))
    for ra in an_data.get("recommended_actions", []):
        story.append(Paragraph(f"• <strong>[{_safe(ra.get('priority'))}] {_safe(ra.get('title'))}</strong>: {_safe(ra.get('explanation'))}", body_style))
        story.append(Spacer(1, 2))

    # LLM Semantic Analysis (Problem 16 fix: explicit non-authoritative section)
    llm_data = data.get("llm_analysis")
    if llm_data:
        story.append(Spacer(1, 8))
        story.append(Paragraph("AI Semantic Analysis — Supporting Evidence", h2_style))
        story.append(Paragraph(f"<i>{_safe(llm_data.get('label'))}</i>", warning_style))
        story.append(Paragraph(
            f"Provider: <strong>{_safe(llm_data.get('provider'))}</strong> | Model: <strong>{_safe(llm_data.get('model'))}</strong> | Status: {_safe(llm_data.get('status'))}",
            body_style
        ))
        if llm_data.get("impersonation_target"):
            story.append(Paragraph(f"Impersonation Target (LLM-inferred): {_safe(llm_data.get('impersonation_target'))}", body_style))
        if llm_data.get("urgency_level"):
            story.append(Paragraph(f"Urgency Level (LLM-inferred): {_safe(llm_data.get('urgency_level'))}", body_style))
        if llm_data.get("intent_categories"):
            story.append(Paragraph(f"Intent Categories: {_safe(', '.join(llm_data.get('intent_categories') or []))}", body_style))
        if llm_data.get("social_engineering_indicators"):
            story.append(Paragraph(f"Social Engineering Indicators: {_safe(', '.join(llm_data.get('social_engineering_indicators') or []))}", body_style))
        for line in (llm_data.get("explanation") or []):
            story.append(Paragraph(f"• {_safe(line)}", body_style))

    # Evidence Custody Chain
    story.append(Spacer(1, 8))
    story.append(Paragraph("Evidence Custody Hash Chain (Tamper-Evident SHA-256)", h2_style))
    for c in ev_data.get("custody_chain", []):
        story.append(Paragraph(f"[{_safe(c.get('event_time'))}] <strong>{_safe(c.get('action'))}</strong> | Hash: <font name='Courier'>{_safe((c.get('event_hash') or '')[:24])}...</font>", body_style))

    # Disclaimer
    story.append(Spacer(1, 12))
    story.append(Paragraph(_safe(data["disclaimer"]), warning_style))

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()

    # B03: Record EXPORTED custody event with PDF SHA-256
    pdf_sha = hashlib.sha256(pdf_bytes).hexdigest()
    append_custody_event(
        db=db,
        evidence=evidence,
        action="EXPORTED",
        actor=None,
        details={"format": "PDF", "report_sha256": pdf_sha}
    )

    return pdf_bytes

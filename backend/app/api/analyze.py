"""
backend/app/api/analyze.py — F01: Direct Multi-Channel Analysis Endpoints

Accepts raw email headers or raw EML / MSG text for immediate inspection without storing evidence.
"""

from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from backend.app.services.parser_service import parse_eml_bytes
from backend.app.engines.header_engine import analyze_headers
from backend.app.engines.url_engine import analyze_urls
from backend.app.engines.intent_engine import analyze_intent
from backend.app.engines.risk_engine import calculate_risk

router = APIRouter(prefix="/analyze", tags=["Direct Analysis"])


class AnalyzeHeadersRequest(BaseModel):
    raw_headers: str = Field(..., description="Raw RFC 5322 header block")
    recipient_domain: Optional[str] = Field(None, description="Receiving organization domain")


class AnalyzeRawRequest(BaseModel):
    raw_eml: str = Field(..., description="Full raw EML / RFC 5322 email string")


@router.post("/headers")
def analyze_raw_headers_endpoint(req: AnalyzeHeadersRequest):
    """F01: Direct header-only analysis route."""
    # Convert header string to bytes and parse
    dummy_eml = req.raw_headers.encode("utf-8") + b"\r\n\r\n"
    parsed = parse_eml_bytes(dummy_eml)

    header_res = analyze_headers(
        from_name=parsed.get("from_name"),
        from_address=parsed.get("from_address"),
        from_domain=parsed.get("from_domain"),
        reply_to=parsed.get("reply_to"),
        return_path=parsed.get("return_path"),
        hops=parsed.get("hops", []),
        auth_results=parsed.get("auth_results", {}),
        recipient_domain=req.recipient_domain
    )

    return {
        "status": "success",
        "header_analysis": header_res,
        "processed_hops": header_res.get("processed_hops", []),
        "auth_summary": header_res.get("auth_summary", {}),
        "anomalies": header_res.get("anomalies", [])
    }


@router.post("/raw")
def analyze_raw_eml_endpoint(req: AnalyzeRawRequest):
    """F01: Direct raw email analysis route without database persistence."""
    eml_bytes = req.raw_eml.encode("utf-8")
    parsed = parse_eml_bytes(eml_bytes)

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

    findings = header_res.get("findings", []) + url_res.get("findings", []) + intent_res.get("findings", [])
    signals = {**header_res.get("signals", {}), **url_res.get("signals", {})}
    score, band, snapshot, recs, verdict, _ = calculate_risk(findings, header_res.get("auth_summary", {}), signals)

    return {
        "verdict": verdict,
        "risk_score": score,
        "risk_band": band,
        "findings": findings,
        "parsed_metadata": {
            "subject": parsed.get("subject"),
            "from_address": parsed.get("from_address"),
            "message_id": parsed.get("message_id")
        },
        "recommended_actions": recs
    }

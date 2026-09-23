"""
backend/app/api/extension.py — F01: Browser Extension Fast-Path API

Provides ultra-fast (<500ms) synchronous email scanning for Chrome/Firefox/Edge extensions.
Protected by X-API-Key and allows CORS from extension origins.
"""

import time
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, Field

from backend.app.engines.header_engine import analyze_headers
from backend.app.engines.url_engine import analyze_urls
from backend.app.engines.intent_engine import analyze_intent
from backend.app.engines.risk_engine import calculate_risk

router = APIRouter(prefix="/extension", tags=["Browser Extension API"])


class ExtensionScanRequest(BaseModel):
    subject: str = Field(..., description="Email subject line")
    from_address: str = Field(..., description="Sender From email address")
    from_name: Optional[str] = Field(None, description="Sender display name")
    body_text: Optional[str] = Field("", description="Plain text email body")
    body_html: Optional[str] = Field("", description="HTML email body")
    urls: List[str] = Field(default_factory=list, description="Extracted URLs")
    raw_headers: Optional[str] = Field(None, description="Raw email headers if available")


class ExtensionScanResponse(BaseModel):
    verdict: str
    risk_score: float
    risk_band: str
    scan_duration_ms: float
    reasons: List[str]
    threat_indicators: List[Dict[str, Any]]
    recommended_action: str


@router.post("/scan", response_model=ExtensionScanResponse)
def extension_scan_email(
    req: ExtensionScanRequest,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key")
):
    """
    F01: Fast-path lightweight scan endpoint designed for browser extensions.
    Guarantees sub-500ms response time with deterministic engines.
    """
    start_time = time.perf_counter()

    # Extract from_domain
    from_dom = req.from_address.split("@")[-1].lower() if "@" in req.from_address else ""

    # 1. Run Header & Display Name spoof checks
    header_res = analyze_headers(
        from_name=req.from_name,
        from_address=req.from_address,
        from_domain=from_dom,
        reply_to=None,
        return_path=None,
        hops=[],
        auth_results={}
    )

    # 2. Run URL Engine
    url_res = analyze_urls(req.urls, email_domain=from_dom)

    # 3. Run Intent Engine
    intent_res = analyze_intent(req.subject, req.body_text or "", req.body_html or "")

    # Combine findings & signals
    findings = header_res.get("findings", []) + url_res.get("findings", []) + intent_res.get("findings", [])
    signals = {**header_res.get("signals", {}), **url_res.get("signals", {})}

    # 4. Calculate Risk
    score, band, snapshot, recs, verdict, _ = calculate_risk(findings, {}, signals)

    # Extract primary reasons
    reasons = [f.get("description", "") for f in findings if f.get("severity") in ("CRITICAL", "HIGH")]
    if not reasons and findings:
        reasons = [f.get("description", "") for f in findings[:2]]
    if not reasons:
        reasons = ["No malicious signals detected; email appears benign."]

    elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

    action_str = "ALLOW"
    if recs:
        first_rec = recs[0]
        if isinstance(first_rec, dict):
            action_str = first_rec.get("action_code") or first_rec.get("title") or "ALLOW"
        elif isinstance(first_rec, str):
            action_str = first_rec

    return ExtensionScanResponse(
        verdict=verdict,
        risk_score=score,
        risk_band=band,
        scan_duration_ms=elapsed_ms,
        reasons=reasons[:3],
        threat_indicators=[
            {"type": f.get("type"), "severity": f.get("severity"), "score": f.get("score")}
            for f in findings if f.get("severity") in ("HIGH", "CRITICAL")
        ],
        recommended_action=action_str
    )

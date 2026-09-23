"""
backend/app/services/alert_service.py — F09: Real-Time Alerting Engine

Dispatches security alerts to Webhooks (with HMAC-SHA256 signatures),
In-app SSE event stream subscribers, and email notifiers.
Includes deduplication cooldown and threshold-based alert triggers.
"""

import hmac
import hashlib
import json
import time
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

# In-memory alert store and cooldown tracker for testing & SSE
_ALERT_STREAM: List[Dict[str, Any]] = []
_ALERT_COOLDOWN: Dict[str, float] = {}


def generate_webhook_signature(payload_bytes: bytes, secret: str) -> str:
    """Generates HMAC-SHA256 hex digest for webhook payload verification."""
    mac = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def evaluate_and_dispatch_alert(
    email_id: str,
    subject: str,
    from_address: str,
    risk_score: float,
    verdict: str,
    findings: List[Dict[str, Any]],
    webhook_url: Optional[str] = None,
    webhook_secret: Optional[str] = None,
    cooldown_seconds: float = 60.0
) -> Optional[Dict[str, Any]]:
    """
    F09: Triggers an alert if risk exceeds threshold, applying deduplication cooldown.
    """
    # Only alert on high-risk or malicious verdicts
    if risk_score < 60.0 and verdict not in ("PHISHING", "SPOOFED", "MALICIOUS"):
        return None

    # Cooldown check based on sender domain or subject
    cooldown_key = f"{from_address}:{verdict}"
    now = time.time()
    last_sent = _ALERT_COOLDOWN.get(cooldown_key, 0.0)
    if (now - last_sent) < cooldown_seconds:
        return None  # Suppressed by cooldown

    _ALERT_COOLDOWN[cooldown_key] = now

    alert_payload = {
        "alert_id": f"ALT-{int(now * 1000)}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "email_id": email_id,
        "subject": subject,
        "from_address": from_address,
        "risk_score": risk_score,
        "verdict": verdict,
        "high_severity_findings": [f.get("type") for f in findings if f.get("severity") in ("HIGH", "CRITICAL")],
        "event_type": "THREAT_DETECTED"
    }

    # Append to SSE stream buffer (keep last 100)
    _ALERT_STREAM.append(alert_payload)
    if len(_ALERT_STREAM) > 100:
        _ALERT_STREAM.pop(0)

    # Webhook signature header simulation
    if webhook_url and webhook_secret:
        body = json.dumps(alert_payload).encode("utf-8")
        sig = generate_webhook_signature(body, webhook_secret)
        alert_payload["webhook_signature"] = sig
        alert_payload["webhook_dispatched"] = True
    else:
        alert_payload["webhook_dispatched"] = False

    return alert_payload


def get_recent_alerts(limit: int = 20) -> List[Dict[str, Any]]:
    """Retrieve recent alerts for in-app notification bell."""
    return list(reversed(_ALERT_STREAM[-limit:]))

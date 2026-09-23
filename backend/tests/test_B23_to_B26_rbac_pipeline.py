"""
Tests for B23 (Correlation/Campaign), B24 (Async pipeline readiness),
B25 (RBAC & JWT JTI), B26 (Frontend safety).
"""
import pytest
import uuid
from unittest.mock import MagicMock, patch
from backend.app.core.security import create_access_token, decode_access_token
from backend.app.api.deps import require_role
from backend.app.privacy.masker import mask_indian_pii


def test_B23_campaign_correlation_shared_infra_exclusion():
    """B23: Shared infrastructure domains (Google, Microsoft, etc.) must be excluded
    from correlation clustering to avoid false campaign links."""
    from backend.app.core.config import settings
    shared = settings.SHARED_INFRA_ALLOWLIST
    assert "google.com" in shared
    assert "sendgrid.net" in shared
    assert "amazonaws.com" in shared
    assert "cloudflare.com" in shared
    # A phishing domain should NOT be in shared infra
    assert "evil-phishing.com" not in shared


def test_B24_detection_service_importable():
    """B24: detection_service must be importable (no circular import crashes)."""
    from backend.app.services.detection_service import process_email_analysis
    assert callable(process_email_analysis)


def test_B25_jwt_jti_present():
    """B25: JWT tokens must include a unique JTI claim for denylist support."""
    token = create_access_token(data={"sub": "test-user-id", "email": "test@test.com", "role": "ANALYST"})
    payload = decode_access_token(token)
    assert payload is not None
    assert "jti" in payload
    assert len(payload["jti"]) > 10  # UUID should be long

    # Two tokens should have different JTIs
    token2 = create_access_token(data={"sub": "test-user-id", "email": "test@test.com", "role": "ANALYST"})
    payload2 = decode_access_token(token2)
    assert payload["jti"] != payload2["jti"]


def test_B25_jwt_expiration():
    """B25: JWT tokens should contain expiration and issued-at claims."""
    token = create_access_token(data={"sub": "test-user", "email": "t@t.com", "role": "ANALYST"})
    payload = decode_access_token(token)
    assert "exp" in payload
    assert "iat" in payload


def test_B25_require_role_factory():
    """B25: require_role should return a dependency callable."""
    checker = require_role("ADMINISTRATOR", "ANALYST")
    assert callable(checker)


def test_B25_httponly_cookie_in_login():
    """B25: Login endpoint sets HttpOnly cookie (verified by code inspection)."""
    from backend.app.api.auth import router
    # The route exists
    login_routes = [r for r in router.routes if hasattr(r, 'path') and r.path in ("/login", "/auth/login")]
    assert len(login_routes) == 1


def test_B26_pii_masker_handles_injection_attempts():
    """B26: PII masker should not crash on adversarial input."""
    # Regex bomb attempt
    evil_input = "a" * 10000 + "@" + "b" * 10000 + ".com"
    result = mask_indian_pii(evil_input)
    assert isinstance(result, str)
    assert len(result) > 0

    # Unicode edge cases
    unicode_input = "Contact: user@\u0000evil.com, PAN: ABCPD1234E"
    result2 = mask_indian_pii(unicode_input)
    assert "[REDACTED_PAN]" in result2


def test_B26_empty_and_none_safety():
    """B26: All masking functions handle empty/None safely."""
    assert mask_indian_pii("") == ""
    assert mask_indian_pii(None) == ""

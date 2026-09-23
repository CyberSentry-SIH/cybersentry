"""
Tests for B20 (VT hardening), B21 (PII masking), B22 (LLM isolation).
No live network calls — all VT/Gemini features are tested offline.
"""
import pytest
from backend.app.privacy.masker import mask_indian_pii, sanitize_url_query, mask_for_external_api
from backend.app.services.virustotal_service import (
    _RateLimiter, _TTLCache, _empty_url_result, _empty_hash_result, _build_url_result
)
from backend.app.providers.llm_provider import mask_pii_for_external_analysis


def test_B20_rate_limiter_token_bucket():
    """B20: Rate limiter should grant tokens up to max and deny when exhausted."""
    rl = _RateLimiter(max_tokens=2, refill_interval=60.0)
    assert rl.acquire(timeout=0.1) is True
    assert rl.acquire(timeout=0.1) is True
    # Third request should fail (bucket empty, refill too slow)
    assert rl.acquire(timeout=0.1) is False


def test_B20_ttl_cache_expiry():
    """B20: TTL cache should expire entries after TTL."""
    cache = _TTLCache(ttl_seconds=0)  # instant expiry
    cache.set("key1", {"result": "value"})
    # Should be expired immediately
    import time
    time.sleep(0.01)
    assert cache.get("key1") is None

    # Valid TTL
    cache2 = _TTLCache(ttl_seconds=300)
    cache2.set("key2", {"result": "ok"})
    assert cache2.get("key2") == {"result": "ok"}
    cache2.clear()
    assert cache2.get("key2") is None


def test_B20_vt_lookup_only_default():
    """B20: With ENABLE_EXTERNAL_INTEL=False, VT returns empty result without network call."""
    result = _empty_url_result("http://evil.com")
    assert result["enriched"] is False
    assert result["source"] == "UNAVAILABLE"
    assert result["verdict"] == "PENDING"


def test_B20_build_url_result_verdicts():
    """B20: VT verdict logic correctly classifies by malicious count."""
    raw = {"data": {"attributes": {"last_analysis_date": 1234567890}}}
    # Clean
    res = _build_url_result("http://safe.com", {"malicious": 0, "suspicious": 0, "harmless": 10, "undetected": 5}, raw)
    assert res["verdict"] == "CLEAN"
    # Suspicious
    res2 = _build_url_result("http://sus.com", {"malicious": 1, "suspicious": 0, "harmless": 10, "undetected": 5}, raw)
    assert res2["verdict"] == "SUSPICIOUS"
    # Malicious
    res3 = _build_url_result("http://bad.com", {"malicious": 5, "suspicious": 2, "harmless": 3, "undetected": 5}, raw)
    assert res3["verdict"] == "MALICIOUS"


def test_B21_indian_mobile_masking():
    """B21: Indian mobile numbers in various formats should be masked."""
    assert "[REDACTED_INDIAN_MOBILE]" in mask_indian_pii("Call me at 9876543210")
    assert "[REDACTED_INDIAN_MOBILE]" in mask_indian_pii("Contact +91 9876543210")
    assert "[REDACTED_INDIAN_MOBILE]" in mask_indian_pii("+91-9876543210")


def test_B21_aadhaar_masking():
    """B21: Aadhaar numbers (12-digit starting with 2-9) should be masked."""
    assert "[REDACTED_AADHAAR]" in mask_indian_pii("Aadhaar: 2345 6789 0123")
    assert "[REDACTED_AADHAAR]" in mask_indian_pii("Aadhaar: 234567890123")
    # Numbers starting with 0 or 1 should not be treated as Aadhaar
    result = mask_indian_pii("Code: 0123 4567 8901")
    assert "[REDACTED_AADHAAR]" not in result


def test_B21_pan_masking():
    """B21: PAN card numbers should be masked."""
    assert "[REDACTED_PAN]" in mask_indian_pii("PAN: ABCPD1234E")
    assert "[REDACTED_PAN]" not in mask_indian_pii("Not a PAN: HELLO")


def test_B21_upi_masking():
    """B21: UPI IDs should be masked."""
    assert "[REDACTED_UPI]" in mask_indian_pii("Pay to user@okicici")
    assert "[REDACTED_UPI]" in mask_indian_pii("UPI: 9876543210@ybl")


def test_B21_ifsc_masking():
    """B21: IFSC codes should be masked."""
    assert "[REDACTED_IFSC]" in mask_indian_pii("IFSC: SBIN0001234")


def test_B21_url_query_sanitization():
    """B21: URL query params should be stripped."""
    assert sanitize_url_query("http://evil.com/track?user=admin&token=abc123") == "http://evil.com/track?[QUERY_REDACTED]"
    assert sanitize_url_query("http://safe.com/page") == "http://safe.com/page"
    assert sanitize_url_query("") == ""


def test_B21_email_masking():
    """B21: Email addresses in text should be masked."""
    assert "[REDACTED_EMAIL]" in mask_indian_pii("Contact admin@company.com for help")


def test_B22_llm_pii_masker_delegates_to_indian_masker():
    """B22: The LLM's PII masker should catch Indian PII patterns."""
    text = "Send to ABCPD1234E, call 9876543210, email admin@company.com"
    masked = mask_pii_for_external_analysis(text)
    assert "[REDACTED_PAN]" in masked
    assert "[REDACTED_INDIAN_MOBILE]" in masked
    assert "[REDACTED_EMAIL]" in masked
    # Original values should not remain
    assert "ABCPD1234E" not in masked
    assert "9876543210" not in masked
    assert "admin@company.com" not in masked


def test_B22_empty_input():
    """B22: Empty input should return empty string."""
    assert mask_pii_for_external_analysis("") == ""
    assert mask_indian_pii("") == ""
    assert mask_for_external_api("") == ""

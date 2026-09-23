"""
backend/tests/test_fuzzing.py — Phase 4: Fuzzing & Resilience Property Tests

Verifies that parser_service and url_engine never raise unhandled exceptions
when presented with mutated bytes, truncated MIME, malformed headers, or extreme payloads.
"""

import os
import random
import pytest
from backend.app.services.parser_service import parse_eml_bytes
from backend.app.engines.url_engine import analyze_urls, safe_urlparse, detect_obfuscated_urls
from backend.app.engines.intent_engine import analyze_intent
from backend.app.engines.header_engine import analyze_headers


def test_fuzz_parser_random_corrupted_bytes():
    """Fuzz parser with 100 iterations of random corrupted byte sequences."""
    random.seed(42)
    for _ in range(100):
        length = random.randint(1, 2048)
        random_bytes = bytes(random.getrandbits(8) for _ in range(length))
        result = parse_eml_bytes(random_bytes)
        assert isinstance(result, dict)
        assert "subject" in result
        assert "hops" in result
        assert "urls" in result


def test_fuzz_parser_nested_mime_bombs():
    """Fuzz parser with deeply nested multipart MIME structures (30 layers)."""
    boundary_base = "BOUNDARY_LAYER_"
    nested_eml = "Content-Type: multipart/mixed; boundary=BOUNDARY_LAYER_0\r\n\r\n"
    
    for i in range(30):
        nested_eml += f"--{boundary_base}{i}\r\n"
        nested_eml += f"Content-Type: multipart/alternative; boundary={boundary_base}{i+1}\r\n\r\n"

    nested_eml += f"--{boundary_base}30\r\nContent-Type: text/plain\r\n\r\nDeep Payload\r\n"
    nested_eml += f"--{boundary_base}30--\r\n"

    result = parse_eml_bytes(nested_eml.encode("utf-8"))
    assert isinstance(result, dict)
    assert result.get("body_text") is not None or result.get("body_html") is not None


def test_fuzz_url_engine_extreme_inputs():
    """Fuzz URL engine with malformed, extreme, and malicious URL structures."""
    extreme_cases = [
        "http://" + "a" * 5000 + ".com",
        "https://[::1]:8080/path",
        "https://[invalid-ipv6-bracketed]/test",
        "http://%00%01%ff%fe@evil.com",
        "http://127.0.0.1%252e%252e/admin",
        "javascript:alert(1)",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "view-source:http://example.com",
        "",
        None,
        "http://\u200b\u200c\ufeffevil.com/path",
        "http://admin:pass@user:pass@evil.com"
    ]

    for u in extreme_cases:
        if u:
            parsed = safe_urlparse(u)
            assert parsed is not None
            obf = detect_obfuscated_urls(u)
            assert isinstance(obf, list)

    res = analyze_urls([u for u in extreme_cases if u is not None])
    assert isinstance(res, dict)
    assert "findings" in res


def test_fuzz_intent_engine_adversarial_text():
    """Fuzz Intent engine with non-ascii, control characters, and huge strings."""
    adversarial_texts = [
        "\x00\x01\x02\x03\x04\x05" * 100,
        "🚀" * 1000,
        "A" * 50000,  # 50KB string
        "URGENT \u202e \u202d CLICK HERE",
        "NULL" * 1000
    ]

    for txt in adversarial_texts:
        res = analyze_intent("Test Subject", txt, "")
        assert isinstance(res, dict)
        assert "urgency_detected" in res
        assert "primary_intent" in res

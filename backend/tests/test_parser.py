import pytest
from backend.app.services.parser_service import parse_eml_bytes

def test_parse_paypal_phish():
    raw_eml = b"""From: "PayPal Security Center" <service@paypa1-security-update.com>
To: target.analyst@company-corp.com
Subject: [URGENT] Verify Identity
Date: Wed, 04 Sep 2026 14:22:10 +0000
Message-ID: <test-123@paypa1.com>
Authentication-Results: mx.company-corp.com; spf=fail; dkim=none; dmarc=fail
Received: from mail.suspicious.net ([185.220.101.5]) by mx.company.com; Wed, 04 Sep 2026 14:22:15 +0000
Content-Type: text/html

<a href="https://paypa1-security-update.com/login">Verify Account</a>
"""
    result = parse_eml_bytes(raw_eml)
    assert result["parser_status"] == "SUCCESS"
    assert result["from_address"] == "service@paypa1-security-update.com"
    assert result["from_domain"] == "paypa1-security-update.com"
    assert "https://paypa1-security-update.com/login" in result["urls"]
    assert len(result["hops"]) == 1
    assert result["hops"][0]["ip_address"] == "185.220.101.5"
    assert result["auth_results"]["spf_result"] == "FAIL"
    assert result["auth_results"]["dmarc_result"] == "FAIL"

import pytest
from datetime import datetime, timezone, timedelta
from email.utils import format_datetime
from backend.app.engines.header_engine import (
    extract_ip_from_hop,
    is_global_routable_ip,
    is_ip_in_trusted_gateways,
    is_host_in_trusted_domains,
    analyze_headers,
    detect_header_anomalies
)

def test_B14_and_B15_trust_boundary_peer_walk_and_cidr():
    # Scenario: 3 hops
    # Hop 0 (newest): internal proxy (10.0.0.2) received by mail.corp.internal
    # Hop 1: boundary gateway (mail.corp.internal) received from external attacker IP (185.220.101.5)
    # Hop 2 (oldest): forged claimed hop received from spoofed IP (1.2.3.4)
    hops = [
        {
            "raw_value": "from internal-proxy (10.0.0.2) by mail.corp.internal with SMTP id 123",
            "hostname": "mail.corp.internal",
            "ip_address": "10.0.0.2"
        },
        {
            "raw_value": "from mail.attacker.com ([185.220.101.5]) by mail.corp.internal with ESMTP id 456",
            "hostname": "mail.attacker.com",
            "ip_address": "185.220.101.5"
        },
        {
            "raw_value": "from forged.source.com ([1.2.3.4]) by mail.attacker.com with ESMTP id 789",
            "hostname": "forged.source.com",
            "ip_address": "1.2.3.4"
        }
    ]

    res = analyze_headers(
        from_name="Security Alert",
        from_address="security@paypal.com",
        from_domain="paypal.com",
        reply_to=None,
        return_path=None,
        hops=hops,
        auth_results={"authserv_id": "mail.corp.internal", "spf_result": "FAIL", "dkim_result": "NONE", "dmarc_result": "FAIL"}
    )

    # Boundary peer must be 185.220.101.5 (Hop 2, 1-indexed)
    boundary_hop = res.get("boundary_hop")
    assert boundary_hop is not None
    assert boundary_hop["ip_address"] == "185.220.101.5"
    assert boundary_hop["hop_order"] == 2

    # Verify trust levels of processed hops
    processed = res.get("processed_hops", [])
    assert len(processed) == 3
    assert processed[0]["trust_level"] == "TRUSTED_GATEWAY"
    assert processed[1]["trust_level"] == "OBSERVED_BY_TRUSTED_MTA"
    assert processed[2]["trust_level"] == "CLAIMED"

def test_B15_cidr_containment_checks():
    trusted_cidrs = ["10.0.0.0/8", "192.168.1.0/24", "172.16.0.0/12", "2001:db8::/32"]
    assert is_ip_in_trusted_gateways("10.50.1.1", trusted_cidrs) is True
    assert is_ip_in_trusted_gateways("192.168.1.254", trusted_cidrs) is True
    assert is_ip_in_trusted_gateways("172.20.5.1", trusted_cidrs) is True
    assert is_ip_in_trusted_gateways("2001:db8:ffff::1", trusted_cidrs) is True
    assert is_ip_in_trusted_gateways("8.8.8.8", trusted_cidrs) is False
    # 192.168.2.1 is RFC 1918 private → auto-trusted by design (internal network)
    assert is_ip_in_trusted_gateways("192.168.2.1", trusted_cidrs) is True
    # Public IP not in any trusted CIDR
    assert is_ip_in_trusted_gateways("93.184.216.34", trusted_cidrs) is False

def test_B16_ipv6_hop_extraction():
    # Various IPv6 formats in Received headers
    hop1 = "from mail.example.com ([IPv6:2001:db8:85a3::8a2e:370:7334]) by mta.receiver.com"
    hop2 = "from mail.example.com ([2607:f8b0:4864:20::62a]) by mx.google.com"
    hop3 = "from [2001:0db8:85a3:0000:0000:8a2e:0370:7334] by mail.test.com"

    assert extract_ip_from_hop(hop1) == "2001:db8:85a3::8a2e:370:7334"
    assert extract_ip_from_hop(hop2) == "2607:f8b0:4864:20::62a"
    assert extract_ip_from_hop(hop3) == "2001:db8:85a3::8a2e:370:7334"

def test_B17_untrusted_auth_results_header():
    # When attacker prepends a fake Authentication-Results header claiming SPF=PASS
    # but the authserv-id does not match receiver domain / trusted MTAs
    untrusted_auth = {
        "authserv_id": "evil-relay.attacker-infra.com",
        "spf_result": "PASS",
        "dkim_result": "PASS",
        "dmarc_result": "PASS"
    }

    res = analyze_headers(
        from_name="CEO",
        from_address="ceo@company.com",
        from_domain="company.com",
        reply_to=None,
        return_path=None,
        hops=[],
        auth_results=untrusted_auth,
        recipient_domain="company.com"
    )

    findings = res.get("findings", [])
    assert any(f["code"] == "UNTRUSTED_AUTH_RESULTS_HEADER" for f in findings)
    assert res.get("auth_summary", {}).get("all_passed") is False

def test_B18_header_anomalies_and_injection():
    raw_headers = [
        ("From", "admin@company.com"),
        ("From", "attacker@spoof.com"),  # Duplicate From header
        ("Subject", "Urgent Invoice\r\nBcc: evil@hacker.com"),  # Header injection attempt
        ("Date", "Tue, 22 Sep 2026 10:00:00 +0000")
    ]
    findings = detect_header_anomalies(raw_headers)
    assert any(f["code"] == "DUPLICATE_CRITICAL_HEADER" for f in findings)
    assert any(f["code"] == "HEADER_INJECTION_DETECTED" for f in findings)

def test_B19_date_skew_and_message_id_discrepancy():
    # Date in far past (e.g. year 2010)
    past_date = "Mon, 10 Jan 2010 12:00:00 +0000"
    res = analyze_headers(
        from_name="Support",
        from_address="support@bank.com",
        from_domain="bank.com",
        reply_to=None,
        return_path=None,
        hops=[],
        auth_results=None,
        message_id="<12345@unrelated-spammer-domain.xyz>",
        date_header=past_date
    )

    findings = res.get("findings", [])
    assert any(f["code"] == "DATE_HEADER_ANOMALY" for f in findings)
    assert any(f["code"] == "MESSAGE_ID_DOMAIN_MISMATCH" for f in findings)

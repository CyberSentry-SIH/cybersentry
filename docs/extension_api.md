# Browser Extension Fast-Path API (F01)

## Overview
CyberSentry exposes a dedicated fast-path API designed specifically for Chrome, Firefox, and Edge browser extensions. It evaluates header spoofing, malicious URLs, lookalike domains, and urgency intent within a sub-500ms response window.

## Endpoint

`POST /api/v1/extension/scan`

### Headers
- `Content-Type: application/json`
- `X-API-Key: <SOC_ANALYST_API_KEY>`

### Request Body
```json
{
  "subject": "Urgent: Update your SBI Bank KYC immediately",
  "from_address": "security@sbi-kyc-update.com",
  "from_name": "State Bank of India",
  "body_text": "Dear customer, your bank account will be blocked within 24 hours. Update KYC here: http://sbi-kyc-update.com/login",
  "urls": ["http://sbi-kyc-update.com/login"]
}
```

### Response (<500ms)
```json
{
  "verdict": "PHISHING",
  "risk_score": 88.5,
  "risk_band": "CRITICAL",
  "scan_duration_ms": 14.2,
  "reasons": [
    "Brand keyword 'sbi' embedded in unauthorized domain 'sbi-kyc-update.com'",
    "High urgency credential harvesting keywords detected."
  ],
  "threat_indicators": [
    {
      "type": "LOOKALIKE_BRAND_DOMAIN",
      "severity": "CRITICAL",
      "score": 40.0
    }
  ],
  "recommended_action": "BLOCK_SENDER_AND_WARN_USER"
}
```

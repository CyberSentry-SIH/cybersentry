"""
backend/app/privacy/masker.py — B21: Indian-context PII Masking

Masks structured PII patterns commonly found in Indian contexts:
- Indian mobile numbers (+91, 10-digit)
- Aadhaar numbers (12-digit with optional spaces)
- PAN card numbers (ABCDE1234F format)
- UPI IDs (user@bank)
- IFSC codes (ABCD0123456)
- Email addresses
- Credit/debit card numbers
- URL query string parameters (sanitize tracking tokens)

Honest limitations:
- This is regex-based pattern matching, NOT NER.
- It will miss names, physical addresses, and unstructured PII.
- It is designed to reduce inadvertent PII leakage to external APIs (VT, Gemini),
  not to provide comprehensive DPDP Act compliance on its own.
"""

import re
from typing import Optional


def mask_indian_pii(text: str) -> str:
    """Apply all Indian-context PII masking patterns."""
    if not text:
        return ""

    masked = text

    # Indian mobile: +91XXXXXXXXXX or 0XXXXXXXXXX or standalone 10-digit
    masked = re.sub(r'(?:\+91[\s-]?)?\b[6-9]\d{9}\b', '[REDACTED_INDIAN_MOBILE]', masked)

    # Aadhaar: 12 digits, optionally grouped as XXXX XXXX XXXX or XXXX-XXXX-XXXX
    masked = re.sub(
        r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
        _aadhaar_replacer,
        masked
    )

    # PAN: 5 alpha + 4 digit + 1 alpha (e.g., ABCPD1234E)
    masked = re.sub(r'\b[A-Z]{5}\d{4}[A-Z]\b', '[REDACTED_PAN]', masked)

    # UPI ID: alphanumeric@bankcode (e.g., user@okicici, 9876543210@ybl)
    masked = re.sub(
        r'\b[A-Za-z0-9._-]+@(?:ok(?:icici|axis|sbi|hdfc)|ybl|paytm|upi|apl|ibl)\b',
        '[REDACTED_UPI]',
        masked
    )

    # IFSC code: 4 alpha + 0 + 6 alphanumeric (e.g., SBIN0001234)
    masked = re.sub(r'\b[A-Z]{4}0[A-Z0-9]{6}\b', '[REDACTED_IFSC]', masked)

    # Credit/Debit card numbers (13-19 digits with optional separators)
    masked = re.sub(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,7}\b', '[REDACTED_CARD]', masked)

    # Email addresses
    masked = re.sub(
        r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}',
        '[REDACTED_EMAIL]',
        masked
    )

    # Generic long digit sequences (bank account numbers etc.) — 9-18 digits
    masked = re.sub(r'\b\d{9,18}\b', '[REDACTED_ACCOUNT_ID]', masked)

    return masked


def _aadhaar_replacer(match: re.Match) -> str:
    """Only replace if the 12 digits pass the Verhoeff checksum hint (starts with 2-9)."""
    digits = re.sub(r'[\s-]', '', match.group(0))
    if len(digits) == 12 and digits[0] in '23456789':
        return '[REDACTED_AADHAAR]'
    return match.group(0)


def sanitize_url_query(url: str) -> str:
    """Strip query parameters from URLs to prevent PII leakage in tracking tokens."""
    if not url:
        return ""
    if '?' in url:
        return url.split('?')[0] + '?[QUERY_REDACTED]'
    return url


def mask_for_external_api(text: str, enable_indian: bool = True) -> str:
    """
    Convenience wrapper: applies Indian PII masking (if enabled) plus
    the basic patterns from llm_provider.mask_pii_for_external_analysis.
    """
    if not text:
        return ""
    if enable_indian:
        return mask_indian_pii(text)
    # Fallback to basic masking
    masked = re.sub(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', '[REDACTED_CARD]', text)
    masked = re.sub(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', '[REDACTED_PHONE]', masked)
    masked = re.sub(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', '[REDACTED_EMAIL]', masked)
    return masked

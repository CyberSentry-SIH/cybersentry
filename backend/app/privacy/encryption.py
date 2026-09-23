"""
backend/app/privacy/encryption.py — F13: Evidence Encryption at Rest & Compliance Controls

Provides AES-256 / Fernet symmetric encryption for raw EML evidence payloads and sensitive message bodies.
"""

import os
import base64
import hashlib
from typing import Optional
from cryptography.fernet import Fernet
from backend.app.core.config import settings


def _get_encryption_cipher() -> Fernet:
    """Derive 32-byte Fernet key from configured secret or generate deterministic fallback."""
    raw_key = getattr(settings, "EVIDENCE_ENCRYPTION_KEY", None) or settings.SECRET_KEY or "cybersentry-evidence-default-key-32b!"
    derived_32 = hashlib.sha256(raw_key.encode("utf-8")).digest()
    b64_key = base64.urlsafe_b64encode(derived_32)
    return Fernet(b64_key)


def encrypt_evidence_payload(raw_bytes: bytes) -> bytes:
    """Encrypt raw EML bytes before writing to evidence vault storage."""
    if not raw_bytes:
        return b""
    cipher = _get_encryption_cipher()
    return cipher.encrypt(raw_bytes)


def decrypt_evidence_payload(encrypted_bytes: bytes) -> bytes:
    """Decrypt stored evidence payload for authorized forensic analysis."""
    if not encrypted_bytes:
        return b""
    cipher = _get_encryption_cipher()
    return cipher.decrypt(encrypted_bytes)

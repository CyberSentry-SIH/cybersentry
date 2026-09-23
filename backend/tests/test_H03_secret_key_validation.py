import pytest
import secrets
import jwt
from pydantic import ValidationError
from backend.app.core.config import Settings, DEFAULT_INSECURE_SECRET_KEY

def test_production_rejects_default_secret_key():
    with pytest.raises(ValueError, match="SECRET_KEY must not be the default"):
        Settings(ENVIRONMENT="production", SECRET_KEY=DEFAULT_INSECURE_SECRET_KEY)

def test_production_rejects_short_secret_key():
    with pytest.raises(ValueError, match="SECRET_KEY must be at least 32 bytes"):
        Settings(ENVIRONMENT="production", SECRET_KEY="short-key-12345")

def test_production_accepts_strong_secret_key():
    strong_key = secrets.token_urlsafe(32)
    s = Settings(ENVIRONMENT="production", SECRET_KEY=strong_key)
    assert s.SECRET_KEY == strong_key

def test_development_generates_random_key_if_default():
    s = Settings(ENVIRONMENT="development", SECRET_KEY=DEFAULT_INSECURE_SECRET_KEY)
    # Must not be the default insecure key
    assert s.SECRET_KEY != DEFAULT_INSECURE_SECRET_KEY
    assert len(s.SECRET_KEY) >= 32

def test_forged_jwt_signed_with_old_default_key_rejected():
    # If the app booted in dev with a generated key or in prod with a strong key,
    # a token signed with the old hard-coded default key must fail validation.
    s = Settings(ENVIRONMENT="development", SECRET_KEY=DEFAULT_INSECURE_SECRET_KEY)
    token = jwt.encode({"sub": "attacker@evil.com", "role": "ADMINISTRATOR"}, DEFAULT_INSECURE_SECRET_KEY, algorithm="HS256")
    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(token, s.SECRET_KEY, algorithms=["HS256"])

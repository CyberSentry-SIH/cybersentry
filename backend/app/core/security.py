from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
import uuid
import bcrypt
import jwt
from backend.app.core.config import settings

# Problem: timing side-channel / user enumeration fix. A valid bcrypt hash
# to check against when no matching user exists, so a nonexistent email and
# a wrong password for a real email take approximately the same amount of
# time. Without this, `if not user or not verify_password(...)` short-
# circuits instantly for nonexistent emails but does real bcrypt work (slow,
# by design) for existing ones -- an attacker can distinguish "this email
# doesn't exist" from "this email exists, wrong password" purely by
# response time, which is a user-enumeration vulnerability even though the
# error message itself is already generic.
_DUMMY_HASH_FOR_TIMING_EQUALIZATION = bcrypt.hashpw(b"not-a-real-password", bcrypt.gensalt()).decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8")[:72],
            hashed_password.encode("utf-8")
        )
    except Exception:
        return False

def get_password_hash(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8")[:72], salt).decode("utf-8")

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "jti": str(uuid.uuid4())  # B25: Unique token ID for denylist/revocation
    })
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None

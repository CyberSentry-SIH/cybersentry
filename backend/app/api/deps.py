from typing import Optional, List, Callable
from fastapi import Depends, HTTPException, status, Header, Request
from sqlalchemy.orm import Session
from backend.app.core.database import get_db
from backend.app.core.security import decode_access_token
from backend.app.models import User

def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
    authorization: Optional[str] = Header(None)
) -> User:
    token = None

    # Check Authorization header (Bearer token)
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]

    # Fallback to cookie
    if not token and "access_token" in request.cookies:
        token = request.cookies.get("access_token")

    # CRITICAL fix: this used to silently log the caller in as "the first
    # ANALYST in the database" whenever no token was present at all. That is
    # a complete authentication bypass (CWE-306) -- every endpoint that
    # depends on get_current_user (evidence upload, cases, campaigns,
    # reports, graph...) required zero credentials to use. A missing token
    # must always be rejected, never silently substituted with a real
    # account.
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token required"
        )

    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )

    user_id = payload.get("sub")
    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )
    return user

def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "ADMINISTRATOR":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator role required"
        )
    return current_user

def require_role(*allowed_roles: str) -> Callable:
    """
    B25: RBAC dependency factory.
    Usage: Depends(require_role("ADMINISTRATOR", "ANALYST"))
    """
    def _role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"One of {list(allowed_roles)} roles required. Your role: {current_user.role}"
            )
        return current_user
    return _role_checker


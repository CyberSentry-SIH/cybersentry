from datetime import timedelta, datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Response
from sqlalchemy.orm import Session
from backend.app.core.database import get_db
from backend.app.core.security import verify_password, create_access_token, _DUMMY_HASH_FOR_TIMING_EQUALIZATION
from backend.app.core.config import settings
from backend.app.models import User, SessionModel
from backend.app.schemas import LoginRequest, TokenResponse, UserResponse
from backend.app.api.deps import get_current_user

router = APIRouter(prefix="/auth", tags=["Authentication"])

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)

@router.post("/login", response_model=TokenResponse)
def login(req: LoginRequest, response: Response, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email.strip().lower()).first()
    now = datetime.now(timezone.utc)

    # Brute-force lockout: reject outright while locked, before even
    # touching the password. We still return the same generic message as
    # any other failure so a locked-out attacker can't distinguish
    # "wrong password" from "locked" and use that as a signal either.
    if user and user.locked_until and user.locked_until > now:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    # Timing side-channel fix: always run bcrypt against SOME hash, real or
    # dummy, so a nonexistent email takes the same time as a wrong password
    # for a real one.
    hash_to_check = user.password_hash if user else _DUMMY_HASH_FOR_TIMING_EQUALIZATION
    password_ok = verify_password(req.password, hash_to_check)

    if not user or not password_ok:
        if user:
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
                user.locked_until = now + LOCKOUT_DURATION
            db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive."
        )

    # Successful login clears any accumulated lockout state.
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()

    access_token = create_access_token(data={"sub": user.id, "email": user.email, "role": user.role})

    # Set HttpOnly cookie
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )

    return TokenResponse(
        access_token=access_token,
        user=UserResponse.model_validate(user)
    )

@router.post("/logout")
def logout(response: Response):
    response.delete_cookie("access_token")
    return {"message": "Logged out successfully."}

@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    return UserResponse.model_validate(current_user)

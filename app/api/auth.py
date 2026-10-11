import hashlib
import os

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.database.models import AuthToken, User
from app.monitor.sentinel import record_local_event
from app.security.passwords import (
    hash_password,
    verify_password,
)
from app.services.audit_log import record_event
from app.services.auth import create_auth_token
from app.services.auth import get_current_user


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)

optional_bearer = HTTPBearer(auto_error=False)


class RegisterRequest(BaseModel):
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/register")
def register(
    request: RegisterRequest,
    db: Session = Depends(get_db),
):
    existing_user = (
        db.query(User)
        .filter(
            User.username == request.username
        )
        .first()
    )

    if existing_user:
        raise HTTPException(
            status_code=409,
            detail="Username already exists.",
        )

    configured_admin = os.environ.get("SENTINEL_ADMIN_USERNAME", "").strip()
    if configured_admin and request.username.strip().casefold() == configured_admin.casefold():
        raise HTTPException(status_code=409, detail="This username is reserved.")

    password_hash = hash_password(
        request.password
    )

    user = User(
        username=request.username,
        password_hash=password_hash,
        is_admin=False,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    record_event(
        db=db,
        event_type="user_registered",
        details=f"Registered user {user.username}.",
    )

    return {
        "message": "User registered successfully.",
        "username": user.username,
    }


def _login(request: LoginRequest, db: Session, admin_login: bool):
    user = (
        db.query(User)
        .filter(
            User.username == request.username
        )
        .first()
    )

    role_matches = bool(user and user.is_admin) == admin_login
    if not user or not role_matches or not verify_password(request.password, user.password_hash):
        record_local_event(
            "failed_auth",
            f"Failed login for {request.username}.",
        )
        record_event(
            db=db,
            event_type="LOGIN_FAILURE",
            details=f"Failed login for {request.username}.",
            actor_id=request.username,
            status="failure",
        )
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password.",
        )

    token = create_auth_token(
        db=db,
        user=user,
    )

    record_event(
        db=db,
        event_type="LOGIN_SUCCESS",
        details=f"User {user.username} logged in.",
        actor_id=user.username,
        status="success",
    )

    return {
        "message": "Login successful.",
        "username": user.username,
        "is_admin": user.is_admin,
        "access_token": token,
        "token_type": "bearer",
    }


@router.post("/login")
def login(request: LoginRequest, db: Session = Depends(get_db)):
    return _login(request, db, admin_login=False)


@router.post("/admin/login")
def admin_login(request: LoginRequest, db: Session = Depends(get_db)):
    return _login(request, db, admin_login=True)


@router.get("/me")
def get_current_account(current_user=Depends(get_current_user)):
    return {"username": current_user.username, "is_admin": current_user.is_admin}


@router.post("/logout")
def logout(
    credentials: HTTPAuthorizationCredentials | None = Depends(
        optional_bearer
    ),
    db: Session = Depends(get_db),
):
    if credentials is None:
        return {"message": "Logged out."}

    token_hash = hashlib.sha256(
        credentials.credentials.encode("utf-8")
    ).hexdigest()

    deleted = (
        db.query(AuthToken)
        .filter(AuthToken.token_hash == token_hash)
        .delete()
    )
    db.commit()

    if deleted:
        record_event(
            db=db,
            event_type="user_logout",
            details="User logged out and token revoked.",
        )

    return {"message": "Logged out."}

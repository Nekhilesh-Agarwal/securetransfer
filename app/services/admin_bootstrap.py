"""Provision the non-self-registering administrator from deployment secrets."""

import os

from sqlalchemy.orm import Session

from app.database.connection import SessionLocal
from app.database.models import AuthToken, User
from app.security.passwords import hash_password, verify_password


def ensure_admin_account() -> None:
    username = os.environ.get("SENTINEL_ADMIN_USERNAME", "").strip()
    password = os.environ.get("SENTINEL_ADMIN_PASSWORD", "")
    if not username and not password:
        return
    if not username or not password:
        raise RuntimeError(
            "Set both SENTINEL_ADMIN_USERNAME and SENTINEL_ADMIN_PASSWORD, or neither."
        )
    if len(password.encode("utf-8")) > 72:
        raise RuntimeError("SENTINEL_ADMIN_PASSWORD must be at most 72 bytes for bcrypt.")

    db: Session = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if user is None:
            user = User(
                username=username,
                password_hash=hash_password(password),
                is_admin=True,
            )
            db.add(user)
            db.commit()
            return

        changed = not user.is_admin or not verify_password(password, user.password_hash)
        user.is_admin = True
        if changed:
            user.password_hash = hash_password(password)
            db.query(AuthToken).filter(AuthToken.user_id == user.id).delete()
        db.commit()
    finally:
        db.close()

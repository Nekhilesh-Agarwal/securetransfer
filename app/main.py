import os
from urllib.parse import urlsplit

from fastapi.middleware.cors import CORSMiddleware

from app.security.device_identity import (
    generate_device_identity,
    get_public_key_base64,
    get_public_key_fingerprint,
)
from fastapi import FastAPI

from app.api.audit import router as audit_router
from app.api.admin import router as admin_router
from app.api.auth import router as auth_router
from app.api.messages import router as messages_router
from app.api.security import router as security_router
from app.api.sessions import router as sessions_router
from app.database.connection import Base, engine
from app.database.init_db import init_db
from app.api.binary import router as binary_router
from app.api.files import router as files_router
from app.api.voice import router as voice_router
from app.api.devices import router as devices_router
from app.middleware.rate_limit import RateLimitMiddleware
from app.services.admin_bootstrap import ensure_admin_account

os.environ.setdefault("SENTINEL_DEVICE_NAME", "SecureTransfer-A")

generate_device_identity()

LAN_ORIGIN_REGEX = (
    r"https?://("
    r"localhost|127\.0\.0\.1|\[::1\]|"
    r"192\.168\.\d{1,3}\.\d{1,3}|"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|"
    r"169\.254\.\d{1,3}\.\d{1,3}"
    r")(:\d+)?$"
)


def _configured_cors_origins() -> list[str]:
    """Normalize configured site URLs to browser Origin values (no trailing slash/path)."""
    origins = []
    for candidate in os.environ.get("SENTINEL_ALLOWED_ORIGINS", "").split(","):
        candidate = candidate.strip().strip("\"'")
        if not candidate:
            continue
        parsed = urlsplit(candidate)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            origins.append(f"{parsed.scheme}://{parsed.netloc}")
    return origins

app = FastAPI(
    title="SecureTransfer",
    description="Offline Secure Text, Image and Voice Transfer",
    version="0.2.0",
)

app.add_middleware(RateLimitMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
        *_configured_cors_origins(),
    ],
    allow_origin_regex=LAN_ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Base.metadata.create_all(bind=engine)
init_db()
ensure_admin_account()

app.include_router(auth_router)
app.include_router(messages_router)
app.include_router(sessions_router)
app.include_router(binary_router)
app.include_router(files_router)
app.include_router(voice_router)
app.include_router(devices_router)
app.include_router(audit_router)
app.include_router(admin_router)
app.include_router(security_router)


@app.get("/")
async def root():
    return {
        "application": "SecureTransfer",
        "device": os.environ.get("SENTINEL_DEVICE_NAME", "SecureTransfer"),
        "status": "running",
        "version": "0.2.0",
    }


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.get("/device/identity")
async def device_identity():
    return {
        "device": os.environ.get("SENTINEL_DEVICE_NAME", "SecureTransfer"),
        "public_key": get_public_key_base64(),
        "fingerprint": get_public_key_fingerprint(),
    }

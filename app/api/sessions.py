import base64
import secrets

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.database.models import User
from app.security.device_identity import (
    get_public_key_base64,
    load_private_key,
)
from app.security.key_exchange import deserialize_public_key
from app.services.auth import get_current_user
from app.services.handshake_manager import (
    PendingHandshake,
    handshake_manager,
)
from app.services.session_establishment import (
    establish_authenticated_session,
    generate_ephemeral_key_pair,
)
from app.services.session_manager import session_manager
from app.monitor.sentinel import record_local_event
from app.services.audit_log import record_event
from app.services.trusted_devices import get_trusted_device
from app.services.user_identity import (
    ensure_user_identity,
    find_identity_by_public_key,
    load_user_private_key,
    load_user_public_key_bytes,
)


router = APIRouter(prefix="/sessions", tags=["Sessions"])


class SessionEstablishRequest(BaseModel):
    device_public_key: str
    ephemeral_public_key: str
    session_id: str | None = None


class SessionInitiateRequest(BaseModel):
    device_public_key: str


class SessionFinalizeRequest(BaseModel):
    session_id: str
    peer_ephemeral_public_key: str


@router.post("/initiate")
def initiate_secure_session(
    request: SessionInitiateRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Start a secure session with a trusted device."""

    trusted_device = get_trusted_device(
        db=db,
        public_key=request.device_public_key,
    )

    if trusted_device is None:
        record_local_event("untrusted", "Session initiate rejected.")
        record_event(
            db=db,
            event_type="untrusted_session",
            details="Rejected session initiate from an untrusted device.",
        )
        raise HTTPException(
            status_code=403,
            detail="Device is not trusted.",
        )

    try:
        peer_static_public_key = base64.b64decode(
            request.device_public_key,
            validate=True,
        )

        deserialize_public_key(peer_static_public_key)

        local_ephemeral_private_key, local_ephemeral_public_key = (
            generate_ephemeral_key_pair()
        )

        session_id = secrets.token_urlsafe(32)
        identity = ensure_user_identity(db, current_user)

        handshake_manager.add(
            PendingHandshake(
                session_id=session_id,
                peer_static_public_key=peer_static_public_key,
                local_ephemeral_private_key=local_ephemeral_private_key,
            )
        )

        return {
            "session_id": session_id,
            "device_public_key": identity.public_key,
            "ephemeral_public_key": base64.b64encode(
                local_ephemeral_public_key
            ).decode("ascii"),
        }

    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc


@router.post("/establish")
def establish_secure_session(
    request: SessionEstablishRequest,
    db: Session = Depends(get_db),
):
    """
    Respond to a secure session initiation.

    The initiator supplies its static and ephemeral public keys.
    This device generates its own ephemeral key pair and derives
    the shared session key.
    """

    trusted_device = get_trusted_device(
        db=db,
        public_key=request.device_public_key,
    )

    if trusted_device is None:
        record_local_event("untrusted", "Session establish rejected.")
        record_event(
            db=db,
            event_type="untrusted_session",
            details="Rejected session establish from an untrusted device.",
        )
        raise HTTPException(
            status_code=403,
            detail="Device is not trusted.",
        )

    try:
        peer_static_public_key = base64.b64decode(
            request.device_public_key,
            validate=True,
        )

        peer_ephemeral_public_key = base64.b64decode(
            request.ephemeral_public_key,
            validate=True,
        )

        deserialize_public_key(peer_static_public_key)
        deserialize_public_key(peer_ephemeral_public_key)

        local_static_private_key = load_private_key()

        local_ephemeral_private_key, local_ephemeral_public_key = (
            generate_ephemeral_key_pair()
        )

        session_id = request.session_id or secrets.token_urlsafe(32)

        session = establish_authenticated_session(
            local_static_private_key=local_static_private_key,
            peer_static_public_key_bytes=peer_static_public_key,
            local_ephemeral_private_key=local_ephemeral_private_key,
            peer_ephemeral_public_key_bytes=peer_ephemeral_public_key,
            session_id=session_id,
        )

        session_manager.add_session(session)

        record_event(
            db=db,
            event_type="SESSION_ESTABLISHED",
            session_id=session.session_id,
            details="Authenticated session established.",
            status="success",
        )

        return {
            "session_id": session.session_id,
            "device_public_key": get_public_key_base64(),
            "ephemeral_public_key": base64.b64encode(
                local_ephemeral_public_key
            ).decode("ascii"),
        }

    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc


@router.post("/finalize")
def finalize_secure_session(
    request: SessionFinalizeRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Complete a session initiated by this device."""

    pending = handshake_manager.remove(request.session_id)

    if pending is None:
        raise HTTPException(
            status_code=404,
            detail="Pending handshake not found.",
        )

    try:
        peer_ephemeral_public_key = base64.b64decode(
            request.peer_ephemeral_public_key,
            validate=True,
        )

        deserialize_public_key(peer_ephemeral_public_key)

        identity = ensure_user_identity(db, current_user)
        local_static_private_key = load_user_private_key(current_user.id)

        session = establish_authenticated_session(
            local_static_private_key=local_static_private_key,
            peer_static_public_key_bytes=pending.peer_static_public_key,
            local_ephemeral_private_key=pending.local_ephemeral_private_key,
            peer_ephemeral_public_key_bytes=peer_ephemeral_public_key,
            session_id=pending.session_id,
        )

        session_manager.add_session(session)
        session_manager.add_session_view(session, current_user.id)

        record_event(
            db=db,
            event_type="SESSION_ESTABLISHED",
            session_id=session.session_id,
            details="Authenticated session finalized.",
            actor_id=current_user.username,
            status="success",
        )

        return {
            "session_id": session.session_id,
            "device_public_key": identity.public_key,
            "message": "Secure session established.",
        }

    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc


class SessionOpenRequest(BaseModel):
    device_public_key: str


@router.post("/open")
def open_secure_session(
    request: SessionOpenRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Establish a bidirectional session with a trusted peer.

    When the peer identity also lives on this server, both
    X25519/HKDF session views are created locally so each
    client keeps independent send/receive sequence state.
    """

    trusted_device = get_trusted_device(
        db=db,
        public_key=request.device_public_key,
    )
    if trusted_device is None:
        record_local_event("untrusted", "Session open rejected.")
        record_event(
            db=db,
            event_type="untrusted_session",
            details="Rejected session open from an untrusted device.",
            actor_id=current_user.username,
            status="failure",
        )
        raise HTTPException(
            status_code=403,
            detail="Device is not trusted.",
        )

    local_identity = ensure_user_identity(db, current_user)
    peer_identity = find_identity_by_public_key(db, request.device_public_key)
    if peer_identity is None:
        raise HTTPException(
            status_code=404,
            detail="Peer identity is not registered on this server.",
        )

    peer_user = db.query(User).filter(User.id == peer_identity.user_id).first()
    if peer_user is None:
        raise HTTPException(
            status_code=404,
            detail="Peer account no longer exists.",
        )
    peer_identity = ensure_user_identity(db, peer_user)
    if peer_identity.public_key != request.device_public_key:
        raise HTTPException(
            status_code=409,
            detail=(
                "The peer's device identity changed. Pair the updated "
                "fingerprint on both accounts, then try again."
            ),
        )

    if get_trusted_device(db=db, public_key=local_identity.public_key) is None:
        raise HTTPException(
            status_code=403,
            detail=(
                "The other device must also confirm your fingerprint "
                "before a session can start."
            ),
        )

    existing = session_manager.find_session_between(
        current_user.id,
        peer_identity.user_id,
    )
    if existing is not None:
        return {
            "session_id": existing,
            "message": "Secure session already established.",
        }

    try:
        peer_static_public_key = base64.b64decode(
            request.device_public_key,
            validate=True,
        )
        deserialize_public_key(peer_static_public_key)

        initiator_eph_private, initiator_eph_public = generate_ephemeral_key_pair()
        responder_eph_private, responder_eph_public = generate_ephemeral_key_pair()
        session_id = secrets.token_urlsafe(32)

        initiator_session = establish_authenticated_session(
            local_static_private_key=load_user_private_key(current_user.id),
            peer_static_public_key_bytes=peer_static_public_key,
            local_ephemeral_private_key=initiator_eph_private,
            peer_ephemeral_public_key_bytes=responder_eph_public,
            session_id=session_id,
        )
        responder_session = establish_authenticated_session(
            local_static_private_key=load_user_private_key(peer_identity.user_id),
            peer_static_public_key_bytes=load_user_public_key_bytes(current_user.id),
            local_ephemeral_private_key=responder_eph_private,
            peer_ephemeral_public_key_bytes=initiator_eph_public,
            session_id=session_id,
        )

        session_manager.add_session(initiator_session)
        session_manager.add_session_view(initiator_session, current_user.id)
        session_manager.add_session_view(responder_session, peer_identity.user_id)
        session_manager.bind_users(
            session_id,
            current_user.id,
            peer_identity.user_id,
        )

        record_event(
            db=db,
            event_type="SESSION_ESTABLISHED",
            session_id=session_id,
            details="Bidirectional authenticated session established.",
            actor_id=current_user.username,
            status="success",
        )

        return {
            "session_id": session_id,
            "message": "Secure session established.",
        }
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

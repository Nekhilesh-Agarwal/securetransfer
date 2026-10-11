import base64
import hashlib
import uuid

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient

from app.database.connection import SessionLocal
from app.database.models import TrustedDevice
from app.main import app
from app.services.session_establishment import (
    establish_authenticated_session,
    generate_ephemeral_key_pair,
)
from app.services.session_manager import session_manager


client = TestClient(app)


def _serialize_public_key(public_key) -> bytes:
    return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def _fingerprint(public_key_bytes: bytes) -> str:
    digest = hashlib.sha256(public_key_bytes).hexdigest()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def _auth_headers():
    username = f"hs_{uuid.uuid4().hex[:8]}"
    password = "TestPassword123!"
    client.post("/auth/register", json={"username": username, "password": password})
    login = client.post(
        "/auth/login",
        json={"username": username, "password": password},
    )
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def test_full_initiate_finalize_handshake():
    headers = _auth_headers()
    peer_static_private = X25519PrivateKey.generate()
    peer_static_public = _serialize_public_key(peer_static_private.public_key())
    peer_static_b64 = base64.b64encode(peer_static_public).decode("ascii")

    db = SessionLocal()
    session_id = None
    try:
        db.add(
            TrustedDevice(
                device_name="Handshake Peer",
                public_key=peer_static_b64,
                fingerprint=_fingerprint(peer_static_public),
                trusted=True,
            )
        )
        db.commit()

        initiate = client.post(
            "/sessions/initiate",
            headers=headers,
            json={"device_public_key": peer_static_b64},
        )
        assert initiate.status_code == 200
        body = initiate.json()
        session_id = body["session_id"]

        peer_eph_private, peer_eph_public = generate_ephemeral_key_pair()
        local_static = base64.b64decode(body["device_public_key"], validate=True)
        initiator_eph = base64.b64decode(body["ephemeral_public_key"], validate=True)

        peer_session = establish_authenticated_session(
            local_static_private_key=peer_static_private,
            peer_static_public_key_bytes=local_static,
            local_ephemeral_private_key=peer_eph_private,
            peer_ephemeral_public_key_bytes=initiator_eph,
            session_id=session_id,
        )

        finalize = client.post(
            "/sessions/finalize",
            headers=headers,
            json={
                "session_id": session_id,
                "peer_ephemeral_public_key": base64.b64encode(
                    peer_eph_public
                ).decode("ascii"),
            },
        )
        assert finalize.status_code == 200
        local_session = session_manager.get_session(session_id)
        assert local_session is not None
        assert local_session.session_key == peer_session.session_key
    finally:
        db.query(TrustedDevice).filter(
            TrustedDevice.public_key == peer_static_b64
        ).delete()
        db.commit()
        db.close()
        if session_id:
            session_manager.remove_session(session_id)

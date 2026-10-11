import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)
from fastapi.testclient import TestClient

from app.database.connection import SessionLocal
from app.database.models import TrustedDevice
from app.main import app
from app.security.device_identity import load_public_key
from app.services.session_establishment import (
    establish_authenticated_session,
    generate_ephemeral_key_pair,
)
from app.services.session_manager import session_manager


client = TestClient(app)


def _serialize_public_key(public_key) -> bytes:
    return public_key.public_bytes(
        Encoding.Raw,
        PublicFormat.Raw,
    )


def _fingerprint(public_key_bytes: bytes) -> str:
    digest = hashlib.sha256(public_key_bytes).hexdigest()

    return ":".join(
        digest[i:i + 2]
        for i in range(0, len(digest), 2)
    )


def test_untrusted_device_cannot_establish_session():
    ephemeral_private_key, ephemeral_public_key = (
        generate_ephemeral_key_pair()
    )

    ephemeral_public_key_b64 = base64.b64encode(
        ephemeral_public_key
    ).decode("ascii")

    response = client.post(
        "/sessions/establish",
        json={
            "device_public_key": "untrusted-device-key",
            "ephemeral_public_key": ephemeral_public_key_b64,
        },
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Device is not trusted."


def test_trusted_device_can_establish_session():
    peer_static_private_key = X25519PrivateKey.generate()
    peer_static_public_key = peer_static_private_key.public_key()

    peer_static_public_key_bytes = _serialize_public_key(
        peer_static_public_key
    )

    peer_static_public_key_b64 = base64.b64encode(
        peer_static_public_key_bytes
    ).decode("ascii")

    peer_ephemeral_private_key, peer_ephemeral_public_key_bytes = (
        generate_ephemeral_key_pair()
    )

    peer_ephemeral_public_key_b64 = base64.b64encode(
        peer_ephemeral_public_key_bytes
    ).decode("ascii")

    db = SessionLocal()

    try:
        trusted_device = TrustedDevice(
            device_name="API Test Device",
            public_key=peer_static_public_key_b64,
            fingerprint=_fingerprint(peer_static_public_key_bytes),
            trusted=True,
        )

        db.add(trusted_device)
        db.commit()

        response = client.post(
            "/sessions/establish",
            json={
                "device_public_key": peer_static_public_key_b64,
                "ephemeral_public_key": peer_ephemeral_public_key_b64,
            },
        )

        assert response.status_code == 200

        data = response.json()

        assert data["session_id"]
        assert data["ephemeral_public_key"]

        server_ephemeral_public_key = base64.b64decode(
            data["ephemeral_public_key"],
            validate=True,
        )

        local_static_public_key = load_public_key()

        peer_session = establish_authenticated_session(
            local_static_private_key=peer_static_private_key,
            peer_static_public_key_bytes=local_static_public_key,
            local_ephemeral_private_key=peer_ephemeral_private_key,
            peer_ephemeral_public_key_bytes=server_ephemeral_public_key,
            session_id=data["session_id"],
        )

        server_session = session_manager.get_session(
            data["session_id"]
        )

        assert server_session is not None
        assert (
            server_session.session_key
            == peer_session.session_key
        )
        assert (
            server_session.session_id
            == peer_session.session_id
        )

    finally:
        db.query(TrustedDevice).filter(
            TrustedDevice.public_key
            == peer_static_public_key_b64
        ).delete()

        db.commit()
        db.close()

        session_manager.remove_session(
            data["session_id"]
            if "data" in locals() and "session_id" in data
            else ""
        )


def test_revoked_device_cannot_establish_session():
    peer_static_private_key = X25519PrivateKey.generate()
    peer_static_public_key_bytes = _serialize_public_key(
        peer_static_private_key.public_key()
    )

    peer_static_public_key_b64 = base64.b64encode(
        peer_static_public_key_bytes
    ).decode("ascii")

    peer_ephemeral_private_key, peer_ephemeral_public_key = (
        generate_ephemeral_key_pair()
    )

    peer_ephemeral_public_key_b64 = base64.b64encode(
        peer_ephemeral_public_key
    ).decode("ascii")

    db = SessionLocal()

    try:
        trusted_device = TrustedDevice(
            device_name="Revoked API Test Device",
            public_key=peer_static_public_key_b64,
            fingerprint=_fingerprint(peer_static_public_key_bytes),
            trusted=False,
        )

        db.add(trusted_device)
        db.commit()

        response = client.post(
            "/sessions/establish",
            json={
                "device_public_key": peer_static_public_key_b64,
                "ephemeral_public_key": peer_ephemeral_public_key_b64,
            },
        )

        assert response.status_code == 403
        assert response.json()["detail"] == "Device is not trusted."

    finally:
        db.query(TrustedDevice).filter(
            TrustedDevice.public_key
            == peer_static_public_key_b64
        ).delete()

        db.commit()
        db.close()


def test_trusted_device_with_invalid_ephemeral_key_is_rejected():
    peer_static_private_key = X25519PrivateKey.generate()
    peer_static_public_key_bytes = _serialize_public_key(
        peer_static_private_key.public_key()
    )

    peer_static_public_key_b64 = base64.b64encode(
        peer_static_public_key_bytes
    ).decode("ascii")

    db = SessionLocal()

    try:
        trusted_device = TrustedDevice(
            device_name="Invalid Key Test Device",
            public_key=peer_static_public_key_b64,
            fingerprint=_fingerprint(peer_static_public_key_bytes),
            trusted=True,
        )

        db.add(trusted_device)
        db.commit()

        response = client.post(
            "/sessions/establish",
            json={
                "device_public_key": peer_static_public_key_b64,
                "ephemeral_public_key": "definitely-not-a-valid-key",
            },
        )

        assert response.status_code == 400

    finally:
        db.query(TrustedDevice).filter(
            TrustedDevice.public_key
            == peer_static_public_key_b64
        ).delete()

        db.commit()
        db.close()

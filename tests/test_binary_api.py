import base64
import uuid

from fastapi.testclient import TestClient

from app.database.connection import SessionLocal
from app.database.models import AuditLog
from app.main import app
from app.security.session import create_session
from app.services.message_storage import get_messages
from app.services.session_manager import session_manager


client = TestClient(app)


def create_authenticated_client():
    username = f"binary_test_{uuid.uuid4().hex[:8]}"
    password = "TestPassword123!"

    register_response = client.post(
        "/auth/register",
        json={
            "username": username,
            "password": password,
        },
    )

    assert register_response.status_code == 200

    login_response = client.post(
        "/auth/login",
        json={
            "username": username,
            "password": password,
        },
    )

    assert login_response.status_code == 200

    token = login_response.json()["access_token"]

    return {
        "Authorization": f"Bearer {token}"
    }


def test_send_binary_without_session():
    headers = create_authenticated_client()

    response = client.post(
        "/binary/send",
        headers=headers,
        json={
            "session_id": "missing-session",
            "data": base64.b64encode(
                b"test image"
            ).decode("ascii"),
            "message_type": "image",
        },
    )

    assert response.status_code == 404


def test_send_binary_requires_authentication():
    response = client.post(
        "/binary/send",
        json={
            "session_id": "missing-session",
            "data": base64.b64encode(
                b"test image"
            ).decode("ascii"),
            "message_type": "image",
        },
    )

    assert response.status_code == 401


def test_send_binary():
    headers = create_authenticated_client()

    session_id = f"binary-api-send-{uuid.uuid4()}"

    session = create_session(
        b"a" * 32,
        session_id=session_id,
    )

    session_manager.add_session(session)

    try:
        original_data = (
            b"\x89PNG\r\n\x1a\n"
            b"fake-image-data"
        )

        response = client.post(
            "/binary/send",
            headers=headers,
            json={
                "session_id": session_id,
                "data": base64.b64encode(
                    original_data
                ).decode("ascii"),
                "message_type": "image",
                "filename": "photo.png",
                "mime_type": "image/png",
            },
        )

        assert response.status_code == 200

        body = response.json()

        assert body["session_id"] == session_id
        assert body["sequence_number"] == 0
        assert body["message_type"] == "image"
        assert body["filename"] == "photo.png"
        assert body["mime_type"] == "image/png"
        assert body["file_size"] == len(original_data)
        assert body["nonce"]
        assert body["ciphertext"]

        assert bytes.fromhex(
            body["ciphertext"]
        ) != original_data

        db = SessionLocal()

        try:
            messages = get_messages(
                db,
                session_id,
            )

            assert len(messages) == 1
            assert messages[0].session_id == session_id
            assert messages[0].sequence_number == 0
            assert messages[0].message_type == "image"

            audit_entries = (
                db.query(AuditLog)
                .filter(
                    AuditLog.session_id == session_id
                )
                .all()
            )

            assert len(audit_entries) == 1
            assert (
                audit_entries[0].event_type
                == "binary_sent"
            )

        finally:
            db.close()

    finally:
        session_manager.remove_session(
            session_id
        )


def test_receive_binary():
    headers = create_authenticated_client()

    session_id = (
        f"binary-api-receive-{uuid.uuid4()}"
    )

    sender = create_session(
        b"b" * 32,
        session_id=session_id,
    )

    receiver = create_session(
        b"b" * 32,
        session_id=session_id,
    )

    session_manager.add_session(receiver)

    try:
        from app.services.binary_message import (
            encrypt_binary_message,
        )

        original_data = (
            b"\x00\x01\x02\x03audio-data"
        )

        filename = "recording.wav"
        mime_type = "audio/wav"

        encrypted = encrypt_binary_message(
            sender,
            original_data,
            "audio",
            filename=filename,
            mime_type=mime_type,
        )

        response = client.post(
            "/binary/receive",
            headers=headers,
            json={
                "session_id": encrypted.session_id,
                "sequence_number": encrypted.sequence_number,
                "message_type": encrypted.message_type,
                "filename": encrypted.filename,
                "mime_type": encrypted.mime_type,
                "file_size": encrypted.file_size,
                "nonce": encrypted.nonce.hex(),
                "ciphertext": encrypted.ciphertext.hex(),
            },
        )

        assert response.status_code == 200

        body = response.json()

        assert body["session_id"] == session_id
        assert body["sequence_number"] == 0
        assert body["message_type"] == "audio"
        assert body["filename"] == filename
        assert body["mime_type"] == mime_type
        assert body["file_size"] == len(original_data)

        assert base64.b64decode(
            body["data"]
        ) == original_data

        db = SessionLocal()

        try:
            messages = get_messages(
                db,
                session_id,
            )

            assert len(messages) == 1
            assert messages[0].session_id == session_id
            assert messages[0].sequence_number == 0
            assert messages[0].message_type == "audio"

            audit_entries = (
                db.query(AuditLog)
                .filter(
                    AuditLog.session_id == session_id
                )
                .all()
            )

            assert len(audit_entries) == 1
            assert (
                audit_entries[0].event_type
                == "binary_received"
            )

        finally:
            db.close()

    finally:
        session_manager.remove_session(
            session_id
        )


def test_receive_binary_rejects_replay():
    headers = create_authenticated_client()

    session_id = (
        f"binary-api-replay-{uuid.uuid4()}"
    )

    sender = create_session(
        b"c" * 32,
        session_id=session_id,
    )

    receiver = create_session(
        b"c" * 32,
        session_id=session_id,
    )

    session_manager.add_session(receiver)

    try:
        from app.services.binary_message import (
            encrypt_binary_message,
        )

        original_data = b"secret-image"

        encrypted = encrypt_binary_message(
            sender,
            original_data,
            "image",
            filename="secret.png",
            mime_type="image/png",
        )

        payload = {
            "session_id": encrypted.session_id,
            "sequence_number": encrypted.sequence_number,
            "message_type": encrypted.message_type,
            "filename": encrypted.filename,
            "mime_type": encrypted.mime_type,
            "file_size": encrypted.file_size,
            "nonce": encrypted.nonce.hex(),
            "ciphertext": encrypted.ciphertext.hex(),
        }

        first_response = client.post(
            "/binary/receive",
            headers=headers,
            json=payload,
        )

        assert first_response.status_code == 200

        replay_response = client.post(
            "/binary/receive",
            headers=headers,
            json=payload,
        )

        assert replay_response.status_code == 400
        assert "Replay detected" in (
            replay_response.json()["detail"]
        )

    finally:
        session_manager.remove_session(
            session_id
        )

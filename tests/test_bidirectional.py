import uuid

from fastapi.testclient import TestClient

from app.database.connection import SessionLocal
from app.database.models import User
from app.main import app
from app.services.session_manager import session_manager
from app.services.user_identity import ensure_user_identity


client = TestClient(app)


def _register_and_login(prefix: str) -> tuple[dict, str]:
    username = f"{prefix}_{uuid.uuid4().hex[:8]}"
    password = "TestPassword123!"
    register = client.post(
        "/auth/register",
        json={"username": username, "password": password},
    )
    assert register.status_code == 200
    login = client.post(
        "/auth/login",
        json={"username": username, "password": password},
    )
    assert login.status_code == 200
    return (
        {"Authorization": f"Bearer {login.json()['access_token']}"},
        username,
    )


def _pair_users(headers_a, headers_b):
    pairing_a = client.get("/devices/me/pairing", headers=headers_a).json()
    pairing_b = client.get("/devices/me/pairing", headers=headers_b).json()
    confirm_a = client.post(
        "/devices/pairing/confirm",
        headers=headers_a,
        json={
            "payload": pairing_b["payload"],
            "fingerprint": pairing_b["fingerprint"],
        },
    )
    confirm_b = client.post(
        "/devices/pairing/confirm",
        headers=headers_b,
        json={
            "payload": pairing_a["payload"],
            "fingerprint": pairing_a["fingerprint"],
        },
    )
    assert confirm_a.status_code == 200
    assert confirm_b.status_code == 200
    return pairing_a, pairing_b


def test_bidirectional_text_between_two_users():
    headers_a, _ = _register_and_login("alice")
    headers_b, _ = _register_and_login("bob")
    pairing_a, pairing_b = _pair_users(headers_a, headers_b)

    open_a = client.post(
        "/sessions/open",
        headers=headers_a,
        json={"device_public_key": pairing_b["public_key"]},
    )
    assert open_a.status_code == 200
    session_id = open_a.json()["session_id"]

    send_a = client.post(
        "/messages/send",
        headers=headers_a,
        json={
            "session_id": session_id,
            "message": "hello from A",
            "message_type": "text",
        },
    )
    assert send_a.status_code == 200

    pending_b = client.get("/messages/pending", headers=headers_b).json()
    incoming_b = [
        item
        for item in pending_b["messages"]
        if item.get("ciphertext") == send_a.json()["ciphertext"]
    ]
    assert incoming_b
    receive_b = client.post(
        "/messages/receive",
        headers=headers_b,
        json={
            key: incoming_b[0][key]
            for key in (
                "session_id",
                "sequence_number",
                "message_type",
                "nonce",
                "ciphertext",
            )
        },
    )
    assert receive_b.status_code == 200
    assert receive_b.json()["message"] == "hello from A"

    send_b = client.post(
        "/messages/send",
        headers=headers_b,
        json={
            "session_id": session_id,
            "message": "hello from B",
            "message_type": "text",
        },
    )
    assert send_b.status_code == 200
    assert send_b.json()["sequence_number"] == 0

    pending_a = client.get("/messages/pending", headers=headers_a).json()
    match = [
        item
        for item in pending_a["messages"]
        if item.get("sequence_number") == 0 and item.get("message_type") == "text"
        and item.get("ciphertext") == send_b.json()["ciphertext"]
    ]
    assert match
    receive_a = client.post(
        "/messages/receive",
        headers=headers_a,
        json={
            key: match[0][key]
            for key in (
                "session_id",
                "sequence_number",
                "message_type",
                "nonce",
                "ciphertext",
            )
        },
    )
    assert receive_a.status_code == 200
    assert receive_a.json()["message"] == "hello from B"

    send_a2 = client.post(
        "/messages/send",
        headers=headers_a,
        json={"session_id": session_id, "message": "second from A"},
    )
    assert send_a2.status_code == 200
    assert send_a2.json()["sequence_number"] == 1
    session_manager.remove_session(session_id)


def test_bidirectional_image_and_transcript(tmp_path, monkeypatch):
    headers_a, _ = _register_and_login("imga")
    headers_b, _ = _register_and_login("imgb")
    _, pairing_b = _pair_users(headers_a, headers_b)
    opened = client.post(
        "/sessions/open",
        headers=headers_a,
        json={"device_public_key": pairing_b["public_key"]},
    )
    session_id = opened.json()["session_id"]
    monkeypatch.setattr("app.api.files.RECEIVED_DIRECTORY", tmp_path / "received")

    send_image = client.post(
        "/files/prepare",
        headers=headers_a,
        data={
            "session_id": session_id,
            "message_type": "image",
            "mime_type": "image/png",
        },
        files={"file": ("shot.png", b"fake-png-bytes", "image/png")},
    )
    assert send_image.status_code == 200
    pending = client.get("/messages/pending", headers=headers_b).json()
    files = [item for item in pending["messages"] if item.get("transfer_kind") == "file"]
    assert files
    received = client.post(
        "/files/receive-encrypted",
        headers=headers_b,
        json={
            key: files[0][key]
            for key in (
                "session_id",
                "sequence_number",
                "message_type",
                "nonce",
                "ciphertext",
                "filename",
                "mime_type",
                "file_size",
            )
        },
    )
    assert received.status_code == 200

    send_voice = client.post(
        "/messages/send",
        headers=headers_b,
        json={
            "session_id": session_id,
            "message": "transcribed note",
            "message_type": "audio_transcript",
        },
    )
    assert send_voice.status_code == 200
    pending_a = client.get("/messages/pending", headers=headers_a).json()
    voice = [
        item
        for item in pending_a["messages"]
        if item.get("message_type") == "audio_transcript"
    ]
    assert voice
    receive_voice = client.post(
        "/messages/receive",
        headers=headers_a,
        json={
            key: voice[0][key]
            for key in (
                "session_id",
                "sequence_number",
                "message_type",
                "nonce",
                "ciphertext",
            )
        },
    )
    assert receive_voice.status_code == 200
    assert receive_voice.json()["message"] == "transcribed note"
    session_manager.remove_session(session_id)


def test_login_and_pairing_audit_events():
    headers_a, name_a = _register_and_login("audita")
    headers_b, _ = _register_and_login("auditb")
    _pair_users(headers_a, headers_b)
    events = client.get("/audit/events", headers=headers_a).json()["events"]
    types = {event["event_type"] for event in events}
    assert "LOGIN_SUCCESS" in types
    assert "DEVICE_PAIRING_SUCCESS" in types
    assert any(event.get("created_at") for event in events)
    assert any(event.get("previous_hash") or event["id"] for event in events)
    bad = client.post(
        "/auth/login",
        json={"username": name_a, "password": "wrong-password"},
    )
    assert bad.status_code == 401
    events = client.get("/audit/events", headers=headers_a).json()["events"]
    assert any(event["event_type"] == "LOGIN_FAILURE" for event in events)


def test_encryption_demo_log_disabled_by_default(tmp_path, monkeypatch):
    monkeypatch.delenv("ENABLE_ENCRYPTION_DEMO_LOG", raising=False)
    log_path = tmp_path / "encryption_demo.log"
    monkeypatch.setattr(
        "app.services.encryption_demo_log.DEMO_LOG_PATH",
        log_path,
    )
    headers_a, _ = _register_and_login("demooff")
    headers_b, _ = _register_and_login("demopeer")
    _, pairing_b = _pair_users(headers_a, headers_b)
    opened = client.post(
        "/sessions/open",
        headers=headers_a,
        json={"device_public_key": pairing_b["public_key"]},
    )
    client.post(
        "/messages/send",
        headers=headers_a,
        json={
            "session_id": opened.json()["session_id"],
            "message": "should not be logged",
        },
    )
    assert not log_path.exists()


def test_encryption_demo_log_when_enabled(tmp_path, monkeypatch):
    monkeypatch.setenv("ENABLE_ENCRYPTION_DEMO_LOG", "true")
    monkeypatch.setenv("ENCRYPTION_DEMO_INCLUDE_PLAINTEXT", "true")
    log_path = tmp_path / "encryption_demo.log"
    monkeypatch.setattr(
        "app.services.encryption_demo_log.DEMO_LOG_PATH",
        log_path,
    )
    headers_a, _ = _register_and_login("demoon")
    headers_b, _ = _register_and_login("demoonpeer")
    _, pairing_b = _pair_users(headers_a, headers_b)
    opened = client.post(
        "/sessions/open",
        headers=headers_a,
        json={"device_public_key": pairing_b["public_key"]},
    )
    send = client.post(
        "/messages/send",
        headers=headers_a,
        json={
            "session_id": opened.json()["session_id"],
            "message": "demo plaintext",
            "message_type": "text",
        },
    )
    assert send.status_code == 200
    assert log_path.exists()
    content = log_path.read_text(encoding="utf-8")
    assert "AES-256-GCM" in content
    assert "demo plaintext" in content
    assert "session_key" not in content
    session_manager.remove_session(opened.json()["session_id"])


def test_user_identities_are_distinct():
    headers_a, name_a = _register_and_login("ida")
    headers_b, name_b = _register_and_login("idb")
    pairing_a = client.get("/devices/me/pairing", headers=headers_a).json()
    pairing_b = client.get("/devices/me/pairing", headers=headers_b).json()
    assert pairing_a["public_key"] != pairing_b["public_key"]
    assert pairing_a["fingerprint"] != pairing_b["fingerprint"]
    db = SessionLocal()
    try:
        user_a = db.query(User).filter(User.username == name_a).first()
        user_b = db.query(User).filter(User.username == name_b).first()
        identity_a = ensure_user_identity(db, user_a)
        identity_b = ensure_user_identity(db, user_b)
        assert identity_a.public_key != identity_b.public_key
    finally:
        db.close()

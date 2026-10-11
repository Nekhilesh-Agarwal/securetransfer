import uuid

from fastapi.testclient import TestClient

from app.main import app
from app.security.session import create_session
from app.services.session_manager import session_manager


client = TestClient(app)


def _auth_headers():
    username = f"msg_{uuid.uuid4().hex[:8]}"
    password = "TestPassword123!"
    client.post(
        "/auth/register",
        json={"username": username, "password": password},
    )
    login = client.post(
        "/auth/login",
        json={"username": username, "password": password},
    )
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def test_send_message_requires_authentication():
    response = client.post(
        "/messages/send",
        json={"session_id": "missing-session", "message": "Hello"},
    )
    assert response.status_code == 401


def test_send_message_without_session():
    headers = _auth_headers()
    response = client.post(
        "/messages/send",
        headers=headers,
        json={
            "session_id": "missing-session",
            "message": "Hello",
        },
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Secure session not found."


def test_send_message():
    headers = _auth_headers()
    session = create_session(
        b"a" * 32,
        session_id="api-test-session",
    )
    session_manager.add_session(session)

    try:
        response = client.post(
            "/messages/send",
            headers=headers,
            json={
                "session_id": "api-test-session",
                "message": "Hello SentinelDrop",
            },
        )

        assert response.status_code == 200

        data = response.json()

        assert data["session_id"] == "api-test-session"
        assert data["sequence_number"] == 0
        assert data["message_type"] == "text"
        assert len(data["nonce"]) == 24
        assert data["ciphertext"]

    finally:
        session_manager.remove_session("api-test-session")


def test_receive_message():
    headers = _auth_headers()
    session = create_session(
        b"b" * 32,
        session_id="api-receive-session",
    )
    session_manager.add_session(session)

    try:
        send_response = client.post(
            "/messages/send",
            headers=headers,
            json={
                "session_id": "api-receive-session",
                "message": "Hello SentinelDrop",
            },
        )

        assert send_response.status_code == 200

        encrypted = send_response.json()

        receive_response = client.post(
            "/messages/receive",
            headers=headers,
            json={
                "session_id": encrypted["session_id"],
                "sequence_number": encrypted["sequence_number"],
                "message_type": encrypted["message_type"],
                "nonce": encrypted["nonce"],
                "ciphertext": encrypted["ciphertext"],
            },
        )

        assert receive_response.status_code == 200

        data = receive_response.json()

        assert data["session_id"] == "api-receive-session"
        assert data["sequence_number"] == 0
        assert data["message_type"] == "text"
        assert data["message"] == "Hello SentinelDrop"

    finally:
        session_manager.remove_session("api-receive-session")


def test_receive_message_rejects_replay():
    headers = _auth_headers()
    session = create_session(
        b"c" * 32,
        session_id="api-replay-session",
    )
    session_manager.add_session(session)

    try:
        send_response = client.post(
            "/messages/send",
            headers=headers,
            json={
                "session_id": "api-replay-session",
                "message": "Replay test",
            },
        )

        encrypted = send_response.json()

        first_receive = client.post(
            "/messages/receive",
            headers=headers,
            json=encrypted,
        )

        assert first_receive.status_code == 200

        replay_receive = client.post(
            "/messages/receive",
            headers=headers,
            json=encrypted,
        )

        assert replay_receive.status_code == 400
        assert replay_receive.json()["detail"] == "Replay detected."

    finally:
        session_manager.remove_session("api-replay-session")


def test_receive_message_rejects_out_of_order():
    headers = _auth_headers()
    session = create_session(
        b"d" * 32,
        session_id="api-order-session",
    )
    session_manager.add_session(session)

    try:
        send_response = client.post(
            "/messages/send",
            headers=headers,
            json={
                "session_id": "api-order-session",
                "message": "Order test",
            },
        )

        encrypted = send_response.json()
        encrypted["sequence_number"] = 1

        receive_response = client.post(
            "/messages/receive",
            headers=headers,
            json=encrypted,
        )

        assert receive_response.status_code == 400
        assert receive_response.json()["detail"] == "Message received out of order."

    finally:
        session_manager.remove_session("api-order-session")


def test_receive_message_rejects_tampered_ciphertext():
    headers = _auth_headers()
    session = create_session(
        b"e" * 32,
        session_id="api-tamper-session",
    )
    session_manager.add_session(session)

    try:
        send_response = client.post(
            "/messages/send",
            headers=headers,
            json={
                "session_id": "api-tamper-session",
                "message": "Integrity test",
            },
        )
        encrypted = send_response.json()
        tampered = bytes.fromhex(encrypted["ciphertext"])
        flipped = bytes([tampered[0] ^ 0xFF]) + tampered[1:]
        encrypted["ciphertext"] = flipped.hex()

        receive_response = client.post(
            "/messages/receive",
            headers=headers,
            json=encrypted,
        )

        assert receive_response.status_code == 400
        assert receive_response.json()["detail"] == "Message authentication failed."

    finally:
        session_manager.remove_session("api-tamper-session")

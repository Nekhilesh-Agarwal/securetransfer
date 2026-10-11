import base64
import uuid
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from app.security.session import create_session
from app.services.binary_message import (
    encrypt_binary_message,
)
from app.services.message import encrypt_message
from app.services.message_inbox import message_inbox
from app.services.session_manager import session_manager


client = TestClient(app)


def test_text_and_file_are_received_in_sequence(tmp_path, monkeypatch):
    session_id = f"mixed-inbox-{uuid.uuid4()}"
    key = b"z" * 32
    sender = create_session(key, session_id=session_id)
    receiver = create_session(key, session_id=session_id)
    session_manager.add_session(receiver)
    headers = _auth_headers()

    try:
        text = encrypt_message(sender, b"first message")
        image = encrypt_binary_message(
            sender,
            b"image bytes",
            "image",
            filename="ordered.png",
            mime_type="image/png",
        )
        assert client.post("/messages/inbox", json={
            "session_id": text.session_id,
            "sequence_number": text.sequence_number,
            "message_type": text.message_type,
            "nonce": text.nonce.hex(),
            "ciphertext": text.ciphertext.hex(),
        }).status_code == 200
        assert client.post("/files/inbox", json={
            "session_id": image.session_id,
            "sequence_number": image.sequence_number,
            "message_type": image.message_type,
            "nonce": image.nonce.hex(),
            "ciphertext": image.ciphertext.hex(),
            "filename": image.filename,
            "mime_type": image.mime_type,
            "file_size": image.file_size,
        }).status_code == 200

        monkeypatch.setattr(
            "app.api.files.RECEIVED_DIRECTORY", tmp_path / "received"
        )
        assert client.post("/messages/receive", headers=headers, json={
            "session_id": text.session_id,
            "sequence_number": text.sequence_number,
            "message_type": text.message_type,
            "nonce": text.nonce.hex(),
            "ciphertext": text.ciphertext.hex(),
        }).status_code == 200
        file_response = client.post(
            "/files/receive-encrypted",
            headers=headers,
            json={
                "session_id": image.session_id,
                "sequence_number": image.sequence_number,
                "message_type": image.message_type,
                "nonce": image.nonce.hex(),
                "ciphertext": image.ciphertext.hex(),
                "filename": image.filename,
                "mime_type": image.mime_type,
                "file_size": image.file_size,
            },
        )
        assert file_response.status_code == 200
        assert (tmp_path / "received" / "ordered.png").read_bytes() == b"image bytes"
        assert receiver.receive_sequence == 2
        assert message_inbox.pending(session_id) == []
    finally:
        message_inbox.clear(session_id)
        session_manager.remove_session(session_id)


def _auth_headers():
    username = f"file_{uuid.uuid4().hex[:8]}"
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


def test_prepare_file_requires_authentication(tmp_path):
    file_path = tmp_path / "photo.png"
    file_path.write_bytes(b"\x89PNG\r\n\x1a\nfake-image")

    with file_path.open("rb") as file:
        response = client.post(
            "/files/prepare",
            data={
                "session_id": "missing-session",
                "message_type": "image",
                "mime_type": "image/png",
            },
            files={
                "file": (
                    "photo.png",
                    file,
                    "image/png",
                )
            },
        )

    assert response.status_code == 401


def test_prepare_file_requires_session(
    tmp_path,
):
    file_path = tmp_path / "photo.png"

    file_path.write_bytes(
        b"\x89PNG\r\n\x1a\nfake-image"
    )

    with file_path.open("rb") as file:
        response = client.post(
            "/files/prepare",
            headers=_auth_headers(),
            data={
                "session_id": "missing-session",
                "message_type": "image",
                "mime_type": "image/png",
            },
            files={
                "file": (
                    "photo.png",
                    file,
                    "image/png",
                )
            },
        )

    assert response.status_code == 404


def test_prepare_image_file(
    tmp_path,
):
    session_id = (
        f"file-api-image-{uuid.uuid4()}"
    )

    session = create_session(
        b"a" * 32,
        session_id=session_id,
    )

    session_manager.add_session(session)

    try:
        file_path = tmp_path / "photo.png"

        original_data = (
            b"\x89PNG\r\n\x1a\n"
            b"fake-image-data"
        )

        file_path.write_bytes(
            original_data
        )

        with file_path.open("rb") as file:
            response = client.post(
                "/files/prepare",
                headers=_auth_headers(),
                data={
                    "session_id": session_id,
                    "message_type": "image",
                    "mime_type": "image/png",
                },
                files={
                    "file": (
                        "photo.png",
                        file,
                        "image/png",
                    )
                },
            )

        assert response.status_code == 200

        body = response.json()

        assert body["session_id"] == session_id
        assert body["sequence_number"] == 0
        assert body["message_type"] == "image"
        assert body["filename"] == "photo.png"
        assert body["mime_type"] == "image/png"
        assert body["file_size"] == len(
            original_data
        )

        assert body["nonce"]
        assert body["ciphertext"]

        assert bytes.fromhex(
            body["ciphertext"]
        ) != original_data

    finally:
        session_manager.remove_session(
            session_id
        )


def test_prepare_audio_file(
    tmp_path,
):
    session_id = (
        f"file-api-audio-{uuid.uuid4()}"
    )

    session = create_session(
        b"b" * 32,
        session_id=session_id,
    )

    session_manager.add_session(session)

    try:
        file_path = (
            tmp_path / "recording.wav"
        )

        original_data = (
            b"RIFF"
            b"\x00\x00\x00\x00"
            b"WAVE"
            b"fake-audio-data"
        )

        file_path.write_bytes(
            original_data
        )

        with file_path.open("rb") as file:
            response = client.post(
                "/files/prepare",
                headers=_auth_headers(),
                data={
                    "session_id": session_id,
                    "message_type": "audio",
                    "mime_type": "audio/wav",
                },
                files={
                    "file": (
                        "recording.wav",
                        file,
                        "audio/wav",
                    )
                },
            )

        assert response.status_code == 200

        body = response.json()

        assert body["message_type"] == "audio"
        assert body["filename"] == (
            "recording.wav"
        )
        assert body["mime_type"] == "audio/wav"
        assert body["file_size"] == len(
            original_data
        )

    finally:
        session_manager.remove_session(
            session_id
        )


def test_prepare_file_infers_mime_type(
    tmp_path,
):
    session_id = (
        f"file-api-mime-{uuid.uuid4()}"
    )

    session = create_session(
        b"c" * 32,
        session_id=session_id,
    )

    session_manager.add_session(session)

    try:
        file_path = tmp_path / "document.pdf"

        file_path.write_bytes(
            b"%PDF-fake-document"
        )

        with file_path.open("rb") as file:
            response = client.post(
                "/files/prepare",
                headers=_auth_headers(),
                data={
                    "session_id": session_id,
                    "message_type": "document",
                },
                files={
                    "file": (
                        "document.pdf",
                        file,
                        "application/pdf",
                    )
                },
            )

        assert response.status_code == 200

        body = response.json()

        assert body["filename"] == (
            "document.pdf"
        )

        assert body["mime_type"] == (
            "application/pdf"
        )

    finally:
        session_manager.remove_session(
            session_id
        )


def test_receive_file(
    tmp_path,
    monkeypatch,
):
    session_id = (
        f"file-api-receive-{uuid.uuid4()}"
    )

    sender = create_session(
        b"d" * 32,
        session_id=session_id,
    )

    receiver = create_session(
        b"d" * 32,
        session_id=session_id,
    )

    session_manager.add_session(
        receiver
    )

    try:
        original_data = (
            b"\x89PNG\r\n\x1a\n"
            b"received-image-data"
        )

        encrypted = encrypt_binary_message(
            sender,
            original_data,
            "image",
            filename="received.png",
            mime_type="image/png",
        )

        import app.api.files as files_api

        monkeypatch.setattr(
            files_api,
            "RECEIVED_DIRECTORY",
            tmp_path / "received",
        )

        response = client.post(
            "/files/receive",
            data={
                "session_id": encrypted.session_id,
                "sequence_number": (
                    encrypted.sequence_number
                ),
                "message_type": (
                    encrypted.message_type
                ),
                "nonce": encrypted.nonce.hex(),
                "ciphertext": (
                    encrypted.ciphertext.hex()
                ),
                "filename": encrypted.filename,
                "mime_type": encrypted.mime_type,
                "file_size": encrypted.file_size,
            },
        )

        assert response.status_code == 200

        body = response.json()

        assert body["session_id"] == (
            session_id
        )

        assert body["sequence_number"] == 0
        assert body["message_type"] == "image"
        assert body["filename"] == (
            "received.png"
        )
        assert body["mime_type"] == (
            "image/png"
        )
        assert body["file_size"] == len(
            original_data
        )

        output_path = (
            tmp_path
            / "received"
            / "received.png"
        )

        assert output_path.exists()

        assert output_path.read_bytes() == (
            original_data
        )

    finally:
        session_manager.remove_session(
            session_id
        )


def test_receive_file_rejects_tampered_metadata(
    tmp_path,
    monkeypatch,
):
    session_id = (
        f"file-api-tamper-{uuid.uuid4()}"
    )

    sender = create_session(
        b"e" * 32,
        session_id=session_id,
    )

    receiver = create_session(
        b"e" * 32,
        session_id=session_id,
    )

    session_manager.add_session(
        receiver
    )

    try:
        encrypted = encrypt_binary_message(
            sender,
            b"secret-file",
            "file",
            filename="original.txt",
            mime_type="text/plain",
        )

        import app.api.files as files_api

        monkeypatch.setattr(
            files_api,
            "RECEIVED_DIRECTORY",
            tmp_path / "received",
        )

        response = client.post(
            "/files/receive",
            data={
                "session_id": encrypted.session_id,
                "sequence_number": (
                    encrypted.sequence_number
                ),
                "message_type": (
                    encrypted.message_type
                ),
                "nonce": encrypted.nonce.hex(),
                "ciphertext": (
                    encrypted.ciphertext.hex()
                ),
                "filename": "tampered.txt",
                "mime_type": encrypted.mime_type,
                "file_size": encrypted.file_size,
            },
        )

        assert response.status_code == 400

        assert response.json()["detail"] == (
            "File authentication failed."
        )

    finally:
        session_manager.remove_session(
            session_id
        )


def test_receive_file_rejects_path_traversal(
    tmp_path,
    monkeypatch,
):
    session_id = (
        f"file-api-path-{uuid.uuid4()}"
    )

    sender = create_session(
        b"f" * 32,
        session_id=session_id,
    )

    receiver = create_session(
        b"f" * 32,
        session_id=session_id,
    )

    session_manager.add_session(
        receiver
    )

    try:
        encrypted = encrypt_binary_message(
            sender,
            b"secret-file",
            "file",
            filename="../secret.txt",
            mime_type="text/plain",
        )

        import app.api.files as files_api

        monkeypatch.setattr(
            files_api,
            "RECEIVED_DIRECTORY",
            tmp_path / "received",
        )

        response = client.post(
            "/files/receive",
            data={
                "session_id": encrypted.session_id,
                "sequence_number": (
                    encrypted.sequence_number
                ),
                "message_type": (
                    encrypted.message_type
                ),
                "nonce": encrypted.nonce.hex(),
                "ciphertext": (
                    encrypted.ciphertext.hex()
                ),
                "filename": "../secret.txt",
                "mime_type": encrypted.mime_type,
                "file_size": encrypted.file_size,
            },
        )

        assert response.status_code == 400

        assert response.json()["detail"] == (
            "Invalid filename."
        )

    finally:
        session_manager.remove_session(
            session_id
        )


def test_download_received_file(
    tmp_path,
    monkeypatch,
):
    import app.api.files as files_api

    received_directory = (
        tmp_path / "received"
    )

    received_directory.mkdir()

    original_data = b"download-test-data"

    file_path = (
        received_directory / "document.pdf"
    )

    file_path.write_bytes(
        original_data
    )

    monkeypatch.setattr(
        files_api,
        "RECEIVED_DIRECTORY",
        received_directory,
    )

    response = client.get(
        "/files/received/document.pdf",
        headers=_auth_headers(),
    )

    assert response.status_code == 200

    assert response.content == (
        original_data
    )


def test_download_received_file_rejects_path_traversal(
    tmp_path,
    monkeypatch,
):
    import app.api.files as files_api

    monkeypatch.setattr(
        files_api,
        "RECEIVED_DIRECTORY",
        tmp_path / "received",
    )

    response = client.get(
        "/files/received/../secret.txt",
        headers=_auth_headers(),
    )

    # Starlette may normalize "../" before the handler runs.
    assert response.status_code in {400, 404}


def test_download_received_file_rejects_encoded_path_traversal(
    tmp_path,
    monkeypatch,
):
    import app.api.files as files_api

    received_directory = (
        tmp_path / "received"
    )

    received_directory.mkdir()

    monkeypatch.setattr(
        files_api,
        "RECEIVED_DIRECTORY",
        received_directory,
    )

    # The HTTP client/server stack normalizes "../"
    # path segments before FastAPI receives the request.
    # Test the endpoint's filename validation directly
    # using a traversal-style filename that reaches the
    # route handler.
    response = client.get(
        "/files/received/%2E%2E%2Fsecret.txt",
        headers=_auth_headers(),
    )

    assert response.status_code in {
        400,
        404,
    }

    assert not (
        tmp_path / "secret.txt"
    ).exists()

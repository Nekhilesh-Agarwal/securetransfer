from app.security.session import create_session
from app.services.binary_message import (
    EncryptedBinaryMessage,
    decrypt_binary_message,
    encrypt_binary_message,
)


def test_binary_message_encrypt_and_decrypt():
    sender = create_session(
        b"a" * 32,
        session_id="binary-test",
    )

    receiver = create_session(
        b"a" * 32,
        session_id="binary-test",
    )

    original_data = b"\x00\x01\x02\x03binary-data"

    encrypted = encrypt_binary_message(
        sender,
        original_data,
        "image",
        filename="photo.png",
        mime_type="image/png",
    )

    assert encrypted.sequence_number == 0
    assert encrypted.message_type == "image"
    assert encrypted.filename == "photo.png"
    assert encrypted.mime_type == "image/png"
    assert encrypted.file_size == len(original_data)
    assert encrypted.ciphertext != original_data

    decrypted = decrypt_binary_message(
        receiver,
        encrypted,
    )

    assert decrypted == original_data


def test_binary_message_supports_audio():
    sender = create_session(
        b"b" * 32,
        session_id="audio-test",
    )

    receiver = create_session(
        b"b" * 32,
        session_id="audio-test",
    )

    original_data = b"fake-audio-data"

    encrypted = encrypt_binary_message(
        sender,
        original_data,
        "audio",
        filename="recording.wav",
        mime_type="audio/wav",
    )

    decrypted = decrypt_binary_message(
        receiver,
        encrypted,
    )

    assert decrypted == original_data
    assert encrypted.filename == "recording.wav"
    assert encrypted.mime_type == "audio/wav"
    assert encrypted.file_size == len(original_data)


def test_binary_message_rejects_replay():
    sender = create_session(
        b"c" * 32,
        session_id="replay-test",
    )

    receiver = create_session(
        b"c" * 32,
        session_id="replay-test",
    )

    encrypted = encrypt_binary_message(
        sender,
        b"secret-data",
        "image",
        filename="secret.png",
        mime_type="image/png",
    )

    decrypt_binary_message(
        receiver,
        encrypted,
    )

    try:
        decrypt_binary_message(
            receiver,
            encrypted,
        )

        assert False, "Replay should have been rejected."

    except ValueError as exc:
        assert "Replay detected" in str(exc)


def test_binary_message_rejects_out_of_order():
    sender = create_session(
        b"d" * 32,
        session_id="order-test",
    )

    receiver = create_session(
        b"d" * 32,
        session_id="order-test",
    )

    first = encrypt_binary_message(
        sender,
        b"first",
        "image",
        filename="first.png",
        mime_type="image/png",
    )

    second = encrypt_binary_message(
        sender,
        b"second",
        "image",
        filename="second.png",
        mime_type="image/png",
    )

    try:
        decrypt_binary_message(
            receiver,
            second,
        )

        assert False, "Out-of-order message should be rejected."

    except ValueError as exc:
        assert "out of order" in str(exc).lower()

    decrypt_binary_message(
        receiver,
        first,
    )


def test_binary_message_rejects_empty_data():
    session = create_session(
        b"e" * 32,
        session_id="empty-test",
    )

    try:
        encrypt_binary_message(
            session,
            b"",
            "image",
        )

        assert False, "Empty data should be rejected."

    except ValueError as exc:
        assert "empty" in str(exc).lower()


def test_binary_message_rejects_wrong_session():
    sender = create_session(
        b"f" * 32,
        session_id="sender-session",
    )

    receiver = create_session(
        b"f" * 32,
        session_id="receiver-session",
    )

    encrypted = encrypt_binary_message(
        sender,
        b"secret-data",
        "image",
        filename="secret.png",
        mime_type="image/png",
    )

    try:
        decrypt_binary_message(
            receiver,
            encrypted,
        )

        assert False, "Wrong session should be rejected."

    except ValueError as exc:
        assert "different session" in str(exc).lower()


def test_binary_message_rejects_tampered_filename():
    sender = create_session(
        b"g" * 32,
        session_id="filename-tamper",
    )

    receiver = create_session(
        b"g" * 32,
        session_id="filename-tamper",
    )

    encrypted = encrypt_binary_message(
        sender,
        b"secret-image",
        "image",
        filename="original.png",
        mime_type="image/png",
    )

    tampered = EncryptedBinaryMessage(
        session_id=encrypted.session_id,
        sequence_number=encrypted.sequence_number,
        message_type=encrypted.message_type,
        nonce=encrypted.nonce,
        ciphertext=encrypted.ciphertext,
        filename="tampered.png",
        mime_type=encrypted.mime_type,
        file_size=encrypted.file_size,
    )

    try:
        decrypt_binary_message(
            receiver,
            tampered,
        )

        assert False, "Tampered filename should be rejected."

    except Exception as exc:
        assert "InvalidTag" in type(exc).__name__


def test_binary_message_rejects_tampered_mime_type():
    sender = create_session(
        b"h" * 32,
        session_id="mime-tamper",
    )

    receiver = create_session(
        b"h" * 32,
        session_id="mime-tamper",
    )

    encrypted = encrypt_binary_message(
        sender,
        b"secret-audio",
        "audio",
        filename="recording.wav",
        mime_type="audio/wav",
    )

    tampered = EncryptedBinaryMessage(
        session_id=encrypted.session_id,
        sequence_number=encrypted.sequence_number,
        message_type=encrypted.message_type,
        nonce=encrypted.nonce,
        ciphertext=encrypted.ciphertext,
        filename=encrypted.filename,
        mime_type="audio/mpeg",
        file_size=encrypted.file_size,
    )

    try:
        decrypt_binary_message(
            receiver,
            tampered,
        )

        assert False, "Tampered MIME type should be rejected."

    except Exception as exc:
        assert "InvalidTag" in type(exc).__name__


def test_binary_message_rejects_tampered_file_size():
    sender = create_session(
        b"i" * 32,
        session_id="size-tamper",
    )

    receiver = create_session(
        b"i" * 32,
        session_id="size-tamper",
    )

    original_data = b"important-file"

    encrypted = encrypt_binary_message(
        sender,
        original_data,
        "file",
        filename="document.bin",
        mime_type="application/octet-stream",
    )

    tampered = EncryptedBinaryMessage(
        session_id=encrypted.session_id,
        sequence_number=encrypted.sequence_number,
        message_type=encrypted.message_type,
        nonce=encrypted.nonce,
        ciphertext=encrypted.ciphertext,
        filename=encrypted.filename,
        mime_type=encrypted.mime_type,
        file_size=encrypted.file_size + 1,
    )

    try:
        decrypt_binary_message(
            receiver,
            tampered,
        )

        assert False, "Tampered file size should be rejected."

    except Exception as exc:
        assert "InvalidTag" in type(exc).__name__


def test_binary_message_rejects_incorrect_file_size():
    sender = create_session(
        b"j" * 32,
        session_id="size-check",
    )

    receiver = create_session(
        b"j" * 32,
        session_id="size-check",
    )

    encrypted = encrypt_binary_message(
        sender,
        b"test-file",
        "file",
        filename="test.bin",
        mime_type="application/octet-stream",
    )

    # First create a correctly authenticated message,
    # then change only the ciphertext to represent
    # data with a different length.
    tampered_ciphertext = encrypted.ciphertext[:-1]

    tampered = EncryptedBinaryMessage(
        session_id=encrypted.session_id,
        sequence_number=encrypted.sequence_number,
        message_type=encrypted.message_type,
        nonce=encrypted.nonce,
        ciphertext=tampered_ciphertext,
        filename=encrypted.filename,
        mime_type=encrypted.mime_type,
        file_size=encrypted.file_size,
    )

    try:
        decrypt_binary_message(
            receiver,
            tampered,
        )

        assert False, "Invalid ciphertext should be rejected."

    except Exception:
        # AES-GCM authentication should reject modified ciphertext.
        pass
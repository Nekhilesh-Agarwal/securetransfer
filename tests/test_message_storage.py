import uuid

from app.database.connection import SessionLocal
from app.services.binary_message import EncryptedBinaryMessage
from app.services.message_storage import (
    get_messages,
    store_binary_message,
)


def test_store_binary_message():
    db = SessionLocal()

    session_id = f"storage-test-{uuid.uuid4()}"

    try:
        message = EncryptedBinaryMessage(
            session_id=session_id,
            sequence_number=0,
            message_type="image",
            nonce=b"a" * 12,
            ciphertext=b"encrypted-image-data",
        )

        record = store_binary_message(
            db,
            message,
        )

        assert record.id is not None
        assert record.session_id == session_id
        assert record.sequence_number == 0
        assert record.message_type == "image"

    finally:
        db.close()


def test_get_messages_in_sequence_order():
    db = SessionLocal()

    session_id = f"storage-order-{uuid.uuid4()}"

    try:
        first = EncryptedBinaryMessage(
            session_id=session_id,
            sequence_number=0,
            message_type="image",
            nonce=b"a" * 12,
            ciphertext=b"image-data",
        )

        second = EncryptedBinaryMessage(
            session_id=session_id,
            sequence_number=1,
            message_type="audio",
            nonce=b"b" * 12,
            ciphertext=b"audio-data",
        )

        # Store them intentionally out of order.
        store_binary_message(
            db,
            second,
        )

        store_binary_message(
            db,
            first,
        )

        messages = get_messages(
            db,
            session_id,
        )

        assert len(messages) == 2

        assert messages[0].sequence_number == 0
        assert messages[0].message_type == "image"

        assert messages[1].sequence_number == 1
        assert messages[1].message_type == "audio"

    finally:
        db.close()
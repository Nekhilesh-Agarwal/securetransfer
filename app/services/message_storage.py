import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.database.models import Message
from app.services.audit_signature import sign_audit_payload
from app.services.binary_message import EncryptedBinaryMessage
from app.services.message import EncryptedMessage


def _store_encrypted_transfer(
    db: Session,
    *,
    session_id: str,
    sequence_number: int,
    message_type: str,
    nonce: bytes,
    ciphertext: bytes,
    sender_user_id: int | None,
    recipient_user_id: int | None,
    filename: str | None = None,
) -> Message:
    sent_at = datetime.now(timezone.utc)
    ciphertext_hex = ciphertext.hex()
    ciphertext_hash = hashlib.sha256(ciphertext).hexdigest()
    signature_payload = {
        "session_id": session_id,
        "sequence_number": sequence_number,
        "message_type": message_type,
        "sender_user_id": sender_user_id,
        "recipient_user_id": recipient_user_id,
        "sent_at": sent_at.isoformat(),
        "nonce": nonce.hex(),
        "ciphertext_sha256": ciphertext_hash,
        "filename": filename,
    }
    record = Message(
        session_id=session_id,
        sequence_number=sequence_number,
        message_type=message_type,
        sender_user_id=sender_user_id,
        recipient_user_id=recipient_user_id,
        sent_at=sent_at,
        ciphertext_hash=ciphertext_hash,
        ciphertext=ciphertext_hex,
        nonce=nonce.hex(),
        filename=filename,
        signature=sign_audit_payload(signature_payload),
        signature_payload=json.dumps(
            signature_payload,
            sort_keys=True,
            separators=(",", ":"),
        ),
        signature_algorithm="Ed25519 server audit attestation",
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def store_message(
    db: Session,
    message: EncryptedMessage,
    sender_user_id: int | None = None,
    recipient_user_id: int | None = None,
) -> Message:
    """Store encrypted text metadata and a signed audit record."""
    return _store_encrypted_transfer(
        db,
        session_id=message.session_id,
        sequence_number=message.sequence_number,
        message_type=message.message_type,
        nonce=message.nonce,
        ciphertext=message.ciphertext,
        sender_user_id=sender_user_id,
        recipient_user_id=recipient_user_id,
    )


def store_binary_message(
    db: Session,
    message: EncryptedBinaryMessage,
    sender_user_id: int | None = None,
    recipient_user_id: int | None = None,
) -> Message:
    """Store encrypted file metadata and a signed audit record."""
    return _store_encrypted_transfer(
        db,
        session_id=message.session_id,
        sequence_number=message.sequence_number,
        message_type=message.message_type,
        nonce=message.nonce,
        ciphertext=message.ciphertext,
        sender_user_id=sender_user_id,
        recipient_user_id=recipient_user_id,
        filename=message.filename,
    )


def mark_message_received(
    db: Session,
    *,
    session_id: str,
    sequence_number: int,
    recipient_user_id: int,
    sender_user_id: int | None = None,
) -> Message | None:
    query = db.query(Message).filter(
        Message.session_id == session_id,
        Message.sequence_number == sequence_number,
    )
    if sender_user_id is not None:
        query = query.filter(Message.sender_user_id == sender_user_id)
    record = query.order_by(Message.id.desc()).first()
    if record is None:
        return None
    if record.received_at is None:
        record.received_at = datetime.now(timezone.utc)
    record.recipient_user_id = recipient_user_id
    db.commit()
    db.refresh(record)
    return record


def get_messages(db: Session, session_id: str) -> list[Message]:
    """Retrieve stored message metadata for a session."""
    return (
        db.query(Message)
        .filter(Message.session_id == session_id)
        .order_by(Message.sequence_number)
        .all()
    )

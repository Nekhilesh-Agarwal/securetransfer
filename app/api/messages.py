from cryptography.exceptions import InvalidTag
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.monitor.sentinel import record_local_event
from app.services.audit_log import record_event
from app.services.auth import get_current_user
from app.services.encryption_demo_log import (
    include_plaintext,
    log_encryption_demo,
)
from app.services.message import (
    EncryptedMessage,
    decrypt_message,
    encrypt_message,
)
from app.services.message_inbox import message_inbox
from app.services.message_storage import mark_message_received, store_message
from app.services.session_manager import session_manager


def _transfer_event_type(message_type: str, direction: str) -> str:
    kind = (message_type or "text").lower()
    if kind in {"image", "png", "jpeg", "jpg"}:
        base = "IMAGE"
    elif kind in {"audio", "audio_transcript", "voice", "transcript"}:
        base = "AUDIO_TRANSCRIPT"
    else:
        base = "TEXT"
    return f"{base}_{direction}"


router = APIRouter(
    prefix="/messages",
    tags=["Messages"],
)


class SendMessageRequest(BaseModel):
    session_id: str
    message: str
    message_type: str = "text"


class ReceiveMessageRequest(BaseModel):
    session_id: str
    sequence_number: int
    message_type: str
    nonce: str
    ciphertext: str
    sender_user_id: int | None = None
    recipient_user_id: int | None = None


class InboxMessageRequest(ReceiveMessageRequest):
    pass


@router.post("/send")
def send_message(
    request: SendMessageRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    session = session_manager.get_session(
        request.session_id,
        user_id=current_user.id,
    )

    if session is None:
        raise HTTPException(
            status_code=404,
            detail="Secure session not found.",
        )

    encrypted_message = encrypt_message(
        session=session,
        plaintext=request.message.encode("utf-8"),
        message_type=request.message_type,
    )

    recipient_user_id = session_manager.peer_user_id(
        request.session_id,
        current_user.id,
    )
    payload = {
        "session_id": encrypted_message.session_id,
        "sequence_number": encrypted_message.sequence_number,
        "message_type": encrypted_message.message_type,
        "nonce": encrypted_message.nonce.hex(),
        "ciphertext": encrypted_message.ciphertext.hex(),
        "sender_user_id": current_user.id,
        "recipient_user_id": recipient_user_id,
        "sender": current_user.username,
    }
    try:
        message_inbox.enqueue(request.session_id, payload)
    except OverflowError as exc:
        record_local_event("flood", "Ciphertext inbox flood rejected.")
        raise HTTPException(
            status_code=429,
            detail="Too many queued ciphertext messages.",
        ) from exc

    trace = store_message(
        db=db,
        message=encrypted_message,
        sender_user_id=current_user.id,
        recipient_user_id=recipient_user_id,
    )

    record_event(
        db=db,
        event_type=_transfer_event_type(
            encrypted_message.message_type,
            "SENT",
        ),
        session_id=request.session_id,
        details=(
            f"Encrypted {encrypted_message.message_type} "
            f"message, sequence {encrypted_message.sequence_number}, "
            f"ciphertext SHA-256 {trace.ciphertext_hash}."
        ),
        actor_id=current_user.username,
        status="success",
    )

    demo_entry = {
        "message_type": encrypted_message.message_type,
        "sender": current_user.username,
        "receiver": payload["recipient_user_id"],
        "session_id": request.session_id,
        "encryption_algorithm": "AES-256-GCM",
        "ciphertext_hex": encrypted_message.ciphertext.hex(),
        "nonce_hex": encrypted_message.nonce.hex(),
        "authentication_tag": "included in AES-GCM ciphertext (last 16 bytes)",
        "encryption_status": "success",
        "decryption_status": "pending",
        "original_message_size": len(request.message.encode("utf-8")),
        "encrypted_payload_size": len(encrypted_message.ciphertext),
        "sequence_number": encrypted_message.sequence_number,
    }
    if include_plaintext() and encrypted_message.message_type.lower() in {
        "text",
        "audio",
        "audio_transcript",
        "voice",
        "transcript",
    }:
        demo_entry["plaintext"] = request.message
    log_encryption_demo(demo_entry)

    return {
        "session_id": encrypted_message.session_id,
        "sequence_number": encrypted_message.sequence_number,
        "message_type": encrypted_message.message_type,
        "nonce": encrypted_message.nonce.hex(),
        "ciphertext": encrypted_message.ciphertext.hex(),
    }


@router.post("/inbox")
def enqueue_ciphertext(
    request: InboxMessageRequest,
):
    """Accept ciphertext only. Plaintext is never stored here."""

    session = session_manager.get_session(request.session_id)
    if session is None:
        raise HTTPException(
            status_code=404,
            detail="Secure session not found.",
        )

    payload = request.model_dump()
    try:
        message_inbox.enqueue(request.session_id, payload)
    except OverflowError as exc:
        record_local_event("flood", "Ciphertext inbox flood rejected.")
        raise HTTPException(
            status_code=429,
            detail="Too many queued ciphertext messages.",
        ) from exc
    return {"queued": True, "session_id": request.session_id}


@router.get("/pending")
def list_pending_ciphertext(
    session_id: str | None = None,
    current_user=Depends(get_current_user),
):
    return {
        "messages": message_inbox.pending(
            session_id,
            recipient_user_id=current_user.id,
        )
    }


@router.post("/receive")
def receive_message(
    request: ReceiveMessageRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    session = session_manager.get_session(
        request.session_id,
        user_id=current_user.id,
    )

    if session is None:
        raise HTTPException(
            status_code=404,
            detail="Secure session not found.",
        )

    try:
        message = EncryptedMessage(
            session_id=request.session_id,
            sequence_number=request.sequence_number,
            message_type=request.message_type,
            nonce=bytes.fromhex(request.nonce),
            ciphertext=bytes.fromhex(
                request.ciphertext
            ),
        )

        plaintext = decrypt_message(
            session=session,
            message=message,
        )

        record_event(
            db=db,
            event_type=_transfer_event_type(
                request.message_type,
                "RECEIVED",
            ),
            session_id=request.session_id,
            details=(
                f"Decrypted {request.message_type} "
                f"message, sequence "
                f"{request.sequence_number}."
            ),
            actor_id=current_user.username,
            status="success",
        )
        mark_message_received(
            db,
            session_id=request.session_id,
            sequence_number=request.sequence_number,
            sender_user_id=session_manager.peer_user_id(
                request.session_id,
                current_user.id,
            ),
            recipient_user_id=current_user.id,
        )
        log_encryption_demo(
            {
                "message_type": request.message_type,
                "sender": None,
                "receiver": current_user.username,
                "session_id": request.session_id,
                "encryption_algorithm": "AES-256-GCM",
                "ciphertext_hex": request.ciphertext,
                "nonce_hex": request.nonce,
                "authentication_tag": "included in AES-GCM ciphertext (last 16 bytes)",
                "encryption_status": "success",
                "decryption_status": "success",
                "original_message_size": len(plaintext),
                "encrypted_payload_size": len(bytes.fromhex(request.ciphertext)),
                "sequence_number": request.sequence_number,
                **(
                    {"plaintext": plaintext.decode("utf-8")}
                    if include_plaintext()
                    and request.message_type.lower()
                    in {
                        "text",
                        "audio",
                        "audio_transcript",
                        "voice",
                        "transcript",
                    }
                    else {}
                ),
            }
        )
        message_inbox.dequeue(
            request.session_id,
            request.sequence_number,
            ciphertext=request.ciphertext,
        )

    except InvalidTag as exc:
        record_local_event("tamper", "GCM authentication failure.")
        record_event(
            db=db,
            event_type="INVALID_AUTHENTICATION_TAG",
            session_id=request.session_id,
            details="Rejected tampered ciphertext.",
            actor_id=current_user.username,
            status="failure",
        )
        raise HTTPException(
            status_code=400,
            detail="Message authentication failed.",
        ) from exc

    except ValueError as exc:
        detail = str(exc)
        kind = "replay" if "Replay" in detail else "reject"
        record_local_event(kind, detail)
        event_type = (
            "REPLAY_REJECTED"
            if "Replay" in detail
            else "DECRYPTION_FAILURE"
        )
        record_event(
            db=db,
            event_type=event_type,
            session_id=request.session_id,
            details=detail,
            actor_id=current_user.username,
            status="failure",
        )
        raise HTTPException(
            status_code=400,
            detail=detail,
        ) from exc

    return {
        "session_id": request.session_id,
        "sequence_number": request.sequence_number,
        "message_type": request.message_type,
        "message": plaintext.decode("utf-8"),
    }

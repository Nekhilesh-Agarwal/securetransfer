import base64

from cryptography.exceptions import InvalidTag
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.services.audit_log import record_event
from app.services.auth import get_current_user
from app.services.binary_message import (
    EncryptedBinaryMessage,
    decrypt_binary_message,
    encrypt_binary_message,
)
from app.services.message_storage import mark_message_received, store_binary_message
from app.services.session_manager import session_manager


router = APIRouter(
    prefix="/binary",
    tags=["Binary Transfer"],
)


class SendBinaryRequest(BaseModel):
    session_id: str
    data: str
    message_type: str
    filename: str | None = None
    mime_type: str | None = None


class ReceiveBinaryRequest(BaseModel):
    session_id: str
    sequence_number: int
    message_type: str
    nonce: str
    ciphertext: str
    filename: str | None = None
    mime_type: str | None = None
    file_size: int | None = None
    sender_user_id: int | None = None
    recipient_user_id: int | None = None


@router.post("/send")
def send_binary(
    request: SendBinaryRequest,
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
        data = base64.b64decode(
            request.data,
            validate=True,
        )

        encrypted_message = encrypt_binary_message(
            session=session,
            data=data,
            message_type=request.message_type,
            filename=request.filename,
            mime_type=request.mime_type,
        )

        trace = store_binary_message(
            db=db,
            message=encrypted_message,
            sender_user_id=current_user.id,
            recipient_user_id=session_manager.peer_user_id(
                request.session_id,
                current_user.id,
            ),
        )

        record_event(
            db=db,
            event_type="binary_sent",
            session_id=request.session_id,
            details=(
                f"User '{current_user.username}' "
                f"encrypted {encrypted_message.message_type} "
                f"binary data, sequence {encrypted_message.sequence_number}, "
                f"ciphertext SHA-256 {trace.ciphertext_hash}."
            ),
        )

    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    return {
        "session_id": encrypted_message.session_id,
        "sequence_number": encrypted_message.sequence_number,
        "message_type": encrypted_message.message_type,
        "filename": encrypted_message.filename,
        "mime_type": encrypted_message.mime_type,
        "file_size": encrypted_message.file_size,
        "nonce": encrypted_message.nonce.hex(),
        "ciphertext": encrypted_message.ciphertext.hex(),
    }


@router.post("/receive")
def receive_binary(
    request: ReceiveBinaryRequest,
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
        message = EncryptedBinaryMessage(
            session_id=request.session_id,
            sequence_number=request.sequence_number,
            message_type=request.message_type,
            nonce=bytes.fromhex(request.nonce),
            ciphertext=bytes.fromhex(request.ciphertext),
            filename=request.filename,
            mime_type=request.mime_type,
            file_size=request.file_size,
        )

        plaintext = decrypt_binary_message(
            session=session,
            message=message,
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

        record_event(
            db=db,
            event_type="binary_received",
            session_id=request.session_id,
            details=(
                f"User '{current_user.username}' "
                f"decrypted {request.message_type} "
                f"binary data, sequence "
                f"{request.sequence_number}."
            ),
        )

    except InvalidTag as exc:
        raise HTTPException(
            status_code=400,
            detail="Binary message authentication failed.",
        ) from exc

    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    return {
        "session_id": request.session_id,
        "sequence_number": request.sequence_number,
        "message_type": request.message_type,
        "filename": request.filename,
        "mime_type": request.mime_type,
        "file_size": len(plaintext),
        "data": base64.b64encode(
            plaintext
        ).decode("ascii"),
    }

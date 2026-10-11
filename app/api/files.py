import mimetypes
from pathlib import Path
from tempfile import NamedTemporaryFile

from cryptography.exceptions import InvalidTag
from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    UploadFile,
)
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.monitor.sentinel import record_local_event
from app.services.audit_log import record_event
from app.services.auth import get_current_user
from app.services.encryption_demo_log import (
    file_content_hash,
    log_encryption_demo,
)
from app.services.binary_message import EncryptedBinaryMessage
from app.services.file_transfer import (
    MAX_FILE_SIZE,
    prepare_file_for_transfer,
    save_received_file,
)
from app.services.session_manager import session_manager
from app.services.message_inbox import message_inbox
from app.services.message_storage import mark_message_received, store_binary_message
from app.storage_paths import data_path


router = APIRouter(
    prefix="/files",
    tags=["File Transfer"],
)


class EncryptedFileRequest(BaseModel):
    session_id: str
    sequence_number: int
    message_type: str
    nonce: str
    ciphertext: str
    filename: str
    mime_type: str | None = None
    file_size: int
    sender_user_id: int | None = None
    recipient_user_id: int | None = None


@router.post("/inbox")
def enqueue_encrypted_file(request: EncryptedFileRequest):
    """Queue encrypted file metadata for ordered receiver processing."""
    if session_manager.get_session(request.session_id) is None:
        raise HTTPException(status_code=404, detail="Secure session not found.")

    payload = request.model_dump()
    payload["transfer_kind"] = "file"
    try:
        message_inbox.enqueue(request.session_id, payload)
    except OverflowError as exc:
        record_local_event("flood", "Ciphertext inbox flood rejected.")
        raise HTTPException(status_code=429, detail="Too many queued ciphertext messages.") from exc
    return {"queued": True, "session_id": request.session_id}


@router.post("/receive-encrypted")
def receive_encrypted_file(
    request: EncryptedFileRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Decrypt a queued file after the receiver reaches its sequence number."""
    session = session_manager.get_session(
        request.session_id,
        user_id=current_user.id,
    )
    if session is None:
        raise HTTPException(status_code=404, detail="Secure session not found.")

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
        output_path = save_received_file(
            session=session,
            message=message,
            output_directory=RECEIVED_DIRECTORY,
            avoid_collision=True,
        )
        event_name = (
            "IMAGE_RECEIVED"
            if request.message_type.lower() in {"image", "png", "jpeg", "jpg"}
            else "AUDIO_TRANSCRIPT_RECEIVED"
            if request.message_type.lower() in {"audio", "audio_transcript", "voice"}
            else "IMAGE_RECEIVED"
        )
        record_event(
            db=db,
            event_type=event_name,
            session_id=request.session_id,
            details=f"Decrypted {request.message_type} file '{output_path.name}', sequence {request.sequence_number}.",
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
        ciphertext_bytes = bytes.fromhex(request.ciphertext)
        log_encryption_demo(
            {
                "message_type": request.message_type,
                "sender": None,
                "receiver": current_user.username,
                "session_id": request.session_id,
                "encryption_algorithm": "AES-256-GCM",
                "ciphertext_sha256": file_content_hash(ciphertext_bytes),
                "nonce_hex": request.nonce,
                "authentication_tag": "included in AES-GCM ciphertext (last 16 bytes)",
                "encryption_status": "success",
                "decryption_status": "success",
                "original_message_size": request.file_size,
                "encrypted_payload_size": len(ciphertext_bytes),
                "filename": request.filename,
                "mime_type": request.mime_type,
            }
        )
        message_inbox.dequeue(
            request.session_id,
            request.sequence_number,
            ciphertext=request.ciphertext,
        )
    except InvalidTag as exc:
        record_local_event("tamper", "File GCM authentication failure.")
        record_event(
            db=db,
            event_type="INVALID_AUTHENTICATION_TAG",
            session_id=request.session_id,
            details="Rejected tampered file ciphertext.",
            actor_id=current_user.username,
            status="failure",
        )
        raise HTTPException(status_code=400, detail="File authentication failed.") from exc
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {
        "session_id": request.session_id,
        "sequence_number": request.sequence_number,
        "message_type": request.message_type,
        "filename": output_path.name,
        "mime_type": request.mime_type,
        "file_size": output_path.stat().st_size,
    }


TRANSFER_DIRECTORY = data_path("storage", "transfers")

RECEIVED_DIRECTORY = data_path("storage", "received")


@router.post("/prepare")
async def prepare_file(
    session_id: str = Form(...),
    message_type: str = Form(...),
    mime_type: str | None = Form(None),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Prepare an uploaded file for encrypted transfer.

    The uploaded file is temporarily written to disk,
    encrypted using the existing secure binary-transfer
    service, and the temporary plaintext file is removed.
    """

    session = session_manager.get_session(
        session_id,
        user_id=current_user.id,
    )

    if session is None:
        raise HTTPException(
            status_code=404,
            detail="Secure session not found.",
        )

    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="Filename is required.",
        )

    if not message_type:
        raise HTTPException(
            status_code=400,
            detail="Message type is required.",
        )

    original_filename = Path(
        file.filename
    ).name

    if (
        not original_filename
        or original_filename in {".", ".."}
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid filename.",
        )

    if original_filename != file.filename:
        raise HTTPException(
            status_code=400,
            detail="Invalid filename.",
        )

    resolved_mime_type = (
        mime_type
        or file.content_type
        or mimetypes.guess_type(
            original_filename
        )[0]
    )

    temporary_path: Path | None = None

    try:
        TRANSFER_DIRECTORY.mkdir(
            parents=True,
            exist_ok=True,
        )

        with NamedTemporaryFile(
            delete=False,
            dir=TRANSFER_DIRECTORY,
            suffix=".upload",
        ) as temporary_file:
            temporary_path = Path(
                temporary_file.name
            )

            total_size = 0

            while True:
                chunk = await file.read(
                    1024 * 1024
                )

                if not chunk:
                    break

                total_size += len(chunk)

                if total_size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail=(
                            "File exceeds the maximum "
                            "allowed size."
                        ),
                    )

                temporary_file.write(chunk)

        encrypted_message = (
            prepare_file_for_transfer(
                session=session,
                file_path=temporary_path,
                message_type=message_type,
                mime_type=resolved_mime_type,
                filename=original_filename,
            )
        )

        recipient_user_id = session_manager.peer_user_id(
            session_id,
            current_user.id,
        )
        payload = {
            "session_id": encrypted_message.session_id,
            "sequence_number": encrypted_message.sequence_number,
            "message_type": encrypted_message.message_type,
            "nonce": encrypted_message.nonce.hex(),
            "ciphertext": encrypted_message.ciphertext.hex(),
            "filename": encrypted_message.filename,
            "mime_type": encrypted_message.mime_type,
            "file_size": encrypted_message.file_size,
            "transfer_kind": "file",
            "sender_user_id": current_user.id,
            "recipient_user_id": recipient_user_id,
        }
        try:
            message_inbox.enqueue(session_id, payload)
        except OverflowError as exc:
            record_local_event("flood", "Ciphertext inbox flood rejected.")
            raise HTTPException(
                status_code=429,
                detail="Too many queued ciphertext messages.",
            ) from exc

        trace = store_binary_message(
            db=db,
            message=encrypted_message,
            sender_user_id=current_user.id,
            recipient_user_id=recipient_user_id,
        )
        record_event(
            db=db,
            event_type=(
                "IMAGE_SENT"
                if message_type.lower() in {"image", "png", "jpeg", "jpg"}
                else "AUDIO_TRANSCRIPT_SENT"
                if message_type.lower() in {"audio", "audio_transcript", "voice"}
                else "IMAGE_SENT"
            ),
            session_id=session_id,
            details=(
                f"Encrypted {message_type} file "
                f"'{original_filename}', sequence {encrypted_message.sequence_number}, "
                f"ciphertext SHA-256 {trace.ciphertext_hash}."
            ),
            actor_id=current_user.username,
            status="success",
        )

        log_encryption_demo(
            {
                "message_type": message_type,
                "sender": current_user.username,
                "receiver": payload["recipient_user_id"],
                "session_id": session_id,
                "encryption_algorithm": "AES-256-GCM",
                "ciphertext_sha256": file_content_hash(
                    encrypted_message.ciphertext
                ),
                "nonce_hex": encrypted_message.nonce.hex(),
                "authentication_tag": "included in AES-GCM ciphertext (last 16 bytes)",
                "encryption_status": "success",
                "decryption_status": "pending",
                "original_message_size": encrypted_message.file_size,
                "encrypted_payload_size": len(encrypted_message.ciphertext),
                "filename": original_filename,
                "mime_type": resolved_mime_type,
            }
        )

        return {
            "session_id": (
                encrypted_message.session_id
            ),
            "sequence_number": (
                encrypted_message.sequence_number
            ),
            "message_type": (
                encrypted_message.message_type
            ),
            "filename": (
                encrypted_message.filename
            ),
            "mime_type": (
                encrypted_message.mime_type
            ),
            "file_size": (
                encrypted_message.file_size
            ),
            "nonce": (
                encrypted_message.nonce.hex()
            ),
            "ciphertext": (
                encrypted_message.ciphertext.hex()
            ),
        }

    except HTTPException:
        raise

    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    finally:
        await file.close()

        if (
            temporary_path is not None
            and temporary_path.exists()
        ):
            temporary_path.unlink()


@router.post("/receive")
def receive_file(
    session_id: str = Form(...),
    sequence_number: int = Form(...),
    message_type: str = Form(...),
    nonce: str = Form(...),
    ciphertext: str = Form(...),
    filename: str = Form(...),
    mime_type: str | None = Form(None),
    file_size: int | None = Form(None),
    sender_user_id: int | None = Form(None),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Decrypt an encrypted file message and save it
    to the received-files directory.
    """

    session = session_manager.get_session(
        session_id,
        user_id=current_user.id,
    )

    if session is None:
        raise HTTPException(
            status_code=404,
            detail="Secure session not found.",
        )

    try:
        message = EncryptedBinaryMessage(
            session_id=session_id,
            sequence_number=sequence_number,
            message_type=message_type,
            nonce=bytes.fromhex(nonce),
            ciphertext=bytes.fromhex(
                ciphertext
            ),
            filename=filename,
            mime_type=mime_type,
            file_size=file_size,
        )

        output_path = save_received_file(
            session=session,
            message=message,
            output_directory=RECEIVED_DIRECTORY,
        )

        record_event(
            db=db,
            event_type="file_received",
            session_id=session_id,
            details=(
                f"Decrypted {message_type} file "
                f"'{output_path.name}', sequence "
                f"{sequence_number}."
            ),
            actor_id=current_user.username,
            status="success",
        )
        mark_message_received(
            db,
            session_id=session_id,
            sequence_number=sequence_number,
            sender_user_id=session_manager.peer_user_id(
                session_id,
                current_user.id,
            ),
            recipient_user_id=current_user.id,
        )

    except InvalidTag as exc:
        record_local_event("tamper", "File GCM authentication failure.")
        record_event(
            db=db,
            event_type="tamper_detected",
            session_id=session_id,
            details="Rejected tampered file ciphertext.",
        )
        raise HTTPException(
            status_code=400,
            detail="File authentication failed.",
        ) from exc

    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    return {
        "session_id": session_id,
        "sequence_number": sequence_number,
        "message_type": message_type,
        "filename": output_path.name,
        "mime_type": mime_type,
        "file_size": output_path.stat().st_size,
        "path": str(output_path),
    }


@router.get("/received")
def list_received_files(
    current_user=Depends(get_current_user),
):
    RECEIVED_DIRECTORY.mkdir(parents=True, exist_ok=True)
    files = [
        {
            "filename": path.name,
            "size": path.stat().st_size,
        }
        for path in sorted(RECEIVED_DIRECTORY.iterdir())
        if path.is_file()
    ]
    return {"files": files}


@router.get("/received/{filename}")
def download_received_file(
    filename: str,
    current_user=Depends(get_current_user),
):
    """
    Download a previously received file.
    """

    safe_filename = Path(
        filename
    ).name

    if safe_filename != filename:
        raise HTTPException(
            status_code=400,
            detail="Invalid filename.",
        )

    if safe_filename in {
        "",
        ".",
        "..",
    }:
        raise HTTPException(
            status_code=400,
            detail="Invalid filename.",
        )

    file_path = (
        RECEIVED_DIRECTORY
        / safe_filename
    )

    if not file_path.exists():
        raise HTTPException(
            status_code=404,
            detail="File not found.",
        )

    if not file_path.is_file():
        raise HTTPException(
            status_code=404,
            detail="File not found.",
        )

    media_type = (
        mimetypes.guess_type(
            safe_filename
        )[0]
        or "application/octet-stream"
    )

    return FileResponse(
        path=file_path,
        filename=safe_filename,
        media_type=media_type,
    )

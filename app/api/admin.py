import json
from datetime import timezone

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from pydantic import BaseModel
from sqlalchemy.orm import Session, aliased

from app.database.connection import get_db
from app.database.models import Message, User
from app.evaluation.image_metrics import ciphertext_preview_data_url, evaluate_image_bytes
from app.evaluation.performance import run_performance_benchmark
from app.evaluation.text_metrics import analyze_text
from app.monitor.sentinel import get_monitor_status
from app.services.audit_signature import get_audit_signing_public_key, verify_audit_signature
from app.services.auth import get_admin_user
from app.services.time_utils import to_utc_isoformat


router = APIRouter(prefix="/admin", tags=["Administrator"])
MAX_ANALYSIS_IMAGE_BYTES = 8 * 1024 * 1024


class TextAnalysisRequest(BaseModel):
    text: str


def _message_query(db: Session):
    sender = aliased(User)
    recipient = aliased(User)
    return (
        db.query(Message, sender.username, recipient.username)
        .outerjoin(sender, Message.sender_user_id == sender.id)
        .outerjoin(recipient, Message.recipient_user_id == recipient.id)
    )


def _message_record(row, include_ciphertext: bool = False) -> dict:
    message, sender, recipient = row
    ciphertext = message.ciphertext or ""
    signature_payload = (
        json.loads(message.signature_payload)
        if message.signature_payload
        else None
    )
    transfer_latency_ms = None
    if message.sent_at is not None and message.received_at is not None:
        sent = message.sent_at
        received = message.received_at
        if sent.tzinfo is None:
            sent = sent.replace(tzinfo=timezone.utc)
        if received.tzinfo is None:
            received = received.replace(tzinfo=timezone.utc)
        transfer_latency_ms = round((received - sent).total_seconds() * 1000, 3)
    item = {
        "id": message.id,
        "session_id": message.session_id,
        "sequence_number": message.sequence_number,
        "message_type": message.message_type,
        "sender": sender,
        "recipient": recipient,
        "sender_user_id": message.sender_user_id,
        "recipient_user_id": message.recipient_user_id,
        "filename": message.filename,
        "sent_at": to_utc_isoformat(message.sent_at),
        "received_at": to_utc_isoformat(message.received_at),
        "transfer_latency_ms": transfer_latency_ms,
        "ciphertext_sha256": message.ciphertext_hash,
        "ciphertext_bytes": len(ciphertext) // 2,
        "nonce": message.nonce,
        "authentication_tag": ciphertext[-32:] if len(ciphertext) >= 32 else None,
        "signature": message.signature,
        "signature_algorithm": message.signature_algorithm,
        "signature_payload": signature_payload,
        "signature_valid": verify_audit_signature(signature_payload, message.signature)
        if signature_payload
        else False,
    }
    if include_ciphertext:
        item["ciphertext"] = ciphertext
        is_image = (
            message.message_type.lower() in {"image", "png", "jpeg", "jpg"}
            or (message.filename or "").lower().endswith((".png", ".jpg", ".jpeg", ".webp", ".bmp"))
        )
        if is_image and ciphertext:
            item["ciphertext_image_preview"] = ciphertext_preview_data_url(
                bytes.fromhex(ciphertext)
            )
            item["ciphertext_image_preview_note"] = (
                "Preview of this transfer's actual ciphertext bytes (including its GCM tag), rendered as pixels. It is not a decryptable image file."
            )
    return item


@router.get("/message-logs")
def list_message_logs(
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    _admin=Depends(get_admin_user),
):
    rows = _message_query(db).order_by(Message.id.desc()).limit(limit).all()
    return {
        "count": len(rows),
        "signature_public_key": get_audit_signing_public_key(),
        "signature_note": (
            "Ed25519 server audit attestation over sender, recipient, time, nonce, "
            "and ciphertext hash; it is not a client-generated signature."
        ),
        "messages": [_message_record(row) for row in rows],
    }


@router.get("/message-logs/{message_id}")
def get_message_log(
    message_id: int,
    db: Session = Depends(get_db),
    _admin=Depends(get_admin_user),
):
    row = _message_query(db).filter(Message.id == message_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Message log not found.")
    return _message_record(row, include_ciphertext=True)


@router.post("/evaluation/image-metrics")
async def run_image_metrics(
    image: UploadFile = File(...),
    _admin=Depends(get_admin_user),
):
    """Analyze an admin-selected image in memory; the upload is not persisted."""
    image_bytes = await image.read(MAX_ANALYSIS_IMAGE_BYTES + 1)
    if len(image_bytes) > MAX_ANALYSIS_IMAGE_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Choose an image no larger than 8 MB.",
        )
    try:
        return evaluate_image_bytes(image_bytes, image.filename or "uploaded image")
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        await image.close()


@router.post("/evaluation/benchmark")
def run_admin_performance_benchmark(
    _admin=Depends(get_admin_user),
):
    """Run the bounded AES-GCM and copy-baseline benchmark for admins."""
    return run_performance_benchmark()


@router.post("/evaluation/text-analysis")
def run_text_analysis(
    request: TextAnalysisRequest,
    _admin=Depends(get_admin_user),
):
    """Analyze admin-supplied sample text without storing the input."""
    try:
        return analyze_text(request.text)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/monitor/status")
def get_admin_monitor_status(
    _admin=Depends(get_admin_user),
):
    """Return application security events and optional PyShark availability."""
    return get_monitor_status()
import json


import tempfile
import time
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.services.audit_log import record_event
from app.services.auth import get_current_user
from app.services.voice import transcribe_wav


router = APIRouter(
    prefix="/voice",
    tags=["Voice"],
)


@router.post("/transcribe")
async def transcribe_voice(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="Audio filename is required.",
        )

    if not file.filename.lower().endswith(".wav"):
        raise HTTPException(
            status_code=400,
            detail="Only WAV audio files are supported.",
        )

    temporary_path: Path | None = None

    try:
        audio_data = await file.read()

        if not audio_data:
            raise HTTPException(
                status_code=400,
                detail="Audio file cannot be empty.",
            )

        with tempfile.NamedTemporaryFile(
            suffix=".wav",
            delete=False,
        ) as temporary_file:
            temporary_file.write(audio_data)
            temporary_path = Path(temporary_file.name)

        transcription_start = time.perf_counter()
        text = transcribe_wav(temporary_path)
        transcription_time_ms = (time.perf_counter() - transcription_start) * 1000
        record_event(
            db,
            event_type="VOICE_TRANSCRIPTION_COMPLETED",
            details=(
                f"Offline transcription completed; audio_bytes={len(audio_data)}; "
                f"transcription_time_ms={transcription_time_ms:.3f}. Transcript content omitted."
            ),
            actor_id=current_user.username,
            status="success",
        )

        return {
            "filename": file.filename,
            "text": text,
            "transcription_time_ms": round(transcription_time_ms, 3),
        }

    except HTTPException:
        raise

    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    except RuntimeError as exc:
        raise HTTPException(
            status_code=503,
            detail=str(exc),
        ) from exc

    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)

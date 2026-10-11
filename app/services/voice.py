import json
import shutil
import tempfile
import threading
import urllib.error
import urllib.request
import wave
import zipfile
from pathlib import Path

from app.storage_paths import data_path

MODEL_NAME = "vosk-model-small-en-us-0.15"
MODEL_PATH = data_path("models", "vosk", MODEL_NAME)
MODEL_URL = f"https://alphacephei.com/vosk/models/{MODEL_NAME}.zip"
MAX_MODEL_ARCHIVE_BYTES = 100 * 1024 * 1024
MAX_MODEL_UNPACKED_BYTES = 250 * 1024 * 1024


_model = None
_model_lock = threading.Lock()


def _model_is_ready(path: Path) -> bool:
    return (path / "am" / "final.mdl").is_file() and (path / "conf" / "model.conf").is_file()


def _download_model() -> None:
    """Fetch and safely unpack the small English model on first voice use."""
    if _model_is_ready(MODEL_PATH):
        return

    parent = MODEL_PATH.parent
    parent.mkdir(parents=True, exist_ok=True)
    temporary_dir = Path(tempfile.mkdtemp(prefix="vosk-model-", dir=parent))
    archive_path = temporary_dir / "model.zip"
    extracted_dir = temporary_dir / "extracted"
    extracted_dir.mkdir()

    try:
        request = urllib.request.Request(
            MODEL_URL,
            headers={"User-Agent": "SecureTransfer/0.2"},
        )
        with urllib.request.urlopen(request, timeout=90) as response:
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > MAX_MODEL_ARCHIVE_BYTES:
                raise RuntimeError("The Vosk model archive exceeded the size limit.")
            total = 0
            with archive_path.open("wb") as archive_file:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_MODEL_ARCHIVE_BYTES:
                        raise RuntimeError("The Vosk model archive exceeded the size limit.")
                    archive_file.write(chunk)

        with zipfile.ZipFile(archive_path) as archive:
            entries = archive.infolist()
            if sum(item.file_size for item in entries) > MAX_MODEL_UNPACKED_BYTES:
                raise RuntimeError("The unpacked Vosk model exceeded the size limit.")
            root = extracted_dir.resolve()
            for item in entries:
                destination = (extracted_dir / item.filename).resolve()
                if destination != root and root not in destination.parents:
                    raise RuntimeError("The Vosk model archive contains an invalid path.")
            archive.extractall(extracted_dir)

        downloaded_model = extracted_dir / MODEL_NAME
        if not _model_is_ready(downloaded_model):
            raise RuntimeError("The downloaded Vosk model archive is incomplete.")
        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        downloaded_model.replace(MODEL_PATH)
    except (OSError, urllib.error.URLError, zipfile.BadZipFile) as exc:
        raise RuntimeError(
            "Could not download the Vosk speech model. Check the backend's internet access and try again."
        ) from exc
    finally:
        shutil.rmtree(temporary_dir, ignore_errors=True)


def get_vosk_model():
    """Load the Vosk model once and reuse it."""
    global _model

    if _model is None:
        with _model_lock:
            if _model is None:
                from vosk import Model

                _download_model()
                _model = Model(str(MODEL_PATH))

    return _model


def validate_wav_file(file_path: str | Path) -> wave.Wave_read:
    """Validate that an audio file is a supported PCM WAV file."""
    path = Path(file_path)

    if not path.exists():
        raise ValueError("Audio file does not exist.")

    if not path.is_file():
        raise ValueError("Audio path is not a file.")

    try:
        audio = wave.open(str(path), "rb")
    except (wave.Error, EOFError) as exc:
        raise ValueError(
            "Audio file must be a valid WAV file."
        ) from exc

    if audio.getnchannels() != 1:
        audio.close()
        raise ValueError(
            "Audio must be mono."
        )

    if audio.getsampwidth() != 2:
        audio.close()
        raise ValueError(
            "Audio must use 16-bit PCM."
        )

    if audio.getcomptype() != "NONE":
        audio.close()
        raise ValueError(
            "Audio must use uncompressed PCM."
        )

    return audio


def transcribe_wav(file_path: str | Path) -> str:
    """Transcribe a mono 16-bit PCM WAV file completely offline."""
    audio = validate_wav_file(file_path)

    try:
        from vosk import KaldiRecognizer

        model = get_vosk_model()

        recognizer = KaldiRecognizer(
            model,
            audio.getframerate(),
        )

        recognizer.SetWords(True)

        while True:
            data = audio.readframes(4000)

            if not data:
                break

            recognizer.AcceptWaveform(data)

        final_result = json.loads(
            recognizer.FinalResult()
        )

        return final_result.get("text", "").strip()

    finally:
        audio.close()

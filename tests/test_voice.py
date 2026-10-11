from pathlib import Path
import wave

import pytest

from app.services.voice import (
    validate_wav_file,
    transcribe_wav,
)


def create_test_wav(path: Path):
    with wave.open(str(path), "wb") as audio:
        audio.setnchannels(1)
        audio.setsampwidth(2)
        audio.setframerate(16000)
        audio.writeframes(b"\x00\x00" * 16000)


def test_validate_wav_file(tmp_path):
    wav_path = tmp_path / "test.wav"
    create_test_wav(wav_path)

    audio = validate_wav_file(wav_path)

    try:
        assert audio.getnchannels() == 1
        assert audio.getsampwidth() == 2
        assert audio.getframerate() == 16000
    finally:
        audio.close()


def test_validate_wav_rejects_missing_file(tmp_path):
    with pytest.raises(
        ValueError,
        match="does not exist",
    ):
        validate_wav_file(tmp_path / "missing.wav")


def test_validate_wav_rejects_stereo(tmp_path):
    wav_path = tmp_path / "stereo.wav"

    with wave.open(str(wav_path), "wb") as audio:
        audio.setnchannels(2)
        audio.setsampwidth(2)
        audio.setframerate(16000)
        audio.writeframes(b"\x00\x00" * 32000)

    with pytest.raises(
        ValueError,
        match="mono",
    ):
        validate_wav_file(wav_path)


def test_transcribe_silent_wav(tmp_path):
    wav_path = tmp_path / "silent.wav"
    create_test_wav(wav_path)

    result = transcribe_wav(wav_path)

    assert isinstance(result, str)

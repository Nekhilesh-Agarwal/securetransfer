from pathlib import Path

import pytest

from app.services.qr import (
    decode_pairing_qr,
    generate_pairing_qr,
)


def test_generate_and_decode_pairing_qr(tmp_path: Path):
    qr_path = tmp_path / "test_pairing_qr.png"

    generated_path = generate_pairing_qr(qr_path)

    assert generated_path.exists()

    data = decode_pairing_qr(generated_path)

    assert data["version"] == 1
    assert data["device"]
    assert "public_key" in data
    assert "fingerprint" in data


def test_decode_missing_qr():
    with pytest.raises(FileNotFoundError):
        decode_pairing_qr("does_not_exist.png")
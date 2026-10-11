from io import BytesIO
from pathlib import Path

import cv2
import qrcode

from app.security.pairing import (
    create_pairing_payload,
    verify_pairing_payload,
)


def _pairing_qr_image(payload: str | None = None):
    """Build a screen-friendly pairing QR that is easier for laptop cameras to resolve."""
    if payload is None:
        payload = create_pairing_payload()
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=8,
    )
    qr.add_data(payload)
    qr.make(fit=True)
    return qr.make_image(
        fill_color="black",
        back_color="white",
    ).convert("RGB")


def pairing_qr_png_bytes(payload: str | None = None) -> bytes:
    buffer = BytesIO()
    _pairing_qr_image(payload=payload).save(buffer, format="PNG")
    return buffer.getvalue()


def generate_pairing_qr(
    output_path: str | Path = "pairing_qr.png",
) -> Path:
    """Generate a QR code containing the device pairing payload."""
    output = Path(output_path)
    _pairing_qr_image().save(output)
    return output


def _decode_qr_payload(image) -> str:
    detectors = [cv2.QRCodeDetector()]
    if hasattr(cv2, "QRCodeDetectorAruco"):
        detectors.insert(0, cv2.QRCodeDetectorAruco())

    candidates = [image]
    if image.ndim == 3:
        candidates.append(cv2.cvtColor(image, cv2.COLOR_BGR2GRAY))

    for detector in detectors:
        for candidate in candidates:
            payload, *_ = detector.detectAndDecode(candidate)
            if payload:
                return payload
    return ""


def decode_pairing_qr(
    image_path: str | Path,
) -> dict:
    """
    Decode a QR image and verify the contained pairing payload.
    """
    image_path = Path(image_path)

    if not image_path.exists():
        raise FileNotFoundError(
            f"QR image not found: {image_path}"
        )

    image = cv2.imread(str(image_path))

    if image is None:
        raise ValueError("Unable to read QR image.")

    payload = _decode_qr_payload(image)
    if not payload:
        raise ValueError("No QR code could be decoded.")

    return verify_pairing_payload(payload)

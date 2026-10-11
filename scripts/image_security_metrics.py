"""Quantify AES-GCM image encryption using six academic metrics."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.evaluation.image_metrics import evaluate


def _synthetic_image(path: Path) -> Path:
    import cv2
    import numpy as np

    path.parent.mkdir(parents=True, exist_ok=True)
    pixels = np.tile(np.arange(256, dtype=np.uint8), (128, 2))[:128, :256]
    cv2.imwrite(str(path), pixels)
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description="SecureTransfer image metrics")
    parser.add_argument(
        "image",
        type=Path,
        nargs="?",
        help="Path to a test image (optional; a sample is generated if omitted)",
    )
    args = parser.parse_args()
    image = args.image or _synthetic_image(
        ROOT / "storage" / "samples" / "metrics-sample.png"
    )
    print(json.dumps(evaluate(image), indent=2))


if __name__ == "__main__":
    main()

import numpy as np
import cv2

from app.evaluation.image_metrics import evaluate


def test_image_metrics_on_synthetic_image(tmp_path):
    image_path = tmp_path / "plain.png"
    pixels = np.tile(np.arange(256, dtype=np.uint8), (128, 2))[:128, :256]
    cv2.imwrite(str(image_path), pixels)

    result = evaluate(image_path)

    assert result["entropy_cipher"] > 7.5
    assert result["npcr_percent"] > 90
    assert result["uaci_percent"] > 20
    assert abs(result["correlation_cipher"]) < abs(result["correlation_plain"]) or abs(
        result["correlation_cipher"]
    ) < 0.2
    assert result["mse_cipher"] > 0
    assert result["mse_decrypted"] == 0
    assert result["psnr_decrypted_db"] == "inf"
    assert result["psnr_cipher_db"] < 20

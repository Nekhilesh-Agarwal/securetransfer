"""Latency, overhead, and throughput for AES-256-GCM transfers."""

from __future__ import annotations

import json
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.security.encryption import decrypt_data, encrypt_data


def _bench(size: int, rounds: int = 25) -> dict:
    plaintext = b"S" * size
    key = b"k" * 32
    times: list[float] = []
    ciphertext = b""
    nonce = b""

    for _ in range(rounds):
        start = time.perf_counter()
        ciphertext, nonce = encrypt_data(plaintext, key, b"bench")
        decrypt_data(ciphertext, nonce, key, b"bench")
        times.append(time.perf_counter() - start)

    mean = statistics.mean(times)
    overhead = (len(ciphertext) + len(nonce) - size) / size * 100
    throughput_mb_s = (size / mean) / (1024 * 1024) if mean else 0
    return {
        "bytes": size,
        "label": f"{size}B payload",
        "rounds": rounds,
        "mean_latency_ms": round(mean * 1000, 4),
        "overhead_percent": round(overhead, 4),
        "throughput_mib_s": round(throughput_mb_s, 4),
    }


def main() -> None:
    image_sizes = (
        64,
        1024,
        64 * 64,
        256 * 256,
        512 * 512,
        1024 * 1024,
    )
    results = [_bench(size) for size in image_sizes]
    print(json.dumps({"results": results}, indent=2))


if __name__ == "__main__":
    main()

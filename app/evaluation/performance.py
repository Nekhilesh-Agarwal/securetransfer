"""Bounded, repeatable AES-GCM processing benchmark for the admin dashboard."""

from __future__ import annotations

import os
import statistics
import time

from app.security.encryption import decrypt_data, encrypt_data


SAMPLE_SIZES = (1024, 64 * 1024, 256 * 1024, 1024 * 1024)
BENCHMARK_ROUNDS = 8


def run_performance_benchmark() -> dict:
    """Measure encrypt, decrypt, combined time, copy baseline, and overhead."""
    results = []
    rounds = BENCHMARK_ROUNDS

    for size in SAMPLE_SIZES:
        payload = os.urandom(size)
        key = os.urandom(32)
        baseline_times = []
        encrypt_times = []
        decrypt_times = []
        roundtrip_times = []
        ciphertext = b""
        nonce = b""

        for _ in range(rounds):
            start = time.perf_counter()
            memoryview(payload).tobytes()
            baseline_times.append(time.perf_counter() - start)

            start = time.perf_counter()
            ciphertext, nonce = encrypt_data(payload, key, b"admin-evaluation")
            encrypt_times.append(time.perf_counter() - start)

            start = time.perf_counter()
            decrypt_data(ciphertext, nonce, key, b"admin-evaluation")
            decrypt_times.append(time.perf_counter() - start)
            roundtrip_times.append(encrypt_times[-1] + decrypt_times[-1])

        mean_encrypt = statistics.mean(encrypt_times)
        mean_decrypt = statistics.mean(decrypt_times)
        mean_roundtrip = statistics.mean(roundtrip_times)
        overhead_bytes = len(ciphertext) + len(nonce) - size
        results.append(
            {
                "bytes": size,
                "rounds": rounds,
                "baseline_copy_ms": round(statistics.mean(baseline_times) * 1000, 4),
                "encryption_ms": round(mean_encrypt * 1000, 4),
                "decryption_ms": round(mean_decrypt * 1000, 4),
                "total_crypto_ms": round(mean_roundtrip * 1000, 4),
                "aes_gcm_roundtrip_ms": round(mean_roundtrip * 1000, 4),
                "crypto_overhead_bytes": overhead_bytes,
                "crypto_overhead_percent": round(overhead_bytes / size * 100, 4),
                "crypto_roundtrip_mib_per_second": round(
                    (size / mean_roundtrip) / (1024 * 1024), 4
                ) if mean_roundtrip else 0,
            }
        )

    return {
        "rounds": rounds,
        "results": results,
        "note": (
            "Backend AES-GCM processing benchmark. Encryption, decryption and combined "
            "times are averaged over each payload size. It excludes HTTP/network, "
            "device, disk and speech-transcription time; run it on the deployment "
            "instance to measure that instance."
        ),
    }

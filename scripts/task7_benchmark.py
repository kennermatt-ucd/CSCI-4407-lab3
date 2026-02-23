"""
Task 7 — Performance Benchmarking (10 pts)
============================================
Benchmarks AES-ECB, AES-CBC, AES-CTR, and AES-GCM across three file sizes.

Methodology:
- File sizes: 1 KB, 1 MB, 10 MB
- Modes: ECB, CBC, CTR, GCM
- Each (mode, file size) combination is repeated 5 times and averaged
  to reduce timing variance caused by system load and cache effects.
- Reports average encryption and decryption time in seconds.
"""

import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

KEY_SIZE      = 32    # 256-bit
BLOCK_SIZE    = 16
GCM_NONCE_SIZE = 12
REPETITIONS   = 5     # repeat 5 times and average

FILE_SIZES = {
    "1 KB":  1 * 1024,
    "1 MB":  1 * 1024 * 1024,
    "10 MB": 10 * 1024 * 1024,
}


# ---------------------------------------------------------------------------
# Padding helpers (ECB and CBC need block-aligned input)
# ---------------------------------------------------------------------------

def pkcs7_pad(data: bytes) -> bytes:
    padder = padding.PKCS7(BLOCK_SIZE * 8).padder()
    return padder.update(data) + padder.finalize()


def pkcs7_unpad(data: bytes) -> bytes:
    unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
    return unpadder.update(data) + unpadder.finalize()


# ---------------------------------------------------------------------------
# Encrypt / decrypt functions (one call per mode)
# ---------------------------------------------------------------------------

def bench_ecb(key: bytes, plaintext: bytes) -> tuple[float, float]:
    """Return (enc_time, dec_time) for AES-ECB."""
    padded = pkcs7_pad(plaintext)

    t0 = time.perf_counter()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    enc = cipher.encryptor()
    ct = enc.update(padded) + enc.finalize()
    enc_time = time.perf_counter() - t0

    t0 = time.perf_counter()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    dec = cipher.decryptor()
    pkcs7_unpad(dec.update(ct) + dec.finalize())
    dec_time = time.perf_counter() - t0

    return enc_time, dec_time


def bench_cbc(key: bytes, plaintext: bytes) -> tuple[float, float]:
    """Return (enc_time, dec_time) for AES-CBC with PKCS#7."""
    iv     = os.urandom(BLOCK_SIZE)
    padded = pkcs7_pad(plaintext)

    t0 = time.perf_counter()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    ct = enc.update(padded) + enc.finalize()
    enc_time = time.perf_counter() - t0

    t0 = time.perf_counter()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    pkcs7_unpad(dec.update(ct) + dec.finalize())
    dec_time = time.perf_counter() - t0

    return enc_time, dec_time


def bench_ctr(key: bytes, plaintext: bytes) -> tuple[float, float]:
    """Return (enc_time, dec_time) for AES-CTR."""
    nonce = os.urandom(BLOCK_SIZE)

    t0 = time.perf_counter()
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    enc = cipher.encryptor()
    ct = enc.update(plaintext) + enc.finalize()
    enc_time = time.perf_counter() - t0

    t0 = time.perf_counter()
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    dec = cipher.decryptor()
    dec.update(ct) + dec.finalize()
    dec_time = time.perf_counter() - t0

    return enc_time, dec_time


def bench_gcm(key: bytes, plaintext: bytes) -> tuple[float, float]:
    """Return (enc_time, dec_time) for AES-GCM (AEAD)."""
    aesgcm = AESGCM(key)
    nonce  = os.urandom(GCM_NONCE_SIZE)

    t0 = time.perf_counter()
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    enc_time = time.perf_counter() - t0

    t0 = time.perf_counter()
    aesgcm.decrypt(nonce, ct, associated_data=None)
    dec_time = time.perf_counter() - t0

    return enc_time, dec_time


BENCH_FUNCS = {
    "ECB": bench_ecb,
    "CBC": bench_cbc,
    "CTR": bench_ctr,
    "GCM": bench_gcm,
}


# ---------------------------------------------------------------------------
# Runner — each combination repeated 5 times and averaged
# ---------------------------------------------------------------------------

def run_benchmark(key: bytes) -> dict:
    results = {}
    for size_label, size_bytes in FILE_SIZES.items():
        plaintext = os.urandom(size_bytes)
        for mode_name, bench_fn in BENCH_FUNCS.items():
            enc_times = []
            dec_times = []
            for _ in range(REPETITIONS):
                e, d = bench_fn(key, plaintext)
                enc_times.append(e)
                dec_times.append(d)
            avg_enc = sum(enc_times) / REPETITIONS
            avg_dec = sum(dec_times) / REPETITIONS
            results[(size_label, mode_name)] = (avg_enc, avg_dec)
    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    key = os.urandom(KEY_SIZE)
    print(f"=== Task 7: AES Mode Performance Benchmark ===")
    print(f"Key (hex): {key.hex()}")
    print(f"Repetitions per combination: {REPETITIONS} (results are averaged)\n")

    results = run_benchmark(key)

    # Print results table
    header = f"{'File Size':<10} {'Mode':<6} {'Avg Enc (s)':<16} {'Avg Dec (s)'}"
    print(header)
    print("-" * len(header))
    for size_label in FILE_SIZES:
        for mode_name in BENCH_FUNCS:
            avg_enc, avg_dec = results[(size_label, mode_name)]
            print(f"{size_label:<10} {mode_name:<6} {avg_enc:<16.6f} {avg_dec:.6f}")
        print()

    print("TODO: copy this table into report.md and write the performance analysis.")

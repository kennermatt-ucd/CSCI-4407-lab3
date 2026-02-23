"""
Task 2 — CBC IV Experiment (15 pts)
=====================================
Demonstrates the effect of IV handling in AES-CBC.

CBC formula: C_i = E_k(P_i XOR C_{i-1}),  C_0 = IV

Experiments:
1. Fresh IV each time  → different ciphertexts (unlinkable)
2. Reused IV           → identical ciphertexts (linkable / deterministic)
3. Verify decryption correctness via SHA-256
"""

import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

BLOCK_SIZE = 16
PLAINTEXT_SIZE = 256  # >= 256 bytes as required


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    padder = padding.PKCS7(block_size * 8).padder()
    return padder.update(data) + padder.finalize()


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    unpadder = padding.PKCS7(block_size * 8).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """Encrypt plaintext with AES-CBC using PKCS#7 padding."""
    padded = pkcs7_pad(plaintext)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Decrypt ciphertext with AES-CBC and remove PKCS#7 padding."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return pkcs7_unpad(padded)


# ---------------------------------------------------------------------------
# Experiments
# ---------------------------------------------------------------------------

def experiment_fresh_iv(key: bytes, plaintext: bytes) -> None:
    """
    Encrypt the same plaintext twice with DIFFERENT random IVs.
    Expected: ciphertexts differ — SHA-256 hashes should not match.
    """
    print("=== Experiment 1: Fresh IV (different each time) ===")
    iv1 = os.urandom(BLOCK_SIZE)
    iv2 = os.urandom(BLOCK_SIZE)
    c1 = cbc_encrypt(key, iv1, plaintext)
    c2 = cbc_encrypt(key, iv2, plaintext)
    h1 = sha256(c1)
    h2 = sha256(c2)
    print(f"  IV1:             {iv1.hex()}")
    print(f"  IV2:             {iv2.hex()}")
    print(f"  SHA-256(C1):     {h1}")
    print(f"  SHA-256(C2):     {h2}")
    print(f"  Ciphertexts match: {h1 == h2}  (expected: False)\n")


def experiment_reused_iv(key: bytes, plaintext: bytes) -> None:
    """
    Encrypt the same plaintext twice with the SAME IV.
    Expected: ciphertexts are identical — SHA-256 hashes must match.
    """
    print("=== Experiment 2: Reused IV (same IV both times) ===")
    iv = os.urandom(BLOCK_SIZE)
    c1 = cbc_encrypt(key, iv, plaintext)
    c2 = cbc_encrypt(key, iv, plaintext)
    h1 = sha256(c1)
    h2 = sha256(c2)
    print(f"  IV:              {iv.hex()}")
    print(f"  SHA-256(C1):     {h1}")
    print(f"  SHA-256(C2):     {h2}")
    print(f"  Ciphertexts match: {h1 == h2}  (expected: True)\n")


def experiment_decryption_verification(key: bytes, plaintext: bytes) -> None:
    """
    Encrypt then decrypt and verify via SHA-256.
    """
    print("=== Experiment 3: Decryption Correctness (SHA-256 verification) ===")
    iv = os.urandom(BLOCK_SIZE)
    ciphertext = cbc_encrypt(key, iv, plaintext)
    recovered = cbc_decrypt(key, iv, ciphertext)
    h_orig = sha256(plaintext)
    h_recv = sha256(recovered)
    print(f"  SHA-256(original):  {h_orig}")
    print(f"  SHA-256(decrypted): {h_recv}")
    print(f"  Match: {h_orig == h_recv}  (expected: True)\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    key = os.urandom(32)
    plaintext = os.urandom(PLAINTEXT_SIZE)

    print(f"AES key (hex): {key.hex()}")
    print(f"Plaintext length: {len(plaintext)} bytes\n")

    experiment_fresh_iv(key, plaintext)
    experiment_reused_iv(key, plaintext)
    experiment_decryption_verification(key, plaintext)

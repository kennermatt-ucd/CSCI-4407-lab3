"""
Task 3 — CTR Implementation (10 pts)
======================================
Implements AES-CTR encryption and decryption on a 4096-byte test file.

CTR formula: C_i = P_i XOR E_k(Nonce || Counter_i)
Encryption == decryption (same operation, symmetric).
No padding required.

Steps:
1. Create 4096-byte test file
2. Generate key (256-bit) + nonce (128-bit)
3. Encrypt
4. Decrypt
5. Verify with SHA-256 hashes
"""

import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

FILE_SIZE = 4096       # bytes
KEY_SIZE  = 32         # 256-bit AES key
NONCE_SIZE = 16        # 128-bit nonce (full block for CTR)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ctr_encrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """
    AES-CTR encryption.
    nonce must be 16 bytes for AES-128/256 CTR (used as the initial counter value).
    """
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def ctr_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """AES-CTR decryption — identical operation to encryption."""
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # --- Setup ---
    key   = os.urandom(KEY_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    plaintext = os.urandom(FILE_SIZE)

    print("=== AES-CTR Implementation ===")
    print(f"Key   ({KEY_SIZE * 8}-bit): {key.hex()}")
    print(f"Nonce ({NONCE_SIZE * 8}-bit): {nonce.hex()}")
    print(f"Plaintext size: {len(plaintext)} bytes\n")

    # --- Encrypt ---
    ciphertext = ctr_encrypt(key, nonce, plaintext)
    print(f"Ciphertext size: {len(ciphertext)} bytes")
    print(f"Ciphertext (first 32 bytes): {ciphertext[:32].hex()}\n")

    # --- Decrypt ---
    recovered = ctr_decrypt(key, nonce, ciphertext)
    print(f"Recovered size: {len(recovered)} bytes\n")

    # --- SHA-256 verification ---
    h_orig = sha256(plaintext)
    h_recv = sha256(recovered)
    print("=== SHA-256 Verification ===")
    print(f"SHA-256(original):  {h_orig}")
    print(f"SHA-256(decrypted): {h_recv}")
    print(f"Match: {h_orig == h_recv}  (expected: True)")

# Lab 3 — Symmetric Encryption: Block Ciphers, IND-CPA, AEAD & Cryptographic Failures

**Course:** CSCI/CSCY 4407 — Security & Cryptography
**Semester:** Spring 2026
**Date:** [DATE]
**Group Members:** [NAMES]

---

## Task 1 — ECB Distinguisher (15 pts)

### Source Code

```python
# [PASTE ECB ENCRYPTION + DISTINGUISHER CODE HERE]
```

### Repeated Ciphertext Block Evidence

[INSERT SCREENSHOT: Ciphertext output showing duplicate 16-byte blocks for P0 (repeated plaintext)]

```
# [PASTE HEX OUTPUT OR BLOCK COMPARISON HERE]
```

### Trial Results Table (≥ 20 Trials)

| Trial | b (chosen) | b' (guessed) | Correct? |
|-------|-----------|--------------|----------|
| 1     |           |              |          |
| 2     |           |              |          |
| 3     |           |              |          |
| 4     |           |              |          |
| 5     |           |              |          |
| 6     |           |              |          |
| 7     |           |              |          |
| 8     |           |              |          |
| 9     |           |              |          |
| 10    |           |              |          |
| 11    |           |              |          |
| 12    |           |              |          |
| 13    |           |              |          |
| 14    |           |              |          |
| 15    |           |              |          |
| 16    |           |              |          |
| 17    |           |              |          |
| 18    |           |              |          |
| 19    |           |              |          |
| 20    |           |              |          |

### Success Rate and Advantage

**Number of correct guesses:** [X / 20]

**Success Rate:** [X / 20 = X%]

**IND-CPA Advantage:**

```
Adv_IND-CPA = |Pr[b' = b] - 1/2| = [VALUE]
```

### Explanation: Why ECB Violates Semantic Security

[EXPLAIN why ECB is deterministic (C_i = E_k(P_i)) and why identical plaintext blocks always produce identical ciphertext blocks. Explain why this pattern leakage means an adversary can distinguish encryptions of different messages, and therefore ECB fails IND-CPA.]

---

## Task 2 — CBC IV Experiment (15 pts)

### Source Code

```python
# [PASTE CBC ENCRYPTION/DECRYPTION CODE WITH PKCS#7 PADDING HERE]
```

### Evidence: Fresh IV → Different Ciphertext

[INSERT SCREENSHOT: Two encryptions of the same plaintext under different IVs producing different ciphertexts]

```
# [PASTE SHA-256 HASHES OF BOTH CIPHERTEXTS HERE — THEY SHOULD DIFFER]
SHA-256(C_fresh_1): [HASH]
SHA-256(C_fresh_2): [HASH]
```

### Evidence: Reused IV → Linkability

[INSERT SCREENSHOT: Two encryptions under the same IV producing the same or linkable ciphertext]

```
# [PASTE SHA-256 HASHES OF BOTH CIPHERTEXTS HERE — THEY SHOULD MATCH]
SHA-256(C_reused_1): [HASH]
SHA-256(C_reused_2): [HASH]
```

### Decryption Verification (SHA-256)

```
SHA-256(original plaintext): [HASH]
SHA-256(decrypted plaintext): [HASH]
Match: [YES/NO]
```

### Explanation: Why a Fresh IV Is Required

[EXPLAIN that CBC chains each block as C_i = E_k(P_i XOR C_{i-1}) with C_0 = IV. If the IV is reused with the same key and same plaintext, the ciphertext is identical — leaking that the same message was sent. Even with different plaintexts, a reused IV allows an attacker to detect when the first block is the same. A fresh random IV per encryption ensures ciphertexts are unlinkable and semantically secure.]

---

## Task 3 — CTR Implementation (10 pts)

### Source Code

```python
# [PASTE CTR ENCRYPTION/DECRYPTION CODE HERE]
```

### Key and Nonce Details

| Parameter | Size | Value |
|-----------|------|-------|
| Key       | [X bits] | [HEX] |
| Nonce     | [X bytes] | [HEX] |
| Test file | 4096 bytes | — |

### Encryption and Decryption Output

[INSERT SCREENSHOT: Script run showing encryption and decryption of the 4096-byte test file]

### SHA-256 Hash Verification

```
SHA-256(original file):   [HASH]
SHA-256(decrypted file):  [HASH]
Match: [YES/NO]
```

### Explanation: Why CTR Behaves Like a Stream Cipher

[EXPLAIN that CTR generates a keystream by encrypting successive counter values: K_i = E_k(Nonce || Counter_i). The plaintext is XORed with this keystream, making encryption and decryption identical operations. No padding is required and blocks can be processed in parallel since each block's keystream is independent.]

---

## Task 4 — CTR Nonce Reuse Attack (20 pts)

### Group Ciphertext Package

**Group number:** 10
**Files used:** [LIST FILENAMES FROM GROUP PACKAGE]

### XOR Script

```python
# [PASTE SCRIPT USED TO COMPUTE C1 XOR C2 HERE]
```

### XOR Output Evidence

[INSERT SCREENSHOT: xxd or strings output on X = C1 XOR C2]

```
# [PASTE RELEVANT HEX/STRING OUTPUT OF X = C1 XOR C2 HERE]
```

### Recovered Plaintext (≥ 20 bytes via Crib Dragging)

| Offset | Crib Used | Recovered Text |
|--------|-----------|----------------|
| [OFFSET] | [WORD] | [RECOVERED SEGMENT] |
| [OFFSET] | [WORD] | [RECOVERED SEGMENT] |
| [OFFSET] | [WORD] | [RECOVERED SEGMENT] |
| [OFFSET] | [WORD] | [RECOVERED SEGMENT] |
| [OFFSET] | [WORD] | [RECOVERED SEGMENT] |

**Total bytes recovered:** [≥ 20]

### Explanation of Keystream Reuse

**Violated assumption: nonce uniqueness** — CTR mode is secure only when every (key, nonce) pair is used for exactly one encryption; reusing the same nonce with the same key directly violates this assumption and renders the scheme insecure.

[EXPLAIN that when the same nonce is reused in CTR mode with the same key, both ciphertexts are encrypted with the identical keystream K. XORing them cancels K entirely: C1 XOR C2 = (P1 XOR K) XOR (P2 XOR K) = P1 XOR P2. This reduces the problem to breaking a two-time pad, which can be solved by crib dragging.]

### Mathematical Explanation of Two-Time Pad Failure

[EXPLAIN formally that in the one-time pad / CTR model, security requires the key (keystream) to be used only once. When reused: C1 = P1 XOR K, C2 = P2 XOR K → C1 XOR C2 = P1 XOR P2. The key is eliminated, and any known or guessable structure in P1 or P2 can be exploited to recover both plaintexts.]

---

## Task 5 — Birthday Attack on CTR (15 pts)

### Source Code

```python
# [PASTE COLLISION SIMULATION SCRIPT HERE]
# Uses small nonce size (e.g. r = 16 bits)
# Generates random nonce per encryption
# Records number of encryptions until first nonce collision
```

### Nonce Size Used

**r =** [e.g., 16 bits]
**Theoretical birthday bound:** q ≈ 1.2 × 2^(r/2) ≈ [VALUE]

### Collision Experiment Results (≥ 20 Runs)

| Run | Encryptions Until Collision |
|-----|-----------------------------|
| 1   |                             |
| 2   |                             |
| 3   |                             |
| 4   |                             |
| 5   |                             |
| 6   |                             |
| 7   |                             |
| 8   |                             |
| 9   |                             |
| 10  |                             |
| 11  |                             |
| 12  |                             |
| 13  |                             |
| 14  |                             |
| 15  |                             |
| 16  |                             |
| 17  |                             |
| 18  |                             |
| 19  |                             |
| 20  |                             |

**Average collision point:** [VALUE]

### Comparison to Theoretical Birthday Bound

| Metric | Value |
|--------|-------|
| r (nonce bits) | [VALUE] |
| Theoretical bound (1.2 × 2^(r/2)) | [VALUE] |
| Observed average | [VALUE] |
| Difference | [VALUE] |

[BRIEFLY DISCUSS whether observed average aligns with the theoretical bound and any deviation]

### Collision Enabling Two-Time Pad Demonstration

[INSERT SCREENSHOT OR OUTPUT: Showing that the two colliding-nonce ciphertexts XOR to P1 XOR P2]

```
# [PASTE EVIDENCE HERE]
```

### Explanation: How Nonce Collision Leads to CTR Insecurity

[EXPLAIN that because CTR generates keystream as K_i = E_k(Nonce || Counter_i), two encryptions sharing the same nonce produce the same keystream. A birthday collision therefore creates a two-time pad scenario where C1 XOR C2 = P1 XOR P2, allowing an attacker to recover plaintext structure. This is why nonce/counter uniqueness is a hard requirement for CTR security.]

---

## Task 6 — Integrity vs. Confidentiality (AES-GCM) (10 pts)

### Source Code

```python
"""
Task 6 — Integrity vs. Confidentiality (AES-GCM) (10 pts)
============================================================
Demonstrates the difference between confidentiality-only (CBC) and
authenticated encryption (GCM / AEAD).

CBC:
  - Flipping a byte in the ciphertext corrupts the corresponding plaintext block
    and causes predictable bit-flips in the NEXT block — but CBC accepts it silently.
  - No integrity guarantee: tampering is undetected.

GCM (AEAD):
  - The authentication tag T covers the entire ciphertext.
  - Any modification to the ciphertext OR the tag causes decryption to raise
    an InvalidTag exception — tampering is always detected.
"""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

KEY_SIZE   = 32   # 256-bit
BLOCK_SIZE = 16
GCM_NONCE_SIZE = 12   # 96-bit recommended for GCM


# ---------------------------------------------------------------------------
# CBC helpers (PKCS#7)
# ---------------------------------------------------------------------------

def pkcs7_pad(data: bytes) -> bytes:
    padder = padding.PKCS7(BLOCK_SIZE * 8).padder()
    return padder.update(data) + padder.finalize()


def pkcs7_unpad(data: bytes) -> bytes:
    unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    padded = pkcs7_pad(plaintext)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(padded) + enc.finalize()


def cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    return pkcs7_unpad(padded)


def flip_byte(data: bytes, offset: int) -> bytes:
    """Flip a single byte in data at the given offset."""
    ba = bytearray(data)
    ba[offset] ^= 0xFF
    return bytes(ba)


# ---------------------------------------------------------------------------
# Task 6a: CBC tamper test
# ---------------------------------------------------------------------------

def test_cbc_tamper(key: bytes, plaintext: bytes) -> None:
    print("=== CBC Tamper Test ===")
    iv = os.urandom(BLOCK_SIZE)
    ciphertext = cbc_encrypt(key, iv, plaintext)
    tampered   = flip_byte(ciphertext, offset=0)  # flip first byte

    print(f"  Original  ciphertext[0]: {ciphertext[0]:02x}")
    print(f"  Tampered  ciphertext[0]: {tampered[0]:02x}")

    try:
        recovered = cbc_decrypt(key, iv, tampered)
        print(f"  Decryption succeeded (no authentication check in CBC).")
        print(f"  Original  plaintext (hex): {plaintext[:32].hex()}")
        print(f"  Recovered plaintext (hex): {recovered[:32].hex()}")
        print(f"  Data corruption detected by comparison: {plaintext[:32] != recovered[:32]}")
    except Exception as e:
        print(f"  Decryption raised: {e}")

    print()


# ---------------------------------------------------------------------------
# Task 6b: GCM tamper test
# ---------------------------------------------------------------------------

def test_gcm_tamper(key: bytes, plaintext: bytes) -> None:
    print("=== GCM Tamper Test ===")
    aesgcm = AESGCM(key)
    nonce  = os.urandom(GCM_NONCE_SIZE)
    ciphertext_tag = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    # ciphertext_tag = ciphertext || 16-byte tag

    tampered = flip_byte(ciphertext_tag, offset=0)  # flip one byte in ciphertext

    print(f"  Original  ciphertext_tag[0]: {ciphertext_tag[0]:02x}")
    print(f"  Tampered  ciphertext_tag[0]: {tampered[0]:02x}")

    try:
        aesgcm.decrypt(nonce, tampered, associated_data=None)
        print("  ERROR: Decryption succeeded despite tampering — this should not happen.")
    except InvalidTag:
        print("  InvalidTag exception raised — tampering detected. (expected)")
    except Exception as e:
        print(f"  Unexpected exception: {e}")

    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    key       = os.urandom(KEY_SIZE)
    plaintext = b"This is a secret message that must not be tampered with!" * 2

    print(f"Key (hex): {key.hex()}\n")

    test_cbc_tamper(key, plaintext)
    test_gcm_tamper(key, plaintext)

    print("=== Summary ===")
    print("  CBC: accepts tampered ciphertext — corrupts plaintext silently (no integrity).")
    print("  GCM: rejects tampered ciphertext — raises InvalidTag (AEAD = confidentiality + integrity).")

```

### CBC Tamper Evidence


![Task 6 CBC tamper evidence](Screenshots/task6a.png)
```
=== CBC Tamper Test ===
  Original  ciphertext[0]: ba
  Tampered  ciphertext[0]: 45
  Decryption succeeded (no authentication check in CBC).
  Original  plaintext (hex): 54686973206973206120736563726574206d6573736167652074686174206d75
  Recovered plaintext (hex): 5963f5dbe9e62868bc156abdb4f7dceddf6d6573736167652074686174206d75
  Data corruption detected by comparison: True

```

**Observation:** CBC accepted the tampered ciphertext and still decrypted, producing corrupted plaintext without any authentication error. This shows CBC provides confidentiality but not integrity.

### GCM Tamper Evidence

[INSERT SCREENSHOT: Flip 1 byte in GCM ciphertext or tag → decryption fails with authentication error]
![Task 6 GCM Tamper evidence](Screenshots/task6b.png)
```
=== GCM Tamper Test ===
  Original  ciphertext_tag[0]: 52
  Tampered  ciphertext_tag[0]: ad
  InvalidTag exception raised — tampering detected. (expected)

```

**Observation:** AES-GCM rejected the tampered ciphertext by failing authentication and raising an InvalidTag error. No plaintext was returned, demonstrating integrity protection.

### Comparison: Confidentiality vs. Integrity

Confidentiality ensures that an attacker cannot learn the plaintext without the secret key. Integrity ensures that an attacker cannot modify the ciphertext without the receiver detecting that modification.

In AES-CBC mode, encryption provides confidentiality by transforming plaintext blocks into ciphertext blocks. However, CBC does not authenticate the ciphertext. As demonstrated above, flipping a single byte in the ciphertext caused the first plaintext block to become corrupted, yet decryption still succeeded without any error. This shows that CBC does not provide integrity — tampering may go undetected and result in corrupted but accepted plaintext.

In contrast, AES-GCM is an AEAD (Authenticated Encryption with Associated Data) mode. It produces both ciphertext and an authentication tag T that covers the entire ciphertext (and any associated data). During decryption, this tag is verified. If any bit of the ciphertext or tag is modified, decryption fails and returns ⊥ (represented here by an InvalidTag exception). Therefore, AES-GCM provides both confidentiality and integrity.

In practice, encryption without authentication (such as CBC alone) is insufficient for secure systems. Modern cryptographic standards recommend using AEAD modes like AES-GCM to ensure both secrecy and tamper detection.

---

## Task 7 — Performance Benchmarking (10 pts)

### Source Code

```python
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
```

### Results Table

| File Size | Mode | Avg Enc Time (s) | Avg Dec Time (s) |
|-----------|------|------------------|------------------|
| 1 KB  | ECB | 0.000702 | 0.000007 |
| 1 KB  | CBC | 0.000005 | 0.000004 |
| 1 KB  | CTR | 0.000005 | 0.000004 |
| 1 KB  | GCM | 0.000002 | 0.000001 |
| 1 MB  | ECB | 0.000535 | 0.000516 |
| 1 MB  | CBC | 0.000996 | 0.000475 |
| 1 MB  | CTR | 0.000391 | 0.000264 |
| 1 MB  | GCM | 0.000253 | 0.000279 |
| 10 MB | ECB | 0.002973 | 0.004152 |
| 10 MB | CBC | 0.007460 | 0.004016 |
| 10 MB | CTR | 0.002907 | 0.002410 |
| 10 MB | GCM | 0.002125 | 0.002226 |

### Performance Analysis

PARAGRAPH 1 — DISCUSS:
CBC encryption is sequential because each ciphertext block depends on the previous ciphertext block (Cᵢ = Eₖ(Pᵢ ⊕ Cᵢ₋₁)), which prevents parallelization during encryption. This is reflected in the results: for 10 MB, CBC encryption (0.007460 s) is noticeably slower than CTR (0.002907 s) and GCM (0.002125 s). In contrast, CTR and GCM generate keystream blocks independently using Eₖ(Nonce || Counterᵢ), allowing full parallelization. ECB is also fully parallelizable and appears relatively fast, but it is insecure in practice due to deterministic pattern leakage.

PARAGRAPH 2 — DISCUSS:
AES-GCM introduces authentication overhead by computing a GHASH over the ciphertext to produce an authentication tag. Despite this additional computation, GCM performance is comparable to CTR and often slightly faster in these results (e.g., 10 MB encryption: GCM 0.002125 s vs CTR 0.002907 s). This demonstrates that the integrity protection provided by AEAD comes with minimal performance cost, making AES-GCM the preferred modern mode for secure systems.

---

## Key Lessons Learned

ECB and Determinism:
ECB mode is deterministic: identical plaintext blocks always produce identical ciphertext blocks (Cᵢ = Eₖ(Pᵢ)). This leaks structural patterns in the data and allows an adversary to distinguish encryptions, violating semantic security (IND-CPA). Even though ECB may appear fast in benchmarks, it is insecure for real-world use due to pattern leakage.

IV / Nonce Freshness in CBC and CTR:
Both CBC and CTR rely on randomness (IV or nonce) to achieve semantic security. If a fresh, unpredictable IV/nonce is used for each encryption, ciphertexts remain unlinkable. Reusing an IV or nonce under the same key leaks information about message structure and breaks security assumptions.

Nonce Reuse and Two-Time Pad Failure in CTR:
In CTR mode, ciphertext is generated as C = P ⊕ K where K is the keystream derived from the nonce and counter. If the same nonce is reused with the same key, the identical keystream is reused. XORing two ciphertexts eliminates the keystream:
C₁ ⊕ C₂ = P₁ ⊕ P₂.
This creates a two-time pad scenario, allowing plaintext recovery via crib dragging. Nonce uniqueness is therefore a strict security requirement.

Birthday Bound and Nonce Space Sizing:
The birthday paradox shows that collisions occur after approximately 1.2 × 2^(r/2) encryptions for an r-bit nonce. If the nonce space is too small, collisions become likely, leading to keystream reuse and catastrophic failure in CTR. This demonstrates why modern systems use large nonce sizes (e.g., 96 bits in GCM).

AEAD and Why Confidentiality Alone Is Insufficient:
Encryption alone does not guarantee integrity. As demonstrated with CBC, tampered ciphertext may decrypt to corrupted plaintext without detection. AEAD modes such as AES-GCM provide both confidentiality and integrity by generating an authentication tag. Any modification to the ciphertext or tag causes decryption to fail, preventing silent corruption.

Performance Trade-Offs Between Modes:
ECB, CTR, and GCM can be parallelized and scale efficiently with large data sizes. CBC encryption is sequential due to block chaining, making it slower at scale. Although GCM introduces authentication overhead (GHASH computation), benchmark results show that the performance cost is minimal compared to CTR. Given its integrity guarantees and competitive performance, AES-GCM is the preferred modern mode.

---

## Appendix

### Full Script Listings

[OPTIONAL: Include complete script code if not fully shown in task sections above]

### Additional Screenshots

[OPTIONAL: Include any additional supporting terminal output or evidence]

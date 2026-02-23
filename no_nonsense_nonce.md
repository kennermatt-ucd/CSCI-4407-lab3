
---

# Lab 3 — Symmetric Encryption

## Block Ciphers, IND-CPA, AEAD & Cryptographic Failures

**CSCI/CSCY 4407 – Spring 2026**

---

# What You Must Do

This is a **group assignment**.

* Tasks **1, 2, 3, 5, 6, 7** → Generate your own plaintexts, keys, IVs, nonces, and data.
* **Task 4** → Use your group-assigned ciphertext package from Canvas.
* Do not use another group’s package.
* All results must be reproducible.
* Submit **one PDF report** per group.
* Include Python source code (zipped or separate file).

---

# Technical Requirements

Environment:

* Linux VM (Kali or Ubuntu)
* Python 3
* `cryptography` library
* `sha256sum`, `xxd`, `time`

Implementation requirements:

* Implement AES in:

  * ECB
  * CBC (with PKCS#7 padding)
  * CTR
  * GCM (AEAD)
* Secure random key generation
* Explicit IV/nonce handling
* Demonstrate:

  * Correct usage
  * Misuse (IV/nonce reuse)
* Verify correctness using SHA-256 hashes.

---

# Task 1 — ECB Distinguisher (15 pts)

### Core Idea

ECB is deterministic:

[
C_i = E_k(P_i)
]

[
P_i = P_j \Rightarrow C_i = C_j
]

Fails IND-CPA.

---

### Required Steps

1. Create two plaintexts (multiple of 16 bytes):

   * P0: repeated 16-byte blocks
   * P1: random bytes (same length)

2. Generate AES key.

3. Encrypt both under AES-ECB:

   * C0 = ECB(P0)
   * C1 = ECB(P1)

4. Detect repeated ciphertext blocks.

5. Build distinguisher:

   * Count duplicate 16-byte blocks
   * Output guess ( b' )

6. Run ≥ 20 trials:

   * Choose random ( b )
   * Encrypt ( P_b )
   * Record whether ( b' = b )

Compute:

[
\text{Success Rate} = \frac{#Correct}{#Trials}
]

[
Adv_{IND-CPA} = |Pr[b' = b] - 1/2|
]

---

### Must Submit

* ECB + distinguisher code
* Screenshot showing repeated ciphertext blocks
* Results table (≥20 trials)
* Success rate + advantage
* Explanation: why ECB violates semantic security

---

# Task 2 — CBC IV Experiment (15 pts)

### CBC Formula

[
C_1 = E_k(P_1 \oplus IV)
]

---

### Required Steps

1. Create ≥256-byte plaintext.

2. Encrypt twice with fresh IVs:

   * Show ciphertext differs (hash evidence)

3. Encrypt twice with same IV:

   * Show ciphertext identical or linkable

4. Verify decryption using SHA-256.

---

### Must Submit

* CBC code (with PKCS#7 padding)
* Evidence: fresh IV → different ciphertext
* Evidence: reused IV → linkability
* Hash verification
* Explanation: why fresh IV required

---

# Task 3 — CTR Implementation (10 pts)

### CTR Formula

[
C_i = P_i \oplus E_k(Nonce || Counter_i)
]

Encryption = decryption.

---

### Required Steps

1. Create test file (4096 bytes).
2. Generate key + nonce (document sizes).
3. Encrypt.
4. Decrypt.
5. Verify with SHA-256 hashes.

---

### Must Submit

* CTR code
* Key and nonce size documented
* Encryption + decryption outputs
* Matching SHA-256 hashes
* Explanation: why CTR behaves like stream cipher

---

# Task 4 — CTR Nonce Reuse Attack (20 pts)

### Core Vulnerability

If nonce reused:

[
C_1 = P_1 \oplus K
]
[
C_2 = P_2 \oplus K
]

[
C_1 \oplus C_2 = P_1 \oplus P_2
]

---

### Required Steps

1. Use group-provided ciphertexts.
2. Compute:

[
X = C_1 \oplus C_2
]

3. Inspect with `xxd` and `strings`.
4. Recover ≥ 20 bytes of unknown plaintext using crib dragging.

---

### Must Submit

* XOR script
* XOR output evidence
* ≥20 bytes recovered (with offsets)
* Explanation of keystream reuse
* Mathematical explanation of two-time pad failure

---

# Task 5 — Birthday Attack on CTR (15 pts)

### Birthday Approximation

[
Pr[collision] \approx \frac{q^2}{2^{r+1}}
]

Collision scale:

[
q \approx 1.2 \cdot 2^{r/2}
]

---

### Required Steps

1. Use small nonce size (e.g., r = 16 bits).
2. Generate random nonce per encryption.
3. Record number of encryptions until collision.
4. Run ≥ 20 independent experiments.
5. Compute average collision point.
6. Compare with theoretical estimate.
7. Demonstrate once that collision enables:

[
C_1 \oplus C_2 = P_1 \oplus P_2
]

---

### Must Submit

* Collision simulation script
* Table of ≥20 runs
* Average collision point
* Comparison to birthday bound
* Explanation connecting collision to CTR insecurity

---

# Task 6 — Integrity vs Confidentiality (AES-GCM) (10 pts)

### AEAD Property

[
(C,T) = Enc_k(P)
]

[
Dec_k(C,T) =
\begin{cases}
P & \text{if tag valid} \
\perp & \text{otherwise}
\end{cases}
]

---

### Required Steps

1. CBC tampering:

   * Flip 1 byte in ciphertext
   * Decrypt
   * Observe corruption or padding failure

2. GCM tampering:

   * Flip 1 byte in ciphertext or tag
   * Decryption must fail

3. Explain difference between confidentiality and integrity.

---

### Must Submit

* CBC tamper evidence
* GCM tamper evidence (authentication failure)
* Short comparison explanation

---

# Task 7 — Performance Benchmarking (10 pts)

### Required File Sizes

* 1KB
* 1MB
* 10MB

---

### Required Modes

* ECB
* CBC
* CTR
* GCM

---

### Required Methodology

* Measure encryption and decryption
* Repeat ≥5 times
* Compute averages

---

### Required Results Table

| File Size | Mode | Avg Enc Time | Avg Dec Time |

---

### Required Analysis (1–2 paragraphs)

Discuss:

* CBC sequential chaining
* CTR/GCM parallelism
* GCM authentication overhead
* ECB speed vs insecurity

---

# Submission Requirements

For each task include:

* Explanation of what was implemented and why
* Mathematical expressions (where appropriate)
* Terminal screenshots
* SHA-256 hash outputs
* Evidence of correctness
* Interpretation (not just raw output)

Include:

* Python source code
* Reproducible steps

---

# Grading Breakdown (100 pts)

| Task           | Points |
| -------------- | ------ |
| Task 1         | 15     |
| Task 2         | 15     |
| Task 3         | 10     |
| Task 4         | 20     |
| Task 5         | 15     |
| Task 6         | 10     |
| Task 7         | 10     |
| Report Quality | 5      |

---

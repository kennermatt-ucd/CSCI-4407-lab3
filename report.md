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
# [PASTE CBC TAMPER TEST AND GCM TAMPER TEST CODE HERE]
```

### CBC Tamper Evidence

[INSERT SCREENSHOT: Flip 1 byte in CBC ciphertext → decrypt → observe corrupted output or padding error]

```
# [PASTE DECRYPTION OUTPUT AFTER TAMPERING — SHOW CORRUPTION OR EXCEPTION]
```

**Observation:** [DESCRIBE what happened — did it corrupt a block? Throw a padding exception? Accept silently?]

### GCM Tamper Evidence

[INSERT SCREENSHOT: Flip 1 byte in GCM ciphertext or tag → decryption fails with authentication error]

```
# [PASTE EXCEPTION OR ERROR OUTPUT SHOWING AUTHENTICATION FAILURE]
```

**Observation:** [DESCRIBE that GCM rejected the tampered ciphertext and raised an authentication failure]

### Comparison: Confidentiality vs. Integrity

[EXPLAIN the distinction between confidentiality (an attacker cannot learn plaintext) and integrity (an attacker cannot modify ciphertext undetected). CBC provides confidentiality but no integrity — a tampered ciphertext decrypts to garbage silently. GCM is AEAD (Authenticated Encryption with Associated Data): the authentication tag T covers the ciphertext, so any modification to C or T causes decryption to return ⊥, catching tampering. Use AES-GCM (or another AEAD) in practice rather than CBC without a MAC.]

---

## Task 7 — Performance Benchmarking (10 pts)

### Source Code

```python
# [PASTE BENCHMARKING SCRIPT HERE]
# Measures encrypt + decrypt times for ECB, CBC, CTR, GCM
# Each (mode, file size) combination is repeated 5 times and averaged to reduce timing variance
```

### Results Table

| File Size | Mode | Avg Enc Time (s) | Avg Dec Time (s) |
|-----------|------|-----------------|-----------------|
| 1 KB      | ECB  |                 |                 |
| 1 KB      | CBC  |                 |                 |
| 1 KB      | CTR  |                 |                 |
| 1 KB      | GCM  |                 |                 |
| 1 MB      | ECB  |                 |                 |
| 1 MB      | CBC  |                 |                 |
| 1 MB      | CTR  |                 |                 |
| 1 MB      | GCM  |                 |                 |
| 10 MB     | ECB  |                 |                 |
| 10 MB     | CBC  |                 |                 |
| 10 MB     | CTR  |                 |                 |
| 10 MB     | GCM  |                 |                 |

### Performance Analysis

[PARAGRAPH 1 — DISCUSS:
- CBC sequential chaining: each block depends on the previous ciphertext block, so encryption cannot be parallelized. Decryption can be parallelized since C_{i-1} is known.
- CTR and GCM parallelism: both generate keystream blocks independently (E_k(Nonce || i)), so encryption and decryption are fully parallelizable and typically faster than CBC at scale.
- ECB speed vs. insecurity: ECB is the fastest mode (no chaining, fully parallel) but is cryptographically broken for most real-world use cases due to pattern leakage.]

[PARAGRAPH 2 — DISCUSS:
- GCM authentication overhead: AES-GCM adds a GHASH computation over the ciphertext to produce the authentication tag, which introduces a small but measurable overhead compared to pure CTR. Discuss whether this overhead is visible in your results and whether it is worthwhile given the integrity guarantees.]

---

## Key Lessons Learned

- [SUMMARIZE key takeaway about ECB and why determinism breaks semantic security]
- [SUMMARIZE key takeaway about IV/nonce freshness in CBC and CTR]
- [SUMMARIZE key takeaway about nonce reuse leading to two-time pad attacks in CTR]
- [SUMMARIZE key takeaway about the birthday bound and nonce space sizing]
- [SUMMARIZE key takeaway about AEAD and why confidentiality alone is insufficient]
- [SUMMARIZE key takeaway about the performance trade-offs between modes]

---

## Appendix

### Full Script Listings

[OPTIONAL: Include complete script code if not fully shown in task sections above]

### Additional Screenshots

[OPTIONAL: Include any additional supporting terminal output or evidence]

"""
Task 5 — Birthday Attack on CTR (15 pts)
==========================================
Simulates nonce collision probability with a small nonce space.

Birthday approximation:
  Pr[collision] ≈ q^2 / 2^(r+1)
  Collision expected around q ≈ 1.2 * 2^(r/2)

With r = 16 bits (nonce space = 65536), expected first collision ≈ 300 encryptions.

Steps:
1. Use r = 16-bit nonce (simulate by drawing random nonces from 0..2^r-1)
2. Encrypt with a fresh random nonce each time
3. Record the number of encryptions until the first nonce collision (birthday paradox)
4. Run >= 20 independent experiments
5. Compare average to theoretical birthday bound
6. Demonstrate that a collision enables C1 XOR C2 = P1 XOR P2
"""

import os
import random
import statistics
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

NONCE_BITS   = 16          # small nonce space for the birthday experiment
NONCE_SPACE  = 2 ** NONCE_BITS
NUM_RUNS     = 20
KEY_SIZE     = 32          # 256-bit AES key
PLAINTEXT_SIZE = 64        # bytes per message


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ctr_encrypt(key: bytes, nonce_int: int, plaintext: bytes) -> bytes:
    """Encrypt using AES-CTR with nonce packed into a 16-byte value."""
    nonce_bytes = nonce_int.to_bytes(16, byteorder="big")
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce_bytes), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(plaintext) + enc.finalize()


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# ---------------------------------------------------------------------------
# Birthday collision experiment
# ---------------------------------------------------------------------------

def find_collision(key: bytes) -> tuple[int, int, int]:
    """
    Encrypt messages one by one with random nonces drawn from [0, 2^NONCE_BITS).
    Return (num_encryptions, nonce_value, colliding_index) at first collision.
    """
    seen: dict[int, int] = {}     # nonce -> encryption index
    for i in range(1, NONCE_SPACE + 1):
        nonce = random.randint(0, NONCE_SPACE - 1)
        if nonce in seen:
            return i, nonce, seen[nonce]
        seen[nonce] = i
    return NONCE_SPACE, -1, -1    # no collision found (should be extremely rare)


# ---------------------------------------------------------------------------
# Demonstrate two-time pad on a collision
# ---------------------------------------------------------------------------

def demonstrate_collision_attack(key: bytes) -> None:
    """
    Find two ciphertexts encrypted under the same nonce.
    Show that C1 XOR C2 = P1 XOR P2 (key cancels).
    """
    nonce = random.randint(0, NONCE_SPACE - 1)
    p1 = os.urandom(PLAINTEXT_SIZE)
    p2 = os.urandom(PLAINTEXT_SIZE)

    c1 = ctr_encrypt(key, nonce, p1)
    c2 = ctr_encrypt(key, nonce, p2)

    c1_xor_c2 = xor_bytes(c1, c2)
    p1_xor_p2 = xor_bytes(p1, p2)

    print("\n=== Collision Attack Demonstration ===")
    print(f"  Shared nonce:    {nonce}")
    print(f"  P1 (hex):        {p1[:16].hex()}...")
    print(f"  P2 (hex):        {p2[:16].hex()}...")
    print(f"  C1 XOR C2:       {c1_xor_c2[:16].hex()}...")
    print(f"  P1 XOR P2:       {p1_xor_p2[:16].hex()}...")
    print(f"  Equal (C1^C2 == P1^P2): {c1_xor_c2 == p1_xor_p2}  (expected: True)")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    key = os.urandom(KEY_SIZE)

    theoretical_bound = 1.2 * (2 ** (NONCE_BITS / 2))
    print(f"=== Task 5: Birthday Attack on CTR ===")
    print(f"Nonce space: r = {NONCE_BITS} bits ({NONCE_SPACE} possible values)")
    print(f"Theoretical birthday bound: q ≈ 1.2 × 2^({NONCE_BITS}/2) ≈ {theoretical_bound:.1f}\n")

    collision_counts = []
    print(f"{'Run':<6} {'Encryptions Until Collision'}")
    print("-" * 35)
    for run in range(1, NUM_RUNS + 1):
        count, nonce_val, prev_idx = find_collision(key)
        collision_counts.append(count)
        print(f"{run:<6} {count}")

    avg = statistics.mean(collision_counts)
    stdev = statistics.stdev(collision_counts)
    print(f"\nAverage collision point: {avg:.2f}")
    print(f"Std dev:                 {stdev:.2f}")
    print(f"Theoretical bound:       {theoretical_bound:.2f}")
    print(f"Difference (avg - theoretical): {avg - theoretical_bound:.2f}")

    demonstrate_collision_attack(key)

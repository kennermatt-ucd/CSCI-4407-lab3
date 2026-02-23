"""
Task 1 — ECB Distinguisher (15 pts)
====================================
Demonstrates that AES-ECB is deterministic and fails IND-CPA.

Approach:
- P0: repeated 16-byte block (same block N times)
- P1: random bytes of the same length
- Encrypt both under AES-ECB with a random key
- Distinguisher counts duplicate 16-byte ciphertext blocks
- Run >= 20 trials, record success rate and IND-CPA advantage
"""

import os
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

BLOCK_SIZE = 16
NUM_BLOCKS = 8       # plaintext length = NUM_BLOCKS * 16 bytes
NUM_TRIALS = 20


# ---------------------------------------------------------------------------
# AES-ECB helpers
# ---------------------------------------------------------------------------

def generate_key() -> bytes:
    """Generate a random 256-bit AES key."""
    return os.urandom(32)


def ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt plaintext under AES-ECB (plaintext must be block-aligned)."""
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


# ---------------------------------------------------------------------------
# Plaintext generation
# ---------------------------------------------------------------------------

def make_p0(num_blocks: int = NUM_BLOCKS) -> bytes:
    """P0: the same 16-byte block repeated num_blocks times."""
    block = os.urandom(BLOCK_SIZE)
    return block * num_blocks


def make_p1(num_blocks: int = NUM_BLOCKS) -> bytes:
    """P1: num_blocks of independent random 16-byte blocks."""
    return os.urandom(num_blocks * BLOCK_SIZE)


# ---------------------------------------------------------------------------
# Distinguisher
# ---------------------------------------------------------------------------

def count_duplicate_blocks(ciphertext: bytes) -> int:
    """Return the number of repeated 16-byte blocks in ciphertext."""
    blocks = [ciphertext[i:i + BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]
    return len(blocks) - len(set(blocks))


def distinguisher(ciphertext: bytes) -> int:
    """
    Guess b' based on ciphertext structure.
    Returns 0 if repeated blocks detected (guess: P0 was encrypted),
    Returns 1 otherwise (guess: P1 was encrypted).
    """
    if count_duplicate_blocks(ciphertext) > 0:
        return 0   # b' = 0  (looks like repeated plaintext)
    return 1       # b' = 1  (looks like random plaintext)


# ---------------------------------------------------------------------------
# IND-CPA game
# ---------------------------------------------------------------------------

def run_trial(key: bytes) -> bool:
    """
    One trial of the IND-CPA experiment.
    Choose b randomly, encrypt P_b, run distinguisher, return whether b' == b.
    """
    b = random.randint(0, 1)
    plaintext = make_p0() if b == 0 else make_p1()
    ciphertext = ecb_encrypt(key, plaintext)
    b_prime = distinguisher(ciphertext)
    return b_prime == b


def run_experiment(num_trials: int = NUM_TRIALS) -> None:
    key = generate_key()
    print(f"AES key (hex): {key.hex()}")
    print(f"Plaintext length: {NUM_BLOCKS * BLOCK_SIZE} bytes ({NUM_BLOCKS} blocks)\n")

    # Show an example of P0 vs P1 encryption to illustrate block repetition
    p0 = make_p0()
    p1 = make_p1()
    c0 = ecb_encrypt(key, p0)
    c1 = ecb_encrypt(key, p1)
    print("=== Example ciphertexts ===")
    print(f"C0 (from repeated P0): {c0.hex()}")
    print(f"  duplicate blocks: {count_duplicate_blocks(c0)}")
    print(f"C1 (from random   P1): {c1.hex()}")
    print(f"  duplicate blocks: {count_duplicate_blocks(c1)}\n")

    # Run trials
    print(f"{'Trial':<8} {'b':<6} {'b_prime':<10} {'Correct'}")
    print("-" * 35)
    correct = 0
    for i in range(1, num_trials + 1):
        b = random.randint(0, 1)
        plaintext = make_p0() if b == 0 else make_p1()
        ciphertext = ecb_encrypt(key, plaintext)
        b_prime = distinguisher(ciphertext)
        result = b_prime == b
        if result:
            correct += 1
        print(f"{i:<8} {b:<6} {b_prime:<10} {'Yes' if result else 'No'}")

    success_rate = correct / num_trials
    advantage = abs(success_rate - 0.5)
    print(f"\nCorrect: {correct}/{num_trials}")
    print(f"Success rate: {success_rate:.2%}")
    print(f"Adv_IND-CPA = |Pr[b'=b] - 1/2| = {advantage:.4f}")


if __name__ == "__main__":
    run_experiment()

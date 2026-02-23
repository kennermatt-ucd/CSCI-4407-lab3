"""
Task 4 — CTR Nonce Reuse Attack (20 pts)
==========================================
Uses the group-provided ciphertext package (Group 10).

VIOLATED ASSUMPTION: nonce uniqueness
--------------------------------------
CTR mode is secure ONLY when every (key, nonce) pair is used for exactly
one encryption. The two provided ciphertexts were encrypted with the SAME
key and SAME nonce, directly violating this assumption. This makes the
scheme equivalent to a two-time pad and allows full plaintext recovery.

Attack:
  C1 = P1 XOR K
  C2 = P2 XOR K
  C1 XOR C2 = P1 XOR P2   (key K cancels out entirely)

Once we have X = P1 XOR P2, crib dragging recovers plaintext bytes.

Usage:
  Place the two ciphertext files from the Group 10 package in the same
  directory and update CIPHERTEXT_1 / CIPHERTEXT_2 below.
"""

import sys

# ---------------------------------------------------------------------------
# Configuration — update these paths to your Group 10 ciphertext files
# ---------------------------------------------------------------------------
CIPHERTEXT_1 = "ciphertext_1.bin"   # TODO: update filename
CIPHERTEXT_2 = "ciphertext_2.bin"   # TODO: update filename


# ---------------------------------------------------------------------------
# Step 1: XOR the two ciphertexts
# ---------------------------------------------------------------------------

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings up to the length of the shorter one."""
    return bytes(x ^ y for x, y in zip(a, b))


def load_and_xor(path1: str, path2: str) -> bytes:
    with open(path1, "rb") as f:
        c1 = f.read()
    with open(path2, "rb") as f:
        c2 = f.read()
    print(f"C1 length: {len(c1)} bytes")
    print(f"C2 length: {len(c2)} bytes")
    x = xor_bytes(c1, c2)
    print(f"X = C1 XOR C2 length: {len(x)} bytes\n")
    return x, c1, c2


# ---------------------------------------------------------------------------
# Step 2: Inspect X with xxd-style hex dump
# ---------------------------------------------------------------------------

def hex_dump(data: bytes, length: int = 256) -> None:
    """Print a hex dump of the first `length` bytes (xxd-style)."""
    for i in range(0, min(length, len(data)), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  {i:08x}: {hex_part:<48}  {ascii_part}")


def printable_strings(data: bytes, min_len: int = 4) -> None:
    """Print runs of printable ASCII characters (like `strings`)."""
    current = []
    results = []
    for i, b in enumerate(data):
        if 32 <= b < 127:
            current.append((i, chr(b)))
        else:
            if len(current) >= min_len:
                offset = current[0][0]
                s = "".join(c for _, c in current)
                results.append((offset, s))
            current = []
    for offset, s in results:
        print(f"  offset {offset:5d}: {s}")


# ---------------------------------------------------------------------------
# Step 3: Crib dragging
# ---------------------------------------------------------------------------

def crib_drag(x: bytes, crib: str, offset: int = 0) -> None:
    """
    Slide a known crib word across X = P1 XOR P2 starting at `offset`.
    For each position, XOR the crib against X to get a candidate for
    the other plaintext at that position.

    If the result looks like readable ASCII, we have found plaintext.
    """
    crib_bytes = crib.encode()
    print(f"\n  Dragging crib '{crib}' (len={len(crib_bytes)}) starting at offset {offset}:")
    for pos in range(offset, min(len(x) - len(crib_bytes) + 1, offset + 200)):
        chunk = x[pos:pos + len(crib_bytes)]
        candidate = xor_bytes(chunk, crib_bytes)
        printable = all(32 <= b < 127 for b in candidate)
        marker = " <-- readable" if printable else ""
        print(f"    pos {pos:4d}: {candidate}{marker}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== Task 4: CTR Nonce Reuse Attack ===")
    print("Violated assumption: nonce uniqueness\n")

    try:
        x, c1, c2 = load_and_xor(CIPHERTEXT_1, CIPHERTEXT_2)
    except FileNotFoundError as e:
        print(f"ERROR: {e}")
        print("Update CIPHERTEXT_1 and CIPHERTEXT_2 at the top of this script.")
        sys.exit(1)

    # --- Hex dump of X ---
    print("=== Hex dump of X = C1 XOR C2 (first 256 bytes) ===")
    hex_dump(x, length=256)

    # --- Strings-style scan ---
    print("\n=== Printable string runs in X ===")
    printable_strings(x)

    # --- Crib dragging examples ---
    # TODO: add cribs based on what you observe in the hex dump / strings output
    cribs = [
        ("the ", 0),
        ("and ", 0),
        ("http", 0),
    ]
    print("\n=== Crib Dragging ===")
    for crib, start_offset in cribs:
        crib_drag(x, crib, offset=start_offset)

    print("\nTODO: record recovered offsets and plaintext bytes in report.md")

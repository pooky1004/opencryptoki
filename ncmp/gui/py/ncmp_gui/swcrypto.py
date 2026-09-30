"""Software reference implementations for result comparison.

Two families:

- ``mock_*`` : bit-exact replicas of the emulator's deterministic algorithms
  (mcu_scheduler.c). Comparing a mock token's output against these verifies the
  *datapath* (framing, chunking, marshalling) end-to-end - not cryptographic
  correctness, since the emulator does not run real AES/SHA.

- ``real_*`` : true cryptography (hashlib / the ``cryptography`` package), for
  comparison against a real HSM.

The GUI picks the family that matches the connected target.
"""
from __future__ import annotations

import hashlib
from typing import Optional

from . import ci

FNV_OFFSET = 0x811C9DC5
FNV_PRIME = 16777619
DIGEST_SEED = FNV_OFFSET


# --- mock replicas ----------------------------------------------------------

def mock_rng(n: int) -> bytes:
    """NCMP_MOCK_RNG_BYTE(i) = 0x5A + i (mod 256)."""
    return bytes((0x5A + i) & 0xFF for i in range(n))


def _fold(acc: int, data: bytes) -> int:
    for b in data:
        acc = ((acc ^ b) * FNV_PRIME) & 0xFFFFFFFF
    return acc


def mock_digest(mech: int, data: bytes) -> bytes:
    """Replica of mock_digest_fold + mock_digest_finalize.

    Matches both the one-shot (NCMP_CMD_DIGEST) and multipart
    (INIT/UPDATE/FINAL) paths, which share the same fold/finalize.
    """
    hsize = ci.DIGEST_SIZE.get(mech, 0)
    if hsize == 0:
        raise ValueError(f"unsupported digest mech 0x{mech:X}")
    acc = _fold((mech ^ DIGEST_SEED) & 0xFFFFFFFF, data)
    out = bytearray(hsize)
    for i in range(hsize):
        out[i] = ((acc >> (i & 7)) + i * 31 + mech) & 0xFF
    return bytes(out)


def mock_aes_stream(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Replica of mock_aes_stream (the AES-CTR datapath).

    out[i] = data[i] ^ (key[i % lk] ^ iv[i % liv] ^ (i & 0xFF)).
    Position i restarts at 0 for each one-shot call, so a chunked caller must
    reset i per chunk to match (see file_xor_chunked).
    """
    lk = len(key)
    liv = len(iv)
    if lk not in (16, 24, 32) or liv == 0 or liv > 16:
        raise ValueError("bad key/iv length for mock AES stream")
    out = bytearray(len(data))
    for i, d in enumerate(data):
        out[i] = d ^ (key[i % lk] ^ iv[i % liv] ^ (i & 0xFF))
    return bytes(out)


# --- real cryptography (for a real HSM) ------------------------------------

def real_digest(mech: int, data: bytes) -> bytes:
    algo = {
        ci.MECH_SHA256: "sha256",
        ci.MECH_SHA512: "sha512",
        ci.MECH_SHA3_224: "sha3_224",
        ci.MECH_SHA3_256: "sha3_256",
        ci.MECH_SHA3_384: "sha3_384",
        ci.MECH_SHA3_512: "sha3_512",
    }.get(mech)
    if algo is None:
        raise ValueError(f"unsupported digest mech 0x{mech:X}")
    return hashlib.new(algo, data).digest()


def real_aes_ctr(key: bytes, ctr: bytes, data: bytes) -> Optional[bytes]:
    """True AES-CTR via the ``cryptography`` package, or None if unavailable."""
    try:
        from cryptography.hazmat.primitives.ciphers import (
            Cipher, algorithms, modes,
        )
    except Exception:
        return None
    nonce = (ctr + b"\x00" * 16)[:16]
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()

"""NCMP wire-frame codec (little-endian), mirroring ncmp/include/ncmp/ncmp_wire.h.

Frame layout (all fields 4-byte aligned, little-endian):

    frame_len (u32)          # length of everything AFTER this field
    header (20 bytes):
        session_id  (u32)
        sequence_id (u32)
        command_id  (u32)    # opcode (low 16) | flags (high 16)
        ack         (u32)    # CKR_* status
        payload_len (u32)    # bytes after header (param array + params)
    param_len[8] (32 bytes)  # per-parameter length
    payload                  # param 0..7 concatenated (len 0 = omitted)

Invariants:  frame_len == 20 + payload_len
             payload_len == 32 + sum(param_len)
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List

MAX_PARAM_COUNT = 8
HEADER_WIRE_SIZE = 20
PARAM_LEN_ARRAY_SIZE = MAX_PARAM_COUNT * 4
FRAME_PREFIX_SIZE = 4
DEV_CONTAINER_SIZE = 64 * 1024
MAX_FRAME_SIZE = DEV_CONTAINER_SIZE
MAX_PARAM_SIZE = DEV_CONTAINER_SIZE - (FRAME_PREFIX_SIZE + HEADER_WIRE_SIZE)


@dataclass
class Message:
    """Decoded NCMP message."""

    session_id: int = 0
    sequence_id: int = 0
    command_id: int = 0
    ack: int = 0
    params: List[bytes] = field(default_factory=list)

    @property
    def opcode(self) -> int:
        return self.command_id & 0x0000FFFF

    def param(self, idx: int) -> bytes:
        return self.params[idx] if idx < len(self.params) else b""


def encode(
    command_id: int,
    params: List[bytes] | None = None,
    *,
    session_id: int = 0,
    sequence_id: int = 0,
    ack: int = 0,
) -> bytes:
    """Serialize a request/response into a complete wire frame (with prefix)."""
    params = list(params or [])
    if len(params) > MAX_PARAM_COUNT:
        raise ValueError("too many parameters (max 8)")
    plens = [len(p) for p in params] + [0] * (MAX_PARAM_COUNT - len(params))
    for n in plens:
        if n > MAX_PARAM_SIZE:
            raise ValueError("parameter exceeds NCMP_MAX_PARAM_SIZE")
    body = b"".join(params)
    payload_len = PARAM_LEN_ARRAY_SIZE + len(body)
    frame_len = HEADER_WIRE_SIZE + payload_len
    if FRAME_PREFIX_SIZE + frame_len > MAX_FRAME_SIZE:
        raise ValueError("encoded frame exceeds one device container")
    out = struct.pack(
        "<IIIIII",
        frame_len,
        session_id,
        sequence_id,
        command_id,
        ack,
        payload_len,
    )
    out += struct.pack("<8I", *plens)
    out += body
    return out


def decode(frame: bytes) -> Message:
    """Parse a complete wire frame (including the 4-byte length prefix)."""
    if len(frame) < FRAME_PREFIX_SIZE + HEADER_WIRE_SIZE + PARAM_LEN_ARRAY_SIZE:
        raise ValueError("frame too short")
    (frame_len, session_id, sequence_id, command_id, ack, payload_len) = struct.unpack_from(
        "<IIIIII", frame, 0
    )
    if FRAME_PREFIX_SIZE + frame_len != len(frame):
        raise ValueError(
            f"frame_len mismatch: prefix says {frame_len}, have {len(frame) - 4}"
        )
    plens = struct.unpack_from("<8I", frame, FRAME_PREFIX_SIZE + HEADER_WIRE_SIZE)
    off = FRAME_PREFIX_SIZE + HEADER_WIRE_SIZE + PARAM_LEN_ARRAY_SIZE
    params: List[bytes] = []
    for n in plens:
        params.append(frame[off : off + n])
        off += n
    # Drop trailing empty params so callers see the natural count.
    while params and params[-1] == b"" and len(params) > 0:
        params.pop()
    return Message(session_id, sequence_id, command_id, ack, params)


# --- little-endian scalar helpers (match ncmp_rd/wr_u32le) ------------------

def u32(v: int) -> bytes:
    return struct.pack("<I", v & 0xFFFFFFFF)


def rd_u32(b: bytes, off: int = 0) -> int:
    return struct.unpack_from("<I", b, off)[0]

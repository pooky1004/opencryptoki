"""NCMP command interface (CI): opcodes, constants, and request builders.

Mirrors ncmp/include/ncmp/ncmp_cmd.h. Each builder returns
(command_id, [params]) ready for wire.encode(); response parsing helpers turn a
decoded wire.Message back into Python values.
"""
from __future__ import annotations

from typing import List, Tuple

from . import wire

# --- opcodes (enum ncmp_opcode) --------------------------------------------
NOP = 0x0000
RNG = 0x0001
DIGEST = 0x0002
GETMECHLIST = 0x0003
DIGEST_INIT = 0x0004
DIGEST_UPDATE = 0x0005
DIGEST_FINAL = 0x0006
SHAKE_DERIVE = 0x0009
AES_GCM = 0x0012
AES_CTR = 0x0013
AES_GCM_INIT = 0x0014
AES_GCM_UPDATE = 0x0015
AES_GCM_FINAL = 0x0016
CTX_FREE = 0x0017
LOGIN = 0x0030
LOGOUT = 0x0031
INIT_PIN = 0x0032
SET_PIN = 0x0033
INIT_TOKEN = 0x0034
GET_UTC_TIME = 0x0035
GET_TOKEN_PARAMS = 0x0036
SET_UTC_TIME = 0x0037
OBJECT_ADD = 0x0038
OBJECT_SET_ATTR = 0x0039
MLDSA_KEYGEN = 0x0050
MLDSA_SIGN = 0x0051
MLDSA_VERIFY = 0x0052
MLKEM_KEYGEN = 0x0053
MLKEM_ENCAPS = 0x0054
MLKEM_DECAPS = 0x0055
VD_MEM_WRITE = 0x0101
VD_MEM_READ = 0x0102
VD_PING = 0x0103
VD_SELFTEST = 0x0104
VD_FW_INFO = 0x0105
VD_MEM_FILL = 0x0106
VD_MEM_CRC = 0x0107
VD_TOKEN_INFO = 0x0108

OPCODE_NAMES = {
    v: k
    for k, v in globals().items()
    if isinstance(v, int) and k.isupper() and not k.startswith(("NCMP", "CKU", "MECH", "FLAG", "CKR"))
}

# --- test-hook flag: force a failing ack (NCMP_MOCK_CMD_FAIL_BIT) -----------
FAIL_BIT = 0x80000000

# --- digest mechanisms (numerically identical to CKM_SHA*) -----------------
MECH_SHA256 = 0x00000250
MECH_SHA512 = 0x00000270
MECH_SHA3_256 = 0x000002B0
MECH_SHA3_224 = 0x000002B5
MECH_SHA3_384 = 0x000002C0
MECH_SHA3_512 = 0x000002D0

MECH_NAMES = {
    MECH_SHA256: "SHA-256",
    MECH_SHA512: "SHA-512",
    MECH_SHA3_224: "SHA3-224",
    MECH_SHA3_256: "SHA3-256",
    MECH_SHA3_384: "SHA3-384",
    MECH_SHA3_512: "SHA3-512",
}

DIGEST_SIZE = {
    MECH_SHA256: 32,
    MECH_SHA512: 64,
    MECH_SHA3_224: 28,
    MECH_SHA3_256: 32,
    MECH_SHA3_384: 48,
    MECH_SHA3_512: 64,
}

# --- login user types / flags ----------------------------------------------
CKU_SO = 0
CKU_USER = 1
CKU_CONTEXT_SPECIFIC = 2
LOGIN_FLAG_NONE = 0x0
LOGIN_FLAG_PROTECTED_AUTH = 0x1
LOGIN_FLAG_CONTEXT = 0x2

AES_FLAG_ENCRYPT = 0x1

# --- CKR_* ack codes used by the mock (subset) -----------------------------
CKR_OK = 0x0
CKR_FUNCTION_FAILED = 0x6
CKR_ARGUMENTS_BAD = 0x7
CKR_DATA_LEN_RANGE = 0x21
CKR_DEVICE_MEMORY = 0x31
CKR_ENCRYPTED_DATA_INVALID = 0x40
CKR_MECHANISM_INVALID = 0x70
CKR_PIN_INCORRECT = 0xA0
CKR_PIN_LEN_RANGE = 0xA2
CKR_USER_ALREADY_LOGGED_IN = 0x100
CKR_USER_NOT_LOGGED_IN = 0x101

CKR_NAMES = {
    0x0: "CKR_OK",
    0x6: "CKR_FUNCTION_FAILED",
    0x7: "CKR_ARGUMENTS_BAD",
    0x13: "CKR_ATTRIBUTE_VALUE_INVALID",
    0x21: "CKR_DATA_LEN_RANGE",
    0x31: "CKR_DEVICE_MEMORY",
    0x40: "CKR_ENCRYPTED_DATA_INVALID",
    0x70: "CKR_MECHANISM_INVALID",
    0xA0: "CKR_PIN_INCORRECT",
    0xA2: "CKR_PIN_LEN_RANGE",
    0x100: "CKR_USER_ALREADY_LOGGED_IN",
    0x101: "CKR_USER_NOT_LOGGED_IN",
}


def ckr_name(ack: int) -> str:
    return CKR_NAMES.get(ack, f"0x{ack:X}")


def opcode_name(op: int) -> str:
    return OPCODE_NAMES.get(op & 0xFFFF, f"0x{op:04X}")


Req = Tuple[int, List[bytes]]


# --- request builders -------------------------------------------------------

def nop(data: bytes = b"") -> Req:
    return (NOP, [data] if data else [])


def rng(count: int) -> Req:
    return (RNG, [wire.u32(count)])


def digest(mech: int, data: bytes) -> Req:
    """One-shot digest: param0 = [mech(u32) | data]."""
    return (DIGEST, [wire.u32(mech) + data])


def digest_init(mech: int) -> Req:
    return (DIGEST_INIT, [wire.u32(mech)])


def digest_update(ctx_id: int, data: bytes) -> Req:
    return (DIGEST_UPDATE, [wire.u32(ctx_id), data])


def digest_final(ctx_id: int) -> Req:
    return (DIGEST_FINAL, [wire.u32(ctx_id)])


def aes_ctr(key: bytes, ctr: bytes, data: bytes, encrypt: bool = True) -> Req:
    """AES-CTR stream: [flags | key | ctr | data]."""
    flags = AES_FLAG_ENCRYPT if encrypt else 0
    return (AES_CTR, [wire.u32(flags), key, ctr, data])


def aes_gcm(key: bytes, iv: bytes, aad: bytes, taglen: int, data: bytes,
            encrypt: bool = True) -> Req:
    """AES-GCM one-shot: [flags | key | iv | aad | taglen | data]."""
    flags = AES_FLAG_ENCRYPT if encrypt else 0
    return (AES_GCM, [wire.u32(flags), key, iv, aad, wire.u32(taglen), data])


def shake_derive(mech: int, out_len: int, base: bytes) -> Req:
    return (SHAKE_DERIVE, [wire.u32(mech) + wire.u32(out_len) + base])


def login(user_type: int, pin: bytes, flags: int = 0) -> Req:
    return (LOGIN, [wire.u32(user_type), wire.u32(flags), pin])


def logout() -> Req:
    return (LOGOUT, [])


def init_pin(new_pin: bytes) -> Req:
    return (INIT_PIN, [new_pin])


def set_pin(old_pin: bytes, new_pin: bytes) -> Req:
    return (SET_PIN, [old_pin, new_pin])


def init_token(so_pin: bytes, label: bytes) -> Req:
    label = (label + b" " * 32)[:32]
    return (INIT_TOKEN, [so_pin, label])


def get_utc_time() -> Req:
    return (GET_UTC_TIME, [])


def set_utc_time(utc16: bytes) -> Req:
    return (SET_UTC_TIME, [(utc16 + b"0" * 16)[:16]])


def get_token_params() -> Req:
    return (GET_TOKEN_PARAMS, [])


def vd_ping() -> Req:
    return (VD_PING, [])


def vd_selftest() -> Req:
    return (VD_SELFTEST, [])


def vd_fw_info() -> Req:
    return (VD_FW_INFO, [])


def vd_token_info() -> Req:
    return (VD_TOKEN_INFO, [])


def vd_mem_write(addr: int, data: bytes) -> Req:
    return (VD_MEM_WRITE, [wire.u32(addr), data])


def vd_mem_read(addr: int, length: int) -> Req:
    return (VD_MEM_READ, [wire.u32(addr), wire.u32(length)])


def vd_mem_crc(addr: int, length: int) -> Req:
    return (VD_MEM_CRC, [wire.u32(addr), wire.u32(length)])

/*
 * Token NCMP - Command opcode scheme carried in the wire header's command_id.
 *
 * command_id layout (32 bits):
 *   [15:0]  opcode  (ncmp_opcode)      - what operation the token performs
 *   [31:16] flags   (NCMP_CMD_FLAG_*)  - modifiers / test hooks
 *
 * The transport layer (ncmp/ subtree) is PKCS#11-agnostic: it moves opaque
 * byte blobs tagged with an opcode. The opencryptoki STDLL adapter maps each
 * token_specific_* crypto hook onto an opcode and marshals CK_* buffers into
 * the parameter payload.
 */
#ifndef NCMP_CMD_H
#define NCMP_CMD_H

#include <stdint.h>

/** Low 16 bits of command_id select the operation. */
#define NCMP_CMD_OPCODE_MASK 0x0000FFFFu
/** High 16 bits carry flags/modifiers (see NCMP_MOCK_CMD_FAIL_BIT). */
#define NCMP_CMD_FLAG_MASK   0xFFFF0000u

/** Operation opcodes. Extend as crypto hooks are forwarded incrementally. */
enum ncmp_opcode {
    NCMP_CMD_NOP    = 0x0000, /**< No-op / echo (keepalive, mock default). */
    NCMP_CMD_RNG    = 0x0001, /**< Random bytes: param0(req)=LE u32 count. */
    NCMP_CMD_DIGEST = 0x0002, /**< One-shot digest: param0=[mech LE u32|data]. */
    NCMP_CMD_GETMECHLIST = 0x0003, /**< Reserved: query token mechanism list. */
    /* Multipart digest (stateful, token-side context handle). */
    NCMP_CMD_DIGEST_INIT   = 0x0004, /**< param0=mech -> resp param0=ctx_id. */
    NCMP_CMD_DIGEST_UPDATE = 0x0005, /**< params [ctx_id|data] -> (no output). */
    NCMP_CMD_DIGEST_FINAL  = 0x0006, /**< param0=ctx_id -> resp param0=digest. */
    NCMP_CMD_AES_CBC = 0x0010, /**< AES-CBC: params [flags|key|iv|data]->[out]. */
    NCMP_CMD_AES_ECB = 0x0011, /**< AES-ECB: params [flags|key|data]->[out]. */
    NCMP_CMD_AES_GCM = 0x0012, /**< AES-GCM: [flags|key|iv|aad|taglen|data]->[out]. */
    NCMP_CMD_RSA_SIGN = 0x0020, /**< RSA sign: params [mod|priv_exp|data]->[sig]. */
    NCMP_CMD_EC_SIGN = 0x0021 /**< EC sign: params [ec_params|priv|data]->[sig]. */
};

/** Sentinel for "no token-side digest context allocated yet". */
#define NCMP_DIGEST_CTX_NONE 0xFFFFFFFFu

/** AES block / IV size (bytes). */
#define NCMP_AES_BLOCK 16u

/** AES-CBC request flag: parameter 0, LE u32. */
#define NCMP_AES_FLAG_ENCRYPT 0x1u

/*
 * Digest mechanism identifiers on the wire. Numerically identical to the
 * PKCS#11 CKM_SHA* constants so the STDLL adapter can pass a CK mechanism
 * through unchanged, while the (PKCS#11-agnostic) emulator maps them via
 * ncmp_digest_size() below.
 */
#define NCMP_MECH_SHA_1   0x00000220u
#define NCMP_MECH_SHA256  0x00000250u
#define NCMP_MECH_SHA224  0x00000255u
#define NCMP_MECH_SHA384  0x00000260u
#define NCMP_MECH_SHA512  0x00000270u

/** Digest output size in bytes for @p mech, or 0 if unsupported. */
static inline uint32_t ncmp_digest_size(uint32_t mech)
{
    switch (mech) {
    case NCMP_MECH_SHA_1:  return 20;
    case NCMP_MECH_SHA224: return 28;
    case NCMP_MECH_SHA256: return 32;
    case NCMP_MECH_SHA384: return 48;
    case NCMP_MECH_SHA512: return 64;
    default:               return 0;
    }
}

/** Extract the opcode from a wire command_id. */
static inline uint32_t ncmp_cmd_opcode(uint32_t command_id)
{
    return command_id & NCMP_CMD_OPCODE_MASK;
}

/* Little-endian scalar helpers shared by the STDLL adapter and the emulator
 * for packing scalar request/response fields into the parameter payload. */
static inline uint32_t ncmp_rd_u32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void ncmp_wr_u32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/**
 * Deterministic byte the mock token returns for RNG at offset @p i. The mock
 * has no real entropy source, so it emits a reproducible pattern that tests
 * can assert against; real hardware returns true random bytes.
 */
#define NCMP_MOCK_RNG_BYTE(i) ((uint8_t)(0x5Au + (unsigned)(i)))

#endif /* NCMP_CMD_H */

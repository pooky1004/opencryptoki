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

/*
 * Operation opcodes. Only the operations the NCMP token actually implements are
 * defined here: symmetric AES-GCM/CTR, SHA-2/SHA-3 digests, SHAKE XOF key
 * derivation, and the post-quantum ML-DSA / ML-KEM suites, plus RNG, the token
 * administration lifecycle, and the vendor datapath opcodes. Mechanisms outside
 * the advertised surface (RSA, EC/ECDSA, DH/ECDH, HMAC, AES-CBC/ECB/OFB/CFB)
 * were removed together with their marshalling adapters, mock handlers, and
 * tests; the opcode gaps they leave are intentionally not reused.
 */
enum ncmp_opcode {
    NCMP_CMD_NOP    = 0x0000, /**< No-op / echo (keepalive, mock default, loopback). */
    NCMP_CMD_RNG    = 0x0001, /**< Random bytes: param0(req)=LE u32 count. */
    NCMP_CMD_DIGEST = 0x0002, /**< One-shot digest: param0=[mech LE u32|data]. */
    NCMP_CMD_GETMECHLIST = 0x0003, /**< Reserved: query token mechanism list. */
    /* Multipart digest (stateful, token-side context handle). */
    NCMP_CMD_DIGEST_INIT   = 0x0004, /**< param0=mech -> resp param0=ctx_id. */
    NCMP_CMD_DIGEST_UPDATE = 0x0005, /**< params [ctx_id|data] -> (no output). */
    NCMP_CMD_DIGEST_FINAL  = 0x0006, /**< param0=ctx_id -> resp param0=digest. */
    NCMP_CMD_SHAKE_DERIVE  = 0x0009, /**< XOF: [mech|outlen(LE u32)|base] -> [out]. */
    /* Symmetric: the only advertised AES modes are AEAD (GCM) and stream (CTR). */
    NCMP_CMD_AES_GCM = 0x0012, /**< AES-GCM: [flags|key|iv|aad|taglen|data]->[out]. */
    NCMP_CMD_AES_CTR = 0x0013, /**< AES-CTR: [flags|key|ctr|data]->[out] (stream). */

    /*
     * Token administration: PIN / login lifecycle and token queries. The
     * physical token owns the PIN material; the STDLL forwards the caller's PIN
     * and the token answers with a CKR_* ack (CKR_OK / CKR_PIN_INCORRECT /
     * CKR_PIN_LEN_RANGE / ...).
     */
    NCMP_CMD_LOGIN      = 0x0030, /**< [user_type(LE u32)|flags(LE u32)|pin] -> (ack). */
    NCMP_CMD_LOGOUT     = 0x0031, /**< (no params) -> (ack). */
    NCMP_CMD_INIT_PIN   = 0x0032, /**< [new_pin] -> (ack) (SO sets user PIN). */
    NCMP_CMD_SET_PIN    = 0x0033, /**< [old_pin|new_pin] -> (ack). */
    NCMP_CMD_INIT_TOKEN = 0x0034, /**< [so_pin|label(32)] -> (ack). */
    NCMP_CMD_GET_UTC_TIME     = 0x0035, /**< (no params) -> [utc(16)]. */
    NCMP_CMD_GET_TOKEN_PARAMS = 0x0036, /**< (no params) -> [label(32)|serial(16)|minpin|maxpin]. */
    NCMP_CMD_SET_UTC_TIME     = 0x0037, /**< [utc(16)] -> (ack) (SO only). */

    /*
     * Post-quantum (PKCS#11 3.2 ML-DSA / ML-KEM). All keys are forwarded as
     * opaque blobs; the mock produces deterministic, size-correct outputs so
     * round-trips (sign->verify, encaps->decaps) succeed. param0 always carries
     * the parameter set (CKP_ML_* keyform, LE u32).
     */
    NCMP_CMD_MLDSA_KEYGEN = 0x0050, /**< [set|pub_len|priv_len] -> [pub|priv]. */
    NCMP_CMD_MLDSA_SIGN   = 0x0051, /**< [set|pub_len|sig_len|priv|data] -> [sig]. */
    NCMP_CMD_MLDSA_VERIFY = 0x0052, /**< [set|pub|data|sig] -> (ack). */
    NCMP_CMD_MLKEM_KEYGEN = 0x0053, /**< [set|pub_len|priv_len] -> [pub|priv]. */
    NCMP_CMD_MLKEM_ENCAPS = 0x0054, /**< [set|ct_len|ss_len|pub] -> [ct|ss]. */
    NCMP_CMD_MLKEM_DECAPS = 0x0055, /**< [set|pub_len|ss_len|priv|ct] -> [ss]. */

    /*
     * Vendor-defined opcodes (0x0101+). They do not correspond to any standard
     * PKCS#11 function; they exercise the token datapath and query device-side
     * state. Implemented at the wire level by the mock token (mcu_scheduler.c).
     * Loopback (echo) is served by NCMP_CMD_NOP, so no dedicated opcode exists.
     */
    NCMP_CMD_VD_MEM_WRITE = 0x0101, /**< [addr(LE u32)|bytes] -> (ack). */
    NCMP_CMD_VD_MEM_READ  = 0x0102, /**< [addr(LE u32)|len(LE u32)] -> [bytes]. */
    NCMP_CMD_VD_PING      = 0x0103, /**< No payload -> [token epoch LE u32]. */
    NCMP_CMD_VD_SELFTEST  = 0x0104, /**< No payload -> [status LE u32 (0=ok)]. */
    NCMP_CMD_VD_FW_INFO   = 0x0105, /**< No payload -> [major|minor|patch|build]. */
    NCMP_CMD_VD_MEM_FILL  = 0x0106, /**< [addr|len|byte] -> (ack). */
    NCMP_CMD_VD_MEM_CRC   = 0x0107, /**< [addr|len] -> [crc32 LE u32]. */
    NCMP_CMD_VD_TOKEN_INFO = 0x0108 /**< (no params) -> [identity blob]. */
};

/*
 * Token identity blob layout (parameter 0 of a NCMP_CMD_VD_TOKEN_INFO response).
 * Fixed 104-byte little-endian record scanned at daemon boot and cached per slot
 * in SHM. Character fields are NUL-padded (the STDLL space-pads to the PKCS#11
 * CK_TOKEN_INFO convention). Kept as raw offsets so the (PKCS#11-agnostic) mock
 * and the daemon agree without sharing a struct definition.
 */
#define NCMP_TI_LABEL_LEN   32u
#define NCMP_TI_SERIAL_LEN  16u
#define NCMP_TI_MANUF_LEN   32u
#define NCMP_TI_MODEL_LEN   16u

#define NCMP_TI_OFF_LABEL     0u
#define NCMP_TI_OFF_SERIAL    32u
#define NCMP_TI_OFF_MANUF     48u
#define NCMP_TI_OFF_MODEL     80u
#define NCMP_TI_OFF_HW_MAJOR  96u
#define NCMP_TI_OFF_HW_MINOR  97u
#define NCMP_TI_OFF_FW_MAJOR  98u
#define NCMP_TI_OFF_FW_MINOR  99u
#define NCMP_TI_OFF_FLAGS     100u

/** Total on-wire size of the token identity blob. */
#define NCMP_TOKEN_INFO_WIRE_SIZE 104u

/** PKCS#11 user types carried in the NCMP_CMD_LOGIN request (LE u32). */
#define NCMP_CKU_SO               0u
#define NCMP_CKU_USER             1u
#define NCMP_CKU_CONTEXT_SPECIFIC 2u /**< Re-auth the logged-in user (always-auth). */

/*
 * Login modifier flags carried in parameter 1 of NCMP_CMD_LOGIN (LE u32). Beyond
 * the SO/User role selector (parameter 0), these convey the other conditions the
 * host must consider when logging in: a protected-authentication-path login
 * enters the PIN on the token's own pad (the wire PIN is empty), and a
 * context-specific re-authentication targets the already-logged-in user.
 */
#define NCMP_LOGIN_FLAG_NONE           0x00000000u
#define NCMP_LOGIN_FLAG_PROTECTED_AUTH 0x00000001u /**< PIN entered on token pad. */
#define NCMP_LOGIN_FLAG_CONTEXT        0x00000002u /**< CKU_CONTEXT_SPECIFIC re-auth. */

/*
 * Token-parameter query (NCMP_CMD_GET_TOKEN_PARAMS) response layout:
 *   param0 = label  (NCMP_TI_LABEL_LEN,  NUL/space padded)
 *   param1 = serial (NCMP_TI_SERIAL_LEN, NUL/space padded)
 *   param2 = ulMinPinLen (LE u32)
 *   param3 = ulMaxPinLen (LE u32)
 * The UTC-time query (NCMP_CMD_GET_UTC_TIME) returns a fixed 16-byte field in
 * param0, matching the PKCS#11 CK_TOKEN_INFO.utcTime convention.
 */
#define NCMP_TOKEN_UTC_LEN 16u

/** Size (bytes) of the mock token's vendor scratch memory region. */
#define NCMP_VD_MEM_SIZE (4u * 1024u)

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
 * ncmp_digest_size() below. Only the advertised hashes are recognised:
 * SHA-256, SHA-512 and the SHA-3 family (SHA3-224/256/384/512).
 */
#define NCMP_MECH_SHA256  0x00000250u
#define NCMP_MECH_SHA512  0x00000270u
/* SHA-3 family (numerically identical to the CKM_SHA3_* constants). */
#define NCMP_MECH_SHA3_256 0x000002B0u
#define NCMP_MECH_SHA3_224 0x000002B5u
#define NCMP_MECH_SHA3_384 0x000002C0u
#define NCMP_MECH_SHA3_512 0x000002D0u

/** Digest output size in bytes for @p mech, or 0 if unsupported. */
static inline uint32_t ncmp_digest_size(uint32_t mech)
{
    switch (mech) {
    case NCMP_MECH_SHA256:  return 32;
    case NCMP_MECH_SHA512:  return 64;
    case NCMP_MECH_SHA3_224: return 28;
    case NCMP_MECH_SHA3_256: return 32;
    case NCMP_MECH_SHA3_384: return 48;
    case NCMP_MECH_SHA3_512: return 64;
    default:                return 0;
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

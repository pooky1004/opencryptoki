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
    NCMP_CMD_HMAC_SIGN   = 0x0007, /**< [mech|key|data] -> [mac]. */
    NCMP_CMD_HMAC_VERIFY = 0x0008, /**< [mech|key|data|mac] -> (ack). */
    NCMP_CMD_SHAKE_DERIVE = 0x0009, /**< XOF: [mech|outlen(LE u32)|base] -> [out]. */
    NCMP_CMD_AES_CBC = 0x0010, /**< AES-CBC: params [flags|key|iv|data]->[out]. */
    NCMP_CMD_AES_ECB = 0x0011, /**< AES-ECB: params [flags|key|data]->[out]. */
    NCMP_CMD_AES_GCM = 0x0012, /**< AES-GCM: [flags|key|iv|aad|taglen|data]->[out]. */
    NCMP_CMD_AES_CTR = 0x0013, /**< AES-CTR: [flags|key|ctr|data]->[out] (stream). */
    NCMP_CMD_AES_OFB = 0x0014, /**< AES-OFB: [flags|key|iv|data]->[out] (stream). */
    NCMP_CMD_AES_CFB = 0x0015, /**< AES-CFB: [flags|key|iv|data]->[out] (stream). */
    NCMP_CMD_RSA_SIGN = 0x0020, /**< RSA sign: params [mod|priv_exp|data]->[sig]. */
    NCMP_CMD_RSA_VERIFY = 0x0022, /**< RSA verify: [mod|pub_exp|data|sig]->(ack). */
    NCMP_CMD_EC_SIGN = 0x0021, /**< EC sign: params [ec_params|priv|data]->[sig]. */
    NCMP_CMD_EC_VERIFY = 0x0023, /**< EC verify: [ec_params|ec_point|data|sig]->(ack). */
    /* Key-pair generation (token generates and returns key components). */
    NCMP_CMD_RSA_KEYGEN = 0x0024, /**< [modbits|pub_exp] -> [n|d|p|q|dp|dq|qinv]. */
    NCMP_CMD_EC_KEYGEN = 0x0025, /**< [ec_params] -> [ec_point|priv_value]. */
    NCMP_CMD_RSA_OAEP_ENC = 0x0026, /**< [mod|pub_exp|data] -> [ciphertext]. */
    NCMP_CMD_RSA_OAEP_DEC = 0x0027, /**< [mod|priv_exp|ct] -> [plaintext]. */
    NCMP_CMD_DH_DERIVE = 0x0028, /**< [prime|priv|peer_pub] -> [shared secret]. */
    NCMP_CMD_ECDH_DERIVE = 0x0029, /**< [ec_params|priv|peer_point] -> [secret]. */
    /* RSA-PSS reuses NCMP_CMD_RSA_SIGN / NCMP_CMD_RSA_VERIFY (same marshalling;
     * the mock signature is deterministic regardless of PSS vs PKCS padding). */

    /*
     * Token administration: PIN / login lifecycle. The physical token owns the
     * PIN material; the STDLL forwards the caller's PIN and the token answers
     * with a CKR_* ack (CKR_OK / CKR_PIN_INCORRECT / CKR_PIN_LEN_RANGE / ...).
     */
    NCMP_CMD_LOGIN      = 0x0030, /**< [user_type(LE u32)|pin] -> (ack). */
    NCMP_CMD_LOGOUT     = 0x0031, /**< (no params) -> (ack). */
    NCMP_CMD_INIT_PIN   = 0x0032, /**< [new_pin] -> (ack) (SO sets user PIN). */
    NCMP_CMD_SET_PIN    = 0x0033, /**< [old_pin|new_pin] -> (ack). */
    NCMP_CMD_INIT_TOKEN = 0x0034, /**< [so_pin|label(32)] -> (ack). */

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
     * Vendor-defined opcodes (0x0100+). They do not correspond to any standard
     * PKCS#11 function; they exercise the token datapath and query device-side
     * state. Implemented at the wire level by the mock token (mcu_scheduler.c).
     */
    NCMP_CMD_VD_LOOPBACK  = 0x0100, /**< Echo param0 back verbatim. */
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
#define NCMP_CKU_SO   0u
#define NCMP_CKU_USER 1u

/** Size (bytes) of the mock token's vendor scratch memory region. */
#define NCMP_VD_MEM_SIZE (4u * 1024u)

/** HMAC output size (bytes) for @p mech (CKM_*_HMAC), or 0 if unsupported. */
static inline uint32_t ncmp_hmac_size(uint32_t mech)
{
    switch (mech) {
    case 0x00000221u: return 20; /* CKM_SHA_1_HMAC   */
    case 0x00000256u: return 28; /* CKM_SHA224_HMAC  */
    case 0x00000251u: return 32; /* CKM_SHA256_HMAC  */
    case 0x00000261u: return 48; /* CKM_SHA384_HMAC  */
    case 0x00000271u: return 64; /* CKM_SHA512_HMAC  */
    default:          return 0;
    }
}

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
/* SHA-3 family (numerically identical to the CKM_SHA3_* constants). */
#define NCMP_MECH_SHA3_256 0x000002B0u
#define NCMP_MECH_SHA3_224 0x000002B5u
#define NCMP_MECH_SHA3_384 0x000002C0u
#define NCMP_MECH_SHA3_512 0x000002D0u

/** Digest output size in bytes for @p mech, or 0 if unsupported. */
static inline uint32_t ncmp_digest_size(uint32_t mech)
{
    switch (mech) {
    case NCMP_MECH_SHA_1:   return 20;
    case NCMP_MECH_SHA224:  return 28;
    case NCMP_MECH_SHA256:  return 32;
    case NCMP_MECH_SHA384:  return 48;
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

/*
 * Token NCMP - MCU round-robin scheduler (emulated).
 *
 * Visits containers in round-robin order, "executes" the staged command, and
 * builds a response frame with a valid ACK (CKR_* status) and an accurate
 * payload_len. The freed container becomes available to the mover again.
 *
 * The emulated execution here is an echo: the response carries the request's
 * session_id/sequence_id/command_id and payload unchanged, with ack=CKR_OK.
 * This is enough to exercise the full host<->device datapath end-to-end.
 */
#include "mock_token_ncmp.h"
#include "ncmp/ncmp_wire.h"
#include "ncmp/ncmp_cmd.h"
#include "ncmp/ncmp_ctx.h"
#include "ncmp/ncmp_errno.h"

#include <stddef.h>
#include <string.h>

/* CKR_* values without pulling the full PKCS#11 headers into the emulator. */
#define MOCK_CKR_OK 0u
#define MOCK_CKR_FUNCTION_FAILED 0x6u
#define MOCK_CKR_ARGUMENTS_BAD 0x7u
#define MOCK_CKR_ATTRIBUTE_VALUE_INVALID 0x13u
#define MOCK_CKR_DATA_LEN_RANGE 0x21u
#define MOCK_CKR_ENCRYPTED_DATA_INVALID 0x40u
#define MOCK_CKR_DEVICE_MEMORY 0x31u
#define MOCK_CKR_MECHANISM_INVALID 0x70u
#define MOCK_CKR_SIGNATURE_INVALID 0xC0u
#define MOCK_CKR_SESSION_COUNT 0xB1u
#define MOCK_CKR_SESSION_HANDLE_INVALID 0xB3u
#define MOCK_CKR_PIN_INCORRECT 0xA0u
#define MOCK_CKR_PIN_LEN_RANGE 0xA2u
#define MOCK_CKR_TEMPLATE_INCOMPLETE 0xD0u
#define MOCK_CKR_USER_ALREADY_LOGGED_IN 0x100u
#define MOCK_CKR_USER_NOT_LOGGED_IN 0x101u
#define MOCK_CKR_USER_TYPE_INVALID 0x103u

/* PIN-length bounds the mock token advertises (GET_TOKEN_PARAMS). */
#define MOCK_MIN_PIN_LEN 4u
#define MOCK_MAX_PIN_LEN NCMP_MOCK_PIN_MAX

void mock_device_set_identity(mock_device_t *dev, uint32_t slot_id)
{
    mock_token_admin_t *a;
    char d = (char)('0' + (slot_id & 0x7u));

    if (!dev)
        return;
    a = &dev->admin;
    if (a->valid)
        return;

    memset(a, 0, sizeof(*a));
    /* Distinct per-slot label/serial so slot-binding tests can match them. */
    memcpy(a->label, "NCMPTOKEN0", 10);
    a->label[9] = d;
    memcpy(a->serial, "NCMPSN0000000", 13);
    a->serial[12] = d;
    memcpy(a->manufacturer, "DYST", 4);
    memcpy(a->model, "NCMP", 4);
    a->hw_major = 1;
    a->hw_minor = 0;
    a->fw_major = 1;
    a->fw_minor = 0;
    a->flags = 0;
    /* Default clock; SET_UTC_TIME overwrites it, GET_UTC_TIME reads it back. */
    memcpy(a->utc, "2026090300000000", NCMP_TOKEN_UTC_LEN);

    /* Factory-default PINs (the physical token owns them). */
    memcpy(a->user_pin, "1234", 4);
    a->user_pin_len = 4;
    memcpy(a->so_pin, "12345678", 8);
    a->so_pin_len = 8;
    a->logged_in = 0;
    a->valid = 1;
}

/** Constant-time-ish PIN compare against the stored PIN for @p user_type. */
static int mock_pin_ok(const mock_token_admin_t *a, uint32_t user_type,
                       const uint8_t *pin, uint32_t len)
{
    const uint8_t *stored = (user_type == 0u) ? a->so_pin : a->user_pin;
    uint32_t slen = (user_type == 0u) ? a->so_pin_len : a->user_pin_len;

    return len == slen && (len == 0 || memcmp(stored, pin, len) == 0);
}

/**
 * @brief Expand an accumulator into a @p outlen-byte signature.
 *
 * Shared by the PQC sign/verify and encaps/decaps paths (and SHAKE expansion)
 * so an output can be recomputed and checked. The mock output is a deterministic
 * function of @p comp (a component available to BOTH sides - e.g. the ML-DSA
 * public prefix) and the folded data. This is a mock limitation, not real
 * cryptographic semantics - hardware performs true operations.
 */
static void mock_sig_expand(uint32_t acc, const uint8_t *comp, uint32_t complen,
                            uint8_t *out, uint32_t outlen)
{
    for (uint32_t i = 0; i < outlen; ++i)
        out[i] = (uint8_t)((acc >> (i & 7)) + i * 197u + comp[i % complen]);
}

/** Deterministic byte expansion keyed only by @p seed (no key component). */
static void mock_pqc_expand(uint32_t seed, uint8_t *out, uint32_t outlen)
{
    uint8_t s[4];

    s[0] = (uint8_t)seed;
    s[1] = (uint8_t)(seed >> 8);
    s[2] = (uint8_t)(seed >> 16);
    s[3] = (uint8_t)(seed >> 24);
    mock_sig_expand(seed, s, sizeof(s), out, outlen);
}

/** Largest PQC blob the mock materializes on the stack (ML-DSA-87 signature). */
#define MOCK_PQC_MAX 5120u

/** Digest accumulator seed; shared by one-shot and multipart so they agree. */
#define MOCK_DIGEST_SEED 0x811C9DC5u

/** Fold @p n bytes of @p d into the running accumulator (FNV-1a style). */
static uint32_t mock_digest_fold(uint32_t acc, const uint8_t *d, uint32_t n)
{
    for (uint32_t j = 0; j < n; ++j)
        acc = (acc ^ d[j]) * 16777619u;
    return acc;
}

/** Expand @p acc into an @p hsize-byte deterministic digest. */
static void mock_digest_finalize(uint32_t acc, uint32_t mech, uint8_t *out,
                                 uint32_t hsize)
{
    for (uint32_t i = 0; i < hsize; ++i)
        out[i] = (uint8_t)((acc >> (i & 7)) + i * 31u + mech);
}

/* ---- Multipart AES-GCM emulation (deterministic; NOT real GCM) ---- */

/** Deterministic keystream byte at position @p n. */
static uint8_t mock_gcm_ks(const uint8_t *key, uint32_t keylen,
                           const uint8_t *iv, uint32_t ivlen, uint32_t n)
{
    uint8_t k = keylen ? key[n % keylen] : 0;
    uint8_t v = ivlen ? iv[n % ivlen] : 0;

    return (uint8_t)(k ^ v ^ (uint8_t)(n * 0x9Eu + 0x3Bu));
}

/** Expand the tag accumulator into a deterministic @p taglen-byte tag. */
static void mock_gcm_tag(uint32_t acc, uint8_t *tag, uint32_t taglen)
{
    for (uint32_t i = 0; i < taglen; ++i)
        tag[i] = (uint8_t)((acc >> ((i & 3) * 8)) ^ (i * 0x2Fu + 0x5Au));
}

/* ---- Token-resident key table (keys referenced by key id) ---- */

/** Store @p len key bytes; returns the key id, or -1 if the table is full. */
static int mock_key_alloc(mock_device_t *dev, const uint8_t *v, uint32_t len)
{
    if (len == 0 || len > sizeof(dev->key_tbl[0].val))
        return -1;
    for (int i = 0; i < NCMP_MOCK_KEY_MAX; ++i) {
        if (!dev->key_tbl[i].in_use) {
            dev->key_tbl[i].in_use = 1;
            dev->key_tbl[i].len = (uint8_t)len;
            memcpy(dev->key_tbl[i].val, v, len);
            return i;
        }
    }
    return -1;
}

/** Resolve a key id to its entry, or NULL if unallocated / out of range. */
static mock_key_t *mock_key_get(mock_device_t *dev, uint32_t id)
{
    if (id >= NCMP_MOCK_KEY_MAX || !dev->key_tbl[id].in_use)
        return NULL;
    return &dev->key_tbl[id];
}

/** Release a key id, scrubbing the key bytes. Idempotent. */
static void mock_key_free(mock_device_t *dev, uint32_t id)
{
    if (id < NCMP_MOCK_KEY_MAX) {
        memset(dev->key_tbl[id].val, 0, sizeof(dev->key_tbl[id].val));
        dev->key_tbl[id].len = 0;
        dev->key_tbl[id].in_use = 0;
    }
}

/**
 * @brief Emulated AES stream modes (CTR/OFB/CFB), rewriting @p msg in place.
 *
 * Params: [0]=flags, [1]=key, [2]=iv/counter, [3]=data. All three modes are a
 * reversible position-keyed keystream XOR in the mock (no block-length
 * constraint), so encrypt then decrypt round-trips. Real firmware runs true
 * CTR/OFB/CFB. Data reads stay ahead of the in-place write (data is the last,
 * highest-offset parameter), so no copy of the data is needed.
 */
static void mock_aes_stream(NCMP_Message *msg)
{
    const uint8_t *pf, *pk, *piv, *pd;
    uint32_t lf, lk, liv, ld;
    uint8_t key[32], iv[16];

    if (ncmp_msg_param(msg, 0, &pf, &lf) != NCMP_OK ||
        ncmp_msg_param(msg, 1, &pk, &lk) != NCMP_OK ||
        ncmp_msg_param(msg, 2, &piv, &liv) != NCMP_OK ||
        ncmp_msg_param(msg, 3, &pd, &ld) != NCMP_OK ||
        lf < 4 || (lk != 16 && lk != 24 && lk != 32) ||
        liv == 0 || liv > sizeof(iv)) {
        msg->param_len[0] = 0;
        msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
        return;
    }
    memcpy(key, pk, lk);
    memcpy(iv, piv, liv);
    for (uint32_t i = 0; i < ld; ++i)
        msg->payload[i] = (uint8_t)(pd[i] ^ (key[i % lk] ^ iv[i % liv] ^
                                    (uint8_t)i));
    msg->param_len[0] = ld;
    for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
        msg->param_len[i] = 0;
    msg->header.ack = MOCK_CKR_OK;
}

/**
 * @brief Emulate one command in place, rewriting @p msg into its response.
 *
 * Dispatches on the opcode carried in command_id. Unknown opcodes echo the
 * request (a mock convenience that keeps loopback/keepalive traffic working);
 * real firmware would reject them. @p dev supplies token-side state (the
 * multipart digest context table).
 */
static void mock_exec_command(mock_device_t *dev, NCMP_Message *msg)
{
    switch (ncmp_cmd_opcode(msg->header.command_id)) {
    case NCMP_CMD_RNG: {
        /* Request parameter 0 is a LE u32 byte count; fill the response with
         * that many deterministic pseudo-random bytes. */
        uint32_t want = (msg->param_len[0] >= 4)
                            ? ncmp_rd_u32le(msg->payload) : 0;

        if (want > NCMP_MAX_PARAM_SIZE)
            want = NCMP_MAX_PARAM_SIZE;
        for (uint32_t i = 0; i < want; ++i)
            msg->payload[i] = NCMP_MOCK_RNG_BYTE(i);
        msg->param_len[0] = want;
        for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_DIGEST: {
        /* One-shot: param 0 is [mech(LE u32) | input bytes]. Produce a
         * deterministic, input-sensitive digest. NOT a real hash - hardware
         * returns the true digest; determinism lets tests assert forwarding.
         * Shares fold/finalize with the multipart path so both agree. */
        uint32_t in_len = msg->param_len[0];
        uint32_t mech = (in_len >= 4) ? ncmp_rd_u32le(msg->payload) : 0;
        uint32_t hsize = ncmp_digest_size(mech);
        uint32_t acc;

        if (hsize == 0 || in_len < 4) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
            break;
        }
        /* Fold consumes all input before finalize overwrites the payload. */
        acc = mock_digest_fold(mech ^ MOCK_DIGEST_SEED, msg->payload + 4,
                               in_len - 4);
        mock_digest_finalize(acc, mech, msg->payload, hsize);
        msg->param_len[0] = hsize;
        for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_DIGEST_INIT: {
#ifdef NCMP_HOST_MANAGED_CTX
        /* Stateless token: param0=mech -> return the typed digest context blob
         * in param0. The daemon (comm_thread) stores it and hands the STDLL an
         * id. */
        uint32_t mech = (msg->param_len[0] >= 4) ? ncmp_rd_u32le(msg->payload)
                                                 : 0;
        ncmp_ctx_digest_t dctx;

        if (ncmp_digest_size(mech) == 0) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
            break;
        }
        dctx.mech = mech;
        dctx.acc = mech ^ MOCK_DIGEST_SEED;
        msg->param_len[0] = ncmp_ctx_digest_put(msg->payload, &dctx);
        for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
#else
        /* param0=mech -> allocate a context, return its id in param0. */
        uint32_t mech = (msg->param_len[0] >= 4) ? ncmp_rd_u32le(msg->payload)
                                                 : 0;
        int slot = -1;

        if (ncmp_digest_size(mech) == 0) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
            break;
        }
        for (int i = 0; i < NCMP_MOCK_DIGEST_CTX_MAX; ++i) {
            if (!dev->digest_ctx[i].in_use) { slot = i; break; }
        }
        if (slot < 0) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_DEVICE_MEMORY;
            break;
        }
        dev->digest_ctx[slot].in_use = 1;
        dev->digest_ctx[slot].mech = mech;
        dev->digest_ctx[slot].acc = mech ^ MOCK_DIGEST_SEED;
        ncmp_wr_u32le(msg->payload, (uint32_t)slot);
        msg->param_len[0] = 4;
        for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
#endif
    }
    case NCMP_CMD_DIGEST_UPDATE: {
#ifdef NCMP_HOST_MANAGED_CTX
        /* Stateless token: params [ctx-blob(param0) | data]; fold data and
         * return the updated typed context blob in param0 (digest has no data
         * output). */
        const uint8_t *pb, *pd;
        uint32_t lb, ld;
        ncmp_ctx_digest_t dctx;

        if (ncmp_msg_param(msg, 0, &pb, &lb) != NCMP_OK ||
            ncmp_ctx_digest_get(pb, lb, &dctx) != 0 ||
            ncmp_msg_param(msg, 1, &pd, &ld) != NCMP_OK) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_FUNCTION_FAILED;
            break;
        }
        dctx.acc = mock_digest_fold(dctx.acc, pd, ld);
        msg->param_len[0] = ncmp_ctx_digest_put(msg->payload, &dctx);
        for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
#else
        /* params [ctx_id | data]; fold data into the context accumulator. */
        const uint8_t *pid, *pd;
        uint32_t lid, ld, id;

        if (ncmp_msg_param(msg, 0, &pid, &lid) != NCMP_OK || lid < 4 ||
            ncmp_msg_param(msg, 1, &pd, &ld) != NCMP_OK) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_FUNCTION_FAILED;
            break;
        }
        id = ncmp_rd_u32le(pid);
        if (id >= NCMP_MOCK_DIGEST_CTX_MAX || !dev->digest_ctx[id].in_use) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_FUNCTION_FAILED;
            break;
        }
        dev->digest_ctx[id].acc =
            mock_digest_fold(dev->digest_ctx[id].acc, pd, ld);
        for (int i = 0; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
#endif
    }
    case NCMP_CMD_DIGEST_FINAL: {
#ifdef NCMP_HOST_MANAGED_CTX
        /* Stateless token: param0=ctx-blob -> finalize to the digest. */
        const uint8_t *pb;
        uint32_t lb, hsize;
        ncmp_ctx_digest_t dctx;

        if (ncmp_msg_param(msg, 0, &pb, &lb) != NCMP_OK ||
            ncmp_ctx_digest_get(pb, lb, &dctx) != 0) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_FUNCTION_FAILED;
            break;
        }
        hsize = ncmp_digest_size(dctx.mech);
        if (hsize == 0) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
            break;
        }
        mock_digest_finalize(dctx.acc, dctx.mech, msg->payload, hsize);
        msg->param_len[0] = hsize;
        for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
#else
        /* param0=ctx_id -> return digest, free the context. */
        uint32_t id = (msg->param_len[0] >= 4) ? ncmp_rd_u32le(msg->payload)
                                               : NCMP_DIGEST_CTX_NONE;
        uint32_t mech, hsize, acc;

        if (id >= NCMP_MOCK_DIGEST_CTX_MAX || !dev->digest_ctx[id].in_use) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_FUNCTION_FAILED;
            break;
        }
        mech = dev->digest_ctx[id].mech;
        hsize = ncmp_digest_size(mech);
        acc = dev->digest_ctx[id].acc;
        mock_digest_finalize(acc, mech, msg->payload, hsize);
        dev->digest_ctx[id].in_use = 0;
        msg->param_len[0] = hsize;
        for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
#endif
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_AES_GCM: {
        /* Params: [0]=flags(bit0 encrypt), [1]=key, [2]=iv, [3]=aad,
         * [4]=taglen(LE u32), [5]=data. AEAD (mock): reversible keystream XOR
         * plus a deterministic tag over key|iv|aad|ciphertext. Encrypt emits
         * ct||tag; decrypt verifies the tag and emits the plaintext. NOT real
         * GCM - hardware performs true AES-GCM. */
        const uint8_t *pf, *pk, *piv, *paad, *ptl, *pd;
        uint32_t lf, lk, liv, laad, ltl, ld;
        uint8_t key[32], iv[16], tag[16];
        uint32_t enc, taglen, acc;

        if (ncmp_msg_param(msg, 0, &pf, &lf) != NCMP_OK ||
            ncmp_msg_param(msg, 1, &pk, &lk) != NCMP_OK ||
            ncmp_msg_param(msg, 2, &piv, &liv) != NCMP_OK ||
            ncmp_msg_param(msg, 3, &paad, &laad) != NCMP_OK ||
            ncmp_msg_param(msg, 4, &ptl, &ltl) != NCMP_OK ||
            ncmp_msg_param(msg, 5, &pd, &ld) != NCMP_OK ||
            lf < 4 || (lk != 16 && lk != 24 && lk != 32) ||
            liv == 0 || liv > sizeof(iv) || ltl < 4) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
            break;
        }
        enc = ncmp_rd_u32le(pf) & 1u;
        taglen = ncmp_rd_u32le(ptl);
        if (taglen == 0 || taglen > sizeof(tag)) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
            break;
        }
        memcpy(key, pk, lk);
        memcpy(iv, piv, liv);
        /* Base tag accumulator over key|iv|aad (read aad before any write). */
        acc = mock_digest_fold(MOCK_DIGEST_SEED, key, lk);
        acc = mock_digest_fold(acc, iv, liv);
        acc = mock_digest_fold(acc, paad, laad);

        if (enc) {
            uint32_t outlen = ld + taglen;
            if (outlen > NCMP_MAX_PARAM_SIZE) {
                msg->param_len[0] = 0;
                msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
                break;
            }
            for (uint32_t i = 0; i < ld; ++i)
                msg->payload[i] = (uint8_t)(pd[i] ^ (key[i % lk] ^
                                            iv[i % liv] ^ (uint8_t)i));
            acc = mock_digest_fold(acc, msg->payload, ld); /* fold ciphertext */
            mock_digest_finalize(acc, 0, msg->payload + ld, taglen);
            msg->param_len[0] = outlen;
        } else {
            uint32_t ctlen;
            if (ld < taglen) {
                msg->param_len[0] = 0;
                msg->header.ack = MOCK_CKR_ENCRYPTED_DATA_INVALID;
                break;
            }
            ctlen = ld - taglen;
            acc = mock_digest_fold(acc, pd, ctlen); /* fold ciphertext */
            mock_digest_finalize(acc, 0, tag, taglen);
            if (memcmp(tag, pd + ctlen, taglen) != 0) {
                msg->param_len[0] = 0;
                msg->header.ack = MOCK_CKR_ENCRYPTED_DATA_INVALID;
                break;
            }
            for (uint32_t i = 0; i < ctlen; ++i)
                msg->payload[i] = (uint8_t)(pd[i] ^ (key[i % lk] ^
                                            iv[i % liv] ^ (uint8_t)i));
            msg->param_len[0] = ctlen;
        }
        for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_AES_GCM_INIT: {
        /* Multipart GCM begin: [flags|key|iv|aad|taglen] -> context (param0).
         * The key is registered in the token key table and referenced by
         * key_id; the context carries key_id, never the key bytes. */
        const uint8_t *pf, *pk, *piv, *paad, *ptl;
        uint32_t lf, lk, liv, laad, ltl, acc;
        ncmp_ctx_gcm_t g;
        int kid;

        if (ncmp_msg_param(msg, 0, &pf, &lf) != NCMP_OK || lf < 4 ||
            ncmp_msg_param(msg, 1, &pk, &lk) != NCMP_OK || lk == 0 || lk > 32 ||
            ncmp_msg_param(msg, 2, &piv, &liv) != NCMP_OK || liv == 0 ||
            liv > 16 ||
            ncmp_msg_param(msg, 3, &paad, &laad) != NCMP_OK ||
            ncmp_msg_param(msg, 4, &ptl, &ltl) != NCMP_OK || ltl < 4) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
            break;
        }
        memset(&g, 0, sizeof(g));
        g.enc = (ncmp_rd_u32le(pf) & NCMP_AES_FLAG_ENCRYPT) ? 1 : 0;
        g.taglen = (uint8_t)ncmp_rd_u32le(ptl);
        if (g.taglen == 0 || g.taglen > NCMP_AES_BLOCK) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
            break;
        }
        /* Register the key HSM-side; the context only ever references its id. */
        kid = mock_key_alloc(dev, pk, lk);
        if (kid < 0) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_DEVICE_MEMORY;
            break;
        }
        g.key_id = (uint32_t)kid;
        g.ivlen = (uint8_t)liv;
        memcpy(g.iv, piv, liv);
        /* Tag seed must not depend on the direction, so an encrypt tag and the
         * decrypt recomputation over the same key/iv/aad/plaintext agree. */
        acc = mock_digest_fold(MOCK_DIGEST_SEED, pk, lk);
        acc = mock_digest_fold(acc, piv, liv);
        acc = mock_digest_fold(acc, paad, laad);
        g.acc = acc;
        g.offset = 0;
#ifdef NCMP_HOST_MANAGED_CTX
        msg->param_len[0] = ncmp_ctx_gcm_put(msg->payload, &g);
#else
        {
            int slot = -1;
            for (int i = 0; i < NCMP_MOCK_DIGEST_CTX_MAX; ++i) {
                if (!dev->admin.gcm_ctx[i].in_use) { slot = i; break; }
            }
            if (slot < 0) {
                mock_key_free(dev, g.key_id);
                msg->param_len[0] = 0;
                msg->header.ack = MOCK_CKR_DEVICE_MEMORY;
                break;
            }
            dev->admin.gcm_ctx[slot].in_use = 1;
            dev->admin.gcm_ctx[slot].ctx = g;
            ncmp_wr_u32le(msg->payload, (uint32_t)slot);
            msg->param_len[0] = 4;
        }
#endif
        for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_AES_GCM_UPDATE: {
        /* Multipart GCM data: [ctx|data] -> [ctx'|out] (out=cipher/plaintext).
         * The key is resolved from the context's key_id via the token key
         * table; key bytes never travel in the context. */
        static _Thread_local uint8_t gcm_out[NCMP_MAX_PARAM_SIZE];
        const uint8_t *pc, *pd;
        uint32_t lc, ld;
        ncmp_ctx_gcm_t g;
        mock_key_t *k;
#ifndef NCMP_HOST_MANAGED_CTX
        uint32_t id;
#endif

        if (ncmp_msg_param(msg, 0, &pc, &lc) != NCMP_OK ||
            ncmp_msg_param(msg, 1, &pd, &ld) != NCMP_OK ||
            ld > sizeof(gcm_out)) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_FUNCTION_FAILED;
            break;
        }
#ifdef NCMP_HOST_MANAGED_CTX
        if (ncmp_ctx_gcm_get(pc, lc, &g) != 0) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_FUNCTION_FAILED;
            break;
        }
#else
        if (lc < 4) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_FUNCTION_FAILED;
            break;
        }
        id = ncmp_rd_u32le(pc);
        if (id >= NCMP_MOCK_DIGEST_CTX_MAX || !dev->admin.gcm_ctx[id].in_use) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_FUNCTION_FAILED;
            break;
        }
        g = dev->admin.gcm_ctx[id].ctx;
#endif
        k = mock_key_get(dev, g.key_id);
        if (k == NULL) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_FUNCTION_FAILED;
            break;
        }
        for (uint32_t i = 0; i < ld; ++i)
            gcm_out[i] = (uint8_t)(pd[i] ^ mock_gcm_ks(k->val, k->len, g.iv,
                                                       g.ivlen, g.offset + i));
        /* Tag folds the plaintext (encrypt: input; decrypt: output). */
        g.acc = mock_digest_fold(g.acc, g.enc ? pd : gcm_out, ld);
        g.offset += ld;
#ifdef NCMP_HOST_MANAGED_CTX
        {
            uint32_t bl = ncmp_ctx_gcm_put(msg->payload, &g);
            memcpy(msg->payload + bl, gcm_out, ld);
            msg->param_len[0] = bl;
            msg->param_len[1] = ld;
        }
#else
        dev->admin.gcm_ctx[id].ctx = g;
        memcpy(msg->payload, gcm_out, ld);
        msg->param_len[0] = ld;
        msg->param_len[1] = 0;
#endif
        for (int i = 2; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_AES_GCM_FINAL: {
        /* Multipart GCM end: [ctx] -> [tag] (encrypt) / [ctx|tag] -> ack (dec).
         * Releases the context's token key on completion. */
        const uint8_t *pc;
        uint32_t lc;
        ncmp_ctx_gcm_t g;
        uint8_t tag[NCMP_AES_BLOCK];
#ifndef NCMP_HOST_MANAGED_CTX
        uint32_t id;
#endif

        if (ncmp_msg_param(msg, 0, &pc, &lc) != NCMP_OK) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_FUNCTION_FAILED;
            break;
        }
#ifdef NCMP_HOST_MANAGED_CTX
        if (ncmp_ctx_gcm_get(pc, lc, &g) != 0) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_FUNCTION_FAILED;
            break;
        }
#else
        if (lc < 4) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_FUNCTION_FAILED;
            break;
        }
        id = ncmp_rd_u32le(pc);
        if (id >= NCMP_MOCK_DIGEST_CTX_MAX || !dev->admin.gcm_ctx[id].in_use) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_FUNCTION_FAILED;
            break;
        }
        g = dev->admin.gcm_ctx[id].ctx;
        dev->admin.gcm_ctx[id].in_use = 0;
#endif
        mock_key_free(dev, g.key_id);
        mock_gcm_tag(g.acc, tag, g.taglen);
        if (g.enc) {
            memcpy(msg->payload, tag, g.taglen);
            msg->param_len[0] = g.taglen;
            msg->header.ack = MOCK_CKR_OK;
        } else {
            const uint8_t *pt;
            uint32_t lt;

            if (ncmp_msg_param(msg, 1, &pt, &lt) == NCMP_OK && lt == g.taglen &&
                memcmp(pt, tag, g.taglen) == 0)
                msg->header.ack = MOCK_CKR_OK;
            else
                msg->header.ack = MOCK_CKR_ENCRYPTED_DATA_INVALID;
            msg->param_len[0] = 0;
        }
        for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        break;
    }
    case NCMP_CMD_CTX_FREE: {
        /* Release a multipart context (abort). Idempotent. Also releases the
         * context's token key so no key material lingers on the token. */
#ifdef NCMP_HOST_MANAGED_CTX
        /* The daemon swapped param0 to the stored context blob (so the token can
         * reach the key_id). Free the key if this is a GCM context; the daemon
         * frees the host-side context slot itself. */
        const uint8_t *pb;
        uint32_t lb;

        if (ncmp_msg_param(msg, 0, &pb, &lb) == NCMP_OK &&
            ncmp_ctx_type_of(pb, lb) == NCMP_CTX_TYPE_GCM) {
            ncmp_ctx_gcm_t g;
            if (ncmp_ctx_gcm_get(pb, lb, &g) == 0)
                mock_key_free(dev, g.key_id);
        }
#else
        const uint8_t *pid, *pk;
        uint32_t lid, lk;

        if (ncmp_msg_param(msg, 0, &pid, &lid) == NCMP_OK && lid >= 4 &&
            ncmp_msg_param(msg, 1, &pk, &lk) == NCMP_OK && lk >= 4) {
            uint32_t id = ncmp_rd_u32le(pid);
            uint32_t kind = ncmp_rd_u32le(pk);

            if (kind == NCMP_CTX_KIND_DIGEST && id < NCMP_MOCK_DIGEST_CTX_MAX) {
                dev->digest_ctx[id].in_use = 0;
            } else if (kind == NCMP_CTX_KIND_GCM &&
                       id < NCMP_MOCK_DIGEST_CTX_MAX) {
                if (dev->admin.gcm_ctx[id].in_use)
                    mock_key_free(dev, dev->admin.gcm_ctx[id].ctx.key_id);
                dev->admin.gcm_ctx[id].in_use = 0;
            }
        }
#endif
        for (int i = 0; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_AES_CTR:
        /* AES-CTR (the only advertised AES stream mode): reversible keystream
         * XOR in the mock. Real firmware performs true AES-CTR. */
        mock_aes_stream(msg);
        break;
    case NCMP_CMD_VD_TOKEN_INFO: {
        /* No input -> emit the fixed 104-byte identity blob in param0. */
        mock_token_admin_t *a = &dev->admin;
        uint8_t *p = msg->payload;

        memset(p, 0, NCMP_TOKEN_INFO_WIRE_SIZE);
        memcpy(p + NCMP_TI_OFF_LABEL, a->label, NCMP_TI_LABEL_LEN);
        memcpy(p + NCMP_TI_OFF_SERIAL, a->serial, NCMP_TI_SERIAL_LEN);
        memcpy(p + NCMP_TI_OFF_MANUF, a->manufacturer, NCMP_TI_MANUF_LEN);
        memcpy(p + NCMP_TI_OFF_MODEL, a->model, NCMP_TI_MODEL_LEN);
        p[NCMP_TI_OFF_HW_MAJOR] = a->hw_major;
        p[NCMP_TI_OFF_HW_MINOR] = a->hw_minor;
        p[NCMP_TI_OFF_FW_MAJOR] = a->fw_major;
        p[NCMP_TI_OFF_FW_MINOR] = a->fw_minor;
        ncmp_wr_u32le(p + NCMP_TI_OFF_FLAGS, a->flags);
        msg->param_len[0] = NCMP_TOKEN_INFO_WIRE_SIZE;
        for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_LOGIN: {
        /* [user_type(LE u32) | flags(LE u32) | pin] -> verify against the
         * stored PIN, honouring the login modifier flags. */
        mock_token_admin_t *a = &dev->admin;
        const uint8_t *put, *pfl, *ppin;
        uint32_t lut, lfl, lpin, ut, fl;

        if (ncmp_msg_param(msg, 0, &put, &lut) != NCMP_OK || lut < 4 ||
            ncmp_msg_param(msg, 1, &pfl, &lfl) != NCMP_OK || lfl < 4 ||
            ncmp_msg_param(msg, 2, &ppin, &lpin) != NCMP_OK) {
            for (int i = 0; i < NCMP_MAX_PARAM_COUNT; ++i)
                msg->param_len[i] = 0;
            msg->header.ack = MOCK_CKR_FUNCTION_FAILED;
            break;
        }
        for (int i = 0; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        ut = ncmp_rd_u32le(put);
        fl = ncmp_rd_u32le(pfl);

        /* Context-specific: re-authenticate the already-logged-in user
         * (PKCS#11 CKA_ALWAYS_AUTHENTICATE) without changing login state. */
        if (ut == NCMP_CKU_CONTEXT_SPECIFIC ||
            (fl & NCMP_LOGIN_FLAG_CONTEXT) != 0u) {
            if (!a->logged_in) {
                msg->header.ack = MOCK_CKR_USER_NOT_LOGGED_IN;
                break;
            }
            if (!mock_pin_ok(a, a->login_user, ppin, lpin))
                msg->header.ack = MOCK_CKR_PIN_INCORRECT;
            else
                msg->header.ack = MOCK_CKR_OK;
            break;
        }

        if (ut != NCMP_CKU_SO && ut != NCMP_CKU_USER) {
            msg->header.ack = MOCK_CKR_USER_TYPE_INVALID;
            break;
        }
        if (a->logged_in) {
            msg->header.ack = MOCK_CKR_USER_ALREADY_LOGGED_IN;
            break;
        }
        /* Protected-authentication path: the PIN is captured on the token's own
         * pad, so the wire PIN is empty and the token authorises it directly. */
        if ((fl & NCMP_LOGIN_FLAG_PROTECTED_AUTH) == 0u &&
            !mock_pin_ok(a, ut, ppin, lpin)) {
            msg->header.ack = MOCK_CKR_PIN_INCORRECT;
            break;
        }
        a->logged_in = 1;
        a->login_user = ut;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_LOGOUT: {
        /* Clear the login state (idempotent). */
        dev->admin.logged_in = 0;
        for (int i = 0; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_INIT_PIN: {
        /* [new_pin] -> SO sets the user PIN (SO must be logged in). */
        mock_token_admin_t *a = &dev->admin;
        const uint8_t *ppin;
        uint32_t lpin;

        if (ncmp_msg_param(msg, 0, &ppin, &lpin) != NCMP_OK) {
            for (int i = 0; i < NCMP_MAX_PARAM_COUNT; ++i)
                msg->param_len[i] = 0;
            msg->header.ack = MOCK_CKR_FUNCTION_FAILED;
            break;
        }
        for (int i = 0; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        if (!a->logged_in || a->login_user != 0u) {
            msg->header.ack = MOCK_CKR_USER_NOT_LOGGED_IN;
            break;
        }
        if (lpin > NCMP_MOCK_PIN_MAX) {
            msg->header.ack = MOCK_CKR_PIN_LEN_RANGE;
            break;
        }
        memcpy(a->user_pin, ppin, lpin);
        a->user_pin_len = lpin;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_SET_PIN: {
        /* [old_pin | new_pin] -> change the current user's PIN. */
        mock_token_admin_t *a = &dev->admin;
        const uint8_t *pold, *pnew;
        uint32_t lold, lnew, ut;
        uint8_t *target;
        uint32_t *tlen;

        if (ncmp_msg_param(msg, 0, &pold, &lold) != NCMP_OK ||
            ncmp_msg_param(msg, 1, &pnew, &lnew) != NCMP_OK) {
            for (int i = 0; i < NCMP_MAX_PARAM_COUNT; ++i)
                msg->param_len[i] = 0;
            msg->header.ack = MOCK_CKR_FUNCTION_FAILED;
            break;
        }
        for (int i = 0; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        ut = (a->logged_in && a->login_user == 0u) ? 0u : 1u;
        if (!mock_pin_ok(a, ut, pold, lold)) {
            msg->header.ack = MOCK_CKR_PIN_INCORRECT;
            break;
        }
        if (lnew > NCMP_MOCK_PIN_MAX) {
            msg->header.ack = MOCK_CKR_PIN_LEN_RANGE;
            break;
        }
        target = (ut == 0u) ? a->so_pin : a->user_pin;
        tlen = (ut == 0u) ? &a->so_pin_len : &a->user_pin_len;
        memcpy(target, pnew, lnew);
        *tlen = lnew;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_INIT_TOKEN: {
        /* [so_pin | label(32)] -> verify SO PIN, set the label. */
        mock_token_admin_t *a = &dev->admin;
        const uint8_t *pso, *plabel;
        uint32_t lso, llabel;

        if (ncmp_msg_param(msg, 0, &pso, &lso) != NCMP_OK ||
            ncmp_msg_param(msg, 1, &plabel, &llabel) != NCMP_OK) {
            for (int i = 0; i < NCMP_MAX_PARAM_COUNT; ++i)
                msg->param_len[i] = 0;
            msg->header.ack = MOCK_CKR_FUNCTION_FAILED;
            break;
        }
        for (int i = 0; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        if (!mock_pin_ok(a, 0u, pso, lso)) {
            msg->header.ack = MOCK_CKR_PIN_INCORRECT;
            break;
        }
        if (llabel > NCMP_TI_LABEL_LEN)
            llabel = NCMP_TI_LABEL_LEN;
        memset(a->label, 0, sizeof(a->label));
        memcpy(a->label, plabel, llabel);
        a->logged_in = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_GET_UTC_TIME: {
        /* No input -> 16-byte CK_TOKEN_INFO.utcTime ("YYYYMMDDhhmmssxx"), read
         * back from the token clock (default, or whatever SET_UTC_TIME stored).
         * The mock has no real RTC; real firmware reads its hardware clock. */
        memcpy(msg->payload, dev->admin.utc, NCMP_TOKEN_UTC_LEN);
        msg->param_len[0] = NCMP_TOKEN_UTC_LEN;
        for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_SET_UTC_TIME: {
        /* [utc(16)] -> set the token clock. Only the SO may set the time; the
         * field must be exactly NCMP_TOKEN_UTC_LEN bytes. */
        mock_token_admin_t *a = &dev->admin;
        const uint8_t *putc;
        uint32_t lutc;

        if (ncmp_msg_param(msg, 0, &putc, &lutc) != NCMP_OK) {
            for (int i = 0; i < NCMP_MAX_PARAM_COUNT; ++i)
                msg->param_len[i] = 0;
            msg->header.ack = MOCK_CKR_FUNCTION_FAILED;
            break;
        }
        for (int i = 0; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        if (!a->logged_in || a->login_user != NCMP_CKU_SO) {
            msg->header.ack = MOCK_CKR_USER_NOT_LOGGED_IN;
            break;
        }
        if (lutc != NCMP_TOKEN_UTC_LEN) {
            msg->header.ack = MOCK_CKR_ARGUMENTS_BAD;
            break;
        }
        memcpy(a->utc, putc, NCMP_TOKEN_UTC_LEN);
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_GET_TOKEN_PARAMS: {
        /* No input -> [label(32) | serial(16) | ulMinPinLen | ulMaxPinLen]. */
        mock_token_admin_t *a = &dev->admin;
        uint8_t *p = msg->payload;
        uint32_t off = 0;

        memcpy(p + off, a->label, NCMP_TI_LABEL_LEN);
        off += NCMP_TI_LABEL_LEN;
        memcpy(p + off, a->serial, NCMP_TI_SERIAL_LEN);
        off += NCMP_TI_SERIAL_LEN;
        ncmp_wr_u32le(p + off, MOCK_MIN_PIN_LEN);
        off += 4;
        ncmp_wr_u32le(p + off, MOCK_MAX_PIN_LEN);
        msg->param_len[0] = NCMP_TI_LABEL_LEN;
        msg->param_len[1] = NCMP_TI_SERIAL_LEN;
        msg->param_len[2] = 4;
        msg->param_len[3] = 4;
        for (int i = 4; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_OBJECT_ADD: {
        /* Register/import a key object: [class | key_type | value] -> (ack).
         * A secure-key token would wrap the value into a backend blob; the mock
         * validates the request shape and accepts it. No output params. */
        const uint8_t *pcls, *pkt, *pval;
        uint32_t lcls, lkt, lval;

        if (ncmp_msg_param(msg, 0, &pcls, &lcls) != NCMP_OK || lcls != 4 ||
            ncmp_msg_param(msg, 1, &pkt, &lkt) != NCMP_OK || lkt != 4) {
            msg->header.ack = MOCK_CKR_ARGUMENTS_BAD;
            break;
        }
        /* Key material must be present (a key object without CKA_VALUE is
         * incomplete for import). */
        if (ncmp_msg_param(msg, 2, &pval, &lval) != NCMP_OK || lval == 0) {
            msg->header.ack = MOCK_CKR_TEMPLATE_INCOMPLETE;
            break;
        }
        (void)pcls;
        (void)pkt;
        (void)pval;
        dev->admin.obj_count++;
        for (int i = 0; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_OBJECT_SET_ATTR: {
        /* Validate key attribute changes: [class | key_type | attrs] -> (ack).
         * attrs = count(u32), then count * { type(u32) | len(u32) | value }. The
         * mock walks the list to confirm it is well-formed. No output params. */
        const uint8_t *pcls, *pkt, *pa;
        uint32_t lcls, lkt, la, count, off;

        if (ncmp_msg_param(msg, 0, &pcls, &lcls) != NCMP_OK || lcls != 4 ||
            ncmp_msg_param(msg, 1, &pkt, &lkt) != NCMP_OK || lkt != 4 ||
            ncmp_msg_param(msg, 2, &pa, &la) != NCMP_OK || la < 4) {
            msg->header.ack = MOCK_CKR_ARGUMENTS_BAD;
            break;
        }
        count = ncmp_rd_u32le(pa);
        off = 4;
        for (uint32_t i = 0; i < count; ++i) {
            uint32_t alen;
            if (off + 8 > la) {              /* type(4) + len(4) */
                msg->header.ack = MOCK_CKR_ATTRIBUTE_VALUE_INVALID;
                goto object_set_attr_done;
            }
            alen = ncmp_rd_u32le(pa + off + 4);
            off += 8;
            if (alen > la - off) {           /* value bytes */
                msg->header.ack = MOCK_CKR_ATTRIBUTE_VALUE_INVALID;
                goto object_set_attr_done;
            }
            off += alen;
        }
        if (off != la) {                     /* trailing garbage */
            msg->header.ack = MOCK_CKR_ATTRIBUTE_VALUE_INVALID;
            break;
        }
        (void)pcls;
        (void)pkt;
        dev->admin.obj_setattr_count++;
        for (int i = 0; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
object_set_attr_done:
        break;
    }
    case NCMP_CMD_OPEN_SESSION: {
        /* Request from ncmpd: a single param0 = flags with a zero wire-header
         * session_id (matches the real firmware). The token allocates a session
         * and returns its session id (hsm_sid) in response parameter 0. The
         * handle is the table index + 1 (1..255), so it is never 0 and never
         * collides with another live session in this slot. */
        const uint8_t *pflags;
        uint32_t lflags, flags = 0;
        int free_idx = -1;

        /* ncmpd rewrites OPEN to a single param0 = flags before it reaches the
         * token (matches the real firmware); read flags from param0. */
        if (ncmp_msg_param(msg, 0, &pflags, &lflags) == NCMP_OK && lflags >= 4)
            flags = ncmp_rd_u32le(pflags);

        for (int i = 0; i < NCMP_MOCK_SESSION_MAX; ++i) {
            if (!dev->sessions[i].in_use) { free_idx = i; break; }
        }
        if (free_idx < 0) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_SESSION_COUNT; /* table full (255) */
            break;
        }
        dev->sessions[free_idx].in_use = 1;
        dev->sessions[free_idx].flags = flags;
        ncmp_wr_u32le(msg->payload, (uint32_t)(free_idx + 1)); /* handle 1..255 */
        msg->param_len[0] = 4;
        for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_CLOSE_SESSION: {
        /* Reference target protocol: the handle rides in the wire header and
         * there are no parameters. Release the session. */
        uint32_t handle = msg->header.session_id;

        for (int i = 0; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        if (handle < 1 || handle > NCMP_MOCK_SESSION_MAX ||
            !dev->sessions[handle - 1].in_use) {
            msg->header.ack = MOCK_CKR_SESSION_HANDLE_INVALID;
            break;
        }
        memset(&dev->sessions[handle - 1], 0, sizeof(dev->sessions[0]));
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_SHAKE_DERIVE: {
        /* XOF: [mech | outlen(LE u32) | base] -> [derived(outlen)]. Deterministic
         * expansion of the base key material to the requested length. */
        const uint8_t *pmech, *plen, *pbase;
        uint32_t lmech, llen, lbase, mech, outlen;
        uint8_t base[256];

        if (ncmp_msg_param(msg, 0, &pmech, &lmech) != NCMP_OK || lmech < 4 ||
            ncmp_msg_param(msg, 1, &plen, &llen) != NCMP_OK || llen < 4 ||
            ncmp_msg_param(msg, 2, &pbase, &lbase) != NCMP_OK ||
            lbase == 0 || lbase > sizeof(base)) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
            break;
        }
        mech = ncmp_rd_u32le(pmech);
        outlen = ncmp_rd_u32le(plen);
        if (outlen == 0 || outlen > NCMP_MAX_PARAM_SIZE) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
            break;
        }
        memcpy(base, pbase, lbase); /* copy before overwriting the payload */
        mock_sig_expand(mock_digest_fold(MOCK_DIGEST_SEED ^ mech, base, lbase),
                        base, lbase, msg->payload, outlen);
        msg->param_len[0] = outlen;
        for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_MLDSA_KEYGEN:
    case NCMP_CMD_MLKEM_KEYGEN: {
        /* [set | pub_len | priv_len] -> [pub | priv]; priv is prefixed with the
         * public blob so sign/verify (resp. encaps/decaps) can agree. */
        const uint8_t *pset, *ppub, *ppriv;
        uint32_t lset, lpub, lpriv, set, pub_len, priv_len, seed;

        if (ncmp_msg_param(msg, 0, &pset, &lset) != NCMP_OK || lset < 4 ||
            ncmp_msg_param(msg, 1, &ppub, &lpub) != NCMP_OK || lpub < 4 ||
            ncmp_msg_param(msg, 2, &ppriv, &lpriv) != NCMP_OK || lpriv < 4) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
            break;
        }
        set = ncmp_rd_u32le(pset);
        pub_len = ncmp_rd_u32le(ppub);
        priv_len = ncmp_rd_u32le(ppriv);
        if (pub_len == 0 || priv_len < pub_len ||
            pub_len > NCMP_MAX_PARAM_SIZE || priv_len > NCMP_MAX_PARAM_SIZE ||
            (uint64_t)pub_len + priv_len > NCMP_MAX_PAYLOAD_SIZE) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
            break;
        }
        seed = MOCK_DIGEST_SEED ^ (set * 2654435761u) ^
               ncmp_cmd_opcode(msg->header.command_id);
        /* pub at [0,pub_len); priv at [pub_len, pub_len+priv_len) with its first
         * pub_len bytes equal to pub. */
        mock_pqc_expand(seed, msg->payload, pub_len);
        memmove(msg->payload + pub_len, msg->payload, pub_len);
        mock_pqc_expand(seed ^ 0x55555555u,
                        msg->payload + pub_len + pub_len, priv_len - pub_len);
        msg->param_len[0] = pub_len;
        msg->param_len[1] = priv_len;
        for (int i = 2; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_MLDSA_SIGN: {
        /* [set | pub_len | sig_len | priv | data] -> [sig]. Fold the public
         * prefix of priv + data; expand to a signature of sig_len bytes. */
        const uint8_t *pset, *ppl, *psl, *ppriv, *pdata;
        uint32_t lset, lpl, lsl, lpriv, ldata, set, pub_len, sig_len, acc;
        uint8_t pub[MOCK_PQC_MAX];

        if (ncmp_msg_param(msg, 0, &pset, &lset) != NCMP_OK || lset < 4 ||
            ncmp_msg_param(msg, 1, &ppl, &lpl) != NCMP_OK || lpl < 4 ||
            ncmp_msg_param(msg, 2, &psl, &lsl) != NCMP_OK || lsl < 4 ||
            ncmp_msg_param(msg, 3, &ppriv, &lpriv) != NCMP_OK ||
            ncmp_msg_param(msg, 4, &pdata, &ldata) != NCMP_OK) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
            break;
        }
        set = ncmp_rd_u32le(pset);
        pub_len = ncmp_rd_u32le(ppl);
        sig_len = ncmp_rd_u32le(psl);
        if (pub_len == 0 || pub_len > sizeof(pub) || pub_len > lpriv ||
            sig_len == 0 || sig_len > NCMP_MAX_PARAM_SIZE) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
            break;
        }
        memcpy(pub, ppriv, pub_len); /* public prefix, before overwriting */
        acc = mock_digest_fold(MOCK_DIGEST_SEED ^ set, pub, pub_len);
        acc = mock_digest_fold(acc, pdata, ldata);
        mock_sig_expand(acc, pub, pub_len, msg->payload, sig_len);
        msg->param_len[0] = sig_len;
        for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_MLDSA_VERIFY: {
        /* [set | pub | data | sig] -> recompute the signature and compare. */
        const uint8_t *pset, *ppub, *pdata, *psig;
        uint32_t lset, lpub, ldata, lsig, set, acc;
        uint8_t pub[MOCK_PQC_MAX], sig[MOCK_PQC_MAX];

        if (ncmp_msg_param(msg, 0, &pset, &lset) != NCMP_OK || lset < 4 ||
            ncmp_msg_param(msg, 1, &ppub, &lpub) != NCMP_OK || lpub == 0 ||
            lpub > sizeof(pub) ||
            ncmp_msg_param(msg, 2, &pdata, &ldata) != NCMP_OK ||
            ncmp_msg_param(msg, 3, &psig, &lsig) != NCMP_OK ||
            lsig == 0 || lsig > sizeof(sig)) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
            break;
        }
        set = ncmp_rd_u32le(pset);
        memcpy(pub, ppub, lpub);
        acc = mock_digest_fold(MOCK_DIGEST_SEED ^ set, pub, lpub);
        acc = mock_digest_fold(acc, pdata, ldata);
        mock_sig_expand(acc, pub, lpub, sig, lsig);
        msg->param_len[0] = 0;
        for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = (memcmp(sig, psig, lsig) == 0)
                              ? MOCK_CKR_OK : MOCK_CKR_SIGNATURE_INVALID;
        break;
    }
    case NCMP_CMD_MLKEM_ENCAPS: {
        /* [set | ct_len | ss_len | pub] -> [ct | ss]. */
        const uint8_t *pset, *pcl, *psl, *ppub;
        uint32_t lset, lcl, lsl, lpub, set, ct_len, ss_len, acc;
        uint8_t pub[MOCK_PQC_MAX];

        if (ncmp_msg_param(msg, 0, &pset, &lset) != NCMP_OK || lset < 4 ||
            ncmp_msg_param(msg, 1, &pcl, &lcl) != NCMP_OK || lcl < 4 ||
            ncmp_msg_param(msg, 2, &psl, &lsl) != NCMP_OK || lsl < 4 ||
            ncmp_msg_param(msg, 3, &ppub, &lpub) != NCMP_OK ||
            lpub == 0 || lpub > sizeof(pub)) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
            break;
        }
        set = ncmp_rd_u32le(pset);
        ct_len = ncmp_rd_u32le(pcl);
        ss_len = ncmp_rd_u32le(psl);
        if (ct_len == 0 || ss_len == 0 || ct_len > NCMP_MAX_PARAM_SIZE ||
            ss_len > NCMP_MAX_PARAM_SIZE ||
            (uint64_t)ct_len + ss_len > NCMP_MAX_PAYLOAD_SIZE) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
            break;
        }
        memcpy(pub, ppub, lpub); /* copy before overwriting the payload */
        acc = mock_digest_fold(MOCK_DIGEST_SEED ^ set, pub, lpub);
        mock_sig_expand(acc, pub, lpub, msg->payload, ct_len); /* ct */
        /* Shared secret binds pub + ciphertext (decaps recomputes the same). */
        mock_sig_expand(mock_digest_fold(acc, msg->payload, ct_len),
                        pub, lpub, msg->payload + ct_len, ss_len);
        msg->param_len[0] = ct_len;
        msg->param_len[1] = ss_len;
        for (int i = 2; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_MLKEM_DECAPS: {
        /* [set | pub_len | ss_len | priv | ct] -> [ss]; recompute encaps' ss. */
        const uint8_t *pset, *ppl, *psl, *ppriv, *pct;
        uint32_t lset, lpl, lsl, lpriv, lct, set, pub_len, ss_len, acc;
        uint8_t pub[MOCK_PQC_MAX];

        if (ncmp_msg_param(msg, 0, &pset, &lset) != NCMP_OK || lset < 4 ||
            ncmp_msg_param(msg, 1, &ppl, &lpl) != NCMP_OK || lpl < 4 ||
            ncmp_msg_param(msg, 2, &psl, &lsl) != NCMP_OK || lsl < 4 ||
            ncmp_msg_param(msg, 3, &ppriv, &lpriv) != NCMP_OK ||
            ncmp_msg_param(msg, 4, &pct, &lct) != NCMP_OK || lct == 0) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
            break;
        }
        set = ncmp_rd_u32le(pset);
        pub_len = ncmp_rd_u32le(ppl);
        ss_len = ncmp_rd_u32le(psl);
        if (pub_len == 0 || pub_len > sizeof(pub) || pub_len > lpriv ||
            ss_len == 0 || ss_len > NCMP_MAX_PARAM_SIZE) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
            break;
        }
        memcpy(pub, ppriv, pub_len); /* public prefix of the private blob */
        acc = mock_digest_fold(MOCK_DIGEST_SEED ^ set, pub, pub_len);
        acc = mock_digest_fold(acc, pct, lct); /* fold the ciphertext */
        mock_sig_expand(acc, pub, pub_len, msg->payload, ss_len);
        msg->param_len[0] = ss_len;
        for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_VD_MEM_WRITE: {
        /* [addr(LE u32) | bytes] -> ack. Stores into the vendor scratch RAM. */
        const uint8_t *pa, *pb;
        uint32_t la, lb, addr;

        if (ncmp_msg_param(msg, 0, &pa, &la) != NCMP_OK || la < 4 ||
            ncmp_msg_param(msg, 1, &pb, &lb) != NCMP_OK) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_FUNCTION_FAILED;
            break;
        }
        addr = ncmp_rd_u32le(pa);
        if ((uint64_t)addr + lb > NCMP_VD_MEM_SIZE) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_DEVICE_MEMORY;
            break;
        }
        memcpy(dev->vd_mem + addr, pb, lb);
        for (int i = 0; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_VD_MEM_READ: {
        /* [addr(LE u32) | len(LE u32)] -> bytes from vendor scratch RAM. */
        const uint8_t *pa, *pl;
        uint32_t la, ll, addr, len;

        if (ncmp_msg_param(msg, 0, &pa, &la) != NCMP_OK || la < 4 ||
            ncmp_msg_param(msg, 1, &pl, &ll) != NCMP_OK || ll < 4) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_FUNCTION_FAILED;
            break;
        }
        addr = ncmp_rd_u32le(pa);
        len = ncmp_rd_u32le(pl);
        if (len > NCMP_MAX_PARAM_SIZE ||
            (uint64_t)addr + len > NCMP_VD_MEM_SIZE) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_DEVICE_MEMORY;
            break;
        }
        memmove(msg->payload, dev->vd_mem + addr, len);
        msg->param_len[0] = len;
        for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_VD_MEM_FILL: {
        /* [addr | len | byte] -> ack. */
        const uint8_t *pa, *pl, *pv;
        uint32_t la, ll, lv, addr, len;

        if (ncmp_msg_param(msg, 0, &pa, &la) != NCMP_OK || la < 4 ||
            ncmp_msg_param(msg, 1, &pl, &ll) != NCMP_OK || ll < 4 ||
            ncmp_msg_param(msg, 2, &pv, &lv) != NCMP_OK || lv < 1) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_FUNCTION_FAILED;
            break;
        }
        addr = ncmp_rd_u32le(pa);
        len = ncmp_rd_u32le(pl);
        if ((uint64_t)addr + len > NCMP_VD_MEM_SIZE) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_DEVICE_MEMORY;
            break;
        }
        memset(dev->vd_mem + addr, pv[0], len);
        for (int i = 0; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_VD_MEM_CRC: {
        /* [addr | len] -> crc32 (LE u32) over vendor scratch RAM. */
        const uint8_t *pa, *pl;
        uint32_t la, ll, addr, len, crc = 0xFFFFFFFFu;

        if (ncmp_msg_param(msg, 0, &pa, &la) != NCMP_OK || la < 4 ||
            ncmp_msg_param(msg, 1, &pl, &ll) != NCMP_OK || ll < 4) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_FUNCTION_FAILED;
            break;
        }
        addr = ncmp_rd_u32le(pa);
        len = ncmp_rd_u32le(pl);
        if ((uint64_t)addr + len > NCMP_VD_MEM_SIZE) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_DEVICE_MEMORY;
            break;
        }
        for (uint32_t i = 0; i < len; ++i) {
            crc ^= dev->vd_mem[addr + i];
            for (int b = 0; b < 8; ++b)
                crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)(-(int)(crc & 1u)));
        }
        crc ^= 0xFFFFFFFFu;
        ncmp_wr_u32le(msg->payload, crc);
        msg->param_len[0] = 4;
        for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_VD_PING:
        ncmp_wr_u32le(msg->payload, dev->epoch);
        msg->param_len[0] = 4;
        for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    case NCMP_CMD_VD_SELFTEST:
        dev->epoch++; /* self-test bumps the epoch a PING can observe. */
        ncmp_wr_u32le(msg->payload, 0u); /* 0 == all subsystems OK */
        msg->param_len[0] = 4;
        for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    case NCMP_CMD_VD_FW_INFO:
        ncmp_wr_u32le(msg->payload + 0, 1u);   /* major */
        ncmp_wr_u32le(msg->payload + 4, 0u);   /* minor */
        ncmp_wr_u32le(msg->payload + 8, 0u);   /* patch */
        ncmp_wr_u32le(msg->payload + 12, 0x0FC3u); /* build tag (FX3) */
        msg->param_len[0] = 16;
        for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    case NCMP_CMD_NOP:
    default:
        /* Echo: identity and payload unchanged. */
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
}

int mock_mcu_step(mock_device_t *dev, uint8_t *rsp, size_t rsp_cap,
                  size_t *rsp_len)
{
    if (!dev || !rsp || !rsp_len)
        return NCMP_ERR_INVAL;

    /* Round-robin across the 4 containers, starting at the saved cursor. */
    for (uint32_t n = 0; n < NCMP_DEV_CONTAINER_COUNT; ++n) {
        uint32_t idx = (dev->rr_cursor + n) % NCMP_DEV_CONTAINER_COUNT;
        mock_container_t *c = &dev->container[idx];
        NCMP_Message msg;
        uint8_t payload[NCMP_MAX_PAYLOAD_SIZE];
        int rc;

        if (!c->busy || c->used == 0)
            continue;

        /* Parse the staged request (copies parameter bytes into payload). */
        msg.payload = payload;
        msg.payload_cap = sizeof(payload);
        rc = ncmp_wire_decode(c->data, c->used, &msg);
        if (rc == NCMP_OK) {
            /* Execute the opcode into a response. The fail-injection bit (test
             * hook) overrides any success ACK. Re-encode into rsp. */
            if (msg.header.command_id & NCMP_MOCK_CMD_FAIL_BIT)
                msg.header.ack = MOCK_CKR_FUNCTION_FAILED;
            else
                mock_exec_command(dev, &msg);
            rc = ncmp_wire_encode(&msg, rsp, rsp_cap, rsp_len);
        }

        /* Release the container regardless of parse/encode outcome. */
        c->used = 0;
        c->busy = 0;
        dev->rr_cursor = (idx + 1) % NCMP_DEV_CONTAINER_COUNT;
        return rc;
    }

    return NCMP_ERR_STATE; /* Nothing to schedule. */
}

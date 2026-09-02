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
#include "ncmp/ncmp_errno.h"

#include <stddef.h>
#include <string.h>

/* CKR_* values without pulling the full PKCS#11 headers into the emulator. */
#define MOCK_CKR_OK 0u
#define MOCK_CKR_FUNCTION_FAILED 0x6u
#define MOCK_CKR_ENCRYPTED_DATA_INVALID 0x40u
#define MOCK_CKR_DEVICE_MEMORY 0x31u
#define MOCK_CKR_MECHANISM_INVALID 0x70u
#define MOCK_CKR_SIGNATURE_INVALID 0xC0u
#define MOCK_CKR_PIN_INCORRECT 0xA0u
#define MOCK_CKR_PIN_LEN_RANGE 0xA2u
#define MOCK_CKR_USER_ALREADY_LOGGED_IN 0x100u
#define MOCK_CKR_USER_NOT_LOGGED_IN 0x101u
#define MOCK_CKR_USER_TYPE_INVALID 0x103u

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
 * Shared by sign and verify so a signature can be recomputed and checked. The
 * mock signature is a deterministic function of @p comp (a key component that
 * is available to BOTH signer and verifier - the RSA modulus or the EC curve
 * params) and the folded data; the private exponent / scalar is forwarded but
 * intentionally not folded, since the verifier never sees it. This is a mock
 * limitation, not real signature semantics - hardware performs true sign/verify.
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
    }
    case NCMP_CMD_DIGEST_UPDATE: {
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
    }
    case NCMP_CMD_DIGEST_FINAL: {
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
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_AES_CBC: {
        /* Params: [0]=flags(LE u32), [1]=key, [2]=iv(16), [3]=data(mult of 16).
         * The mock has no AES; it applies a reversible keystream XOR derived
         * from key+iv+position (direction-agnostic, so encrypt then decrypt
         * round-trips). Real firmware performs true AES-CBC. */
        const uint8_t *pf, *pk, *piv, *pd;
        uint32_t lf, lk, liv, ld;
        uint8_t key[32], iv[NCMP_AES_BLOCK];

        if (ncmp_msg_param(msg, 0, &pf, &lf) != NCMP_OK ||
            ncmp_msg_param(msg, 1, &pk, &lk) != NCMP_OK ||
            ncmp_msg_param(msg, 2, &piv, &liv) != NCMP_OK ||
            ncmp_msg_param(msg, 3, &pd, &ld) != NCMP_OK ||
            lf < 4 || (lk != 16 && lk != 24 && lk != 32) ||
            liv != NCMP_AES_BLOCK || (ld % NCMP_AES_BLOCK) != 0) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
            break;
        }

        /* Copy key/iv out before overwriting the payload; data stays in place
         * because its offset (>= 4+lk+16) always leads the write cursor. */
        memcpy(key, pk, lk);
        memcpy(iv, piv, NCMP_AES_BLOCK);
        for (uint32_t i = 0; i < ld; ++i) {
            uint8_t ks = (uint8_t)(key[i % lk] ^ iv[i % NCMP_AES_BLOCK] ^
                                   (uint8_t)i);
            msg->payload[i] = (uint8_t)(pd[i] ^ ks);
        }
        msg->param_len[0] = ld;
        for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
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
    case NCMP_CMD_AES_ECB: {
        /* Params: [0]=flags, [1]=key, [2]=data. Like AES-CBC without an IV:
         * reversible per-position keystream XOR (mock only). */
        const uint8_t *pf, *pk, *pd;
        uint32_t lf, lk, ld;
        uint8_t key[32];

        if (ncmp_msg_param(msg, 0, &pf, &lf) != NCMP_OK ||
            ncmp_msg_param(msg, 1, &pk, &lk) != NCMP_OK ||
            ncmp_msg_param(msg, 2, &pd, &ld) != NCMP_OK ||
            lf < 4 || (lk != 16 && lk != 24 && lk != 32) ||
            (ld % NCMP_AES_BLOCK) != 0) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
            break;
        }
        memcpy(key, pk, lk);
        for (uint32_t i = 0; i < ld; ++i)
            msg->payload[i] = (uint8_t)(pd[i] ^ (key[i % lk] ^ (uint8_t)i));
        msg->param_len[0] = ld;
        for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_EC_SIGN: {
        /* Params: [0]=EC params (curve), [1]=private scalar, [2]=data. Emit an
         * ECDSA-shaped signature of 2*fieldlen bytes, folding curve+data (both
         * available to EC_VERIFY). The private scalar sets the signature size
         * and is forwarded but not folded. NOT real ECDSA. */
        const uint8_t *pparams, *ppriv, *pdata;
        uint32_t lp, lpriv, ldata, acc, siglen;
        uint8_t params[64]; /* EC curve params (OID) are short */

        if (ncmp_msg_param(msg, 0, &pparams, &lp) != NCMP_OK ||
            ncmp_msg_param(msg, 1, &ppriv, &lpriv) != NCMP_OK ||
            ncmp_msg_param(msg, 2, &pdata, &ldata) != NCMP_OK ||
            lp == 0 || lp > sizeof(params) || lpriv == 0) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
            break;
        }
        (void)ppriv;
        siglen = 2u * lpriv;
        /* Copy curve params before overwriting; fold curve+data first. */
        memcpy(params, pparams, lp);
        acc = mock_digest_fold(MOCK_DIGEST_SEED ^ lp, params, lp);
        acc = mock_digest_fold(acc, pdata, ldata);
        mock_sig_expand(acc, params, lp, msg->payload, siglen);
        msg->param_len[0] = siglen;
        for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_EC_VERIFY: {
        /* Params: [0]=EC params, [1]=EC point (public), [2]=data, [3]=sig.
         * Recompute the signature from curve+data and compare. */
        const uint8_t *pparams, *ppoint, *pdata, *psig;
        uint32_t lp, lpoint, ldata, lsig, acc;
        uint8_t params[64], sig[132]; /* up to 2*P-521 */

        if (ncmp_msg_param(msg, 0, &pparams, &lp) != NCMP_OK ||
            ncmp_msg_param(msg, 1, &ppoint, &lpoint) != NCMP_OK ||
            ncmp_msg_param(msg, 2, &pdata, &ldata) != NCMP_OK ||
            ncmp_msg_param(msg, 3, &psig, &lsig) != NCMP_OK ||
            lp == 0 || lp > sizeof(params) || lsig == 0 || lsig > sizeof(sig)) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
            break;
        }
        (void)ppoint;
        (void)lpoint;
        memcpy(params, pparams, lp);
        acc = mock_digest_fold(MOCK_DIGEST_SEED ^ lp, params, lp);
        acc = mock_digest_fold(acc, pdata, ldata);
        mock_sig_expand(acc, params, lp, sig, lsig);
        msg->param_len[0] = 0;
        for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = (memcmp(sig, psig, lsig) == 0)
                              ? MOCK_CKR_OK : MOCK_CKR_SIGNATURE_INVALID;
        break;
    }
    case NCMP_CMD_RSA_SIGN: {
        /* Params: [0]=modulus, [1]=private exponent, [2]=data. Emit a
         * signature of modulus length, folding modulus+data (the modulus is
         * shared with the public key so RSA_VERIFY can recompute it). The
         * private exponent is forwarded but not folded. Not real RSA. */
        const uint8_t *pmod, *pexp, *pdata;
        uint32_t lmod, lexp, ldata, acc;
        uint8_t mod[512]; /* up to RSA-4096 */

        if (ncmp_msg_param(msg, 0, &pmod, &lmod) != NCMP_OK ||
            ncmp_msg_param(msg, 1, &pexp, &lexp) != NCMP_OK ||
            ncmp_msg_param(msg, 2, &pdata, &ldata) != NCMP_OK ||
            lmod == 0 || lmod > sizeof(mod)) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
            break;
        }
        (void)pexp;
        (void)lexp;
        /* Copy modulus before overwriting; fold modulus+data (reads) first. */
        memcpy(mod, pmod, lmod);
        acc = mock_digest_fold(MOCK_DIGEST_SEED ^ lmod, mod, lmod);
        acc = mock_digest_fold(acc, pdata, ldata);
        mock_sig_expand(acc, mod, lmod, msg->payload, lmod);
        msg->param_len[0] = lmod;
        for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_RSA_VERIFY: {
        /* Params: [0]=modulus, [1]=public exponent, [2]=data, [3]=signature.
         * Recompute the signature from modulus+data and compare. */
        const uint8_t *pmod, *pexp, *pdata, *psig;
        uint32_t lmod, lexp, ldata, lsig, acc;
        uint8_t mod[512], sig[512];

        if (ncmp_msg_param(msg, 0, &pmod, &lmod) != NCMP_OK ||
            ncmp_msg_param(msg, 1, &pexp, &lexp) != NCMP_OK ||
            ncmp_msg_param(msg, 2, &pdata, &ldata) != NCMP_OK ||
            ncmp_msg_param(msg, 3, &psig, &lsig) != NCMP_OK ||
            lmod == 0 || lmod > sizeof(mod) || lsig > sizeof(sig)) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
            break;
        }
        (void)pexp;
        (void)lexp;
        msg->param_len[0] = 0;
        for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        if (lsig != lmod) {
            msg->header.ack = MOCK_CKR_SIGNATURE_INVALID;
            break;
        }
        memcpy(mod, pmod, lmod);
        acc = mock_digest_fold(MOCK_DIGEST_SEED ^ lmod, mod, lmod);
        acc = mock_digest_fold(acc, pdata, ldata);
        mock_sig_expand(acc, mod, lmod, sig, lsig);
        msg->header.ack = (memcmp(sig, psig, lsig) == 0)
                              ? MOCK_CKR_OK : MOCK_CKR_SIGNATURE_INVALID;
        break;
    }
    case NCMP_CMD_RSA_KEYGEN: {
        /* Req: [0]=modulus bits (LE u32), [1]=public exponent. Resp: the seven
         * private/public components n|d|p|q|dp|dq|qinv of appropriate sizes.
         * NOT a real key - deterministic bytes so the STDLL can populate the
         * PKCS#11 templates and tests can assert sizes; hardware generates a
         * real keypair. */
        const uint8_t *pbits, *pexp;
        uint32_t lbits, lexp, mod_bits, nbytes, hbytes, seed, off;
        uint32_t sizes[7];

        if (ncmp_msg_param(msg, 0, &pbits, &lbits) != NCMP_OK ||
            ncmp_msg_param(msg, 1, &pexp, &lexp) != NCMP_OK || lbits < 4) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
            break;
        }
        mod_bits = ncmp_rd_u32le(pbits);
        if (mod_bits < 512 || mod_bits > 4096 || (mod_bits % 8) != 0) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
            break;
        }
        nbytes = mod_bits / 8;
        hbytes = nbytes / 2;
        /* Seed from key size + public exponent (reads) before writing. */
        seed = mock_digest_fold(MOCK_DIGEST_SEED ^ mod_bits, pexp, lexp);

        sizes[0] = nbytes; /* n  */
        sizes[1] = nbytes; /* d  */
        sizes[2] = hbytes; /* p  */
        sizes[3] = hbytes; /* q  */
        sizes[4] = hbytes; /* dp */
        sizes[5] = hbytes; /* dq */
        sizes[6] = hbytes; /* qinv */
        off = 0;
        for (int k = 0; k < 7; ++k) {
            for (uint32_t i = 0; i < sizes[k]; ++i)
                msg->payload[off + i] =
                    (uint8_t)(seed + (uint32_t)k * 101u + i * 7u);
            msg->param_len[k] = sizes[k];
            off += sizes[k];
        }
        msg->param_len[7] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_EC_KEYGEN: {
        /* Req: [0]=EC params (curve). Resp: [ec_point | private value]. Mock
         * uses a P-256-sized key (32-byte scalar, 65-byte uncompressed point);
         * hardware honours the actual curve. */
        const uint8_t *pparams;
        uint32_t lp, seed;
        uint8_t params[64];
        const uint32_t privlen = 32;
        const uint32_t pointlen = 1u + 2u * privlen; /* 0x04 || X || Y */

        if (ncmp_msg_param(msg, 0, &pparams, &lp) != NCMP_OK ||
            lp == 0 || lp > sizeof(params)) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
            break;
        }
        memcpy(params, pparams, lp);
        seed = mock_digest_fold(MOCK_DIGEST_SEED ^ lp, params, lp);

        msg->payload[0] = 0x04; /* uncompressed point marker */
        for (uint32_t i = 1; i < pointlen; ++i)
            msg->payload[i] = (uint8_t)(seed + i * 13u);
        for (uint32_t i = 0; i < privlen; ++i)
            msg->payload[pointlen + i] = (uint8_t)(seed + 0x55u + i * 17u);
        msg->param_len[0] = pointlen;
        msg->param_len[1] = privlen;
        for (int i = 2; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_AES_CTR:
    case NCMP_CMD_AES_OFB:
    case NCMP_CMD_AES_CFB:
        /* Stream modes: identical reversible keystream XOR in the mock. */
        mock_aes_stream(msg);
        break;
    case NCMP_CMD_HMAC_SIGN: {
        /* [mech | key | data] -> MAC (hash-sized). Folds key+data so sign and
         * verify (which share the key) agree. */
        const uint8_t *pmech, *pkey, *pdata;
        uint32_t lmech, lkey, ldata, mech, hsize, acc;

        if (ncmp_msg_param(msg, 0, &pmech, &lmech) != NCMP_OK || lmech < 4 ||
            ncmp_msg_param(msg, 1, &pkey, &lkey) != NCMP_OK ||
            ncmp_msg_param(msg, 2, &pdata, &ldata) != NCMP_OK) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
            break;
        }
        mech = ncmp_rd_u32le(pmech);
        hsize = ncmp_hmac_size(mech);
        if (hsize == 0) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
            break;
        }
        acc = mock_digest_fold(MOCK_DIGEST_SEED ^ mech, pkey, lkey);
        acc = mock_digest_fold(acc, pdata, ldata);
        mock_digest_finalize(acc, mech, msg->payload, hsize);
        msg->param_len[0] = hsize;
        for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_HMAC_VERIFY: {
        /* [mech | key | data | mac] -> recompute and compare. */
        const uint8_t *pmech, *pkey, *pdata, *pmac;
        uint32_t lmech, lkey, ldata, lmac, mech, hsize, acc;
        uint8_t mac[64];

        if (ncmp_msg_param(msg, 0, &pmech, &lmech) != NCMP_OK || lmech < 4 ||
            ncmp_msg_param(msg, 1, &pkey, &lkey) != NCMP_OK ||
            ncmp_msg_param(msg, 2, &pdata, &ldata) != NCMP_OK ||
            ncmp_msg_param(msg, 3, &pmac, &lmac) != NCMP_OK) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
            break;
        }
        mech = ncmp_rd_u32le(pmech);
        hsize = ncmp_hmac_size(mech);
        msg->param_len[0] = 0;
        for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        if (hsize == 0 || lmac != hsize) {
            msg->header.ack = MOCK_CKR_SIGNATURE_INVALID;
            break;
        }
        acc = mock_digest_fold(MOCK_DIGEST_SEED ^ mech, pkey, lkey);
        acc = mock_digest_fold(acc, pdata, ldata);
        mock_digest_finalize(acc, mech, mac, hsize);
        msg->header.ack = (memcmp(mac, pmac, hsize) == 0)
                              ? MOCK_CKR_OK : MOCK_CKR_SIGNATURE_INVALID;
        break;
    }
    case NCMP_CMD_RSA_OAEP_ENC: {
        /* [modulus | pub_exp | data] -> ciphertext (modulus length). Encodes
         * [len | data | zero-pad] XORed with a modulus-derived keystream so
         * RSA_OAEP_DEC recovers it. NOT real OAEP. */
        const uint8_t *pmod, *pexp, *pdata;
        uint32_t lmod, lexp, ldata;
        uint8_t mod[512], block[512];

        if (ncmp_msg_param(msg, 0, &pmod, &lmod) != NCMP_OK ||
            ncmp_msg_param(msg, 1, &pexp, &lexp) != NCMP_OK ||
            ncmp_msg_param(msg, 2, &pdata, &ldata) != NCMP_OK ||
            lmod == 0 || lmod > sizeof(mod) || 4 + ldata > lmod) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
            break;
        }
        (void)pexp;
        (void)lexp;
        memcpy(mod, pmod, lmod);
        memset(block, 0, lmod);
        ncmp_wr_u32le(block, ldata);
        memcpy(block + 4, pdata, ldata);
        for (uint32_t i = 0; i < lmod; ++i)
            msg->payload[i] = (uint8_t)(block[i] ^ mod[i] ^ (i * 13u + 0xA5u));
        msg->param_len[0] = lmod;
        for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_RSA_OAEP_DEC: {
        /* [modulus | priv_exp | ciphertext] -> recovered plaintext. */
        const uint8_t *pmod, *pexp, *pct;
        uint32_t lmod, lexp, lct, plen;
        uint8_t mod[512], block[512];

        if (ncmp_msg_param(msg, 0, &pmod, &lmod) != NCMP_OK ||
            ncmp_msg_param(msg, 1, &pexp, &lexp) != NCMP_OK ||
            ncmp_msg_param(msg, 2, &pct, &lct) != NCMP_OK ||
            lmod == 0 || lmod > sizeof(mod) || lct != lmod) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
            break;
        }
        (void)pexp;
        (void)lexp;
        memcpy(mod, pmod, lmod);
        for (uint32_t i = 0; i < lmod; ++i)
            block[i] = (uint8_t)(pct[i] ^ mod[i] ^ (i * 13u + 0xA5u));
        plen = ncmp_rd_u32le(block);
        if (4 + plen > lmod) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_ENCRYPTED_DATA_INVALID;
            break;
        }
        memcpy(msg->payload, block + 4, plen);
        msg->param_len[0] = plen;
        for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_DH_DERIVE: {
        /* [prime | own private | peer public] -> shared secret (prime length).
         * A one-sided key agreement in the mock: a deterministic function of
         * all three inputs. NOT real DH (no modexp); hardware computes the true
         * shared secret. */
        const uint8_t *pprime, *ppriv, *ppub;
        uint32_t lprime, lpriv, lpub, acc;
        uint8_t prime[512];

        if (ncmp_msg_param(msg, 0, &pprime, &lprime) != NCMP_OK ||
            ncmp_msg_param(msg, 1, &ppriv, &lpriv) != NCMP_OK ||
            ncmp_msg_param(msg, 2, &ppub, &lpub) != NCMP_OK ||
            lprime == 0 || lprime > sizeof(prime)) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
            break;
        }
        memcpy(prime, pprime, lprime);
        acc = mock_digest_fold(MOCK_DIGEST_SEED ^ lprime, ppriv, lpriv);
        acc = mock_digest_fold(acc, ppub, lpub);
        mock_sig_expand(acc, prime, lprime, msg->payload, lprime);
        msg->param_len[0] = lprime;
        for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_ECDH_DERIVE: {
        /* [ec_params | own private | peer point] -> shared secret (one field
         * element). Field length is inferred from the uncompressed peer point
         * (0x04 || X || Y). Deterministic mock only. */
        const uint8_t *poid, *ppriv, *ppub;
        uint32_t loid, lpriv, lpub, acc, flen;
        uint8_t oid[64];

        if (ncmp_msg_param(msg, 0, &poid, &loid) != NCMP_OK ||
            ncmp_msg_param(msg, 1, &ppriv, &lpriv) != NCMP_OK ||
            ncmp_msg_param(msg, 2, &ppub, &lpub) != NCMP_OK ||
            loid == 0 || loid > sizeof(oid) || lpub < 3) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
            break;
        }
        flen = (lpub - 1u) / 2u; /* uncompressed point X||Y */
        if (flen == 0 || flen > 66)
            flen = 32; /* fall back to P-256 field size */
        memcpy(oid, poid, loid);
        acc = mock_digest_fold(MOCK_DIGEST_SEED ^ loid, ppriv, lpriv);
        acc = mock_digest_fold(acc, ppub, lpub);
        mock_sig_expand(acc, oid, loid, msg->payload, flen);
        msg->param_len[0] = flen;
        for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
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
        /* [user_type(LE u32) | pin] -> verify against the stored PIN. */
        mock_token_admin_t *a = &dev->admin;
        const uint8_t *put, *ppin;
        uint32_t lut, lpin, ut;

        if (ncmp_msg_param(msg, 0, &put, &lut) != NCMP_OK || lut < 4 ||
            ncmp_msg_param(msg, 1, &ppin, &lpin) != NCMP_OK) {
            for (int i = 0; i < NCMP_MAX_PARAM_COUNT; ++i)
                msg->param_len[i] = 0;
            msg->header.ack = MOCK_CKR_FUNCTION_FAILED;
            break;
        }
        for (int i = 0; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        ut = ncmp_rd_u32le(put);
        if (ut != 0u && ut != 1u) {
            msg->header.ack = MOCK_CKR_USER_TYPE_INVALID;
            break;
        }
        if (a->logged_in) {
            msg->header.ack = MOCK_CKR_USER_ALREADY_LOGGED_IN;
            break;
        }
        if (!mock_pin_ok(a, ut, ppin, lpin)) {
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
    case NCMP_CMD_VD_LOOPBACK:
        /* Echo param0 verbatim (payload already holds it). */
        msg->header.ack = MOCK_CKR_OK;
        break;
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

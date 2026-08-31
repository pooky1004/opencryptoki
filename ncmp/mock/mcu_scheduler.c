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
         * ECDSA-shaped signature of 2*fieldlen bytes. NOT real ECDSA - folds
         * curve+key+data deterministically so tests can assert forwarding. */
        const uint8_t *pparams, *ppriv, *pdata;
        uint32_t lp, lpriv, ldata, acc, siglen;
        uint8_t priv[66]; /* up to P-521 field size */

        if (ncmp_msg_param(msg, 0, &pparams, &lp) != NCMP_OK ||
            ncmp_msg_param(msg, 1, &ppriv, &lpriv) != NCMP_OK ||
            ncmp_msg_param(msg, 2, &pdata, &ldata) != NCMP_OK ||
            lpriv == 0 || lpriv > sizeof(priv)) {
            msg->param_len[0] = 0;
            msg->header.ack = MOCK_CKR_MECHANISM_INVALID;
            break;
        }
        siglen = 2u * lpriv;
        /* Copy priv, fold all inputs (reads) before writing the signature. */
        memcpy(priv, ppriv, lpriv);
        acc = mock_digest_fold(MOCK_DIGEST_SEED ^ lp, pparams, lp);
        acc = mock_digest_fold(acc, pdata, ldata);
        acc = mock_digest_fold(acc, priv, lpriv);
        for (uint32_t i = 0; i < siglen; ++i)
            msg->payload[i] = (uint8_t)((acc >> (i & 7)) + i * 197u +
                                        priv[i % lpriv]);
        msg->param_len[0] = siglen;
        for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
    case NCMP_CMD_RSA_SIGN: {
        /* Params: [0]=modulus, [1]=private exponent, [2]=data. Emit a
         * signature of modulus length. NOT real RSA - the mock folds key +
         * data into a deterministic, input/key-sensitive byte pattern so tests
         * can assert forwarding; hardware performs true RSA. */
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
        /* Copy modulus before overwriting; fold key+data (all reads) first. */
        memcpy(mod, pmod, lmod);
        acc = mock_digest_fold(MOCK_DIGEST_SEED ^ lmod, pexp, lexp);
        acc = mock_digest_fold(acc, pdata, ldata);
        for (uint32_t i = 0; i < lmod; ++i)
            msg->payload[i] = (uint8_t)((acc >> (i & 7)) + i * 131u + mod[i]);
        msg->param_len[0] = lmod;
        for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i)
            msg->param_len[i] = 0;
        msg->header.ack = MOCK_CKR_OK;
        break;
    }
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

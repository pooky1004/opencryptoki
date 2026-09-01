/*
 * Token NCMP - PKCS#11 cryptographic operations (data plane).
 *
 * Encryption, decryption, digesting, signing/MACing, verification, the
 * dual-function combinations, and the message-based (v3.0) variants. Every
 * operation resolves its key from the object store (under the provider lock),
 * snapshots the needed key material into local buffers, releases the lock, and
 * forwards the marshalled command to the token via p11_forward*() - so threads
 * run concurrently through the lock-free transport.
 *
 * Wire parameter layouts mirror the token opcodes exactly (see
 * ncmp/tests/test_client.c, the marshalling reference).
 */
#include "p11_provider.h"

#include "ncmp/ncmp_cmd.h"
#include "ncmp/ncmp_wire.h"

#include <stdlib.h>
#include <string.h>

/* Local scratch bounds. */
#define KMAX 1024u  /* largest key component (RSA-4096 modulus / exponent) */

/* ------------------------------------------------------------------------- */
/* Shared helpers                                                            */
/* ------------------------------------------------------------------------- */

/** Copy attribute @p t of key @p h into @p buf. Caller MUST hold the lock. */
static CK_RV grab(CK_OBJECT_HANDLE h, CK_ATTRIBUTE_TYPE t, uint8_t *buf,
                  uint32_t cap, uint32_t *len)
{
    p11_object_t *o = p11_object_get(h);
    p11_attr_t *a;

    if (!o)
        return CKR_KEY_HANDLE_INVALID;
    a = p11_obj_attr(o, t);
    if (!a || a->len == 0)
        return CKR_TEMPLATE_INCOMPLETE;
    if (a->len > cap)
        return CKR_DEVICE_MEMORY;
    memcpy(buf, a->val, a->len);
    *len = (uint32_t)a->len;
    return CKR_OK;
}

/** Validate that key @p h grants boolean permission @p perm. Lock held. */
static CK_RV check_perm(CK_OBJECT_HANDLE h, CK_ATTRIBUTE_TYPE perm)
{
    p11_object_t *o = p11_object_get(h);

    if (!o)
        return CKR_KEY_HANDLE_INVALID;
    if (!p11_obj_bool(o, perm, CK_TRUE))
        return CKR_KEY_FUNCTION_NOT_PERMITTED;
    return CKR_OK;
}

/** True for AES cipher mechanisms handled by the symmetric datapath. */
static int is_aes_mech(CK_MECHANISM_TYPE m)
{
    return m == CKM_AES_ECB || m == CKM_AES_CBC || m == CKM_AES_CBC_PAD ||
           m == CKM_AES_CTR || m == CKM_AES_GCM;
}

/**
 * @brief Run one AES transform on the token (opcode chosen from @p mech).
 * @param enc Non-zero to encrypt.
 * All buffers are caller-owned; @p out receives the raw token output.
 */
static CK_RV aes_core(CK_SLOT_ID slot, CK_MECHANISM_TYPE mech, int enc,
                      const uint8_t *key, uint32_t keylen,
                      const uint8_t *iv, uint32_t ivlen,
                      const uint8_t *aad, uint32_t aadlen, uint32_t taglen,
                      const uint8_t *in, uint32_t inlen,
                      uint8_t *out, uint32_t outcap, uint32_t *outlen)
{
    uint8_t flags[4], tl[4];
    const uint8_t *parts[6];
    uint32_t lens[6];
    NCMP_Message rsp;
    CK_RV rv;
    uint32_t opcode;
    int n;

    ncmp_wr_u32le(flags, enc ? NCMP_AES_FLAG_ENCRYPT : 0u);

    switch (mech) {
    case CKM_AES_ECB:
        opcode = NCMP_CMD_AES_ECB;
        parts[0] = flags; lens[0] = 4;
        parts[1] = key;   lens[1] = keylen;
        parts[2] = in;    lens[2] = inlen;
        n = 3;
        break;
    case CKM_AES_CBC:
    case CKM_AES_CBC_PAD:
        opcode = NCMP_CMD_AES_CBC;
        parts[0] = flags; lens[0] = 4;
        parts[1] = key;   lens[1] = keylen;
        parts[2] = iv;    lens[2] = ivlen;
        parts[3] = in;    lens[3] = inlen;
        n = 4;
        break;
    case CKM_AES_CTR:
        opcode = NCMP_CMD_AES_CTR;
        parts[0] = flags; lens[0] = 4;
        parts[1] = key;   lens[1] = keylen;
        parts[2] = iv;    lens[2] = ivlen;
        parts[3] = in;    lens[3] = inlen;
        n = 4;
        break;
    case CKM_AES_GCM:
        opcode = NCMP_CMD_AES_GCM;
        ncmp_wr_u32le(tl, taglen);
        parts[0] = flags; lens[0] = 4;
        parts[1] = key;   lens[1] = keylen;
        parts[2] = iv;    lens[2] = ivlen;
        parts[3] = aad;   lens[3] = aadlen;
        parts[4] = tl;    lens[4] = 4;
        parts[5] = in;    lens[5] = inlen;
        n = 6;
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }

    memset(&rsp, 0, sizeof(rsp));
    rv = p11_forward_mp(slot, opcode, parts, lens, n, out, outcap, &rsp);
    if (rv != CKR_OK)
        return rv;
    if (outlen)
        *outlen = rsp.param_len[0];
    return CKR_OK;
}

/* ------------------------------------------------------------------------- */
/* Encryption                                                                */
/* ------------------------------------------------------------------------- */

/** Capture mechanism parameters into an operation context. Lock held. */
static CK_RV capture_cipher_params(p11_opctx_t *c, CK_MECHANISM_PTR mech)
{
    c->iv_len = 0;
    c->aad_len = 0;
    c->tag_len = 0;

    switch (mech->mechanism) {
    case CKM_AES_ECB:
        return CKR_OK;
    case CKM_AES_CBC:
    case CKM_AES_CBC_PAD:
    case CKM_AES_CTR:
        if (!mech->pParameter || mech->ulParameterLen < 16)
            return CKR_MECHANISM_PARAM_INVALID;
        memcpy(c->iv, mech->pParameter, 16);
        c->iv_len = 16;
        return CKR_OK;
    case CKM_AES_GCM: {
        CK_GCM_PARAMS *g = (CK_GCM_PARAMS *)mech->pParameter;

        if (!g || mech->ulParameterLen < sizeof(CK_GCM_PARAMS))
            return CKR_MECHANISM_PARAM_INVALID;
        if (g->ulIvLen == 0 || g->ulIvLen > sizeof(c->iv))
            return CKR_MECHANISM_PARAM_INVALID;
        memcpy(c->iv, g->pIv, g->ulIvLen);
        c->iv_len = (uint32_t)g->ulIvLen;
        if (g->ulAADLen > sizeof(c->aad))
            return CKR_MECHANISM_PARAM_INVALID;
        if (g->ulAADLen && g->pAAD)
            memcpy(c->aad, g->pAAD, g->ulAADLen);
        c->aad_len = (uint32_t)g->ulAADLen;
        c->tag_len = (uint32_t)(g->ulTagBits / 8);
        if (c->tag_len == 0 || c->tag_len > 16)
            return CKR_MECHANISM_PARAM_INVALID;
        return CKR_OK;
    }
    default:
        return CKR_MECHANISM_INVALID;
    }
}

/** Common *Init for an encrypt/decrypt op (kind selects direction). */
static CK_RV cipher_init(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                         CK_OBJECT_HANDLE hKey, p11_op_kind_t kind, int message)
{
    p11_session_t *s;
    p11_opctx_t *c;
    CK_RV rv;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!pMechanism)
        return CKR_ARGUMENTS_BAD;

    p11_lock();
    s = p11_session_get(hSession);
    if (!s) {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    c = (kind == P11_OP_ENCRYPT) ? &s->enc : &s->dec;
    if (c->kind != P11_OP_NONE) {
        p11_unlock();
        return CKR_OPERATION_ACTIVE;
    }
    rv = check_perm(hKey, (kind == P11_OP_ENCRYPT) ? CKA_ENCRYPT : CKA_DECRYPT);
    if (rv != CKR_OK) {
        p11_unlock();
        return rv;
    }
    if (is_aes_mech(pMechanism->mechanism)) {
        rv = capture_cipher_params(c, pMechanism);
    } else if (pMechanism->mechanism == CKM_RSA_PKCS_OAEP ||
               pMechanism->mechanism == CKM_RSA_PKCS) {
        c->iv_len = 0;
        rv = CKR_OK;
    } else {
        rv = CKR_MECHANISM_INVALID;
    }
    if (rv != CKR_OK) {
        c->iv_len = 0;
        p11_unlock();
        return rv;
    }
    c->kind = kind;
    c->mech = pMechanism->mechanism;
    c->key = hKey;
    c->message = message;
    c->buf_len = 0;
    p11_unlock();
    return CKR_OK;
}

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                    CK_OBJECT_HANDLE hKey)
{
    return cipher_init(hSession, pMechanism, hKey, P11_OP_ENCRYPT, 0);
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                    CK_OBJECT_HANDLE hKey)
{
    return cipher_init(hSession, pMechanism, hKey, P11_OP_DECRYPT, 0);
}

/** RSA public/private encrypt (OAEP). Snapshot done by caller under lock. */
static CK_RV rsa_encdec(CK_SLOT_ID slot, int enc, const uint8_t *mod,
                        uint32_t modlen, const uint8_t *exp, uint32_t explen,
                        const uint8_t *in, uint32_t inlen, uint8_t *out,
                        uint32_t outcap, uint32_t *outlen)
{
    const uint8_t *parts[3];
    uint32_t lens[3];
    NCMP_Message rsp;
    CK_RV rv;

    parts[0] = mod; lens[0] = modlen;
    parts[1] = exp; lens[1] = explen;
    parts[2] = in;  lens[2] = inlen;
    memset(&rsp, 0, sizeof(rsp));
    rv = p11_forward_mp(slot, enc ? NCMP_CMD_RSA_OAEP_ENC : NCMP_CMD_RSA_OAEP_DEC,
                        parts, lens, 3, out, outcap, &rsp);
    if (rv != CKR_OK)
        return rv;
    if (outlen)
        *outlen = rsp.param_len[0];
    return CKR_OK;
}

/**
 * @brief Perform a one-shot cipher on @p in, honoring the two-call buffer
 *        protocol. Terminates the operation on success.
 */
static CK_RV cipher_oneshot(CK_SESSION_HANDLE hSession, p11_op_kind_t kind,
                            CK_BYTE_PTR in, CK_ULONG inlen, CK_BYTE_PTR out,
                            CK_ULONG_PTR poutlen)
{
    p11_session_t *s;
    p11_opctx_t *c;
    CK_SLOT_ID slot;
    CK_MECHANISM_TYPE mech;
    CK_OBJECT_HANDLE key;
    uint8_t kbuf[KMAX], iv[16], aad[512], mod[KMAX], exp[KMAX];
    uint32_t klen = 0, ivlen, aadlen, taglen, modlen = 0, explen = 0;
    int enc = (kind == P11_OP_ENCRYPT);
    CK_RV rv;
    uint32_t predicted, produced = 0;
    uint8_t *work = NULL;
    uint32_t workcap;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!poutlen)
        return CKR_ARGUMENTS_BAD;

    p11_lock();
    s = p11_session_get(hSession);
    if (!s) {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    c = enc ? &s->enc : &s->dec;
    if (c->kind != kind) {
        p11_unlock();
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    slot = s->slot;
    mech = c->mech;
    key = c->key;
    ivlen = c->iv_len;
    aadlen = c->aad_len;
    taglen = c->tag_len;
    memcpy(iv, c->iv, sizeof(iv));
    memcpy(aad, c->aad, sizeof(aad));

    if (is_aes_mech(mech)) {
        rv = grab(key, CKA_VALUE, kbuf, sizeof(kbuf), &klen);
    } else {
        rv = grab(key, CKA_MODULUS, mod, sizeof(mod), &modlen);
        if (rv == CKR_OK)
            rv = grab(key, enc ? CKA_PUBLIC_EXPONENT : CKA_PRIVATE_EXPONENT,
                      exp, sizeof(exp), &explen);
    }
    if (rv != CKR_OK) {
        p11_unlock();
        return rv;
    }

    /* Predict output length for the two-call buffer protocol. */
    if (is_aes_mech(mech)) {
        if (mech == CKM_AES_GCM)
            predicted = enc ? (uint32_t)inlen + taglen
                            : (inlen >= taglen ? (uint32_t)inlen - taglen : 0);
        else if (mech == CKM_AES_CBC_PAD)
            predicted = enc ? ((uint32_t)(inlen / 16) + 1) * 16
                            : (uint32_t)inlen;
        else
            predicted = (uint32_t)inlen;
    } else {
        predicted = modlen; /* RSA output is one modulus block (dec: upper bound) */
    }
    p11_unlock();

    if (!out) {
        *poutlen = predicted;
        return CKR_OK; /* length query; operation stays active */
    }
    if ((CK_ULONG)predicted > *poutlen) {
        *poutlen = predicted;
        return CKR_BUFFER_TOO_SMALL; /* operation stays active */
    }

    /* Produce into a work buffer sized to the predicted length (+ block). */
    workcap = predicted + 32;
    work = (uint8_t *)malloc(workcap);
    if (!work)
        return CKR_DEVICE_MEMORY;

    if (is_aes_mech(mech)) {
        if (mech == CKM_AES_CBC_PAD && enc) {
            /* PKCS#7 pad to a block multiple. */
            uint32_t pad = 16 - (uint32_t)(inlen % 16);
            uint8_t *padbuf = (uint8_t *)malloc(inlen + pad);

            if (!padbuf) { free(work); return CKR_DEVICE_MEMORY; }
            memcpy(padbuf, in, inlen);
            memset(padbuf + inlen, (int)pad, pad);
            rv = aes_core(slot, CKM_AES_CBC, 1, kbuf, klen, iv, ivlen,
                          aad, aadlen, taglen, padbuf, (uint32_t)inlen + pad,
                          work, workcap, &produced);
            free(padbuf);
        } else if (mech == CKM_AES_CBC_PAD && !enc) {
            rv = aes_core(slot, CKM_AES_CBC, 0, kbuf, klen, iv, ivlen,
                          aad, aadlen, taglen, in, (uint32_t)inlen,
                          work, workcap, &produced);
            if (rv == CKR_OK && produced > 0) {
                uint32_t pad = work[produced - 1];

                if (pad == 0 || pad > 16 || pad > produced)
                    rv = CKR_ENCRYPTED_DATA_INVALID;
                else
                    produced -= pad;
            }
        } else {
            rv = aes_core(slot, mech, enc, kbuf, klen, iv, ivlen, aad, aadlen,
                          taglen, in, (uint32_t)inlen, work, workcap, &produced);
        }
    } else {
        rv = rsa_encdec(slot, enc, mod, modlen, exp, explen, in, (uint32_t)inlen,
                        work, workcap, &produced);
    }

    if (rv == CKR_OK) {
        if ((CK_ULONG)produced > *poutlen) {
            rv = CKR_BUFFER_TOO_SMALL;
        } else {
            memcpy(out, work, produced);
            *poutlen = produced;
        }
    }
    free(work);

    /* One-shot operation terminates (success or hard error). */
    if (rv != CKR_BUFFER_TOO_SMALL) {
        p11_lock();
        s = p11_session_get(hSession);
        if (s) {
            c = enc ? &s->enc : &s->dec;
            c->kind = P11_OP_NONE;
            c->buf_len = 0;
        }
        p11_unlock();
    }
    return rv;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
    return cipher_oneshot(hSession, P11_OP_ENCRYPT, pData, ulDataLen,
                          pEncryptedData, pulEncryptedDataLen);
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData,
                CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData,
                CK_ULONG_PTR pulDataLen)
{
    return cipher_oneshot(hSession, P11_OP_DECRYPT, pEncryptedData,
                          ulEncryptedDataLen, pData, pulDataLen);
}

/** Append @p len bytes to a context's multipart buffer. Lock held. */
static CK_RV opctx_append(p11_opctx_t *c, const uint8_t *data, uint32_t len)
{
    if (c->buf_len + len > P11_MAX_OP_BUF)
        return CKR_DATA_LEN_RANGE;
    if (!c->buf) {
        c->buf = (uint8_t *)malloc(P11_MAX_OP_BUF);
        if (!c->buf)
            return CKR_DEVICE_MEMORY;
        c->buf_cap = P11_MAX_OP_BUF;
    }
    memcpy(c->buf + c->buf_len, data, len);
    c->buf_len += len;
    return CKR_OK;
}

/** Multipart *Update: buffer the part, produce no output (token buffers). */
static CK_RV cipher_update(CK_SESSION_HANDLE hSession, p11_op_kind_t kind,
                           CK_BYTE_PTR in, CK_ULONG inlen, CK_BYTE_PTR out,
                           CK_ULONG_PTR poutlen)
{
    p11_session_t *s;
    p11_opctx_t *c;
    CK_RV rv;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!poutlen)
        return CKR_ARGUMENTS_BAD;

    p11_lock();
    s = p11_session_get(hSession);
    if (!s) {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    c = (kind == P11_OP_ENCRYPT) ? &s->enc : &s->dec;
    if (c->kind != kind) {
        p11_unlock();
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    rv = opctx_append(c, in, (uint32_t)inlen);
    p11_unlock();
    if (rv != CKR_OK)
        return rv;

    if (out)
        *poutlen = 0; /* all output is produced at *Final */
    else
        *poutlen = 0;
    return CKR_OK;
}

/** Multipart *Final: transform the whole buffered input at once. */
static CK_RV cipher_final(CK_SESSION_HANDLE hSession, p11_op_kind_t kind,
                          CK_BYTE_PTR out, CK_ULONG_PTR poutlen)
{
    p11_session_t *s;
    p11_opctx_t *c;
    CK_SLOT_ID slot;
    CK_MECHANISM_TYPE mech;
    CK_OBJECT_HANDLE key;
    uint8_t kbuf[KMAX], iv[16], aad[512];
    uint32_t klen = 0, ivlen, aadlen, taglen;
    int enc = (kind == P11_OP_ENCRYPT);
    uint8_t *inbuf = NULL;
    uint32_t inlen = 0;
    uint8_t *work = NULL;
    uint32_t predicted, produced = 0, workcap;
    CK_RV rv;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!poutlen)
        return CKR_ARGUMENTS_BAD;

    p11_lock();
    s = p11_session_get(hSession);
    if (!s) {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    c = enc ? &s->enc : &s->dec;
    if (c->kind != kind) {
        p11_unlock();
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    slot = s->slot;
    mech = c->mech;
    key = c->key;
    ivlen = c->iv_len;
    aadlen = c->aad_len;
    taglen = c->tag_len;
    memcpy(iv, c->iv, sizeof(iv));
    memcpy(aad, c->aad, sizeof(aad));
    inlen = c->buf_len;
    if (inlen) {
        inbuf = (uint8_t *)malloc(inlen);
        if (!inbuf) {
            p11_unlock();
            return CKR_DEVICE_MEMORY;
        }
        memcpy(inbuf, c->buf, inlen);
    }
    rv = grab(key, CKA_VALUE, kbuf, sizeof(kbuf), &klen);
    if (rv != CKR_OK) {
        free(inbuf);
        p11_unlock();
        return rv;
    }

    if (mech == CKM_AES_CBC_PAD)
        predicted = enc ? ((inlen / 16) + 1) * 16 : inlen;
    else if (mech == CKM_AES_GCM)
        predicted = enc ? inlen + taglen : (inlen >= taglen ? inlen - taglen : 0);
    else
        predicted = inlen;
    p11_unlock();

    if (!out) {
        *poutlen = predicted;
        free(inbuf);
        return CKR_OK;
    }
    if ((CK_ULONG)predicted > *poutlen) {
        *poutlen = predicted;
        free(inbuf);
        return CKR_BUFFER_TOO_SMALL;
    }

    workcap = predicted + 32;
    work = (uint8_t *)malloc(workcap);
    if (!work) {
        free(inbuf);
        return CKR_DEVICE_MEMORY;
    }
    if (mech == CKM_AES_CBC_PAD && enc) {
        uint32_t pad = 16 - (inlen % 16);
        uint8_t *padbuf = (uint8_t *)malloc(inlen + pad);

        if (!padbuf) { free(work); free(inbuf); return CKR_DEVICE_MEMORY; }
        if (inlen)
            memcpy(padbuf, inbuf, inlen);
        memset(padbuf + inlen, (int)pad, pad);
        rv = aes_core(slot, CKM_AES_CBC, 1, kbuf, klen, iv, ivlen, aad, aadlen,
                      taglen, padbuf, inlen + pad, work, workcap, &produced);
        free(padbuf);
    } else if (mech == CKM_AES_CBC_PAD && !enc) {
        rv = aes_core(slot, CKM_AES_CBC, 0, kbuf, klen, iv, ivlen, aad, aadlen,
                      taglen, inbuf, inlen, work, workcap, &produced);
        if (rv == CKR_OK && produced > 0) {
            uint32_t pad = work[produced - 1];

            if (pad == 0 || pad > 16 || pad > produced)
                rv = CKR_ENCRYPTED_DATA_INVALID;
            else
                produced -= pad;
        }
    } else {
        rv = aes_core(slot, mech, enc, kbuf, klen, iv, ivlen, aad, aadlen,
                      taglen, inbuf, inlen, work, workcap, &produced);
    }
    free(inbuf);

    if (rv == CKR_OK) {
        if ((CK_ULONG)produced > *poutlen)
            rv = CKR_BUFFER_TOO_SMALL;
        else {
            memcpy(out, work, produced);
            *poutlen = produced;
        }
    }
    free(work);

    if (rv != CKR_BUFFER_TOO_SMALL) {
        p11_lock();
        s = p11_session_get(hSession);
        if (s) {
            c = enc ? &s->enc : &s->dec;
            c->kind = P11_OP_NONE;
            c->buf_len = 0;
        }
        p11_unlock();
    }
    return rv;
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                      CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                      CK_ULONG_PTR pulEncryptedPartLen)
{
    return cipher_update(hSession, P11_OP_ENCRYPT, pPart, ulPartLen,
                         pEncryptedPart, pulEncryptedPartLen);
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart,
                     CK_ULONG_PTR pulLastEncryptedPartLen)
{
    return cipher_final(hSession, P11_OP_ENCRYPT, pLastEncryptedPart,
                        pulLastEncryptedPartLen);
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
                      CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
                      CK_ULONG_PTR pulPartLen)
{
    return cipher_update(hSession, P11_OP_DECRYPT, pEncryptedPart,
                         ulEncryptedPartLen, pPart, pulPartLen);
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart,
                     CK_ULONG_PTR pulLastPartLen)
{
    return cipher_final(hSession, P11_OP_DECRYPT, pLastPart, pulLastPartLen);
}

/* ------------------------------------------------------------------------- */
/* Message digesting                                                         */
/* ------------------------------------------------------------------------- */

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
    p11_session_t *s;
    uint32_t dsize;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!pMechanism)
        return CKR_ARGUMENTS_BAD;
    dsize = ncmp_digest_size((uint32_t)pMechanism->mechanism);
    if (dsize == 0)
        return CKR_MECHANISM_INVALID;

    p11_lock();
    s = p11_session_get(hSession);
    if (!s) {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (s->dig.kind != P11_OP_NONE) {
        p11_unlock();
        return CKR_OPERATION_ACTIVE;
    }
    s->dig.kind = P11_OP_DIGEST;
    s->dig.mech = pMechanism->mechanism;
    s->dig.digest_ctx = NCMP_DIGEST_CTX_NONE;
    s->dig.buf_len = 0;
    p11_unlock();
    return CKR_OK;
}

CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
               CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
    p11_session_t *s;
    CK_SLOT_ID slot;
    CK_MECHANISM_TYPE mech;
    uint32_t dsize, outlen = 0;
    uint8_t *req = NULL;
    uint8_t out[64];
    CK_RV rv;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!pulDigestLen)
        return CKR_ARGUMENTS_BAD;

    p11_lock();
    s = p11_session_get(hSession);
    if (!s) {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (s->dig.kind != P11_OP_DIGEST) {
        p11_unlock();
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    slot = s->slot;
    mech = s->dig.mech;
    p11_unlock();

    dsize = ncmp_digest_size((uint32_t)mech);
    if (!pDigest) {
        *pulDigestLen = dsize;
        return CKR_OK;
    }
    if (*pulDigestLen < dsize) {
        *pulDigestLen = dsize;
        return CKR_BUFFER_TOO_SMALL;
    }

    req = (uint8_t *)malloc(4 + ulDataLen);
    if (!req)
        return CKR_DEVICE_MEMORY;
    ncmp_wr_u32le(req, (uint32_t)mech);
    if (ulDataLen)
        memcpy(req + 4, pData, ulDataLen);
    rv = p11_forward(slot, NCMP_CMD_DIGEST, req, 4 + (uint32_t)ulDataLen,
                     out, sizeof(out), &outlen);
    free(req);
    if (rv == CKR_OK) {
        memcpy(pDigest, out, outlen);
        *pulDigestLen = outlen;
    }
    p11_lock();
    s = p11_session_get(hSession);
    if (s)
        s->dig.kind = P11_OP_NONE;
    p11_unlock();
    return rv;
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                     CK_ULONG ulPartLen)
{
    p11_session_t *s;
    CK_SLOT_ID slot;
    CK_MECHANISM_TYPE mech;
    uint32_t ctx_id, outlen = 0;
    CK_RV rv;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    p11_lock();
    s = p11_session_get(hSession);
    if (!s) {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (s->dig.kind != P11_OP_DIGEST) {
        p11_unlock();
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    slot = s->slot;
    mech = s->dig.mech;
    ctx_id = s->dig.digest_ctx;
    p11_unlock();

    /* Lazily allocate the token-side multipart context on the first update. */
    if (ctx_id == NCMP_DIGEST_CTX_NONE) {
        uint8_t mbuf[4], idbuf[4];

        ncmp_wr_u32le(mbuf, (uint32_t)mech);
        rv = p11_forward(slot, NCMP_CMD_DIGEST_INIT, mbuf, 4, idbuf,
                         sizeof(idbuf), &outlen);
        if (rv != CKR_OK)
            return rv;
        ctx_id = ncmp_rd_u32le(idbuf);
        p11_lock();
        s = p11_session_get(hSession);
        if (s)
            s->dig.digest_ctx = ctx_id;
        p11_unlock();
    }
    {
        uint8_t idbuf[4];
        const uint8_t *parts[2];
        uint32_t lens[2];
        NCMP_Message rsp;

        ncmp_wr_u32le(idbuf, ctx_id);
        parts[0] = idbuf; lens[0] = 4;
        parts[1] = pPart; lens[1] = (uint32_t)ulPartLen;
        memset(&rsp, 0, sizeof(rsp));
        rv = p11_forward_mp(slot, NCMP_CMD_DIGEST_UPDATE, parts, lens, 2,
                            NULL, 0, &rsp);
    }
    return rv;
}

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
    p11_session_t *s;
    uint8_t kbuf[KMAX];
    uint32_t klen = 0;
    CK_RV rv;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    p11_lock();
    s = p11_session_get(hSession);
    if (!s) {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (s->dig.kind != P11_OP_DIGEST) {
        p11_unlock();
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    rv = grab(hKey, CKA_VALUE, kbuf, sizeof(kbuf), &klen);
    p11_unlock();
    if (rv != CKR_OK)
        return rv;
    /* Feed the key bytes into the running digest. */
    return C_DigestUpdate(hSession, kbuf, klen);
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest,
                    CK_ULONG_PTR pulDigestLen)
{
    p11_session_t *s;
    CK_SLOT_ID slot;
    CK_MECHANISM_TYPE mech;
    uint32_t ctx_id, dsize, outlen = 0;
    uint8_t idbuf[4], out[64];
    CK_RV rv;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!pulDigestLen)
        return CKR_ARGUMENTS_BAD;

    p11_lock();
    s = p11_session_get(hSession);
    if (!s) {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (s->dig.kind != P11_OP_DIGEST) {
        p11_unlock();
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    slot = s->slot;
    mech = s->dig.mech;
    ctx_id = s->dig.digest_ctx;
    p11_unlock();

    dsize = ncmp_digest_size((uint32_t)mech);
    if (!pDigest) {
        *pulDigestLen = dsize;
        return CKR_OK;
    }
    if (*pulDigestLen < dsize) {
        *pulDigestLen = dsize;
        return CKR_BUFFER_TOO_SMALL;
    }
    if (ctx_id == NCMP_DIGEST_CTX_NONE) {
        /* No update happened: digest of the empty message. */
        uint8_t req[4];

        ncmp_wr_u32le(req, (uint32_t)mech);
        rv = p11_forward(slot, NCMP_CMD_DIGEST, req, 4, out, sizeof(out),
                         &outlen);
    } else {
        ncmp_wr_u32le(idbuf, ctx_id);
        rv = p11_forward(slot, NCMP_CMD_DIGEST_FINAL, idbuf, 4, out,
                         sizeof(out), &outlen);
    }
    if (rv == CKR_OK) {
        memcpy(pDigest, out, outlen);
        *pulDigestLen = outlen;
    }
    p11_lock();
    s = p11_session_get(hSession);
    if (s) {
        s->dig.kind = P11_OP_NONE;
        s->dig.digest_ctx = NCMP_DIGEST_CTX_NONE;
    }
    p11_unlock();
    return rv;
}

/* ------------------------------------------------------------------------- */
/* Signing / MACing and verification                                         */
/* ------------------------------------------------------------------------- */

/** True for RSA signature mechanisms. */
static int is_rsa_sig(CK_MECHANISM_TYPE m)
{
    return m == CKM_RSA_PKCS || m == CKM_RSA_PKCS_PSS;
}
/** True for ECDSA signature mechanisms. */
static int is_ec_sig(CK_MECHANISM_TYPE m)
{
    return m == CKM_ECDSA || m == CKM_ECDSA_SHA256 || m == CKM_ECDSA_SHA384;
}
/** HMAC output size for @p m, or 0. */
static uint32_t hmac_size(CK_MECHANISM_TYPE m)
{
    return ncmp_hmac_size((uint32_t)m);
}

/** Common *Init for sign/verify (kind selects direction). */
static CK_RV sv_init(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                     CK_OBJECT_HANDLE hKey, p11_op_kind_t kind, int message)
{
    p11_session_t *s;
    p11_opctx_t *c;
    CK_MECHANISM_TYPE m;
    CK_RV rv;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!pMechanism)
        return CKR_ARGUMENTS_BAD;
    m = pMechanism->mechanism;
    if (!is_rsa_sig(m) && !is_ec_sig(m) && hmac_size(m) == 0)
        return CKR_MECHANISM_INVALID;

    p11_lock();
    s = p11_session_get(hSession);
    if (!s) {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    c = (kind == P11_OP_SIGN) ? &s->sig : &s->ver;
    if (c->kind != P11_OP_NONE) {
        p11_unlock();
        return CKR_OPERATION_ACTIVE;
    }
    rv = check_perm(hKey, (kind == P11_OP_SIGN) ? CKA_SIGN : CKA_VERIFY);
    if (rv != CKR_OK) {
        p11_unlock();
        return rv;
    }
    c->kind = kind;
    c->mech = m;
    c->key = hKey;
    c->message = message;
    c->buf_len = 0;
    p11_unlock();
    return CKR_OK;
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                 CK_OBJECT_HANDLE hKey)
{
    return sv_init(hSession, pMechanism, hKey, P11_OP_SIGN, 0);
}

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                   CK_OBJECT_HANDLE hKey)
{
    return sv_init(hSession, pMechanism, hKey, P11_OP_VERIFY, 0);
}

/**
 * @brief Compute a signature/MAC over @p data (one-shot sign path).
 * @param out May be NULL for a length query; terminates op on success.
 */
static CK_RV do_sign(CK_SESSION_HANDLE hSession, const uint8_t *data,
                     uint32_t datalen, uint8_t *out, CK_ULONG_PTR poutlen)
{
    p11_session_t *s;
    CK_SLOT_ID slot;
    CK_MECHANISM_TYPE mech;
    CK_OBJECT_HANDLE key;
    uint8_t a0[KMAX], a1[KMAX];
    uint32_t l0 = 0, l1 = 0, predicted, produced = 0;
    uint8_t sig[600];
    const uint8_t *parts[3];
    uint32_t lens[3];
    NCMP_Message rsp;
    CK_RV rv;
    uint32_t opcode;

    p11_lock();
    s = p11_session_get(hSession);
    if (!s) {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (s->sig.kind != P11_OP_SIGN) {
        p11_unlock();
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    slot = s->slot;
    mech = s->sig.mech;
    key = s->sig.key;

    if (is_rsa_sig(mech)) {
        rv = grab(key, CKA_MODULUS, a0, sizeof(a0), &l0);
        if (rv == CKR_OK)
            rv = grab(key, CKA_PRIVATE_EXPONENT, a1, sizeof(a1), &l1);
        predicted = l0;
        opcode = NCMP_CMD_RSA_SIGN;
    } else if (is_ec_sig(mech)) {
        rv = grab(key, CKA_EC_PARAMS, a0, sizeof(a0), &l0);
        if (rv == CKR_OK)
            rv = grab(key, CKA_VALUE, a1, sizeof(a1), &l1);
        predicted = 2u * l1;
        opcode = NCMP_CMD_EC_SIGN;
    } else {
        rv = grab(key, CKA_VALUE, a1, sizeof(a1), &l1);
        l0 = 4;
        ncmp_wr_u32le(a0, (uint32_t)mech);
        predicted = hmac_size(mech);
        opcode = NCMP_CMD_HMAC_SIGN;
    }
    if (rv != CKR_OK) {
        p11_unlock();
        return rv;
    }
    p11_unlock();

    if (!out) {
        *poutlen = predicted;
        return CKR_OK;
    }
    if ((CK_ULONG)predicted > *poutlen) {
        *poutlen = predicted;
        return CKR_BUFFER_TOO_SMALL;
    }

    if (opcode == NCMP_CMD_HMAC_SIGN) {
        parts[0] = a0;   lens[0] = l0;   /* mech */
        parts[1] = a1;   lens[1] = l1;   /* key */
        parts[2] = data; lens[2] = datalen;
    } else {
        parts[0] = a0;   lens[0] = l0;   /* modulus / ec_params */
        parts[1] = a1;   lens[1] = l1;   /* priv exp / scalar */
        parts[2] = data; lens[2] = datalen;
    }
    memset(&rsp, 0, sizeof(rsp));
    rv = p11_forward_mp(slot, opcode, parts, lens, 3, sig, sizeof(sig), &rsp);
    if (rv == CKR_OK) {
        produced = rsp.param_len[0];
        if ((CK_ULONG)produced > *poutlen) {
            rv = CKR_BUFFER_TOO_SMALL;
        } else {
            memcpy(out, sig, produced);
            *poutlen = produced;
        }
    }
    if (rv != CKR_BUFFER_TOO_SMALL) {
        p11_lock();
        s = p11_session_get(hSession);
        if (s) {
            s->sig.kind = P11_OP_NONE;
            s->sig.buf_len = 0;
        }
        p11_unlock();
    }
    return rv;
}

/** Verify a signature/MAC over @p data (one-shot verify path). */
static CK_RV do_verify(CK_SESSION_HANDLE hSession, const uint8_t *data,
                       uint32_t datalen, const uint8_t *sig, uint32_t siglen)
{
    p11_session_t *s;
    CK_SLOT_ID slot;
    CK_MECHANISM_TYPE mech;
    CK_OBJECT_HANDLE key;
    uint8_t a0[KMAX], a1[KMAX];
    uint32_t l0 = 0, l1 = 0;
    const uint8_t *parts[4];
    uint32_t lens[4];
    NCMP_Message rsp;
    CK_RV rv;
    uint32_t opcode;

    p11_lock();
    s = p11_session_get(hSession);
    if (!s) {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (s->ver.kind != P11_OP_VERIFY) {
        p11_unlock();
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    slot = s->slot;
    mech = s->ver.mech;
    key = s->ver.key;

    if (is_rsa_sig(mech)) {
        rv = grab(key, CKA_MODULUS, a0, sizeof(a0), &l0);
        if (rv == CKR_OK)
            rv = grab(key, CKA_PUBLIC_EXPONENT, a1, sizeof(a1), &l1);
        opcode = NCMP_CMD_RSA_VERIFY;
    } else if (is_ec_sig(mech)) {
        rv = grab(key, CKA_EC_PARAMS, a0, sizeof(a0), &l0);
        if (rv == CKR_OK)
            rv = grab(key, CKA_EC_POINT, a1, sizeof(a1), &l1);
        opcode = NCMP_CMD_EC_VERIFY;
    } else {
        rv = grab(key, CKA_VALUE, a1, sizeof(a1), &l1);
        l0 = 4;
        ncmp_wr_u32le(a0, (uint32_t)mech);
        opcode = NCMP_CMD_HMAC_VERIFY;
    }
    if (rv != CKR_OK) {
        p11_unlock();
        return rv;
    }
    p11_unlock();

    parts[0] = a0;   lens[0] = l0;
    parts[1] = a1;   lens[1] = l1;
    parts[2] = data; lens[2] = datalen;
    parts[3] = sig;  lens[3] = siglen;
    memset(&rsp, 0, sizeof(rsp));
    rv = p11_forward_mp(slot, opcode, parts, lens, 4, NULL, 0, &rsp);

    p11_lock();
    s = p11_session_get(hSession);
    if (s) {
        s->ver.kind = P11_OP_NONE;
        s->ver.buf_len = 0;
    }
    p11_unlock();
    return rv;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
             CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    if (!pulSignatureLen)
        return CKR_ARGUMENTS_BAD;
    return do_sign(hSession, pData, (uint32_t)ulDataLen, pSignature,
                   pulSignatureLen);
}

CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
               CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    return do_verify(hSession, pData, (uint32_t)ulDataLen, pSignature,
                     (uint32_t)ulSignatureLen);
}

/** Sign/verify *Update: buffer the message parts. */
static CK_RV sv_update(CK_SESSION_HANDLE hSession, p11_op_kind_t kind,
                       CK_BYTE_PTR part, CK_ULONG len)
{
    p11_session_t *s;
    p11_opctx_t *c;
    CK_RV rv;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    p11_lock();
    s = p11_session_get(hSession);
    if (!s) {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    c = (kind == P11_OP_SIGN) ? &s->sig : &s->ver;
    if (c->kind != kind) {
        p11_unlock();
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    rv = opctx_append(c, part, (uint32_t)len);
    p11_unlock();
    return rv;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                   CK_ULONG ulPartLen)
{
    return sv_update(hSession, P11_OP_SIGN, pPart, ulPartLen);
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                     CK_ULONG ulPartLen)
{
    return sv_update(hSession, P11_OP_VERIFY, pPart, ulPartLen);
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
                  CK_ULONG_PTR pulSignatureLen)
{
    p11_session_t *s;
    uint8_t *buf = NULL;
    uint32_t len = 0;
    CK_RV rv;

    if (!pulSignatureLen)
        return CKR_ARGUMENTS_BAD;
    p11_lock();
    s = p11_session_get(hSession);
    if (!s) {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (s->sig.kind != P11_OP_SIGN) {
        p11_unlock();
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    len = s->sig.buf_len;
    if (len) {
        buf = (uint8_t *)malloc(len);
        if (!buf) {
            p11_unlock();
            return CKR_DEVICE_MEMORY;
        }
        memcpy(buf, s->sig.buf, len);
    }
    p11_unlock();
    rv = do_sign(hSession, buf, len, pSignature, pulSignatureLen);
    free(buf);
    return rv;
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
                    CK_ULONG ulSignatureLen)
{
    p11_session_t *s;
    uint8_t *buf = NULL;
    uint32_t len = 0;
    CK_RV rv;

    p11_lock();
    s = p11_session_get(hSession);
    if (!s) {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (s->ver.kind != P11_OP_VERIFY) {
        p11_unlock();
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    len = s->ver.buf_len;
    if (len) {
        buf = (uint8_t *)malloc(len);
        if (!buf) {
            p11_unlock();
            return CKR_DEVICE_MEMORY;
        }
        memcpy(buf, s->ver.buf, len);
    }
    p11_unlock();
    rv = do_verify(hSession, buf, len, pSignature, (uint32_t)ulSignatureLen);
    free(buf);
    return rv;
}

CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                        CK_OBJECT_HANDLE hKey)
{
    (void)pMechanism;
    (void)hKey;
    if (!p11_session_get(hSession))
        return CKR_SESSION_HANDLE_INVALID;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                    CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
                    CK_ULONG_PTR pulSignatureLen)
{
    (void)pData;
    (void)ulDataLen;
    (void)pSignature;
    (void)pulSignatureLen;
    if (!p11_session_get(hSession))
        return CKR_SESSION_HANDLE_INVALID;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession,
                          CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    (void)pMechanism;
    (void)hKey;
    if (!p11_session_get(hSession))
        return CKR_SESSION_HANDLE_INVALID;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
                      CK_ULONG ulSignatureLen, CK_BYTE_PTR pData,
                      CK_ULONG_PTR pulDataLen)
{
    (void)pSignature;
    (void)ulSignatureLen;
    (void)pData;
    (void)pulDataLen;
    if (!p11_session_get(hSession))
        return CKR_SESSION_HANDLE_INVALID;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* ------------------------------------------------------------------------- */
/* Dual-function operations                                                  */
/* ------------------------------------------------------------------------- */

CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                            CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                            CK_ULONG_PTR pulEncryptedPartLen)
{
    CK_RV rv = C_DigestUpdate(hSession, pPart, ulPartLen);

    if (rv != CKR_OK)
        return rv;
    return C_EncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart,
                           pulEncryptedPartLen);
}

CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession,
                            CK_BYTE_PTR pEncryptedPart,
                            CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
                            CK_ULONG_PTR pulPartLen)
{
    CK_RV rv = C_DecryptUpdate(hSession, pEncryptedPart, ulEncryptedPartLen,
                               pPart, pulPartLen);

    if (rv != CKR_OK)
        return rv;
    /* Digest the recovered plaintext part. */
    if (pPart && pulPartLen && *pulPartLen)
        return C_DigestUpdate(hSession, pPart, *pulPartLen);
    return CKR_OK;
}

CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                          CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                          CK_ULONG_PTR pulEncryptedPartLen)
{
    CK_RV rv = C_SignUpdate(hSession, pPart, ulPartLen);

    if (rv != CKR_OK)
        return rv;
    return C_EncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart,
                           pulEncryptedPartLen);
}

CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession,
                            CK_BYTE_PTR pEncryptedPart,
                            CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
                            CK_ULONG_PTR pulPartLen)
{
    CK_RV rv = C_DecryptUpdate(hSession, pEncryptedPart, ulEncryptedPartLen,
                               pPart, pulPartLen);

    if (rv != CKR_OK)
        return rv;
    if (pPart && pulPartLen && *pulPartLen)
        return C_VerifyUpdate(hSession, pPart, *pulPartLen);
    return CKR_OK;
}

/* ------------------------------------------------------------------------- */
/* Message-based operations (v3.0). Single-shot forms are implemented; the    */
/* streaming Begin/Next forms are declined (CKR_FUNCTION_NOT_SUPPORTED).       */
/* ------------------------------------------------------------------------- */

CK_RV C_MessageEncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMech,
                           CK_OBJECT_HANDLE hKey)
{
    /* Defer parameter capture to EncryptMessage (per-message GCM params). */
    p11_session_t *s;
    CK_RV rv;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!pMech)
        return CKR_ARGUMENTS_BAD;
    p11_lock();
    s = p11_session_get(hSession);
    if (!s) { p11_unlock(); return CKR_SESSION_HANDLE_INVALID; }
    if (s->enc.kind != P11_OP_NONE) { p11_unlock(); return CKR_OPERATION_ACTIVE; }
    rv = check_perm(hKey, CKA_ENCRYPT);
    if (rv != CKR_OK) { p11_unlock(); return rv; }
    s->enc.kind = P11_OP_ENCRYPT;
    s->enc.mech = pMech->mechanism;
    s->enc.key = hKey;
    s->enc.message = 1;
    p11_unlock();
    return CKR_OK;
}

/** Shared message enc/dec: GCM one-shot with per-call params. */
static CK_RV message_cipher(CK_SESSION_HANDLE hSession, int enc,
                            void *pParameter, CK_ULONG ulParameterLen,
                            CK_BYTE *pAad, CK_ULONG ulAadLen, CK_BYTE *pIn,
                            CK_ULONG ulInLen, CK_BYTE *pOut, CK_ULONG *pulOutLen)
{
    p11_session_t *s;
    p11_opctx_t *c;
    CK_SLOT_ID slot;
    CK_MECHANISM_TYPE mech;
    CK_OBJECT_HANDLE key;
    CK_GCM_PARAMS *g = (CK_GCM_PARAMS *)pParameter;
    uint8_t kbuf[KMAX], iv[16], aad[512], *work;
    uint32_t klen = 0, ivlen, aadlen, taglen, predicted, produced = 0, workcap;
    CK_RV rv;

    if (!pulOutLen || !g || ulParameterLen < sizeof(CK_GCM_PARAMS))
        return CKR_ARGUMENTS_BAD;

    p11_lock();
    s = p11_session_get(hSession);
    if (!s) { p11_unlock(); return CKR_SESSION_HANDLE_INVALID; }
    c = enc ? &s->enc : &s->dec;
    if (c->kind == P11_OP_NONE || !c->message) {
        p11_unlock();
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if (c->mech != CKM_AES_GCM) {
        p11_unlock();
        return CKR_MECHANISM_INVALID;
    }
    slot = s->slot;
    mech = c->mech;
    key = c->key;
    if (g->ulIvLen == 0 || g->ulIvLen > sizeof(iv)) {
        p11_unlock();
        return CKR_MECHANISM_PARAM_INVALID;
    }
    ivlen = (uint32_t)g->ulIvLen;
    memcpy(iv, g->pIv, ivlen);
    aadlen = (uint32_t)(pAad ? ulAadLen : g->ulAADLen);
    if (aadlen > sizeof(aad)) { p11_unlock(); return CKR_MECHANISM_PARAM_INVALID; }
    if (aadlen)
        memcpy(aad, pAad ? pAad : g->pAAD, aadlen);
    taglen = (uint32_t)(g->ulTagBits / 8);
    if (taglen == 0 || taglen > 16) { p11_unlock(); return CKR_MECHANISM_PARAM_INVALID; }
    rv = grab(key, CKA_VALUE, kbuf, sizeof(kbuf), &klen);
    p11_unlock();
    if (rv != CKR_OK)
        return rv;

    predicted = enc ? (uint32_t)ulInLen + taglen
                    : (ulInLen >= taglen ? (uint32_t)ulInLen - taglen : 0);
    if (!pOut) {
        *pulOutLen = predicted;
        return CKR_OK;
    }
    if ((CK_ULONG)predicted > *pulOutLen) {
        *pulOutLen = predicted;
        return CKR_BUFFER_TOO_SMALL;
    }
    workcap = predicted + 32;
    work = (uint8_t *)malloc(workcap);
    if (!work)
        return CKR_DEVICE_MEMORY;
    rv = aes_core(slot, mech, enc, kbuf, klen, iv, ivlen, aad, aadlen, taglen,
                  pIn, (uint32_t)ulInLen, work, workcap, &produced);
    if (rv == CKR_OK) {
        memcpy(pOut, work, produced);
        *pulOutLen = produced;
    }
    free(work);
    return rv;
}

CK_RV C_EncryptMessage(CK_SESSION_HANDLE hSession, void *pParameter,
                       CK_ULONG ulParameterLen, CK_BYTE *pAssociatedData,
                       CK_ULONG ulAssociatedDataLen, CK_BYTE *pPlaintext,
                       CK_ULONG ulPlaintextLen, CK_BYTE *pCiphertext,
                       CK_ULONG *pulCiphertextLen)
{
    return message_cipher(hSession, 1, pParameter, ulParameterLen,
                          pAssociatedData, ulAssociatedDataLen, pPlaintext,
                          ulPlaintextLen, pCiphertext, pulCiphertextLen);
}

CK_RV C_MessageEncryptFinal(CK_SESSION_HANDLE hSession)
{
    p11_session_t *s;

    p11_lock();
    s = p11_session_get(hSession);
    if (s)
        s->enc.kind = P11_OP_NONE;
    p11_unlock();
    return s ? CKR_OK : CKR_SESSION_HANDLE_INVALID;
}

CK_RV C_MessageDecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMech,
                           CK_OBJECT_HANDLE hKey)
{
    p11_session_t *s;
    CK_RV rv;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!pMech)
        return CKR_ARGUMENTS_BAD;
    p11_lock();
    s = p11_session_get(hSession);
    if (!s) { p11_unlock(); return CKR_SESSION_HANDLE_INVALID; }
    if (s->dec.kind != P11_OP_NONE) { p11_unlock(); return CKR_OPERATION_ACTIVE; }
    rv = check_perm(hKey, CKA_DECRYPT);
    if (rv != CKR_OK) { p11_unlock(); return rv; }
    s->dec.kind = P11_OP_DECRYPT;
    s->dec.mech = pMech->mechanism;
    s->dec.key = hKey;
    s->dec.message = 1;
    p11_unlock();
    return CKR_OK;
}

CK_RV C_DecryptMessage(CK_SESSION_HANDLE hSession, void *pParameter,
                       CK_ULONG ulParameterLen, CK_BYTE *pAssociatedData,
                       CK_ULONG ulAssociatedDataLen, CK_BYTE *pCiphertext,
                       CK_ULONG ulCiphertextLen, CK_BYTE *pPlaintext,
                       CK_ULONG *pulPlaintextLen)
{
    return message_cipher(hSession, 0, pParameter, ulParameterLen,
                          pAssociatedData, ulAssociatedDataLen, pCiphertext,
                          ulCiphertextLen, pPlaintext, pulPlaintextLen);
}

CK_RV C_MessageDecryptFinal(CK_SESSION_HANDLE hSession)
{
    p11_session_t *s;

    p11_lock();
    s = p11_session_get(hSession);
    if (s)
        s->dec.kind = P11_OP_NONE;
    p11_unlock();
    return s ? CKR_OK : CKR_SESSION_HANDLE_INVALID;
}

CK_RV C_MessageSignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMech,
                        CK_OBJECT_HANDLE hKey)
{
    return sv_init(hSession, pMech, hKey, P11_OP_SIGN, 1);
}

CK_RV C_SignMessage(CK_SESSION_HANDLE hSession, void *pParameter,
                    CK_ULONG ulParameterLen, CK_BYTE *pData, CK_ULONG ulDataLen,
                    CK_BYTE *pSignature, CK_ULONG *pulSignatureLen)
{
    (void)pParameter;
    (void)ulParameterLen;
    return do_sign(hSession, pData, (uint32_t)ulDataLen, pSignature,
                   pulSignatureLen);
}

CK_RV C_MessageSignFinal(CK_SESSION_HANDLE hSession)
{
    p11_session_t *s;

    p11_lock();
    s = p11_session_get(hSession);
    if (s)
        s->sig.kind = P11_OP_NONE;
    p11_unlock();
    return s ? CKR_OK : CKR_SESSION_HANDLE_INVALID;
}

CK_RV C_MessageVerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMech,
                          CK_OBJECT_HANDLE hKey)
{
    return sv_init(hSession, pMech, hKey, P11_OP_VERIFY, 1);
}

CK_RV C_VerifyMessage(CK_SESSION_HANDLE hSession, void *pParameter,
                      CK_ULONG ulParameterLen, CK_BYTE *pData,
                      CK_ULONG ulDataLen, CK_BYTE *pSignature,
                      CK_ULONG ulSignatureLen)
{
    (void)pParameter;
    (void)ulParameterLen;
    return do_verify(hSession, pData, (uint32_t)ulDataLen, pSignature,
                     (uint32_t)ulSignatureLen);
}

CK_RV C_MessageVerifyFinal(CK_SESSION_HANDLE hSession)
{
    p11_session_t *s;

    p11_lock();
    s = p11_session_get(hSession);
    if (s)
        s->ver.kind = P11_OP_NONE;
    p11_unlock();
    return s ? CKR_OK : CKR_SESSION_HANDLE_INVALID;
}

/* Streaming message forms are not supported by the mock datapath. */
CK_RV C_EncryptMessageBegin(CK_SESSION_HANDLE h, void *p, CK_ULONG pl,
                            CK_BYTE *a, CK_ULONG al)
{ (void)h;(void)p;(void)pl;(void)a;(void)al; return CKR_FUNCTION_NOT_SUPPORTED; }
CK_RV C_EncryptMessageNext(CK_SESSION_HANDLE h, void *p, CK_ULONG pl,
                           CK_BYTE *pt, CK_ULONG ptl, CK_BYTE *ct,
                           CK_ULONG *ctl, CK_ULONG f)
{ (void)h;(void)p;(void)pl;(void)pt;(void)ptl;(void)ct;(void)ctl;(void)f;
  return CKR_FUNCTION_NOT_SUPPORTED; }
CK_RV C_DecryptMessageBegin(CK_SESSION_HANDLE h, void *p, CK_ULONG pl,
                            CK_BYTE *a, CK_ULONG al)
{ (void)h;(void)p;(void)pl;(void)a;(void)al; return CKR_FUNCTION_NOT_SUPPORTED; }
CK_RV C_DecryptMessageNext(CK_SESSION_HANDLE h, void *p, CK_ULONG pl,
                           CK_BYTE *ct, CK_ULONG ctl, CK_BYTE *pt,
                           CK_ULONG *ptl, CK_FLAGS f)
{ (void)h;(void)p;(void)pl;(void)ct;(void)ctl;(void)pt;(void)ptl;(void)f;
  return CKR_FUNCTION_NOT_SUPPORTED; }
CK_RV C_SignMessageBegin(CK_SESSION_HANDLE h, void *p, CK_ULONG pl)
{ (void)h;(void)p;(void)pl; return CKR_FUNCTION_NOT_SUPPORTED; }
CK_RV C_SignMessageNext(CK_SESSION_HANDLE h, void *p, CK_ULONG pl, CK_BYTE *d,
                        CK_ULONG dl, CK_BYTE *sig, CK_ULONG *sigl)
{ (void)h;(void)p;(void)pl;(void)d;(void)dl;(void)sig;(void)sigl;
  return CKR_FUNCTION_NOT_SUPPORTED; }
CK_RV C_VerifyMessageBegin(CK_SESSION_HANDLE h, void *p, CK_ULONG pl)
{ (void)h;(void)p;(void)pl; return CKR_FUNCTION_NOT_SUPPORTED; }
CK_RV C_VerifyMessageNext(CK_SESSION_HANDLE h, void *p, CK_ULONG pl, CK_BYTE *d,
                          CK_ULONG dl, CK_BYTE *sig, CK_ULONG sigl)
{ (void)h;(void)p;(void)pl;(void)d;(void)dl;(void)sig;(void)sigl;
  return CKR_FUNCTION_NOT_SUPPORTED; }

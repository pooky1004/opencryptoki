/*
 * Token NCMP - PKCS#11 key management, RNG, parallel + v3.2 stubs.
 */
#include "p11_provider.h"

#include "ncmp/ncmp_cmd.h"
#include "ncmp/ncmp_wire.h"

#include <stdlib.h>
#include <string.h>

#define KMAX 1024u

/** Draw @p n random bytes from the token behind @p slot. */
static CK_RV gen_random(CK_SLOT_ID slot, uint8_t *out, uint32_t n)
{
    uint8_t lenbuf[4];
    uint32_t got = 0;
    CK_RV rv;

    ncmp_wr_u32le(lenbuf, n);
    rv = p11_forward(slot, NCMP_CMD_RNG, lenbuf, 4, out, n, &got);
    if (rv != CKR_OK)
        return rv;
    if (got != n)
        return CKR_DEVICE_ERROR;
    return CKR_OK;
}

/** Default secret-key length (bytes) for a key-gen mechanism. */
static CK_ULONG default_keylen(CK_MECHANISM_TYPE m)
{
    switch (m) {
    case CKM_AES_KEY_GEN:  return 32;
    case CKM_DES3_KEY_GEN: return 24;
    default:               return 0; /* generic-secret: caller must specify */
    }
}

/** CKK_* key type for a key-gen mechanism. */
static CK_KEY_TYPE keytype_for(CK_MECHANISM_TYPE m)
{
    switch (m) {
    case CKM_AES_KEY_GEN:  return CKK_AES;
    case CKM_DES3_KEY_GEN: return CKK_DES3;
    default:               return CKK_GENERIC_SECRET;
    }
}

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                    CK_OBJECT_HANDLE_PTR phKey)
{
    p11_session_t *s;
    p11_object_t *o;
    CK_SLOT_ID slot;
    CK_ULONG keylen = 0;
    CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
    CK_KEY_TYPE kt;
    uint8_t keybuf[64];
    CK_ULONG i;
    CK_RV rv;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!pMechanism || !phKey)
        return CKR_ARGUMENTS_BAD;

    /* Determine requested key length. */
    for (i = 0; i < ulCount; ++i) {
        if (pTemplate[i].type == CKA_VALUE_LEN &&
            pTemplate[i].ulValueLen == sizeof(CK_ULONG))
            keylen = *(CK_ULONG *)pTemplate[i].pValue;
    }
    if (keylen == 0)
        keylen = default_keylen(pMechanism->mechanism);
    if (keylen == 0 || keylen > sizeof(keybuf))
        return CKR_TEMPLATE_INCOMPLETE;
    kt = keytype_for(pMechanism->mechanism);

    p11_lock();
    s = p11_session_get(hSession);
    if (!s) {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    slot = s->slot;
    p11_unlock();

    rv = gen_random(slot, keybuf, (uint32_t)keylen);
    if (rv != CKR_OK)
        return rv;

    p11_lock();
    s = p11_session_get(hSession);
    if (!s) {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    o = p11_object_alloc();
    if (!o) {
        p11_unlock();
        return CKR_DEVICE_MEMORY;
    }
    rv = p11_obj_from_template(o, pTemplate, ulCount);
    if (rv == CKR_OK)
        rv = p11_obj_set(o, CKA_CLASS, &cls, sizeof(cls));
    if (rv == CKR_OK)
        rv = p11_obj_set(o, CKA_KEY_TYPE, &kt, sizeof(kt));
    if (rv == CKR_OK)
        rv = p11_obj_set(o, CKA_VALUE, keybuf, keylen);
    if (rv != CKR_OK) {
        p11_object_free(o);
        p11_unlock();
        return rv;
    }
    o->slot = s->slot;
    o->session = o->is_token ? CK_INVALID_HANDLE : s->handle;
    *phKey = o->handle;
    p11_unlock();
    return CKR_OK;
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                        CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                        CK_ULONG ulPublicKeyAttributeCount,
                        CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                        CK_ULONG ulPrivateKeyAttributeCount,
                        CK_OBJECT_HANDLE_PTR phPublicKey,
                        CK_OBJECT_HANDLE_PTR phPrivateKey)
{
    p11_session_t *s;
    p11_object_t *pub, *priv;
    CK_SLOT_ID slot;
    CK_MECHANISM_TYPE mech;
    CK_KEY_TYPE kt;
    CK_OBJECT_CLASS pub_cls = CKO_PUBLIC_KEY, priv_cls = CKO_PRIVATE_KEY;
    NCMP_Message rsp;
    uint8_t out[8192]; /* per-call: RSA-4096 keygen response fits with margin */
    CK_RV rv;
    CK_ULONG i;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!pMechanism || !phPublicKey || !phPrivateKey)
        return CKR_ARGUMENTS_BAD;
    mech = pMechanism->mechanism;

    p11_lock();
    s = p11_session_get(hSession);
    if (!s) {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    slot = s->slot;
    p11_unlock();

    if (mech == CKM_RSA_PKCS_KEY_PAIR_GEN) {
        CK_ULONG modbits = 2048;
        uint8_t pubexp[8] = { 0x01, 0x00, 0x01 };
        uint32_t pubexp_len = 3;
        uint8_t bits[4];
        const uint8_t *parts[2];
        uint32_t lens[2];

        for (i = 0; i < ulPublicKeyAttributeCount; ++i) {
            if (pPublicKeyTemplate[i].type == CKA_MODULUS_BITS &&
                pPublicKeyTemplate[i].ulValueLen == sizeof(CK_ULONG))
                modbits = *(CK_ULONG *)pPublicKeyTemplate[i].pValue;
            else if (pPublicKeyTemplate[i].type == CKA_PUBLIC_EXPONENT &&
                     pPublicKeyTemplate[i].ulValueLen <= sizeof(pubexp)) {
                memcpy(pubexp, pPublicKeyTemplate[i].pValue,
                       pPublicKeyTemplate[i].ulValueLen);
                pubexp_len = (uint32_t)pPublicKeyTemplate[i].ulValueLen;
            }
        }
        ncmp_wr_u32le(bits, (uint32_t)modbits);
        parts[0] = bits;   lens[0] = 4;
        parts[1] = pubexp; lens[1] = pubexp_len;
        memset(&rsp, 0, sizeof(rsp));
        rv = p11_forward_mp(slot, NCMP_CMD_RSA_KEYGEN, parts, lens, 2, out,
                            sizeof(out), &rsp);
        if (rv != CKR_OK)
            return rv;

        p11_lock();
        s = p11_session_get(hSession);
        if (!s) { p11_unlock(); return CKR_SESSION_HANDLE_INVALID; }
        pub = p11_object_alloc();
        priv = pub ? p11_object_alloc() : NULL;
        if (!pub || !priv) {
            if (pub) p11_object_free(pub);
            p11_unlock();
            return CKR_DEVICE_MEMORY;
        }
        kt = CKK_RSA;
        rv = p11_obj_from_template(pub, pPublicKeyTemplate,
                                   ulPublicKeyAttributeCount);
        {
            const uint8_t *n, *d, *p, *q, *dp, *dq, *qinv;
            uint32_t ln, ld, lp, lq, ldp, ldq, lqi;

            ncmp_msg_param(&rsp, 0, &n, &ln);
            ncmp_msg_param(&rsp, 1, &d, &ld);
            ncmp_msg_param(&rsp, 2, &p, &lp);
            ncmp_msg_param(&rsp, 3, &q, &lq);
            ncmp_msg_param(&rsp, 4, &dp, &ldp);
            ncmp_msg_param(&rsp, 5, &dq, &ldq);
            ncmp_msg_param(&rsp, 6, &qinv, &lqi);

            if (rv == CKR_OK) rv = p11_obj_set(pub, CKA_CLASS, &pub_cls, sizeof(pub_cls));
            if (rv == CKR_OK) rv = p11_obj_set(pub, CKA_KEY_TYPE, &kt, sizeof(kt));
            if (rv == CKR_OK) rv = p11_obj_set(pub, CKA_MODULUS, n, ln);
            if (rv == CKR_OK) rv = p11_obj_set(pub, CKA_PUBLIC_EXPONENT, pubexp, pubexp_len);

            if (rv == CKR_OK) rv = p11_obj_from_template(priv, pPrivateKeyTemplate,
                                                         ulPrivateKeyAttributeCount);
            if (rv == CKR_OK) rv = p11_obj_set(priv, CKA_CLASS, &priv_cls, sizeof(priv_cls));
            if (rv == CKR_OK) rv = p11_obj_set(priv, CKA_KEY_TYPE, &kt, sizeof(kt));
            if (rv == CKR_OK) rv = p11_obj_set(priv, CKA_MODULUS, n, ln);
            if (rv == CKR_OK) rv = p11_obj_set(priv, CKA_PUBLIC_EXPONENT, pubexp, pubexp_len);
            if (rv == CKR_OK) rv = p11_obj_set(priv, CKA_PRIVATE_EXPONENT, d, ld);
            if (rv == CKR_OK) rv = p11_obj_set(priv, CKA_PRIME_1, p, lp);
            if (rv == CKR_OK) rv = p11_obj_set(priv, CKA_PRIME_2, q, lq);
            if (rv == CKR_OK) rv = p11_obj_set(priv, CKA_EXPONENT_1, dp, ldp);
            if (rv == CKR_OK) rv = p11_obj_set(priv, CKA_EXPONENT_2, dq, ldq);
            if (rv == CKR_OK) rv = p11_obj_set(priv, CKA_COEFFICIENT, qinv, lqi);
        }
        if (rv != CKR_OK) {
            p11_object_free(pub);
            p11_object_free(priv);
            p11_unlock();
            return rv;
        }
        pub->slot = priv->slot = s->slot;
        pub->session = pub->is_token ? CK_INVALID_HANDLE : s->handle;
        priv->session = priv->is_token ? CK_INVALID_HANDLE : s->handle;
        *phPublicKey = pub->handle;
        *phPrivateKey = priv->handle;
        p11_unlock();
        return CKR_OK;
    }

    if (mech == CKM_EC_KEY_PAIR_GEN) {
        uint8_t ecp[256];
        uint32_t ecp_len = 0;
        const uint8_t *parts[1];
        uint32_t lens[1];

        /* CKA_EC_PARAMS may live on either template. */
        for (i = 0; i < ulPublicKeyAttributeCount; ++i)
            if (pPublicKeyTemplate[i].type == CKA_EC_PARAMS &&
                pPublicKeyTemplate[i].ulValueLen <= sizeof(ecp)) {
                memcpy(ecp, pPublicKeyTemplate[i].pValue,
                       pPublicKeyTemplate[i].ulValueLen);
                ecp_len = (uint32_t)pPublicKeyTemplate[i].ulValueLen;
            }
        for (i = 0; ecp_len == 0 && i < ulPrivateKeyAttributeCount; ++i)
            if (pPrivateKeyTemplate[i].type == CKA_EC_PARAMS &&
                pPrivateKeyTemplate[i].ulValueLen <= sizeof(ecp)) {
                memcpy(ecp, pPrivateKeyTemplate[i].pValue,
                       pPrivateKeyTemplate[i].ulValueLen);
                ecp_len = (uint32_t)pPrivateKeyTemplate[i].ulValueLen;
            }
        if (ecp_len == 0)
            return CKR_TEMPLATE_INCOMPLETE;

        parts[0] = ecp; lens[0] = ecp_len;
        memset(&rsp, 0, sizeof(rsp));
        rv = p11_forward_mp(slot, NCMP_CMD_EC_KEYGEN, parts, lens, 1, out,
                            sizeof(out), &rsp);
        if (rv != CKR_OK)
            return rv;

        p11_lock();
        s = p11_session_get(hSession);
        if (!s) { p11_unlock(); return CKR_SESSION_HANDLE_INVALID; }
        pub = p11_object_alloc();
        priv = pub ? p11_object_alloc() : NULL;
        if (!pub || !priv) {
            if (pub) p11_object_free(pub);
            p11_unlock();
            return CKR_DEVICE_MEMORY;
        }
        kt = CKK_EC;
        {
            const uint8_t *point, *pv;
            uint32_t lpoint, lpv;

            ncmp_msg_param(&rsp, 0, &point, &lpoint);
            ncmp_msg_param(&rsp, 1, &pv, &lpv);

            rv = p11_obj_from_template(pub, pPublicKeyTemplate,
                                       ulPublicKeyAttributeCount);
            if (rv == CKR_OK) rv = p11_obj_set(pub, CKA_CLASS, &pub_cls, sizeof(pub_cls));
            if (rv == CKR_OK) rv = p11_obj_set(pub, CKA_KEY_TYPE, &kt, sizeof(kt));
            if (rv == CKR_OK) rv = p11_obj_set(pub, CKA_EC_PARAMS, ecp, ecp_len);
            if (rv == CKR_OK) rv = p11_obj_set(pub, CKA_EC_POINT, point, lpoint);

            if (rv == CKR_OK) rv = p11_obj_from_template(priv, pPrivateKeyTemplate,
                                                         ulPrivateKeyAttributeCount);
            if (rv == CKR_OK) rv = p11_obj_set(priv, CKA_CLASS, &priv_cls, sizeof(priv_cls));
            if (rv == CKR_OK) rv = p11_obj_set(priv, CKA_KEY_TYPE, &kt, sizeof(kt));
            if (rv == CKR_OK) rv = p11_obj_set(priv, CKA_EC_PARAMS, ecp, ecp_len);
            if (rv == CKR_OK) rv = p11_obj_set(priv, CKA_VALUE, pv, lpv);
        }
        if (rv != CKR_OK) {
            p11_object_free(pub);
            p11_object_free(priv);
            p11_unlock();
            return rv;
        }
        pub->slot = priv->slot = s->slot;
        pub->session = pub->is_token ? CK_INVALID_HANDLE : s->handle;
        priv->session = priv->is_token ? CK_INVALID_HANDLE : s->handle;
        *phPublicKey = pub->handle;
        *phPrivateKey = priv->handle;
        p11_unlock();
        return CKR_OK;
    }

    return CKR_MECHANISM_INVALID;
}

CK_RV C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,
                CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
    p11_session_t *s;
    CK_SLOT_ID slot;
    uint8_t mod[KMAX], exp[KMAX], target[KMAX], wrapbuf[KMAX];
    uint32_t modlen = 0, explen = 0, tlen = 0, wlen = 0;
    const uint8_t *parts[3];
    uint32_t lens[3];
    NCMP_Message rsp;
    CK_RV rv;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!pMechanism || !pulWrappedKeyLen)
        return CKR_ARGUMENTS_BAD;
    if (pMechanism->mechanism != CKM_RSA_PKCS_OAEP &&
        pMechanism->mechanism != CKM_RSA_PKCS)
        return CKR_MECHANISM_INVALID;

    p11_lock();
    s = p11_session_get(hSession);
    if (!s) { p11_unlock(); return CKR_SESSION_HANDLE_INVALID; }
    slot = s->slot;
    {
        p11_object_t *wk = p11_object_get(hWrappingKey);
        p11_object_t *tk = p11_object_get(hKey);
        p11_attr_t *a;

        if (!wk) { p11_unlock(); return CKR_WRAPPING_KEY_HANDLE_INVALID; }
        if (!tk) { p11_unlock(); return CKR_KEY_HANDLE_INVALID; }
        if (!p11_obj_bool(wk, CKA_WRAP, CK_TRUE)) {
            p11_unlock();
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
        }
        if (!p11_obj_bool(tk, CKA_EXTRACTABLE, CK_TRUE)) {
            p11_unlock();
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
        }
        a = p11_obj_attr(wk, CKA_MODULUS);
        if (!a) { p11_unlock(); return CKR_WRAPPING_KEY_HANDLE_INVALID; }
        modlen = (uint32_t)a->len; memcpy(mod, a->val, modlen);
        a = p11_obj_attr(wk, CKA_PUBLIC_EXPONENT);
        if (!a) { p11_unlock(); return CKR_WRAPPING_KEY_HANDLE_INVALID; }
        explen = (uint32_t)a->len; memcpy(exp, a->val, explen);
        a = p11_obj_attr(tk, CKA_VALUE);
        if (!a) { p11_unlock(); return CKR_KEY_INDIGESTIBLE; }
        tlen = (uint32_t)a->len; memcpy(target, a->val, tlen);
    }
    p11_unlock();

    if (!pWrappedKey) {
        *pulWrappedKeyLen = modlen;
        return CKR_OK;
    }
    if (*pulWrappedKeyLen < modlen) {
        *pulWrappedKeyLen = modlen;
        return CKR_BUFFER_TOO_SMALL;
    }

    parts[0] = mod;    lens[0] = modlen;
    parts[1] = exp;    lens[1] = explen;
    parts[2] = target; lens[2] = tlen;
    memset(&rsp, 0, sizeof(rsp));
    rv = p11_forward_mp(slot, NCMP_CMD_RSA_OAEP_ENC, parts, lens, 3, wrapbuf,
                        sizeof(wrapbuf), &rsp);
    if (rv != CKR_OK)
        return rv;
    wlen = rsp.param_len[0];
    memcpy(pWrappedKey, wrapbuf, wlen);
    *pulWrappedKeyLen = wlen;
    return CKR_OK;
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                  CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey,
                  CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate,
                  CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
    p11_session_t *s;
    p11_object_t *o;
    CK_SLOT_ID slot;
    uint8_t mod[KMAX], exp[KMAX], plain[KMAX];
    uint32_t modlen = 0, explen = 0, plen = 0;
    const uint8_t *parts[3];
    uint32_t lens[3];
    NCMP_Message rsp;
    CK_RV rv;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!pMechanism || !phKey || !pWrappedKey)
        return CKR_ARGUMENTS_BAD;
    if (pMechanism->mechanism != CKM_RSA_PKCS_OAEP &&
        pMechanism->mechanism != CKM_RSA_PKCS)
        return CKR_MECHANISM_INVALID;

    p11_lock();
    s = p11_session_get(hSession);
    if (!s) { p11_unlock(); return CKR_SESSION_HANDLE_INVALID; }
    slot = s->slot;
    {
        p11_object_t *uk = p11_object_get(hUnwrappingKey);
        p11_attr_t *a;

        if (!uk) { p11_unlock(); return CKR_UNWRAPPING_KEY_HANDLE_INVALID; }
        if (!p11_obj_bool(uk, CKA_UNWRAP, CK_TRUE)) {
            p11_unlock();
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
        }
        a = p11_obj_attr(uk, CKA_MODULUS);
        if (!a) { p11_unlock(); return CKR_UNWRAPPING_KEY_HANDLE_INVALID; }
        modlen = (uint32_t)a->len; memcpy(mod, a->val, modlen);
        a = p11_obj_attr(uk, CKA_PRIVATE_EXPONENT);
        if (!a) { p11_unlock(); return CKR_UNWRAPPING_KEY_HANDLE_INVALID; }
        explen = (uint32_t)a->len; memcpy(exp, a->val, explen);
    }
    p11_unlock();

    parts[0] = mod; lens[0] = modlen;
    parts[1] = exp; lens[1] = explen;
    parts[2] = pWrappedKey; lens[2] = (uint32_t)ulWrappedKeyLen;
    memset(&rsp, 0, sizeof(rsp));
    rv = p11_forward_mp(slot, NCMP_CMD_RSA_OAEP_DEC, parts, lens, 3, plain,
                        sizeof(plain), &rsp);
    if (rv != CKR_OK)
        return rv;
    plen = rsp.param_len[0];

    p11_lock();
    s = p11_session_get(hSession);
    if (!s) { p11_unlock(); return CKR_SESSION_HANDLE_INVALID; }
    o = p11_object_alloc();
    if (!o) { p11_unlock(); return CKR_DEVICE_MEMORY; }
    rv = p11_obj_from_template(o, pTemplate, ulAttributeCount);
    if (rv == CKR_OK)
        rv = p11_obj_set(o, CKA_VALUE, plain, plen);
    if (rv != CKR_OK) {
        p11_object_free(o);
        p11_unlock();
        return rv;
    }
    o->slot = s->slot;
    o->session = o->is_token ? CK_INVALID_HANDLE : s->handle;
    *phKey = o->handle;
    p11_unlock();
    return CKR_OK;
}

CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                  CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate,
                  CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
    p11_session_t *s;
    p11_object_t *o;
    CK_SLOT_ID slot;
    uint8_t dom[KMAX], priv[KMAX], peer[KMAX], secret[KMAX];
    uint32_t domlen = 0, privlen = 0, peerlen = 0, seclen = 0;
    const uint8_t *parts[3];
    uint32_t lens[3];
    NCMP_Message rsp;
    uint32_t opcode;
    CK_ULONG want = 0, i;
    CK_RV rv;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!pMechanism || !phKey)
        return CKR_ARGUMENTS_BAD;

    p11_lock();
    s = p11_session_get(hSession);
    if (!s) { p11_unlock(); return CKR_SESSION_HANDLE_INVALID; }
    slot = s->slot;
    {
        p11_object_t *bk = p11_object_get(hBaseKey);
        p11_attr_t *a;

        if (!bk) { p11_unlock(); return CKR_KEY_HANDLE_INVALID; }
        if (!p11_obj_bool(bk, CKA_DERIVE, CK_TRUE)) {
            p11_unlock();
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
        }
        if (pMechanism->mechanism == CKM_DH_PKCS_DERIVE) {
            opcode = NCMP_CMD_DH_DERIVE;
            a = p11_obj_attr(bk, CKA_PRIME);
            if (!a) { p11_unlock(); return CKR_KEY_TYPE_INCONSISTENT; }
            domlen = (uint32_t)a->len; memcpy(dom, a->val, domlen);
            a = p11_obj_attr(bk, CKA_VALUE);
            if (!a) { p11_unlock(); return CKR_KEY_TYPE_INCONSISTENT; }
            privlen = (uint32_t)a->len; memcpy(priv, a->val, privlen);
            if (!pMechanism->pParameter || pMechanism->ulParameterLen == 0) {
                p11_unlock();
                return CKR_MECHANISM_PARAM_INVALID;
            }
            peerlen = (uint32_t)pMechanism->ulParameterLen;
            if (peerlen > sizeof(peer)) peerlen = sizeof(peer);
            memcpy(peer, pMechanism->pParameter, peerlen);
        } else if (pMechanism->mechanism == CKM_ECDH1_DERIVE) {
            CK_ECDH1_DERIVE_PARAMS *ep =
                (CK_ECDH1_DERIVE_PARAMS *)pMechanism->pParameter;

            opcode = NCMP_CMD_ECDH_DERIVE;
            if (!ep || pMechanism->ulParameterLen < sizeof(*ep) ||
                !ep->pPublicData || ep->ulPublicDataLen == 0) {
                p11_unlock();
                return CKR_MECHANISM_PARAM_INVALID;
            }
            a = p11_obj_attr(bk, CKA_EC_PARAMS);
            if (!a) { p11_unlock(); return CKR_KEY_TYPE_INCONSISTENT; }
            domlen = (uint32_t)a->len; memcpy(dom, a->val, domlen);
            a = p11_obj_attr(bk, CKA_VALUE);
            if (!a) { p11_unlock(); return CKR_KEY_TYPE_INCONSISTENT; }
            privlen = (uint32_t)a->len; memcpy(priv, a->val, privlen);
            peerlen = (uint32_t)ep->ulPublicDataLen;
            if (peerlen > sizeof(peer)) peerlen = sizeof(peer);
            memcpy(peer, ep->pPublicData, peerlen);
        } else {
            p11_unlock();
            return CKR_MECHANISM_INVALID;
        }
    }
    p11_unlock();

    parts[0] = dom;  lens[0] = domlen;
    parts[1] = priv; lens[1] = privlen;
    parts[2] = peer; lens[2] = peerlen;
    memset(&rsp, 0, sizeof(rsp));
    rv = p11_forward_mp(slot, opcode, parts, lens, 3, secret, sizeof(secret),
                        &rsp);
    if (rv != CKR_OK)
        return rv;
    seclen = rsp.param_len[0];

    /* Truncate to the requested CKA_VALUE_LEN, if any. */
    for (i = 0; i < ulAttributeCount; ++i)
        if (pTemplate[i].type == CKA_VALUE_LEN &&
            pTemplate[i].ulValueLen == sizeof(CK_ULONG))
            want = *(CK_ULONG *)pTemplate[i].pValue;
    if (want > 0 && want < seclen)
        seclen = (uint32_t)want;

    p11_lock();
    s = p11_session_get(hSession);
    if (!s) { p11_unlock(); return CKR_SESSION_HANDLE_INVALID; }
    o = p11_object_alloc();
    if (!o) { p11_unlock(); return CKR_DEVICE_MEMORY; }
    rv = p11_obj_from_template(o, pTemplate, ulAttributeCount);
    {
        CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
        if (rv == CKR_OK) rv = p11_obj_set(o, CKA_CLASS, &cls, sizeof(cls));
        if (rv == CKR_OK) rv = p11_obj_set(o, CKA_VALUE, secret, seclen);
    }
    if (rv != CKR_OK) {
        p11_object_free(o);
        p11_unlock();
        return rv;
    }
    o->slot = s->slot;
    o->session = o->is_token ? CK_INVALID_HANDLE : s->handle;
    *phKey = o->handle;
    p11_unlock();
    return CKR_OK;
}

/* ------------------------------------------------------------------------- */
/* Random number generation                                                  */
/* ------------------------------------------------------------------------- */

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed,
                   CK_ULONG ulSeedLen)
{
    (void)pSeed;
    (void)ulSeedLen;
    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!p11_session_get(hSession))
        return CKR_SESSION_HANDLE_INVALID;
    /* The token has its own TRNG; external seeding is a no-op. */
    return CKR_OK;
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData,
                       CK_ULONG ulRandomLen)
{
    p11_session_t *s;
    CK_SLOT_ID slot;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!pRandomData && ulRandomLen)
        return CKR_ARGUMENTS_BAD;
    if (ulRandomLen == 0)
        return CKR_OK;
    if (ulRandomLen > NCMP_MAX_PARAM_SIZE)
        return CKR_DATA_LEN_RANGE;

    p11_lock();
    s = p11_session_get(hSession);
    if (!s) {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    slot = s->slot;
    p11_unlock();
    return gen_random(slot, pRandomData, (uint32_t)ulRandomLen);
}

/* ------------------------------------------------------------------------- */
/* Parallel function management (legacy)                                     */
/* ------------------------------------------------------------------------- */

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
    if (!p11_session_get(hSession))
        return CKR_SESSION_HANDLE_INVALID;
    return CKR_FUNCTION_NOT_PARALLEL;
}

CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession)
{
    if (!p11_session_get(hSession))
        return CKR_SESSION_HANDLE_INVALID;
    return CKR_FUNCTION_NOT_PARALLEL;
}

/* ------------------------------------------------------------------------- */
/* PKCS#11 v3.2 additions - declined by the mock datapath.                   */
/* ------------------------------------------------------------------------- */

CK_RV C_EncapsulateKey(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m,
                       CK_OBJECT_HANDLE pk, CK_ATTRIBUTE_PTR t, CK_ULONG c,
                       CK_BYTE_PTR ct, CK_ULONG_PTR ctl, CK_OBJECT_HANDLE_PTR k)
{ (void)h;(void)m;(void)pk;(void)t;(void)c;(void)ct;(void)ctl;(void)k;
  return CKR_FUNCTION_NOT_SUPPORTED; }
CK_RV C_DecapsulateKey(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m,
                       CK_OBJECT_HANDLE pk, CK_ATTRIBUTE_PTR t, CK_ULONG c,
                       CK_BYTE_PTR ct, CK_ULONG ctl, CK_OBJECT_HANDLE_PTR k)
{ (void)h;(void)m;(void)pk;(void)t;(void)c;(void)ct;(void)ctl;(void)k;
  return CKR_FUNCTION_NOT_SUPPORTED; }
CK_RV C_VerifySignatureInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m,
                            CK_OBJECT_HANDLE k, CK_BYTE_PTR s, CK_ULONG sl)
{ (void)h;(void)m;(void)k;(void)s;(void)sl; return CKR_FUNCTION_NOT_SUPPORTED; }
CK_RV C_VerifySignature(CK_SESSION_HANDLE h, CK_BYTE_PTR d, CK_ULONG dl)
{ (void)h;(void)d;(void)dl; return CKR_FUNCTION_NOT_SUPPORTED; }
CK_RV C_VerifySignatureUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR p, CK_ULONG pl)
{ (void)h;(void)p;(void)pl; return CKR_FUNCTION_NOT_SUPPORTED; }
CK_RV C_VerifySignatureFinal(CK_SESSION_HANDLE h)
{ (void)h; return CKR_FUNCTION_NOT_SUPPORTED; }
CK_RV C_GetSessionValidationFlags(CK_SESSION_HANDLE h,
                                  CK_SESSION_VALIDATION_FLAGS_TYPE t,
                                  CK_FLAGS_PTR f)
{ (void)h;(void)t;(void)f; return CKR_FUNCTION_NOT_SUPPORTED; }
CK_RV C_AsyncComplete(CK_SESSION_HANDLE h, CK_UTF8CHAR_PTR n,
                      CK_ASYNC_DATA_PTR r)
{ (void)h;(void)n;(void)r; return CKR_FUNCTION_NOT_SUPPORTED; }
CK_RV C_AsyncGetID(CK_SESSION_HANDLE h, CK_UTF8CHAR_PTR n, CK_ULONG_PTR id)
{ (void)h;(void)n;(void)id; return CKR_FUNCTION_NOT_SUPPORTED; }
CK_RV C_AsyncJoin(CK_SESSION_HANDLE h, CK_UTF8CHAR_PTR n, CK_ULONG id,
                  CK_BYTE_PTR d, CK_ULONG dl)
{ (void)h;(void)n;(void)id;(void)d;(void)dl; return CKR_FUNCTION_NOT_SUPPORTED; }
CK_RV C_WrapKeyAuthenticated(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m,
                             CK_OBJECT_HANDLE wk, CK_OBJECT_HANDLE k,
                             CK_BYTE_PTR ad, CK_ULONG adl, CK_BYTE_PTR w,
                             CK_ULONG_PTR wl)
{ (void)h;(void)m;(void)wk;(void)k;(void)ad;(void)adl;(void)w;(void)wl;
  return CKR_FUNCTION_NOT_SUPPORTED; }
CK_RV C_UnwrapKeyAuthenticated(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m,
                               CK_OBJECT_HANDLE uk, CK_BYTE_PTR w, CK_ULONG wl,
                               CK_ATTRIBUTE_PTR t, CK_ULONG c, CK_BYTE_PTR ad,
                               CK_ULONG adl, CK_OBJECT_HANDLE_PTR k)
{ (void)h;(void)m;(void)uk;(void)w;(void)wl;(void)t;(void)c;(void)ad;(void)adl;
  (void)k; return CKR_FUNCTION_NOT_SUPPORTED; }

/*
 * Token NCMP - opencryptoki STDLL token-specific implementation.
 *
 * Implements the lifecycle and reporting hooks referenced by tok_struct.h. The
 * token is a proxy: token_specific_init() connects to the ncmpd multiplexer
 * (which owns the USB link to the physical FX3 token) and stashes the client
 * handle in tokdata->private_data. Cryptographic operations are forwarded over
 * that channel and are added incrementally.
 */
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "platform.h"
#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "errno.h"
#include "tok_specific.h"
#include "tok_struct.h"
#include "trace.h"

/* NCMP client + error-mapping API (ncmp/ subtree). */
#include "ncmp/ncmp_client.h"
#include "ncmp/ncmp_ckr.h"
#include "ncmp/ncmp_cmd.h"
#include "ncmp/ncmp_limits.h"
#include "ncmp/ncmp_errno.h"

/*
 * Token identity globals referenced by the common layer (key.c, utility.c).
 * Every STDLL must define these; see soft_specific.c for the pattern.
 */
const char manuf[] = "IBM";
const char model[] = "NCMP";
const char descr[] = "NCMP USB Token";
const char label[] = "ncmptok";

/** Per-token private state held in STDLL_TokData_t::private_data. */
struct ncmp_private_data {
    ncmp_client_t client;    /**< Connection to ncmpd (socket + SHM). */
    uint32_t      ncmp_slot; /**< Physical NCMP slot backing this token. */
};

/*
 * Mechanisms advertised by the NCMP token. Placeholder set representing what
 * the FX3 firmware exposes; the real list should be queried from the token
 * once the query command is wired. Kept small until then.
 */
static const MECH_LIST_ELEMENT ncmp_mech_list[] = {
    { CKM_SHA_1,    { 0,   0,    CKF_DIGEST } },
    { CKM_SHA224,   { 0,   0,    CKF_DIGEST } },
    { CKM_SHA256,   { 0,   0,    CKF_DIGEST } },
    { CKM_SHA384,   { 0,   0,    CKF_DIGEST } },
    { CKM_SHA512,   { 0,   0,    CKF_DIGEST } },
    { CKM_AES_CBC,  { 16,  32,   CKF_ENCRYPT | CKF_DECRYPT } },
    { CKM_AES_ECB,  { 16,  32,   CKF_ENCRYPT | CKF_DECRYPT } },
    { CKM_AES_GCM,  { 16,  32,   CKF_ENCRYPT | CKF_DECRYPT } },
    { CKM_AES_CTR,  { 16,  32,   CKF_ENCRYPT | CKF_DECRYPT } },
    { CKM_AES_OFB,  { 16,  32,   CKF_ENCRYPT | CKF_DECRYPT } },
    { CKM_AES_CFB128,{ 16, 32,   CKF_ENCRYPT | CKF_DECRYPT } },
    { CKM_RSA_PKCS, { 512, 4096, CKF_ENCRYPT | CKF_DECRYPT |
                                 CKF_SIGN | CKF_VERIFY } },
    { CKM_RSA_PKCS_KEY_PAIR_GEN, { 512, 4096, CKF_GENERATE_KEY_PAIR } },
    { CKM_ECDSA,    { 256, 521,  CKF_SIGN | CKF_VERIFY } },
    { CKM_EC_KEY_PAIR_GEN, { 256, 521, CKF_GENERATE_KEY_PAIR } },
    { CKM_RSA_PKCS_OAEP, { 512, 4096, CKF_ENCRYPT | CKF_DECRYPT } },
    { CKM_SHA_1_HMAC,   { 0, 0, CKF_SIGN | CKF_VERIFY } },
    { CKM_SHA224_HMAC,  { 0, 0, CKF_SIGN | CKF_VERIFY } },
    { CKM_SHA256_HMAC,  { 0, 0, CKF_SIGN | CKF_VERIFY } },
    { CKM_SHA384_HMAC,  { 0, 0, CKF_SIGN | CKF_VERIFY } },
    { CKM_SHA512_HMAC,  { 0, 0, CKF_SIGN | CKF_VERIFY } },
    { CKM_DES3_KEY_GEN, { 24, 24, CKF_GENERATE } },
    { CKM_GENERIC_SECRET_KEY_GEN, { 1, 4096, CKF_GENERATE } },
    { CKM_RSA_PKCS_PSS, { 512, 4096, CKF_SIGN | CKF_VERIFY } },
    { CKM_DH_PKCS_DERIVE, { 512, 4096, CKF_DERIVE } },
    { CKM_ECDH1_DERIVE, { 256, 521, CKF_DERIVE } },
};
static const CK_ULONG ncmp_mech_list_len =
    (sizeof(ncmp_mech_list) / sizeof(MECH_LIST_ELEMENT));

/** Accept-all mechanism filter (the advertised list is already curated). */
static CK_BBOOL ncmp_filter_mechanism(STDLL_TokData_t *tokdata,
                                      CK_MECHANISM_TYPE mechanism,
                                      CK_MECHANISM_INFO *info)
{
    UNUSED(tokdata);
    UNUSED(mechanism);
    UNUSED(info);
    return CK_TRUE;
}

CK_RV token_specific_init(STDLL_TokData_t *tokdata, CK_SLOT_ID SlotNumber,
                          char *conf_name)
{
    struct ncmp_private_data *priv;
    CK_RV rc;
    int nrc;

    UNUSED(conf_name);

    TRACE_INFO("ncmp %s slot=%lu running\n", __func__, SlotNumber);

    rc = ock_generic_filter_mechanism_list(tokdata,
                                           ncmp_mech_list, ncmp_mech_list_len,
                                           &(tokdata->mech_list),
                                           &(tokdata->mech_list_len));
    if (rc != CKR_OK) {
        TRACE_ERROR("Mechanism filtering failed! rc = 0x%lx\n", rc);
        goto error;
    }

    priv = calloc(1, sizeof(*priv));
    if (priv == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto error;
    }

    /*
     * Connect to ncmpd (must already be running). A proxy token is only
     * present when its backend is reachable, so a failed connect is surfaced
     * as the mapped CKR_* (e.g. CKR_TOKEN_NOT_PRESENT when the daemon is down).
     */
    nrc = ncmp_client_init(&priv->client, NULL);
    if (nrc != NCMP_OK) {
        rc = ncmp_err_to_ckr(nrc);
        TRACE_ERROR("ncmp_client_init failed (ncmp rc=%d -> ck 0x%lx)\n",
                    nrc, rc);
        free(priv);
        goto error;
    }

    /*
     * Map this token to the first NCMP slot the daemon reports online. A single
     * FX3 board maps to one slot; multi-board setups will select the slot via
     * ncmptok.conf (TODO) instead of taking the lowest online one.
     */
    if (priv->client.slot_mask == 0) {
        TRACE_ERROR("ncmp: daemon reports no online slots\n");
        rc = CKR_TOKEN_NOT_PRESENT;
        ncmp_client_fini(&priv->client);
        free(priv);
        goto error;
    }
    priv->ncmp_slot = (uint32_t)__builtin_ctz(priv->client.slot_mask);

    tokdata->private_data = priv;
    return CKR_OK;

error:
    token_specific_final(tokdata, FALSE);
    return rc;
}

CK_RV token_specific_final(STDLL_TokData_t *tokdata,
                           CK_BBOOL in_fork_initializer)
{
    struct ncmp_private_data *priv = tokdata->private_data;

    UNUSED(in_fork_initializer);

    TRACE_INFO("ncmp %s running\n", __func__);

    if (tokdata->mech_list != NULL) {
        free(tokdata->mech_list);
        tokdata->mech_list = NULL;
    }

    if (priv != NULL) {
        ncmp_client_fini(&priv->client);
        free(priv);
        tokdata->private_data = NULL;
    }

    return CKR_OK;
}

CK_RV token_specific_rng(STDLL_TokData_t *tokdata, CK_BYTE *output,
                         CK_ULONG bytes)
{
    struct ncmp_private_data *priv = tokdata->private_data;
    CK_ULONG done = 0;

    if (priv == NULL)
        return CKR_FUNCTION_FAILED;

    /* Forward to the token in <=32KB parameter-sized chunks. */
    while (done < bytes) {
        CK_ULONG remaining = bytes - done;
        uint32_t chunk = (remaining > NCMP_MAX_PARAM_SIZE)
                             ? NCMP_MAX_PARAM_SIZE : (uint32_t)remaining;
        uint8_t lenbuf[4];
        uint32_t out_len = 0;
        uint32_t ack = 0;
        int nrc;

        ncmp_wr_u32le(lenbuf, chunk);
        nrc = ncmp_client_command(&priv->client, priv->ncmp_slot,
                                  NCMP_CMD_RNG, lenbuf, sizeof(lenbuf),
                                  (uint8_t *)output + done, chunk,
                                  &out_len, &ack);
        if (nrc != NCMP_OK)
            return ncmp_err_to_ckr(nrc);
        if (ack != NCMP_CKR_OK)
            return (CK_RV)ack;          /* token-reported failure */
        if (out_len != chunk)
            return CKR_FUNCTION_FAILED;  /* short RNG response */

        done += chunk;
    }

    return CKR_OK;
}

/** Free the digest context sentinel allocated by token_specific_sha_init. */
static void ncmp_sha_free(STDLL_TokData_t *tokdata, SESSION *sess,
                          CK_BYTE *context, CK_ULONG context_len)
{
    UNUSED(tokdata);
    UNUSED(sess);
    UNUSED(context_len);
    free(context);
}

CK_RV token_specific_sha_init(STDLL_TokData_t *tokdata, DIGEST_CONTEXT *ctx,
                              CK_MECHANISM *mech)
{
    UNUSED(tokdata);

    if (ncmp_digest_size((uint32_t)mech->mechanism) == 0)
        return CKR_MECHANISM_INVALID;

    ctx->mech.mechanism = mech->mechanism;
    ctx->mech.ulParameterLen = mech->ulParameterLen;
    ctx->mech.pParameter = NULL; /* SHA-2 family takes no parameters */

    /* ctx->context holds the token-side multipart context id (created lazily on
     * the first update/final). dig_mgr also requires it be non-NULL for the
     * one-shot path, which this satisfies. */
    ctx->context = (CK_BYTE *)malloc(sizeof(uint32_t));
    if (ctx->context == NULL)
        return CKR_HOST_MEMORY;
    *(uint32_t *)ctx->context = NCMP_DIGEST_CTX_NONE;
    ctx->context_len = sizeof(uint32_t);
    ctx->context_free_func = &ncmp_sha_free;
    ctx->state_unsaveable = CK_TRUE;

    return CKR_OK;
}

/**
 * @brief Ensure a token-side multipart digest context exists; return its id.
 *
 * Created lazily (NCMP_CMD_DIGEST_INIT) on the first update/final so the
 * one-shot path never allocates a token context.
 */
static CK_RV ncmp_digest_ensure_ctx(struct ncmp_private_data *priv,
                                    DIGEST_CONTEXT *ctx, uint32_t *out_id)
{
    uint32_t *idp = (uint32_t *)ctx->context;
    uint8_t mechbuf[4];
    uint8_t idbuf[4];
    uint32_t out_len = 0;
    uint32_t ack = 0;
    int nrc;

    if (*idp != NCMP_DIGEST_CTX_NONE) {
        *out_id = *idp;
        return CKR_OK;
    }

    ncmp_wr_u32le(mechbuf, (uint32_t)ctx->mech.mechanism);
    nrc = ncmp_client_command(&priv->client, priv->ncmp_slot,
                              NCMP_CMD_DIGEST_INIT, mechbuf, sizeof(mechbuf),
                              idbuf, sizeof(idbuf), &out_len, &ack);
    if (nrc != NCMP_OK)
        return ncmp_err_to_ckr(nrc);
    if (ack != NCMP_CKR_OK)
        return (CK_RV)ack;
    if (out_len != 4)
        return CKR_FUNCTION_FAILED;

    *idp = ncmp_rd_u32le(idbuf);
    *out_id = *idp;
    return CKR_OK;
}

CK_RV token_specific_sha_update(STDLL_TokData_t *tokdata, DIGEST_CONTEXT *ctx,
                                CK_BYTE *in_data, CK_ULONG in_data_len)
{
    struct ncmp_private_data *priv = tokdata->private_data;
    uint32_t id;
    CK_RV rc;
    CK_ULONG done = 0;

    if (priv == NULL)
        return CKR_FUNCTION_FAILED;
    rc = ncmp_digest_ensure_ctx(priv, ctx, &id);
    if (rc != CKR_OK)
        return rc;

    /* Feed the token in <=32KB parameter-sized chunks: [ctx_id | data]. */
    while (done < in_data_len) {
        CK_ULONG remaining = in_data_len - done;
        uint32_t chunk = (remaining > NCMP_MAX_PARAM_SIZE)
                             ? NCMP_MAX_PARAM_SIZE : (uint32_t)remaining;
        const uint8_t *parts[2];
        uint32_t lens[2];
        uint8_t idbuf[4];
        NCMP_Message rsp;
        int nrc;

        ncmp_wr_u32le(idbuf, id);
        parts[0] = idbuf;          lens[0] = sizeof(idbuf);
        parts[1] = in_data + done; lens[1] = chunk;
        nrc = ncmp_client_command_mp(&priv->client, priv->ncmp_slot,
                                     NCMP_CMD_DIGEST_UPDATE, parts, lens, 2,
                                     NULL, 0, &rsp);
        if (nrc != NCMP_OK)
            return ncmp_err_to_ckr(nrc);
        if (rsp.header.ack != NCMP_CKR_OK)
            return (CK_RV)rsp.header.ack;
        done += chunk;
    }

    return CKR_OK;
}

CK_RV token_specific_sha_final(STDLL_TokData_t *tokdata, DIGEST_CONTEXT *ctx,
                               CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    struct ncmp_private_data *priv = tokdata->private_data;
    uint32_t mech = (uint32_t)ctx->mech.mechanism;
    uint32_t hsize = ncmp_digest_size(mech);
    uint32_t id;
    uint32_t out_len = 0;
    uint32_t ack = 0;
    uint8_t idbuf[4];
    CK_RV rc;
    int nrc;

    if (priv == NULL || hsize == 0)
        return CKR_FUNCTION_FAILED;
    if (out_data == NULL || *out_data_len < hsize) {
        *out_data_len = hsize;
        return CKR_BUFFER_TOO_SMALL;
    }

    /* Digest of empty input if no update happened: create the context now. */
    rc = ncmp_digest_ensure_ctx(priv, ctx, &id);
    if (rc != CKR_OK)
        return rc;

    ncmp_wr_u32le(idbuf, id);
    nrc = ncmp_client_command(&priv->client, priv->ncmp_slot,
                              NCMP_CMD_DIGEST_FINAL, idbuf, sizeof(idbuf),
                              out_data, (uint32_t)*out_data_len, &out_len, &ack);
    if (nrc != NCMP_OK)
        return ncmp_err_to_ckr(nrc);
    if (ack != NCMP_CKR_OK)
        return (CK_RV)ack;
    if (out_len != hsize)
        return CKR_FUNCTION_FAILED;

    /* Token freed the context; mark ours consumed. */
    *(uint32_t *)ctx->context = NCMP_DIGEST_CTX_NONE;
    *out_data_len = hsize;
    return CKR_OK;
}

CK_RV token_specific_sha(STDLL_TokData_t *tokdata, DIGEST_CONTEXT *ctx,
                         CK_BYTE *in_data, CK_ULONG in_data_len,
                         CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    struct ncmp_private_data *priv = tokdata->private_data;
    uint32_t mech = (uint32_t)ctx->mech.mechanism;
    uint32_t hsize = ncmp_digest_size(mech);
    uint32_t req_len;
    uint32_t out_len = 0;
    uint32_t ack = 0;
    uint8_t *req;
    int nrc;

    if (priv == NULL || hsize == 0)
        return CKR_FUNCTION_FAILED;
    /* One-shot input must fit one wire parameter (mech prefix + data). Larger
     * inputs need the multipart path (t_sha_update/final), added later. */
    if ((CK_ULONG)4 + in_data_len > NCMP_MAX_PARAM_SIZE)
        return CKR_DATA_LEN_RANGE;

    req_len = 4 + (uint32_t)in_data_len;
    req = (uint8_t *)malloc(req_len);
    if (req == NULL)
        return CKR_HOST_MEMORY;
    ncmp_wr_u32le(req, mech);
    if (in_data_len > 0)
        memcpy(req + 4, in_data, in_data_len);

    nrc = ncmp_client_command(&priv->client, priv->ncmp_slot, NCMP_CMD_DIGEST,
                              req, req_len, out_data, hsize, &out_len, &ack);
    free(req);

    if (nrc != NCMP_OK)
        return ncmp_err_to_ckr(nrc);
    if (ack != NCMP_CKR_OK)
        return (CK_RV)ack;
    if (out_len != hsize)
        return CKR_FUNCTION_FAILED;

    *out_data_len = hsize;
    return CKR_OK;
}

CK_RV token_specific_aes_cbc(STDLL_TokData_t *tokdata, SESSION *sess,
                             CK_BYTE *in_data, CK_ULONG in_data_len,
                             CK_BYTE *out_data, CK_ULONG *out_data_len,
                             OBJECT *key, CK_BYTE *init_v, CK_BYTE encrypt)
{
    struct ncmp_private_data *priv = tokdata->private_data;
    CK_ATTRIBUTE *key_attr = NULL;
    NCMP_Message rsp;
    const uint8_t *parts[4];
    uint32_t lens[4];
    uint8_t flags[4];
    CK_RV rc;
    int nrc;

    UNUSED(sess);

    if (priv == NULL)
        return CKR_FUNCTION_FAILED;
    if ((in_data_len % NCMP_AES_BLOCK) != 0)
        return CKR_DATA_LEN_RANGE;
    if (out_data == NULL || *out_data_len < in_data_len) {
        *out_data_len = in_data_len;
        return CKR_BUFFER_TOO_SMALL;
    }

    /* Pull the raw key bytes from the key object. */
    rc = template_attribute_get_non_empty(key->template, CKA_VALUE, &key_attr);
    if (rc != CKR_OK)
        return rc;

    ncmp_wr_u32le(flags, encrypt ? NCMP_AES_FLAG_ENCRYPT : 0u);
    parts[0] = flags;             lens[0] = sizeof(flags);
    parts[1] = key_attr->pValue;  lens[1] = (uint32_t)key_attr->ulValueLen;
    parts[2] = init_v;            lens[2] = NCMP_AES_BLOCK;
    parts[3] = in_data;           lens[3] = (uint32_t)in_data_len;

    nrc = ncmp_client_command_mp(&priv->client, priv->ncmp_slot,
                                 NCMP_CMD_AES_CBC, parts, lens, 4,
                                 out_data, (uint32_t)*out_data_len, &rsp);
    if (nrc != NCMP_OK)
        return ncmp_err_to_ckr(nrc);
    if (rsp.header.ack != NCMP_CKR_OK)
        return (CK_RV)rsp.header.ack;
    if (rsp.param_len[0] != in_data_len)
        return CKR_FUNCTION_FAILED;

    *out_data_len = in_data_len;
    return CKR_OK;
}

CK_RV token_specific_rsa_sign(STDLL_TokData_t *tokdata, SESSION *sess,
                              CK_BYTE *in_data, CK_ULONG in_data_len,
                              CK_BYTE *out_data, CK_ULONG *out_data_len,
                              OBJECT *key)
{
    struct ncmp_private_data *priv = tokdata->private_data;
    CK_ATTRIBUTE *mod_attr = NULL;
    CK_ATTRIBUTE *exp_attr = NULL;
    NCMP_Message rsp;
    const uint8_t *parts[3];
    uint32_t lens[3];
    CK_RV rc;
    int nrc;

    UNUSED(sess);

    if (priv == NULL)
        return CKR_FUNCTION_FAILED;

    /* Asymmetric key: pull the modulus and private exponent from the object. */
    rc = template_attribute_get_non_empty(key->template, CKA_MODULUS, &mod_attr);
    if (rc != CKR_OK)
        return rc;
    rc = template_attribute_get_non_empty(key->template, CKA_PRIVATE_EXPONENT,
                                          &exp_attr);
    if (rc != CKR_OK)
        return rc;

    if (out_data == NULL || *out_data_len < mod_attr->ulValueLen) {
        *out_data_len = mod_attr->ulValueLen;
        return CKR_BUFFER_TOO_SMALL;
    }

    parts[0] = mod_attr->pValue; lens[0] = (uint32_t)mod_attr->ulValueLen;
    parts[1] = exp_attr->pValue; lens[1] = (uint32_t)exp_attr->ulValueLen;
    parts[2] = in_data;          lens[2] = (uint32_t)in_data_len;

    nrc = ncmp_client_command_mp(&priv->client, priv->ncmp_slot,
                                 NCMP_CMD_RSA_SIGN, parts, lens, 3,
                                 out_data, (uint32_t)*out_data_len, &rsp);
    if (nrc != NCMP_OK)
        return ncmp_err_to_ckr(nrc);
    if (rsp.header.ack != NCMP_CKR_OK)
        return (CK_RV)rsp.header.ack;
    if (rsp.param_len[0] != mod_attr->ulValueLen)
        return CKR_FUNCTION_FAILED;

    *out_data_len = mod_attr->ulValueLen;
    return CKR_OK;
}

CK_RV token_specific_aes_ecb(STDLL_TokData_t *tokdata, SESSION *sess,
                             CK_BYTE *in_data, CK_ULONG in_data_len,
                             CK_BYTE *out_data, CK_ULONG *out_data_len,
                             OBJECT *key, CK_BYTE encrypt)
{
    struct ncmp_private_data *priv = tokdata->private_data;
    CK_ATTRIBUTE *key_attr = NULL;
    NCMP_Message rsp;
    const uint8_t *parts[3];
    uint32_t lens[3];
    uint8_t flags[4];
    CK_RV rc;
    int nrc;

    UNUSED(sess);

    if (priv == NULL)
        return CKR_FUNCTION_FAILED;
    if ((in_data_len % NCMP_AES_BLOCK) != 0)
        return CKR_DATA_LEN_RANGE;
    if (out_data == NULL || *out_data_len < in_data_len) {
        *out_data_len = in_data_len;
        return CKR_BUFFER_TOO_SMALL;
    }

    rc = template_attribute_get_non_empty(key->template, CKA_VALUE, &key_attr);
    if (rc != CKR_OK)
        return rc;

    ncmp_wr_u32le(flags, encrypt ? NCMP_AES_FLAG_ENCRYPT : 0u);
    parts[0] = flags;            lens[0] = sizeof(flags);
    parts[1] = key_attr->pValue; lens[1] = (uint32_t)key_attr->ulValueLen;
    parts[2] = in_data;          lens[2] = (uint32_t)in_data_len;

    nrc = ncmp_client_command_mp(&priv->client, priv->ncmp_slot,
                                 NCMP_CMD_AES_ECB, parts, lens, 3,
                                 out_data, (uint32_t)*out_data_len, &rsp);
    if (nrc != NCMP_OK)
        return ncmp_err_to_ckr(nrc);
    if (rsp.header.ack != NCMP_CKR_OK)
        return (CK_RV)rsp.header.ack;
    if (rsp.param_len[0] != in_data_len)
        return CKR_FUNCTION_FAILED;

    *out_data_len = in_data_len;
    return CKR_OK;
}

CK_RV token_specific_aes_gcm_init(STDLL_TokData_t *tokdata, SESSION *sess,
                                  ENCR_DECR_CONTEXT *ctx, CK_MECHANISM *mech,
                                  CK_OBJECT_HANDLE key, CK_BYTE encrypt)
{
    UNUSED(tokdata);
    UNUSED(sess);
    UNUSED(ctx);
    UNUSED(key);
    UNUSED(encrypt);

    /* The common layer duplicates the GCM params into ctx->mech and records
     * the key handle in ctx->key, so a proxy token needs no per-init state -
     * just validate the mechanism carries GCM parameters. */
    if (mech->pParameter == NULL ||
        mech->ulParameterLen < sizeof(CK_GCM_PARAMS))
        return CKR_MECHANISM_PARAM_INVALID;
    return CKR_OK;
}

CK_RV token_specific_aes_gcm(STDLL_TokData_t *tokdata, SESSION *sess,
                             ENCR_DECR_CONTEXT *ctx, CK_BYTE *in_data,
                             CK_ULONG in_data_len, CK_BYTE *out_data,
                             CK_ULONG *out_data_len, CK_BYTE encrypt)
{
    struct ncmp_private_data *priv = tokdata->private_data;
    CK_GCM_PARAMS *gcm = (CK_GCM_PARAMS *)ctx->mech.pParameter;
    OBJECT *key_obj = NULL;
    CK_ATTRIBUTE *key_attr = NULL;
    NCMP_Message rsp;
    const uint8_t *parts[6];
    uint32_t lens[6];
    uint8_t flags[4];
    uint8_t tlbuf[4];
    uint32_t taglen;
    CK_ULONG expected_out;
    CK_RV rc;
    int nrc;

    UNUSED(sess);

    if (priv == NULL || gcm == NULL)
        return CKR_FUNCTION_FAILED;

    taglen = gcm->ulTagBits / 8;
    if (taglen == 0 || taglen > NCMP_AES_BLOCK)
        return CKR_MECHANISM_PARAM_INVALID;
    if (!encrypt && in_data_len < taglen)
        return CKR_ENCRYPTED_DATA_INVALID;

    expected_out = encrypt ? (in_data_len + taglen) : (in_data_len - taglen);
    if (out_data == NULL || *out_data_len < expected_out) {
        *out_data_len = expected_out;
        return CKR_BUFFER_TOO_SMALL;
    }

    /* Resolve the key handle to its raw bytes (held under READ_LOCK for the
     * duration of the forwarded command). */
    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK)
        return rc;
    rc = template_attribute_get_non_empty(key_obj->template, CKA_VALUE,
                                          &key_attr);
    if (rc != CKR_OK) {
        object_put(tokdata, key_obj, TRUE);
        return rc;
    }

    ncmp_wr_u32le(flags, encrypt ? NCMP_AES_FLAG_ENCRYPT : 0u);
    ncmp_wr_u32le(tlbuf, taglen);
    parts[0] = flags;            lens[0] = sizeof(flags);
    parts[1] = key_attr->pValue; lens[1] = (uint32_t)key_attr->ulValueLen;
    parts[2] = gcm->pIv;         lens[2] = (uint32_t)gcm->ulIvLen;
    parts[3] = gcm->pAAD;        lens[3] = (uint32_t)gcm->ulAADLen;
    parts[4] = tlbuf;            lens[4] = sizeof(tlbuf);
    parts[5] = in_data;          lens[5] = (uint32_t)in_data_len;

    nrc = ncmp_client_command_mp(&priv->client, priv->ncmp_slot,
                                 NCMP_CMD_AES_GCM, parts, lens, 6,
                                 out_data, (uint32_t)*out_data_len, &rsp);
    object_put(tokdata, key_obj, TRUE);

    if (nrc != NCMP_OK)
        return ncmp_err_to_ckr(nrc);
    if (rsp.header.ack != NCMP_CKR_OK)
        return (CK_RV)rsp.header.ack;
    if (rsp.param_len[0] != expected_out)
        return CKR_FUNCTION_FAILED;

    *out_data_len = expected_out;
    return CKR_OK;
}

/** Forward a stream-mode AES op: [flags|key|iv|data] -> out (same length). */
static CK_RV ncmp_aes_stream(struct ncmp_private_data *priv, uint32_t opcode,
                             OBJECT *key, const CK_BYTE *iv, CK_ULONG iv_len,
                             CK_BYTE encrypt, CK_BYTE *in_data,
                             CK_ULONG in_data_len, CK_BYTE *out_data,
                             CK_ULONG out_cap)
{
    CK_ATTRIBUTE *key_attr = NULL;
    NCMP_Message rsp;
    const uint8_t *parts[4];
    uint32_t lens[4];
    uint8_t flags[4];
    CK_RV rc;
    int nrc;

    rc = template_attribute_get_non_empty(key->template, CKA_VALUE, &key_attr);
    if (rc != CKR_OK)
        return rc;

    ncmp_wr_u32le(flags, encrypt ? NCMP_AES_FLAG_ENCRYPT : 0u);
    parts[0] = flags;            lens[0] = sizeof(flags);
    parts[1] = key_attr->pValue; lens[1] = (uint32_t)key_attr->ulValueLen;
    parts[2] = iv;               lens[2] = (uint32_t)iv_len;
    parts[3] = in_data;          lens[3] = (uint32_t)in_data_len;

    nrc = ncmp_client_command_mp(&priv->client, priv->ncmp_slot, opcode,
                                 parts, lens, 4, out_data, (uint32_t)out_cap,
                                 &rsp);
    if (nrc != NCMP_OK)
        return ncmp_err_to_ckr(nrc);
    if (rsp.header.ack != NCMP_CKR_OK)
        return (CK_RV)rsp.header.ack;
    if (rsp.param_len[0] != in_data_len)
        return CKR_FUNCTION_FAILED;
    return CKR_OK;
}

CK_RV token_specific_aes_ctr(STDLL_TokData_t *tokdata, CK_BYTE *in_data,
                             CK_ULONG in_data_len, CK_BYTE *out_data,
                             CK_ULONG *out_data_len, OBJECT *key,
                             CK_BYTE *counter_block, CK_ULONG counter_width,
                             CK_BYTE encrypt)
{
    struct ncmp_private_data *priv = tokdata->private_data;
    CK_RV rc;

    UNUSED(counter_width); /* mock treats the counter block as an IV */

    if (priv == NULL)
        return CKR_FUNCTION_FAILED;
    if (out_data == NULL || *out_data_len < in_data_len) {
        *out_data_len = in_data_len;
        return CKR_BUFFER_TOO_SMALL;
    }

    rc = ncmp_aes_stream(priv, NCMP_CMD_AES_CTR, key, counter_block,
                         NCMP_AES_BLOCK, encrypt, in_data, in_data_len,
                         out_data, *out_data_len);
    if (rc == CKR_OK)
        *out_data_len = in_data_len;
    return rc;
}

CK_RV token_specific_aes_ofb(STDLL_TokData_t *tokdata, CK_BYTE *in_data,
                             CK_ULONG in_data_len, CK_BYTE *out_data,
                             OBJECT *key, CK_BYTE *init_v, uint_32 encrypt)
{
    struct ncmp_private_data *priv = tokdata->private_data;

    if (priv == NULL)
        return CKR_FUNCTION_FAILED;
    /* OFB output length equals input length; caller sizes out_data. */
    return ncmp_aes_stream(priv, NCMP_CMD_AES_OFB, key, init_v, NCMP_AES_BLOCK,
                           (CK_BYTE)(encrypt != 0), in_data, in_data_len,
                           out_data, in_data_len);
}

CK_RV token_specific_aes_cfb(STDLL_TokData_t *tokdata, CK_BYTE *in_data,
                             CK_ULONG in_data_len, CK_BYTE *out_data,
                             OBJECT *key, CK_BYTE *init_v, uint_32 cfb_len,
                             uint_32 encrypt)
{
    struct ncmp_private_data *priv = tokdata->private_data;

    UNUSED(cfb_len); /* mock ignores the CFB segment size */

    if (priv == NULL)
        return CKR_FUNCTION_FAILED;
    return ncmp_aes_stream(priv, NCMP_CMD_AES_CFB, key, init_v, NCMP_AES_BLOCK,
                           (CK_BYTE)(encrypt != 0), in_data, in_data_len,
                           out_data, in_data_len);
}

CK_RV token_specific_ec_sign(STDLL_TokData_t *tokdata, SESSION *sess,
                             CK_BYTE *in_data, CK_ULONG in_data_len,
                             CK_BYTE *out_data, CK_ULONG *out_data_len,
                             OBJECT *key)
{
    struct ncmp_private_data *priv = tokdata->private_data;
    CK_ATTRIBUTE *params_attr = NULL;
    CK_ATTRIBUTE *val_attr = NULL;
    NCMP_Message rsp;
    const uint8_t *parts[3];
    uint32_t lens[3];
    CK_ULONG siglen;
    CK_RV rc;
    int nrc;

    UNUSED(sess);

    if (priv == NULL)
        return CKR_FUNCTION_FAILED;

    /* EC private key: the curve (CKA_EC_PARAMS) and the private scalar
     * (CKA_VALUE). ECDSA signature length is 2 * field length. */
    rc = template_attribute_get_non_empty(key->template, CKA_EC_PARAMS,
                                          &params_attr);
    if (rc != CKR_OK)
        return rc;
    rc = template_attribute_get_non_empty(key->template, CKA_VALUE, &val_attr);
    if (rc != CKR_OK)
        return rc;

    siglen = 2 * val_attr->ulValueLen;
    if (out_data == NULL || *out_data_len < siglen) {
        *out_data_len = siglen;
        return CKR_BUFFER_TOO_SMALL;
    }

    parts[0] = params_attr->pValue; lens[0] = (uint32_t)params_attr->ulValueLen;
    parts[1] = val_attr->pValue;    lens[1] = (uint32_t)val_attr->ulValueLen;
    parts[2] = in_data;             lens[2] = (uint32_t)in_data_len;

    nrc = ncmp_client_command_mp(&priv->client, priv->ncmp_slot,
                                 NCMP_CMD_EC_SIGN, parts, lens, 3,
                                 out_data, (uint32_t)*out_data_len, &rsp);
    if (nrc != NCMP_OK)
        return ncmp_err_to_ckr(nrc);
    if (rsp.header.ack != NCMP_CKR_OK)
        return (CK_RV)rsp.header.ack;
    if (rsp.param_len[0] != siglen)
        return CKR_FUNCTION_FAILED;

    *out_data_len = siglen;
    return CKR_OK;
}

CK_RV token_specific_rsa_verify(STDLL_TokData_t *tokdata, SESSION *sess,
                                CK_BYTE *in_data, CK_ULONG in_data_len,
                                CK_BYTE *signature, CK_ULONG sig_len,
                                OBJECT *key)
{
    struct ncmp_private_data *priv = tokdata->private_data;
    CK_ATTRIBUTE *mod_attr = NULL;
    CK_ATTRIBUTE *exp_attr = NULL;
    NCMP_Message rsp;
    const uint8_t *parts[4];
    uint32_t lens[4];
    CK_RV rc;
    int nrc;

    UNUSED(sess);

    if (priv == NULL)
        return CKR_FUNCTION_FAILED;

    /* Verify uses the public key: modulus + public exponent. */
    rc = template_attribute_get_non_empty(key->template, CKA_MODULUS, &mod_attr);
    if (rc != CKR_OK)
        return rc;
    rc = template_attribute_get_non_empty(key->template, CKA_PUBLIC_EXPONENT,
                                          &exp_attr);
    if (rc != CKR_OK)
        return rc;

    parts[0] = mod_attr->pValue; lens[0] = (uint32_t)mod_attr->ulValueLen;
    parts[1] = exp_attr->pValue; lens[1] = (uint32_t)exp_attr->ulValueLen;
    parts[2] = in_data;          lens[2] = (uint32_t)in_data_len;
    parts[3] = signature;        lens[3] = (uint32_t)sig_len;

    nrc = ncmp_client_command_mp(&priv->client, priv->ncmp_slot,
                                 NCMP_CMD_RSA_VERIFY, parts, lens, 4,
                                 NULL, 0, &rsp);
    if (nrc != NCMP_OK)
        return ncmp_err_to_ckr(nrc);
    /* The token reports CKR_OK or CKR_SIGNATURE_INVALID in the ACK. */
    return (CK_RV)rsp.header.ack;
}

CK_RV token_specific_ec_verify(STDLL_TokData_t *tokdata, SESSION *sess,
                               CK_BYTE *in_data, CK_ULONG in_data_len,
                               CK_BYTE *signature, CK_ULONG sig_len,
                               OBJECT *key)
{
    struct ncmp_private_data *priv = tokdata->private_data;
    CK_ATTRIBUTE *params_attr = NULL;
    CK_ATTRIBUTE *point_attr = NULL;
    NCMP_Message rsp;
    const uint8_t *parts[4];
    uint32_t lens[4];
    CK_RV rc;
    int nrc;

    UNUSED(sess);

    if (priv == NULL)
        return CKR_FUNCTION_FAILED;

    /* Verify uses the public key: curve params + public point. */
    rc = template_attribute_get_non_empty(key->template, CKA_EC_PARAMS,
                                          &params_attr);
    if (rc != CKR_OK)
        return rc;
    rc = template_attribute_get_non_empty(key->template, CKA_EC_POINT,
                                          &point_attr);
    if (rc != CKR_OK)
        return rc;

    parts[0] = params_attr->pValue; lens[0] = (uint32_t)params_attr->ulValueLen;
    parts[1] = point_attr->pValue;  lens[1] = (uint32_t)point_attr->ulValueLen;
    parts[2] = in_data;             lens[2] = (uint32_t)in_data_len;
    parts[3] = signature;           lens[3] = (uint32_t)sig_len;

    nrc = ncmp_client_command_mp(&priv->client, priv->ncmp_slot,
                                 NCMP_CMD_EC_VERIFY, parts, lens, 4,
                                 NULL, 0, &rsp);
    if (nrc != NCMP_OK)
        return ncmp_err_to_ckr(nrc);
    return (CK_RV)rsp.header.ack;
}

/* Defined later (keypair-gen section); used by generic_secret_key_gen below. */
static CK_RV ncmp_tmpl_add(TEMPLATE *tmpl, CK_ATTRIBUTE_TYPE type,
                           const uint8_t *data, uint32_t len);

/** Fill @p buf with @p len random bytes generated by the token (RNG opcode). */
static CK_RV ncmp_gen_random(struct ncmp_private_data *priv, CK_BYTE *buf,
                             CK_ULONG len)
{
    uint8_t lenbuf[4];
    uint32_t out_len = 0;
    uint32_t ack = 0;
    int nrc;

    if (len == 0 || len > NCMP_MAX_PARAM_SIZE)
        return CKR_KEY_SIZE_RANGE;

    ncmp_wr_u32le(lenbuf, (uint32_t)len);
    nrc = ncmp_client_command(&priv->client, priv->ncmp_slot, NCMP_CMD_RNG,
                              lenbuf, sizeof(lenbuf), buf, (uint32_t)len,
                              &out_len, &ack);
    if (nrc != NCMP_OK)
        return ncmp_err_to_ckr(nrc);
    if (ack != NCMP_CKR_OK || out_len != len)
        return CKR_FUNCTION_FAILED;
    return CKR_OK;
}

/** Generate a clear symmetric key of @p keysize bytes (AES / DES / 3DES). */
static CK_RV ncmp_symkey_gen(struct ncmp_private_data *priv,
                             CK_BYTE **key_value, CK_ULONG *key_len,
                             CK_ULONG keysize, CK_BBOOL *is_opaque)
{
    CK_BYTE *buf;
    CK_RV rc;

    if (priv == NULL)
        return CKR_FUNCTION_FAILED;

    buf = (CK_BYTE *)malloc(keysize ? keysize : 1);
    if (buf == NULL)
        return CKR_HOST_MEMORY;

    rc = ncmp_gen_random(priv, buf, keysize);
    if (rc != CKR_OK) {
        free(buf);
        return rc;
    }

    *key_value = buf;
    *key_len = keysize;
    *is_opaque = FALSE; /* clear key material, not an opaque token blob */
    return CKR_OK;
}

CK_RV token_specific_aes_key_gen(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                 CK_BYTE **key_value, CK_ULONG *key_len,
                                 CK_ULONG keysize, CK_BBOOL *is_opaque)
{
    UNUSED(tmpl);
    return ncmp_symkey_gen(tokdata->private_data, key_value, key_len, keysize,
                           is_opaque);
}

CK_RV token_specific_des_key_gen(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                 CK_BYTE **key_value, CK_ULONG *key_len,
                                 CK_ULONG keysize, CK_BBOOL *is_opaque)
{
    UNUSED(tmpl);
    /* DES (8) and 3DES (24) key material are random bytes like AES. */
    return ncmp_symkey_gen(tokdata->private_data, key_value, key_len, keysize,
                           is_opaque);
}

CK_RV token_specific_generic_secret_key_gen(STDLL_TokData_t *tokdata,
                                            TEMPLATE *tmpl)
{
    struct ncmp_private_data *priv = tokdata->private_data;
    CK_ULONG key_length = 0;
    CK_BYTE *buf;
    CK_RV rc;

    if (priv == NULL)
        return CKR_FUNCTION_FAILED;

    rc = template_attribute_get_ulong(tmpl, CKA_VALUE_LEN, &key_length);
    if (rc != CKR_OK)
        return rc;
    if (key_length == 0 || key_length > NCMP_MAX_PARAM_SIZE)
        return CKR_KEY_SIZE_RANGE;

    buf = (CK_BYTE *)malloc(key_length);
    if (buf == NULL)
        return CKR_HOST_MEMORY;

    rc = ncmp_gen_random(priv, buf, key_length);
    if (rc == CKR_OK)
        rc = ncmp_tmpl_add(tmpl, CKA_VALUE, buf, (uint32_t)key_length);
    free(buf); /* build_attribute deep-copies */
    return rc;
}

/** Build one attribute from raw bytes and insert it into a template. */
static CK_RV ncmp_tmpl_add(TEMPLATE *tmpl, CK_ATTRIBUTE_TYPE type,
                           const uint8_t *data, uint32_t len)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_RV rc = build_attribute(type, (CK_BYTE *)data, len, &attr);

    if (rc != CKR_OK)
        return rc;
    rc = template_update_attribute(tmpl, attr);
    if (rc != CKR_OK)
        free(attr); /* template did not take ownership on failure */
    return rc;
}

CK_RV token_specific_rsa_generate_keypair(STDLL_TokData_t *tokdata,
                                          TEMPLATE *publ_tmpl,
                                          TEMPLATE *priv_tmpl)
{
    struct ncmp_private_data *priv = tokdata->private_data;
    CK_ATTRIBUTE *pubexp = NULL;
    CK_ULONG mod_bits = 0;
    uint32_t nbytes, hbytes, total;
    uint8_t bitsbuf[4];
    const uint8_t *pin[2];
    uint32_t lin[2];
    uint8_t *outbuf;
    NCMP_Message rsp;
    const uint8_t *comp[7];
    uint32_t clen[7];
    CK_RV rc;
    int nrc;

    if (priv == NULL)
        return CKR_FUNCTION_FAILED;

    rc = template_attribute_get_ulong(publ_tmpl, CKA_MODULUS_BITS, &mod_bits);
    if (rc != CKR_OK)
        return rc;
    rc = template_attribute_get_non_empty(publ_tmpl, CKA_PUBLIC_EXPONENT,
                                          &pubexp);
    if (rc != CKR_OK)
        return rc;
    if (mod_bits < 512 || mod_bits > 4096 || (mod_bits % 8) != 0)
        return CKR_KEY_SIZE_RANGE;

    nbytes = (uint32_t)mod_bits / 8;
    hbytes = nbytes / 2;
    total = 2 * nbytes + 5 * hbytes;
    outbuf = (uint8_t *)malloc(total);
    if (outbuf == NULL)
        return CKR_HOST_MEMORY;

    /* Ask the token to generate the key: [modulus bits | public exponent]. */
    ncmp_wr_u32le(bitsbuf, (uint32_t)mod_bits);
    pin[0] = bitsbuf;        lin[0] = sizeof(bitsbuf);
    pin[1] = pubexp->pValue; lin[1] = (uint32_t)pubexp->ulValueLen;
    nrc = ncmp_client_command_mp(&priv->client, priv->ncmp_slot,
                                 NCMP_CMD_RSA_KEYGEN, pin, lin, 2,
                                 outbuf, total, &rsp);
    if (nrc != NCMP_OK) {
        free(outbuf);
        return ncmp_err_to_ckr(nrc);
    }
    if (rsp.header.ack != NCMP_CKR_OK) {
        CK_RV ack = (CK_RV)rsp.header.ack;
        free(outbuf);
        return ack;
    }

    /* Components: n, d, p, q, dp, dq, qinv. */
    for (int i = 0; i < 7; ++i) {
        if (ncmp_msg_param(&rsp, i, &comp[i], &clen[i]) != NCMP_OK ||
            clen[i] == 0) {
            free(outbuf);
            return CKR_FUNCTION_FAILED;
        }
    }

    /* Public key: modulus (+ the caller's public exponent stays in publ_tmpl).
     * Private key: full component set. build_attribute deep-copies, so outbuf
     * can be freed afterwards. */
    rc = ncmp_tmpl_add(publ_tmpl, CKA_MODULUS, comp[0], clen[0]);
    if (rc == CKR_OK)
        rc = ncmp_tmpl_add(priv_tmpl, CKA_MODULUS, comp[0], clen[0]);
    if (rc == CKR_OK)
        rc = ncmp_tmpl_add(priv_tmpl, CKA_PUBLIC_EXPONENT,
                           (const uint8_t *)pubexp->pValue,
                           (uint32_t)pubexp->ulValueLen);
    if (rc == CKR_OK)
        rc = ncmp_tmpl_add(priv_tmpl, CKA_PRIVATE_EXPONENT, comp[1], clen[1]);
    if (rc == CKR_OK)
        rc = ncmp_tmpl_add(priv_tmpl, CKA_PRIME_1, comp[2], clen[2]);
    if (rc == CKR_OK)
        rc = ncmp_tmpl_add(priv_tmpl, CKA_PRIME_2, comp[3], clen[3]);
    if (rc == CKR_OK)
        rc = ncmp_tmpl_add(priv_tmpl, CKA_EXPONENT_1, comp[4], clen[4]);
    if (rc == CKR_OK)
        rc = ncmp_tmpl_add(priv_tmpl, CKA_EXPONENT_2, comp[5], clen[5]);
    if (rc == CKR_OK)
        rc = ncmp_tmpl_add(priv_tmpl, CKA_COEFFICIENT, comp[6], clen[6]);

    free(outbuf);
    return rc;
}

CK_RV token_specific_ec_generate_keypair(STDLL_TokData_t *tokdata,
                                         TEMPLATE *publ_tmpl,
                                         TEMPLATE *priv_tmpl)
{
    struct ncmp_private_data *priv = tokdata->private_data;
    CK_ATTRIBUTE *params = NULL;
    uint8_t outbuf[256];
    const uint8_t *pin[1];
    uint32_t lin[1];
    NCMP_Message rsp;
    const uint8_t *point, *pval;
    uint32_t lpoint, lpval;
    CK_RV rc;
    int nrc;

    if (priv == NULL)
        return CKR_FUNCTION_FAILED;

    rc = template_attribute_get_non_empty(publ_tmpl, CKA_EC_PARAMS, &params);
    if (rc != CKR_OK)
        return rc;

    pin[0] = params->pValue; lin[0] = (uint32_t)params->ulValueLen;
    nrc = ncmp_client_command_mp(&priv->client, priv->ncmp_slot,
                                 NCMP_CMD_EC_KEYGEN, pin, lin, 1,
                                 outbuf, sizeof(outbuf), &rsp);
    if (nrc != NCMP_OK)
        return ncmp_err_to_ckr(nrc);
    if (rsp.header.ack != NCMP_CKR_OK)
        return (CK_RV)rsp.header.ack;

    if (ncmp_msg_param(&rsp, 0, &point, &lpoint) != NCMP_OK || lpoint == 0 ||
        ncmp_msg_param(&rsp, 1, &pval, &lpval) != NCMP_OK || lpval == 0)
        return CKR_FUNCTION_FAILED;

    /* Public key: EC point. Private key: curve params + private value + point. */
    rc = ncmp_tmpl_add(publ_tmpl, CKA_EC_POINT, point, lpoint);
    if (rc == CKR_OK)
        rc = ncmp_tmpl_add(priv_tmpl, CKA_EC_PARAMS,
                           (const uint8_t *)params->pValue,
                           (uint32_t)params->ulValueLen);
    if (rc == CKR_OK)
        rc = ncmp_tmpl_add(priv_tmpl, CKA_VALUE, pval, lpval);
    if (rc == CKR_OK)
        rc = ncmp_tmpl_add(priv_tmpl, CKA_EC_POINT, point, lpoint);

    return rc;
}

CK_RV token_specific_hmac_sign_init(STDLL_TokData_t *tokdata, SESSION *sess,
                                    CK_MECHANISM *mech, CK_OBJECT_HANDLE key)
{
    UNUSED(tokdata);
    UNUSED(sess);
    UNUSED(key);
    /* Key + mech live in sess->sign_ctx at one-shot time; just validate. */
    return (ncmp_hmac_size((uint32_t)mech->mechanism) != 0)
               ? CKR_OK : CKR_MECHANISM_INVALID;
}

CK_RV token_specific_hmac_verify_init(STDLL_TokData_t *tokdata, SESSION *sess,
                                      CK_MECHANISM *mech, CK_OBJECT_HANDLE key)
{
    UNUSED(tokdata);
    UNUSED(sess);
    UNUSED(key);
    return (ncmp_hmac_size((uint32_t)mech->mechanism) != 0)
               ? CKR_OK : CKR_MECHANISM_INVALID;
}

CK_RV token_specific_hmac_sign(STDLL_TokData_t *tokdata, SESSION *sess,
                               CK_BYTE *in_data, CK_ULONG in_data_len,
                               CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    struct ncmp_private_data *priv = tokdata->private_data;
    SIGN_VERIFY_CONTEXT *ctx = &sess->sign_ctx;
    uint32_t mech = (uint32_t)ctx->mech.mechanism;
    uint32_t hsize = ncmp_hmac_size(mech);
    OBJECT *key_obj = NULL;
    CK_ATTRIBUTE *kv = NULL;
    NCMP_Message rsp;
    const uint8_t *parts[3];
    uint32_t lens[3];
    uint8_t mechbuf[4];
    CK_RV rc;
    int nrc;

    if (priv == NULL || hsize == 0)
        return CKR_FUNCTION_FAILED;
    if (out_data == NULL || *out_data_len < hsize) {
        *out_data_len = hsize;
        return CKR_BUFFER_TOO_SMALL;
    }

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK)
        return rc;
    rc = template_attribute_get_non_empty(key_obj->template, CKA_VALUE, &kv);
    if (rc != CKR_OK) {
        object_put(tokdata, key_obj, TRUE);
        return rc;
    }

    ncmp_wr_u32le(mechbuf, mech);
    parts[0] = mechbuf;    lens[0] = sizeof(mechbuf);
    parts[1] = kv->pValue; lens[1] = (uint32_t)kv->ulValueLen;
    parts[2] = in_data;    lens[2] = (uint32_t)in_data_len;
    nrc = ncmp_client_command_mp(&priv->client, priv->ncmp_slot,
                                 NCMP_CMD_HMAC_SIGN, parts, lens, 3,
                                 out_data, (uint32_t)*out_data_len, &rsp);
    object_put(tokdata, key_obj, TRUE);

    if (nrc != NCMP_OK)
        return ncmp_err_to_ckr(nrc);
    if (rsp.header.ack != NCMP_CKR_OK)
        return (CK_RV)rsp.header.ack;
    if (rsp.param_len[0] != hsize)
        return CKR_FUNCTION_FAILED;
    *out_data_len = hsize;
    return CKR_OK;
}

CK_RV token_specific_hmac_verify(STDLL_TokData_t *tokdata, SESSION *sess,
                                 CK_BYTE *in_data, CK_ULONG in_data_len,
                                 CK_BYTE *signature, CK_ULONG sig_len)
{
    struct ncmp_private_data *priv = tokdata->private_data;
    SIGN_VERIFY_CONTEXT *ctx = &sess->verify_ctx;
    uint32_t mech = (uint32_t)ctx->mech.mechanism;
    OBJECT *key_obj = NULL;
    CK_ATTRIBUTE *kv = NULL;
    NCMP_Message rsp;
    const uint8_t *parts[4];
    uint32_t lens[4];
    uint8_t mechbuf[4];
    CK_RV rc;
    int nrc;

    if (priv == NULL || ncmp_hmac_size(mech) == 0)
        return CKR_FUNCTION_FAILED;

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK)
        return rc;
    rc = template_attribute_get_non_empty(key_obj->template, CKA_VALUE, &kv);
    if (rc != CKR_OK) {
        object_put(tokdata, key_obj, TRUE);
        return rc;
    }

    ncmp_wr_u32le(mechbuf, mech);
    parts[0] = mechbuf;    lens[0] = sizeof(mechbuf);
    parts[1] = kv->pValue; lens[1] = (uint32_t)kv->ulValueLen;
    parts[2] = in_data;    lens[2] = (uint32_t)in_data_len;
    parts[3] = signature;  lens[3] = (uint32_t)sig_len;
    nrc = ncmp_client_command_mp(&priv->client, priv->ncmp_slot,
                                 NCMP_CMD_HMAC_VERIFY, parts, lens, 4,
                                 NULL, 0, &rsp);
    object_put(tokdata, key_obj, TRUE);

    if (nrc != NCMP_OK)
        return ncmp_err_to_ckr(nrc);
    return (CK_RV)rsp.header.ack; /* CKR_OK or CKR_SIGNATURE_INVALID */
}

/** Forward an RSA-OAEP op resolving the key handle and modulus/exponent. */
static CK_RV ncmp_rsa_oaep(STDLL_TokData_t *tokdata,
                           struct ncmp_private_data *priv,
                           ENCR_DECR_CONTEXT *ctx, uint32_t opcode,
                           CK_ATTRIBUTE_TYPE exp_type, int need_modlen_out,
                           CK_BYTE *in, CK_ULONG in_len,
                           CK_BYTE *out, CK_ULONG *out_len)
{
    OBJECT *key_obj = NULL;
    CK_ATTRIBUTE *mod = NULL;
    CK_ATTRIBUTE *exp = NULL;
    NCMP_Message rsp;
    const uint8_t *parts[3];
    uint32_t lens[3];
    CK_RV rc;
    int nrc;

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK)
        return rc;
    rc = template_attribute_get_non_empty(key_obj->template, CKA_MODULUS, &mod);
    if (rc != CKR_OK)
        goto out;
    rc = template_attribute_get_non_empty(key_obj->template, exp_type, &exp);
    if (rc != CKR_OK)
        goto out;

    if (need_modlen_out && (out == NULL || *out_len < mod->ulValueLen)) {
        *out_len = mod->ulValueLen; /* ciphertext is one modulus long */
        rc = CKR_BUFFER_TOO_SMALL;
        goto out;
    }
    if (out == NULL) {
        rc = CKR_ARGUMENTS_BAD;
        goto out;
    }

    parts[0] = mod->pValue; lens[0] = (uint32_t)mod->ulValueLen;
    parts[1] = exp->pValue; lens[1] = (uint32_t)exp->ulValueLen;
    parts[2] = in;          lens[2] = (uint32_t)in_len;
    nrc = ncmp_client_command_mp(&priv->client, priv->ncmp_slot, opcode,
                                 parts, lens, 3, out, (uint32_t)*out_len, &rsp);
    if (nrc != NCMP_OK) {
        rc = ncmp_err_to_ckr(nrc);
        goto out;
    }
    if (rsp.header.ack != NCMP_CKR_OK) {
        rc = (CK_RV)rsp.header.ack;
        goto out;
    }
    *out_len = rsp.param_len[0];
    rc = CKR_OK;

out:
    object_put(tokdata, key_obj, TRUE);
    return rc;
}

CK_RV token_specific_rsa_oaep_encrypt(STDLL_TokData_t *tokdata,
                                      ENCR_DECR_CONTEXT *ctx, CK_BYTE *in_data,
                                      CK_ULONG in_data_len, CK_BYTE *out_data,
                                      CK_ULONG *out_data_len, CK_BYTE *hash,
                                      CK_ULONG hlen)
{
    struct ncmp_private_data *priv = tokdata->private_data;

    UNUSED(hash);
    UNUSED(hlen); /* mock ignores the OAEP label hash */

    if (priv == NULL)
        return CKR_FUNCTION_FAILED;
    return ncmp_rsa_oaep(tokdata, priv, ctx, NCMP_CMD_RSA_OAEP_ENC,
                         CKA_PUBLIC_EXPONENT, 1, in_data, in_data_len,
                         out_data, out_data_len);
}

CK_RV token_specific_rsa_oaep_decrypt(STDLL_TokData_t *tokdata,
                                      ENCR_DECR_CONTEXT *ctx, CK_BYTE *in_data,
                                      CK_ULONG in_data_len, CK_BYTE *out_data,
                                      CK_ULONG *out_data_len, CK_BYTE *hash,
                                      CK_ULONG hlen)
{
    struct ncmp_private_data *priv = tokdata->private_data;

    UNUSED(hash);
    UNUSED(hlen);

    if (priv == NULL)
        return CKR_FUNCTION_FAILED;
    return ncmp_rsa_oaep(tokdata, priv, ctx, NCMP_CMD_RSA_OAEP_DEC,
                         CKA_PRIVATE_EXPONENT, 0, in_data, in_data_len,
                         out_data, out_data_len);
}

CK_RV token_specific_rsa_pss_sign(STDLL_TokData_t *tokdata, SESSION *sess,
                                  SIGN_VERIFY_CONTEXT *ctx, CK_BYTE *in_data,
                                  CK_ULONG in_data_len, CK_BYTE *sig,
                                  CK_ULONG *sig_len)
{
    struct ncmp_private_data *priv = tokdata->private_data;
    OBJECT *key_obj = NULL;
    CK_ATTRIBUTE *mod = NULL;
    CK_ATTRIBUTE *exp = NULL;
    NCMP_Message rsp;
    const uint8_t *parts[3];
    uint32_t lens[3];
    CK_ULONG modlen;
    CK_RV rc;
    int nrc;

    UNUSED(sess);

    if (priv == NULL)
        return CKR_FUNCTION_FAILED;

    /* PSS signs with the private key; marshalling matches PKCS RSA sign. */
    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK)
        return rc;
    rc = template_attribute_get_non_empty(key_obj->template, CKA_MODULUS, &mod);
    if (rc != CKR_OK)
        goto out;
    rc = template_attribute_get_non_empty(key_obj->template,
                                          CKA_PRIVATE_EXPONENT, &exp);
    if (rc != CKR_OK)
        goto out;
    modlen = mod->ulValueLen;
    if (sig == NULL || *sig_len < modlen) {
        *sig_len = modlen;
        rc = CKR_BUFFER_TOO_SMALL;
        goto out;
    }

    parts[0] = mod->pValue; lens[0] = (uint32_t)modlen;
    parts[1] = exp->pValue; lens[1] = (uint32_t)exp->ulValueLen;
    parts[2] = in_data;     lens[2] = (uint32_t)in_data_len;
    nrc = ncmp_client_command_mp(&priv->client, priv->ncmp_slot,
                                 NCMP_CMD_RSA_SIGN, parts, lens, 3,
                                 sig, (uint32_t)*sig_len, &rsp);
    if (nrc != NCMP_OK) {
        rc = ncmp_err_to_ckr(nrc);
        goto out;
    }
    if (rsp.header.ack != NCMP_CKR_OK) {
        rc = (CK_RV)rsp.header.ack;
        goto out;
    }
    if (rsp.param_len[0] != modlen) {
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }
    *sig_len = modlen;
    rc = CKR_OK;

out:
    object_put(tokdata, key_obj, TRUE);
    return rc;
}

CK_RV token_specific_rsa_pss_verify(STDLL_TokData_t *tokdata, SESSION *sess,
                                    SIGN_VERIFY_CONTEXT *ctx, CK_BYTE *in_data,
                                    CK_ULONG in_data_len, CK_BYTE *signature,
                                    CK_ULONG sig_len)
{
    struct ncmp_private_data *priv = tokdata->private_data;
    OBJECT *key_obj = NULL;
    CK_ATTRIBUTE *mod = NULL;
    CK_ATTRIBUTE *exp = NULL;
    NCMP_Message rsp;
    const uint8_t *parts[4];
    uint32_t lens[4];
    CK_RV rc;
    int nrc;

    UNUSED(sess);

    if (priv == NULL)
        return CKR_FUNCTION_FAILED;

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK)
        return rc;
    rc = template_attribute_get_non_empty(key_obj->template, CKA_MODULUS, &mod);
    if (rc != CKR_OK)
        goto out;
    rc = template_attribute_get_non_empty(key_obj->template,
                                          CKA_PUBLIC_EXPONENT, &exp);
    if (rc != CKR_OK)
        goto out;

    parts[0] = mod->pValue; lens[0] = (uint32_t)mod->ulValueLen;
    parts[1] = exp->pValue; lens[1] = (uint32_t)exp->ulValueLen;
    parts[2] = in_data;     lens[2] = (uint32_t)in_data_len;
    parts[3] = signature;   lens[3] = (uint32_t)sig_len;
    nrc = ncmp_client_command_mp(&priv->client, priv->ncmp_slot,
                                 NCMP_CMD_RSA_VERIFY, parts, lens, 4,
                                 NULL, 0, &rsp);
    rc = (nrc != NCMP_OK) ? ncmp_err_to_ckr(nrc) : (CK_RV)rsp.header.ack;

out:
    object_put(tokdata, key_obj, TRUE);
    return rc;
}

CK_RV token_specific_dh_pkcs_derive(STDLL_TokData_t *tokdata, CK_BYTE *secret,
                                    CK_ULONG *secret_len, CK_BYTE *pub,
                                    CK_ULONG pub_len, CK_BYTE *priv_val,
                                    CK_ULONG priv_len, CK_BYTE *prime,
                                    CK_ULONG prime_len)
{
    struct ncmp_private_data *priv = tokdata->private_data;
    NCMP_Message rsp;
    const uint8_t *parts[3];
    uint32_t lens[3];
    int nrc;

    if (priv == NULL || secret == NULL)
        return CKR_FUNCTION_FAILED;

    /* Raw values (no object): [prime | own private | peer public]. */
    parts[0] = prime;    lens[0] = (uint32_t)prime_len;
    parts[1] = priv_val; lens[1] = (uint32_t)priv_len;
    parts[2] = pub;      lens[2] = (uint32_t)pub_len;
    nrc = ncmp_client_command_mp(&priv->client, priv->ncmp_slot,
                                 NCMP_CMD_DH_DERIVE, parts, lens, 3,
                                 secret, (uint32_t)*secret_len, &rsp);
    if (nrc != NCMP_OK)
        return ncmp_err_to_ckr(nrc);
    if (rsp.header.ack != NCMP_CKR_OK)
        return (CK_RV)rsp.header.ack;
    *secret_len = rsp.param_len[0];
    return CKR_OK;
}

CK_RV token_specific_ecdh_pkcs_derive(STDLL_TokData_t *tokdata, CK_BYTE *priv_val,
                                      CK_ULONG priv_len, CK_BYTE *pub,
                                      CK_ULONG pub_len, CK_BYTE *secret,
                                      CK_ULONG *secret_len, CK_BYTE *oid,
                                      CK_ULONG oid_len, CK_BBOOL flag)
{
    struct ncmp_private_data *priv = tokdata->private_data;
    NCMP_Message rsp;
    const uint8_t *parts[3];
    uint32_t lens[3];
    int nrc;

    UNUSED(flag);

    if (priv == NULL || secret == NULL)
        return CKR_FUNCTION_FAILED;

    parts[0] = oid;      lens[0] = (uint32_t)oid_len;
    parts[1] = priv_val; lens[1] = (uint32_t)priv_len;
    parts[2] = pub;      lens[2] = (uint32_t)pub_len;
    nrc = ncmp_client_command_mp(&priv->client, priv->ncmp_slot,
                                 NCMP_CMD_ECDH_DERIVE, parts, lens, 3,
                                 secret, (uint32_t)*secret_len, &rsp);
    if (nrc != NCMP_OK)
        return ncmp_err_to_ckr(nrc);
    if (rsp.header.ack != NCMP_CKR_OK)
        return (CK_RV)rsp.header.ack;
    *secret_len = rsp.param_len[0];
    return CKR_OK;
}

CK_RV token_specific_get_token_info(STDLL_TokData_t *tokdata,
                                    CK_TOKEN_INFO_PTR pInfo)
{
    UNUSED(tokdata);

    /* Report the NCMP token/firmware revision. TODO: query the FX3 firmware
     * for its actual version once that command is wired. */
    pInfo->firmwareVersion.major = 1;
    pInfo->firmwareVersion.minor = 0;
    pInfo->hardwareVersion.major = 1;
    pInfo->hardwareVersion.minor = 0;

    return CKR_OK;
}

CK_RV token_specific_get_mechanism_list(STDLL_TokData_t *tokdata,
                                        CK_MECHANISM_TYPE_PTR pMechanismList,
                                        CK_ULONG_PTR pulCount)
{
    return ock_generic_get_mechanism_list(tokdata, pMechanismList, pulCount,
                                          &ncmp_filter_mechanism);
}

CK_RV token_specific_get_mechanism_info(STDLL_TokData_t *tokdata,
                                        CK_MECHANISM_TYPE type,
                                        CK_MECHANISM_INFO_PTR pInfo)
{
    return ock_generic_get_mechanism_info(tokdata, type, pInfo,
                                          &ncmp_filter_mechanism);
}

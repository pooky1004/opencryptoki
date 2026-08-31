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
    { CKM_RSA_PKCS, { 512, 4096, CKF_ENCRYPT | CKF_DECRYPT |
                                 CKF_SIGN | CKF_VERIFY } },
    { CKM_ECDSA,    { 256, 521,  CKF_SIGN | CKF_VERIFY } },
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

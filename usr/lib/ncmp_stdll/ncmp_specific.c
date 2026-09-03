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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "platform.h"
#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "pqc_defs.h"
#include "errno.h"
#include "tok_specific.h"
#include "tok_struct.h"
#include "trace.h"

/* NCMP client + crypto/admin adapters + error-mapping API (ncmp/ subtree). */
#include "ncmp/ncmp_client.h"
#include "ncmp/ncmp_crypto.h"
#include "ncmp/ncmp_admin.h"
#include "ncmp/ncmp_slotmap.h"
#include "ncmp/ncmp_ckr.h"
#include "ncmp/ncmp_cmd.h"
#include "ncmp/ncmp_limits.h"
#include "ncmp/ncmp_errno.h"

/*
 * Token identity globals referenced by the common layer (key.c, utility.c).
 * Every STDLL must define these; see soft_specific.c for the pattern.
 */
const char manuf[] = "DYST";
const char model[] = "NCMP";
const char descr[] = "NCMP USB Token";
const char label[] = "ncmptok";

/** Per-token private state held in STDLL_TokData_t::private_data. */
struct ncmp_private_data {
    ncmp_client_t      client;    /**< Connection to ncmpd (socket + SHM). */
    uint32_t           ncmp_slot; /**< Physical NCMP slot backing this token. */
    int32_t            ck_slot;   /**< CK slot id this token was opened for. */
    NCMP_TokenIdentity identity;  /**< Cached identity of the bound token. */
};

/**
 * @brief Resolve the desired token label/serial for a CK slot from the
 *        environment.
 *
 * Per-slot overrides (NCMP_TOK_LABEL<n> / NCMP_TOK_SERIAL<n>) take precedence
 * over the generic NCMP_TOK_LABEL / NCMP_TOK_SERIAL. An unset value yields an
 * empty string ("no preference"), which makes ncmp_slot_bind() fall back to the
 * first unallocated online token. (A future ncmptok.conf file can supply the
 * same mapping; see docs/architecture.md.)
 */
static void ncmp_desired_identity(CK_SLOT_ID slot, char *label, size_t label_cap,
                                  char *serial, size_t serial_cap)
{
    char key[48];
    const char *v;

    label[0] = '\0';
    serial[0] = '\0';

    snprintf(key, sizeof(key), "NCMP_TOK_LABEL%lu", (unsigned long)slot);
    v = getenv(key);
    if (v == NULL)
        v = getenv("NCMP_TOK_LABEL");
    if (v != NULL)
        snprintf(label, label_cap, "%s", v);

    snprintf(key, sizeof(key), "NCMP_TOK_SERIAL%lu", (unsigned long)slot);
    v = getenv(key);
    if (v == NULL)
        v = getenv("NCMP_TOK_SERIAL");
    if (v != NULL)
        snprintf(serial, serial_cap, "%s", v);
}

/*
 * Mechanisms advertised by the NCMP token. This is the token's defined surface:
 *   - symmetric AEAD/stream : AES-GCM, AES-CTR
 *   - hash / XOF            : SHA-256, SHA-512, SHA3-{224,256,384,512},
 *                             SHAKE-128/256 key derivation
 *   - post-quantum          : ML-KEM (strength 1/3/5 via CKA_PARAMETER_SET;
 *                             key agreement) and ML-DSA (sign/verify)
 * AES key sizes are 16..32 bytes; PQC strengths are selected per key via
 * CKA_PARAMETER_SET (CKP_ML_{KEM,DSA}_*), so the min/max fields are left 0.
 */
static const MECH_LIST_ELEMENT ncmp_mech_list[] = {
    /* Symmetric. */
    { CKM_AES_GCM,  { 16,  32,   CKF_ENCRYPT | CKF_DECRYPT } },
    { CKM_AES_CTR,  { 16,  32,   CKF_ENCRYPT | CKF_DECRYPT } },
    /* Hash. */
    { CKM_SHA256,   { 0,   0,    CKF_DIGEST } },
    { CKM_SHA512,   { 0,   0,    CKF_DIGEST } },
    { CKM_SHA3_224, { 0,   0,    CKF_DIGEST } },
    { CKM_SHA3_256, { 0,   0,    CKF_DIGEST } },
    { CKM_SHA3_384, { 0,   0,    CKF_DIGEST } },
    { CKM_SHA3_512, { 0,   0,    CKF_DIGEST } },
    /* XOF (SHAKE) key derivation. */
    { CKM_SHAKE_128_KEY_DERIVATION, { 0, 0, CKF_DERIVE } },
    { CKM_SHAKE_256_KEY_DERIVATION, { 0, 0, CKF_DERIVE } },
    /* Post-quantum KEM (key agreement) + keypair generation. */
    { CKM_ML_KEM_KEY_PAIR_GEN, { 0, 0, CKF_GENERATE_KEY_PAIR } },
    { CKM_ML_KEM,   { 0,   0,    CKF_ENCAPSULATE | CKF_DECAPSULATE } },
    /* Post-quantum signature + keypair generation. */
    { CKM_ML_DSA_KEY_PAIR_GEN, { 0, 0, CKF_GENERATE_KEY_PAIR } },
    { CKM_ML_DSA,   { 0,   0,    CKF_SIGN | CKF_VERIFY } },
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
     * Bind this CK slot to a physical NCMP token. The daemon has already scanned
     * each device's identity into SHM; ncmp_slot_bind() matches the configured
     * label or serial against the online tokens and, failing a match, claims the
     * first unallocated one. The binding is keyed by CK slot id and shared in
     * SHM, so every process opening this CK slot resolves to the same token.
     */
    if (priv->client.slot_mask == 0) {
        TRACE_ERROR("ncmp: daemon reports no online slots\n");
        rc = CKR_TOKEN_NOT_PRESENT;
        ncmp_client_fini(&priv->client);
        free(priv);
        goto error;
    }

    {
        char want_label[NCMP_TI_LABEL_LEN + 1];
        char want_serial[NCMP_TI_SERIAL_LEN + 1];
        uint32_t phys = 0;
        int nrc2;

        ncmp_desired_identity(SlotNumber, want_label, sizeof(want_label),
                              want_serial, sizeof(want_serial));
        priv->ck_slot = (int32_t)SlotNumber;
        nrc2 = ncmp_slot_bind(priv->client.shm_base, priv->client.slot_mask,
                              priv->ck_slot, want_label, want_serial, &phys);
        if (nrc2 != NCMP_OK) {
            rc = ncmp_err_to_ckr(nrc2);
            TRACE_ERROR("ncmp_slot_bind failed (ncmp rc=%d -> ck 0x%lx)\n",
                        nrc2, rc);
            ncmp_client_fini(&priv->client);
            free(priv);
            goto error;
        }
        priv->ncmp_slot = phys;
        TRACE_INFO("ncmp: CK slot %lu -> physical slot %u\n",
                   (unsigned long)SlotNumber, phys);
    }

    /* Cache the bound token's identity for get_token_info (best-effort: the
     * daemon may not have completed the identity scan). */
    (void)ncmp_slot_get_identity(priv->client.shm_base, priv->ncmp_slot,
                                 &priv->identity);

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
        /* The CK-slot -> physical-slot binding intentionally persists in SHM
         * for the daemon's lifetime (other processes may still use this slot);
         * only the per-process client is torn down here. */
        ncmp_client_fini(&priv->client);
        free(priv);
        tokdata->private_data = NULL;
    }

    return CKR_OK;
}

/** Best-effort memory scrub that the optimizer may not elide (no OpenSSL dep). */
static void ncmp_secure_zero(void *p, size_t n)
{
    volatile unsigned char *v = (volatile unsigned char *)p;

    while (n--)
        *v++ = 0;
}

/** Map a PKCS#11 CK_USER_TYPE to the wire user type. */
static uint32_t ncmp_wire_user_type(CK_USER_TYPE user_type)
{
    switch (user_type) {
    case CKU_SO:               return NCMP_CKU_SO;
    case CKU_CONTEXT_SPECIFIC: return NCMP_CKU_CONTEXT_SPECIFIC;
    default:                   return NCMP_CKU_USER;
    }
}

CK_RV token_specific_login(STDLL_TokData_t *tokdata, SESSION *sess,
                           CK_USER_TYPE user_type, CK_CHAR_PTR pin,
                           CK_ULONG pin_len)
{
    struct ncmp_private_data *priv = tokdata->private_data;
    uint32_t flags = NCMP_LOGIN_FLAG_NONE;

    UNUSED(sess);

    if (priv == NULL)
        return CKR_FUNCTION_FAILED;

    /*
     * Beyond the SO/User role, fold in the other conditions the login must
     * consider:
     *   - a NULL PIN (or the token flagging CKF_PROTECTED_AUTHENTICATION_PATH)
     *     means the PIN is entered on the token's own pad -> protected-auth;
     *   - CKU_CONTEXT_SPECIFIC re-authenticates the already-logged-in user
     *     (PKCS#11 CKA_ALWAYS_AUTHENTICATE) rather than opening a new session.
     */
    if (pin == NULL ||
        (tokdata->nv_token_data->token_info.flags &
         CKF_PROTECTED_AUTHENTICATION_PATH) != 0)
        flags |= NCMP_LOGIN_FLAG_PROTECTED_AUTH;
    if (user_type == CKU_CONTEXT_SPECIFIC)
        flags |= NCMP_LOGIN_FLAG_CONTEXT;

    return ncmp_admin_login(&priv->client, priv->ncmp_slot,
                            ncmp_wire_user_type(user_type), flags,
                            (const uint8_t *)pin, (uint32_t)pin_len);
}

CK_RV token_specific_logout(STDLL_TokData_t *tokdata)
{
    struct ncmp_private_data *priv = tokdata->private_data;

    if (priv == NULL)
        return CKR_FUNCTION_FAILED;

    return ncmp_admin_logout(&priv->client, priv->ncmp_slot);
}

CK_RV token_specific_init_pin(STDLL_TokData_t *tokdata, SESSION *sess,
                              CK_CHAR_PTR pin, CK_ULONG pin_len)
{
    struct ncmp_private_data *priv = tokdata->private_data;

    UNUSED(sess);

    if (priv == NULL)
        return CKR_FUNCTION_FAILED;

    return ncmp_admin_init_pin(&priv->client, priv->ncmp_slot,
                               (const uint8_t *)pin, (uint32_t)pin_len);
}

CK_RV token_specific_set_pin(STDLL_TokData_t *tokdata, SESSION *sess,
                             CK_CHAR_PTR old_pin, CK_ULONG old_len,
                             CK_CHAR_PTR new_pin, CK_ULONG new_len)
{
    struct ncmp_private_data *priv = tokdata->private_data;

    UNUSED(sess);

    if (priv == NULL)
        return CKR_FUNCTION_FAILED;

    return ncmp_admin_set_pin(&priv->client, priv->ncmp_slot,
                              (const uint8_t *)old_pin, (uint32_t)old_len,
                              (const uint8_t *)new_pin, (uint32_t)new_len);
}

/* Forward decl: defined in the token-reporting section below. */
static void ncmp_copy_padded(CK_CHAR *dst, size_t dst_len, const char *src,
                             size_t src_cap);

/** Length of @p s within @p cap, excluding trailing spaces and NULs. */
static size_t ncmp_trim_len(const char *s, size_t cap)
{
    size_t n = 0;

    while (n < cap && s[n] != '\0')
        ++n;
    while (n > 0 && s[n - 1] == ' ')
        --n;
    return n;
}

/** Copy the scanned identity into the STDLL's nv_token_data->token_info. */
static void ncmp_apply_identity(STDLL_TokData_t *tokdata,
                                const NCMP_TokenIdentity *id)
{
    CK_TOKEN_INFO_32 *ti = &tokdata->nv_token_data->token_info;

    ncmp_copy_padded(ti->label, sizeof(ti->label), id->label,
                     NCMP_TI_LABEL_LEN);
    ncmp_copy_padded(ti->manufacturerID, sizeof(ti->manufacturerID),
                     id->manufacturer, NCMP_TI_MANUF_LEN);
    ncmp_copy_padded(ti->model, sizeof(ti->model), id->model, NCMP_TI_MODEL_LEN);
    ncmp_copy_padded(ti->serialNumber, sizeof(ti->serialNumber), id->serial,
                     NCMP_TI_SERIAL_LEN);
    ti->hardwareVersion.major = id->hw_major;
    ti->hardwareVersion.minor = id->hw_minor;
    ti->firmwareVersion.major = id->fw_major;
    ti->firmwareVersion.minor = id->fw_minor;
    ti->flags |= CKF_TOKEN_INITIALIZED;
    ti->flags &= ~(CKF_USER_PIN_INITIALIZED | CKF_USER_PIN_LOCKED |
                   CKF_USER_PIN_FINAL_TRY | CKF_USER_PIN_COUNT_LOW);
}

CK_RV token_specific_init_token(STDLL_TokData_t *tokdata, CK_SLOT_ID sid,
                                CK_CHAR_PTR pin, CK_ULONG pin_len,
                                CK_CHAR_PTR label)
{
    struct ncmp_private_data *priv = tokdata->private_data;
    char lbl[NCMP_TI_LABEL_LEN + 1];
    uint8_t *pinbuf = NULL;
    NCMP_TokenIdentity id;
    unsigned long arc;
    CK_RV rc;

    if (priv == NULL)
        return CKR_FUNCTION_FAILED;

    /* The label arrives as a 32-byte space-padded field; forward it as a string
     * (the admin adapter re-pads to the fixed wire width). */
    memcpy(lbl, label, NCMP_TI_LABEL_LEN);
    lbl[NCMP_TI_LABEL_LEN] = '\0';

    /* Work on a private copy of the SO PIN so the temporary can be scrubbed
     * before returning (only the token must retain the secret). */
    if (pin_len > 0) {
        pinbuf = (uint8_t *)malloc(pin_len);
        if (pinbuf == NULL)
            return CKR_HOST_MEMORY;
        memcpy(pinbuf, pin, pin_len);
    }

    /* 1) Set the SO PIN + label on the physical token. */
    arc = ncmp_admin_init_token(&priv->client, priv->ncmp_slot, pinbuf,
                                (uint32_t)pin_len, lbl);
    if (arc != CKR_OK) {
        rc = (CK_RV)arc;
        goto out;
    }

    /* 2) Read the identity back and validate the label round-tripped exactly. */
    arc = ncmp_admin_token_info(&priv->client, priv->ncmp_slot, &id);
    if (arc != CKR_OK) {
        rc = (CK_RV)arc;
        goto out;
    }
    {
        size_t want = ncmp_trim_len(lbl, NCMP_TI_LABEL_LEN);
        size_t got = ncmp_trim_len(id.label, NCMP_TI_LABEL_LEN);

        if (want != got || memcmp(lbl, id.label, want) != 0) {
            TRACE_ERROR("ncmp: init_token label readback mismatch\n");
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }
    }

    /* 3) Cache the validated identity and persist it in nv_token_data. */
    priv->identity = id;
    ncmp_apply_identity(tokdata, &id);
    rc = save_token_data(tokdata, sid);

out:
    /* Scrub every temporary that touched the PIN / label material. */
    if (pinbuf != NULL) {
        ncmp_secure_zero(pinbuf, pin_len);
        free(pinbuf);
    }
    ncmp_secure_zero(lbl, sizeof(lbl));
    ncmp_secure_zero(&id, sizeof(id));
    return rc;
}

CK_RV token_specific_init_token_data(STDLL_TokData_t *tokdata,
                                     CK_SLOT_ID slot_id)
{
    struct ncmp_private_data *priv = tokdata->private_data;
    CK_RV rc;

    UNUSED(slot_id);

    /* Cache the physical token's identity (scanned in t_init) into the freshly
     * initialized nv_token_data so label/serial/versions reflect the device. */
    if (priv != NULL && priv->identity.valid)
        ncmp_apply_identity(tokdata, &priv->identity);

    /* Providing this hook replaces the common layer's default master-key setup,
     * so generate and persist the master key the same way it would. */
    rc = generate_master_key(tokdata, tokdata->master_key);
    if (rc != CKR_OK) {
        TRACE_ERROR("ncmp: generate_master_key failed rc=0x%lx\n", rc);
        return CKR_FUNCTION_FAILED;
    }
    return save_masterkey_so(tokdata);
}

/*
 * The STDLL keeps no extra on-disk state beyond the standard nv_token_data, so
 * the load/save hooks are pass-throughs: they exist to satisfy the secure-key
 * data-store contract and give the token a place to (de)serialize device state
 * alongside the common record in the future.
 */
CK_RV token_specific_load_token_data(STDLL_TokData_t *tokdata,
                                     CK_SLOT_ID slot_id, FILE *fh)
{
    UNUSED(tokdata);
    UNUSED(slot_id);
    UNUSED(fh);
    return CKR_OK;
}

CK_RV token_specific_save_token_data(STDLL_TokData_t *tokdata,
                                     CK_SLOT_ID slot_id, FILE *fh)
{
    UNUSED(tokdata);
    UNUSED(slot_id);
    UNUSED(fh);
    return CKR_OK;
}

CK_RV token_specific_rng(STDLL_TokData_t *tokdata, CK_BYTE *output,
                         CK_ULONG bytes)
{
    struct ncmp_private_data *priv = tokdata->private_data;
    CK_ULONG done = 0;

    if (priv == NULL)
        return CKR_FUNCTION_FAILED;

    /* Forward to the token in <=32KB parameter-sized chunks. The adapter checks
     * for a short response and maps transport errors. */
    while (done < bytes) {
        CK_ULONG remaining = bytes - done;
        uint32_t chunk = (remaining > NCMP_MAX_PARAM_SIZE)
                             ? NCMP_MAX_PARAM_SIZE : (uint32_t)remaining;
        CK_RV rv = ncmp_crypto_rng(&priv->client, priv->ncmp_slot,
                                   (uint8_t *)output + done, chunk);
        if (rv != CKR_OK)
            return rv;
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
    uint32_t id = 0;
    CK_RV rv;

    if (*idp != NCMP_DIGEST_CTX_NONE) {
        *out_id = *idp;
        return CKR_OK;
    }

    rv = ncmp_crypto_digest_init(&priv->client, priv->ncmp_slot,
                                 (uint32_t)ctx->mech.mechanism, &id);
    if (rv != CKR_OK)
        return rv;

    *idp = id;
    *out_id = id;
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
        CK_RV rv = ncmp_crypto_digest_update(&priv->client, priv->ncmp_slot, id,
                                             in_data + done, chunk);
        if (rv != CKR_OK)
            return rv;
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
    CK_RV rc;

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

    rc = ncmp_crypto_digest_final(&priv->client, priv->ncmp_slot, id, out_data,
                                  (uint32_t)*out_data_len, &out_len);
    if (rc != CKR_OK)
        return rc;
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
    uint32_t out_len = 0;
    CK_RV rc;

    if (priv == NULL || hsize == 0)
        return CKR_FUNCTION_FAILED;
    /* One-shot input must fit one wire parameter (mech prefix + data). Larger
     * inputs need the multipart path (t_sha_update/final), added later. */
    if ((CK_ULONG)4 + in_data_len > NCMP_MAX_PARAM_SIZE)
        return CKR_DATA_LEN_RANGE;

    rc = ncmp_crypto_digest(&priv->client, priv->ncmp_slot, mech, in_data,
                            (uint32_t)in_data_len, out_data, hsize, &out_len);
    if (rc != CKR_OK)
        return rc;
    if (out_len != hsize)
        return CKR_FUNCTION_FAILED;

    *out_data_len = hsize;
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
    uint32_t taglen;
    uint32_t out_len = 0;
    CK_ULONG expected_out;
    CK_RV rc;

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

    rc = ncmp_crypto_aes_gcm(&priv->client, priv->ncmp_slot, encrypt,
                             key_attr->pValue, (uint32_t)key_attr->ulValueLen,
                             gcm->pIv, (uint32_t)gcm->ulIvLen, gcm->pAAD,
                             (uint32_t)gcm->ulAADLen, taglen, in_data,
                             (uint32_t)in_data_len, out_data,
                             (uint32_t)*out_data_len, &out_len);
    object_put(tokdata, key_obj, TRUE);

    if (rc != CKR_OK)
        return rc;
    if (out_len != expected_out)
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
    uint32_t out_len = 0;
    CK_RV rc;

    rc = template_attribute_get_non_empty(key->template, CKA_VALUE, &key_attr);
    if (rc != CKR_OK)
        return rc;

    rc = ncmp_crypto_aes_stream(&priv->client, priv->ncmp_slot, opcode, encrypt,
                                key_attr->pValue,
                                (uint32_t)key_attr->ulValueLen, iv,
                                (uint32_t)iv_len, in_data,
                                (uint32_t)in_data_len, out_data,
                                (uint32_t)out_cap, &out_len);
    if (rc != CKR_OK)
        return rc;
    if (out_len != in_data_len)
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

/** Fill @p buf with @p len random bytes generated by the token (RNG opcode). */
static CK_RV ncmp_gen_random(struct ncmp_private_data *priv, CK_BYTE *buf,
                             CK_ULONG len)
{
    if (len == 0 || len > NCMP_MAX_PARAM_SIZE)
        return CKR_KEY_SIZE_RANGE;

    return ncmp_crypto_rng(&priv->client, priv->ncmp_slot, buf, (uint32_t)len);
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

/* ------------------------------------------------------------------------- *
 * XOF (SHAKE) key derivation and post-quantum (ML-DSA / ML-KEM).
 *
 * PQC keys are forwarded as opaque blobs stored whole in CKA_VALUE; the private
 * blob carries the public blob as its prefix so the token's sign/verify and
 * encaps/decaps agree. Blob sizes come from the resolved parameter set. The
 * shared secret produced by ML-KEM is always 32 bytes (NIST FIPS 203).
 * ------------------------------------------------------------------------- */

/** ML-KEM shared-secret size in bytes (FIPS 203). */
#define NCMP_MLKEM_SS_LEN 32u

/** Whole-blob sizes (bytes) the proxy stores for an ML-DSA parameter set. */
static void ncmp_mldsa_lens(const struct pqc_oid *oid, uint32_t *pub_len,
                            uint32_t *priv_len, uint32_t *sig_len)
{
    *pub_len = (uint32_t)(oid->len_info.ml_dsa.rho_len +
                          oid->len_info.ml_dsa.t1_len);
    *priv_len = (uint32_t)(oid->len_info.ml_dsa.rho_len +
                           oid->len_info.ml_dsa.tr_len +
                           oid->len_info.ml_dsa.s1_len +
                           oid->len_info.ml_dsa.s2_len +
                           oid->len_info.ml_dsa.t0_len);
    switch (oid->keyform) {
    case CKP_ML_DSA_44: *sig_len = 2420; break;
    case CKP_ML_DSA_65: *sig_len = 3309; break;
    case CKP_ML_DSA_87: *sig_len = 4627; break;
    default:            *sig_len = 0;    break;
    }
}

/** Whole-blob sizes (bytes) the proxy stores for an ML-KEM parameter set. */
static void ncmp_mlkem_lens(const struct pqc_oid *oid, uint32_t *pub_len,
                            uint32_t *priv_len, uint32_t *ct_len)
{
    *pub_len = (uint32_t)oid->len_info.ml_kem.pk_len;
    *priv_len = (uint32_t)oid->len_info.ml_kem.sk_len;
    *ct_len = (uint32_t)oid->len_info.ml_kem.ct_len;
}

CK_RV token_specific_ml_dsa_generate_keypair(STDLL_TokData_t *tokdata,
                                             const struct pqc_oid *oid,
                                             TEMPLATE *publ_tmpl,
                                             TEMPLATE *priv_tmpl)
{
    struct ncmp_private_data *priv = tokdata->private_data;
    uint32_t pub_len, priv_len, sig_len;
    CK_BYTE *pub = NULL, *prv = NULL;
    CK_RV rc;

    if (priv == NULL)
        return CKR_FUNCTION_FAILED;
    ncmp_mldsa_lens(oid, &pub_len, &priv_len, &sig_len);
    if (pub_len == 0 || priv_len <= pub_len)
        return CKR_MECHANISM_PARAM_INVALID;

    pub = malloc(pub_len);
    prv = malloc(priv_len);
    if (pub == NULL || prv == NULL) {
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    rc = ncmp_crypto_mldsa_keygen(&priv->client, priv->ncmp_slot,
                                  (uint32_t)oid->keyform, pub_len, priv_len,
                                  pub, prv);
    if (rc != CKR_OK)
        goto out;

    rc = template_build_update_attribute(publ_tmpl, CKA_VALUE, pub, pub_len);
    if (rc != CKR_OK)
        goto out;
    rc = template_build_update_attribute(priv_tmpl, CKA_VALUE, prv, priv_len);
    if (rc != CKR_OK)
        goto out;
    /* Persist the parameter set so sign/verify can re-resolve the OID. */
    rc = pqc_add_keyform_mode(publ_tmpl, oid, CKM_ML_DSA_KEY_PAIR_GEN);
    if (rc != CKR_OK)
        goto out;
    rc = pqc_add_keyform_mode(priv_tmpl, oid, CKM_ML_DSA_KEY_PAIR_GEN);

out:
    free(pub);
    free(prv);
    return rc;
}

CK_RV token_specific_ml_dsa_sign(STDLL_TokData_t *tokdata, SESSION *sess,
                                 CK_BBOOL length_only,
                                 const struct pqc_oid *oid, CK_MECHANISM *mech,
                                 CK_BYTE *in_data, CK_ULONG in_data_len,
                                 CK_BYTE *sig, CK_ULONG *sig_len,
                                 OBJECT *key_obj, CK_BBOOL final_part)
{
    struct ncmp_private_data *priv = tokdata->private_data;
    uint32_t pub_len, priv_len, exp_sig_len, out_len = 0;
    CK_ATTRIBUTE *val = NULL;
    CK_RV rc;

    UNUSED(sess);
    UNUSED(mech);
    UNUSED(final_part);

    if (priv == NULL)
        return CKR_FUNCTION_FAILED;
    ncmp_mldsa_lens(oid, &pub_len, &priv_len, &exp_sig_len);
    if (exp_sig_len == 0)
        return CKR_MECHANISM_PARAM_INVALID;

    if (length_only) {
        *sig_len = exp_sig_len;
        return CKR_OK;
    }
    if (*sig_len < exp_sig_len) {
        *sig_len = exp_sig_len;
        return CKR_BUFFER_TOO_SMALL;
    }

    rc = template_attribute_get_non_empty(key_obj->template, CKA_VALUE, &val);
    if (rc != CKR_OK)
        return rc;

    rc = ncmp_crypto_mldsa_sign(&priv->client, priv->ncmp_slot,
                                (uint32_t)oid->keyform, pub_len, exp_sig_len,
                                val->pValue, (uint32_t)val->ulValueLen,
                                in_data, (uint32_t)in_data_len, sig, &out_len);
    if (rc != CKR_OK)
        return rc;
    *sig_len = out_len;
    return CKR_OK;
}

CK_RV token_specific_ml_dsa_verify(STDLL_TokData_t *tokdata, SESSION *sess,
                                   const struct pqc_oid *oid,
                                   CK_MECHANISM *mech, CK_BYTE *in_data,
                                   CK_ULONG in_data_len, CK_BYTE *signature,
                                   CK_ULONG signature_len, OBJECT *key_obj,
                                   CK_BBOOL final_part)
{
    struct ncmp_private_data *priv = tokdata->private_data;
    CK_ATTRIBUTE *val = NULL;
    CK_RV rc;

    UNUSED(sess);
    UNUSED(mech);
    UNUSED(final_part);

    if (priv == NULL)
        return CKR_FUNCTION_FAILED;

    rc = template_attribute_get_non_empty(key_obj->template, CKA_VALUE, &val);
    if (rc != CKR_OK)
        return rc;

    return ncmp_crypto_mldsa_verify(&priv->client, priv->ncmp_slot,
                                    (uint32_t)oid->keyform, val->pValue,
                                    (uint32_t)val->ulValueLen, in_data,
                                    (uint32_t)in_data_len, signature,
                                    (uint32_t)signature_len);
}

CK_RV token_specific_ml_kem_generate_keypair(STDLL_TokData_t *tokdata,
                                             const struct pqc_oid *oid,
                                             TEMPLATE *publ_tmpl,
                                             TEMPLATE *priv_tmpl)
{
    struct ncmp_private_data *priv = tokdata->private_data;
    uint32_t pub_len, priv_len, ct_len;
    CK_BYTE *pub = NULL, *prv = NULL;
    CK_RV rc;

    if (priv == NULL)
        return CKR_FUNCTION_FAILED;
    ncmp_mlkem_lens(oid, &pub_len, &priv_len, &ct_len);
    if (pub_len == 0 || priv_len <= pub_len)
        return CKR_MECHANISM_PARAM_INVALID;

    pub = malloc(pub_len);
    prv = malloc(priv_len);
    if (pub == NULL || prv == NULL) {
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    rc = ncmp_crypto_mlkem_keygen(&priv->client, priv->ncmp_slot,
                                  (uint32_t)oid->keyform, pub_len, priv_len,
                                  pub, prv);
    if (rc != CKR_OK)
        goto out;

    rc = template_build_update_attribute(publ_tmpl, CKA_VALUE, pub, pub_len);
    if (rc != CKR_OK)
        goto out;
    rc = template_build_update_attribute(priv_tmpl, CKA_VALUE, prv, priv_len);
    if (rc != CKR_OK)
        goto out;
    rc = pqc_add_keyform_mode(publ_tmpl, oid, CKM_ML_KEM_KEY_PAIR_GEN);
    if (rc != CKR_OK)
        goto out;
    rc = pqc_add_keyform_mode(priv_tmpl, oid, CKM_ML_KEM_KEY_PAIR_GEN);

out:
    free(pub);
    free(prv);
    return rc;
}

/** Build the shared-secret CKO_SECRET_KEY object from @p secret (encaps/decaps). */
static CK_RV ncmp_mlkem_make_secret(STDLL_TokData_t *tokdata, SESSION *sess,
                                    CK_ATTRIBUTE *pTemplate,
                                    CK_ULONG ulAttributeCount, CK_ULONG mode,
                                    CK_KEY_TYPE keytype, CK_ULONG keylen,
                                    const CK_BYTE *secret, CK_ULONG secret_len,
                                    CK_OBJECT_HANDLE *phKey)
{
    OBJECT *new_key_obj = NULL;
    CK_RV rc;

    if (keylen > secret_len)
        return CKR_TEMPLATE_INCONSISTENT;

    rc = object_mgr_create_skel(tokdata, sess, pTemplate, ulAttributeCount,
                                mode, CKO_SECRET_KEY, keytype, &new_key_obj);
    if (rc != CKR_OK)
        return rc;

    rc = template_build_update_attribute(new_key_obj->template, CKA_VALUE,
                                         (CK_BYTE *)secret, keylen);
    if (rc != CKR_OK)
        goto err;

    switch (keytype) {
    case CKK_GENERIC_SECRET:
    case CKK_AES:
    case CKK_AES_XTS:
        rc = template_build_update_attribute(new_key_obj->template,
                                             CKA_VALUE_LEN, (CK_BYTE *)&keylen,
                                             sizeof(keylen));
        if (rc != CKR_OK)
            goto err;
        break;
    default:
        break;
    }

    rc = object_mgr_create_final(tokdata, sess, new_key_obj, phKey);
    if (rc != CKR_OK)
        goto err;
    return CKR_OK;

err:
    object_free(new_key_obj);
    if (phKey != NULL)
        *phKey = CK_INVALID_HANDLE;
    return rc;
}

CK_RV token_specific_ml_kem_encapsulate_key(STDLL_TokData_t *tokdata,
                                            SESSION *sess, CK_BBOOL length_only,
                                            const struct pqc_oid *oid,
                                            CK_MECHANISM *mech, OBJECT *key_obj,
                                            CK_ATTRIBUTE *pTemplate,
                                            CK_ULONG ulAttributeCount,
                                            CK_BYTE *pCiphertext,
                                            CK_ULONG *pulCiphertextLen,
                                            CK_KEY_TYPE keytype, CK_ULONG keylen,
                                            CK_OBJECT_HANDLE *phKey)
{
    struct ncmp_private_data *priv = tokdata->private_data;
    uint32_t pub_len, priv_len, ct_len;
    CK_ATTRIBUTE *val = NULL;
    CK_BYTE ss[NCMP_MLKEM_SS_LEN];
    CK_RV rc;

    UNUSED(mech);

    if (priv == NULL)
        return CKR_FUNCTION_FAILED;
    ncmp_mlkem_lens(oid, &pub_len, &priv_len, &ct_len);

    if (length_only) {
        *pulCiphertextLen = ct_len;
        return CKR_OK;
    }
    if (*pulCiphertextLen < ct_len) {
        *pulCiphertextLen = ct_len;
        return CKR_BUFFER_TOO_SMALL;
    }

    rc = template_attribute_get_non_empty(key_obj->template, CKA_VALUE, &val);
    if (rc != CKR_OK)
        return rc;

    rc = ncmp_crypto_mlkem_encaps(&priv->client, priv->ncmp_slot,
                                  (uint32_t)oid->keyform, val->pValue,
                                  (uint32_t)val->ulValueLen, ct_len,
                                  NCMP_MLKEM_SS_LEN, pCiphertext, ss);
    if (rc != CKR_OK)
        return rc;
    *pulCiphertextLen = ct_len;

    return ncmp_mlkem_make_secret(tokdata, sess, pTemplate, ulAttributeCount,
                                  MODE_ENCAPS, keytype, keylen, ss,
                                  NCMP_MLKEM_SS_LEN, phKey);
}

CK_RV token_specific_ml_kem_decapsulate_key(STDLL_TokData_t *tokdata,
                                            SESSION *sess,
                                            const struct pqc_oid *oid,
                                            CK_MECHANISM *mech, OBJECT *key_obj,
                                            CK_ATTRIBUTE *pTemplate,
                                            CK_ULONG ulAttributeCount,
                                            CK_BYTE *pCiphertext,
                                            CK_ULONG ulCiphertextLen,
                                            CK_KEY_TYPE keytype, CK_ULONG keylen,
                                            CK_OBJECT_HANDLE *phKey)
{
    struct ncmp_private_data *priv = tokdata->private_data;
    uint32_t pub_len, priv_len, ct_len;
    CK_ATTRIBUTE *val = NULL;
    CK_BYTE ss[NCMP_MLKEM_SS_LEN];
    CK_RV rc;

    UNUSED(mech);

    if (priv == NULL)
        return CKR_FUNCTION_FAILED;
    ncmp_mlkem_lens(oid, &pub_len, &priv_len, &ct_len);

    rc = template_attribute_get_non_empty(key_obj->template, CKA_VALUE, &val);
    if (rc != CKR_OK)
        return rc;

    rc = ncmp_crypto_mlkem_decaps(&priv->client, priv->ncmp_slot,
                                  (uint32_t)oid->keyform, pub_len, val->pValue,
                                  (uint32_t)val->ulValueLen, pCiphertext,
                                  (uint32_t)ulCiphertextLen, NCMP_MLKEM_SS_LEN,
                                  ss);
    if (rc != CKR_OK)
        return rc;

    return ncmp_mlkem_make_secret(tokdata, sess, pTemplate, ulAttributeCount,
                                  MODE_DECAPS, keytype, keylen, ss,
                                  NCMP_MLKEM_SS_LEN, phKey);
}

CK_RV token_specific_shake_key_derive(STDLL_TokData_t *tokdata, SESSION *sess,
                                      CK_MECHANISM *mech, OBJECT *base_key_obj,
                                      CK_KEY_TYPE base_key_type,
                                      OBJECT *derived_key_obj,
                                      CK_KEY_TYPE derived_key_type,
                                      CK_ULONG derived_key_len)
{
    struct ncmp_private_data *priv = tokdata->private_data;
    CK_ATTRIBUTE *base_val = NULL;
    CK_BYTE *derived = NULL;
    CK_RV rc;

    UNUSED(sess);
    UNUSED(base_key_type);

    if (priv == NULL)
        return CKR_FUNCTION_FAILED;
    if (derived_key_len == 0 || derived_key_len > NCMP_MAX_PARAM_SIZE)
        return CKR_KEY_SIZE_RANGE;

    rc = template_attribute_get_non_empty(base_key_obj->template, CKA_VALUE,
                                          &base_val);
    if (rc != CKR_OK)
        return rc;

    derived = malloc(derived_key_len);
    if (derived == NULL)
        return CKR_HOST_MEMORY;

    rc = ncmp_crypto_shake_derive(&priv->client, priv->ncmp_slot,
                                  (uint32_t)mech->mechanism, base_val->pValue,
                                  (uint32_t)base_val->ulValueLen, derived,
                                  (uint32_t)derived_key_len);
    if (rc != CKR_OK)
        goto out;

    rc = template_build_update_attribute(derived_key_obj->template, CKA_VALUE,
                                         derived, derived_key_len);
    if (rc != CKR_OK)
        goto out;

    switch (derived_key_type) {
    case CKK_GENERIC_SECRET:
    case CKK_AES:
    case CKK_AES_XTS:
    case CKK_SHA_1_HMAC:
    case CKK_SHA224_HMAC:
    case CKK_SHA256_HMAC:
    case CKK_SHA384_HMAC:
    case CKK_SHA512_HMAC:
        rc = template_build_update_attribute(derived_key_obj->template,
                                             CKA_VALUE_LEN,
                                             (CK_BYTE *)&derived_key_len,
                                             sizeof(derived_key_len));
        break;
    default:
        break;
    }

out:
    free(derived);
    return rc;
}

/** Copy a NUL-padded identity field into a space-padded CK_TOKEN_INFO field. */
static void ncmp_copy_padded(CK_CHAR *dst, size_t dst_len, const char *src,
                             size_t src_cap)
{
    size_t n;

    for (n = 0; n < src_cap && n < dst_len && src[n] != '\0'; ++n)
        dst[n] = (CK_CHAR)src[n];
    for (; n < dst_len; ++n)
        dst[n] = ' ';
}

CK_RV token_specific_get_token_info(STDLL_TokData_t *tokdata,
                                    CK_TOKEN_INFO_PTR pInfo)
{
    struct ncmp_private_data *priv = tokdata->private_data;

    /*
     * Report the identity the daemon scanned from the physical token. The common
     * layer has already populated label/manufacturer/model/serial from the token
     * globals; override them with the live values (and the real versions) when a
     * valid identity was cached.
     */
    if (priv != NULL && priv->identity.valid) {
        const NCMP_TokenIdentity *id = &priv->identity;

        ncmp_copy_padded(pInfo->manufacturerID, sizeof(pInfo->manufacturerID),
                         id->manufacturer, NCMP_TI_MANUF_LEN);
        ncmp_copy_padded(pInfo->model, sizeof(pInfo->model), id->model,
                         NCMP_TI_MODEL_LEN);
        ncmp_copy_padded(pInfo->serialNumber, sizeof(pInfo->serialNumber),
                         id->serial, NCMP_TI_SERIAL_LEN);
        pInfo->hardwareVersion.major = id->hw_major;
        pInfo->hardwareVersion.minor = id->hw_minor;
        pInfo->firmwareVersion.major = id->fw_major;
        pInfo->firmwareVersion.minor = id->fw_minor;
    } else {
        pInfo->firmwareVersion.major = 1;
        pInfo->firmwareVersion.minor = 0;
        pInfo->hardwareVersion.major = 1;
        pInfo->hardwareVersion.minor = 0;
    }

    /*
     * Override the PIN-length bounds and UTC time with the values the physical
     * token reports (GET_TOKEN_PARAMS / GET_UTC_TIME). Best-effort: keep the
     * common-layer defaults if the token cannot be reached.
     */
    if (priv != NULL) {
        uint32_t minp = 0, maxp = 0;
        uint8_t utc[NCMP_TOKEN_UTC_LEN];

        if (ncmp_admin_get_token_params(&priv->client, priv->ncmp_slot, NULL,
                                        NULL, &minp, &maxp) == CKR_OK) {
            pInfo->ulMinPinLen = minp;
            pInfo->ulMaxPinLen = maxp;
        }
        if (ncmp_admin_get_utc_time(&priv->client, priv->ncmp_slot, utc)
                == CKR_OK)
            memcpy(pInfo->utcTime, utc, NCMP_TOKEN_UTC_LEN);
    }

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

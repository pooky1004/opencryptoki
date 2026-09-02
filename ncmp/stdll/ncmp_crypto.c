/*
 * Token NCMP - STDLL crypto marshalling adapter (implementation).
 *
 * Every function turns already-extracted key material and data buffers into the
 * NCMP wire parameter layout and forwards them to the token via the client
 * transport. The token's CKR_* ACK (or a mapped transport error) is returned;
 * see ncmp_crypto.h for the return-value contract.
 */
#include "ncmp/ncmp_crypto.h"
#include "ncmp/ncmp_cmd.h"
#include "ncmp/ncmp_ckr.h"
#include "ncmp/ncmp_wire.h"
#include "ncmp/ncmp_limits.h"
#include "ncmp/ncmp_errno.h"

#include <stdlib.h>
#include <string.h>

/**
 * @brief Run a single-parameter command and surface the token's status.
 * @return NCMP_CKR_OK / token ACK / mapped transport error. @p out_len (if not
 *         NULL) receives the response parameter-0 length on a completed
 *         round-trip.
 */
static unsigned long crypto_cmd(ncmp_client_t *c, uint32_t slot, uint32_t opcode,
                                const uint8_t *in, uint32_t in_len, uint8_t *out,
                                uint32_t out_cap, uint32_t *out_len)
{
    uint32_t ack = 0;
    uint32_t got = 0;
    int nrc;

    nrc = ncmp_client_command(c, slot, opcode, in, in_len, out, out_cap,
                              &got, &ack);
    if (nrc != NCMP_OK)
        return ncmp_err_to_ckr(nrc);
    if (out_len)
        *out_len = got;
    return ack;
}

/**
 * @brief Run a multi-parameter command and surface the token's status.
 * @return NCMP_CKR_OK / token ACK / mapped transport error. @p rsp (if not
 *         NULL) receives the decoded response so multi-output callers can read
 *         each parameter via ncmp_msg_param().
 */
static unsigned long crypto_cmd_mp(ncmp_client_t *c, uint32_t slot,
                                   uint32_t opcode, const uint8_t *const parts[],
                                   const uint32_t lens[], int n, uint8_t *out,
                                   uint32_t out_cap, NCMP_Message *rsp)
{
    NCMP_Message local;
    NCMP_Message *r = rsp ? rsp : &local;
    int nrc;

    nrc = ncmp_client_command_mp(c, slot, opcode, parts, lens, n, out, out_cap,
                                 r);
    if (nrc != NCMP_OK)
        return ncmp_err_to_ckr(nrc);
    return r->header.ack;
}

unsigned long ncmp_crypto_rng(ncmp_client_t *c, uint32_t slot, uint8_t *out,
                              uint32_t out_len)
{
    uint8_t lenbuf[4];
    uint32_t got = 0;
    unsigned long rv;

    if (out == NULL || out_len == 0 || out_len > NCMP_MAX_PARAM_SIZE)
        return NCMP_CKR_ARGUMENTS_BAD;

    ncmp_wr_u32le(lenbuf, out_len);
    rv = crypto_cmd(c, slot, NCMP_CMD_RNG, lenbuf, sizeof(lenbuf), out, out_len,
                    &got);
    if (rv != NCMP_CKR_OK)
        return rv;
    return (got == out_len) ? NCMP_CKR_OK : NCMP_CKR_FUNCTION_FAILED;
}

unsigned long ncmp_crypto_digest(ncmp_client_t *c, uint32_t slot, uint32_t mech,
                                 const uint8_t *data, uint32_t data_len,
                                 uint8_t *out, uint32_t out_cap,
                                 uint32_t *out_len)
{
    uint8_t *req;
    uint32_t req_len;
    unsigned long rv;

    if ((uint64_t)4 + data_len > NCMP_MAX_PARAM_SIZE)
        return NCMP_CKR_ARGUMENTS_BAD;

    req_len = 4 + data_len;
    req = (uint8_t *)malloc(req_len);
    if (req == NULL)
        return NCMP_CKR_DEVICE_MEMORY;

    ncmp_wr_u32le(req, mech);
    if (data_len > 0)
        memcpy(req + 4, data, data_len);

    rv = crypto_cmd(c, slot, NCMP_CMD_DIGEST, req, req_len, out, out_cap,
                    out_len);
    free(req);
    return rv;
}

unsigned long ncmp_crypto_digest_init(ncmp_client_t *c, uint32_t slot,
                                      uint32_t mech, uint32_t *ctx_id)
{
    uint8_t mechbuf[4];
    uint8_t idbuf[4];
    uint32_t got = 0;
    unsigned long rv;

    if (ctx_id == NULL)
        return NCMP_CKR_ARGUMENTS_BAD;

    ncmp_wr_u32le(mechbuf, mech);
    rv = crypto_cmd(c, slot, NCMP_CMD_DIGEST_INIT, mechbuf, sizeof(mechbuf),
                    idbuf, sizeof(idbuf), &got);
    if (rv != NCMP_CKR_OK)
        return rv;
    if (got != sizeof(idbuf))
        return NCMP_CKR_FUNCTION_FAILED;

    *ctx_id = ncmp_rd_u32le(idbuf);
    return NCMP_CKR_OK;
}

unsigned long ncmp_crypto_digest_update(ncmp_client_t *c, uint32_t slot,
                                        uint32_t ctx_id, const uint8_t *data,
                                        uint32_t data_len)
{
    const uint8_t *parts[2];
    uint32_t lens[2];
    uint8_t idbuf[4];

    ncmp_wr_u32le(idbuf, ctx_id);
    parts[0] = idbuf; lens[0] = sizeof(idbuf);
    parts[1] = data;  lens[1] = data_len;
    return crypto_cmd_mp(c, slot, NCMP_CMD_DIGEST_UPDATE, parts, lens, 2, NULL,
                         0, NULL);
}

unsigned long ncmp_crypto_digest_final(ncmp_client_t *c, uint32_t slot,
                                       uint32_t ctx_id, uint8_t *out,
                                       uint32_t out_cap, uint32_t *out_len)
{
    uint8_t idbuf[4];

    ncmp_wr_u32le(idbuf, ctx_id);
    return crypto_cmd(c, slot, NCMP_CMD_DIGEST_FINAL, idbuf, sizeof(idbuf), out,
                      out_cap, out_len);
}

unsigned long ncmp_crypto_aes_ecb(ncmp_client_t *c, uint32_t slot, int encrypt,
                                  const uint8_t *key, uint32_t key_len,
                                  const uint8_t *in, uint32_t in_len,
                                  uint8_t *out, uint32_t out_cap,
                                  uint32_t *out_len)
{
    const uint8_t *parts[3];
    uint32_t lens[3];
    uint8_t flags[4];
    NCMP_Message rsp;
    unsigned long rv;

    ncmp_wr_u32le(flags, encrypt ? NCMP_AES_FLAG_ENCRYPT : 0u);
    parts[0] = flags; lens[0] = sizeof(flags);
    parts[1] = key;   lens[1] = key_len;
    parts[2] = in;    lens[2] = in_len;

    rv = crypto_cmd_mp(c, slot, NCMP_CMD_AES_ECB, parts, lens, 3, out, out_cap,
                       &rsp);
    if (rv == NCMP_CKR_OK && out_len)
        *out_len = rsp.param_len[0];
    return rv;
}

unsigned long ncmp_crypto_aes_cbc(ncmp_client_t *c, uint32_t slot, int encrypt,
                                  const uint8_t *key, uint32_t key_len,
                                  const uint8_t *iv, uint32_t iv_len,
                                  const uint8_t *in, uint32_t in_len,
                                  uint8_t *out, uint32_t out_cap,
                                  uint32_t *out_len)
{
    const uint8_t *parts[4];
    uint32_t lens[4];
    uint8_t flags[4];
    NCMP_Message rsp;
    unsigned long rv;

    ncmp_wr_u32le(flags, encrypt ? NCMP_AES_FLAG_ENCRYPT : 0u);
    parts[0] = flags; lens[0] = sizeof(flags);
    parts[1] = key;   lens[1] = key_len;
    parts[2] = iv;    lens[2] = iv_len;
    parts[3] = in;    lens[3] = in_len;

    rv = crypto_cmd_mp(c, slot, NCMP_CMD_AES_CBC, parts, lens, 4, out, out_cap,
                       &rsp);
    if (rv == NCMP_CKR_OK && out_len)
        *out_len = rsp.param_len[0];
    return rv;
}

unsigned long ncmp_crypto_aes_stream(ncmp_client_t *c, uint32_t slot,
                                     uint32_t opcode, int encrypt,
                                     const uint8_t *key, uint32_t key_len,
                                     const uint8_t *iv, uint32_t iv_len,
                                     const uint8_t *in, uint32_t in_len,
                                     uint8_t *out, uint32_t out_cap,
                                     uint32_t *out_len)
{
    const uint8_t *parts[4];
    uint32_t lens[4];
    uint8_t flags[4];
    NCMP_Message rsp;
    unsigned long rv;

    ncmp_wr_u32le(flags, encrypt ? NCMP_AES_FLAG_ENCRYPT : 0u);
    parts[0] = flags; lens[0] = sizeof(flags);
    parts[1] = key;   lens[1] = key_len;
    parts[2] = iv;    lens[2] = iv_len;
    parts[3] = in;    lens[3] = in_len;

    rv = crypto_cmd_mp(c, slot, opcode, parts, lens, 4, out, out_cap, &rsp);
    if (rv == NCMP_CKR_OK && out_len)
        *out_len = rsp.param_len[0];
    return rv;
}

unsigned long ncmp_crypto_aes_gcm(ncmp_client_t *c, uint32_t slot, int encrypt,
                                  const uint8_t *key, uint32_t key_len,
                                  const uint8_t *iv, uint32_t iv_len,
                                  const uint8_t *aad, uint32_t aad_len,
                                  uint32_t tag_len, const uint8_t *in,
                                  uint32_t in_len, uint8_t *out,
                                  uint32_t out_cap, uint32_t *out_len)
{
    const uint8_t *parts[6];
    uint32_t lens[6];
    uint8_t flags[4];
    uint8_t tlbuf[4];
    NCMP_Message rsp;
    unsigned long rv;

    ncmp_wr_u32le(flags, encrypt ? NCMP_AES_FLAG_ENCRYPT : 0u);
    ncmp_wr_u32le(tlbuf, tag_len);
    parts[0] = flags; lens[0] = sizeof(flags);
    parts[1] = key;   lens[1] = key_len;
    parts[2] = iv;    lens[2] = iv_len;
    parts[3] = aad;   lens[3] = aad_len;
    parts[4] = tlbuf; lens[4] = sizeof(tlbuf);
    parts[5] = in;    lens[5] = in_len;

    rv = crypto_cmd_mp(c, slot, NCMP_CMD_AES_GCM, parts, lens, 6, out, out_cap,
                       &rsp);
    if (rv == NCMP_CKR_OK && out_len)
        *out_len = rsp.param_len[0];
    return rv;
}

unsigned long ncmp_crypto_rsa_sign(ncmp_client_t *c, uint32_t slot,
                                   const uint8_t *mod, uint32_t mod_len,
                                   const uint8_t *exp, uint32_t exp_len,
                                   const uint8_t *data, uint32_t data_len,
                                   uint8_t *out, uint32_t out_cap,
                                   uint32_t *out_len)
{
    const uint8_t *parts[3];
    uint32_t lens[3];
    NCMP_Message rsp;
    unsigned long rv;

    parts[0] = mod;  lens[0] = mod_len;
    parts[1] = exp;  lens[1] = exp_len;
    parts[2] = data; lens[2] = data_len;

    rv = crypto_cmd_mp(c, slot, NCMP_CMD_RSA_SIGN, parts, lens, 3, out, out_cap,
                       &rsp);
    if (rv == NCMP_CKR_OK && out_len)
        *out_len = rsp.param_len[0];
    return rv;
}

unsigned long ncmp_crypto_rsa_verify(ncmp_client_t *c, uint32_t slot,
                                     const uint8_t *mod, uint32_t mod_len,
                                     const uint8_t *exp, uint32_t exp_len,
                                     const uint8_t *data, uint32_t data_len,
                                     const uint8_t *sig, uint32_t sig_len)
{
    const uint8_t *parts[4];
    uint32_t lens[4];

    parts[0] = mod;  lens[0] = mod_len;
    parts[1] = exp;  lens[1] = exp_len;
    parts[2] = data; lens[2] = data_len;
    parts[3] = sig;  lens[3] = sig_len;

    return crypto_cmd_mp(c, slot, NCMP_CMD_RSA_VERIFY, parts, lens, 4, NULL, 0,
                         NULL);
}

unsigned long ncmp_crypto_rsa_oaep(ncmp_client_t *c, uint32_t slot,
                                   uint32_t opcode, const uint8_t *mod,
                                   uint32_t mod_len, const uint8_t *exp,
                                   uint32_t exp_len, const uint8_t *in,
                                   uint32_t in_len, uint8_t *out,
                                   uint32_t out_cap, uint32_t *out_len)
{
    const uint8_t *parts[3];
    uint32_t lens[3];
    NCMP_Message rsp;
    unsigned long rv;

    parts[0] = mod; lens[0] = mod_len;
    parts[1] = exp; lens[1] = exp_len;
    parts[2] = in;  lens[2] = in_len;

    rv = crypto_cmd_mp(c, slot, opcode, parts, lens, 3, out, out_cap, &rsp);
    if (rv == NCMP_CKR_OK && out_len)
        *out_len = rsp.param_len[0];
    return rv;
}

unsigned long ncmp_crypto_ec_sign(ncmp_client_t *c, uint32_t slot,
                                  const uint8_t *ec_params,
                                  uint32_t ec_params_len, const uint8_t *priv,
                                  uint32_t priv_len, const uint8_t *data,
                                  uint32_t data_len, uint8_t *out,
                                  uint32_t out_cap, uint32_t *out_len)
{
    const uint8_t *parts[3];
    uint32_t lens[3];
    NCMP_Message rsp;
    unsigned long rv;

    parts[0] = ec_params; lens[0] = ec_params_len;
    parts[1] = priv;      lens[1] = priv_len;
    parts[2] = data;      lens[2] = data_len;

    rv = crypto_cmd_mp(c, slot, NCMP_CMD_EC_SIGN, parts, lens, 3, out, out_cap,
                       &rsp);
    if (rv == NCMP_CKR_OK && out_len)
        *out_len = rsp.param_len[0];
    return rv;
}

unsigned long ncmp_crypto_ec_verify(ncmp_client_t *c, uint32_t slot,
                                    const uint8_t *ec_params,
                                    uint32_t ec_params_len,
                                    const uint8_t *ec_point,
                                    uint32_t ec_point_len, const uint8_t *data,
                                    uint32_t data_len, const uint8_t *sig,
                                    uint32_t sig_len)
{
    const uint8_t *parts[4];
    uint32_t lens[4];

    parts[0] = ec_params; lens[0] = ec_params_len;
    parts[1] = ec_point;  lens[1] = ec_point_len;
    parts[2] = data;      lens[2] = data_len;
    parts[3] = sig;       lens[3] = sig_len;

    return crypto_cmd_mp(c, slot, NCMP_CMD_EC_VERIFY, parts, lens, 4, NULL, 0,
                         NULL);
}

unsigned long ncmp_crypto_hmac_sign(ncmp_client_t *c, uint32_t slot,
                                    uint32_t mech, const uint8_t *key,
                                    uint32_t key_len, const uint8_t *data,
                                    uint32_t data_len, uint8_t *out,
                                    uint32_t out_cap, uint32_t *out_len)
{
    const uint8_t *parts[3];
    uint32_t lens[3];
    uint8_t mechbuf[4];
    NCMP_Message rsp;
    unsigned long rv;

    ncmp_wr_u32le(mechbuf, mech);
    parts[0] = mechbuf; lens[0] = sizeof(mechbuf);
    parts[1] = key;     lens[1] = key_len;
    parts[2] = data;    lens[2] = data_len;

    rv = crypto_cmd_mp(c, slot, NCMP_CMD_HMAC_SIGN, parts, lens, 3, out, out_cap,
                       &rsp);
    if (rv == NCMP_CKR_OK && out_len)
        *out_len = rsp.param_len[0];
    return rv;
}

unsigned long ncmp_crypto_hmac_verify(ncmp_client_t *c, uint32_t slot,
                                      uint32_t mech, const uint8_t *key,
                                      uint32_t key_len, const uint8_t *data,
                                      uint32_t data_len, const uint8_t *mac,
                                      uint32_t mac_len)
{
    const uint8_t *parts[4];
    uint32_t lens[4];
    uint8_t mechbuf[4];

    ncmp_wr_u32le(mechbuf, mech);
    parts[0] = mechbuf; lens[0] = sizeof(mechbuf);
    parts[1] = key;     lens[1] = key_len;
    parts[2] = data;    lens[2] = data_len;
    parts[3] = mac;     lens[3] = mac_len;

    return crypto_cmd_mp(c, slot, NCMP_CMD_HMAC_VERIFY, parts, lens, 4, NULL, 0,
                         NULL);
}

unsigned long ncmp_crypto_rsa_keygen(ncmp_client_t *c, uint32_t slot,
                                     uint32_t mod_bits, const uint8_t *pub_exp,
                                     uint32_t pub_exp_len, uint8_t *scratch,
                                     uint32_t scratch_cap,
                                     ncmp_rsa_keypair_t *out)
{
    const uint8_t *parts[2];
    uint32_t lens[2];
    uint8_t bitsbuf[4];
    NCMP_Message rsp;
    const uint8_t *comp[7];
    uint32_t clen[7];
    unsigned long rv;

    if (out == NULL)
        return NCMP_CKR_ARGUMENTS_BAD;

    ncmp_wr_u32le(bitsbuf, mod_bits);
    parts[0] = bitsbuf; lens[0] = sizeof(bitsbuf);
    parts[1] = pub_exp; lens[1] = pub_exp_len;

    rv = crypto_cmd_mp(c, slot, NCMP_CMD_RSA_KEYGEN, parts, lens, 2, scratch,
                       scratch_cap, &rsp);
    if (rv != NCMP_CKR_OK)
        return rv;

    for (int i = 0; i < 7; ++i) {
        if (ncmp_msg_param(&rsp, i, &comp[i], &clen[i]) != NCMP_OK ||
            clen[i] == 0)
            return NCMP_CKR_FUNCTION_FAILED;
    }

    out->modulus  = comp[0]; out->modulus_len  = clen[0];
    out->priv_exp = comp[1]; out->priv_exp_len = clen[1];
    out->prime1   = comp[2]; out->prime1_len   = clen[2];
    out->prime2   = comp[3]; out->prime2_len   = clen[3];
    out->exp1     = comp[4]; out->exp1_len     = clen[4];
    out->exp2     = comp[5]; out->exp2_len     = clen[5];
    out->coeff    = comp[6]; out->coeff_len    = clen[6];
    return NCMP_CKR_OK;
}

unsigned long ncmp_crypto_ec_keygen(ncmp_client_t *c, uint32_t slot,
                                    const uint8_t *ec_params,
                                    uint32_t ec_params_len, uint8_t *scratch,
                                    uint32_t scratch_cap, ncmp_ec_keypair_t *out)
{
    const uint8_t *parts[1];
    uint32_t lens[1];
    NCMP_Message rsp;
    const uint8_t *point, *pval;
    uint32_t lpoint, lpval;
    unsigned long rv;

    if (out == NULL)
        return NCMP_CKR_ARGUMENTS_BAD;

    parts[0] = ec_params; lens[0] = ec_params_len;
    rv = crypto_cmd_mp(c, slot, NCMP_CMD_EC_KEYGEN, parts, lens, 1, scratch,
                       scratch_cap, &rsp);
    if (rv != NCMP_CKR_OK)
        return rv;

    if (ncmp_msg_param(&rsp, 0, &point, &lpoint) != NCMP_OK || lpoint == 0 ||
        ncmp_msg_param(&rsp, 1, &pval, &lpval) != NCMP_OK || lpval == 0)
        return NCMP_CKR_FUNCTION_FAILED;

    out->ec_point = point; out->ec_point_len = lpoint;
    out->priv     = pval;  out->priv_len     = lpval;
    return NCMP_CKR_OK;
}

unsigned long ncmp_crypto_dh_derive(ncmp_client_t *c, uint32_t slot,
                                    const uint8_t *prime, uint32_t prime_len,
                                    const uint8_t *priv, uint32_t priv_len,
                                    const uint8_t *peer_pub,
                                    uint32_t peer_pub_len, uint8_t *out,
                                    uint32_t out_cap, uint32_t *out_len)
{
    const uint8_t *parts[3];
    uint32_t lens[3];
    NCMP_Message rsp;
    unsigned long rv;

    parts[0] = prime;    lens[0] = prime_len;
    parts[1] = priv;     lens[1] = priv_len;
    parts[2] = peer_pub; lens[2] = peer_pub_len;

    rv = crypto_cmd_mp(c, slot, NCMP_CMD_DH_DERIVE, parts, lens, 3, out, out_cap,
                       &rsp);
    if (rv == NCMP_CKR_OK && out_len)
        *out_len = rsp.param_len[0];
    return rv;
}

unsigned long ncmp_crypto_ecdh_derive(ncmp_client_t *c, uint32_t slot,
                                      const uint8_t *ec_params,
                                      uint32_t ec_params_len,
                                      const uint8_t *priv, uint32_t priv_len,
                                      const uint8_t *peer_point,
                                      uint32_t peer_point_len, uint8_t *out,
                                      uint32_t out_cap, uint32_t *out_len)
{
    const uint8_t *parts[3];
    uint32_t lens[3];
    NCMP_Message rsp;
    unsigned long rv;

    parts[0] = ec_params;  lens[0] = ec_params_len;
    parts[1] = priv;       lens[1] = priv_len;
    parts[2] = peer_point; lens[2] = peer_point_len;

    rv = crypto_cmd_mp(c, slot, NCMP_CMD_ECDH_DERIVE, parts, lens, 3, out,
                       out_cap, &rsp);
    if (rv == NCMP_CKR_OK && out_len)
        *out_len = rsp.param_len[0];
    return rv;
}

/* ------------------------------------------------------------------------- *
 * XOF (SHAKE) + post-quantum (ML-DSA / ML-KEM).
 * ------------------------------------------------------------------------- */

unsigned long ncmp_crypto_shake_derive(ncmp_client_t *c, uint32_t slot,
                                       uint32_t mech, const uint8_t *base,
                                       uint32_t base_len, uint8_t *out,
                                       uint32_t out_len)
{
    uint8_t mbuf[4], lbuf[4];
    const uint8_t *parts[3];
    uint32_t lens[3];
    NCMP_Message rsp;
    const uint8_t *d;
    uint32_t dl;
    unsigned long rv;

    if (out == NULL || out_len == 0 || out_len > NCMP_MAX_PARAM_SIZE)
        return NCMP_CKR_ARGUMENTS_BAD;

    ncmp_wr_u32le(mbuf, mech);
    ncmp_wr_u32le(lbuf, out_len);
    parts[0] = mbuf; lens[0] = 4;
    parts[1] = lbuf; lens[1] = 4;
    parts[2] = base; lens[2] = base_len;
    rv = crypto_cmd_mp(c, slot, NCMP_CMD_SHAKE_DERIVE, parts, lens, 3, out,
                       out_len, &rsp);
    if (rv != NCMP_CKR_OK)
        return rv;
    if (ncmp_msg_param(&rsp, 0, &d, &dl) != NCMP_OK || dl != out_len)
        return NCMP_CKR_FUNCTION_FAILED;
    return NCMP_CKR_OK;
}

/** Shared [set|len_a|len_b] -> [blob_a|blob_b] keygen for ML-DSA and ML-KEM. */
static unsigned long pqc_keygen(ncmp_client_t *c, uint32_t slot, uint32_t opcode,
                                uint32_t paramset, uint32_t a_len,
                                uint32_t b_len, uint8_t *a, uint8_t *b)
{
    uint8_t sbuf[4], albuf[4], blbuf[4];
    const uint8_t *parts[3];
    uint32_t lens[3];
    NCMP_Message rsp;
    const uint8_t *pa, *pb;
    uint32_t la, lb;
    uint8_t *scratch;
    unsigned long rv;

    if (a == NULL || b == NULL || a_len == 0 || b_len == 0)
        return NCMP_CKR_ARGUMENTS_BAD;
    if ((uint64_t)a_len + b_len > NCMP_MAX_PAYLOAD_SIZE)
        return NCMP_CKR_ARGUMENTS_BAD;

    scratch = (uint8_t *)malloc((size_t)a_len + b_len);
    if (scratch == NULL)
        return NCMP_CKR_DEVICE_MEMORY;

    ncmp_wr_u32le(sbuf, paramset);
    ncmp_wr_u32le(albuf, a_len);
    ncmp_wr_u32le(blbuf, b_len);
    parts[0] = sbuf;  lens[0] = 4;
    parts[1] = albuf; lens[1] = 4;
    parts[2] = blbuf; lens[2] = 4;
    rv = crypto_cmd_mp(c, slot, opcode, parts, lens, 3, scratch,
                       a_len + b_len, &rsp);
    if (rv != NCMP_CKR_OK)
        goto out;
    if (ncmp_msg_param(&rsp, 0, &pa, &la) != NCMP_OK || la != a_len ||
        ncmp_msg_param(&rsp, 1, &pb, &lb) != NCMP_OK || lb != b_len) {
        rv = NCMP_CKR_FUNCTION_FAILED;
        goto out;
    }
    memcpy(a, pa, a_len);
    memcpy(b, pb, b_len);

out:
    free(scratch);
    return rv;
}

unsigned long ncmp_crypto_mldsa_keygen(ncmp_client_t *c, uint32_t slot,
                                       uint32_t paramset, uint32_t pub_len,
                                       uint32_t priv_len, uint8_t *pub,
                                       uint8_t *priv)
{
    return pqc_keygen(c, slot, NCMP_CMD_MLDSA_KEYGEN, paramset, pub_len,
                      priv_len, pub, priv);
}

unsigned long ncmp_crypto_mlkem_keygen(ncmp_client_t *c, uint32_t slot,
                                       uint32_t paramset, uint32_t pub_len,
                                       uint32_t priv_len, uint8_t *pub,
                                       uint8_t *priv)
{
    return pqc_keygen(c, slot, NCMP_CMD_MLKEM_KEYGEN, paramset, pub_len,
                      priv_len, pub, priv);
}

unsigned long ncmp_crypto_mldsa_sign(ncmp_client_t *c, uint32_t slot,
                                     uint32_t paramset, uint32_t pub_len,
                                     uint32_t sig_len, const uint8_t *priv,
                                     uint32_t priv_len, const uint8_t *data,
                                     uint32_t data_len, uint8_t *sig,
                                     uint32_t *out_sig_len)
{
    uint8_t sbuf[4], plbuf[4], slbuf[4];
    const uint8_t *parts[5];
    uint32_t lens[5];
    NCMP_Message rsp;
    const uint8_t *ps;
    uint32_t ls;
    unsigned long rv;

    if (sig == NULL || sig_len == 0 || sig_len > NCMP_MAX_PARAM_SIZE)
        return NCMP_CKR_ARGUMENTS_BAD;

    ncmp_wr_u32le(sbuf, paramset);
    ncmp_wr_u32le(plbuf, pub_len);
    ncmp_wr_u32le(slbuf, sig_len);
    parts[0] = sbuf;  lens[0] = 4;
    parts[1] = plbuf; lens[1] = 4;
    parts[2] = slbuf; lens[2] = 4;
    parts[3] = priv;  lens[3] = priv_len;
    parts[4] = data;  lens[4] = data_len;
    rv = crypto_cmd_mp(c, slot, NCMP_CMD_MLDSA_SIGN, parts, lens, 5, sig,
                       sig_len, &rsp);
    if (rv != NCMP_CKR_OK)
        return rv;
    if (ncmp_msg_param(&rsp, 0, &ps, &ls) != NCMP_OK || ls == 0)
        return NCMP_CKR_FUNCTION_FAILED;
    if (out_sig_len)
        *out_sig_len = ls;
    return NCMP_CKR_OK;
}

unsigned long ncmp_crypto_mldsa_verify(ncmp_client_t *c, uint32_t slot,
                                       uint32_t paramset, const uint8_t *pub,
                                       uint32_t pub_len, const uint8_t *data,
                                       uint32_t data_len, const uint8_t *sig,
                                       uint32_t sig_len)
{
    uint8_t sbuf[4];
    uint8_t rspbuf[8];
    const uint8_t *parts[4];
    uint32_t lens[4];
    NCMP_Message rsp;

    ncmp_wr_u32le(sbuf, paramset);
    parts[0] = sbuf; lens[0] = 4;
    parts[1] = pub;  lens[1] = pub_len;
    parts[2] = data; lens[2] = data_len;
    parts[3] = sig;  lens[3] = sig_len;
    return crypto_cmd_mp(c, slot, NCMP_CMD_MLDSA_VERIFY, parts, lens, 4, rspbuf,
                         sizeof(rspbuf), &rsp);
}

unsigned long ncmp_crypto_mlkem_encaps(ncmp_client_t *c, uint32_t slot,
                                       uint32_t paramset, const uint8_t *pub,
                                       uint32_t pub_len, uint32_t ct_len,
                                       uint32_t ss_len, uint8_t *ct,
                                       uint8_t *ss)
{
    uint8_t sbuf[4], clbuf[4], slbuf[4];
    const uint8_t *parts[4];
    uint32_t lens[4];
    NCMP_Message rsp;
    const uint8_t *pct, *pss;
    uint32_t lct, lss;
    uint8_t *scratch;
    unsigned long rv;

    if (ct == NULL || ss == NULL || ct_len == 0 || ss_len == 0)
        return NCMP_CKR_ARGUMENTS_BAD;
    if ((uint64_t)ct_len + ss_len > NCMP_MAX_PAYLOAD_SIZE)
        return NCMP_CKR_ARGUMENTS_BAD;

    scratch = (uint8_t *)malloc((size_t)ct_len + ss_len);
    if (scratch == NULL)
        return NCMP_CKR_DEVICE_MEMORY;

    ncmp_wr_u32le(sbuf, paramset);
    ncmp_wr_u32le(clbuf, ct_len);
    ncmp_wr_u32le(slbuf, ss_len);
    parts[0] = sbuf;  lens[0] = 4;
    parts[1] = clbuf; lens[1] = 4;
    parts[2] = slbuf; lens[2] = 4;
    parts[3] = pub;   lens[3] = pub_len;
    rv = crypto_cmd_mp(c, slot, NCMP_CMD_MLKEM_ENCAPS, parts, lens, 4, scratch,
                       ct_len + ss_len, &rsp);
    if (rv != NCMP_CKR_OK)
        goto out;
    if (ncmp_msg_param(&rsp, 0, &pct, &lct) != NCMP_OK || lct != ct_len ||
        ncmp_msg_param(&rsp, 1, &pss, &lss) != NCMP_OK || lss != ss_len) {
        rv = NCMP_CKR_FUNCTION_FAILED;
        goto out;
    }
    memcpy(ct, pct, ct_len);
    memcpy(ss, pss, ss_len);

out:
    free(scratch);
    return rv;
}

unsigned long ncmp_crypto_mlkem_decaps(ncmp_client_t *c, uint32_t slot,
                                       uint32_t paramset, uint32_t pub_len,
                                       const uint8_t *priv, uint32_t priv_len,
                                       const uint8_t *ct, uint32_t ct_len,
                                       uint32_t ss_len, uint8_t *ss)
{
    uint8_t sbuf[4], plbuf[4], slbuf[4];
    const uint8_t *parts[5];
    uint32_t lens[5];
    NCMP_Message rsp;
    const uint8_t *pss;
    uint32_t lss;
    unsigned long rv;

    if (ss == NULL || ss_len == 0 || ss_len > NCMP_MAX_PARAM_SIZE)
        return NCMP_CKR_ARGUMENTS_BAD;

    ncmp_wr_u32le(sbuf, paramset);
    ncmp_wr_u32le(plbuf, pub_len);
    ncmp_wr_u32le(slbuf, ss_len);
    parts[0] = sbuf;  lens[0] = 4;
    parts[1] = plbuf; lens[1] = 4;
    parts[2] = slbuf; lens[2] = 4;
    parts[3] = priv;  lens[3] = priv_len;
    parts[4] = ct;    lens[4] = ct_len;
    rv = crypto_cmd_mp(c, slot, NCMP_CMD_MLKEM_DECAPS, parts, lens, 5, ss,
                       ss_len, &rsp);
    if (rv != NCMP_CKR_OK)
        return rv;
    if (ncmp_msg_param(&rsp, 0, &pss, &lss) != NCMP_OK || lss != ss_len)
        return NCMP_CKR_FUNCTION_FAILED;
    return NCMP_CKR_OK;
}

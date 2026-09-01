/*
 * Token NCMP - STDLL crypto marshalling adapter.
 *
 * A pure-buffer layer between the opencryptoki token_specific_* callbacks and
 * the lock-free client transport. Each function packs its byte-buffer arguments
 * into the NCMP wire parameter layout (see ncmp_cmd.h), forwards the command to
 * @p slot via ncmp_client_command[_mp](), and returns the token's PKCS#11
 * status. Key material is passed in as already-extracted raw bytes: the STDLL
 * (ncmp_specific.c) pulls it out of OBJECT templates and calls these, while the
 * standalone test suite drives them directly against the mock token.
 *
 * Return value (unsigned long, PKCS#11 CK_RV convention):
 *   NCMP_CKR_OK (0) on success,
 *   a transport error mapped by ncmp_err_to_ckr() if the round-trip failed, or
 *   the token's CKR_* ACK if the token rejected the operation.
 * When an @c out_len pointer is present it receives the actual response length
 * on success; the caller enforces any PKCS#11 length invariant.
 */
#ifndef NCMP_CRYPTO_H
#define NCMP_CRYPTO_H

#include <stdint.h>

#include "ncmp_client.h"

/**
 * @brief Random bytes: request exactly @p out_len bytes into @p out.
 * @param out_len Byte count; must not exceed NCMP_MAX_PARAM_SIZE (caller chunks
 *                larger requests). A short token response yields
 *                CKR_FUNCTION_FAILED.
 */
unsigned long ncmp_crypto_rng(ncmp_client_t *c, uint32_t slot,
                              uint8_t *out, uint32_t out_len);

/**
 * @brief One-shot digest of @p data under @p mech (an NCMP_MECH_SHA* value).
 * @note @c 4 + data_len must fit one wire parameter (<= NCMP_MAX_PARAM_SIZE).
 */
unsigned long ncmp_crypto_digest(ncmp_client_t *c, uint32_t slot, uint32_t mech,
                                 const uint8_t *data, uint32_t data_len,
                                 uint8_t *out, uint32_t out_cap,
                                 uint32_t *out_len);

/** @brief Open a token-side multipart digest context; returns its id. */
unsigned long ncmp_crypto_digest_init(ncmp_client_t *c, uint32_t slot,
                                      uint32_t mech, uint32_t *ctx_id);

/** @brief Feed one <=32KB chunk to multipart digest context @p ctx_id. */
unsigned long ncmp_crypto_digest_update(ncmp_client_t *c, uint32_t slot,
                                        uint32_t ctx_id, const uint8_t *data,
                                        uint32_t data_len);

/** @brief Finalize multipart digest context @p ctx_id (token frees the ctx). */
unsigned long ncmp_crypto_digest_final(ncmp_client_t *c, uint32_t slot,
                                       uint32_t ctx_id, uint8_t *out,
                                       uint32_t out_cap, uint32_t *out_len);

/** @brief AES-ECB. @p encrypt != 0 encrypts. Output length equals @p in_len. */
unsigned long ncmp_crypto_aes_ecb(ncmp_client_t *c, uint32_t slot, int encrypt,
                                  const uint8_t *key, uint32_t key_len,
                                  const uint8_t *in, uint32_t in_len,
                                  uint8_t *out, uint32_t out_cap,
                                  uint32_t *out_len);

/** @brief AES-CBC with IV @p iv. Output length equals @p in_len. */
unsigned long ncmp_crypto_aes_cbc(ncmp_client_t *c, uint32_t slot, int encrypt,
                                  const uint8_t *key, uint32_t key_len,
                                  const uint8_t *iv, uint32_t iv_len,
                                  const uint8_t *in, uint32_t in_len,
                                  uint8_t *out, uint32_t out_cap,
                                  uint32_t *out_len);

/**
 * @brief AES stream mode (@p opcode = NCMP_CMD_AES_CTR / _OFB / _CFB).
 * @note Stream ciphers: output length equals @p in_len (no block padding).
 */
unsigned long ncmp_crypto_aes_stream(ncmp_client_t *c, uint32_t slot,
                                     uint32_t opcode, int encrypt,
                                     const uint8_t *key, uint32_t key_len,
                                     const uint8_t *iv, uint32_t iv_len,
                                     const uint8_t *in, uint32_t in_len,
                                     uint8_t *out, uint32_t out_cap,
                                     uint32_t *out_len);

/**
 * @brief AES-GCM. Encrypt appends the @p tag_len tag (out == in_len+tag_len);
 *        decrypt consumes and checks it (out == in_len-tag_len).
 */
unsigned long ncmp_crypto_aes_gcm(ncmp_client_t *c, uint32_t slot, int encrypt,
                                  const uint8_t *key, uint32_t key_len,
                                  const uint8_t *iv, uint32_t iv_len,
                                  const uint8_t *aad, uint32_t aad_len,
                                  uint32_t tag_len, const uint8_t *in,
                                  uint32_t in_len, uint8_t *out,
                                  uint32_t out_cap, uint32_t *out_len);

/** @brief RSA sign (raw components): [modulus | private exponent | data]. */
unsigned long ncmp_crypto_rsa_sign(ncmp_client_t *c, uint32_t slot,
                                   const uint8_t *mod, uint32_t mod_len,
                                   const uint8_t *exp, uint32_t exp_len,
                                   const uint8_t *data, uint32_t data_len,
                                   uint8_t *out, uint32_t out_cap,
                                   uint32_t *out_len);

/** @brief RSA verify: [modulus | public exponent | data | signature]. */
unsigned long ncmp_crypto_rsa_verify(ncmp_client_t *c, uint32_t slot,
                                     const uint8_t *mod, uint32_t mod_len,
                                     const uint8_t *exp, uint32_t exp_len,
                                     const uint8_t *data, uint32_t data_len,
                                     const uint8_t *sig, uint32_t sig_len);

/**
 * @brief RSA-OAEP (@p opcode = NCMP_CMD_RSA_OAEP_ENC / _DEC): [mod | exp | in].
 * @note For encrypt pass the public exponent; for decrypt the private exponent.
 */
unsigned long ncmp_crypto_rsa_oaep(ncmp_client_t *c, uint32_t slot,
                                   uint32_t opcode, const uint8_t *mod,
                                   uint32_t mod_len, const uint8_t *exp,
                                   uint32_t exp_len, const uint8_t *in,
                                   uint32_t in_len, uint8_t *out,
                                   uint32_t out_cap, uint32_t *out_len);

/** @brief EC sign: [ec_params | private value | data]. */
unsigned long ncmp_crypto_ec_sign(ncmp_client_t *c, uint32_t slot,
                                  const uint8_t *ec_params,
                                  uint32_t ec_params_len, const uint8_t *priv,
                                  uint32_t priv_len, const uint8_t *data,
                                  uint32_t data_len, uint8_t *out,
                                  uint32_t out_cap, uint32_t *out_len);

/** @brief EC verify: [ec_params | ec_point | data | signature]. */
unsigned long ncmp_crypto_ec_verify(ncmp_client_t *c, uint32_t slot,
                                    const uint8_t *ec_params,
                                    uint32_t ec_params_len,
                                    const uint8_t *ec_point,
                                    uint32_t ec_point_len, const uint8_t *data,
                                    uint32_t data_len, const uint8_t *sig,
                                    uint32_t sig_len);

/** @brief HMAC sign: [mech | key | data] -> MAC. */
unsigned long ncmp_crypto_hmac_sign(ncmp_client_t *c, uint32_t slot,
                                    uint32_t mech, const uint8_t *key,
                                    uint32_t key_len, const uint8_t *data,
                                    uint32_t data_len, uint8_t *out,
                                    uint32_t out_cap, uint32_t *out_len);

/** @brief HMAC verify: [mech | key | data | mac]. */
unsigned long ncmp_crypto_hmac_verify(ncmp_client_t *c, uint32_t slot,
                                      uint32_t mech, const uint8_t *key,
                                      uint32_t key_len, const uint8_t *data,
                                      uint32_t data_len, const uint8_t *mac,
                                      uint32_t mac_len);

/** RSA key-pair components returned by ncmp_crypto_rsa_keygen (point into the
 *  caller's scratch buffer; valid until that buffer is reused/freed). */
typedef struct ncmp_rsa_keypair {
    const uint8_t *modulus;  uint32_t modulus_len;
    const uint8_t *priv_exp; uint32_t priv_exp_len;
    const uint8_t *prime1;   uint32_t prime1_len;
    const uint8_t *prime2;   uint32_t prime2_len;
    const uint8_t *exp1;     uint32_t exp1_len;
    const uint8_t *exp2;     uint32_t exp2_len;
    const uint8_t *coeff;    uint32_t coeff_len;
} ncmp_rsa_keypair_t;

/**
 * @brief Generate an RSA key pair: [modulus bits | public exponent] ->
 *        n, d, p, q, dp, dq, qinv. Response bytes land in @p scratch and @p out
 *        points at them.
 */
unsigned long ncmp_crypto_rsa_keygen(ncmp_client_t *c, uint32_t slot,
                                     uint32_t mod_bits, const uint8_t *pub_exp,
                                     uint32_t pub_exp_len, uint8_t *scratch,
                                     uint32_t scratch_cap,
                                     ncmp_rsa_keypair_t *out);

/** EC key-pair components returned by ncmp_crypto_ec_keygen (into scratch). */
typedef struct ncmp_ec_keypair {
    const uint8_t *ec_point; uint32_t ec_point_len;
    const uint8_t *priv;     uint32_t priv_len;
} ncmp_ec_keypair_t;

/** @brief Generate an EC key pair: [ec_params] -> ec_point, private value. */
unsigned long ncmp_crypto_ec_keygen(ncmp_client_t *c, uint32_t slot,
                                    const uint8_t *ec_params,
                                    uint32_t ec_params_len, uint8_t *scratch,
                                    uint32_t scratch_cap,
                                    ncmp_ec_keypair_t *out);

/** @brief DH derive: [prime | own private | peer public] -> shared secret. */
unsigned long ncmp_crypto_dh_derive(ncmp_client_t *c, uint32_t slot,
                                    const uint8_t *prime, uint32_t prime_len,
                                    const uint8_t *priv, uint32_t priv_len,
                                    const uint8_t *peer_pub,
                                    uint32_t peer_pub_len, uint8_t *out,
                                    uint32_t out_cap, uint32_t *out_len);

/** @brief ECDH derive: [ec_params | own private | peer point] -> secret. */
unsigned long ncmp_crypto_ecdh_derive(ncmp_client_t *c, uint32_t slot,
                                      const uint8_t *ec_params,
                                      uint32_t ec_params_len,
                                      const uint8_t *priv, uint32_t priv_len,
                                      const uint8_t *peer_point,
                                      uint32_t peer_point_len, uint8_t *out,
                                      uint32_t out_cap, uint32_t *out_len);

#endif /* NCMP_CRYPTO_H */

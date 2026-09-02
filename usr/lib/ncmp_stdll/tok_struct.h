/*
 * Token NCMP - opencryptoki STDLL identity + token_specific SPI table.
 *
 * NCMP is a USB proxy token (Cypress FX3 reached via the ncmpd daemon), so it
 * follows the EP11/ICSF "remote backend" pattern: only lifecycle hooks are
 * populated here; cryptographic operations are forwarded to the physical token
 * and are wired in incrementally. Any NULL function pointer makes the common
 * layer report CKR_MECHANISM_INVALID / CKR_FUNCTION_NOT_SUPPORTED.
 *
 * NOTE: unlike the other tokens (which use positional initializers over ~150
 * fields), this table uses C99 designated initializers. It is functionally
 * identical but robust to field reordering/additions in token_spec_struct.h -
 * a deliberate choice for a table that starts almost entirely NULL.
 */
#ifndef __NCMP_TOK_STRUCT_H
#define __NCMP_TOK_STRUCT_H

#include <pkcs11types.h>

#include "tok_spec_struct.h"

#ifndef NCMP_CONFIG_PATH
#ifndef CONFIG_PATH
#warning CONFIG_PATH not set, using default (/usr/local/var/lib/opencryptoki)
#define CONFIG_PATH "/usr/local/var/lib/opencryptoki"
#endif
#define NCMP_CONFIG_PATH CONFIG_PATH "/ncmptok"
#endif

token_spec_t token_specific = {
    .token_directory = NCMP_CONFIG_PATH,
    .token_subdir = "ncmptok",
    .secure_key_token = FALSE,
    .data_store = {
        .per_user = FALSE,
        .use_master_key = TRUE,
        .encryption_algorithm = CKM_DES3_CBC,
        .pin_initial_vector = (CK_BYTE *)"12345678",
        .obj_initial_vector = (CK_BYTE *)"10293847",
    },

    /* Lifecycle: connect to / disconnect from the ncmpd multiplexer. */
    .t_init = &token_specific_init,
    .t_final = &token_specific_final,

    /* PIN / login lifecycle: forwarded to the physical token via ncmpd. */
    .t_init_token = &token_specific_init_token,
    .t_login = &token_specific_login,
    .t_logout = &token_specific_logout,
    .t_init_pin = &token_specific_init_pin,
    .t_set_pin = &token_specific_set_pin,

    /* First forwarded crypto operation: RNG (NCMP_CMD_RNG over the wire). */
    .t_rng = &token_specific_rng,

    /* One-shot digest forwarding (NCMP_CMD_DIGEST). Multipart update/final is
     * added later once token-side context handles are wired. */
    .t_sha_init = &token_specific_sha_init,
    .t_sha = &token_specific_sha,
    .t_sha_update = &token_specific_sha_update,
    .t_sha_final = &token_specific_sha_final,

    /* Symmetric AES: block modes (CBC/ECB), AEAD (GCM), stream (CTR/OFB/CFB). */
    .t_aes_cbc = &token_specific_aes_cbc,
    .t_aes_ecb = &token_specific_aes_ecb,
    .t_aes_gcm_init = &token_specific_aes_gcm_init,
    .t_aes_gcm = &token_specific_aes_gcm,
    .t_aes_ctr = &token_specific_aes_ctr,
    .t_aes_ofb = &token_specific_aes_ofb,
    .t_aes_cfb = &token_specific_aes_cfb,

    /* Asymmetric ops: RSA and EC (ECDSA) sign + verify; RSA-OAEP enc/dec. */
    .t_rsa_sign = &token_specific_rsa_sign,
    .t_rsa_verify = &token_specific_rsa_verify,
    .t_ec_sign = &token_specific_ec_sign,
    .t_ec_verify = &token_specific_ec_verify,
    .t_rsa_oaep_encrypt = &token_specific_rsa_oaep_encrypt,
    .t_rsa_oaep_decrypt = &token_specific_rsa_oaep_decrypt,
    .t_rsa_pss_sign = &token_specific_rsa_pss_sign,
    .t_rsa_pss_verify = &token_specific_rsa_pss_verify,

    /* Key agreement: Diffie-Hellman and ECDH derive. */
    .t_dh_pkcs_derive = &token_specific_dh_pkcs_derive,
    .t_ecdh_pkcs_derive = &token_specific_ecdh_pkcs_derive,

    /* Keyed MAC: HMAC sign + verify (one-shot). */
    .t_hmac_sign_init = &token_specific_hmac_sign_init,
    .t_hmac_sign = &token_specific_hmac_sign,
    .t_hmac_verify_init = &token_specific_hmac_verify_init,
    .t_hmac_verify = &token_specific_hmac_verify,

    /* Key generation: symmetric (AES/DES/3DES/generic-secret) + RSA/EC key
     * pairs (token generates; the STDLL populates the PKCS#11 templates). */
    .t_aes_key_gen = &token_specific_aes_key_gen,
    .t_des_key_gen = &token_specific_des_key_gen,
    .t_generic_secret_key_gen = &token_specific_generic_secret_key_gen,
    .t_rsa_generate_keypair = &token_specific_rsa_generate_keypair,
    .t_ec_generate_keypair = &token_specific_ec_generate_keypair,

    /* XOF: SHAKE-128/256 key derivation. */
    .t_shake_key_derive = &token_specific_shake_key_derive,

    /* Post-quantum (PKCS#11 3.2): ML-DSA sign/verify + ML-KEM key agreement,
     * with their key-pair generators. Strength is selected per key via
     * CKA_PARAMETER_SET. */
    .t_ml_dsa_generate_keypair = &token_specific_ml_dsa_generate_keypair,
    .t_ml_dsa_sign = &token_specific_ml_dsa_sign,
    .t_ml_dsa_verify = &token_specific_ml_dsa_verify,
    .t_ml_kem_generate_keypair = &token_specific_ml_kem_generate_keypair,
    .t_ml_kem_encapsulate_key = &token_specific_ml_kem_encapsulate_key,
    .t_ml_kem_decapsulate_key = &token_specific_ml_kem_decapsulate_key,

    /* Token/mechanism reporting. */
    .t_get_token_info = &token_specific_get_token_info,
    .t_get_mechanism_list = &token_specific_get_mechanism_list,
    .t_get_mechanism_info = &token_specific_get_mechanism_info,

    /* All cryptographic operations are proxied to the FX3 token via ncmpd and
     * are added incrementally; leaving them NULL is intentional. */
};

#endif /* __NCMP_TOK_STRUCT_H */

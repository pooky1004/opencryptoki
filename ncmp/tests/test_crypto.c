/*
 * Token NCMP - crypto adapter tests (ncmp_crypto).
 *
 * Drives the pure-buffer marshalling adapter (ncmp/stdll/ncmp_crypto.c) - the
 * exact layer the opencryptoki token_specific_* callbacks forward through -
 * end-to-end against the in-process mock token. Each op is checked for a correct
 * round-trip plus its failure signal (tamper / wrong length) so the wire
 * marshalling contract the STDLL depends on is regression-tested here, where the
 * full opencryptoki object/template stack is not available.
 */
#include "ncmp/ncmp_client.h"
#include "ncmp/ncmp_crypto.h"
#include "ncmp/ncmp_ckr.h"
#include "ncmp/ncmp_cmd.h"
#include "ncmp/ncmp_shm.h"
#include "ncmp/ncmp_transport.h"
#include "ncmp/ncmp_wire.h"
#include "ncmp/ncmp_errno.h"
#include "ncmpd.h"
#include "mock_token_ncmp.h"
#include "ncmp_test.h"

#include <pthread.h>
#include <sched.h>
#include <string.h>

#define TEST_SOCK "/tmp/ncmp_crypto_test.sock"

/* Token ACK codes the mock returns for rejected operations (raw CKR values). */
#define CK_SIGNATURE_INVALID      0xC0u
#define CK_ENCRYPTED_DATA_INVALID 0x40u

typedef struct {
    void             *shm_base;
    ncmp_transport_t *t;
    ncmpd_slot_ctx_t  comm;
    ncmpd_conn_ctx_t  conn;
} harness_t;

/** Stand up SHM, mark slot 0 online, and start comm + conn threads. */
static int harness_up(harness_t *hz)
{
    NCMP_Slot *slot;

    memset(hz, 0, sizeof(*hz));
    (void)ncmp_shm_destroy(NULL);
    if (ncmp_shm_create(&hz->shm_base) != NCMP_OK)
        return -1;

    slot = ncmp_shm_slot(hz->shm_base, 0);
    slot->state = NCMP_SLOT_ONLINE;

    if (ncmp_transport_open(0, &hz->t) != NCMP_OK)
        return -1;

    hz->comm.shm_base = hz->shm_base;
    hz->comm.slot = slot;
    hz->comm.slot_id = 0;
    hz->comm.transport = hz->t;
    if (pthread_create(&hz->comm.thread, NULL, ncmpd_comm_thread, &hz->comm))
        return -1;

    hz->conn.shm_base = hz->shm_base;
    hz->conn.sock_path = TEST_SOCK;
    if (pthread_create(&hz->conn.thread, NULL, ncmpd_conn_thread, &hz->conn))
        return -1;

    return 0;
}

static void harness_down(harness_t *hz)
{
    ncmpd_request_stop(&hz->conn.stop);
    pthread_join(hz->conn.thread, NULL);
    ncmpd_request_stop(&hz->comm.stop);
    pthread_join(hz->comm.thread, NULL);
    ncmp_transport_close(hz->t);
    ncmp_shm_destroy(hz->shm_base);
}

/** Connect with retry: the conn_thread may not have bound the socket yet. */
static int client_connect_retry(ncmp_client_t *c)
{
    for (int i = 0; i < 100000; ++i) {
        if (ncmp_client_init(c, TEST_SOCK) == NCMP_OK)
            return NCMP_OK;
        sched_yield();
    }
    return NCMP_ERR_NODAEMON;
}

int test_crypto_rng(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint8_t out[64];

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    NCMP_CHECK(ncmp_crypto_rng(&c, 0, out, sizeof(out)) == NCMP_CKR_OK);
    for (uint32_t i = 0; i < sizeof(out); ++i)
        NCMP_CHECK(out[i] == NCMP_MOCK_RNG_BYTE(i));

    /* Zero-length request is rejected by the adapter (arguments bad). */
    NCMP_CHECK(ncmp_crypto_rng(&c, 0, out, 0) != NCMP_CKR_OK);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_crypto_digest(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint8_t d1[32], d2[32], d3[32];
    uint32_t l1 = 0, l2 = 0, l3 = 0;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    NCMP_CHECK(ncmp_crypto_digest(&c, 0, NCMP_MECH_SHA256,
                                  (const uint8_t *)"hello", 5,
                                  d1, sizeof(d1), &l1) == NCMP_CKR_OK);
    NCMP_CHECK(l1 == ncmp_digest_size(NCMP_MECH_SHA256)); /* 32 */

    /* Deterministic + input-sensitive. */
    NCMP_CHECK(ncmp_crypto_digest(&c, 0, NCMP_MECH_SHA256,
                                  (const uint8_t *)"hello", 5,
                                  d2, sizeof(d2), &l2) == NCMP_CKR_OK);
    NCMP_CHECK(memcmp(d1, d2, 32) == 0);
    NCMP_CHECK(ncmp_crypto_digest(&c, 0, NCMP_MECH_SHA256,
                                  (const uint8_t *)"world", 5,
                                  d3, sizeof(d3), &l3) == NCMP_CKR_OK);
    NCMP_CHECK(memcmp(d1, d3, 32) != 0);

    /* Unsupported mechanism -> token rejects (non-OK). */
    NCMP_CHECK(ncmp_crypto_digest(&c, 0, 0x00000999u,
                                  (const uint8_t *)"x", 1,
                                  d2, sizeof(d2), &l2) != NCMP_CKR_OK);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_crypto_digest_multipart(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint8_t mp[32], one[32];
    uint32_t mlen = 0, olen = 0, id = 0;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    /* INIT -> UPDATE("hel") -> UPDATE("lo") -> FINAL. */
    NCMP_CHECK(ncmp_crypto_digest_init(&c, 0, NCMP_MECH_SHA256, &id)
               == NCMP_CKR_OK);
    NCMP_CHECK(ncmp_crypto_digest_update(&c, 0, id, (const uint8_t *)"hel", 3)
               == NCMP_CKR_OK);
    NCMP_CHECK(ncmp_crypto_digest_update(&c, 0, id, (const uint8_t *)"lo", 2)
               == NCMP_CKR_OK);
    NCMP_CHECK(ncmp_crypto_digest_final(&c, 0, id, mp, sizeof(mp), &mlen)
               == NCMP_CKR_OK);
    NCMP_CHECK(mlen == 32);

    /* Multipart("hello") == one-shot("hello"). */
    NCMP_CHECK(ncmp_crypto_digest(&c, 0, NCMP_MECH_SHA256,
                                  (const uint8_t *)"hello", 5,
                                  one, sizeof(one), &olen) == NCMP_CKR_OK);
    NCMP_CHECK(memcmp(mp, one, 32) == 0);

    /* Context was freed by FINAL: a second FINAL on the same id fails. */
    NCMP_CHECK(ncmp_crypto_digest_final(&c, 0, id, mp, sizeof(mp), &mlen)
               != NCMP_CKR_OK);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_crypto_aes_ecb(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint8_t key[16], data[32], ct[32], pt[32];
    uint32_t cl = 0, pl = 0;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    for (int i = 0; i < 16; ++i) key[i] = (uint8_t)(i + 5);
    for (int i = 0; i < 32; ++i) data[i] = (uint8_t)(i * 9 + 1);

    NCMP_CHECK(ncmp_crypto_aes_ecb(&c, 0, 1, key, sizeof(key), data,
                                   sizeof(data), ct, sizeof(ct), &cl)
               == NCMP_CKR_OK);
    NCMP_CHECK(cl == sizeof(data));
    NCMP_CHECK(memcmp(ct, data, sizeof(data)) != 0);

    NCMP_CHECK(ncmp_crypto_aes_ecb(&c, 0, 0, key, sizeof(key), ct, cl,
                                   pt, sizeof(pt), &pl) == NCMP_CKR_OK);
    NCMP_CHECK(pl == sizeof(data));
    NCMP_CHECK(memcmp(pt, data, sizeof(data)) == 0);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_crypto_aes_cbc(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint8_t key[16], iv[16], data[32], ct[32], pt[32];
    uint32_t cl = 0, pl = 0;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    for (int i = 0; i < 16; ++i) { key[i] = (uint8_t)(i + 1); iv[i] = (uint8_t)(0xF0 + i); }
    for (int i = 0; i < 32; ++i) data[i] = (uint8_t)(i * 7 + 3);

    NCMP_CHECK(ncmp_crypto_aes_cbc(&c, 0, 1, key, sizeof(key), iv, sizeof(iv),
                                   data, sizeof(data), ct, sizeof(ct), &cl)
               == NCMP_CKR_OK);
    NCMP_CHECK(cl == sizeof(data));
    NCMP_CHECK(memcmp(ct, data, sizeof(data)) != 0);

    NCMP_CHECK(ncmp_crypto_aes_cbc(&c, 0, 0, key, sizeof(key), iv, sizeof(iv),
                                   ct, cl, pt, sizeof(pt), &pl) == NCMP_CKR_OK);
    NCMP_CHECK(memcmp(pt, data, sizeof(data)) == 0);

    /* Non-block-multiple input -> token rejects. */
    NCMP_CHECK(ncmp_crypto_aes_cbc(&c, 0, 1, key, sizeof(key), iv, sizeof(iv),
                                   data, 20, ct, sizeof(ct), &cl)
               != NCMP_CKR_OK);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_crypto_aes_stream(void)
{
    harness_t hz;
    ncmp_client_t c;
    const uint32_t modes[3] = { NCMP_CMD_AES_CTR, NCMP_CMD_AES_OFB,
                                NCMP_CMD_AES_CFB };
    uint8_t key[16], iv[16], data[20], ct[20], pt[20];
    uint32_t cl = 0, pl = 0;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    for (int i = 0; i < 16; ++i) { key[i] = (uint8_t)(i + 8); iv[i] = (uint8_t)(0xB0 + i); }
    for (int i = 0; i < 20; ++i) data[i] = (uint8_t)(i * 13 + 2); /* not block-aligned */

    for (int m = 0; m < 3; ++m) {
        NCMP_CHECK(ncmp_crypto_aes_stream(&c, 0, modes[m], 1, key, sizeof(key),
                                          iv, sizeof(iv), data, sizeof(data),
                                          ct, sizeof(ct), &cl) == NCMP_CKR_OK);
        NCMP_CHECK(cl == sizeof(data)); /* stream: out len == in len */
        NCMP_CHECK(memcmp(ct, data, sizeof(data)) != 0);

        NCMP_CHECK(ncmp_crypto_aes_stream(&c, 0, modes[m], 0, key, sizeof(key),
                                          iv, sizeof(iv), ct, cl,
                                          pt, sizeof(pt), &pl) == NCMP_CKR_OK);
        NCMP_CHECK(memcmp(pt, data, sizeof(data)) == 0);
    }

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_crypto_aes_gcm(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint8_t key[16], iv[12], aad[8], data[32], ct[48], pt[32];
    uint32_t cl = 0, pl = 0;
    const uint32_t taglen = 16;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    for (int i = 0; i < 16; ++i) key[i] = (uint8_t)(i + 3);
    for (int i = 0; i < 12; ++i) iv[i] = (uint8_t)(0xA0 + i);
    for (int i = 0; i < 8; ++i) aad[i] = (uint8_t)(i * 2);
    for (int i = 0; i < 32; ++i) data[i] = (uint8_t)(i * 11 + 4);

    NCMP_CHECK(ncmp_crypto_aes_gcm(&c, 0, 1, key, sizeof(key), iv, sizeof(iv),
                                   aad, sizeof(aad), taglen, data, sizeof(data),
                                   ct, sizeof(ct), &cl) == NCMP_CKR_OK);
    NCMP_CHECK(cl == sizeof(data) + taglen); /* 48 */
    NCMP_CHECK(memcmp(ct, data, sizeof(data)) != 0);

    NCMP_CHECK(ncmp_crypto_aes_gcm(&c, 0, 0, key, sizeof(key), iv, sizeof(iv),
                                   aad, sizeof(aad), taglen, ct, cl,
                                   pt, sizeof(pt), &pl) == NCMP_CKR_OK);
    NCMP_CHECK(pl == sizeof(data));
    NCMP_CHECK(memcmp(pt, data, sizeof(data)) == 0);

    /* Tamper the ciphertext -> authentication fails. */
    ct[0] ^= 0xFF;
    NCMP_CHECK(ncmp_crypto_aes_gcm(&c, 0, 0, key, sizeof(key), iv, sizeof(iv),
                                   aad, sizeof(aad), taglen, ct, cl,
                                   pt, sizeof(pt), &pl)
               == CK_ENCRYPTED_DATA_INVALID);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_crypto_rsa(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint8_t mod[256], priv[256], pub[3] = { 0x01, 0x00, 0x01 };
    uint8_t data[32], sig[256];
    uint32_t sl = 0;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    for (int i = 0; i < 256; ++i) { mod[i] = (uint8_t)(i ^ 0x5A); priv[i] = (uint8_t)(i * 3 + 1); }
    for (int i = 0; i < 32; ++i) data[i] = (uint8_t)(i + 100);

    /* Sign with the private exponent; signature length == modulus length. */
    NCMP_CHECK(ncmp_crypto_rsa_sign(&c, 0, mod, sizeof(mod), priv, sizeof(priv),
                                    data, sizeof(data), sig, sizeof(sig), &sl)
               == NCMP_CKR_OK);
    NCMP_CHECK(sl == sizeof(mod));

    /* Verify with the public exponent -> OK. */
    NCMP_CHECK(ncmp_crypto_rsa_verify(&c, 0, mod, sizeof(mod), pub, sizeof(pub),
                                      data, sizeof(data), sig, sl)
               == NCMP_CKR_OK);

    /* Tampered signature -> CKR_SIGNATURE_INVALID. */
    sig[0] ^= 0xFF;
    NCMP_CHECK(ncmp_crypto_rsa_verify(&c, 0, mod, sizeof(mod), pub, sizeof(pub),
                                      data, sizeof(data), sig, sl)
               == CK_SIGNATURE_INVALID);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_crypto_rsa_oaep(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint8_t mod[256], pub[3] = { 0x01, 0x00, 0x01 }, priv[256], data[32];
    static uint8_t ct[256], pt[256];
    uint32_t cl = 0, pl = 0;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    for (int i = 0; i < 256; ++i) { mod[i] = (uint8_t)(i ^ 0x77); priv[i] = (uint8_t)(i * 5 + 2); }
    for (int i = 0; i < 32; ++i) data[i] = (uint8_t)(i * 9 + 4);

    NCMP_CHECK(ncmp_crypto_rsa_oaep(&c, 0, NCMP_CMD_RSA_OAEP_ENC, mod,
                                    sizeof(mod), pub, sizeof(pub), data,
                                    sizeof(data), ct, sizeof(ct), &cl)
               == NCMP_CKR_OK);
    NCMP_CHECK(cl == sizeof(mod)); /* ciphertext is one modulus long */
    NCMP_CHECK(memcmp(ct, data, sizeof(data)) != 0);

    NCMP_CHECK(ncmp_crypto_rsa_oaep(&c, 0, NCMP_CMD_RSA_OAEP_DEC, mod,
                                    sizeof(mod), priv, sizeof(priv), ct, cl,
                                    pt, sizeof(pt), &pl) == NCMP_CKR_OK);
    NCMP_CHECK(pl == sizeof(data));
    NCMP_CHECK(memcmp(pt, data, sizeof(data)) == 0);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_crypto_ec(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint8_t ecp[10], priv[32], point[20], data[32], sig[64];
    uint32_t sl = 0;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    for (int i = 0; i < 10; ++i) ecp[i] = (uint8_t)(0x30 + i);
    for (int i = 0; i < 20; ++i) point[i] = (uint8_t)(0x40 + i);
    for (int i = 0; i < 32; ++i) { priv[i] = (uint8_t)(i * 5 + 7); data[i] = (uint8_t)(i + 2); }

    /* ECDSA signature length == 2 * private-scalar length. */
    NCMP_CHECK(ncmp_crypto_ec_sign(&c, 0, ecp, sizeof(ecp), priv, sizeof(priv),
                                   data, sizeof(data), sig, sizeof(sig), &sl)
               == NCMP_CKR_OK);
    NCMP_CHECK(sl == 2 * sizeof(priv));

    NCMP_CHECK(ncmp_crypto_ec_verify(&c, 0, ecp, sizeof(ecp), point,
                                     sizeof(point), data, sizeof(data), sig, sl)
               == NCMP_CKR_OK);

    sig[0] ^= 0xFF;
    NCMP_CHECK(ncmp_crypto_ec_verify(&c, 0, ecp, sizeof(ecp), point,
                                     sizeof(point), data, sizeof(data), sig, sl)
               == CK_SIGNATURE_INVALID);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_crypto_hmac(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint8_t key[32], data[40], mac[32];
    uint32_t ml = 0;
    const uint32_t mech = 0x00000251u; /* CKM_SHA256_HMAC -> 32-byte MAC */

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    for (int i = 0; i < 32; ++i) key[i] = (uint8_t)(i + 11);
    for (int i = 0; i < 40; ++i) data[i] = (uint8_t)(i * 3 + 1);

    NCMP_CHECK(ncmp_crypto_hmac_sign(&c, 0, mech, key, sizeof(key), data,
                                     sizeof(data), mac, sizeof(mac), &ml)
               == NCMP_CKR_OK);
    NCMP_CHECK(ml == 32);

    NCMP_CHECK(ncmp_crypto_hmac_verify(&c, 0, mech, key, sizeof(key), data,
                                       sizeof(data), mac, ml) == NCMP_CKR_OK);

    mac[0] ^= 0xFF;
    NCMP_CHECK(ncmp_crypto_hmac_verify(&c, 0, mech, key, sizeof(key), data,
                                       sizeof(data), mac, ml)
               == CK_SIGNATURE_INVALID);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_crypto_rsa_keygen(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint8_t pubexp[3] = { 0x01, 0x00, 0x01 };
    static uint8_t scratch[8192];
    ncmp_rsa_keypair_t kp;
    const uint32_t nbytes = 256, hbytes = 128;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    NCMP_CHECK(ncmp_crypto_rsa_keygen(&c, 0, 2048, pubexp, sizeof(pubexp),
                                      scratch, sizeof(scratch), &kp)
               == NCMP_CKR_OK);
    NCMP_CHECK(kp.modulus_len == nbytes);
    NCMP_CHECK(kp.priv_exp_len == nbytes);
    NCMP_CHECK(kp.prime1_len == hbytes);
    NCMP_CHECK(kp.prime2_len == hbytes);
    NCMP_CHECK(kp.exp1_len == hbytes);
    NCMP_CHECK(kp.exp2_len == hbytes);
    NCMP_CHECK(kp.coeff_len == hbytes);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_crypto_ec_keygen(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint8_t ecp[10];
    uint8_t scratch[256];
    ncmp_ec_keypair_t kp;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    for (int i = 0; i < 10; ++i) ecp[i] = (uint8_t)(0x30 + i);

    NCMP_CHECK(ncmp_crypto_ec_keygen(&c, 0, ecp, sizeof(ecp), scratch,
                                     sizeof(scratch), &kp) == NCMP_CKR_OK);
    NCMP_CHECK(kp.ec_point_len == 65); /* uncompressed EC point (P-256) */
    NCMP_CHECK(kp.priv_len == 32);     /* private scalar */

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_crypto_dh_derive(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint8_t prime[128], priv[128], pub[128], secret[128], secret2[128];
    uint32_t sl = 0, sl2 = 0;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    for (int i = 0; i < 128; ++i) {
        prime[i] = (uint8_t)(0x80 + i); priv[i] = (uint8_t)(i * 3 + 1);
        pub[i] = (uint8_t)(i * 5 + 2);
    }

    NCMP_CHECK(ncmp_crypto_dh_derive(&c, 0, prime, sizeof(prime), priv,
                                     sizeof(priv), pub, sizeof(pub), secret,
                                     sizeof(secret), &sl) == NCMP_CKR_OK);
    NCMP_CHECK(sl == sizeof(prime)); /* secret is one prime long */

    /* Deterministic: same inputs -> same secret. */
    NCMP_CHECK(ncmp_crypto_dh_derive(&c, 0, prime, sizeof(prime), priv,
                                     sizeof(priv), pub, sizeof(pub), secret2,
                                     sizeof(secret2), &sl2) == NCMP_CKR_OK);
    NCMP_CHECK(sl2 == sl && memcmp(secret, secret2, sl) == 0);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_crypto_ecdh_derive(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint8_t oid[10], priv[32], pub[65], secret[64];
    uint32_t sl = 0;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    for (int i = 0; i < 10; ++i) oid[i] = (uint8_t)(0x30 + i);
    for (int i = 0; i < 32; ++i) priv[i] = (uint8_t)(i * 7 + 3);
    pub[0] = 0x04; /* uncompressed point */
    for (int i = 1; i < 65; ++i) pub[i] = (uint8_t)(i * 2 + 1);

    NCMP_CHECK(ncmp_crypto_ecdh_derive(&c, 0, oid, sizeof(oid), priv,
                                       sizeof(priv), pub, sizeof(pub), secret,
                                       sizeof(secret), &sl) == NCMP_CKR_OK);
    NCMP_CHECK(sl == 32); /* field size = (65-1)/2 */

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

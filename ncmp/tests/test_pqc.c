/*
 * Token NCMP - SHA3 / XOF / post-quantum adapter tests (ncmp_crypto).
 *
 * Drives the pure-buffer adapter end-to-end against the mock token for the
 * mechanisms the NCMP token advertises: SHA3 digests, SHAKE XOF key derivation,
 * ML-DSA (sign/verify) and ML-KEM (encapsulate/decapsulate). Each op is checked
 * for a correct round-trip plus its failure signal (tamper / wrong length).
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

#define TEST_SOCK "/tmp/ncmp_pqc_test.sock"

/* Token ACK for a rejected signature (raw CKR value). */
#define CK_SIGNATURE_INVALID 0xC0u

/* PKCS#11 parameter-set keyforms exercised (strength 1/3/5 selectors). */
#define P_ML_DSA_65 2u
#define P_ML_KEM_768 2u

typedef struct {
    void             *shm_base;
    ncmp_transport_t *t;
    ncmpd_slot_ctx_t  comm;
    ncmpd_conn_ctx_t  conn;
} harness_t;

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

static int client_connect_retry(ncmp_client_t *c)
{
    for (int i = 0; i < 100000; ++i) {
        if (ncmp_client_init(c, TEST_SOCK) == NCMP_OK)
            return NCMP_OK;
        sched_yield();
    }
    return NCMP_ERR_NODAEMON;
}

int test_pqc_sha3(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint8_t a[64], b[64], d[64];
    uint32_t la = 0, lb = 0, ld = 0;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    /* SHA3-256 -> 32 bytes, deterministic + input-sensitive. */
    NCMP_CHECK(ncmp_crypto_digest(&c, 0, NCMP_MECH_SHA3_256,
                                  (const uint8_t *)"abc", 3, a, sizeof(a), &la)
               == NCMP_CKR_OK);
    NCMP_CHECK(la == 32);
    NCMP_CHECK(ncmp_crypto_digest(&c, 0, NCMP_MECH_SHA3_256,
                                  (const uint8_t *)"abc", 3, b, sizeof(b), &lb)
               == NCMP_CKR_OK);
    NCMP_CHECK(lb == 32 && memcmp(a, b, 32) == 0);
    NCMP_CHECK(ncmp_crypto_digest(&c, 0, NCMP_MECH_SHA3_256,
                                  (const uint8_t *)"abd", 3, b, sizeof(b), &lb)
               == NCMP_CKR_OK);
    NCMP_CHECK(memcmp(a, b, 32) != 0);

    /* SHA3-512 -> 64 bytes. */
    NCMP_CHECK(ncmp_crypto_digest(&c, 0, NCMP_MECH_SHA3_512,
                                  (const uint8_t *)"abc", 3, d, sizeof(d), &ld)
               == NCMP_CKR_OK);
    NCMP_CHECK(ld == 64);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_pqc_shake(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint8_t base[16], o1[32], o2[32], o3[64];

    memset(base, 0xA5, sizeof(base));
    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    /* SHAKE-256 XOF: deterministic expansion to the requested length. */
    NCMP_CHECK(ncmp_crypto_shake_derive(&c, 0, 0x0000039Cu, base, sizeof(base),
                                        o1, sizeof(o1)) == NCMP_CKR_OK);
    NCMP_CHECK(ncmp_crypto_shake_derive(&c, 0, 0x0000039Cu, base, sizeof(base),
                                        o2, sizeof(o2)) == NCMP_CKR_OK);
    NCMP_CHECK(memcmp(o1, o2, 32) == 0);
    NCMP_CHECK(ncmp_crypto_shake_derive(&c, 0, 0x0000039Cu, base, sizeof(base),
                                        o3, sizeof(o3)) == NCMP_CKR_OK);
    /* Longer request shares its prefix with the shorter one's keystream head. */
    NCMP_CHECK(memcmp(o1, o3, 32) == 0);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_pqc_mldsa(void)
{
    harness_t hz;
    ncmp_client_t c;
    /* ML-DSA-65 nominal sizes. */
    const uint32_t pub_len = 1952, priv_len = 4032, sig_len = 3309;
    uint8_t pub[1952], priv[4032], sig[3309];
    uint32_t got = 0;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    NCMP_CHECK(ncmp_crypto_mldsa_keygen(&c, 0, P_ML_DSA_65, pub_len, priv_len,
                                        pub, priv) == NCMP_CKR_OK);
    /* The private blob carries the public blob as its prefix. */
    NCMP_CHECK(memcmp(pub, priv, pub_len) == 0);

    NCMP_CHECK(ncmp_crypto_mldsa_sign(&c, 0, P_ML_DSA_65, pub_len, sig_len,
                                      priv, priv_len,
                                      (const uint8_t *)"message", 7,
                                      sig, &got) == NCMP_CKR_OK);
    NCMP_CHECK(got == sig_len);

    NCMP_CHECK(ncmp_crypto_mldsa_verify(&c, 0, P_ML_DSA_65, pub, pub_len,
                                        (const uint8_t *)"message", 7,
                                        sig, sig_len) == NCMP_CKR_OK);
    /* Tampered message fails verification. */
    NCMP_CHECK(ncmp_crypto_mldsa_verify(&c, 0, P_ML_DSA_65, pub, pub_len,
                                        (const uint8_t *)"messagX", 7,
                                        sig, sig_len) == CK_SIGNATURE_INVALID);
    /* Tampered signature fails verification. */
    sig[0] ^= 0xFF;
    NCMP_CHECK(ncmp_crypto_mldsa_verify(&c, 0, P_ML_DSA_65, pub, pub_len,
                                        (const uint8_t *)"message", 7,
                                        sig, sig_len) == CK_SIGNATURE_INVALID);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_pqc_mlkem(void)
{
    harness_t hz;
    ncmp_client_t c;
    /* ML-KEM-768 nominal sizes; shared secret is 32 bytes. */
    const uint32_t pub_len = 1184, priv_len = 2400, ct_len = 1088, ss_len = 32;
    uint8_t pub[1184], priv[2400], ct[1088], ss_e[32], ss_d[32], ss_bad[32];

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    NCMP_CHECK(ncmp_crypto_mlkem_keygen(&c, 0, P_ML_KEM_768, pub_len, priv_len,
                                        pub, priv) == NCMP_CKR_OK);
    NCMP_CHECK(memcmp(pub, priv, pub_len) == 0);

    NCMP_CHECK(ncmp_crypto_mlkem_encaps(&c, 0, P_ML_KEM_768, pub, pub_len,
                                        ct_len, ss_len, ct, ss_e)
               == NCMP_CKR_OK);
    NCMP_CHECK(ncmp_crypto_mlkem_decaps(&c, 0, P_ML_KEM_768, pub_len, priv,
                                        priv_len, ct, ct_len, ss_len, ss_d)
               == NCMP_CKR_OK);
    /* Encapsulated and decapsulated shared secrets agree. */
    NCMP_CHECK(memcmp(ss_e, ss_d, ss_len) == 0);

    /* A tampered ciphertext decapsulates to a different secret. */
    ct[0] ^= 0xFF;
    NCMP_CHECK(ncmp_crypto_mlkem_decaps(&c, 0, P_ML_KEM_768, pub_len, priv,
                                        priv_len, ct, ct_len, ss_len, ss_bad)
               == NCMP_CKR_OK);
    NCMP_CHECK(memcmp(ss_e, ss_bad, ss_len) != 0);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}
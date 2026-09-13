/*
 * Token NCMP - multipart AES-GCM adapter tests (context-bearing).
 *
 * Drives ncmp_crypto_aes_gcm_{init,update,final} end-to-end against the mock
 * through the daemon comm_thread: encrypt across two chunks, then decrypt the
 * ciphertext across two chunks and verify the tag. The same test passes in both
 * context models (default token-side context and NCMP_HOST_MANAGED_CTX, where
 * comm_thread keeps the context host-side) - it exercises whichever the daemon
 * was built with.
 */
#include "ncmp/ncmp_client.h"
#include "ncmp/ncmp_crypto.h"
#include "ncmp/ncmp_ckr.h"
#include "ncmp/ncmp_cmd.h"
#include "ncmp/ncmp_shm.h"
#include "ncmp/ncmp_transport.h"
#include "ncmp/ncmp_errno.h"
#include "ncmpd.h"
#include "ncmp_test.h"

#include <pthread.h>
#include <sched.h>
#include <string.h>

#define TEST_SOCK "/tmp/ncmp_gcmmp_test.sock"

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

int test_crypto_aes_gcm_multipart(void)
{
    harness_t hz;
    ncmp_client_t c;
    const uint8_t key[16] = { 1, 2, 3, 4, 5, 6, 7, 8,
                              9, 10, 11, 12, 13, 14, 15, 16 };
    const uint8_t iv[12] = { 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
                             0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b };
    const uint8_t aad[5] = { 'h', 'e', 'l', 'l', 'o' };
    const uint8_t pt1[10] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    const uint8_t pt2[6] = { 100, 101, 102, 103, 104, 105 };
    uint8_t ct1[10], ct2[6], dt1[10], dt2[6], tag[16], badtag[16];
    uint32_t cid, l1, l2, tl, m1, m2;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    /* Encrypt across two chunks, then finalize to the tag. */
    NCMP_CHECK(ncmp_crypto_aes_gcm_init(&c, 0, 1, key, sizeof(key), iv,
                                        sizeof(iv), aad, sizeof(aad), 16,
                                        &cid) == NCMP_CKR_OK);
    NCMP_CHECK(ncmp_crypto_aes_gcm_update(&c, 0, cid, pt1, sizeof(pt1), ct1,
                                          sizeof(ct1), &l1) == NCMP_CKR_OK);
    NCMP_CHECK(l1 == sizeof(pt1));
    NCMP_CHECK(ncmp_crypto_aes_gcm_update(&c, 0, cid, pt2, sizeof(pt2), ct2,
                                          sizeof(ct2), &l2) == NCMP_CKR_OK);
    NCMP_CHECK(l2 == sizeof(pt2));
    NCMP_CHECK(ncmp_crypto_aes_gcm_final(&c, 0, cid, 1, NULL, 0, tag,
                                         sizeof(tag), &tl) == NCMP_CKR_OK);
    NCMP_CHECK(tl == 16);
    /* Ciphertext must differ from plaintext (keystream applied). */
    NCMP_CHECK(memcmp(ct1, pt1, sizeof(pt1)) != 0);

    /* Decrypt the ciphertext across two chunks; verify plaintext + tag. */
    NCMP_CHECK(ncmp_crypto_aes_gcm_init(&c, 0, 0, key, sizeof(key), iv,
                                        sizeof(iv), aad, sizeof(aad), 16,
                                        &cid) == NCMP_CKR_OK);
    NCMP_CHECK(ncmp_crypto_aes_gcm_update(&c, 0, cid, ct1, sizeof(ct1), dt1,
                                          sizeof(dt1), &m1) == NCMP_CKR_OK);
    NCMP_CHECK(ncmp_crypto_aes_gcm_update(&c, 0, cid, ct2, sizeof(ct2), dt2,
                                          sizeof(dt2), &m2) == NCMP_CKR_OK);
    NCMP_CHECK(m1 == sizeof(pt1) && m2 == sizeof(pt2));
    NCMP_CHECK(memcmp(dt1, pt1, sizeof(pt1)) == 0);
    NCMP_CHECK(memcmp(dt2, pt2, sizeof(pt2)) == 0);
    NCMP_CHECK(ncmp_crypto_aes_gcm_final(&c, 0, cid, 0, tag, 16, NULL, 0,
                                         NULL) == NCMP_CKR_OK);

    /* A corrupted tag must be rejected. */
    NCMP_CHECK(ncmp_crypto_aes_gcm_init(&c, 0, 0, key, sizeof(key), iv,
                                        sizeof(iv), aad, sizeof(aad), 16,
                                        &cid) == NCMP_CKR_OK);
    NCMP_CHECK(ncmp_crypto_aes_gcm_update(&c, 0, cid, ct1, sizeof(ct1), dt1,
                                          sizeof(dt1), &m1) == NCMP_CKR_OK);
    NCMP_CHECK(ncmp_crypto_aes_gcm_update(&c, 0, cid, ct2, sizeof(ct2), dt2,
                                          sizeof(dt2), &m2) == NCMP_CKR_OK);
    memcpy(badtag, tag, 16);
    badtag[0] ^= 0xff;
    NCMP_CHECK(ncmp_crypto_aes_gcm_final(&c, 0, cid, 0, badtag, 16, NULL, 0,
                                         NULL) == NCMP_CKR_ENCRYPTED_DATA_INVALID);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

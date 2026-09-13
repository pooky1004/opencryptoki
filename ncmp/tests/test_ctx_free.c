/*
 * Token NCMP - multipart context abort/free (NCMP_CMD_CTX_FREE) tests.
 *
 * Opening then freeing a multipart context many more times than there are
 * context slots must succeed: if CTX_FREE did not recycle the slot, the ~9th
 * (default token-side table, 8 slots) or ~65th (host-managed table, 64 slots)
 * INIT would fail with a device-memory error. Runs against whichever context
 * model the daemon was built with.
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

#define TEST_SOCK "/tmp/ncmp_ctxfree_test.sock"

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

int test_ctx_free_digest(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint32_t id;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    /* Far exceed both slot pools (8 token-side / 64 host-side). */
    for (int i = 0; i < 100; ++i) {
        NCMP_CHECK(ncmp_crypto_digest_init(&c, 0, NCMP_MECH_SHA256, &id) ==
                   NCMP_CKR_OK);
        NCMP_CHECK(ncmp_crypto_ctx_free(&c, 0, id, NCMP_CTX_KIND_DIGEST) ==
                   NCMP_CKR_OK);
    }
    /* Freeing an already-freed id is harmless (idempotent). */
    NCMP_CHECK(ncmp_crypto_ctx_free(&c, 0, id, NCMP_CTX_KIND_DIGEST) ==
               NCMP_CKR_OK);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_ctx_free_gcm(void)
{
    harness_t hz;
    ncmp_client_t c;
    const uint8_t key[16] = { 1, 2, 3, 4, 5, 6, 7, 8,
                              9, 10, 11, 12, 13, 14, 15, 16 };
    const uint8_t iv[12] = { 0 };
    uint32_t id;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    for (int i = 0; i < 100; ++i) {
        NCMP_CHECK(ncmp_crypto_aes_gcm_init(&c, 0, 1, key, sizeof(key), iv,
                                            sizeof(iv), NULL, 0, 16, &id) ==
                   NCMP_CKR_OK);
        NCMP_CHECK(ncmp_crypto_ctx_free(&c, 0, id, NCMP_CTX_KIND_GCM) ==
                   NCMP_CKR_OK);
    }

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

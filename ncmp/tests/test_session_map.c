/*
 * Token NCMP - (pid, app_sid) -> hsm_sid session-map tests.
 *
 * Verifies the ncmpd session translation (see docs/session-id-mapping.md):
 *   - OPEN_SESSION records sess_map[(pid, app_sid)] = hsm_sid (token handle);
 *   - a later command with wire session_id = app_sid is translated to hsm_sid
 *     before it reaches the token (observed via CLOSE_SESSION, which the mock
 *     validates against the handle it issued);
 *   - CLOSE_SESSION removes the mapping;
 *   - an unmapped app_sid is sent as-is and the token rejects it.
 */
#include "ncmp/ncmp_client.h"
#include "ncmp/ncmp_admin.h"
#include "ncmp/ncmp_slot.h"
#include "ncmp/ncmp_ckr.h"
#include "ncmp/ncmp_shm.h"
#include "ncmp/ncmp_transport.h"
#include "ncmp/ncmp_errno.h"
#include "ncmpd.h"
#include "ncmp_test.h"

#include <pthread.h>
#include <sched.h>
#include <string.h>

#define TEST_SOCK "/tmp/ncmp_sessmap_test.sock"

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

/* Close the session whose app_sid is @p app_sid (wire header carries app_sid;
 * ncmpd translates it to hsm_sid before the token sees it). */
static unsigned long close_app_sid(ncmp_client_t *c, uint32_t app_sid)
{
    c->active_session_id = app_sid;
    return ncmp_admin_close_session(c, 0);
}

int test_session_map_translate(void)
{
    harness_t hz;
    ncmp_client_t c;
    NCMP_Slot *slot;
    uint32_t hsmA = 0, hsmB = 0, hsmC = 0, got = 0;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);
    slot = ncmp_shm_slot(c.shm_base, 0);

    /* OPEN A (app_sid 100) -> token hsm 1; map stored. */
    c.active_session_id = 0;
    NCMP_CHECK(ncmp_admin_open_session(&c, 0, 100u, 0u, &hsmA) == NCMP_CKR_OK);
    NCMP_CHECK(hsmA != 0);
    NCMP_CHECK(ncmp_sess_map_lookup(slot, c.pid, 100u, &got) == 1 && got == hsmA);

    /* OPEN B (app_sid 200) -> token hsm 2. */
    c.active_session_id = 0;
    NCMP_CHECK(ncmp_admin_open_session(&c, 0, 200u, 0u, &hsmB) == NCMP_CKR_OK);
    NCMP_CHECK(hsmB != 0 && hsmB != hsmA);

    /* CLOSE A by app_sid 100: ncmpd translates 100 -> hsmA, the token accepts,
     * and the mapping is removed. */
    NCMP_CHECK(close_app_sid(&c, 100u) == NCMP_CKR_OK);
    NCMP_CHECK(ncmp_sess_map_lookup(slot, c.pid, 100u, &got) == 0);

    /* OPEN C (app_sid 300): the token reuses A's freed handle, so hsmC == hsmA
     * while app_sid (300) differs from it - a real translation is required. */
    c.active_session_id = 0;
    NCMP_CHECK(ncmp_admin_open_session(&c, 0, 300u, 0u, &hsmC) == NCMP_CKR_OK);
    NCMP_CHECK(hsmC == hsmA);
    NCMP_CHECK(ncmp_sess_map_lookup(slot, c.pid, 300u, &got) == 1 && got == hsmC);

    /* CLOSE C by app_sid 300: must translate 300 -> hsmC for the token to accept
     * it. Without translation the token would see handle 300 and reject it. */
    NCMP_CHECK(close_app_sid(&c, 300u) == NCMP_CKR_OK);

    /* Unmapped app_sid: sent as-is, the token rejects the unknown handle. */
    NCMP_CHECK(close_app_sid(&c, 999u) != NCMP_CKR_OK);

    /* CLOSE B tidies up. */
    NCMP_CHECK(close_app_sid(&c, 200u) == NCMP_CKR_OK);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

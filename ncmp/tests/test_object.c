/*
 * Token NCMP - object-management adapter tests.
 *
 * Exercises the ncmp_object_* adapter end-to-end against the mock token: a key
 * object is registered (OBJECT_ADD) and its changed attributes are forwarded
 * (OBJECT_SET_ATTR), plus the rejection paths (missing key material, malformed
 * attribute list). Object storage/enumeration itself is handled by the
 * opencryptoki common layer and is not exercised here.
 */
#include "ncmp/ncmp_client.h"
#include "ncmp/ncmp_object.h"
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

#define TEST_SOCK "/tmp/ncmp_object_test.sock"

/* Wire values are opaque to the mock; use representative PKCS#11 numbers. */
#define TEST_CKO_SECRET_KEY 0x00000004u
#define TEST_CKK_AES        0x0000001Fu
#define TEST_CKA_LABEL      0x00000003u

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

int test_object_add(void)
{
    harness_t hz;
    ncmp_client_t c;
    const uint8_t key[16] = { 0x11, 0x22, 0x33, 0x44 };

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    /* A 16-byte AES key registers cleanly. */
    NCMP_CHECK(ncmp_object_add(&c, 0, TEST_CKO_SECRET_KEY, TEST_CKK_AES, key,
                               sizeof(key)) == NCMP_CKR_OK);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_object_add_no_value(void)
{
    harness_t hz;
    ncmp_client_t c;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    /* A key object with no clear key material is incomplete for import. */
    NCMP_CHECK(ncmp_object_add(&c, 0, TEST_CKO_SECRET_KEY, TEST_CKK_AES, NULL,
                               0) == NCMP_CKR_TEMPLATE_INCOMPLETE);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_object_set_attrs(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint8_t attrs[32];
    uint32_t off = 0;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    /* One changed attribute: CKA_LABEL = "test". */
    ncmp_wr_u32le(attrs + off, 1);              off += 4; /* count */
    ncmp_wr_u32le(attrs + off, TEST_CKA_LABEL); off += 4; /* type */
    ncmp_wr_u32le(attrs + off, 4);              off += 4; /* len */
    memcpy(attrs + off, "test", 4);             off += 4; /* value */
    NCMP_CHECK(ncmp_object_set_attrs(&c, 0, TEST_CKO_SECRET_KEY, TEST_CKK_AES,
                                     attrs, off) == NCMP_CKR_OK);

    /* An empty change list is well-formed and accepted. */
    ncmp_wr_u32le(attrs, 0);
    NCMP_CHECK(ncmp_object_set_attrs(&c, 0, TEST_CKO_SECRET_KEY, TEST_CKK_AES,
                                     attrs, 4) == NCMP_CKR_OK);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_object_set_attrs_malformed(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint8_t attrs[16];
    uint32_t off = 0;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    /* count=2 but only one (truncated) entry follows -> rejected. */
    ncmp_wr_u32le(attrs + off, 2);              off += 4; /* count */
    ncmp_wr_u32le(attrs + off, TEST_CKA_LABEL); off += 4; /* type */
    ncmp_wr_u32le(attrs + off, 4);              off += 4; /* len (no value) */
    NCMP_CHECK(ncmp_object_set_attrs(&c, 0, TEST_CKO_SECRET_KEY, TEST_CKK_AES,
                                     attrs, off) ==
               NCMP_CKR_ATTRIBUTE_VALUE_INVALID);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

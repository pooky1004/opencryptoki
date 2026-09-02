/*
 * Token NCMP - token administration tests (identity, slot binding, login/PIN).
 *
 * Exercises the non-crypto STDLL path end-to-end against the mock token:
 *   - ncmp_admin_* adapter (token identity query + login/PIN lifecycle);
 *   - ncmp_slot_* binding (CK slot -> physical token by label/serial, with the
 *     first-unallocated fallback and cross-open idempotency).
 * The daemon's boot-time identity scan is reproduced here by fetching each
 * slot's identity through the adapter and caching it with ncmp_slot_set_identity,
 * exactly as ncmpd does at startup.
 */
#include "ncmp/ncmp_client.h"
#include "ncmp/ncmp_admin.h"
#include "ncmp/ncmp_slotmap.h"
#include "ncmp/ncmp_ckr.h"
#include "ncmp/ncmp_cmd.h"
#include "ncmp/ncmp_shm.h"
#include "ncmp/ncmp_transport.h"
#include "ncmp/ncmp_errno.h"
#include "ncmpd.h"
#include "mock_token_ncmp.h"
#include "ncmp_test.h"

#include <pthread.h>
#include <sched.h>
#include <string.h>

#define TEST_SOCK "/tmp/ncmp_admin_test.sock"

typedef struct {
    void             *shm_base;
    uint32_t          n;
    ncmp_transport_t *t[PKCS11_MAX_SLOT_COUNT];
    ncmpd_slot_ctx_t  comm[PKCS11_MAX_SLOT_COUNT];
    ncmpd_conn_ctx_t  conn;
} harness_t;

/** Stand up SHM, mark @p n slots online, start their comm threads + conn. */
static int harness_up_n(harness_t *hz, uint32_t n)
{
    memset(hz, 0, sizeof(*hz));
    (void)ncmp_shm_destroy(NULL);
    if (ncmp_shm_create(&hz->shm_base) != NCMP_OK)
        return -1;
    hz->n = n;

    for (uint32_t s = 0; s < n; ++s) {
        NCMP_Slot *slot = ncmp_shm_slot(hz->shm_base, s);

        slot->state = NCMP_SLOT_ONLINE;
        if (ncmp_transport_open(s, &hz->t[s]) != NCMP_OK)
            return -1;
        hz->comm[s].shm_base = hz->shm_base;
        hz->comm[s].slot = slot;
        hz->comm[s].slot_id = s;
        hz->comm[s].transport = hz->t[s];
        if (pthread_create(&hz->comm[s].thread, NULL, ncmpd_comm_thread,
                           &hz->comm[s]))
            return -1;
    }

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
    for (uint32_t s = 0; s < hz->n; ++s) {
        ncmpd_request_stop(&hz->comm[s].stop);
        pthread_join(hz->comm[s].thread, NULL);
        ncmp_transport_close(hz->t[s]);
    }
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

/** Reproduce ncmpd's boot scan: cache every online slot's identity in SHM. */
static int probe_identities(harness_t *hz, ncmp_client_t *c)
{
    for (uint32_t s = 0; s < hz->n; ++s) {
        NCMP_TokenIdentity id;

        if (ncmp_admin_token_info(c, s, &id) != NCMP_CKR_OK)
            return -1;
        if (ncmp_slot_set_identity(hz->shm_base, s, &id) != NCMP_OK)
            return -1;
    }
    return 0;
}

int test_admin_token_info(void)
{
    harness_t hz;
    ncmp_client_t c;
    NCMP_TokenIdentity id;

    NCMP_CHECK(harness_up_n(&hz, 1) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    NCMP_CHECK(ncmp_admin_token_info(&c, 0, &id) == NCMP_CKR_OK);
    NCMP_CHECK(id.valid == 1);
    NCMP_CHECK(strncmp(id.label, "NCMPTOKEN0", 10) == 0);
    NCMP_CHECK(strncmp(id.serial, "NCMPSN0000000", 13) == 0);
    NCMP_CHECK(strncmp(id.manufacturer, "DYST", 4) == 0);
    NCMP_CHECK(strncmp(id.model, "NCMP", 4) == 0);
    NCMP_CHECK(id.fw_major == 1 && id.fw_minor == 0);
    NCMP_CHECK(id.hw_major == 1 && id.hw_minor == 0);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_admin_bind_by_serial(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint32_t phys = 99;

    NCMP_CHECK(harness_up_n(&hz, 2) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);
    NCMP_CHECK(probe_identities(&hz, &c) == 0);

    /* CK slot 5 wants slot 1's serial -> resolves to physical slot 1. */
    NCMP_CHECK(ncmp_slot_bind(c.shm_base, c.slot_mask, 5, NULL,
                              "NCMPSN0000001", &phys) == NCMP_OK);
    NCMP_CHECK(phys == 1);

    /* CK slot 6 wants slot 0's serial -> physical slot 0. */
    phys = 99;
    NCMP_CHECK(ncmp_slot_bind(c.shm_base, c.slot_mask, 6, NULL,
                              "NCMPSN0000000", &phys) == NCMP_OK);
    NCMP_CHECK(phys == 0);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_admin_bind_by_label(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint32_t phys = 99;

    NCMP_CHECK(harness_up_n(&hz, 2) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);
    NCMP_CHECK(probe_identities(&hz, &c) == 0);

    NCMP_CHECK(ncmp_slot_bind(c.shm_base, c.slot_mask, 7, "NCMPTOKEN1", NULL,
                              &phys) == NCMP_OK);
    NCMP_CHECK(phys == 1);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_admin_bind_first_free(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint32_t p0 = 99, p1 = 99, p2 = 99;

    NCMP_CHECK(harness_up_n(&hz, 2) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);
    NCMP_CHECK(probe_identities(&hz, &c) == 0);

    /* No preference: distinct CK slots take distinct physical slots in order. */
    NCMP_CHECK(ncmp_slot_bind(c.shm_base, c.slot_mask, 10, NULL, NULL, &p0)
               == NCMP_OK);
    NCMP_CHECK(ncmp_slot_bind(c.shm_base, c.slot_mask, 11, NULL, NULL, &p1)
               == NCMP_OK);
    NCMP_CHECK(p0 == 0);
    NCMP_CHECK(p1 == 1);

    /* A third CK slot finds no free device. */
    NCMP_CHECK(ncmp_slot_bind(c.shm_base, c.slot_mask, 12, NULL, NULL, &p2)
               == NCMP_ERR_FULL);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_admin_bind_idempotent(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint32_t a = 99, b = 99;

    NCMP_CHECK(harness_up_n(&hz, 2) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);
    NCMP_CHECK(probe_identities(&hz, &c) == 0);

    /* Re-opening the same CK slot resolves to the same physical slot. */
    NCMP_CHECK(ncmp_slot_bind(c.shm_base, c.slot_mask, 3, "NCMPTOKEN1", NULL,
                              &a) == NCMP_OK);
    NCMP_CHECK(ncmp_slot_bind(c.shm_base, c.slot_mask, 3, "NCMPTOKEN1", NULL,
                              &b) == NCMP_OK);
    NCMP_CHECK(a == b && a == 1);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_admin_bind_no_match_falls_back(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint32_t phys = 99;

    NCMP_CHECK(harness_up_n(&hz, 2) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);
    NCMP_CHECK(probe_identities(&hz, &c) == 0);

    /* Unknown serial -> fall back to the first unallocated device (slot 0). */
    NCMP_CHECK(ncmp_slot_bind(c.shm_base, c.slot_mask, 4, "NOPE", "NOPESERIAL",
                              &phys) == NCMP_OK);
    NCMP_CHECK(phys == 0);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_admin_unbind(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint32_t a = 99, b = 99;

    NCMP_CHECK(harness_up_n(&hz, 2) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);
    NCMP_CHECK(probe_identities(&hz, &c) == 0);

    NCMP_CHECK(ncmp_slot_bind(c.shm_base, c.slot_mask, 8, NULL, "NCMPSN0000000",
                              &a) == NCMP_OK);
    NCMP_CHECK(a == 0);
    NCMP_CHECK(ncmp_slot_unbind(c.shm_base, 0, 8) == NCMP_OK);
    /* A different CK slot can now claim the freed device by the same serial. */
    NCMP_CHECK(ncmp_slot_bind(c.shm_base, c.slot_mask, 9, NULL, "NCMPSN0000000",
                              &b) == NCMP_OK);
    NCMP_CHECK(b == 0);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_admin_login(void)
{
    harness_t hz;
    ncmp_client_t c;
    const uint8_t user_pin[] = "1234";
    const uint8_t so_pin[] = "12345678";
    const uint8_t bad_pin[] = "0000";

    NCMP_CHECK(harness_up_n(&hz, 1) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    /* Wrong PIN is rejected. */
    NCMP_CHECK(ncmp_admin_login(&c, 0, NCMP_CKU_USER, bad_pin, 4)
               == NCMP_CKR_PIN_INCORRECT);
    /* Correct user PIN logs in. */
    NCMP_CHECK(ncmp_admin_login(&c, 0, NCMP_CKU_USER, user_pin, 4)
               == NCMP_CKR_OK);
    /* A second login without logout is refused. */
    NCMP_CHECK(ncmp_admin_login(&c, 0, NCMP_CKU_USER, user_pin, 4)
               == NCMP_CKR_USER_ALREADY_LOGGED_IN);
    /* Logout, then log in as SO. */
    NCMP_CHECK(ncmp_admin_logout(&c, 0) == NCMP_CKR_OK);
    NCMP_CHECK(ncmp_admin_login(&c, 0, NCMP_CKU_SO, so_pin, 8) == NCMP_CKR_OK);
    NCMP_CHECK(ncmp_admin_logout(&c, 0) == NCMP_CKR_OK);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_admin_set_pin(void)
{
    harness_t hz;
    ncmp_client_t c;
    const uint8_t old_pin[] = "1234";
    const uint8_t new_pin[] = "9999";

    NCMP_CHECK(harness_up_n(&hz, 1) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    /* Change the user PIN, then prove the new one authenticates. */
    NCMP_CHECK(ncmp_admin_login(&c, 0, NCMP_CKU_USER, old_pin, 4)
               == NCMP_CKR_OK);
    NCMP_CHECK(ncmp_admin_set_pin(&c, 0, old_pin, 4, new_pin, 4)
               == NCMP_CKR_OK);
    NCMP_CHECK(ncmp_admin_logout(&c, 0) == NCMP_CKR_OK);
    NCMP_CHECK(ncmp_admin_login(&c, 0, NCMP_CKU_USER, old_pin, 4)
               == NCMP_CKR_PIN_INCORRECT);
    NCMP_CHECK(ncmp_admin_login(&c, 0, NCMP_CKU_USER, new_pin, 4)
               == NCMP_CKR_OK);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_admin_init_pin(void)
{
    harness_t hz;
    ncmp_client_t c;
    const uint8_t so_pin[] = "12345678";
    const uint8_t new_user[] = "4321";

    NCMP_CHECK(harness_up_n(&hz, 1) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    /* init_pin requires the SO to be logged in. */
    NCMP_CHECK(ncmp_admin_init_pin(&c, 0, new_user, 4)
               == NCMP_CKR_USER_NOT_LOGGED_IN);
    NCMP_CHECK(ncmp_admin_login(&c, 0, NCMP_CKU_SO, so_pin, 8) == NCMP_CKR_OK);
    NCMP_CHECK(ncmp_admin_init_pin(&c, 0, new_user, 4) == NCMP_CKR_OK);
    NCMP_CHECK(ncmp_admin_logout(&c, 0) == NCMP_CKR_OK);
    /* The SO-set user PIN now authenticates. */
    NCMP_CHECK(ncmp_admin_login(&c, 0, NCMP_CKU_USER, new_user, 4)
               == NCMP_CKR_OK);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_admin_init_token(void)
{
    harness_t hz;
    ncmp_client_t c;
    NCMP_TokenIdentity id;
    const uint8_t so_pin[] = "12345678";
    const uint8_t bad_so[] = "00000000";

    NCMP_CHECK(harness_up_n(&hz, 1) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    /* Wrong SO PIN is rejected. */
    NCMP_CHECK(ncmp_admin_init_token(&c, 0, bad_so, 8, "Relabelled")
               == NCMP_CKR_PIN_INCORRECT);
    /* Correct SO PIN relabels the token; the new label is observable. */
    NCMP_CHECK(ncmp_admin_init_token(&c, 0, so_pin, 8, "Relabelled")
               == NCMP_CKR_OK);
    NCMP_CHECK(ncmp_admin_token_info(&c, 0, &id) == NCMP_CKR_OK);
    NCMP_CHECK(strncmp(id.label, "Relabelled", 10) == 0);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

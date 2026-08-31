/*
 * Token NCMP - Multi-threaded concurrency tests (STEP 2, real comm_thread).
 *
 * Several producer threads enqueue to the SAME slot with no slot-level lock
 * (MPSC), while one comm_thread consumes. Verifies correct request/response
 * correlation by (session_id, sequence_id), no entry leaks (all return to
 * FREE), and an accurate total command count.
 */
#include "ncmp/ncmp_shm.h"
#include "ncmp/ncmp_slot.h"
#include "ncmp/ncmp_queue.h"
#include "ncmp/ncmp_transport.h"
#include "ncmp/ncmp_wire.h"
#include "ncmp/ncmp_limits.h"
#include "ncmp/ncmp_errno.h"
#include "ncmpd.h"
#include "ncmp_test.h"

#include <pthread.h>
#include <string.h>

#define NPROD 4
#define NREQ  4

typedef struct {
    void      *base;
    NCMP_Slot *slot;
    uint32_t   session;
    int        ok;
} prod_arg_t;

static void *producer(void *a)
{
    prod_arg_t *p = (prod_arg_t *)a;

    for (int i = 0; i < NREQ; ++i) {
        NCMP_Message req;
        NCMP_Message rsp;
        uint8_t body[8];
        uint8_t rpl[16];
        int idx = -1;

        memset(&req, 0, sizeof(req));
        req.header.session_id = p->session;
        req.header.sequence_id = (uint32_t)i;
        req.header.command_id = 0x200u + (uint32_t)i;
        memcpy(body, "REQ!", 4);
        req.param_len[0] = 4;
        req.payload = body;
        req.payload_cap = 4;

        if (ncmp_slot_enqueue(p->base, p->slot, p->session, (uint32_t)i, &req,
                              &idx) != NCMP_OK)
            return NULL;

        memset(&rsp, 0, sizeof(rsp));
        rsp.payload = rpl;
        rsp.payload_cap = sizeof(rpl);
        if (ncmp_slot_wait(p->base, p->slot, idx, &rsp, 0) != NCMP_OK)
            return NULL;

        if (rsp.header.session_id != p->session ||
            rsp.header.sequence_id != (uint32_t)i || rsp.header.ack != 0 ||
            rsp.param_len[0] != 4 || memcmp(rsp.payload, "REQ!", 4) != 0)
            return NULL;

        p->ok++;
    }
    return NULL;
}

int test_concurrent_enqueue_single_slot(void)
{
    void *base = NULL;
    NCMP_Slot *slot;
    ncmp_transport_t *t = NULL;
    ncmpd_slot_ctx_t ctx;
    pthread_t th[NPROD];
    prod_arg_t pa[NPROD];
    int total_ok = 0;

    NCMP_CHECK(PKCS11_MAX_SLOT_COUNT == 4);

    (void)ncmp_shm_destroy(NULL);
    NCMP_CHECK(ncmp_shm_create(&base) == NCMP_OK);
    slot = ncmp_shm_slot(base, 0);
    NCMP_CHECK(slot != NULL);
    slot->state = NCMP_SLOT_ONLINE;

    NCMP_CHECK(ncmp_transport_open(0, &t) == NCMP_OK);

    memset(&ctx, 0, sizeof(ctx));
    ctx.shm_base = base;
    ctx.slot = slot;
    ctx.slot_id = 0;
    ctx.transport = t;
    NCMP_CHECK(pthread_create(&ctx.thread, NULL, ncmpd_comm_thread, &ctx) == 0);

    for (int p = 0; p < NPROD; ++p) {
        pa[p].base = base;
        pa[p].slot = slot;
        pa[p].session = (uint32_t)(100 + p);
        pa[p].ok = 0;
        NCMP_CHECK(pthread_create(&th[p], NULL, producer, &pa[p]) == 0);
    }
    for (int p = 0; p < NPROD; ++p) {
        pthread_join(th[p], NULL);
        total_ok += pa[p].ok;
    }

    ncmpd_request_stop(&ctx.stop);
    pthread_join(ctx.thread, NULL);

    NCMP_CHECK(total_ok == NPROD * NREQ);
    NCMP_CHECK(slot->stats.stats_total_sent_cmds == (uint64_t)(NPROD * NREQ));
    NCMP_CHECK(slot->stats.in_flight_cnt == 0);
    NCMP_CHECK(slot->stats.stats_max_in_flight >= 1);
    NCMP_CHECK(slot->stats.stats_max_in_flight <= slot->max_inflight);

    /* No leaks: every ring entry must be back to FREE. */
    for (uint32_t i = 0; i < NCMP_QUEUE_DEPTH; ++i)
        NCMP_CHECK(ncmp_qentry_state(&slot->ring[i]) == NCMP_Q_FREE);

    NCMP_CHECK(ncmp_transport_close(t) == NCMP_OK);
    NCMP_CHECK(ncmp_shm_destroy(base) == NCMP_OK);
    return 0;
}

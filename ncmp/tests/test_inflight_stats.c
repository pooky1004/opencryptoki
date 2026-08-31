/*
 * Token NCMP - In-flight statistics tests (STEP 2, real comm_thread).
 *
 * Enqueues N requests BEFORE starting the slot's comm_thread, so the dispatch
 * phase fills the pipe to the in-flight ceiling in one go and the peak is
 * deterministic. Asserts:
 *   - stats_total_sent_cmds == N,
 *   - stats_max_in_flight == max_inflight (== NCMP_DEFAULT_MAX_INFLIGHT),
 *   - in_flight_cnt returns to 0 once every response is consumed.
 */
#include "ncmp/ncmp_shm.h"
#include "ncmp/ncmp_slot.h"
#include "ncmp/ncmp_transport.h"
#include "ncmp/ncmp_wire.h"
#include "ncmp/ncmp_errno.h"
#include "ncmpd.h"
#include "ncmp_test.h"

#include <pthread.h>
#include <string.h>

static void build_req(NCMP_Message *m, uint8_t *payload, uint32_t session,
                      uint32_t seq)
{
    memset(m, 0, sizeof(*m));
    m->header.session_id = session;
    m->header.sequence_id = seq;
    m->header.command_id = 0x100u + seq;
    memcpy(payload, "PING", 4);
    m->param_len[0] = 4;
    m->payload = payload;
    m->payload_cap = 4;
}

int test_inflight_stats_tracking(void)
{
    enum { N = 8 };
    void *base = NULL;
    NCMP_Slot *slot;
    ncmp_transport_t *t = NULL;
    ncmpd_slot_ctx_t ctx;
    int idx[N];
    uint8_t pl[N][8];

    (void)ncmp_shm_destroy(NULL);
    NCMP_CHECK(ncmp_shm_create(&base) == NCMP_OK);
    slot = ncmp_shm_slot(base, 0);
    NCMP_CHECK(slot != NULL);
    slot->state = NCMP_SLOT_ONLINE;
    NCMP_CHECK(slot->max_inflight == NCMP_DEFAULT_MAX_INFLIGHT);

    NCMP_CHECK(ncmp_transport_open(0, &t) == NCMP_OK);

    /* Post all requests while the consumer is still idle. */
    for (int i = 0; i < N; ++i) {
        NCMP_Message req;
        build_req(&req, pl[i], 1u, (uint32_t)i);
        NCMP_CHECK(ncmp_slot_enqueue(base, slot, 1u, (uint32_t)i, &req,
                                     &idx[i]) == NCMP_OK);
    }

    memset(&ctx, 0, sizeof(ctx));
    ctx.shm_base = base;
    ctx.slot = slot;
    ctx.slot_id = 0;
    ctx.transport = t;
    NCMP_CHECK(pthread_create(&ctx.thread, NULL, ncmpd_comm_thread, &ctx) == 0);

    for (int i = 0; i < N; ++i) {
        NCMP_Message rsp;
        uint8_t rpl[64];
        memset(&rsp, 0, sizeof(rsp));
        rsp.payload = rpl;
        rsp.payload_cap = sizeof(rpl);
        NCMP_CHECK(ncmp_slot_wait(base, slot, idx[i], &rsp, 0) == NCMP_OK);
        NCMP_CHECK(rsp.header.sequence_id == (uint32_t)i);
        NCMP_CHECK(rsp.header.ack == 0);
        NCMP_CHECK(rsp.param_len[0] == 4);
        NCMP_CHECK(memcmp(rsp.payload, "PING", 4) == 0);
    }

    ncmpd_request_stop(&ctx.stop);
    pthread_join(ctx.thread, NULL);

    NCMP_CHECK(slot->stats.stats_total_sent_cmds == (uint64_t)N);
    NCMP_CHECK(slot->stats.stats_max_in_flight == NCMP_DEFAULT_MAX_INFLIGHT);
    NCMP_CHECK(slot->stats.stats_max_in_flight <= slot->max_inflight);
    NCMP_CHECK(slot->stats.in_flight_cnt == 0);

    NCMP_CHECK(ncmp_transport_close(t) == NCMP_OK);
    NCMP_CHECK(ncmp_shm_destroy(base) == NCMP_OK);
    return 0;
}

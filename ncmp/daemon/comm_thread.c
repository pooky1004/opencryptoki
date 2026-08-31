/*
 * Token NCMP - Per-slot communication thread (up to 4, one per active slot).
 *
 * Sole consumer of its slot's MPSC ring. Producers (STDLL client threads)
 * CAS entries FREE->CLAIMED->POSTED concurrently; this thread advances
 * POSTED->SENT, dispatches over the transport under the in-flight ceiling,
 * then on each response advances SENT->DONE and wakes the waiting client.
 *
 * Pipelined so multiple commands are outstanding at once (up to
 * slot->max_inflight): the dispatch phase fills the token's containers, then
 * the drain phase collects one response and correlates it by sequence_id.
 * In-flight statistics are updated at dispatch time.
 */
#include "ncmpd.h"
#include "ncmp/ncmp_queue.h"
#include "ncmp/ncmp_wire.h"
#include "ncmp/ncmp_transport.h"
#include "ncmp/ncmp_errno.h"

#include <sched.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/** Atomically read the current in-flight count. */
static uint32_t comm_inflight(const NCMP_Slot *slot)
{
    return __atomic_load_n(&slot->stats.in_flight_cnt, __ATOMIC_ACQUIRE);
}

/**
 * @brief Record stats and reserve an in-flight slot before dispatch.
 * @param slot Slot whose counters are updated.
 *
 * Called only after the caller has confirmed in_flight_cnt < max_inflight, so
 * this always succeeds. This thread is the sole writer of the stats fields, so
 * plain updates are safe; in_flight_cnt is bumped atomically because clients
 * also read it.
 */
static void comm_reserve_inflight(NCMP_Slot *slot)
{
    uint32_t after = comm_inflight(slot) + 1;

    if (after > slot->stats.stats_max_in_flight)
        slot->stats.stats_max_in_flight = after;
    slot->stats.stats_total_sent_cmds++;

    __atomic_add_fetch(&slot->stats.in_flight_cnt, 1, __ATOMIC_ACQ_REL);
}

/** Release the in-flight reservation when a response arrives (or send fails). */
static void comm_release_inflight(NCMP_Slot *slot)
{
    __atomic_sub_fetch(&slot->stats.in_flight_cnt, 1, __ATOMIC_ACQ_REL);
}

/** Find a POSTED entry and claim it for sending (POSTED -> SENT). Returns idx. */
static int comm_take_posted(NCMP_Slot *slot)
{
    for (uint32_t i = 0; i < NCMP_QUEUE_DEPTH; ++i) {
        if (ncmp_qentry_state(&slot->ring[i]) == NCMP_Q_POSTED &&
            ncmp_qentry_cas(&slot->ring[i], NCMP_Q_POSTED, NCMP_Q_SENT))
            return (int)i;
    }
    return -1;
}

/** Match an in-flight (SENT) entry to a response by owner + sequence id. */
static int comm_match_sent(NCMP_Slot *slot, uint32_t session_id,
                           uint32_t sequence_id)
{
    for (uint32_t i = 0; i < NCMP_QUEUE_DEPTH; ++i) {
        NCMP_QEntry *e = &slot->ring[i];

        if (ncmp_qentry_state(e) == NCMP_Q_SENT &&
            e->owner_sess == session_id && e->sequence_id == sequence_id)
            return (int)i;
    }
    return -1;
}

/**
 * @brief Dispatch phase: send POSTED requests until the in-flight ceiling.
 * @return Number of requests dispatched this call.
 */
static int comm_dispatch(ncmpd_slot_ctx_t *ctx)
{
    NCMP_Slot *slot = ctx->slot;
    int dispatched = 0;
    int idx;

    while (comm_inflight(slot) < slot->max_inflight &&
           (idx = comm_take_posted(slot)) >= 0) {
        NCMP_QEntry *e = &slot->ring[idx];
        const uint8_t *req = (const uint8_t *)ncmp_shm_ptr(ctx->shm_base,
                                                           e->req_off);
        int rc;

        comm_reserve_inflight(slot);
        rc = ncmp_transport_send(ctx->transport, req, e->req_len);
        if (rc != NCMP_OK) {
            /* Undo the reservation and requeue for a later attempt. */
            comm_release_inflight(slot);
            ncmp_qentry_cas(e, NCMP_Q_SENT, NCMP_Q_POSTED);
            break;
        }
        ++dispatched;
    }
    return dispatched;
}

/**
 * @brief Drain phase: collect one response and route it to its entry.
 * @return 1 if a response was consumed, 0 otherwise.
 */
static int comm_drain(ncmpd_slot_ctx_t *ctx, uint8_t *rxbuf, size_t rxcap)
{
    NCMP_Slot *slot = ctx->slot;
    NCMP_Header hdr;
    size_t rx_len = 0;
    int idx;

    if (comm_inflight(slot) == 0)
        return 0;
    if (ncmp_transport_recv(ctx->transport, rxbuf, rxcap, &rx_len) != NCMP_OK)
        return 0;
    if (ncmp_wire_decode_header(rxbuf, rx_len, &hdr) != NCMP_OK)
        return 0;

    idx = comm_match_sent(slot, hdr.session_id, hdr.sequence_id);
    if (idx < 0) {
        /* No matching in-flight entry: the client abandoned it. The
         * in-flight reservation is still charged, so release it here. */
        comm_release_inflight(slot);
        return 1;
    }

    NCMP_QEntry *e = &slot->ring[idx];
    uint8_t *rsp = (uint8_t *)ncmp_shm_ptr(ctx->shm_base, e->rsp_off);

    memcpy(rsp, rxbuf, rx_len);
    e->rsp_len = (uint32_t)rx_len;
    comm_release_inflight(slot);

    /* Publish the response. If the client abandoned the entry meanwhile, roll
     * it straight back to FREE instead of DONE. */
    if (!ncmp_qentry_cas(e, NCMP_Q_SENT, NCMP_Q_DONE))
        ncmp_qentry_cas(e, NCMP_Q_ABANDONED, NCMP_Q_FREE);
    return 1;
}

void *ncmpd_comm_thread(void *arg)
{
    ncmpd_slot_ctx_t *ctx = (ncmpd_slot_ctx_t *)arg;
    static _Thread_local uint8_t rxbuf[NCMP_MAX_FRAME_SIZE];

    while (!ncmpd_should_stop(&ctx->stop)) {
        int worked = comm_dispatch(ctx);
        worked += comm_drain(ctx, rxbuf, sizeof(rxbuf));
        if (!worked)
            sched_yield();
    }

    /* Self-report on exit (never from a signal handler). */
    fprintf(stderr,
            "[comm slot %u] total_sent=%llu max_in_flight=%u in_flight=%u\n",
            ctx->slot_id,
            (unsigned long long)ctx->slot->stats.stats_total_sent_cmds,
            ctx->slot->stats.stats_max_in_flight,
            comm_inflight(ctx->slot));
    return NULL;
}

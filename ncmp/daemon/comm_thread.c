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

#ifdef NCMP_HOST_MANAGED_CTX
/*
 * Host-managed multipart context (NCMP_HOST_MANAGED_CTX build).
 *
 * The physical token is stateless: it returns the whole operation context blob
 * on INIT and on every UPDATE, and expects the blob back on UPDATE/FINAL. This
 * comm_thread keeps the blobs host-side (HSM storage is scarce) and bridges so
 * the STDLL keeps using a small context id, unchanged. Convention (see
 * ncmp_cmd.h): parameter 0 is the context slot for the INIT response and every
 * UPDATE/FINAL request; the operation's own data lives in parameters 1+.
 *
 * The table is owned solely by this slot's comm_thread (single consumer), so it
 * needs no lock.
 */
#include "ncmp/ncmp_cmd.h"
#include "ncmp/ncmp_ckr.h"

#include <stdlib.h>

/** Host-side multipart contexts per slot (host RAM is ample vs the HSM). */
#define NCMP_HOST_CTX_MAX 64u

typedef struct ncmp_host_ctx_entry {
    int      in_use;
    uint32_t blob_len;
    uint8_t  blob[NCMP_HOST_CTX_BLOB_MAX];
} ncmp_host_ctx_entry_t;

typedef struct ncmp_host_ctx_table {
    ncmp_host_ctx_entry_t e[NCMP_HOST_CTX_MAX];
} ncmp_host_ctx_table_t;

/** Multipart phase of a context-bearing opcode (else CTX_NONE). */
typedef enum { CTX_NONE = 0, CTX_INIT, CTX_UPDATE, CTX_FINAL, CTX_FREE }
    ctx_phase_t;

static ctx_phase_t ctx_phase_of(uint32_t opcode)
{
    switch (opcode) {
    case NCMP_CMD_DIGEST_INIT:    return CTX_INIT;
    case NCMP_CMD_DIGEST_UPDATE:  return CTX_UPDATE;
    case NCMP_CMD_DIGEST_FINAL:   return CTX_FINAL;
    case NCMP_CMD_AES_GCM_INIT:   return CTX_INIT;
    case NCMP_CMD_AES_GCM_UPDATE: return CTX_UPDATE;
    case NCMP_CMD_AES_GCM_FINAL:  return CTX_FINAL;
    case NCMP_CMD_CTX_FREE:       return CTX_FREE;
    default:                      return CTX_NONE;
    }
}

/** Build+encode a frame from @p h and @p n parameter parts into @p out. */
static int ctx_encode(const NCMP_Header *h, const uint8_t *const parts[],
                      const uint32_t lens[], int n, uint8_t *pay, size_t paycap,
                      uint8_t *out, size_t outcap, size_t *outlen)
{
    NCMP_Message m;

    m.header = *h;
    for (int i = 0; i < NCMP_MAX_PARAM_COUNT; ++i)
        m.param_len[i] = 0;
    m.payload = pay;
    m.payload_cap = paycap;
    if (n > 0 && ncmp_msg_pack(&m, pay, paycap, parts, lens, n) != NCMP_OK)
        return -1;
    return ncmp_wire_encode(&m, out, outcap, outlen);
}

/**
 * @brief Pre-send: on an UPDATE/FINAL request, swap parameter 0 (the STDLL
 *        context id) for the stored context blob before the frame goes to the
 *        token. Returns 1 if @p txbuf holds a transformed frame, 0 to send the
 *        original request unchanged.
 */
static int ctx_xform_request(ncmpd_slot_ctx_t *sctx, const uint8_t *req,
                             uint32_t req_len, uint8_t *txbuf, size_t txcap,
                             size_t *out_len)
{
    static _Thread_local uint8_t dpay[NCMP_MAX_PAYLOAD_SIZE];
    static _Thread_local uint8_t ppay[NCMP_MAX_PAYLOAD_SIZE];
    ncmp_host_ctx_table_t *tbl = (ncmp_host_ctx_table_t *)sctx->host_ctx;
    const uint8_t *parts[NCMP_MAX_PARAM_COUNT];
    uint32_t lens[NCMP_MAX_PARAM_COUNT];
    const uint8_t *p0;
    uint32_t l0, cid;
    NCMP_Message m;
    ctx_phase_t ph;
    int n, i;

    if (tbl == NULL)
        return 0;

    m.payload = dpay;
    m.payload_cap = sizeof(dpay);
    if (ncmp_wire_decode(req, req_len, &m) != NCMP_OK)
        return 0;

    ph = ctx_phase_of(ncmp_cmd_opcode(m.header.command_id));
    if (ph != CTX_UPDATE && ph != CTX_FINAL)
        return 0; /* INIT / non-context: send original */

    if (ncmp_msg_param(&m, 0, &p0, &l0) != NCMP_OK || l0 < 4)
        return 0;
    cid = ncmp_rd_u32le(p0);
    if (cid >= NCMP_HOST_CTX_MAX || !tbl->e[cid].in_use)
        return 0; /* unknown id: let the token reject it */

    /* part0 = stored blob; part1.. = the original operation parameters. */
    parts[0] = tbl->e[cid].blob;
    lens[0] = tbl->e[cid].blob_len;
    n = 1;
    for (i = 1; i < NCMP_MAX_PARAM_COUNT; ++i) {
        const uint8_t *pi;
        uint32_t li;

        if (ncmp_msg_param(&m, i, &pi, &li) != NCMP_OK || li == 0)
            continue;
        parts[n] = pi;
        lens[n] = li;
        ++n;
    }

    if (ctx_encode(&m.header, parts, lens, n, ppay, sizeof(ppay), txbuf, txcap,
                   out_len) != NCMP_OK)
        return 0;
    return 1;
}

/**
 * @brief Post-recv: capture/replace the context in a response.
 *   INIT  : token returned the blob in param0 -> allocate an id, store the blob,
 *           rewrite param0 to that id (so the STDLL gets an id as before).
 *   UPDATE: token returned the updated blob in param0 -> store it, drop param0
 *           (the operation output, if any, is in params 1+ and shifts down).
 *   FINAL : free the context; the response (digest/tag) passes through.
 * Transforms @p rx in place; may change @p *rx_len.
 */
static void ctx_xform_response(ncmpd_slot_ctx_t *sctx, const uint8_t *req,
                               uint32_t req_len, uint8_t *rx, size_t *rx_len,
                               size_t rxcap)
{
    static _Thread_local uint8_t rpay[NCMP_MAX_PAYLOAD_SIZE];
    static _Thread_local uint8_t qpay[NCMP_MAX_PAYLOAD_SIZE];
    static _Thread_local uint8_t opay[NCMP_MAX_PAYLOAD_SIZE];
    static _Thread_local uint8_t enc[NCMP_MAX_FRAME_SIZE];
    ncmp_host_ctx_table_t *tbl = (ncmp_host_ctx_table_t *)sctx->host_ctx;
    const uint8_t *parts[NCMP_MAX_PARAM_COUNT];
    uint32_t lens[NCMP_MAX_PARAM_COUNT];
    const uint8_t *p0;
    uint32_t l0, cid = 0;
    NCMP_Message reqm, m;
    ctx_phase_t ph;
    size_t enclen;
    int n, i;

    if (tbl == NULL)
        return;

    reqm.payload = rpay;
    reqm.payload_cap = sizeof(rpay);
    if (ncmp_wire_decode(req, req_len, &reqm) != NCMP_OK)
        return;
    ph = ctx_phase_of(ncmp_cmd_opcode(reqm.header.command_id));
    if (ph == CTX_NONE)
        return;
    if (ph == CTX_UPDATE || ph == CTX_FINAL || ph == CTX_FREE) {
        if (ncmp_msg_param(&reqm, 0, &p0, &l0) != NCMP_OK || l0 < 4)
            return;
        cid = ncmp_rd_u32le(p0);
    }

    /* Abort/teardown: release the host-side context; response relays as-is. */
    if (ph == CTX_FREE) {
        if (cid < NCMP_HOST_CTX_MAX)
            tbl->e[cid].in_use = 0;
        return;
    }

    m.payload = qpay;
    m.payload_cap = sizeof(qpay);
    if (ncmp_wire_decode(rx, *rx_len, &m) != NCMP_OK)
        return;

    /* On a token error, relay verbatim; FINAL still releases the context. */
    if (m.header.ack != NCMP_CKR_OK) {
        if (ph == CTX_FINAL && cid < NCMP_HOST_CTX_MAX)
            tbl->e[cid].in_use = 0;
        return;
    }

    if (ph == CTX_INIT) {
        const uint8_t *pb;
        uint32_t lb;
        uint8_t idbuf[4];
        int slot = -1;

        if (ncmp_msg_param(&m, 0, &pb, &lb) != NCMP_OK || lb == 0 ||
            lb > NCMP_HOST_CTX_BLOB_MAX)
            return; /* malformed init blob: relay as-is */

        for (i = 0; i < (int)NCMP_HOST_CTX_MAX; ++i) {
            if (!tbl->e[i].in_use) { slot = i; break; }
        }
        if (slot < 0) {
            /* No host context free: surface a device-memory error, no output. */
            NCMP_Header h = m.header;
            h.ack = NCMP_CKR_DEVICE_MEMORY;
            if (ctx_encode(&h, NULL, NULL, 0, opay, sizeof(opay), enc,
                           sizeof(enc), &enclen) == NCMP_OK && enclen <= rxcap) {
                memcpy(rx, enc, enclen);
                *rx_len = enclen;
            }
            return;
        }
        memcpy(tbl->e[slot].blob, pb, lb);
        tbl->e[slot].blob_len = lb;
        tbl->e[slot].in_use = 1;

        /* Response to the STDLL is just the context id in param0. */
        ncmp_wr_u32le(idbuf, (uint32_t)slot);
        parts[0] = idbuf;
        lens[0] = sizeof(idbuf);
        if (ctx_encode(&m.header, parts, lens, 1, opay, sizeof(opay), enc,
                       sizeof(enc), &enclen) == NCMP_OK && enclen <= rxcap) {
            memcpy(rx, enc, enclen);
            *rx_len = enclen;
        }
        return;
    }

    if (ph == CTX_UPDATE) {
        const uint8_t *pb;
        uint32_t lb;

        /* param0 = updated blob -> store it against the request's context id. */
        if (ncmp_msg_param(&m, 0, &pb, &lb) == NCMP_OK && lb > 0 &&
            lb <= NCMP_HOST_CTX_BLOB_MAX && cid < NCMP_HOST_CTX_MAX &&
            tbl->e[cid].in_use) {
            memcpy(tbl->e[cid].blob, pb, lb);
            tbl->e[cid].blob_len = lb;
        }

        /* Drop param0; the operation output (if any) is in params 1+. */
        n = 0;
        for (i = 1; i < NCMP_MAX_PARAM_COUNT; ++i) {
            const uint8_t *pi;
            uint32_t li;

            if (ncmp_msg_param(&m, i, &pi, &li) != NCMP_OK || li == 0)
                continue;
            parts[n] = pi;
            lens[n] = li;
            ++n;
        }
        if (ctx_encode(&m.header, parts, lens, n, opay, sizeof(opay), enc,
                       sizeof(enc), &enclen) == NCMP_OK && enclen <= rxcap) {
            memcpy(rx, enc, enclen);
            *rx_len = enclen;
        }
        return;
    }

    /* CTX_FINAL: free the context; digest/tag passes through unchanged. */
    if (cid < NCMP_HOST_CTX_MAX)
        tbl->e[cid].in_use = 0;
}
#endif /* NCMP_HOST_MANAGED_CTX */

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
        const uint8_t *send = req;
        uint32_t send_len = e->req_len;
        int rc;

#ifdef NCMP_HOST_MANAGED_CTX
        /* Swap the STDLL context id for the stored context blob before send. */
        static _Thread_local uint8_t txbuf[NCMP_MAX_FRAME_SIZE];
        size_t txl = 0;

        if (ctx_xform_request(ctx, req, e->req_len, txbuf, sizeof(txbuf),
                              &txl)) {
            send = txbuf;
            send_len = (uint32_t)txl;
        }
#endif

        comm_reserve_inflight(slot);
        rc = ncmp_transport_send(ctx->transport, send, send_len);
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

#ifdef NCMP_HOST_MANAGED_CTX
    /* Capture the returned context blob (INIT/UPDATE) or free it (FINAL), and
     * present the STDLL a context-id/data-only response as in the default mode. */
    {
        const uint8_t *req = (const uint8_t *)ncmp_shm_ptr(ctx->shm_base,
                                                           e->req_off);
        ctx_xform_response(ctx, req, e->req_len, rxbuf, &rx_len, rxcap);
    }
#endif

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

#ifdef NCMP_HOST_MANAGED_CTX
    /* Per-slot host-side multipart context store, owned solely by this thread. */
    ctx->host_ctx = calloc(1, sizeof(ncmp_host_ctx_table_t));
#endif

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

#ifdef NCMP_HOST_MANAGED_CTX
    free(ctx->host_ctx);
    ctx->host_ctx = NULL;
#endif
    return NULL;
}

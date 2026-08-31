/*
 * Token NCMP - Producer-side slot submission helpers (implementation).
 *
 * See ncmp_slot.h. These run in the client/producer context; the comm_thread
 * is the consumer. No slot-level lock is taken - coordination is purely via
 * the ring entries' CAS state machine.
 */
#include "ncmp/ncmp_slot.h"
#include "ncmp/ncmp_queue.h"
#include "ncmp/ncmp_errno.h"

#include <sched.h>

int ncmp_slot_enqueue(void *base, NCMP_Slot *slot, uint32_t session_id,
                      uint32_t sequence_id, const NCMP_Message *req,
                      int *out_idx)
{
    NCMP_QEntry *e;
    uint8_t *reqbuf;
    size_t enc_len = 0;
    int idx;
    int rc;

    if (!base || !slot || !req || !out_idx)
        return NCMP_ERR_INVAL;

    idx = ncmp_queue_claim(slot->ring, NCMP_QUEUE_DEPTH);
    if (idx < 0)
        return idx; /* NCMP_ERR_FULL */
    e = &slot->ring[idx];

    /* Encode directly into the entry's SHM request buffer. */
    reqbuf = (uint8_t *)ncmp_shm_ptr(base, e->req_off);
    rc = ncmp_wire_encode(req, reqbuf, NCMP_ENTRY_BUF_SIZE, &enc_len);
    if (rc != NCMP_OK) {
        /* Roll the claim back so the entry is reusable. */
        ncmp_qentry_cas(e, NCMP_Q_CLAIMED, NCMP_Q_FREE);
        return rc;
    }

    e->owner_sess = session_id;
    e->sequence_id = sequence_id;
    e->req_len = (uint32_t)enc_len;
    e->rsp_len = 0;

    rc = ncmp_queue_post(e); /* CLAIMED -> POSTED */
    if (rc != NCMP_OK) {
        ncmp_qentry_cas(e, NCMP_Q_CLAIMED, NCMP_Q_FREE);
        return rc;
    }

    *out_idx = idx;
    return NCMP_OK;
}

int ncmp_slot_wait(void *base, NCMP_Slot *slot, int idx, NCMP_Message *rsp,
                   uint64_t spin_budget)
{
    NCMP_QEntry *e;
    const uint8_t *rspbuf;
    uint64_t spins = 0;

    if (!base || !slot || idx < 0 || idx >= (int)NCMP_QUEUE_DEPTH || !rsp)
        return NCMP_ERR_INVAL;
    e = &slot->ring[idx];

    while (ncmp_qentry_state(e) != NCMP_Q_DONE) {
        if (spin_budget && ++spins > spin_budget) {
            /* Give up: mark ABANDONED so a late response is dropped. The
             * comm_thread returns the entry to FREE after that. */
            if (ncmp_qentry_cas(e, NCMP_Q_SENT, NCMP_Q_ABANDONED) ||
                ncmp_qentry_cas(e, NCMP_Q_POSTED, NCMP_Q_ABANDONED))
                return NCMP_ERR_TIMEOUT;
            /* Raced with completion; fall through to consume the DONE state. */
            if (ncmp_qentry_state(e) == NCMP_Q_DONE)
                break;
            return NCMP_ERR_TIMEOUT;
        }
        sched_yield();
    }

    rspbuf = (const uint8_t *)ncmp_shm_ptr(base, e->rsp_off);
    (void)ncmp_wire_decode(rspbuf, e->rsp_len, rsp);

    /* Release the entry for reuse (DONE -> FREE). */
    ncmp_qentry_cas(e, NCMP_Q_DONE, NCMP_Q_FREE);
    return NCMP_OK;
}

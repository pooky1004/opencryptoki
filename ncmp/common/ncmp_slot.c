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
#include <string.h>
#include <time.h>

int ncmp_slot_enqueue(void *base, NCMP_Slot *slot, uint32_t session_id,
                      uint32_t pid, uint32_t sequence_id,
                      const NCMP_Message *req, int *out_idx)
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
    e->pid = pid;
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

/* ------------------------------------------------------------------ */
/* Session map: (pid, app_sid) -> hsm_sid, per slot (ncmpd side).      */
/* ------------------------------------------------------------------ */

int ncmp_sess_map_store(NCMP_Slot *slot, uint32_t pid, uint32_t app_sid,
                        uint32_t hsm_sid)
{
    int free_idx = -1;

    if (!slot)
        return NCMP_ERR_INVAL;
    /* Replace an existing mapping for the same (pid, app_sid) if present. */
    for (int i = 0; i < PKCS11_MAX_SESSION_PER_SLOT; ++i) {
        NCMP_SessMap *m = &slot->sess_map[i];
        if (m->in_use && m->pid == pid && m->app_sid == app_sid) {
            m->hsm_sid = hsm_sid;
            return NCMP_OK;
        }
        if (!m->in_use && free_idx < 0)
            free_idx = i;
    }
    if (free_idx < 0)
        return NCMP_ERR_FULL;
    slot->sess_map[free_idx].pid = pid;
    slot->sess_map[free_idx].app_sid = app_sid;
    slot->sess_map[free_idx].hsm_sid = hsm_sid;
    slot->sess_map[free_idx].in_use = 1;
    return NCMP_OK;
}

int ncmp_sess_map_lookup(const NCMP_Slot *slot, uint32_t pid, uint32_t app_sid,
                         uint32_t *out_hsm)
{
    if (!slot)
        return 0;
    for (int i = 0; i < PKCS11_MAX_SESSION_PER_SLOT; ++i) {
        const NCMP_SessMap *m = &slot->sess_map[i];
        if (m->in_use && m->pid == pid && m->app_sid == app_sid) {
            if (out_hsm)
                *out_hsm = m->hsm_sid;
            return 1;
        }
    }
    return 0;
}

void ncmp_sess_map_remove_hsm(NCMP_Slot *slot, uint32_t hsm_sid)
{
    if (!slot)
        return;
    for (int i = 0; i < PKCS11_MAX_SESSION_PER_SLOT; ++i) {
        NCMP_SessMap *m = &slot->sess_map[i];
        if (m->in_use && m->hsm_sid == hsm_sid) {
            m->in_use = 0;
            m->pid = m->app_sid = m->hsm_sid = 0;
            return;
        }
    }
}

/* ------------------------------------------------------------------ */
/* Last comm<->HSM message capture (Debug App).                        */
/* ------------------------------------------------------------------ */

static uint64_t slot_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

void ncmp_slot_lastmsg_tx(NCMP_Slot *slot, const uint8_t *buf, uint32_t len)
{
    NCMP_LastMsg *lm;
    uint32_t cap;

    if (!slot || !buf)
        return;
    lm = &slot->last_msg;
    cap = len < NCMP_LASTMSG_CAP ? len : NCMP_LASTMSG_CAP;
    if (cap)
        memcpy(lm->tx, buf, cap);
    lm->tx_len = len;
    lm->tx_cap = cap;          /* set length last so a reader sees valid bytes */
    lm->tx_ms = slot_now_ms();
}

void ncmp_slot_lastmsg_rx(NCMP_Slot *slot, const uint8_t *buf, uint32_t len)
{
    NCMP_LastMsg *lm;
    uint32_t cap;

    if (!slot || !buf)
        return;
    lm = &slot->last_msg;
    cap = len < NCMP_LASTMSG_CAP ? len : NCMP_LASTMSG_CAP;
    if (cap)
        memcpy(lm->rx, buf, cap);
    lm->rx_len = len;
    lm->rx_cap = cap;
    lm->rx_ms = slot_now_ms();
}

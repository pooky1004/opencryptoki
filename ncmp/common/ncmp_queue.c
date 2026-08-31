/*
 * Token NCMP - MPSC command queue helpers (implementation).
 *
 * All state changes go through ncmp_qentry_cas() (see ncmp_queue.h). No
 * blocking locks are taken here: producers race only on FREE->CLAIMED CAS.
 */
#include "ncmp/ncmp_queue.h"
#include "ncmp/ncmp_errno.h"

int ncmp_queue_claim(NCMP_QEntry *ring, uint32_t depth)
{
    if (!ring || depth == 0)
        return NCMP_ERR_INVAL;

    /* Linear scan for a FREE entry, claiming the first that CASes cleanly.
     * TODO: start the scan from an atomic hint cursor to reduce contention. */
    for (uint32_t i = 0; i < depth; ++i) {
        if (ncmp_qentry_cas(&ring[i], NCMP_Q_FREE, NCMP_Q_CLAIMED))
            return (int)i;
    }
    return NCMP_ERR_FULL;
}

int ncmp_queue_post(NCMP_QEntry *e)
{
    if (!e)
        return NCMP_ERR_INVAL;

    /* Publish: the request body must be fully written before this CAS so the
     * comm_thread observes a complete entry (ACQ_REL ordering on the CAS). */
    if (!ncmp_qentry_cas(e, NCMP_Q_CLAIMED, NCMP_Q_POSTED))
        return NCMP_ERR_STATE;
    return NCMP_OK;
}

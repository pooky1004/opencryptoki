/*
 * Token NCMP - Lock-free MPSC command queue (CAS state machine).
 *
 * Multiple application threads (producers) enqueue commands to the same slot
 * without any slot-level blocking lock; the slot's single comm_thread is the
 * sole consumer. Entry state is advanced ONLY through
 * __atomic_compare_exchange_n() - direct assignment is FORBIDDEN.
 *
 * State lifecycle:
 *     FREE -> CLAIMED -> POSTED -> SENT -> DONE -> FREE
 *   Timeout path:                  SENT -> ABANDONED -> FREE
 *
 *   FREE      : entry unused, claimable by any producer.
 *   CLAIMED   : a producer owns the entry and is filling the request.
 *   POSTED    : request fully written; visible to the comm_thread.
 *   SENT      : comm_thread dispatched it over USB (in_flight++).
 *   DONE      : response written back; waiting client may consume it.
 *   ABANDONED : client timed out; comm_thread must discard the late response.
 *
 * All buffer references are byte OFFSETS into SHM, never raw pointers.
 */
#ifndef NCMP_QUEUE_H
#define NCMP_QUEUE_H

#include <stdint.h>

/** Queue entry state. Stored as int32 and mutated only via CAS. */
typedef enum ncmp_qstate {
    NCMP_Q_FREE = 0,
    NCMP_Q_CLAIMED = 1,
    NCMP_Q_POSTED = 2,
    NCMP_Q_SENT = 3,
    NCMP_Q_DONE = 4,
    NCMP_Q_ABANDONED = 5
} ncmp_qstate_t;

/** Number of entries in each slot's command ring. Power of two. */
#define NCMP_QUEUE_DEPTH 32

/**
 * A single command slot in the ring. Lives in SHM; contains no pointers.
 * @c req_off / @c rsp_off are byte offsets from the SHM base to the request
 * and response scratch buffers reserved for this entry.
 */
typedef struct ncmp_qentry {
    volatile int32_t state;       /**< ncmp_qstate_t, CAS-only. */
    uint32_t         owner_sess;  /**< Session id of the enqueuing client. */
    uint32_t         sequence_id; /**< Correlates request and response. */
    uint32_t         req_len;     /**< Encoded request length in bytes. */
    uint32_t         rsp_len;     /**< Encoded response length in bytes. */
    uint64_t         req_off;     /**< SHM offset of request buffer. */
    uint64_t         rsp_off;     /**< SHM offset of response buffer. */
    uint64_t         posted_ns;   /**< Enqueue timestamp for timeout logic. */
} NCMP_QEntry;

/**
 * @brief Attempt a CAS state transition on @p e.
 * @param e    Entry to transition.
 * @param from Expected current state.
 * @param to   Desired new state.
 * @return 1 if the transition succeeded, 0 if the observed state differed.
 */
static inline int ncmp_qentry_cas(NCMP_QEntry *e, ncmp_qstate_t from,
                                  ncmp_qstate_t to)
{
    int32_t expected = (int32_t)from;
    return __atomic_compare_exchange_n(&e->state, &expected, (int32_t)to,
                                       0 /* strong */, __ATOMIC_ACQ_REL,
                                       __ATOMIC_ACQUIRE);
}

/** Atomically load the current entry state. */
static inline ncmp_qstate_t ncmp_qentry_state(const NCMP_QEntry *e)
{
    return (ncmp_qstate_t)__atomic_load_n(&e->state, __ATOMIC_ACQUIRE);
}

/**
 * @brief Producer: claim a FREE entry (FREE -> CLAIMED).
 * @param ring  Base of the slot's entry ring.
 * @param depth Ring depth (NCMP_QUEUE_DEPTH).
 * @return Index of the claimed entry, or -1 if the ring is full.
 */
int ncmp_queue_claim(NCMP_QEntry *ring, uint32_t depth);

/**
 * @brief Producer: publish a filled entry (CLAIMED -> POSTED).
 * @return 0 on success; negative NCMP error if @p e was not CLAIMED.
 */
int ncmp_queue_post(NCMP_QEntry *e);

#endif /* NCMP_QUEUE_H */

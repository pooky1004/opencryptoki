/*
 * Token NCMP - MPSC queue CAS state-machine tests.
 * Verifies the FREE->CLAIMED->POSTED transitions and ring-full behavior.
 */
#include "ncmp/ncmp_queue.h"
#include "ncmp/ncmp_errno.h"
#include "ncmp_test.h"

#include <string.h>

int test_queue_claim_post_cycle(void)
{
    NCMP_QEntry ring[NCMP_QUEUE_DEPTH];
    memset(ring, 0, sizeof(ring)); /* all NCMP_Q_FREE */

    int idx = ncmp_queue_claim(ring, NCMP_QUEUE_DEPTH);
    NCMP_CHECK(idx == 0);
    NCMP_CHECK(ncmp_qentry_state(&ring[idx]) == NCMP_Q_CLAIMED);

    NCMP_CHECK(ncmp_queue_post(&ring[idx]) == NCMP_OK);
    NCMP_CHECK(ncmp_qentry_state(&ring[idx]) == NCMP_Q_POSTED);
    return 0;
}

int test_queue_full(void)
{
    NCMP_QEntry ring[NCMP_QUEUE_DEPTH];
    memset(ring, 0, sizeof(ring));

    for (uint32_t i = 0; i < NCMP_QUEUE_DEPTH; ++i)
        NCMP_CHECK(ncmp_queue_claim(ring, NCMP_QUEUE_DEPTH) == (int)i);

    NCMP_CHECK(ncmp_queue_claim(ring, NCMP_QUEUE_DEPTH) == NCMP_ERR_FULL);
    return 0;
}

int test_queue_post_requires_claimed(void)
{
    NCMP_QEntry e;
    memset(&e, 0, sizeof(e)); /* NCMP_Q_FREE */
    NCMP_CHECK(ncmp_queue_post(&e) == NCMP_ERR_STATE);
    return 0;
}

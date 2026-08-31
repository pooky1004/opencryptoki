/*
 * Token NCMP - Per-slot session ceiling tests (max 8 sessions/slot).
 */
#include "ncmp/ncmp_shm.h"
#include "ncmp/ncmp_mutex.h"
#include "ncmp/ncmp_limits.h"
#include "ncmp/ncmp_errno.h"
#include "ncmp_test.h"

#include <string.h>

/* Declared in stdll/ncmp_session.c. */
int ncmp_session_open(NCMP_Slot *slot);
int ncmp_session_close(NCMP_Slot *slot);

int test_session_ceiling(void)
{
    NCMP_Slot slot;
    memset(&slot, 0, sizeof(slot));
    NCMP_CHECK(ncmp_mutex_init(&slot.sess_lock) == 0);

    for (int i = 0; i < PKCS11_MAX_SESSION_PER_SLOT; ++i)
        NCMP_CHECK(ncmp_session_open(&slot) == NCMP_OK);

    /* 9th open must be rejected (maps to CKR_SESSION_COUNT_EXCEEDED). */
    NCMP_CHECK(ncmp_session_open(&slot) == NCMP_ERR_FULL);
    NCMP_CHECK(slot.cur_sessions == PKCS11_MAX_SESSION_PER_SLOT);

    NCMP_CHECK(ncmp_session_close(&slot) == NCMP_OK);
    NCMP_CHECK(ncmp_session_open(&slot) == NCMP_OK); /* slot freed, reusable */
    return 0;
}

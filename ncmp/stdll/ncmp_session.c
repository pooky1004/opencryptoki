/*
 * Token NCMP - Session counter management.
 *
 * STRICT RULE: cur_sessions is mutated ONLY inside the slot's sess_lock
 * critical section (a robust process-shared mutex). It is NOT replaced by raw
 * atomics, because the check-then-increment must be atomic against the
 * PKCS11_MAX_SESSION_PER_SLOT ceiling across processes.
 */
#include "ncmp/ncmp_shm.h"
#include "ncmp/ncmp_mutex.h"
#include "ncmp/ncmp_limits.h"
#include "ncmp/ncmp_errno.h"

/* CKR_SESSION_COUNT_EXCEEDED without pulling in the full PKCS#11 headers here;
 * the STDLL SPI layer maps NCMP codes back to CKR_* for the caller. */

/**
 * @brief Reserve one session on @p slot under sess_lock.
 * @param slot Target slot.
 * @return NCMP_OK on success, NCMP_ERR_FULL if the per-slot ceiling is hit,
 *         or NCMP_ERR_MUTEX on unrecoverable lock failure. The STDLL maps
 *         NCMP_ERR_FULL to CKR_SESSION_COUNT_EXCEEDED.
 */
int ncmp_session_open(NCMP_Slot *slot)
{
    int rc;

    if (!slot)
        return NCMP_ERR_INVAL;

    rc = ncmp_mutex_lock(&slot->sess_lock);
    if (rc < 0)
        return rc;
    /* rc == NCMP_MUTEX_RECOVERED: a prior owner died; cur_sessions may be
     * stale but is a bounded integer, so we proceed under the ceiling check. */

    if (slot->cur_sessions >= PKCS11_MAX_SESSION_PER_SLOT) {
        ncmp_mutex_unlock(&slot->sess_lock);
        return NCMP_ERR_FULL;
    }
    slot->cur_sessions++;
    ncmp_mutex_unlock(&slot->sess_lock);
    return NCMP_OK;
}

/**
 * @brief Release one session on @p slot under sess_lock.
 * @param slot Target slot.
 * @return NCMP_OK or NCMP_ERR_MUTEX.
 */
int ncmp_session_close(NCMP_Slot *slot)
{
    int rc;

    if (!slot)
        return NCMP_ERR_INVAL;

    rc = ncmp_mutex_lock(&slot->sess_lock);
    if (rc < 0)
        return rc;

    if (slot->cur_sessions > 0)
        slot->cur_sessions--;
    ncmp_mutex_unlock(&slot->sess_lock);
    return NCMP_OK;
}

/*
 * Token NCMP - Robust process-shared mutex wrappers (implementation).
 *
 * See include/ncmp/ncmp_mutex.h for the contract. This is the ONLY module
 * permitted to call the raw pthread_mutex_* primitives.
 */
/* Robust process-shared mutex API (pthread_mutexattr_setrobust,
 * pthread_mutex_consistent, PTHREAD_MUTEX_ROBUST) requires _GNU_SOURCE on
 * glibc. Must precede any system header include. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "ncmp/ncmp_mutex.h"
#include "ncmp/ncmp_errno.h"

#include <errno.h>

int ncmp_mutex_init(pthread_mutex_t *m)
{
    pthread_mutexattr_t attr;
    int rc;

    if (!m)
        return NCMP_ERR_INVAL;
    if ((rc = pthread_mutexattr_init(&attr)) != 0)
        return rc;

    /* Process-shared so the mutex works across mmap'd address spaces, and
     * robust so a crashed owner is recoverable via EOWNERDEAD. */
    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
    pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST);

    rc = pthread_mutex_init(m, &attr);
    pthread_mutexattr_destroy(&attr);
    return rc;
}

int ncmp_mutex_lock(pthread_mutex_t *m)
{
    int rc;

    if (!m)
        return NCMP_ERR_INVAL;

    rc = pthread_mutex_lock(m);
    if (rc == 0)
        return NCMP_OK;

    if (rc == EOWNERDEAD) {
        /* Previous owner died holding the lock. Mark state consistent so the
         * caller can repair the protected invariant, then report recovery. */
        if (pthread_mutex_consistent(m) != 0)
            return NCMP_ERR_MUTEX;
        return NCMP_MUTEX_RECOVERED;
    }

    /* ENOTRECOVERABLE or other hard failure. */
    return NCMP_ERR_MUTEX;
}

int ncmp_mutex_unlock(pthread_mutex_t *m)
{
    if (!m)
        return NCMP_ERR_INVAL;
    return pthread_mutex_unlock(m) == 0 ? NCMP_OK : NCMP_ERR_MUTEX;
}

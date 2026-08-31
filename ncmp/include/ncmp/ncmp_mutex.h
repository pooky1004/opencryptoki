/*
 * Token NCMP - Robust, process-shared mutex wrappers.
 *
 * STRICT RULE: pthread_mutex_lock() / pthread_mutex_unlock() MUST NOT be
 * called directly anywhere in the NCMP subsystem. Every SHM-resident mutex
 * is initialized PTHREAD_PROCESS_SHARED + PTHREAD_MUTEX_ROBUST and accessed
 * only through the wrappers below, which recover EOWNERDEAD via
 * pthread_mutex_consistent().
 */
#ifndef NCMP_MUTEX_H
#define NCMP_MUTEX_H

#include <pthread.h>

/**
 * @brief Initialize a mutex for cross-process, crash-robust use.
 *
 * Sets PTHREAD_PROCESS_SHARED and PTHREAD_MUTEX_ROBUST on the attributes.
 * Call exactly once, by the daemon, on freshly mapped SHM.
 *
 * @param m Mutex to initialize (must live in shared memory).
 * @return 0 on success; errno-style positive value on failure.
 */
int ncmp_mutex_init(pthread_mutex_t *m);

/**
 * @brief Lock a robust process-shared mutex, recovering a dead owner.
 *
 * On EOWNERDEAD (previous owner died holding the lock) the wrapper calls
 * pthread_mutex_consistent() and returns success so the caller can repair
 * the protected invariant. Callers MUST treat a successful lock that
 * followed EOWNERDEAD as "state may be inconsistent".
 *
 * @param m Mutex to lock.
 * @return 0 if acquired cleanly, NCMP_MUTEX_RECOVERED if acquired after
 *         EOWNERDEAD recovery, or negative NCMP error on unrecoverable
 *         failure (e.g. ENOTRECOVERABLE).
 */
int ncmp_mutex_lock(pthread_mutex_t *m);

/**
 * @brief Unlock a mutex previously acquired via ncmp_mutex_lock().
 * @param m Mutex to unlock.
 * @return 0 on success; negative NCMP error on failure.
 */
int ncmp_mutex_unlock(pthread_mutex_t *m);

/** Return code from ncmp_mutex_lock() when a dead owner was recovered. */
#define NCMP_MUTEX_RECOVERED 1

#endif /* NCMP_MUTEX_H */

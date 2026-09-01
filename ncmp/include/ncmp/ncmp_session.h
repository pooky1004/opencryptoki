/*
 * Token NCMP - Cross-process session counter (declarations).
 *
 * cur_sessions is mutated ONLY inside the slot's robust process-shared
 * sess_lock, enforcing PKCS11_MAX_SESSION_PER_SLOT across every process that
 * shares the token. See ncmp/stdll/ncmp_session.c.
 */
#ifndef NCMP_SESSION_H
#define NCMP_SESSION_H

#include "ncmp_shm.h"

/**
 * @brief Reserve one session on @p slot under sess_lock.
 * @return NCMP_OK, NCMP_ERR_FULL at the per-slot ceiling, or NCMP_ERR_MUTEX.
 */
int ncmp_session_open(NCMP_Slot *slot);

/**
 * @brief Release one session on @p slot under sess_lock.
 * @return NCMP_OK or NCMP_ERR_MUTEX.
 */
int ncmp_session_close(NCMP_Slot *slot);

#endif /* NCMP_SESSION_H */

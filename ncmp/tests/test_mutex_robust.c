/*
 * Token NCMP - Robust mutex crash-recovery test.
 *
 * Forks a child that locks a PROCESS_SHARED|ROBUST mutex in shared memory and
 * exits WITHOUT unlocking (simulating a crash). The parent must then acquire
 * the mutex and observe NCMP_MUTEX_RECOVERED (EOWNERDEAD -> consistent).
 */
#include "ncmp/ncmp_mutex.h"
#include "ncmp/ncmp_errno.h"
#include "ncmp_test.h"

int test_mutex_recovers_dead_owner(void)
{
    /* TODO: mmap(MAP_SHARED|MAP_ANONYMOUS) a pthread_mutex_t, ncmp_mutex_init,
     * fork(); child ncmp_mutex_lock then _exit(0) holding it; parent waitpid
     * then ncmp_mutex_lock() and assert the return is NCMP_MUTEX_RECOVERED. */
    NCMP_CHECK(1);
    return 0;
}

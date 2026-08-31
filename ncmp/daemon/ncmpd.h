/*
 * Token NCMP - ncmpd internal declarations (daemon-private).
 */
#ifndef NCMPD_H
#define NCMPD_H

#include <pthread.h>
#include <signal.h>
#include <stdint.h>

#include "ncmp/ncmp_shm.h"
#include "ncmp/ncmp_transport.h"

/**
 * Global run flag. Set to 0 by the signal handler ONLY. Async-signal-safe:
 * no other work is performed in the handler. The daemon mirrors clears of this
 * flag into each slot context's `stop` field so comm_threads exit their loops.
 */
extern volatile sig_atomic_t g_running;

/**
 * @brief Atomically request a worker thread (comm/conn) to stop.
 *
 * The stop flag is written by a normal thread (main after g_running clears, or
 * a test harness) and read in the worker's loop, so both sides must be atomic
 * to be race-free - a plain volatile access is a data race under the C11 model.
 */
static inline void ncmpd_request_stop(volatile sig_atomic_t *stop)
{
    __atomic_store_n(stop, 1, __ATOMIC_RELEASE);
}

/** @brief Atomically test a worker stop flag. */
static inline int ncmpd_should_stop(volatile sig_atomic_t *stop)
{
    return __atomic_load_n(stop, __ATOMIC_ACQUIRE);
}

/** Connection thread runtime context. */
typedef struct ncmpd_conn_ctx {
    void                 *shm_base;  /**< Local SHM mapping base. */
    const char           *sock_path; /**< IPC socket path (NULL = default). */
    volatile sig_atomic_t stop;      /**< Set non-zero to stop the accept loop. */
    pthread_t             thread;    /**< conn_thread handle. */
} ncmpd_conn_ctx_t;

/** Per-slot comm_thread runtime context (daemon-local, holds real pointers). */
typedef struct ncmpd_slot_ctx {
    void             *shm_base;  /**< Local SHM mapping base. */
    NCMP_Slot        *slot;      /**< Local pointer into the SHM slot array. */
    uint32_t          slot_id;   /**< Slot index. */
    ncmp_transport_t *transport; /**< Token transport (real USB or mock). */
    pthread_t         thread;    /**< comm_thread handle. */
    volatile sig_atomic_t stop;  /**< Set non-zero to stop the comm loop. */
} ncmpd_slot_ctx_t;

/**
 * @brief Install async-signal-safe handlers that only set g_running = 0.
 * @return 0 on success; negative NCMP error otherwise.
 */
int ncmpd_install_signals(void);

/**
 * @brief Connection thread entry: accept STDLL clients and run the IPC
 *        handshake, handing over the SHM name and online-slot mask.
 * @param arg Pointer to an ncmpd_conn_ctx_t.
 */
void *ncmpd_conn_thread(void *arg);

/**
 * @brief Per-slot comm_thread entry: drain the MPSC ring, dispatch over USB
 *        under the in-flight ceiling, and route responses back.
 * @param arg Pointer to an ncmpd_slot_ctx_t.
 */
void *ncmpd_comm_thread(void *arg);

#endif /* NCMPD_H */

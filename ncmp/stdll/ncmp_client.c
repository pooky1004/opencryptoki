/*
 * Token NCMP - STDLL client transport (implementation).
 *
 * Bridges PKCS#11 calls to the daemon: connects to ncmpd (IPC HELLO/ATTACH),
 * attaches SHM, then for each command claims a ring entry, writes the encoded
 * request, publishes it, and waits for the response - all lock-free on the hot
 * path via the shared ncmp_slot_* helpers.
 */
#include "ncmp/ncmp_client.h"
#include "ncmp/ncmp_ipc.h"
#include "ncmp/ncmp_shm.h"
#include "ncmp/ncmp_slot.h"
#include "ncmp/ncmp_wire.h"
#include "ncmp/ncmp_limits.h"
#include "ncmp/ncmp_errno.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/*
 * Bound on how long ncmp_client_command waits for a response, expressed as
 * ncmp_slot_wait() yield iterations. Generous but finite so a dead daemon
 * surfaces as NCMP_ERR_TIMEOUT instead of hanging a PKCS#11 caller forever.
 */
#define NCMP_CLIENT_SPIN_BUDGET 200000000ull

/*
 * When the slot's SHM ring has no FREE entry, ncmp_slot_enqueue() returns
 * NCMP_ERR_FULL ("message queue allocation failed"). Under many concurrent
 * clients on one token this is transient - the comm_thread drains entries back
 * to FREE continuously - so retry the enqueue a few times with a short backoff
 * before surfacing the error to the PKCS#11 caller.
 */
#ifndef NCMP_CLIENT_ENQUEUE_RETRIES
#define NCMP_CLIENT_ENQUEUE_RETRIES 3        /* extra attempts after the first */
#endif
#define NCMP_CLIENT_ENQUEUE_BACKOFF_US 200   /* grows linearly per retry */

/** Sleep @p usec microseconds (best-effort; ignores EINTR). */
static void ncmp_client_backoff(unsigned usec)
{
    struct timespec ts;
    ts.tv_sec = (time_t)(usec / 1000000u);
    ts.tv_nsec = (long)(usec % 1000000u) * 1000L;
    (void)nanosleep(&ts, NULL);
}

int ncmp_client_init(ncmp_client_t *c, const char *sock_path)
{
    int rc;

    if (!c)
        return NCMP_ERR_INVAL;

    memset(c, 0, sizeof(*c));
    c->ipc_fd = -1;
    c->pid = (uint32_t)getpid();

    rc = ncmp_ipc_connect(sock_path, &c->ipc_fd, &c->slot_mask);
    if (rc != NCMP_OK)
        return rc;

    rc = ncmp_shm_attach(&c->shm_base);
    if (rc != NCMP_OK) {
        close(c->ipc_fd);
        c->ipc_fd = -1;
        return rc;
    }
    return NCMP_OK;
}

int ncmp_client_exec(ncmp_client_t *c, uint32_t slot_id,
                     const NCMP_Message *req, NCMP_Message *rsp,
                     uint64_t spin_budget)
{
    NCMP_Slot *slot;
    int idx = -1;
    int rc;

    if (!c || !c->shm_base || !req || !rsp)
        return NCMP_ERR_INVAL;
    if (slot_id >= PKCS11_MAX_SLOT_COUNT)
        return NCMP_ERR_INVAL;
    /* Reject commands to a slot the daemon did not report as online. */
    if ((c->slot_mask & (1u << slot_id)) == 0)
        return NCMP_ERR_NODAEMON;

    slot = ncmp_shm_slot(c->shm_base, slot_id);
    if (!slot)
        return NCMP_ERR_INVAL;

    /* Enqueue (FREE->CLAIMED->POSTED); the slot's comm_thread consumes it.
     * Retry a full ring (NCMP_ERR_FULL) up to NCMP_CLIENT_ENQUEUE_RETRIES times
     * with a short, growing backoff: with several apps sharing one token the
     * ring fills transiently and drains again within microseconds. */
    rc = ncmp_slot_enqueue(c->shm_base, slot, req->header.session_id,
                           c->pid, req->header.sequence_id, req, &idx);
    for (int attempt = 1;
         rc == NCMP_ERR_FULL && attempt <= NCMP_CLIENT_ENQUEUE_RETRIES;
         ++attempt) {
        ncmp_client_backoff((unsigned)NCMP_CLIENT_ENQUEUE_BACKOFF_US * (unsigned)attempt);
        rc = ncmp_slot_enqueue(c->shm_base, slot, req->header.session_id,
                               c->pid, req->header.sequence_id, req, &idx);
    }
    if (rc != NCMP_OK)
        return rc;

    /* Block until DONE (or timeout -> ABANDONED). rsp->header.ack carries the
     * token's CKR_* result on success. */
    return ncmp_slot_wait(c->shm_base, slot, idx, rsp, spin_budget);
}

int ncmp_client_command(ncmp_client_t *c, uint32_t slot_id, uint32_t opcode,
                        const uint8_t *in, uint32_t in_len,
                        uint8_t *out, uint32_t out_cap, uint32_t *out_len,
                        uint32_t *out_ack)
{
    NCMP_Message req;
    NCMP_Message rsp;
    int rc;

    if (!c || (in_len && !in) || (out_cap && !out))
        return NCMP_ERR_INVAL;
    if (in_len > NCMP_MAX_PARAM_SIZE)
        return NCMP_ERR_PARAM_SIZE;

    memset(&req, 0, sizeof(req));
    req.header.session_id = c->active_session_id; /* token session handle, or 0 */
    req.header.sequence_id = __atomic_add_fetch(&c->seq, 1, __ATOMIC_RELAXED);
    req.header.command_id = opcode;
    req.param_len[0] = in_len;
    req.payload = (uint8_t *)in;   /* encode reads but never mutates */
    req.payload_cap = in_len;

    memset(&rsp, 0, sizeof(rsp));
    rsp.payload = out;
    rsp.payload_cap = out_cap;

    rc = ncmp_client_exec(c, slot_id, &req, &rsp, NCMP_CLIENT_SPIN_BUDGET);
    if (rc != NCMP_OK)
        return rc;

    if (out_ack)
        *out_ack = rsp.header.ack;
    if (out_len)
        *out_len = rsp.param_len[0];
    return NCMP_OK;
}

int ncmp_client_command_mp(ncmp_client_t *c, uint32_t slot_id, uint32_t opcode,
                           const uint8_t *const in[], const uint32_t in_len[],
                           int n_in, uint8_t *out_payload, uint32_t out_cap,
                           NCMP_Message *out_msg)
{
    NCMP_Message req;
    uint8_t *req_payload;
    size_t total = 0;
    int rc;

    if (!c || !in || !in_len || !out_msg || n_in < 1 ||
        n_in > NCMP_MAX_PARAM_COUNT)
        return NCMP_ERR_INVAL;

    for (int i = 0; i < n_in; ++i)
        total += in_len[i];

    /* Scratch buffer for the concatenated request parameters. */
    req_payload = (uint8_t *)malloc(total ? total : 1);
    if (!req_payload)
        return NCMP_ERR_NOSPACE;

    memset(&req, 0, sizeof(req));
    rc = ncmp_msg_pack(&req, req_payload, total ? total : 1, in, in_len, n_in);
    if (rc != NCMP_OK) {
        free(req_payload);
        return rc;
    }
    req.header.session_id = c->active_session_id; /* token session handle, or 0 */
    req.header.sequence_id = __atomic_add_fetch(&c->seq, 1, __ATOMIC_RELAXED);
    req.header.command_id = opcode;

    memset(out_msg, 0, sizeof(*out_msg));
    out_msg->payload = out_payload;
    out_msg->payload_cap = out_cap;

    rc = ncmp_client_exec(c, slot_id, &req, out_msg, NCMP_CLIENT_SPIN_BUDGET);
    free(req_payload);
    return rc;
}

int ncmp_client_fini(ncmp_client_t *c)
{
    if (!c)
        return NCMP_ERR_INVAL;
    if (c->shm_base) {
        ncmp_shm_detach(c->shm_base);
        c->shm_base = NULL;
    }
    if (c->ipc_fd >= 0) {
        close(c->ipc_fd);
        c->ipc_fd = -1;
    }
    return NCMP_OK;
}

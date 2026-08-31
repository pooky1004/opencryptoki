/*
 * Token NCMP - Connection thread (single instance).
 *
 * Accepts STDLL clients on the UNIX socket and performs the HELLO/ATTACH
 * handshake, returning the SHM name and online-slot bitmask. No bulk command
 * data flows here; clients use SHM directly after attaching.
 *
 * The accept loop polls with a short timeout so it can observe ctx->stop and
 * exit cleanly for a graceful shutdown.
 */
#include "ncmpd.h"
#include "ncmp/ncmp_ipc.h"
#include "ncmp/ncmp_shm.h"
#include "ncmp/ncmp_errno.h"

#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/** Compute the online-slot bitmask from the current SHM slot states. */
static uint32_t ncmpd_online_mask(void *shm_base)
{
    NCMP_ShmHeader *h = (NCMP_ShmHeader *)shm_base;
    uint32_t mask = 0;

    for (uint32_t s = 0; s < h->slot_count; ++s) {
        if (h->slots[s].state == NCMP_SLOT_ONLINE)
            mask |= (1u << s);
    }
    return mask;
}

/** Handle one accepted client: read HELLO, reply ATTACH (or ERROR). */
static void ncmpd_conn_serve_one(int cfd, void *shm_base)
{
    NCMP_IpcMsg in;
    NCMP_IpcMsg out;
    ssize_t n;

    n = read(cfd, &in, sizeof(in));
    if (n != (ssize_t)sizeof(in))
        return;

    memset(&out, 0, sizeof(out));
    out.version = NCMP_IPC_VERSION;

    if (in.op == NCMP_IPC_HELLO && in.version == NCMP_IPC_VERSION) {
        out.op = NCMP_IPC_ATTACH;
        out.status = NCMP_OK;
        out.slot_mask = ncmpd_online_mask(shm_base);
        strncpy(out.shm_name, NCMP_SHM_NAME, sizeof(out.shm_name) - 1);
    } else {
        out.op = NCMP_IPC_ERROR;
        out.status = (uint32_t)NCMP_ERR_VERSION;
    }

    {
        ssize_t wr = write(cfd, &out, sizeof(out));
        (void)wr; /* best-effort reply; client will time out if it fails */
    }
}

void *ncmpd_conn_thread(void *arg)
{
    ncmpd_conn_ctx_t *ctx = (ncmpd_conn_ctx_t *)arg;
    int lfd = -1;

    if (ncmp_ipc_listen(ctx->sock_path, &lfd) != NCMP_OK)
        return NULL;

    while (!ncmpd_should_stop(&ctx->stop)) {
        struct pollfd pfd = { .fd = lfd, .events = POLLIN, .revents = 0 };
        int pr = poll(&pfd, 1, 100 /* ms */);
        int cfd;

        if (pr <= 0)
            continue; /* timeout or EINTR: re-check stop */

        cfd = accept(lfd, NULL, NULL);
        if (cfd < 0)
            continue;
        ncmpd_conn_serve_one(cfd, ctx->shm_base);
        close(cfd);
    }

    close(lfd);
    if (ctx->sock_path)
        unlink(ctx->sock_path);
    else
        unlink(NCMP_IPC_SOCK_PATH);
    return NULL;
}

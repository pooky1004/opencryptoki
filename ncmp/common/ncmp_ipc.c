/*
 * Token NCMP - IPC socket helpers (client connect + daemon listen).
 *
 * Only the control handshake travels on this UNIX domain socket; bulk command
 * data goes through shared memory. The daemon's accept/serve loop lives in
 * daemon/conn_thread.c and uses ncmp_ipc_listen() here.
 */
#include "ncmp/ncmp_ipc.h"
#include "ncmp/ncmp_errno.h"

#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/** Fill @p addr for @p path; returns NCMP_ERR_INVAL if the path is too long. */
static int ncmp_ipc_addr(const char *path, struct sockaddr_un *addr)
{
    if (!path)
        path = NCMP_IPC_SOCK_PATH;
    if (strlen(path) >= sizeof(addr->sun_path))
        return NCMP_ERR_INVAL;

    memset(addr, 0, sizeof(*addr));
    addr->sun_family = AF_UNIX;
    strncpy(addr->sun_path, path, sizeof(addr->sun_path) - 1);
    return NCMP_OK;
}

/** Read exactly @p len bytes; returns NCMP_OK or NCMP_ERR_STATE on short read. */
static int ncmp_read_full(int fd, void *buf, size_t len)
{
    uint8_t *p = (uint8_t *)buf;
    size_t got = 0;

    while (got < len) {
        ssize_t n = read(fd, p + got, len - got);
        if (n <= 0)
            return NCMP_ERR_STATE;
        got += (size_t)n;
    }
    return NCMP_OK;
}

/** Write exactly @p len bytes; returns NCMP_OK or NCMP_ERR_STATE on failure. */
static int ncmp_write_full(int fd, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t sent = 0;

    while (sent < len) {
        ssize_t n = write(fd, p + sent, len - sent);
        if (n <= 0)
            return NCMP_ERR_STATE;
        sent += (size_t)n;
    }
    return NCMP_OK;
}

int ncmp_ipc_connect(const char *sock_path, int *out_fd, uint32_t *out_slot_mask)
{
    struct sockaddr_un addr;
    NCMP_IpcMsg hello;
    NCMP_IpcMsg reply;
    int fd;
    int rc;

    if (!out_fd || !out_slot_mask)
        return NCMP_ERR_INVAL;
    rc = ncmp_ipc_addr(sock_path, &addr);
    if (rc != NCMP_OK)
        return rc;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return NCMP_ERR_NODAEMON;
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return NCMP_ERR_NODAEMON;
    }

    memset(&hello, 0, sizeof(hello));
    hello.op = NCMP_IPC_HELLO;
    hello.version = NCMP_IPC_VERSION;
    if (ncmp_write_full(fd, &hello, sizeof(hello)) != NCMP_OK ||
        ncmp_read_full(fd, &reply, sizeof(reply)) != NCMP_OK) {
        close(fd);
        return NCMP_ERR_NODAEMON;
    }

    if (reply.op != NCMP_IPC_ATTACH || reply.version != NCMP_IPC_VERSION) {
        close(fd);
        return NCMP_ERR_VERSION;
    }

    *out_fd = fd;
    *out_slot_mask = reply.slot_mask;
    return NCMP_OK;
}

int ncmp_ipc_listen(const char *sock_path, int *out_listen_fd)
{
    struct sockaddr_un addr;
    int fd;
    int rc;

    if (!out_listen_fd)
        return NCMP_ERR_INVAL;
    rc = ncmp_ipc_addr(sock_path, &addr);
    if (rc != NCMP_OK)
        return rc;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return NCMP_ERR_STATE;

    /* Remove a stale socket file from a previous run before binding. */
    unlink(addr.sun_path);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(fd, 8) != 0) {
        close(fd);
        return NCMP_ERR_STATE;
    }

    *out_listen_fd = fd;
    return NCMP_OK;
}

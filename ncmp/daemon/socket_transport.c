/*
 * Token NCMP - TCP socket transport backend (ncmp_transport.h implementation).
 *
 * Provides the same ncmp_transport_* symbols the daemon uses, but carries wire
 * frames over a TCP socket to a frame server (the GUI mock_server, or any
 * endpoint speaking the NCMP link protocol) instead of libusb. This realizes
 * the "ncmpd --socket--> mock" path: build ncmpd with -DENABLE_SOCKET_TOKEN=ON
 * so it connects to mock_server, exercising the real STDLL -> token_specific ->
 * ncmpd stack without hardware. See docs/app-stdll-path-design.md.
 *
 * One TCP connection per slot: slot s connects to host:(port_base + s), matching
 * mock_server's "data port = base + slot" convention.
 *
 * Configuration (environment):
 *   NCMP_SOCKET_HOST       server host            (default "127.0.0.1")
 *   NCMP_SOCKET_PORT_BASE  base data port         (default 7010; slot s = base+s)
 *   NCMP_SOCKET_SLOTS      max slots to probe     (default PKCS11_MAX_SLOT_COUNT)
 *
 * Style: Google C Style. A developer/testing backend, not the shipped path.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "ncmp/ncmp_transport.h"
#include "ncmp/ncmp_wire.h"
#include "ncmp/ncmp_limits.h"
#include "ncmp/ncmp_errno.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct ncmp_transport {
    uint32_t slot_id;
    int      fd;
};

/* --- configuration helpers ------------------------------------------------ */

static const char *sock_host(void)
{
    const char *h = getenv("NCMP_SOCKET_HOST");
    return (h && *h) ? h : "127.0.0.1";
}

static int sock_port_base(void)
{
    const char *p = getenv("NCMP_SOCKET_PORT_BASE");
    int v = p ? atoi(p) : 0;
    return (v > 0 && v < 65536) ? v : 7010;
}

static uint32_t sock_slots(void)
{
    const char *s = getenv("NCMP_SOCKET_SLOTS");
    int v = s ? atoi(s) : 0;
    if (v < 1 || v > PKCS11_MAX_SLOT_COUNT)
        v = PKCS11_MAX_SLOT_COUNT;
    return (uint32_t)v;
}

/* --- blocking socket I/O -------------------------------------------------- */

/** Connect to host:port, returning a fd or -1. */
static int connect_tcp(const char *host, int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    struct sockaddr_in addr;

    if (fd < 0)
        return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    return fd;
}

static int read_full(int fd, void *buf, size_t n)
{
    uint8_t *p = buf;
    size_t got = 0;
    while (got < n) {
        ssize_t r = recv(fd, p + got, n - got, 0);
        if (r == 0)
            return NCMP_ERR_USB; /* peer closed */
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return NCMP_ERR_USB;
        }
        got += (size_t)r;
    }
    return NCMP_OK;
}

static int write_full(int fd, const void *buf, size_t n)
{
    const uint8_t *p = buf;
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = send(fd, p + sent, n - sent, MSG_NOSIGNAL);
        if (w <= 0) {
            if (w < 0 && errno == EINTR)
                continue;
            return NCMP_ERR_USB;
        }
        sent += (size_t)w;
    }
    return NCMP_OK;
}

/* --- ncmp_transport_* implementation -------------------------------------- */

static int sock_probe(uint32_t *out_slot_mask)
{
    const char *host = sock_host();
    int base = sock_port_base();
    uint32_t n = sock_slots();

    if (!out_slot_mask)
        return NCMP_ERR_INVAL;
    *out_slot_mask = 0;
    /* A slot is "present" if its data port accepts a connection right now. */
    for (uint32_t s = 0; s < n && s < PKCS11_MAX_SLOT_COUNT; ++s) {
        int fd = connect_tcp(host, base + (int)s);
        if (fd >= 0) {
            *out_slot_mask |= (1u << s);
            close(fd);
        }
    }
    return NCMP_OK;
}

static int sock_open(uint32_t slot_id, ncmp_transport_t **out)
{
    ncmp_transport_t *t;
    int fd;

    if (!out || slot_id >= PKCS11_MAX_SLOT_COUNT)
        return NCMP_ERR_INVAL;
    fd = connect_tcp(sock_host(), sock_port_base() + (int)slot_id);
    if (fd < 0)
        return NCMP_ERR_USB;
    t = calloc(1, sizeof(*t));
    if (!t) {
        close(fd);
        return NCMP_ERR_NOSPACE;
    }
    t->slot_id = slot_id;
    t->fd = fd;
    *out = t;
    return NCMP_OK;
}

static int sock_send(ncmp_transport_t *t, const uint8_t *frame, size_t len)
{
    if (!t || !frame || len < NCMP_FRAME_PREFIX_SIZE)
        return NCMP_ERR_INVAL;
    return write_full(t->fd, frame, len);
}

static int sock_recv(ncmp_transport_t *t, uint8_t *buf, size_t buf_len,
                        size_t *out_len)
{
    uint32_t frame_len;
    int rc;

    if (!t || !buf || !out_len)
        return NCMP_ERR_INVAL;
    if (buf_len < NCMP_FRAME_PREFIX_SIZE)
        return NCMP_ERR_NOSPACE;

    /* Single logical frame: 4-byte length prefix, then that many bytes. The
     * read may span several recv() calls, but the frame is parsed as one unit
     * (not a header-then-remainder protocol split). */
    rc = read_full(t->fd, buf, NCMP_FRAME_PREFIX_SIZE);
    if (rc != NCMP_OK)
        return rc;
    memcpy(&frame_len, buf, sizeof(frame_len));
    if ((size_t)frame_len + NCMP_FRAME_PREFIX_SIZE > buf_len)
        return NCMP_ERR_NOSPACE;
    if (frame_len == 0)
        return NCMP_ERR_TRUNCATED;
    rc = read_full(t->fd, buf + NCMP_FRAME_PREFIX_SIZE, frame_len);
    if (rc != NCMP_OK)
        return rc;
    *out_len = NCMP_FRAME_PREFIX_SIZE + frame_len;
    return NCMP_OK;
}

static int sock_close(ncmp_transport_t *t)
{
    if (t) {
        if (t->fd >= 0)
            close(t->fd);
        free(t);
    }
    return NCMP_OK;
}

/* Backend op table (dispatcher selects this for NCMP_BACKEND_SOCKET). */
const ncmp_transport_ops ncmp_socket_ops = {
    sock_probe, sock_open, sock_send, sock_recv, sock_close
};

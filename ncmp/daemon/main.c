/*
 * Token NCMP - ncmpd daemon entry point.
 *
 * Lifecycle:
 *   1. Install async-signal-safe handlers (set g_running=0 only).
 *   2. Create SHM (ncmp_shm_create) and initialize all robust mutexes.
 *   3. Probe tokens; mark each present slot ONLINE and start one comm_thread
 *      per slot (<=4), each with its own transport handle.
 *   4. Start the single connection thread for STDLL IPC handshakes.
 *   5. Wait until g_running clears, then stop and join every thread. Each
 *      comm_thread prints its own in-flight/throughput summary as it exits
 *      (never from the signal handler).
 *
 * The transport backend (real libusb vs mock loopback) is chosen at link time;
 * this file is backend-agnostic and drives everything through ncmp_transport_*.
 */
#include "ncmpd.h"
#include "ncmp/ncmp_shm.h"
#include "ncmp/ncmp_slot.h"
#include "ncmp/ncmp_slotmap.h"
#include "ncmp/ncmp_transport.h"
#include "ncmp/ncmp_wire.h"
#include "ncmp/ncmp_cmd.h"
#include "ncmp/ncmp_ipc.h"
#include "ncmp/ncmp_errno.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

volatile sig_atomic_t g_running = 1;

/**
 * @brief Async-signal-safe termination handler.
 * @param signo Delivered signal (unused).
 *
 * MUST only touch the atomic flag. No printf/malloc/locks here.
 */
static void on_terminate(int signo)
{
    (void)signo;
    g_running = 0;
}

int ncmpd_install_signals(void)
{
    struct sigaction sa;

    sa.sa_handler = on_terminate;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGINT, &sa, NULL) != 0 ||
        sigaction(SIGTERM, &sa, NULL) != 0)
        return NCMP_ERR_STATE;

    /* Never die from a client socket disconnect. */
    signal(SIGPIPE, SIG_IGN);
    return NCMP_OK;
}

/** Best-effort creation of the default socket directory (/run/ncmpd). */
static void ncmpd_ensure_sock_dir(void)
{
    (void)mkdir("/run/ncmpd", 0755); /* ignore EEXIST / permission errors */
}

/**
 * @brief Query one token's identity over its transport and cache it in SHM.
 *
 * Runs a single synchronous NCMP_CMD_VD_TOKEN_INFO round-trip before the slot's
 * comm_thread starts (so the transport is used exclusively here), then stores
 * the decoded identity so every STDLL process can match a CK slot to a physical
 * token by label or serial. A probe failure is non-fatal: the slot still serves
 * crypto, it just has no cached identity (binding falls back to first-free).
 */
#if 0 /* Boot-time identity probe disabled (per request); see the call site. */
static void ncmpd_probe_identity(ncmp_transport_t *transport, uint32_t slot_id,
                                 void *shm_base)
{
    uint8_t reqbuf[64];
    uint8_t rspbuf[NCMP_MAX_FRAME_SIZE];
    uint8_t payload[128];
    NCMP_Message req;
    NCMP_Message rsp;
    NCMP_TokenIdentity ident;
    const uint8_t *blob;
    uint32_t blob_len;
    size_t enc_len = 0;
    size_t got = 0;

    memset(&req, 0, sizeof(req));
    req.header.command_id = NCMP_CMD_VD_TOKEN_INFO;
    req.payload = payload;
    req.payload_cap = sizeof(payload);
    if (ncmp_wire_encode(&req, reqbuf, sizeof(reqbuf), &enc_len) != NCMP_OK)
        return;
    /* Capture the boot identity probe as this slot's last comm<->HSM message so
     * the Debug App shows something right after startup (before app commands). */
    {
        NCMP_Slot *slot = ncmp_shm_slot(shm_base, slot_id);
        if (slot)
            ncmp_slot_lastmsg_tx(slot, reqbuf, (uint32_t)enc_len);
        if (ncmp_transport_send(transport, reqbuf, enc_len) != NCMP_OK)
            return;
        if (ncmp_transport_recv(transport, rspbuf, sizeof(rspbuf), &got) != NCMP_OK)
            return;
        if (slot)
            ncmp_slot_lastmsg_rx(slot, rspbuf, (uint32_t)got);
    }

    rsp.payload = payload;
    rsp.payload_cap = sizeof(payload);
    if (ncmp_wire_decode(rspbuf, got, &rsp) != NCMP_OK)
        return;
    if (ncmp_msg_param(&rsp, 0, &blob, &blob_len) != NCMP_OK)
        return;
    if (ncmp_token_info_unpack(blob, blob_len, &ident) != NCMP_OK)
        return;

    (void)ncmp_slot_set_identity(shm_base, slot_id, &ident);
    fprintf(stderr, "ncmpd: slot %u token '%.*s' serial '%.*s'\n", slot_id,
            (int)NCMP_TI_LABEL_LEN, ident.label,
            (int)NCMP_TI_SERIAL_LEN, ident.serial);
}
#endif /* boot-time identity probe disabled */

/**
 * @brief Enforce a single system-wide ncmpd instance.
 *
 * ncmpd owns the one physical USB device and the shared memory, so a second
 * instance must never run (two daemons would fight over the FX3 and corrupt the
 * rendezvous). Hold an exclusive, non-blocking advisory lock on a fixed file
 * for the whole process lifetime; the kernel releases it automatically when the
 * process exits (or is killed), so a stale lock file is harmless. Path defaults
 * to /tmp/ncmpd.lock, overridable with $NCMP_LOCK_PATH.
 *
 * @return The held lock fd (kept open on purpose) on success; -1 if another
 *         instance holds the lock or the file cannot be locked.
 */
static int ncmpd_single_instance_lock(void)
{
    const char *path = getenv("NCMP_LOCK_PATH");
    int fd;

    if (!path || !*path)
        path = "/tmp/ncmpd.lock";

    fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
    if (fd < 0) {
        fprintf(stderr, "ncmpd: cannot open lock file %s: %s\n",
                path, strerror(errno));
        return -1;
    }
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        if (errno == EWOULDBLOCK)
            fprintf(stderr, "ncmpd: another ncmpd is already running "
                    "(lock %s held) - only one ncmpd may run system-wide; "
                    "reuse it (share its socket) or stop it first.\n", path);
        else
            fprintf(stderr, "ncmpd: flock(%s) failed: %s\n",
                    path, strerror(errno));
        close(fd);
        return -1;
    }
    /* Record the PID for diagnostics; keep the fd open to hold the lock. */
    if (ftruncate(fd, 0) == 0) {
        char buf[32];
        int n = snprintf(buf, sizeof(buf), "%d\n", (int)getpid());
        if (n > 0) {
            ssize_t w = write(fd, buf, (size_t)n);
            (void)w;
        }
    }
    return fd;
}

int main(int argc, char **argv)
{
    ncmpd_slot_ctx_t slots[PKCS11_MAX_SLOT_COUNT];
    ncmpd_conn_ctx_t conn;
    void *shm_base = NULL;
    const char *sock_path;
    uint32_t slot_mask = 0;
    uint32_t started = 0;
    int rc;

    /* Transport backend: comm threads send to the real target (USB) or the
     * mock (or a socket frame server). Default = real; override with
     * --transport real|mock|socket or $NCMP_TRANSPORT. */
    ncmp_backend_kind backend = NCMP_BACKEND_REAL;
    const char *tsel = getenv("NCMP_TRANSPORT");
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--transport") && i + 1 < argc)
            tsel = argv[++i];
    }
    if (tsel) {
        if (!strcmp(tsel, "mock"))
            backend = NCMP_BACKEND_MOCK;
        else if (!strcmp(tsel, "socket"))
            backend = NCMP_BACKEND_SOCKET;
        else if (!strcmp(tsel, "real"))
            backend = NCMP_BACKEND_REAL;
        else {
            fprintf(stderr, "ncmpd: unknown --transport '%s' "
                    "(use real|mock|socket)\n", tsel);
            return 2;
        }
    }
    ncmp_transport_set_backend(backend);
    fprintf(stderr, "ncmpd: transport = %s\n",
            backend == NCMP_BACKEND_MOCK ? "mock" :
            backend == NCMP_BACKEND_SOCKET ? "socket" : "real");

    /* Refuse to start if another ncmpd already runs (single device/SHM owner).
     * The lock fd is intentionally held for the process lifetime. */
    if (ncmpd_single_instance_lock() < 0)
        return 1;

    if (ncmpd_install_signals() != NCMP_OK) {
        fprintf(stderr, "ncmpd: failed to install signal handlers\n");
        return 1;
    }

    rc = ncmp_shm_create(&shm_base);
    if (rc != NCMP_OK) {
        fprintf(stderr, "ncmpd: SHM create failed (%d)\n", rc);
        return 1;
    }

    /* Discover tokens and bring one comm_thread up per present slot. */
    if (ncmp_transport_probe(&slot_mask) != NCMP_OK)
        slot_mask = 0;

    for (uint32_t s = 0; s < NCMP_SLOT_SCAN_MAX; ++s) {
        NCMP_Slot *slot;

        if (NCMP_SLOT_IN_MASK(slot_mask, s) == 0)
            continue;
        slot = ncmp_shm_slot(shm_base, s);

        memset(&slots[s], 0, sizeof(slots[s]));
        slots[s].shm_base = shm_base;
        slots[s].slot = slot;
        slots[s].slot_id = s;

        /* The real FX3 Slave-FIFO path is strictly one request/response at a
         * time (bus-turnaround erratum; see usb_transport.c), so serialise it.
         * Mock/socket keep the pipelined default. */
        if (backend == NCMP_BACKEND_REAL)
            slot->max_inflight = 1;

        if (ncmp_transport_open(s, &slots[s].transport) != NCMP_OK) {
            fprintf(stderr, "ncmpd: slot %u transport open failed "
                    "(device busy? another ncmpd/process may hold the FX3, "
                    "or check udev/permissions)\n", s);
            continue;
        }

        /* Boot-time token-identity scan DISABLED (per request): do not open a
         * session or query the token (VD_TOKEN_INFO) at startup. Identity is
         * fetched later within a session instead. Leaving it on made the Debug
         * App's comm<->HSM view always show a TOKEN_INFO TX (and an empty RX on a
         * non-responding token). CK-slot binding by label/serial then falls back
         * to first-free until an in-session identity query runs. */
        /* ncmpd_probe_identity(slots[s].transport, s, shm_base); */

        if (pthread_create(&slots[s].thread, NULL, ncmpd_comm_thread,
                           &slots[s]) != 0) {
            fprintf(stderr, "ncmpd: slot %u comm_thread start failed\n", s);
            ncmp_transport_close(slots[s].transport);
            slots[s].transport = NULL;
            continue;
        }
        slot->state = NCMP_SLOT_ONLINE;
        started |= (1u << s);
    }

    /* Start the connection/handshake thread. NCMP_SOCK_PATH overrides the
     * default socket location (useful for unprivileged dev runs). */
    sock_path = getenv("NCMP_SOCK_PATH");
    if (!sock_path)
        ncmpd_ensure_sock_dir();
    memset(&conn, 0, sizeof(conn));
    conn.shm_base = shm_base;
    conn.sock_path = sock_path; /* NULL => NCMP_IPC_SOCK_PATH */
    if (pthread_create(&conn.thread, NULL, ncmpd_conn_thread, &conn) != 0) {
        fprintf(stderr, "ncmpd: conn_thread start failed\n");
        g_running = 0;
    }

    fprintf(stderr, "ncmpd: running (online slots mask=0x%x)\n", started);

    /* Idle until a termination signal clears g_running. */
    while (g_running) {
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 100 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }

    /* Graceful shutdown: stop conn first, then each comm_thread. */
    ncmpd_request_stop(&conn.stop);
    pthread_join(conn.thread, NULL);

    for (uint32_t s = 0; s < NCMP_SLOT_SCAN_MAX; ++s) {
        if (NCMP_SLOT_IN_MASK(started, s) == 0)
            continue;
        ncmpd_request_stop(&slots[s].stop);
        pthread_join(slots[s].thread, NULL);
        ncmp_transport_close(slots[s].transport);
    }

    ncmp_shm_destroy(shm_base);
    fprintf(stderr, "ncmpd: stopped\n");
    return 0;
}

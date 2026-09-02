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
#include "ncmp/ncmp_slotmap.h"
#include "ncmp/ncmp_transport.h"
#include "ncmp/ncmp_wire.h"
#include "ncmp/ncmp_cmd.h"
#include "ncmp/ncmp_ipc.h"
#include "ncmp/ncmp_errno.h"

#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

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
    if (ncmp_transport_send(transport, reqbuf, enc_len) != NCMP_OK)
        return;
    if (ncmp_transport_recv(transport, rspbuf, sizeof(rspbuf), &got) != NCMP_OK)
        return;

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

int main(int argc, char **argv)
{
    ncmpd_slot_ctx_t slots[PKCS11_MAX_SLOT_COUNT];
    ncmpd_conn_ctx_t conn;
    void *shm_base = NULL;
    const char *sock_path;
    uint32_t slot_mask = 0;
    uint32_t started = 0;
    int rc;

    (void)argc;
    (void)argv;

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

    for (uint32_t s = 0; s < PKCS11_MAX_SLOT_COUNT; ++s) {
        NCMP_Slot *slot;

        if ((slot_mask & (1u << s)) == 0)
            continue;
        slot = ncmp_shm_slot(shm_base, s);

        memset(&slots[s], 0, sizeof(slots[s]));
        slots[s].shm_base = shm_base;
        slots[s].slot = slot;
        slots[s].slot_id = s;

        if (ncmp_transport_open(s, &slots[s].transport) != NCMP_OK) {
            fprintf(stderr, "ncmpd: slot %u transport open failed\n", s);
            continue;
        }

        /* Scan the token's identity before its comm_thread claims the
         * transport, and cache it in SHM for CK-slot binding. */
        ncmpd_probe_identity(slots[s].transport, s, shm_base);

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

    for (uint32_t s = 0; s < PKCS11_MAX_SLOT_COUNT; ++s) {
        if ((started & (1u << s)) == 0)
            continue;
        ncmpd_request_stop(&slots[s].stop);
        pthread_join(slots[s].thread, NULL);
        ncmp_transport_close(slots[s].transport);
    }

    ncmp_shm_destroy(shm_base);
    fprintf(stderr, "ncmpd: stopped\n");
    return 0;
}

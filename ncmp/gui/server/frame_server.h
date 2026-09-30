/*
 * Token NCMP - Generic wire-frame socket server (shared scaffolding).
 *
 * Both the mock HSM server and the real-HSM bridge are the same server: a
 * per-slot data port carrying wire frames plus a JSON control port for stats,
 * a debug ring, and link up/down. Only the *backend* differs - the emulator
 * (mover + MCU on a mock_device_t) versus the USB transport (ncmp_transport_*).
 * This module owns the sockets, threads, statistics and control protocol; a
 * backend supplies the per-slot request->response execution and (optionally)
 * identity get/set.
 */
#ifndef NCMP_FRAME_SERVER_H
#define NCMP_FRAME_SERVER_H

#include <stddef.h>
#include <stdint.h>

#include "ncmp/ncmp_limits.h"

#define FS_MAX_SLOTS PKCS11_MAX_SLOT_COUNT

/**
 * Backend vtable. Every callback receives the per-slot context pointer the
 * caller placed in fs_config.ctx[slot]. All callbacks run under the slot lock,
 * so a backend needs no locking of its own.
 */
typedef struct fs_backend {
    /**
     * Execute one complete request frame into a response frame.
     * @return 0 (NCMP_OK) on success; negative NCMP error on failure (the
     *         server records an error and drops the data link).
     */
    int (*exec)(void *ctx, const uint8_t *req, size_t req_len,
                uint8_t *rsp, size_t rsp_cap, size_t *rsp_len);

    /** Optional: write identity JSON key/values (no surrounding braces) into
     *  @p out. Return bytes written, or -1 if unsupported. NULL => unsupported. */
    int (*get_identity)(void *ctx, char *out, size_t cap);

    /** Optional: apply identity fields from a JSON body. Return 0 on success,
     *  negative on error, or -1 if unsupported. NULL => unsupported. */
    int (*set_identity)(void *ctx, const char *body);

    /** Optional: reset backend device state (keeps identity). NULL => no-op. */
    void (*reset)(void *ctx);

    /** Write a short label for the slot list into @p out. */
    void (*label)(void *ctx, char *out, size_t cap);
} fs_backend_t;

/** Server configuration passed to fs_run(). */
typedef struct fs_config {
    const char        *name;            /**< Banner name (e.g. "mock"/"bridge"). */
    uint32_t           n_slots;         /**< Number of slots (1..FS_MAX_SLOTS). */
    int                data_port_base;  /**< Slot s listens on base + s. */
    int                ctrl_port;       /**< Control (JSON) port. */
    const fs_backend_t *backend;        /**< Per-slot execution backend. */
    void              *ctx[FS_MAX_SLOTS]; /**< Per-slot backend context. */
} fs_config_t;

/**
 * @brief Run the server: bind the control + per-slot data ports and serve
 *        until SIGINT/SIGTERM. Blocking.
 * @return 0 on clean shutdown, non-zero on a fatal setup error.
 */
int fs_run(const fs_config_t *cfg);

/* --- JSON helpers (exposed for backends' identity get/set) ---------------- */

/** Extract a quoted string value for "key" from a flat JSON object. 0/-1. */
int fs_json_get_str(const char *buf, const char *key, char *out, size_t cap);
/** Extract an integer value for "key" from a flat JSON object. 0/-1. */
int fs_json_get_int(const char *buf, const char *key, long *out);
/** JSON-escape @p in (length @p inlen) into @p out. */
void fs_json_escape(const char *in, size_t inlen, char *out, size_t cap);

#endif /* NCMP_FRAME_SERVER_H */

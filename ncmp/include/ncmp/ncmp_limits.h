/*
 * Token NCMP - System resource limits and hardware constants.
 *
 * Private fork of opencryptoki. All values here are compile-time constants
 * shared by ncmpd, libpkcs11_ncmp.so, the mock token, and the test suite.
 *
 * Style: Google C Style. Comments: Doxygen.
 */
#ifndef NCMP_LIMITS_H
#define NCMP_LIMITS_H

/* -------------------------------------------------------------------------
 * PKCS#11 resource limits (STRICT - see docs/architecture.md section 2).
 * ------------------------------------------------------------------------- */

/** Maximum number of slots / tokens exposed by the NCMP subsystem. */
#define PKCS11_MAX_SLOT_COUNT 4

/** Maximum concurrent sessions allowed per slot. */
#define PKCS11_MAX_SESSION_PER_SLOT 8

/** Total system-wide concurrent session ceiling (slots * sessions/slot). */
#define PKCS11_MAX_TOTAL_SESSIONS \
    (PKCS11_MAX_SLOT_COUNT * PKCS11_MAX_SESSION_PER_SLOT)

/* -------------------------------------------------------------------------
 * Wire protocol / payload limits.
 * ------------------------------------------------------------------------- */

/** Number of parameter slots carried in every message. */
#define NCMP_MAX_PARAM_COUNT 8

/** Maximum size (bytes) of a single parameter. */
#define NCMP_MAX_PARAM_SIZE (32 * 1024)

/**
 * Maximum combined payload size (bytes): the 8-entry length array plus the
 * concatenated parameter bytes. Enforced by the STDLL before enqueue.
 */
#define NCMP_MAX_PAYLOAD_SIZE (40 * 1024)

/** All wire fields are aligned to this many bytes. */
#define NCMP_WIRE_ALIGN 4

/* -------------------------------------------------------------------------
 * FX3 DMA / device container topology (Token NCMP hardware, CYUSB3KIT-003).
 * These mirror the firmware configuration and bound the in-flight window.
 * ------------------------------------------------------------------------- */

/** Rx (device -> host) DMA: buffer size and count => 16KB x 4 = 64KB. */
#define NCMP_FX3_RX_BUF_SIZE (16 * 1024)
#define NCMP_FX3_RX_BUF_COUNT 4

/** Tx (host -> device) DMA: buffer size and count => 16KB x 8 = 128KB. */
#define NCMP_FX3_TX_BUF_SIZE (16 * 1024)
#define NCMP_FX3_TX_BUF_COUNT 8

/** Internal SRAM containers on the device (64KB each). */
#define NCMP_DEV_CONTAINER_COUNT 4
#define NCMP_DEV_CONTAINER_SIZE (64 * 1024)

/**
 * Default per-slot in-flight ceiling. Bounded by the number of device
 * containers so the host never dispatches more work than the mover can hold.
 * A slot may lower this via its runtime metadata but never exceed it.
 */
#define NCMP_DEFAULT_MAX_INFLIGHT NCMP_DEV_CONTAINER_COUNT

#endif /* NCMP_LIMITS_H */

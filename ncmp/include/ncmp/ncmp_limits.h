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

/**
 * On-wire framing that precedes the payload: the 4-byte frame-length prefix
 * plus the fixed 20-byte NCMP_Header. Kept as a literal here because ncmp_wire.h
 * (which defines NCMP_FRAME_PREFIX_SIZE / NCMP_HEADER_WIRE_SIZE) includes this
 * header, not the reverse; ncmp_wire.c static-asserts that this matches.
 */
#define NCMP_WIRE_FRAME_OVERHEAD (4 + 20)

/**
 * Maximum size (bytes) of a single parameter: one device SRAM container minus
 * the wire framing overhead, so a whole parameter fits a single container/DMA
 * buffer. A lone parameter of this exact size is further bounded by
 * NCMP_MAX_PAYLOAD_SIZE (which also carries the 8-entry length array).
 */
#define NCMP_MAX_PARAM_SIZE (NCMP_DEV_CONTAINER_SIZE - NCMP_WIRE_FRAME_OVERHEAD)

/**
 * Maximum combined payload size (bytes): the 8-entry length array plus the
 * concatenated parameter bytes. Enforced by the STDLL before enqueue. Bounded
 * so an encoded frame fits exactly one device container
 * (NCMP_MAX_FRAME_SIZE == NCMP_DEV_CONTAINER_SIZE).
 */
#define NCMP_MAX_PAYLOAD_SIZE (NCMP_DEV_CONTAINER_SIZE - NCMP_WIRE_FRAME_OVERHEAD)

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

/*
 * Token NCMP - Abstract token transport interface.
 *
 * The daemon talks to the token through this narrow interface. Two
 * implementations provide the same symbols and exactly one is linked:
 *   - daemon/usb_transport.c : real FX3 hardware over libusb-1.0.
 *   - mock/mock_transport.c  : in-process loopback to the software emulator,
 *                              selected by ENABLE_MOCK_TOKEN.
 *
 * All calls are blocking. A frame is a complete, 4-byte-aligned wire packet
 * (see ncmp_wire.h): frame_len prefix + header + param array + payload.
 */
#ifndef NCMP_TRANSPORT_H
#define NCMP_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

/** Opaque per-slot transport handle; defined by the chosen implementation. */
typedef struct ncmp_transport ncmp_transport_t;

/**
 * @brief Enumerate available tokens and report them as an online-slot bitmask.
 *
 * Each present token maps to one slot (bit s => slot s), capped at
 * PKCS11_MAX_SLOT_COUNT. The real backend enumerates matching FX3 USB devices;
 * the mock backend reports its emulated token(s). Called once by the daemon at
 * startup to decide how many comm_threads to spawn.
 *
 * @param out_slot_mask Receives the bitmask of present slots (0 if none).
 * @return NCMP_OK on success (mask may still be 0), or a negative NCMP error.
 */
int ncmp_transport_probe(uint32_t *out_slot_mask);

/**
 * @brief Open the transport bound to @p slot_id.
 * @param slot_id Logical slot index (0 .. PKCS11_MAX_SLOT_COUNT-1).
 * @param out     Receives the handle on success.
 * @return NCMP_OK or a negative NCMP error.
 */
int ncmp_transport_open(uint32_t slot_id, ncmp_transport_t **out);

/**
 * @brief Send one fully encoded wire frame to the token (blocking).
 * @param t     Transport handle.
 * @param frame Encoded frame (starts with the 4-byte frame_len prefix).
 * @param len   Total frame length in bytes.
 * @return NCMP_OK or a negative NCMP error.
 */
int ncmp_transport_send(ncmp_transport_t *t, const uint8_t *frame, size_t len);

/**
 * @brief Receive one message using the mandatory two-step read.
 *
 * Step 1 reads the fixed header (frame prefix + NCMP_Header); step 2 reads
 * exactly payload_len more bytes. The assembled frame is written to @p buf.
 *
 * @param t       Transport handle.
 * @param buf     Destination buffer (>= NCMP_MAX_FRAME_SIZE recommended).
 * @param buf_len Capacity of @p buf.
 * @param out_len Total assembled frame length on success.
 * @return NCMP_OK, NCMP_ERR_TRUNCATED, NCMP_ERR_TIMEOUT, or NCMP_ERR_USB.
 */
int ncmp_transport_recv(ncmp_transport_t *t, uint8_t *buf, size_t buf_len,
                        size_t *out_len);

/**
 * @brief Close a transport handle and release its resources.
 * @param t Transport handle (may be NULL).
 * @return NCMP_OK or a negative NCMP error.
 */
int ncmp_transport_close(ncmp_transport_t *t);

#endif /* NCMP_TRANSPORT_H */

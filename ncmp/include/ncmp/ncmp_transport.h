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
 * @brief Receive one message with a single-shot read into a max-size buffer.
 *
 * The whole frame is pulled in ONE transfer into @p buf and then parsed; the
 * frame prefix + NCMP_Header and its payload are never read in separate calls,
 * because the FX3 bulk IN endpoint delivers one frame per transfer. Pass a
 * buffer at least NCMP_MAX_FRAME_SIZE so any valid frame fits in one read.
 *
 * @param t       Transport handle.
 * @param buf     Destination buffer (must be >= NCMP_MAX_FRAME_SIZE).
 * @param buf_len Capacity of @p buf.
 * @param out_len Total received frame length on success.
 * @return NCMP_OK, NCMP_ERR_TRUNCATED, NCMP_ERR_PAYLOAD, NCMP_ERR_TIMEOUT,
 *         or NCMP_ERR_USB.
 */
int ncmp_transport_recv(ncmp_transport_t *t, uint8_t *buf, size_t buf_len,
                        size_t *out_len);

/**
 * @brief Close a transport handle and release its resources.
 * @param t Transport handle (may be NULL).
 * @return NCMP_OK or a negative NCMP error.
 */
int ncmp_transport_close(ncmp_transport_t *t);

/* -------------------------------------------------------------------------- */
/* Runtime backend selection                                                  */
/*                                                                            */
/* The daemon links every backend and picks one at startup (default: the real */
/* FX3 over libusb). The five ncmp_transport_* calls above are a dispatcher    */
/* (daemon/transport.c) that forwards to the selected backend's ops. The       */
/* standalone test suite instead links a single backend directly and does not  */
/* use the dispatcher.                                                         */
/* -------------------------------------------------------------------------- */

/** Which token transport the daemon's comm threads use. */
typedef enum ncmp_backend_kind {
    NCMP_BACKEND_REAL   = 0, /**< Real FX3 over libusb (default). */
    NCMP_BACKEND_MOCK   = 1, /**< In-process software emulator. */
    NCMP_BACKEND_SOCKET = 2, /**< TCP to a frame server (GUI mock_server). */
    NCMP_BACKEND_PEM    = 3, /**< PEM token: NCMP<->CI v4 translating usbfs transport. */
} ncmp_backend_kind;

/** Per-backend operation table (one instance exported by each backend). */
typedef struct ncmp_transport_ops {
    int (*probe)(uint32_t *out_slot_mask);
    int (*open)(uint32_t slot_id, ncmp_transport_t **out);
    int (*send)(ncmp_transport_t *t, const uint8_t *frame, size_t len);
    int (*recv)(ncmp_transport_t *t, uint8_t *buf, size_t buf_len,
                size_t *out_len);
    int (*close)(ncmp_transport_t *t);
} ncmp_transport_ops;

extern const ncmp_transport_ops ncmp_usb_ops;     /**< usb_transport.c */
extern const ncmp_transport_ops ncmp_mock_ops;    /**< mock_backend.c */
extern const ncmp_transport_ops ncmp_socket_ops;  /**< socket_transport.c */
extern const ncmp_transport_ops ncmp_pem_ops;     /**< pem_transport.c */

/**
 * @brief Select the active transport backend. Call once before the first
 *        probe/open. Default is NCMP_BACKEND_REAL.
 * @return NCMP_OK or NCMP_ERR_INVAL.
 */
int ncmp_transport_set_backend(ncmp_backend_kind kind);

#endif /* NCMP_TRANSPORT_H */

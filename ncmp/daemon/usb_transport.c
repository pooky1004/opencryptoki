/*
 * Token NCMP - libusb transport (FX3 bulk endpoints).
 *
 * Real-hardware implementation of ncmp_transport.h. Selected when
 * ENABLE_MOCK_TOKEN is OFF; otherwise mock/mock_transport.c is linked instead.
 *
 * Each slot corresponds to one physical FX3 board (its own USB interface), so
 * a per-slot transport handle owns one libusb device handle and its bulk
 * IN/OUT endpoints. Receive uses a single-shot read: the whole frame is pulled
 * in ONE bulk transfer into a max-size buffer (NCMP_MAX_FRAME_SIZE) and then
 * parsed. The FX3 bulk IN endpoint delivers one response per transfer
 * (terminated by a short packet / ZLP), so a header-first then remainder read
 * would split that transfer and desynchronise the byte stream.
 *
 * The libusb body compiles only when <libusb.h> is available; otherwise a
 * stub is built so the tree still configures without the -dev package (the
 * mock build never compiles this file).
 */
#include "ncmp/ncmp_transport.h"
#include "ncmp/ncmp_wire.h"
#include "ncmp/ncmp_limits.h"
#include "ncmp/ncmp_errno.h"

#include <stddef.h>
#include <stdint.h>

#if defined(__has_include)
#  if __has_include(<libusb.h>)
#    include <libusb.h>
#    define NCMP_HAVE_LIBUSB 1
#  elif __has_include(<libusb-1.0/libusb.h>)
#    include <libusb-1.0/libusb.h>
#    define NCMP_HAVE_LIBUSB 1
#  endif
#endif

/*
 * Device identity and endpoint map. TODO: set VID/PID to the Token NCMP FX3
 * firmware's actual descriptors; the endpoint addresses match the firmware's
 * bulk OUT (host->device) / bulk IN (device->host) configuration.
 */
#define NCMP_FX3_VID     0x04B4u  /* Cypress Semiconductor */
#define NCMP_FX3_PID     0x00F1u  /* placeholder - Token NCMP firmware PID */
#define NCMP_FX3_IFACE   0
#define NCMP_FX3_EP_OUT  0x01u    /* bulk OUT */
#define NCMP_FX3_EP_IN   0x81u    /* bulk IN  */
#define NCMP_USB_TIMEOUT_MS 5000

#ifdef NCMP_HAVE_LIBUSB

#include <stdlib.h>

struct ncmp_transport {
    libusb_context       *ctx;
    libusb_device_handle *dev;
    uint8_t               ep_in;
    uint8_t               ep_out;
};

/** Count FX3 devices matching our VID/PID in @p list; open the @p want-th one. */
static libusb_device *ncmp_pick_device(libusb_device **list, ssize_t n,
                                       uint32_t want, uint32_t *out_total)
{
    libusb_device *chosen = NULL;
    uint32_t match = 0;

    for (ssize_t i = 0; i < n; ++i) {
        struct libusb_device_descriptor d;

        if (libusb_get_device_descriptor(list[i], &d) != 0)
            continue;
        if (d.idVendor != NCMP_FX3_VID || d.idProduct != NCMP_FX3_PID)
            continue;
        if (match == want)
            chosen = list[i];
        ++match;
    }
    if (out_total)
        *out_total = match;
    return chosen;
}

int ncmp_transport_probe(uint32_t *out_slot_mask)
{
    libusb_context *ctx = NULL;
    libusb_device **list = NULL;
    uint32_t total = 0;
    ssize_t n;

    if (!out_slot_mask)
        return NCMP_ERR_INVAL;
    *out_slot_mask = 0;

    if (libusb_init(&ctx) != 0)
        return NCMP_ERR_USB;
    n = libusb_get_device_list(ctx, &list);
    if (n >= 0) {
        (void)ncmp_pick_device(list, n, (uint32_t)-1, &total);
        libusb_free_device_list(list, 1);
    }
    libusb_exit(ctx);

    if (total > PKCS11_MAX_SLOT_COUNT)
        total = PKCS11_MAX_SLOT_COUNT;
    for (uint32_t s = 0; s < total; ++s)
        *out_slot_mask |= (1u << s);
    return NCMP_OK;
}

int ncmp_transport_open(uint32_t slot_id, ncmp_transport_t **out)
{
    ncmp_transport_t *t;
    libusb_device **list = NULL;
    libusb_device *dev;
    ssize_t n;
    int rc;

    if (!out || slot_id >= PKCS11_MAX_SLOT_COUNT)
        return NCMP_ERR_INVAL;

    t = (ncmp_transport_t *)calloc(1, sizeof(*t));
    if (!t)
        return NCMP_ERR_NOSPACE;
    t->ep_in = NCMP_FX3_EP_IN;
    t->ep_out = NCMP_FX3_EP_OUT;

    if (libusb_init(&t->ctx) != 0) {
        free(t);
        return NCMP_ERR_USB;
    }

    n = libusb_get_device_list(t->ctx, &list);
    if (n < 0) {
        libusb_exit(t->ctx);
        free(t);
        return NCMP_ERR_USB;
    }
    dev = ncmp_pick_device(list, n, slot_id, NULL);
    rc = dev ? libusb_open(dev, &t->dev) : LIBUSB_ERROR_NO_DEVICE;
    libusb_free_device_list(list, 1);
    if (rc != 0 || !t->dev) {
        libusb_exit(t->ctx);
        free(t);
        return NCMP_ERR_USB;
    }

    libusb_set_auto_detach_kernel_driver(t->dev, 1);
    if (libusb_claim_interface(t->dev, NCMP_FX3_IFACE) != 0) {
        libusb_close(t->dev);
        libusb_exit(t->ctx);
        free(t);
        return NCMP_ERR_USB;
    }

    *out = t;
    return NCMP_OK;
}

/** Transfer exactly @p len bytes on @p ep; direction implied by the endpoint. */
static int ncmp_bulk_exact(ncmp_transport_t *t, uint8_t ep, uint8_t *buf,
                           size_t len)
{
    size_t done = 0;

    while (done < len) {
        int chunk = (len - done) > INT32_MAX ? INT32_MAX : (int)(len - done);
        int transferred = 0;
        int rc = libusb_bulk_transfer(t->dev, ep, buf + done, chunk,
                                      &transferred, NCMP_USB_TIMEOUT_MS);

        if (rc == LIBUSB_ERROR_TIMEOUT && transferred == 0)
            return NCMP_ERR_TIMEOUT;
        if (rc != 0 && rc != LIBUSB_ERROR_TIMEOUT)
            return NCMP_ERR_USB;
        if (transferred == 0)
            return NCMP_ERR_USB;
        done += (size_t)transferred;
    }
    return NCMP_OK;
}

int ncmp_transport_send(ncmp_transport_t *t, const uint8_t *frame, size_t len)
{
    if (!t || !frame)
        return NCMP_ERR_INVAL;
    /* Cast away const: libusb writes from the buffer but does not modify it. */
    return ncmp_bulk_exact(t, t->ep_out, (uint8_t *)frame, len);
}

/**
 * Read one complete frame from the bulk IN endpoint in a single transfer.
 *
 * The FX3 firmware emits each response as one bulk transfer, so the host posts
 * one read spanning the whole max-size buffer and takes whatever the device
 * delivers. libusb ends the transfer on a short packet (or a ZLP when the frame
 * length is a multiple of the endpoint's max packet size), returning the full
 * frame length in @p *out_len. The buffer must be at least one full frame
 * (NCMP_MAX_FRAME_SIZE); an oversized transfer is reported as LIBUSB_ERROR_
 * OVERFLOW and mapped to NCMP_ERR_PAYLOAD.
 */
static int ncmp_bulk_read_frame(ncmp_transport_t *t, uint8_t *buf,
                                size_t buf_len, size_t *out_len)
{
    int cap = buf_len > INT32_MAX ? INT32_MAX : (int)buf_len;
    int transferred = 0;
    int rc = libusb_bulk_transfer(t->dev, t->ep_in, buf, cap, &transferred,
                                  NCMP_USB_TIMEOUT_MS);

    if (rc == LIBUSB_ERROR_TIMEOUT && transferred == 0)
        return NCMP_ERR_TIMEOUT;
    if (rc == LIBUSB_ERROR_OVERFLOW)
        return NCMP_ERR_PAYLOAD;
    if (rc != 0 && rc != LIBUSB_ERROR_TIMEOUT)
        return NCMP_ERR_USB;
    if (transferred <= 0)
        return NCMP_ERR_USB;

    *out_len = (size_t)transferred;
    return NCMP_OK;
}

int ncmp_transport_recv(ncmp_transport_t *t, uint8_t *buf, size_t buf_len,
                        size_t *out_len)
{
    const size_t fixed = NCMP_FRAME_PREFIX_SIZE + NCMP_HEADER_WIRE_SIZE;
    NCMP_Header hdr;
    size_t got = 0;
    int rc;

    if (!t || !buf || !out_len)
        return NCMP_ERR_INVAL;
    if (buf_len < fixed)
        return NCMP_ERR_TRUNCATED;

    /*
     * Single-shot read: pull the entire frame in ONE bulk transfer into the
     * caller's max-size buffer, then parse. The FX3 bulk IN endpoint delivers a
     * whole frame per transfer, so the header and its payload cannot be split
     * across two reads without losing byte-stream alignment.
     */
    rc = ncmp_bulk_read_frame(t, buf, buf_len, &got);
    if (rc != NCMP_OK)
        return rc;

    /* Parse the header from what arrived and confirm the frame is complete. */
    if (got < fixed)
        return NCMP_ERR_TRUNCATED;
    rc = ncmp_wire_decode_header(buf, got, &hdr);
    if (rc != NCMP_OK)
        return rc;
    if (got != fixed + hdr.payload_len)
        return NCMP_ERR_TRUNCATED;

    *out_len = got;
    return NCMP_OK;
}

int ncmp_transport_close(ncmp_transport_t *t)
{
    if (!t)
        return NCMP_OK;
    if (t->dev) {
        libusb_release_interface(t->dev, NCMP_FX3_IFACE);
        libusb_close(t->dev);
    }
    if (t->ctx)
        libusb_exit(t->ctx);
    free(t);
    return NCMP_OK;
}

#else /* !NCMP_HAVE_LIBUSB */

/*
 * Fallback stub: builds without the libusb -dev package so the source tree
 * always configures. A real (non-mock) daemon requires libusb at build time,
 * where the branch above is compiled instead.
 */
struct ncmp_transport { int unused; };

int ncmp_transport_probe(uint32_t *out_slot_mask)
{
    if (!out_slot_mask)
        return NCMP_ERR_INVAL;
    *out_slot_mask = 0; /* no libusb -> no hardware tokens visible */
    return NCMP_OK;
}

int ncmp_transport_open(uint32_t slot_id, ncmp_transport_t **out)
{
    (void)slot_id;
    (void)out;
    return NCMP_ERR_USB;
}

int ncmp_transport_send(ncmp_transport_t *t, const uint8_t *frame, size_t len)
{
    (void)t;
    (void)frame;
    (void)len;
    return NCMP_ERR_USB;
}

int ncmp_transport_recv(ncmp_transport_t *t, uint8_t *buf, size_t buf_len,
                        size_t *out_len)
{
    (void)t;
    (void)buf;
    (void)buf_len;
    (void)out_len;
    return NCMP_ERR_USB;
}

int ncmp_transport_close(ncmp_transport_t *t)
{
    (void)t;
    return NCMP_OK;
}

#endif /* NCMP_HAVE_LIBUSB */

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
#include <stdio.h>
#include <string.h>
#include <time.h>

/*
 * FX3 Slave-FIFO (slfifosync) transport quirks, matching the verified reference
 * host (bang/.../host/web_ui/fx3_ci.py):
 *   - The GPIF bus has a short-packet erratum: a device->host (P-to-U) response
 *     is only committed when the FOLLOWING host->device (U-to-P) transfer turns
 *     the bus around. So after every real request we send a harmless NOP trigger
 *     OUT, then read IN; the NOP's own response is discarded.
 *   - Physical USB transfers are padded to a 4-byte multiple (32-bit GPIF bus).
 *   - A short cooldown is needed after an IN response before the next OUT.
 */
#define FX3_GUARD_NS      5000000ull            /* 5 ms interframe guard */
#define FX3_OUT_CHUNK_MS  50
#define FX3_RX_CAP        (2u * (uint32_t)NCMP_MAX_FRAME_SIZE)
#define FX3_NOP_FRAME_LEN 56u                   /* 4 + 20 + 32, already 4-aligned */

struct ncmp_transport {
    libusb_context       *ctx;
    libusb_device_handle *dev;
    uint8_t               ep_in;
    uint8_t               ep_out;
    uint8_t              *rx;        /* pending IN accumulator (FX3_RX_CAP) */
    size_t                rx_len;    /* valid bytes in rx */
    uint8_t              *txpad;     /* 4-byte-padded OUT scratch (frame + pad) */
    uint32_t              trig_seq;  /* NOP trigger sequence counter */
    uint64_t              next_out_ns; /* earliest time the next OUT may start */
};

static uint64_t fx3_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void fx3_sleep_ns(uint64_t ns)
{
    struct timespec ts;
    ts.tv_sec = (time_t)(ns / 1000000000ull);
    ts.tv_nsec = (long)(ns % 1000000000ull);
    nanosleep(&ts, NULL);
}

static uint32_t fx3_rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void fx3_wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

/* Build a 56-byte NOP trigger frame (command_id 0, no params). */
static void fx3_build_nop(uint8_t out[FX3_NOP_FRAME_LEN], uint32_t seq)
{
    memset(out, 0, FX3_NOP_FRAME_LEN);
    fx3_wr32(out + 0, 20u + 32u);   /* frame_len = header(20) + payload(32) */
    fx3_wr32(out + 8, seq);         /* sequence_id */
    fx3_wr32(out + 20, 32u);        /* payload_len = param-length array only */
}

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

static int usb_probe(uint32_t *out_slot_mask)
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
    /* The online mask is a uint32; only the first NCMP_SLOT_MASK_BITS slots are
     * representable (see ncmp_limits.h / docs/slot-scaling-design.md). */
    for (uint32_t s = 0; s < total && s < NCMP_SLOT_SCAN_MAX; ++s)
        *out_slot_mask |= (1u << s);
    return NCMP_OK;
}

static int usb_open(uint32_t slot_id, ncmp_transport_t **out)
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
    t->rx = (uint8_t *)malloc(FX3_RX_CAP);
    t->txpad = (uint8_t *)malloc((size_t)NCMP_MAX_FRAME_SIZE + 4u);
    if (!t->rx || !t->txpad) {
        free(t->rx); free(t->txpad); free(t);
        return NCMP_ERR_NOSPACE;
    }

    if (libusb_init(&t->ctx) != 0) {
        free(t->rx); free(t->txpad); free(t);
        return NCMP_ERR_USB;
    }

    n = libusb_get_device_list(t->ctx, &list);
    if (n < 0) {
        libusb_exit(t->ctx);
        free(t->rx); free(t->txpad); free(t);
        return NCMP_ERR_USB;
    }
    dev = ncmp_pick_device(list, n, slot_id, NULL);
    rc = dev ? libusb_open(dev, &t->dev) : LIBUSB_ERROR_NO_DEVICE;
    libusb_free_device_list(list, 1);
    if (rc != 0 || !t->dev) {
        libusb_exit(t->ctx);
        free(t->rx); free(t->txpad); free(t);
        return NCMP_ERR_USB;
    }

    libusb_set_auto_detach_kernel_driver(t->dev, 1);
    if (libusb_claim_interface(t->dev, NCMP_FX3_IFACE) != 0) {
        libusb_close(t->dev);
        libusb_exit(t->ctx);
        free(t->rx); free(t->txpad); free(t);
        return NCMP_ERR_USB;
    }

    /* Recover a possibly-wedged FX3: a prior run (or an aborted transfer) can
     * leave the Slave-FIFO GPIF/DMA stuck so the bulk-OUT endpoint stops
     * draining (every OUT then times out). A USB reset restores it. Best effort;
     * re-claim afterwards since a reset re-enumerates the interface. */
    if (libusb_reset_device(t->dev) == 0)
        (void)libusb_claim_interface(t->dev, NCMP_FX3_IFACE);

    *out = t;
    return NCMP_OK;
}

/* Append whatever is available on the bulk IN endpoint to t->rx (best effort). */
static void fx3_drain_in(ncmp_transport_t *t, int timeout_ms)
{
    int space, transferred = 0, rc;

    if (t->rx_len + 1024u > FX3_RX_CAP)
        return;   /* no room; a frame should be parseable already */
    space = (int)(FX3_RX_CAP - t->rx_len);
    rc = libusb_bulk_transfer(t->dev, t->ep_in, t->rx + t->rx_len, space,
                              &transferred, timeout_ms);
    if ((rc == 0 || rc == LIBUSB_ERROR_TIMEOUT) && transferred > 0)
        t->rx_len += (size_t)transferred;
}

/* Write @p len bytes to EP_OUT by @p deadline, servicing IN during the send so
 * a queued response cannot back-pressure the GPIF and stall a long OUT. */
static int fx3_out_write(ncmp_transport_t *t, const uint8_t *buf, size_t len,
                         uint64_t deadline_ns)
{
    size_t off = 0;

    while (off < len) {
        uint64_t now = fx3_now_ns();
        int rem_ms = now < deadline_ns ? (int)((deadline_ns - now) / 1000000ull) : 1;
        int to = rem_ms < FX3_OUT_CHUNK_MS ? rem_ms : FX3_OUT_CHUNK_MS;
        int transferred = 0;
        int rc;

        if (to < 1) to = 1;
        rc = libusb_bulk_transfer(t->dev, t->ep_out, (uint8_t *)buf + off,
                                  (int)(len - off), &transferred, to);
        off += (size_t)transferred;
        if (rc != 0 && rc != LIBUSB_ERROR_TIMEOUT)
            return NCMP_ERR_USB;
        if (off == len)
            return NCMP_OK;
        if (fx3_now_ns() >= deadline_ns)
            return NCMP_ERR_TIMEOUT;
        fx3_drain_in(t, to);   /* keep the IN side moving while OUT is partial */
    }
    return NCMP_OK;
}

/* Send one NOP trigger OUT to turn the GPIF bus around (commit a response). */
static void fx3_send_trigger(ncmp_transport_t *t, int timeout_ms)
{
    uint8_t nop[FX3_NOP_FRAME_LEN];
    int transferred = 0;

    t->trig_seq = (t->trig_seq + 1u) & 0xFFFFFFFFu;
    fx3_build_nop(nop, t->trig_seq);
    (void)libusb_bulk_transfer(t->dev, t->ep_out, nop, (int)sizeof(nop),
                               &transferred, timeout_ms);
}

static int usb_send(ncmp_transport_t *t, const uint8_t *frame, size_t len)
{
    uint64_t now, deadline;
    size_t plen;
    int rc;

    if (!t || !frame || len == 0)
        return NCMP_ERR_INVAL;
    if (len > (size_t)NCMP_MAX_FRAME_SIZE)
        return NCMP_ERR_PAYLOAD;

    /* Cooldown: the Slave-FIFO DMA needs a gap after an IN before the next OUT. */
    now = fx3_now_ns();
    if (t->next_out_ns > now)
        fx3_sleep_ns(t->next_out_ns - now);

    /* Pad the physical transfer to a 4-byte multiple (32-bit GPIF bus). */
    plen = (len + 3u) & ~(size_t)3u;
    memcpy(t->txpad, frame, len);
    if (plen > len)
        memset(t->txpad + len, 0, plen - len);

    deadline = fx3_now_ns() + (uint64_t)NCMP_USB_TIMEOUT_MS * 1000000ull;
    rc = fx3_out_write(t, t->txpad, plen, deadline);
    if (getenv("NCMP_USB_DEBUG"))
        fprintf(stderr, "[usb] OUT %zu bytes rc=%d rx_pending=%zu\n", plen, rc, t->rx_len);
    if (rc != NCMP_OK)
        return rc;

    /* Erratum workaround: a NOP trigger turns the bus around so the device
     * commits this request's response to the IN endpoint. */
    fx3_sleep_ns(FX3_GUARD_NS);
    fx3_send_trigger(t, FX3_OUT_CHUNK_MS);
    return NCMP_OK;
}

/* Extract the first non-NOP frame from t->rx into @p buf. Returns 1 on success
 * (sets *out_len), 0 if more bytes are needed, -1 on a corrupt stream. NOP
 * trigger responses (command_id 0) are discarded. */
static int fx3_extract(ncmp_transport_t *t, uint8_t *buf, size_t cap,
                       size_t *out_len)
{
    size_t pos = 0;

    while (t->rx_len - pos >= NCMP_FRAME_PREFIX_SIZE) {
        uint32_t frame_len = fx3_rd32(t->rx + pos);
        size_t total = (size_t)frame_len + NCMP_FRAME_PREFIX_SIZE;
        size_t physical;
        uint32_t cmd;

        if (total < 56u || total > (size_t)NCMP_MAX_FRAME_SIZE) {
            t->rx_len = 0;        /* desynced: drop the buffer and resync */
            return 0;
        }
        physical = (total + 3u) & ~(size_t)3u;
        if (t->rx_len - pos < physical)
            break;                /* a full (padded) frame has not arrived yet */

        cmd = fx3_rd32(t->rx + pos + 12);   /* command_id at offset 12 */
        if (cmd == 0x0000u) {               /* NOP trigger response: discard */
            pos += physical;
            continue;
        }
        if (total > cap) {                  /* caller buffer too small: skip */
            pos += physical;
            continue;
        }
        memcpy(buf, t->rx + pos, total);
        *out_len = total;
        pos += physical;
        memmove(t->rx, t->rx + pos, t->rx_len - pos);
        t->rx_len -= pos;
        return 1;
    }
    if (pos > 0) {                          /* compact consumed NOP bytes */
        memmove(t->rx, t->rx + pos, t->rx_len - pos);
        t->rx_len -= pos;
    }
    return 0;
}

static int usb_recv(ncmp_transport_t *t, uint8_t *buf, size_t buf_len,
                    size_t *out_len)
{
    uint64_t deadline;
    int flush_retries = 0;
    const int flush_limit = 3 + NCMP_USB_TIMEOUT_MS / 200;

    if (!t || !buf || !out_len)
        return NCMP_ERR_INVAL;

    deadline = fx3_now_ns() + (uint64_t)NCMP_USB_TIMEOUT_MS * 1000000ull;
    for (;;) {
        int r = fx3_extract(t, buf, buf_len, out_len);
        if (r == 1) {
            t->next_out_ns = fx3_now_ns() + FX3_GUARD_NS;
            return NCMP_OK;
        }
        if (fx3_now_ns() >= deadline)
            return NCMP_ERR_TIMEOUT;

        int rem_ms = (int)((deadline - fx3_now_ns()) / 1000000ull);
        int to = (flush_retries < flush_limit)
                     ? (rem_ms < 200 ? rem_ms : 200) : rem_ms;
        int space = (t->rx_len + 1024u <= FX3_RX_CAP)
                        ? (int)(FX3_RX_CAP - t->rx_len) : 0;
        int transferred = 0, rc;

        if (to < 1) to = 1;
        if (space <= 0) {        /* buffer full but no complete frame: resync */
            t->rx_len = 0;
            continue;
        }
        rc = libusb_bulk_transfer(t->dev, t->ep_in, t->rx + t->rx_len, space,
                                  &transferred, to);
        if (getenv("NCMP_USB_DEBUG"))
            fprintf(stderr, "[usb] IN rc=%d transferred=%d rx_len=%zu retries=%d\n",
                    rc, transferred, t->rx_len, flush_retries);
        if (rc == LIBUSB_ERROR_OVERFLOW)
            return NCMP_ERR_PAYLOAD;
        if (transferred > 0) {
            t->rx_len += (size_t)transferred;
            continue;
        }
        if (rc == LIBUSB_ERROR_TIMEOUT) {
            /* Nothing yet: a late response needs another bus turnaround. */
            if (flush_retries < flush_limit && fx3_now_ns() < deadline) {
                flush_retries++;
                fx3_send_trigger(t, FX3_OUT_CHUNK_MS);
                continue;
            }
            return NCMP_ERR_TIMEOUT;
        }
        if (rc != 0)
            return NCMP_ERR_USB;
    }
}

static int usb_close(ncmp_transport_t *t)
{
    if (!t)
        return NCMP_OK;
    if (t->dev) {
        libusb_release_interface(t->dev, NCMP_FX3_IFACE);
        libusb_close(t->dev);
    }
    if (t->ctx)
        libusb_exit(t->ctx);
    free(t->rx);
    free(t->txpad);
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

static int usb_probe(uint32_t *out_slot_mask)
{
    if (!out_slot_mask)
        return NCMP_ERR_INVAL;
    *out_slot_mask = 0; /* no libusb -> no hardware tokens visible */
    return NCMP_OK;
}

static int usb_open(uint32_t slot_id, ncmp_transport_t **out)
{
    (void)slot_id;
    (void)out;
    return NCMP_ERR_USB;
}

static int usb_send(ncmp_transport_t *t, const uint8_t *frame, size_t len)
{
    (void)t;
    (void)frame;
    (void)len;
    return NCMP_ERR_USB;
}

static int usb_recv(ncmp_transport_t *t, uint8_t *buf, size_t buf_len,
                        size_t *out_len)
{
    (void)t;
    (void)buf;
    (void)buf_len;
    (void)out_len;
    return NCMP_ERR_USB;
}

static int usb_close(ncmp_transport_t *t)
{
    (void)t;
    return NCMP_OK;
}

#endif /* NCMP_HAVE_LIBUSB */

/* Backend op table (dispatcher selects this for NCMP_BACKEND_REAL). */
const ncmp_transport_ops ncmp_usb_ops = {
    usb_probe, usb_open, usb_send, usb_recv, usb_close
};

/*
 * Token NCMP - Mock loopback transport (ncmp_transport.h implementation).
 *
 * Provides the same ncmp_transport_* symbols the daemon uses, but backed by
 * the in-process FX3 emulator instead of libusb. Linked in place of
 * daemon/usb_transport.c when ENABLE_MOCK_TOKEN is set, and by the test suite.
 *
 * Model: each slot owns one mock_device_t. ncmp_transport_send() feeds a frame
 * to the mover; ncmp_transport_recv() runs one MCU step and returns the
 * response. Single-threaded request/response pairing is sufficient for the
 * step-1 end-to-end skeleton; the daemon's comm_thread drives concurrency.
 */
#include "mock_token_ncmp.h"
#include "ncmp/ncmp_transport.h"
#include "ncmp/ncmp_limits.h"
#include "ncmp/ncmp_errno.h"

#include <stdlib.h>
#include <string.h>

/* One emulated device per slot; zero-initialized (all containers free). */
static mock_device_t g_mock_dev[PKCS11_MAX_SLOT_COUNT];

struct ncmp_transport {
    uint32_t        slot_id;
    mock_device_t  *dev;
};

/** Number of emulated tokens the mock backend presents. */
#ifndef NCMP_MOCK_SLOT_COUNT
#define NCMP_MOCK_SLOT_COUNT 1
#endif

int ncmp_transport_probe(uint32_t *out_slot_mask)
{
    if (!out_slot_mask)
        return NCMP_ERR_INVAL;
    *out_slot_mask = 0;
    for (uint32_t s = 0; s < NCMP_MOCK_SLOT_COUNT &&
                         s < PKCS11_MAX_SLOT_COUNT; ++s)
        *out_slot_mask |= (1u << s);
    return NCMP_OK;
}

int ncmp_transport_open(uint32_t slot_id, ncmp_transport_t **out)
{
    ncmp_transport_t *t;

    if (!out || slot_id >= PKCS11_MAX_SLOT_COUNT)
        return NCMP_ERR_INVAL;

    t = (ncmp_transport_t *)calloc(1, sizeof(*t));
    if (!t)
        return NCMP_ERR_NOSPACE;

    t->slot_id = slot_id;
    t->dev = &g_mock_dev[slot_id];
    memset(t->dev, 0, sizeof(*t->dev));
    mock_device_set_identity(t->dev, slot_id);
    *out = t;
    return NCMP_OK;
}

int ncmp_transport_send(ncmp_transport_t *t, const uint8_t *frame, size_t len)
{
    if (!t || !frame)
        return NCMP_ERR_INVAL;
    /* Mover reads the 4-byte length prefix and stages into a free container. */
    return mock_mover_ingest(t->dev, frame, len);
}

int ncmp_transport_recv(ncmp_transport_t *t, uint8_t *buf, size_t buf_len,
                        size_t *out_len)
{
    if (!t || !buf || !out_len)
        return NCMP_ERR_INVAL;
    /* One scheduler step drains the staged container into a response frame. */
    return mock_mcu_step(t->dev, buf, buf_len, out_len);
}

int ncmp_transport_close(ncmp_transport_t *t)
{
    free(t);
    return NCMP_OK;
}

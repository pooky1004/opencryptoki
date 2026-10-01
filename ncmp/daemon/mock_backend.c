/*
 * Token NCMP - Daemon-side mock transport backend.
 *
 * Provides the NCMP_BACKEND_MOCK op table for the transport dispatcher
 * (daemon/transport.c): wire frames are served by the in-process FX3 emulator
 * (mcu_scheduler.c / container.c) instead of libusb. One mock_device_t per slot.
 *
 * This mirrors mock/mock_transport.c but exposes its functions as an ops table
 * (not the public ncmp_transport_* symbols), so the daemon can link it next to
 * the real USB and socket backends and pick one at runtime. mock_transport.c is
 * left untouched for the standalone test suite, which links a single backend.
 */
#include "mock_token_ncmp.h"
#include "ncmp/ncmp_transport.h"
#include "ncmp/ncmp_limits.h"
#include "ncmp/ncmp_errno.h"

#include <stdlib.h>
#include <string.h>

/** Number of emulated tokens the mock backend presents. */
#ifndef NCMP_MOCK_SLOT_COUNT
#define NCMP_MOCK_SLOT_COUNT 1
#endif

static mock_device_t g_mock_dev[PKCS11_MAX_SLOT_COUNT];

struct ncmp_transport {
    uint32_t       slot_id;
    mock_device_t *dev;
};

static int mock_be_probe(uint32_t *out_slot_mask)
{
    if (!out_slot_mask)
        return NCMP_ERR_INVAL;
    *out_slot_mask = 0;
    for (uint32_t s = 0; s < NCMP_MOCK_SLOT_COUNT &&
                         s < PKCS11_MAX_SLOT_COUNT; ++s)
        *out_slot_mask |= (1u << s);
    return NCMP_OK;
}

static int mock_be_open(uint32_t slot_id, ncmp_transport_t **out)
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

static int mock_be_send(ncmp_transport_t *t, const uint8_t *frame, size_t len)
{
    if (!t || !frame)
        return NCMP_ERR_INVAL;
    return mock_mover_ingest(t->dev, frame, len);
}

static int mock_be_recv(ncmp_transport_t *t, uint8_t *buf, size_t buf_len,
                        size_t *out_len)
{
    if (!t || !buf || !out_len)
        return NCMP_ERR_INVAL;
    return mock_mcu_step(t->dev, buf, buf_len, out_len);
}

static int mock_be_close(ncmp_transport_t *t)
{
    free(t);
    return NCMP_OK;
}

/* Backend op table (dispatcher selects this for NCMP_BACKEND_MOCK). */
const ncmp_transport_ops ncmp_mock_ops = {
    mock_be_probe, mock_be_open, mock_be_send, mock_be_recv, mock_be_close
};

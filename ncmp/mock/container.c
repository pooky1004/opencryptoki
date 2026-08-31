/*
 * Token NCMP - Mover controller + SRAM container management (emulated).
 *
 * The mover reads the leading 4-byte length prefix of an inbound frame and
 * copies the whole message into the first free 64KB container. If all four
 * containers are occupied it reports backpressure until one frees.
 */
#include "mock_token_ncmp.h"
#include "ncmp/ncmp_wire.h"
#include "ncmp/ncmp_errno.h"

#include <string.h>

int mock_mover_ingest(mock_device_t *dev, const uint8_t *frame, size_t len)
{
    uint32_t frame_len;

    if (!dev || !frame || len < NCMP_FRAME_PREFIX_SIZE)
        return NCMP_ERR_INVAL;

    /* First 4 bytes = length of the rest of the message (little-endian). */
    memcpy(&frame_len, frame, sizeof(frame_len));
    if ((size_t)frame_len + NCMP_FRAME_PREFIX_SIZE != len)
        return NCMP_ERR_TRUNCATED;
    if (len > NCMP_DEV_CONTAINER_SIZE)
        return NCMP_ERR_NOSPACE;

    for (int i = 0; i < NCMP_DEV_CONTAINER_COUNT; ++i) {
        mock_container_t *c = &dev->container[i];
        if (c->used == 0 && !c->busy) {
            memcpy(c->data, frame, len);
            c->used = (uint32_t)len;
            c->busy = 1; /* Hand off to the MCU scheduler. */
            return NCMP_OK;
        }
    }
    return NCMP_ERR_FULL; /* All containers full - mover halts. */
}

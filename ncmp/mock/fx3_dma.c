/*
 * Token NCMP - FX3 DMA ring emulation.
 *
 * Models the two DMA directions with the firmware's buffer geometry:
 *   Rx (device -> host): NCMP_FX3_RX_BUF_SIZE x NCMP_FX3_RX_BUF_COUNT = 64KB.
 *   Tx (host -> device): NCMP_FX3_TX_BUF_SIZE x NCMP_FX3_TX_BUF_COUNT = 128KB.
 * Buffers are consumed/produced in order to mimic hardware backpressure.
 */
#include "mock_token_ncmp.h"
#include "ncmp/ncmp_errno.h"

#include <stddef.h>

/* TODO: implement ring push/pop honoring buffer counts and 16KB granularity,
 * so tests can exercise partial-DMA and backpressure paths. */
int mock_fx3_tx_push(const uint8_t *chunk, size_t len)
{
    (void)chunk;
    (void)len;
    return NCMP_ERR_STATE;
}

int mock_fx3_rx_pop(uint8_t *chunk, size_t cap, size_t *out_len)
{
    (void)chunk;
    (void)cap;
    (void)out_len;
    return NCMP_ERR_STATE;
}

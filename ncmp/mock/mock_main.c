/*
 * Token NCMP - Mock token entry point.
 *
 * Presents the same bulk-endpoint contract the daemon expects from a real FX3
 * token, but backed by the in-process emulator. Selected at build time via the
 * CMake option ENABLE_MOCK_TOKEN (-DENABLE_MOCK_TOKEN=ON); when enabled the
 * daemon's usb_transport is redirected to this loopback instead of libusb.
 */
#include "mock_token_ncmp.h"
#include "ncmp/ncmp_errno.h"

#include <stddef.h>

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    /* TODO: set up the loopback transport, instantiate up to 4 mock_device_t
     * (one per slot), then loop: mock_mover_ingest() on inbound frames and
     * mock_mcu_step() to drain responses. */
    return 0;
}

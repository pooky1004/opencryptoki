/*
 * Token NCMP - Real HSM bridge.
 *
 * Backend for frame_server that forwards wire frames to a real FX3 token over
 * the USB transport (ncmp_transport_*), so the test App GUI can drive real
 * hardware exactly as it drives the mock server: connect to slot s on data port
 * base+s and exchange frames. The token owns its identity, so identity get/set
 * over the control channel is unsupported; stats, the debug ring, and link
 * up/down work the same.
 *
 * Build note: this links daemon/usb_transport.c, which uses libusb when its
 * header is present and otherwise compiles a stub that reports no device. So the
 * bridge builds without libusb (every data command then returns a device error)
 * and runs against real hardware when libusb + a token are present.
 *
 * Style: Google C Style. A developer tool, not part of the shipped token.
 */
#define _GNU_SOURCE
#include "frame_server.h"

#include "ncmp/ncmp_transport.h"
#include "ncmp/ncmp_limits.h"
#include "ncmp/ncmp_errno.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------- */
/* USB backend                                                                */
/* -------------------------------------------------------------------------- */

/** Per-slot context: the open transport handle (NULL if the open failed). */
typedef struct usb_slot {
    uint32_t          slot_id;
    ncmp_transport_t *xport;
} usb_slot_t;

static int usb_exec(void *ctx, const uint8_t *req, size_t req_len,
                    uint8_t *rsp, size_t rsp_cap, size_t *rsp_len)
{
    usb_slot_t *u = ctx;
    int rc;

    if (!u->xport)
        return NCMP_ERR_USB;     /* no device bound to this slot */
    rc = ncmp_transport_send(u->xport, req, req_len);
    if (rc != NCMP_OK)
        return rc;
    return ncmp_transport_recv(u->xport, rsp, rsp_cap, rsp_len);
}

static void usb_label(void *ctx, char *out, size_t cap)
{
    usb_slot_t *u = ctx;
    snprintf(out, cap, "USB slot %u%s", u->slot_id,
             u->xport ? "" : " (no device)");
}

static const fs_backend_t USB_BACKEND = {
    .exec = usb_exec,
    .get_identity = NULL,   /* the token owns its identity; query via VD_TOKEN_INFO */
    .set_identity = NULL,
    .reset = NULL,
    .label = usb_label,
};

/* -------------------------------------------------------------------------- */
/* main                                                                       */
/* -------------------------------------------------------------------------- */

static usb_slot_t g_slot[FS_MAX_SLOTS];

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [--slots N] [--data-port P] [--ctrl-port P]\n"
        "  --slots N       slots to expose (1..%d); default = detected count\n"
        "  --data-port P   base TCP port; slot s listens on P+s (default 7010)\n"
        "  --ctrl-port P   control TCP port (default 7000)\n"
        "\n"
        "Bridges the App GUI link to a real FX3 token over USB. Without libusb\n"
        "or hardware it still starts, and data commands return a device error.\n",
        prog, FS_MAX_SLOTS);
}

int main(int argc, char **argv)
{
    fs_config_t cfg;
    uint32_t mask = 0;
    int want_slots = 0;   /* 0 => auto from probe */

    memset(&cfg, 0, sizeof(cfg));
    cfg.name = "bridge";
    cfg.data_port_base = 7010;
    cfg.ctrl_port = 7000;
    cfg.backend = &USB_BACKEND;

    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--slots") && i + 1 < argc)
            want_slots = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--data-port") && i + 1 < argc)
            cfg.data_port_base = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--ctrl-port") && i + 1 < argc)
            cfg.ctrl_port = atoi(argv[++i]);
        else {
            usage(argv[0]);
            return 2;
        }
    }

    if (ncmp_transport_probe(&mask) != NCMP_OK)
        mask = 0;
    {
        int detected = 0;
        for (uint32_t b = 0; b < FS_MAX_SLOTS; ++b)
            if (mask & (1u << b))
                detected++;
        printf("bridge: probe found %d device(s) (slot mask 0x%X)\n",
               detected, mask);
        if (want_slots <= 0)
            want_slots = detected > 0 ? detected : 1;  /* serve >=1 for testing */
    }
    if (want_slots < 1 || want_slots > FS_MAX_SLOTS) {
        usage(argv[0]);
        return 2;
    }
    cfg.n_slots = (uint32_t)want_slots;

    for (uint32_t i = 0; i < cfg.n_slots; ++i) {
        g_slot[i].slot_id = i;
        g_slot[i].xport = NULL;
        if (ncmp_transport_open(i, &g_slot[i].xport) != NCMP_OK) {
            g_slot[i].xport = NULL;
            fprintf(stderr, "slot %u: no device bound (open failed)\n", i);
        }
        cfg.ctx[i] = &g_slot[i];
    }

    {
        int rc = fs_run(&cfg);
        for (uint32_t i = 0; i < cfg.n_slots; ++i)
            if (g_slot[i].xport)
                ncmp_transport_close(g_slot[i].xport);
        return rc;
    }
}

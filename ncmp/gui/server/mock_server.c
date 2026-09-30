/*
 * Token NCMP - Mock HSM socket server.
 *
 * Backend for frame_server that drives the in-process FX3 emulator
 * (mcu_scheduler.c / container.c). Each slot owns one mock_device_t; a request
 * frame is staged by the mover and executed by one MCU step, reusing the
 * authoritative emulation path unchanged. Identity is editable over the control
 * channel (a mock convenience real hardware does not offer).
 *
 * Style: Google C Style. A developer tool, not part of the shipped token.
 */
#define _GNU_SOURCE
#include "frame_server.h"
#include "mock_token_ncmp.h"

#include "ncmp/ncmp_wire.h"
#include "ncmp/ncmp_cmd.h"
#include "ncmp/ncmp_errno.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------- */
/* Mock backend                                                               */
/* -------------------------------------------------------------------------- */

static int mock_exec(void *ctx, const uint8_t *req, size_t req_len,
                     uint8_t *rsp, size_t rsp_cap, size_t *rsp_len)
{
    mock_device_t *dev = ctx;
    int rc = mock_mover_ingest(dev, req, req_len);
    if (rc == NCMP_OK)
        rc = mock_mcu_step(dev, rsp, rsp_cap, rsp_len);
    return rc;
}

/** Copy a NUL/length-bounded char field to an escaped JSON string. */
static void field_str(const char *src, size_t maxlen, char *out, size_t cap)
{
    size_t n = 0;
    while (n < maxlen && src[n] != '\0')
        n++;
    fs_json_escape(src, n, out, cap);
}

static int mock_get_identity(void *ctx, char *out, size_t cap)
{
    mock_token_admin_t *a = &((mock_device_t *)ctx)->admin;
    char label[80], serial[64], manuf[80], model[64], utc[48];

    field_str(a->label, sizeof(a->label), label, sizeof(label));
    field_str(a->serial, sizeof(a->serial), serial, sizeof(serial));
    field_str(a->manufacturer, sizeof(a->manufacturer), manuf, sizeof(manuf));
    field_str(a->model, sizeof(a->model), model, sizeof(model));
    field_str(a->utc, sizeof(a->utc), utc, sizeof(utc));

    return snprintf(out, cap,
        "\"label\":\"%s\",\"serial\":\"%s\",\"manufacturer\":\"%s\","
        "\"model\":\"%s\",\"hw_major\":%u,\"hw_minor\":%u,"
        "\"fw_major\":%u,\"fw_minor\":%u,\"flags\":%u,\"utc\":\"%s\","
        "\"logged_in\":%d,\"login_user\":%u,\"obj_count\":%u",
        label, serial, manuf, model,
        a->hw_major, a->hw_minor, a->fw_major, a->fw_minor, a->flags, utc,
        a->logged_in, a->login_user, a->obj_count);
}

static void set_field(const char *body, const char *key, char *dst,
                      size_t maxlen)
{
    char tmp[128];
    if (fs_json_get_str(body, key, tmp, sizeof(tmp)) == 0) {
        size_t n = strlen(tmp);
        if (n > maxlen)
            n = maxlen;
        memset(dst, 0, maxlen);
        memcpy(dst, tmp, n);
    }
}

static int mock_set_identity(void *ctx, const char *body)
{
    mock_token_admin_t *a = &((mock_device_t *)ctx)->admin;
    long v;

    set_field(body, "label", a->label, NCMP_TI_LABEL_LEN);
    set_field(body, "serial", a->serial, NCMP_TI_SERIAL_LEN);
    set_field(body, "manufacturer", a->manufacturer, NCMP_TI_MANUF_LEN);
    set_field(body, "model", a->model, NCMP_TI_MODEL_LEN);
    set_field(body, "utc", a->utc, NCMP_TOKEN_UTC_LEN);
    if (fs_json_get_int(body, "hw_major", &v) == 0) a->hw_major = (uint8_t)v;
    if (fs_json_get_int(body, "hw_minor", &v) == 0) a->hw_minor = (uint8_t)v;
    if (fs_json_get_int(body, "fw_major", &v) == 0) a->fw_major = (uint8_t)v;
    if (fs_json_get_int(body, "fw_minor", &v) == 0) a->fw_minor = (uint8_t)v;
    if (fs_json_get_int(body, "flags", &v) == 0) a->flags = (uint32_t)v;
    a->valid = 1;
    return 0;
}

static void mock_reset(void *ctx)
{
    mock_device_t *dev = ctx;
    mock_token_admin_t saved = dev->admin;   /* keep identity + PINs */
    memset(dev, 0, sizeof(*dev));
    dev->admin = saved;
}

static void mock_label(void *ctx, char *out, size_t cap)
{
    field_str(((mock_device_t *)ctx)->admin.label, NCMP_TI_LABEL_LEN, out, cap);
}

static const fs_backend_t MOCK_BACKEND = {
    .exec = mock_exec,
    .get_identity = mock_get_identity,
    .set_identity = mock_set_identity,
    .reset = mock_reset,
    .label = mock_label,
};

/* -------------------------------------------------------------------------- */
/* main                                                                       */
/* -------------------------------------------------------------------------- */

static mock_device_t g_dev[FS_MAX_SLOTS];

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [--slots N] [--data-port P] [--ctrl-port P]\n"
        "  --slots N       number of emulated tokens (1..%d, default 1)\n"
        "  --data-port P   base TCP port; slot s listens on P+s (default 7010)\n"
        "  --ctrl-port P   control TCP port (default 7000)\n",
        prog, FS_MAX_SLOTS);
}

int main(int argc, char **argv)
{
    fs_config_t cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.name = "mock";
    cfg.n_slots = 1;
    cfg.data_port_base = 7010;
    cfg.ctrl_port = 7000;
    cfg.backend = &MOCK_BACKEND;

    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--slots") && i + 1 < argc)
            cfg.n_slots = (uint32_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--data-port") && i + 1 < argc)
            cfg.data_port_base = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--ctrl-port") && i + 1 < argc)
            cfg.ctrl_port = atoi(argv[++i]);
        else {
            usage(argv[0]);
            return 2;
        }
    }
    if (cfg.n_slots < 1 || cfg.n_slots > FS_MAX_SLOTS) {
        usage(argv[0]);
        return 2;
    }

    for (uint32_t i = 0; i < cfg.n_slots; ++i) {
        memset(&g_dev[i], 0, sizeof(g_dev[i]));
        mock_device_set_identity(&g_dev[i], i);
        cfg.ctx[i] = &g_dev[i];
    }
    return fs_run(&cfg);
}

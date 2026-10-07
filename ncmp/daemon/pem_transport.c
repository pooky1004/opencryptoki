/*
 * Token NCMP - Daemon-side PEM transport backend (ncmp_pem_ops).
 *
 * Ports the PEM CI test-console unit functions onto the existing ncmpd/facade
 * framework WITHOUT changing the facade, comm_thread, session map or SHM: this
 * backend is a *translating* transport. It accepts a fully-encoded NCMP wire
 * frame (the same frames the facade already builds), decodes the opcode and
 * parameters, maps them to the PEM CI v4 wire format, exchanges over usbfs with
 * the PEM board (04b4:5054), and re-encodes the PEM response back into an NCMP
 * wire frame. So comm_thread/send+recv stay unchanged.
 *
 * PEM CI v4 (see docs/pem-command-interface.md): 16-byte header
 * {total, session_id, command, ack} LE; request ack=0x0000FFFF; args are
 * positional with u64 LE integers and 8-byte-aligned variable blobs.
 *
 * Covered unit functions (Phase 2): SESSION open/close, SHA3 (one-shot +
 * INIT/UPDATE/FINAL), AES-GCM one-shot, AES-CTR one-shot. Other opcodes return
 * a clean CKR_MECHANISM_INVALID ack (extended in later phases).
 */
#include "ncmp/ncmp_transport.h"
#include "ncmp/ncmp_limits.h"
#include "ncmp/ncmp_errno.h"
#include "ncmp/ncmp_wire.h"
#include "ncmp/ncmp_cmd.h"
#include "ncmp/ncmp_ckr.h"

#include "cifx_protocol.h"   /* ncmp/pem/ */
#include "ci_usb_lib.h"      /* ncmp/pem/ */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

static int pem_dbg(void) { static int v = -1; if (v < 0) v = getenv("NCMP_PEM_DEBUG") ? 1 : 0; return v; }

#define PEM_REQ_ACK 0x0000FFFFu     /* CI v4 request ack sentinel */
#define PEM_MAXBUF  (CIFX_CI_V4_RESPONSE_MAX_BYTES + 16u)

struct ncmp_transport {
    uint32_t  slot_id;
    CI_USB   *usb;
    uint32_t  dig_bits;                 /* active SHA3 variant for UPDATE/FINAL */
    uint8_t   rsp[NCMP_MAX_FRAME_SIZE]; /* last response, NCMP-encoded */
    size_t    rsp_len;
    uint8_t   payload[NCMP_MAX_PAYLOAD_SIZE]; /* response params scratch */
};

/* ---- little-endian helpers for CI v4 args (u64) ---- */
static void put_u64le(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (8 * i));
}
static uint32_t rd_u32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static size_t pad8(size_t n) { return (n + 7u) & ~(size_t)7u; }

/* Append a u64 LE scalar to an arg buffer. */
static size_t arg_u64(uint8_t *a, size_t off, uint64_t v)
{
    put_u64le(a + off, v);
    return off + 8;
}
/* Append a length-prefixed, 8-byte-aligned variable blob: len(u64)|data|PAD8. */
static size_t arg_var(uint8_t *a, size_t off, const uint8_t *d, size_t n)
{
    put_u64le(a + off, (uint64_t)n);
    off += 8;
    if (n) memcpy(a + off, d, n);
    size_t padded = pad8(n);
    if (padded > n) memset(a + off + n, 0, padded - n);
    return off + padded;
}
/* Append a fixed-size blob (no length field). */
static size_t arg_fixed(uint8_t *a, size_t off, const uint8_t *d, size_t n)
{
    if (n) memcpy(a + off, d, n);
    return off + n;
}

/* ---- SHA3 mech <-> variant mapping ---- */
static int sha3_bits(uint32_t mech)
{
    switch (mech) {
    case NCMP_MECH_SHA3_256: return 256;
    case NCMP_MECH_SHA3_384: return 384;
    case NCMP_MECH_SHA3_512: return 512;
    default: return 0;   /* SHA-2 and others are not supported by PEM */
    }
}
static uint32_t sha3_oneshot_cmd(int bits)
{
    return bits == 384 ? CIFX_CI_COMMAND_SHA3_384_ONESHOT
         : bits == 512 ? CIFX_CI_COMMAND_SHA3_512_ONESHOT
                       : CIFX_CI_COMMAND_SHA3_256_ONESHOT;
}
static uint32_t sha3_stage_cmd(int bits, uint32_t base256)
{
    /* base256 = one of the 0x0340/41/42 (256) opcodes; add 3 per step up. */
    uint32_t step = base256 - CIFX_CI_COMMAND_SHA3_256_INIT; /* 0=INIT,1=UPD,2=FIN */
    return (bits == 384 ? CIFX_CI_COMMAND_SHA3_384_INIT
          : bits == 512 ? CIFX_CI_COMMAND_SHA3_512_INIT
                        : CIFX_CI_COMMAND_SHA3_256_INIT) + step;
}
static int digest_len(int bits) { return bits == 384 ? 48 : bits == 512 ? 64 : 32; }

/* ---- build an NCMP response frame into t->rsp ---- */
static int build_rsp(ncmp_transport_t *t, const NCMP_Header *req, uint32_t ack,
                     const uint8_t *p0, uint32_t p0len)
{
    NCMP_Message m;
    size_t out = 0;

    memset(&m, 0, sizeof(m));
    m.header.session_id = req->session_id;
    m.header.sequence_id = req->sequence_id;
    m.header.command_id = req->command_id;
    m.header.ack = ack;
    m.payload = t->payload;
    m.payload_cap = sizeof(t->payload);
    if (p0len) {
        if (p0len > sizeof(t->payload)) return NCMP_ERR_PAYLOAD;
        memcpy(t->payload, p0, p0len);
        m.param_len[0] = p0len;
    }
    if (ncmp_wire_encode(&m, t->rsp, sizeof(t->rsp), &out) != NCMP_OK)
        return NCMP_ERR_PAYLOAD;
    t->rsp_len = out;
    return NCMP_OK;
}

/* One PEM CI v4 exchange: build message[command|args], transfer, send/recv.
 * @p resp receives the response message bytes (from offset 0), *resp_len set.
 * @return NCMP_OK (USB ok; token ack is in resp[12..16)) or negative on USB err. */
/* @p exp_bytes = expected response MESSAGE size hint (header+args). It is rounded
 * up to 4 and clamped to [16, 65520] as CI_USB_Exchange requires. The firmware
 * short-packets at the true length, so an over-estimate still returns actual. */
static int pem_exchange(ncmp_transport_t *t, uint32_t session_id, uint32_t command,
                        const uint8_t *args, size_t args_len, size_t exp_bytes,
                        uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
    static _Thread_local uint8_t msg[PEM_MAXBUF];
    static _Thread_local uint8_t xfer[PEM_MAXBUF];
    size_t msg_len = 0, xfer_len = 0, actual = 0;
    CI_USB_Timing timing;

    size_t expected = (exp_bytes + 3u) & ~(size_t)3u;
    if (expected < 16u) expected = 16u;
    if (expected > 65520u) expected = 65520u;
    if (expected > resp_cap) expected = resp_cap & ~(size_t)3u;

    if (cifx_build_ci_v4_message(session_id, command, PEM_REQ_ACK, args, args_len,
                                 msg, sizeof(msg), &msg_len) != CIFX_OK)
        return NCMP_ERR_INVAL;
    if (cifx_build_ci_v4_transfer(msg, msg_len, xfer, sizeof(xfer), &xfer_len) != CIFX_OK)
        return NCMP_ERR_INVAL;
    int xrc = CI_USB_Exchange(t->usb, xfer, xfer_len, resp, expected, &actual, &timing);
    if (pem_dbg())
        fprintf(stderr, "[pem] cmd=0x%04x args=%zu xfer=%zu exp=%zu exch_rc=%d actual=%zu\n",
                command, args_len, xfer_len, expected, xrc, actual);
    if (xrc != CI_USB_OK)
        return NCMP_ERR_USB;
    if (actual < CIFX_CI_V4_HEADER_BYTES)
        return NCMP_ERR_TRUNCATED;
    *resp_len = actual;
    return NCMP_OK;
}

/* ---- backend ops ---- */

static int pem_be_probe(uint32_t *out_slot_mask)
{
    CI_USB_Options opt;
    CI_USB *probe = NULL;

    if (!out_slot_mask) return NCMP_ERR_INVAL;
    *out_slot_mask = 0;
    CI_USB_DefaultOptions(&opt);           /* 04b4:5054 */
    if (CI_USB_Open(&opt, &probe) == CI_USB_OK) {
        CI_USB_Close(probe);
        *out_slot_mask = 1u;               /* one PEM token on slot 0 */
    }
    return NCMP_OK;
}

static int pem_be_open(uint32_t slot_id, ncmp_transport_t **out)
{
    CI_USB_Options opt;
    ncmp_transport_t *t;

    if (!out || slot_id >= PKCS11_MAX_SLOT_COUNT) return NCMP_ERR_INVAL;
    t = (ncmp_transport_t *)calloc(1, sizeof(*t));
    if (!t) return NCMP_ERR_NOSPACE;
    t->slot_id = slot_id;
    CI_USB_DefaultOptions(&opt);
    if (CI_USB_Open(&opt, &t->usb) != CI_USB_OK) { free(t); return NCMP_ERR_USB; }
    *out = t;
    return NCMP_OK;
}

/* Translate one NCMP request frame -> PEM CI exchange -> stash NCMP response. */
static int pem_be_send(ncmp_transport_t *t, const uint8_t *frame, size_t len)
{
    static _Thread_local uint8_t reqpay[NCMP_MAX_PAYLOAD_SIZE];
    static _Thread_local uint8_t args[PEM_MAXBUF];
    static _Thread_local uint8_t resp[PEM_MAXBUF];
    NCMP_Message m;
    uint32_t op, ack = NCMP_CKR_OK;
    size_t rlen = 0, alen = 0;

    if (!t || !frame) return NCMP_ERR_INVAL;
    m.payload = reqpay;
    m.payload_cap = sizeof(reqpay);
    if (ncmp_wire_decode(frame, len, &m) != NCMP_OK) return NCMP_ERR_TRUNCATED;
    op = ncmp_cmd_opcode(m.header.command_id);

    const uint8_t *p0 = NULL, *p1 = NULL, *p2 = NULL, *p3 = NULL, *p4 = NULL, *p5 = NULL;
    uint32_t l0 = 0, l1 = 0, l2 = 0, l3 = 0, l4 = 0, l5 = 0;
#define P(i, pp, ll) (ncmp_msg_param(&m, (i), &(pp), &(ll)) == NCMP_OK)

    switch (op) {
    case NCMP_CMD_OPEN_SESSION: {   /* -> PEM SESSION action=1 (OPEN) */
        alen = arg_u64(args, 0, 1);
        if (pem_exchange(t, 0, CIFX_CI_COMMAND_SESSION, args, alen, 24,
                         resp, sizeof(resp), &rlen) != NCMP_OK) return NCMP_ERR_USB;
        ack = rd_u32le(resp + 12);
        uint8_t hsid[4] = {0};
        if (ack == NCMP_CKR_OK && rlen >= 16 + 8) {
            uint32_t v = rd_u32le(resp + 16);          /* hSession (u64 LE, low 32) */
            hsid[0]=(uint8_t)v; hsid[1]=(uint8_t)(v>>8); hsid[2]=(uint8_t)(v>>16); hsid[3]=(uint8_t)(v>>24);
        }
        return build_rsp(t, &m.header, ack, hsid, 4);
    }
    case NCMP_CMD_CLOSE_SESSION: {  /* -> PEM SESSION action=2 (CLOSE) */
        alen = arg_u64(args, 0, 2);
        if (pem_exchange(t, m.header.session_id, CIFX_CI_COMMAND_SESSION, args, alen, 16,
                         resp, sizeof(resp), &rlen) != NCMP_OK) return NCMP_ERR_USB;
        ack = rd_u32le(resp + 12);
        return build_rsp(t, &m.header, ack, NULL, 0);
    }
    case NCMP_CMD_DIGEST: {         /* [mech|data] -> PEM SHA3 oneshot */
        if (!P(0, p0, l0) || l0 < 4) return build_rsp(t, &m.header, NCMP_CKR_ARGUMENTS_BAD, NULL, 0);
        int bits = sha3_bits(rd_u32le(p0));
        if (!bits) return build_rsp(t, &m.header, NCMP_CKR_MECHANISM_INVALID, NULL, 0);
        alen = arg_var(args, 0, p0 + 4, l0 - 4);
        if (pem_exchange(t, m.header.session_id, sha3_oneshot_cmd(bits), args, alen, 16+digest_len(bits),
                         resp, sizeof(resp), &rlen) != NCMP_OK) return NCMP_ERR_USB;
        ack = rd_u32le(resp + 12);
        return build_rsp(t, &m.header, ack, resp + 16, (uint32_t)(rlen > 16 ? rlen - 16 : 0));
    }
    case NCMP_CMD_DIGEST_INIT: {    /* [mech] -> PEM SHA3 INIT; resp ctx_id = bits */
        if (!P(0, p0, l0) || l0 < 4) return build_rsp(t, &m.header, NCMP_CKR_ARGUMENTS_BAD, NULL, 0);
        int bits = sha3_bits(rd_u32le(p0));
        if (!bits) return build_rsp(t, &m.header, NCMP_CKR_MECHANISM_INVALID, NULL, 0);
        if (pem_exchange(t, m.header.session_id, sha3_stage_cmd(bits, CIFX_CI_COMMAND_SHA3_256_INIT),
                         NULL, 0, 16, resp, sizeof(resp), &rlen) != NCMP_OK) return NCMP_ERR_USB;
        ack = rd_u32le(resp + 12);
        t->dig_bits = (uint32_t)bits;
        uint8_t ctx[4];
        ncmp_wr_u32le(ctx, (uint32_t)bits);   /* ctx_id encodes the SHA3 variant */
        return build_rsp(t, &m.header, ack, ctx, 4);
    }
    case NCMP_CMD_DIGEST_UPDATE: {  /* [ctx|data] -> PEM SHA3 UPDATE */
        int bits = t->dig_bits ? (int)t->dig_bits : 256;
        if (P(0, p0, l0) && l0 >= 2) { int b = rd_u32le(p0); if (b==256||b==384||b==512) bits=b; }
        if (!P(1, p1, l1)) { p1 = NULL; l1 = 0; }
        alen = arg_var(args, 0, p1, l1);
        if (pem_exchange(t, m.header.session_id, sha3_stage_cmd(bits, CIFX_CI_COMMAND_SHA3_256_UPDATE),
                         args, alen, 16, resp, sizeof(resp), &rlen) != NCMP_OK) return NCMP_ERR_USB;
        ack = rd_u32le(resp + 12);
        return build_rsp(t, &m.header, ack, NULL, 0);
    }
    case NCMP_CMD_DIGEST_FINAL: {   /* [ctx] -> PEM SHA3 FINAL -> digest */
        int bits = t->dig_bits ? (int)t->dig_bits : 256;
        if (P(0, p0, l0) && l0 >= 2) { int b = rd_u32le(p0); if (b==256||b==384||b==512) bits=b; }
        if (pem_exchange(t, m.header.session_id, sha3_stage_cmd(bits, CIFX_CI_COMMAND_SHA3_256_FINAL),
                         NULL, 0, 16+digest_len(bits), resp, sizeof(resp), &rlen) != NCMP_OK) return NCMP_ERR_USB;
        ack = rd_u32le(resp + 12);
        t->dig_bits = 0;
        return build_rsp(t, &m.header, ack, resp + 16, (uint32_t)(rlen > 16 ? rlen - 16 : 0));
    }
    case NCMP_CMD_AES_GCM:          /* [flags|key|iv|aad|taglen|data(+tag)] */
    case NCMP_CMD_AES_CTR: {        /* [flags|key|iv|data] */
        int gcm = (op == NCMP_CMD_AES_GCM);
        if (!P(0, p0, l0) || !P(1, p1, l1) || !P(2, p2, l2))
            return build_rsp(t, &m.header, NCMP_CKR_ARGUMENTS_BAD, NULL, 0);
        if (l1 != 32)   /* PEM one-shot is AES-256 only (32-byte key) */
            return build_rsp(t, &m.header, NCMP_CKR_MECHANISM_INVALID, NULL, 0);
        uint32_t enc = (rd_u32le(p0) & NCMP_AES_FLAG_ENCRYPT) ? 1u : 0u;
        uint32_t dir = enc ? 0u : 1u;              /* PEM: 0=enc,1=dec */
        alen = 0;
        alen = arg_u64(args, alen, gcm ? 1u : 0u); /* mode */
        alen = arg_u64(args, alen, dir);           /* direction */
        alen = arg_fixed(args, alen, p1, 32);      /* key */
        if (gcm) {
            uint32_t taglen = 16; const uint8_t *aad = NULL; uint32_t aadl = 0;
            const uint8_t *data; uint32_t datal;
            if (P(3, p3, l3)) { aad = p3; aadl = l3; }
            if (P(4, p4, l4) && l4 >= 4) taglen = rd_u32le(p4);
            if (!P(5, p5, l5)) { p5 = NULL; l5 = 0; }
            data = p5; datal = l5;
            alen = arg_var(args, alen, p2, l2);    /* iv (len-prefixed) */
            alen = arg_var(args, alen, aad, aadl); /* aad (len-prefixed, may be 0) */
            if (!enc) {   /* decrypt input is ct||tag: split tag off the end */
                if (datal < taglen) return build_rsp(t, &m.header, NCMP_CKR_ARGUMENTS_BAD, NULL, 0);
                alen = arg_var(args, alen, data, datal - taglen);
                alen = arg_fixed(args, alen, data + datal - taglen, taglen); /* tag */
            } else {
                alen = arg_var(args, alen, data, datal);
            }
        } else { /* CTR: iv fixed 16B, no len field; data len-prefixed */
            const uint8_t *data; uint32_t datal;
            if (l2 != 16) return build_rsp(t, &m.header, NCMP_CKR_ARGUMENTS_BAD, NULL, 0);
            if (!P(3, p3, l3)) { p3 = NULL; l3 = 0; }
            data = p3; datal = l3;
            alen = arg_fixed(args, alen, p2, 16);  /* counter */
            alen = arg_var(args, alen, data, datal);
        }
        if (pem_exchange(t, m.header.session_id, CIFX_CI_COMMAND_AES_ONESHOT, args, alen,
                         (size_t)24 + ((l5 + 7u) & ~7u) + 16u + ((l2 + 7u) & ~7u),
                         resp, sizeof(resp), &rlen) != NCMP_OK) return NCMP_ERR_USB;
        ack = rd_u32le(resp + 12);
        if (ack != NCMP_CKR_OK)
            return build_rsp(t, &m.header, ack, NULL, 0);
        /* response: data_len(u64)|data|PAD8 [+ tag16 on GCM encrypt] */
        if (rlen < 16 + 8) return build_rsp(t, &m.header, NCMP_CKR_FUNCTION_FAILED, NULL, 0);
        uint32_t outl = rd_u32le(resp + 16);       /* low 32 of data_len */
        const uint8_t *outd = resp + 24;
        uint32_t total = outl;
        if (gcm && enc) {                           /* append tag that follows PAD8 */
            size_t tagoff = 24 + pad8(outl);
            if (tagoff + 16 <= rlen) {
                /* concat data||tag into payload scratch for a single param0 */
                if ((size_t)outl + 16 > sizeof(t->payload)) return NCMP_ERR_PAYLOAD;
                memcpy(t->payload, outd, outl);
                memcpy(t->payload + outl, resp + tagoff, 16);
                return build_rsp(t, &m.header, ack, t->payload, outl + 16);
            }
        }
        return build_rsp(t, &m.header, ack, outd, total);
    }
    default:
        /* RNG, PQC, object/admin and other opcodes: not yet ported to PEM. */
        return build_rsp(t, &m.header, NCMP_CKR_MECHANISM_INVALID, NULL, 0);
    }
#undef P
    return NCMP_ERR_INVAL;   /* unreachable: every case returns */
}

static int pem_be_recv(ncmp_transport_t *t, uint8_t *buf, size_t buf_len, size_t *out_len)
{
    if (!t || !buf || !out_len) return NCMP_ERR_INVAL;
    if (t->rsp_len == 0 || t->rsp_len > buf_len) return NCMP_ERR_TRUNCATED;
    memcpy(buf, t->rsp, t->rsp_len);
    *out_len = t->rsp_len;
    t->rsp_len = 0;
    return NCMP_OK;
}

static int pem_be_close(ncmp_transport_t *t)
{
    if (t) {
        if (t->usb) CI_USB_Close(t->usb);
        free(t);
    }
    return NCMP_OK;
}

/* Backend op table (dispatcher selects this for NCMP_BACKEND_PEM). */
const ncmp_transport_ops ncmp_pem_ops = {
    pem_be_probe, pem_be_open, pem_be_send, pem_be_recv, pem_be_close
};

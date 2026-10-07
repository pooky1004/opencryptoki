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

/* Generic PEM CI tunnel opcode (PEM slots only; unused in the NCMP opcode space).
 * Lets the Web Test App drive any PEM-native CI command through /api/ci:
 *   param0 = PEM CI command (u32 LE), param1 = raw PEM args (already PEM-encoded),
 *   param2 = expected response message bytes (u32 LE, optional hint).
 * The response's PEM args (bytes after the 16-byte CI header) are returned as
 * NCMP response param0. Used for CAPABILITIES/ECHO/KEY_TABLE_INFO/PERF_QUERY. */
#define PEM_RAW_CMD 0x000001F0u

/*
 * Response shaping kind: how recv() turns a PEM CI response into the NCMP
 * response for a pending request. send() records one of these per dispatched
 * request so recv() can rebuild the frame without re-running the request switch.
 */
typedef enum {
    PEM_RK_LOCAL = 0,   /* translation error: ack-only, NO USB IN expected */
    PEM_RK_ACKONLY,     /* USB IN; ack only (close, digest update, gcm final dec) */
    PEM_RK_PASSTHRU,    /* USB IN; param0 = resp[16..rlen) (digest, raw tunnel) */
    PEM_RK_HSESSION,    /* USB IN; param0 = 4B hSession (0 unless ok) (open) */
    PEM_RK_CTX4_UNCOND, /* USB IN; param0 = 4B aux0, even on error (digest init) */
    PEM_RK_CTX4_OK,     /* USB IN; param0 = 4B 0 if ok else ack-only (gcm init) */
    PEM_RK_AES_ONESHOT, /* USB IN; data(+tag16 if aux0) (aes one-shot) */
    PEM_RK_GCM_UPDATE,  /* USB IN; param0 = data (gcm multipart update) */
    PEM_RK_TAG16        /* USB IN; param0 = resp+16 16B (gcm final encrypt) */
} pem_rsp_kind_t;

/*
 * One dispatched-but-undrained request. The PEM board holds up to
 * NCMP_PEM_CONTAINER_COUNT (3) of these, so the comm_thread can issue several
 * bulk-OUTs (send) before collecting the bulk-IN responses (recv) in FIFO order.
 */
typedef struct {
    int            has_usb;     /* 1 = recv reads a CI IN; 0 = LOCAL (no IN) */
    NCMP_Header    req;         /* echo session/sequence/command into the reply */
    pem_rsp_kind_t kind;
    uint32_t       aux0;        /* kind-specific (SHA3 bits / want-tag flag) */
    uint32_t       local_ack;   /* PEM_RK_LOCAL: the CKR ack to return */
    size_t         exp_bytes;   /* CI IN expected-size hint (already clamped) */
} pem_pending_t;

struct ncmp_transport {
    uint32_t  slot_id;
    CI_USB   *usb;
    uint32_t  dig_bits;                 /* active SHA3 variant for UPDATE/FINAL */
    uint8_t   rsp[NCMP_MAX_FRAME_SIZE]; /* last response, NCMP-encoded */
    size_t    rsp_len;
    uint8_t   payload[NCMP_MAX_PAYLOAD_SIZE]; /* response params scratch */
    /* Pending-exchange FIFO (depth = device container count). Owned solely by
     * this slot's comm_thread (single producer+consumer), so it needs no lock. */
    pem_pending_t pend[NCMP_PEM_CONTAINER_COUNT];
    int       pend_head;
    int       pend_tail;
    int       pend_count;
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

/* ---- pending-exchange FIFO (device container pipeline) ---- */

/** Reserve the next FIFO slot for a request about to be dispatched, or NULL if
 *  the pipeline is already full (comm_thread caps dispatch at max_inflight). */
static pem_pending_t *pem_pend_push(ncmp_transport_t *t)
{
    pem_pending_t *e;

    if (t->pend_count >= (int)NCMP_PEM_CONTAINER_COUNT)
        return NULL;
    e = &t->pend[t->pend_tail];
    t->pend_tail = (t->pend_tail + 1) % (int)NCMP_PEM_CONTAINER_COUNT;
    ++t->pend_count;
    memset(e, 0, sizeof(*e));
    return e;
}

/** Peek the oldest pending request (FIFO front), or NULL if none. */
static pem_pending_t *pem_pend_front(ncmp_transport_t *t)
{
    return (t->pend_count > 0) ? &t->pend[t->pend_head] : NULL;
}

/** Drop the oldest pending request after it has been drained. */
static void pem_pend_pop(ncmp_transport_t *t)
{
    if (t->pend_count <= 0)
        return;
    t->pend_head = (t->pend_head + 1) % (int)NCMP_PEM_CONTAINER_COUNT;
    --t->pend_count;
}

/*
 * Dispatch one request (OUT only): build the CI v4 message[command|args], do a
 * bulk-OUT, and queue a pending descriptor so recv() can shape the reply. The
 * device buffers the request in one of its containers; the IN response is
 * collected later by pem_be_recv(). @p exp_bytes is the expected response size
 * hint (rounded to 4, clamped to [16,65520]); the firmware short-packets at the
 * true length, so an over-estimate is fine.
 */
static int pem_post(ncmp_transport_t *t, const NCMP_Header *req,
                    uint32_t ci_session, uint32_t command,
                    const uint8_t *args, size_t args_len, size_t exp_bytes,
                    pem_rsp_kind_t kind, uint32_t aux0)
{
    static _Thread_local uint8_t msg[PEM_MAXBUF];
    static _Thread_local uint8_t xfer[PEM_MAXBUF];
    size_t msg_len = 0, xfer_len = 0, expected;
    CI_USB_Timing timing;
    pem_pending_t *e;
    int xrc;

    if (t->pend_count >= (int)NCMP_PEM_CONTAINER_COUNT)
        return NCMP_ERR_FULL;   /* pipeline full (should not happen: capped) */
    if (cifx_build_ci_v4_message(ci_session, command, PEM_REQ_ACK, args, args_len,
                                 msg, sizeof(msg), &msg_len) != CIFX_OK)
        return NCMP_ERR_INVAL;
    if (cifx_build_ci_v4_transfer(msg, msg_len, xfer, sizeof(xfer), &xfer_len) != CIFX_OK)
        return NCMP_ERR_INVAL;

    xrc = CI_USB_Send(t->usb, xfer, xfer_len, &timing);
    if (pem_dbg())
        fprintf(stderr, "[pem] send cmd=0x%04x args=%zu xfer=%zu rc=%d inflight=%d\n",
                command, args_len, xfer_len, xrc, t->pend_count + 1);
    if (xrc != CI_USB_OK)
        return (xrc == CI_USB_ERR_TIMEOUT) ? NCMP_ERR_TIMEOUT : NCMP_ERR_USB;

    expected = (exp_bytes + 3u) & ~(size_t)3u;
    if (expected < 16u) expected = 16u;
    if (expected > 65520u) expected = 65520u;

    e = pem_pend_push(t);       /* count < max checked above: never NULL */
    e->has_usb = 1;
    e->req = *req;
    e->kind = kind;
    e->aux0 = aux0;
    e->exp_bytes = expected;
    return NCMP_OK;
}

/** Queue a request that failed translation locally (no USB OUT issued): recv()
 *  returns an ack-only error without reading a CI IN. */
static int pem_post_local(ncmp_transport_t *t, const NCMP_Header *req, uint32_t ack)
{
    pem_pending_t *e;

    if (t->pend_count >= (int)NCMP_PEM_CONTAINER_COUNT)
        return NCMP_ERR_FULL;
    e = pem_pend_push(t);
    e->has_usb = 0;
    e->req = *req;
    e->kind = PEM_RK_LOCAL;
    e->local_ack = ack;
    return NCMP_OK;
}

/* Shape one CI response (resp[0..rlen)) into the NCMP reply for @p e (writes
 * t->rsp / t->rsp_len via build_rsp). The per-kind logic mirrors the former
 * inline switch; the token ack lives at resp[12..16). */
static void pem_shape(ncmp_transport_t *t, const pem_pending_t *e,
                      const uint8_t *resp, size_t rlen)
{
    uint32_t ack = rd_u32le(resp + 12);

    switch (e->kind) {
    case PEM_RK_ACKONLY:
        build_rsp(t, &e->req, ack, NULL, 0);
        return;
    case PEM_RK_PASSTHRU:
        build_rsp(t, &e->req, ack, resp + 16, (uint32_t)(rlen > 16 ? rlen - 16 : 0));
        return;
    case PEM_RK_HSESSION: {
        uint8_t hsid[4] = {0};
        if (ack == NCMP_CKR_OK && rlen >= 16 + 8)
            ncmp_wr_u32le(hsid, rd_u32le(resp + 16));  /* hSession low 32 */
        build_rsp(t, &e->req, ack, hsid, 4);
        return;
    }
    case PEM_RK_CTX4_UNCOND: {
        uint8_t ctx[4];
        ncmp_wr_u32le(ctx, e->aux0);                    /* SHA3 bits as ctx id */
        build_rsp(t, &e->req, ack, ctx, 4);
        return;
    }
    case PEM_RK_CTX4_OK: {
        uint8_t ctx[4];
        if (ack != NCMP_CKR_OK) { build_rsp(t, &e->req, ack, NULL, 0); return; }
        ncmp_wr_u32le(ctx, 0u);                         /* single input-key ctx */
        build_rsp(t, &e->req, ack, ctx, 4);
        return;
    }
    case PEM_RK_AES_ONESHOT: {
        uint32_t outl;
        const uint8_t *outd;
        if (ack != NCMP_CKR_OK) { build_rsp(t, &e->req, ack, NULL, 0); return; }
        if (rlen < 16 + 8) { build_rsp(t, &e->req, NCMP_CKR_FUNCTION_FAILED, NULL, 0); return; }
        outl = rd_u32le(resp + 16);        /* low 32 of data_len */
        outd = resp + 24;
        if (e->aux0) {                     /* GCM encrypt: append tag after PAD8 */
            size_t tagoff = 24 + pad8(outl);
            if (tagoff + 16 <= rlen && (size_t)outl + 16 <= sizeof(t->payload)) {
                memcpy(t->payload, outd, outl);
                memcpy(t->payload + outl, resp + tagoff, 16);
                build_rsp(t, &e->req, ack, t->payload, outl + 16);
                return;
            }
        }
        build_rsp(t, &e->req, ack, outd, outl);
        return;
    }
    case PEM_RK_GCM_UPDATE: {
        uint32_t outl;
        if (ack != NCMP_CKR_OK) { build_rsp(t, &e->req, ack, NULL, 0); return; }
        if (rlen < 16 + 8) { build_rsp(t, &e->req, NCMP_CKR_FUNCTION_FAILED, NULL, 0); return; }
        outl = rd_u32le(resp + 16);
        build_rsp(t, &e->req, ack, resp + 24, outl);
        return;
    }
    case PEM_RK_TAG16:
        if (ack != NCMP_CKR_OK) { build_rsp(t, &e->req, ack, NULL, 0); return; }
        if (rlen < 16 + 16) { build_rsp(t, &e->req, NCMP_CKR_FUNCTION_FAILED, NULL, 0); return; }
        build_rsp(t, &e->req, ack, resp + 16, 16);
        return;
    case PEM_RK_LOCAL:
    default:
        build_rsp(t, &e->req, ack, NULL, 0);
        return;
    }
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

/*
 * Dispatch one NCMP request (send phase): decode the opcode/params, map to a
 * PEM CI v4 command, issue the bulk-OUT via pem_post(), and queue a pending
 * descriptor. The matching CI response is collected later by pem_be_recv(), so
 * up to NCMP_PEM_CONTAINER_COUNT requests can be in flight at once. Translation
 * errors are queued via pem_post_local() (ack-only, no OUT).
 */
static int pem_be_send(ncmp_transport_t *t, const uint8_t *frame, size_t len)
{
    static _Thread_local uint8_t reqpay[NCMP_MAX_PAYLOAD_SIZE];
    static _Thread_local uint8_t args[PEM_MAXBUF];
    NCMP_Message m;
    uint32_t op;
    size_t alen = 0;

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
        return pem_post(t, &m.header, 0, CIFX_CI_COMMAND_SESSION, args, alen, 24,
                        PEM_RK_HSESSION, 0);
    }
    case NCMP_CMD_CLOSE_SESSION: {  /* -> PEM SESSION action=2 (CLOSE) */
        alen = arg_u64(args, 0, 2);
        return pem_post(t, &m.header, m.header.session_id, CIFX_CI_COMMAND_SESSION,
                        args, alen, 16, PEM_RK_ACKONLY, 0);
    }
    case NCMP_CMD_DIGEST: {         /* [mech|data] -> PEM SHA3 oneshot */
        if (!P(0, p0, l0) || l0 < 4) return pem_post_local(t, &m.header, NCMP_CKR_ARGUMENTS_BAD);
        int bits = sha3_bits(rd_u32le(p0));
        if (!bits) return pem_post_local(t, &m.header, NCMP_CKR_MECHANISM_INVALID);
        alen = arg_var(args, 0, p0 + 4, l0 - 4);
        return pem_post(t, &m.header, m.header.session_id, sha3_oneshot_cmd(bits),
                        args, alen, 16 + digest_len(bits), PEM_RK_PASSTHRU, 0);
    }
    case NCMP_CMD_DIGEST_INIT: {    /* [mech] -> PEM SHA3 INIT; resp ctx_id = bits */
        if (!P(0, p0, l0) || l0 < 4) return pem_post_local(t, &m.header, NCMP_CKR_ARGUMENTS_BAD);
        int bits = sha3_bits(rd_u32le(p0));
        if (!bits) return pem_post_local(t, &m.header, NCMP_CKR_MECHANISM_INVALID);
        t->dig_bits = (uint32_t)bits;
        return pem_post(t, &m.header, m.header.session_id,
                        sha3_stage_cmd(bits, CIFX_CI_COMMAND_SHA3_256_INIT),
                        NULL, 0, 16, PEM_RK_CTX4_UNCOND, (uint32_t)bits);
    }
    case NCMP_CMD_DIGEST_UPDATE: {  /* [ctx|data] -> PEM SHA3 UPDATE */
        int bits = t->dig_bits ? (int)t->dig_bits : 256;
        if (P(0, p0, l0) && l0 >= 2) { int b = rd_u32le(p0); if (b==256||b==384||b==512) bits=b; }
        if (!P(1, p1, l1)) { p1 = NULL; l1 = 0; }
        alen = arg_var(args, 0, p1, l1);
        return pem_post(t, &m.header, m.header.session_id,
                        sha3_stage_cmd(bits, CIFX_CI_COMMAND_SHA3_256_UPDATE),
                        args, alen, 16, PEM_RK_ACKONLY, 0);
    }
    case NCMP_CMD_DIGEST_FINAL: {   /* [ctx] -> PEM SHA3 FINAL -> digest */
        int bits = t->dig_bits ? (int)t->dig_bits : 256;
        if (P(0, p0, l0) && l0 >= 2) { int b = rd_u32le(p0); if (b==256||b==384||b==512) bits=b; }
        t->dig_bits = 0;
        return pem_post(t, &m.header, m.header.session_id,
                        sha3_stage_cmd(bits, CIFX_CI_COMMAND_SHA3_256_FINAL),
                        NULL, 0, 16 + digest_len(bits), PEM_RK_PASSTHRU, 0);
    }
    case NCMP_CMD_AES_GCM:          /* [flags|key|iv|aad|taglen|data(+tag)] */
    case NCMP_CMD_AES_CTR: {        /* [flags|key|iv|data] */
        int gcm = (op == NCMP_CMD_AES_GCM);
        if (!P(0, p0, l0) || !P(1, p1, l1) || !P(2, p2, l2))
            return pem_post_local(t, &m.header, NCMP_CKR_ARGUMENTS_BAD);
        if (l1 != 32)   /* PEM one-shot is AES-256 only (32-byte key) */
            return pem_post_local(t, &m.header, NCMP_CKR_MECHANISM_INVALID);
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
                if (datal < taglen) return pem_post_local(t, &m.header, NCMP_CKR_ARGUMENTS_BAD);
                alen = arg_var(args, alen, data, datal - taglen);
                alen = arg_fixed(args, alen, data + datal - taglen, taglen); /* tag */
            } else {
                alen = arg_var(args, alen, data, datal);
            }
        } else { /* CTR: iv fixed 16B, no len field; data len-prefixed */
            const uint8_t *data; uint32_t datal;
            if (l2 != 16) return pem_post_local(t, &m.header, NCMP_CKR_ARGUMENTS_BAD);
            if (!P(3, p3, l3)) { p3 = NULL; l3 = 0; }
            data = p3; datal = l3;
            alen = arg_fixed(args, alen, p2, 16);  /* counter */
            alen = arg_var(args, alen, data, datal);
        }
        return pem_post(t, &m.header, m.header.session_id, CIFX_CI_COMMAND_AES_ONESHOT,
                        args, alen,
                        (size_t)24 + ((l5 + 7u) & ~7u) + 16u + ((l2 + 7u) & ~7u),
                        PEM_RK_AES_ONESHOT, (gcm && enc) ? 1u : 0u);
    }
    case NCMP_CMD_AES_GCM_INIT: {   /* [flags|key|iv|aad|taglen] -> PEM AES_GCM_INIT; resp ctx=0 */
        if (!P(0, p0, l0) || !P(1, p1, l1) || !P(2, p2, l2))
            return pem_post_local(t, &m.header, NCMP_CKR_ARGUMENTS_BAD);
        if (l1 != 32)   /* PEM multipart GCM is AES-256 only (32-byte key) */
            return pem_post_local(t, &m.header, NCMP_CKR_MECHANISM_INVALID);
        uint32_t enc = (rd_u32le(p0) & NCMP_AES_FLAG_ENCRYPT) ? 1u : 0u;
        const uint8_t *aad = NULL; uint32_t aadl = 0;
        if (P(3, p3, l3)) { aad = p3; aadl = l3; }
        alen = 0;
        alen = arg_u64(args, alen, 0u);            /* key_id = 0 (input key/IV) */
        alen = arg_u64(args, alen, enc ? 0u : 1u); /* direction: 0=enc, 1=dec */
        alen = arg_fixed(args, alen, p1, 32);      /* key */
        alen = arg_var(args, alen, p2, l2);        /* iv (len-prefixed) */
        alen = arg_var(args, alen, aad, aadl);     /* aad (len-prefixed, may be 0) */
        return pem_post(t, &m.header, m.header.session_id, CIFX_CI_COMMAND_AES_GCM_INIT,
                        args, alen, 16, PEM_RK_CTX4_OK, 0);
    }
    case NCMP_CMD_AES_GCM_UPDATE: {  /* [ctx|data] -> PEM AES_GCM_UPDATE -> out */
        if (!P(1, p1, l1)) { p1 = NULL; l1 = 0; }
        alen = 0;
        alen = arg_u64(args, alen, 0u);            /* key_id = 0 */
        alen = arg_var(args, alen, p1, l1);        /* data (len-prefixed) */
        return pem_post(t, &m.header, m.header.session_id, CIFX_CI_COMMAND_AES_GCM_UPDATE,
                        args, alen, (size_t)24 + pad8(l1), PEM_RK_GCM_UPDATE, 0);
    }
    case NCMP_CMD_AES_GCM_FINAL: {   /* enc:[ctx]->tag ; dec:[ctx|tag]->ack */
        /* Decrypt carries the expected tag as a non-empty param1; encrypt has
         * only the ctx param (param1 absent/empty — msg_param may still report
         * OK with len 0, so gate on the length). */
        int dec = (P(1, p1, l1) && l1 > 0);
        alen = 0;
        alen = arg_u64(args, alen, 0u);            /* key_id = 0 */
        if (dec) {
            if (l1 != 16) return pem_post_local(t, &m.header, NCMP_CKR_ARGUMENTS_BAD);
            alen = arg_fixed(args, alen, p1, 16);  /* expected tag */
        }
        return pem_post(t, &m.header, m.header.session_id, CIFX_CI_COMMAND_AES_GCM_FINAL,
                        args, alen, dec ? 16u : 32u,
                        dec ? PEM_RK_ACKONLY : PEM_RK_TAG16, 0);
    }
    case PEM_RAW_CMD: {   /* generic PEM CI tunnel (param0=cmd, param1=args, param2=exp) */
        uint32_t pemcmd = 0, exp = 4096;
        const uint8_t *a = NULL; uint32_t al = 0;
        if (!P(0, p0, l0) || l0 < 4)
            return pem_post_local(t, &m.header, NCMP_CKR_ARGUMENTS_BAD);
        pemcmd = rd_u32le(p0);
        if (P(1, p1, l1)) { a = p1; al = l1; }
        if (P(2, p2, l2) && l2 >= 4) exp = rd_u32le(p2);
        return pem_post(t, &m.header, m.header.session_id, pemcmd, a, al, exp,
                        PEM_RK_PASSTHRU, 0);
    }
    default:
        /* RNG, PQC, object/admin and other opcodes: not yet ported to PEM. */
        return pem_post_local(t, &m.header, NCMP_CKR_MECHANISM_INVALID);
    }
#undef P
    return NCMP_ERR_INVAL;   /* unreachable: every case returns */
}

/*
 * Drain one response (recv phase): take the oldest pending request; if it was a
 * local translation error, build its ack-only reply without touching USB;
 * otherwise read one CI IN frame and shape it per the pending kind. FIFO order
 * matches the device's in-order container responses.
 */
static int pem_be_recv(ncmp_transport_t *t, uint8_t *buf, size_t buf_len, size_t *out_len)
{
    static _Thread_local uint8_t resp[PEM_MAXBUF];
    pem_pending_t *e;

    if (!t || !buf || !out_len) return NCMP_ERR_INVAL;
    e = pem_pend_front(t);
    if (e == NULL) return NCMP_ERR_TRUNCATED;   /* nothing dispatched */

    if (!e->has_usb) {
        build_rsp(t, &e->req, e->local_ack, NULL, 0);
        pem_pend_pop(t);
    } else {
        size_t rlen = 0;
        CI_USB_Timing timing;
        int rc = CI_USB_Recv(t->usb, resp, e->exp_bytes, &rlen, &timing);
        if (pem_dbg())
            fprintf(stderr, "[pem] recv kind=%d exp=%zu rc=%d actual=%zu inflight=%d\n",
                    (int)e->kind, e->exp_bytes, rc, rlen, t->pend_count);
        if (rc != CI_USB_OK) {
            pem_pend_pop(t);
            return (rc == CI_USB_ERR_TIMEOUT) ? NCMP_ERR_TIMEOUT : NCMP_ERR_USB;
        }
        if (rlen < CIFX_CI_V4_HEADER_BYTES) {
            pem_pend_pop(t);
            return NCMP_ERR_TRUNCATED;
        }
        pem_shape(t, e, resp, rlen);
        pem_pend_pop(t);
    }

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

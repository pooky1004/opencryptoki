/*
 * Token NCMP - Wire packet encode/decode + validation.
 *
 * Encoding is little-endian and 4-byte aligned. See ncmp_wire.h for the
 * frame layout and invariants.
 */
#include "ncmp/ncmp_wire.h"
#include "ncmp/ncmp_errno.h"

#include <string.h>

/* The wire encoding hard-codes a 20-byte header; keep the struct in sync. */
_Static_assert(sizeof(NCMP_Header) == NCMP_HEADER_WIRE_SIZE,
               "NCMP_Header must serialize to exactly 20 bytes");

/* -------------------------------------------------------------------------
 * Little-endian scalar helpers (portable regardless of host byte order).
 * ------------------------------------------------------------------------- */

static void put_u32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint32_t get_u32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int ncmp_wire_validate_params(const uint32_t param_len[NCMP_MAX_PARAM_COUNT])
{
    uint64_t total = NCMP_PARAM_LEN_ARRAY_SIZE;

    if (!param_len)
        return NCMP_ERR_INVAL;

    for (int i = 0; i < NCMP_MAX_PARAM_COUNT; ++i) {
        if (param_len[i] > NCMP_MAX_PARAM_SIZE)
            return NCMP_ERR_PARAM_SIZE;
        total += param_len[i];
    }
    if (total > NCMP_MAX_PAYLOAD_SIZE)
        return NCMP_ERR_PAYLOAD;

    return NCMP_OK;
}

int ncmp_wire_encode(const NCMP_Message *msg, uint8_t *buf, size_t buf_len,
                     size_t *out_len)
{
    uint32_t payload_sum = 0;
    uint32_t payload_len;
    uint32_t frame_len;
    size_t   total;
    uint8_t *p;
    int      rc;

    if (!msg || !buf || !out_len)
        return NCMP_ERR_INVAL;

    rc = ncmp_wire_validate_params(msg->param_len);
    if (rc != NCMP_OK)
        return rc;

    for (int i = 0; i < NCMP_MAX_PARAM_COUNT; ++i)
        payload_sum += msg->param_len[i];

    /* payload_len = param-length array + concatenated parameter bytes. */
    payload_len = (uint32_t)NCMP_PARAM_LEN_ARRAY_SIZE + payload_sum;
    frame_len = (uint32_t)NCMP_HEADER_WIRE_SIZE + payload_len;
    total = NCMP_FRAME_PREFIX_SIZE + frame_len;

    if (buf_len < total)
        return NCMP_ERR_NOSPACE;
    if (payload_sum > 0 && (!msg->payload || msg->payload_cap < payload_sum))
        return NCMP_ERR_INVAL;

    p = buf;
    put_u32le(p, frame_len);              p += 4;   /* frame prefix */
    put_u32le(p, msg->header.session_id); p += 4;
    put_u32le(p, msg->header.sequence_id);p += 4;
    put_u32le(p, msg->header.command_id); p += 4;
    put_u32le(p, msg->header.ack);        p += 4;
    put_u32le(p, payload_len);            p += 4;
    for (int i = 0; i < NCMP_MAX_PARAM_COUNT; ++i) {
        put_u32le(p, msg->param_len[i]);
        p += 4;
    }
    if (payload_sum > 0) {
        memcpy(p, msg->payload, payload_sum);
        p += payload_sum;
    }

    *out_len = total;
    return NCMP_OK;
}

int ncmp_msg_pack(NCMP_Message *m, uint8_t *payload_buf, size_t cap,
                  const uint8_t *const parts[], const uint32_t lens[],
                  int nparts)
{
    size_t off = 0;

    if (!m || !parts || !lens || nparts < 1 || nparts > NCMP_MAX_PARAM_COUNT)
        return NCMP_ERR_INVAL;

    for (int i = 0; i < NCMP_MAX_PARAM_COUNT; ++i)
        m->param_len[i] = 0;

    for (int i = 0; i < nparts; ++i) {
        if (lens[i] > NCMP_MAX_PARAM_SIZE)
            return NCMP_ERR_PARAM_SIZE;
        if (lens[i] > 0 && !parts[i])
            return NCMP_ERR_INVAL;
        if (off + lens[i] > cap)
            return NCMP_ERR_NOSPACE;
        if (lens[i] > 0)
            memcpy(payload_buf + off, parts[i], lens[i]);
        m->param_len[i] = lens[i];
        off += lens[i];
    }

    /* Enforce the combined payload ceiling (array + parameters). */
    if (NCMP_PARAM_LEN_ARRAY_SIZE + off > NCMP_MAX_PAYLOAD_SIZE)
        return NCMP_ERR_PAYLOAD;

    m->payload = payload_buf;
    m->payload_cap = cap;
    return NCMP_OK;
}

int ncmp_msg_param(const NCMP_Message *m, int idx, const uint8_t **out,
                   uint32_t *out_len)
{
    size_t off = 0;

    if (!m || !out || !out_len || idx < 0 || idx >= NCMP_MAX_PARAM_COUNT)
        return NCMP_ERR_INVAL;

    for (int i = 0; i < idx; ++i)
        off += m->param_len[i];

    *out_len = m->param_len[idx];
    *out = (m->param_len[idx] > 0) ? (m->payload + off) : (const uint8_t *)0;
    return NCMP_OK;
}

int ncmp_wire_decode_header(const uint8_t *buf, size_t buf_len, NCMP_Header *out)
{
    uint32_t frame_len;
    const uint8_t *h;

    if (!buf || !out)
        return NCMP_ERR_INVAL;
    if (buf_len < NCMP_FRAME_PREFIX_SIZE + NCMP_HEADER_WIRE_SIZE)
        return NCMP_ERR_TRUNCATED;

    frame_len = get_u32le(buf);
    h = buf + NCMP_FRAME_PREFIX_SIZE;
    out->session_id  = get_u32le(h + 0);
    out->sequence_id = get_u32le(h + 4);
    out->command_id  = get_u32le(h + 8);
    out->ack         = get_u32le(h + 12);
    out->payload_len = get_u32le(h + 16);

    /* Invariant: frame_len == header + payload. */
    if (frame_len != (uint32_t)NCMP_HEADER_WIRE_SIZE + out->payload_len)
        return NCMP_ERR_TRUNCATED;

    return NCMP_OK;
}

int ncmp_wire_decode(const uint8_t *buf, size_t buf_len, NCMP_Message *out)
{
    const uint8_t *arr;
    const uint8_t *params;
    uint32_t sum = 0;
    size_t need;
    int rc;

    if (!buf || !out)
        return NCMP_ERR_INVAL;

    rc = ncmp_wire_decode_header(buf, buf_len, &out->header);
    if (rc != NCMP_OK)
        return rc;

    need = NCMP_FRAME_PREFIX_SIZE + NCMP_HEADER_WIRE_SIZE + out->header.payload_len;
    if (buf_len < need)
        return NCMP_ERR_TRUNCATED;
    if (out->header.payload_len < NCMP_PARAM_LEN_ARRAY_SIZE)
        return NCMP_ERR_TRUNCATED;

    arr = buf + NCMP_FRAME_PREFIX_SIZE + NCMP_HEADER_WIRE_SIZE;
    for (int i = 0; i < NCMP_MAX_PARAM_COUNT; ++i) {
        out->param_len[i] = get_u32le(arr + (size_t)i * 4);
        sum += out->param_len[i];
    }

    /* payload_len must exactly account for the array plus all parameters. */
    if ((uint64_t)out->header.payload_len != NCMP_PARAM_LEN_ARRAY_SIZE + sum)
        return NCMP_ERR_TRUNCATED;

    params = arr + NCMP_PARAM_LEN_ARRAY_SIZE;
    if (out->payload && sum > 0) {
        if (out->payload_cap < sum)
            return NCMP_ERR_NOSPACE;
        memcpy(out->payload, params, sum);
    }

    return NCMP_OK;
}

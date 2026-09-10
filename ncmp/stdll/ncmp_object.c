/*
 * Token NCMP - STDLL object-management marshalling adapter (implementation).
 *
 * See ncmp_object.h. Mirrors ncmp_admin.c: pack the request parameters as the
 * NCMP wire parameter layout, forward via the client transport, and surface the
 * token's CKR_* ack (or a mapped transport error).
 */
#include "ncmp/ncmp_object.h"
#include "ncmp/ncmp_cmd.h"
#include "ncmp/ncmp_ckr.h"
#include "ncmp/ncmp_wire.h"
#include "ncmp/ncmp_limits.h"
#include "ncmp/ncmp_errno.h"

/** Forward a 3-parameter object command and surface the token status. */
static unsigned long object_cmd(ncmp_client_t *c, uint32_t slot,
                                uint32_t opcode, uint32_t p0, uint32_t p1,
                                const uint8_t *blob, uint32_t blob_len)
{
    uint8_t w0[4], w1[4];
    const uint8_t *parts[3];
    uint32_t lens[3];
    uint8_t out[64];
    NCMP_Message rsp;
    int nrc;

    if (blob_len > NCMP_MAX_PARAM_SIZE)
        return NCMP_CKR_DATA_LEN_RANGE;

    ncmp_wr_u32le(w0, p0);
    ncmp_wr_u32le(w1, p1);
    parts[0] = w0;   lens[0] = sizeof(w0);
    parts[1] = w1;   lens[1] = sizeof(w1);
    parts[2] = blob; lens[2] = blob_len;

    nrc = ncmp_client_command_mp(c, slot, opcode, parts, lens, 3, out,
                                 sizeof(out), &rsp);
    if (nrc != NCMP_OK)
        return ncmp_err_to_ckr(nrc);
    return rsp.header.ack;
}

unsigned long ncmp_object_add(ncmp_client_t *c, uint32_t slot,
                              uint32_t obj_class, uint32_t key_type,
                              const uint8_t *value, uint32_t value_len)
{
    return object_cmd(c, slot, NCMP_CMD_OBJECT_ADD, obj_class, key_type, value,
                      value_len);
}

unsigned long ncmp_object_set_attrs(ncmp_client_t *c, uint32_t slot,
                                    uint32_t obj_class, uint32_t key_type,
                                    const uint8_t *attrs, uint32_t attrs_len)
{
    return object_cmd(c, slot, NCMP_CMD_OBJECT_SET_ATTR, obj_class, key_type,
                      attrs, attrs_len);
}

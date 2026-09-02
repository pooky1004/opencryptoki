/*
 * Token NCMP - STDLL token-administration marshalling adapter (implementation).
 *
 * See ncmp_admin.h. Mirrors ncmp_crypto.c: pack the request parameters, forward
 * via the client transport, surface the token's CKR_* ack (or a mapped
 * transport error).
 */
#include "ncmp/ncmp_admin.h"
#include "ncmp/ncmp_slotmap.h"
#include "ncmp/ncmp_cmd.h"
#include "ncmp/ncmp_ckr.h"
#include "ncmp/ncmp_wire.h"
#include "ncmp/ncmp_limits.h"
#include "ncmp/ncmp_errno.h"

#include <string.h>

/** Single-parameter admin command: forward and surface the token status. */
static unsigned long admin_cmd(ncmp_client_t *c, uint32_t slot, uint32_t opcode,
                               const uint8_t *in, uint32_t in_len, uint8_t *out,
                               uint32_t out_cap, uint32_t *out_len)
{
    uint32_t ack = 0;
    uint32_t got = 0;
    int nrc;

    nrc = ncmp_client_command(c, slot, opcode, in, in_len, out, out_cap, &got,
                              &ack);
    if (nrc != NCMP_OK)
        return ncmp_err_to_ckr(nrc);
    if (out_len)
        *out_len = got;
    return ack;
}

/** Multi-parameter admin command: forward and surface the token status. */
static unsigned long admin_cmd_mp(ncmp_client_t *c, uint32_t slot,
                                  uint32_t opcode, const uint8_t *const parts[],
                                  const uint32_t lens[], int n)
{
    uint8_t out[64];
    NCMP_Message rsp;
    int nrc;

    nrc = ncmp_client_command_mp(c, slot, opcode, parts, lens, n, out,
                                 sizeof(out), &rsp);
    if (nrc != NCMP_OK)
        return ncmp_err_to_ckr(nrc);
    return rsp.header.ack;
}

unsigned long ncmp_admin_token_info(ncmp_client_t *c, uint32_t slot,
                                    NCMP_TokenIdentity *out)
{
    uint8_t blob[NCMP_TOKEN_INFO_WIRE_SIZE];
    uint32_t got = 0;
    unsigned long rv;

    if (out == NULL)
        return NCMP_CKR_ARGUMENTS_BAD;

    rv = admin_cmd(c, slot, NCMP_CMD_VD_TOKEN_INFO, NULL, 0, blob, sizeof(blob),
                   &got);
    if (rv != NCMP_CKR_OK)
        return rv;
    if (ncmp_token_info_unpack(blob, got, out) != NCMP_OK)
        return NCMP_CKR_FUNCTION_FAILED;
    return NCMP_CKR_OK;
}

unsigned long ncmp_admin_login(ncmp_client_t *c, uint32_t slot,
                               uint32_t user_type, const uint8_t *pin,
                               uint32_t pin_len)
{
    uint8_t ut[4];
    const uint8_t *parts[2];
    uint32_t lens[2];

    if (pin_len > NCMP_MAX_PARAM_SIZE)
        return NCMP_CKR_PIN_LEN_RANGE;

    ncmp_wr_u32le(ut, user_type);
    parts[0] = ut;      lens[0] = sizeof(ut);
    parts[1] = pin;     lens[1] = pin_len;
    return admin_cmd_mp(c, slot, NCMP_CMD_LOGIN, parts, lens, 2);
}

unsigned long ncmp_admin_logout(ncmp_client_t *c, uint32_t slot)
{
    return admin_cmd(c, slot, NCMP_CMD_LOGOUT, NULL, 0, NULL, 0, NULL);
}

unsigned long ncmp_admin_init_pin(ncmp_client_t *c, uint32_t slot,
                                  const uint8_t *pin, uint32_t pin_len)
{
    if (pin_len > NCMP_MAX_PARAM_SIZE)
        return NCMP_CKR_PIN_LEN_RANGE;
    return admin_cmd(c, slot, NCMP_CMD_INIT_PIN, pin, pin_len, NULL, 0, NULL);
}

unsigned long ncmp_admin_set_pin(ncmp_client_t *c, uint32_t slot,
                                 const uint8_t *old_pin, uint32_t old_len,
                                 const uint8_t *new_pin, uint32_t new_len)
{
    const uint8_t *parts[2];
    uint32_t lens[2];

    if (old_len > NCMP_MAX_PARAM_SIZE || new_len > NCMP_MAX_PARAM_SIZE)
        return NCMP_CKR_PIN_LEN_RANGE;

    parts[0] = old_pin; lens[0] = old_len;
    parts[1] = new_pin; lens[1] = new_len;
    return admin_cmd_mp(c, slot, NCMP_CMD_SET_PIN, parts, lens, 2);
}

unsigned long ncmp_admin_init_token(ncmp_client_t *c, uint32_t slot,
                                    const uint8_t *so_pin, uint32_t so_len,
                                    const char *label)
{
    uint8_t labelbuf[NCMP_TI_LABEL_LEN];
    const uint8_t *parts[2];
    uint32_t lens[2];
    size_t llen;

    if (so_len > NCMP_MAX_PARAM_SIZE)
        return NCMP_CKR_PIN_LEN_RANGE;

    /* Right-pad the label with spaces to the fixed field width (PKCS#11). */
    memset(labelbuf, ' ', sizeof(labelbuf));
    if (label != NULL) {
        llen = strlen(label);
        if (llen > sizeof(labelbuf))
            llen = sizeof(labelbuf);
        memcpy(labelbuf, label, llen);
    }

    parts[0] = so_pin;   lens[0] = so_len;
    parts[1] = labelbuf; lens[1] = sizeof(labelbuf);
    return admin_cmd_mp(c, slot, NCMP_CMD_INIT_TOKEN, parts, lens, 2);
}

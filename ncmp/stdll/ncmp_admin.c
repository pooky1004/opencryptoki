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

unsigned long ncmp_admin_get_utc_time(ncmp_client_t *c, uint32_t slot,
                                      uint8_t *out)
{
    uint8_t blob[NCMP_TOKEN_UTC_LEN];
    uint32_t got = 0;
    unsigned long rv;

    if (out == NULL)
        return NCMP_CKR_ARGUMENTS_BAD;

    rv = admin_cmd(c, slot, NCMP_CMD_GET_UTC_TIME, NULL, 0, blob, sizeof(blob),
                   &got);
    if (rv != NCMP_CKR_OK)
        return rv;
    if (got != NCMP_TOKEN_UTC_LEN)
        return NCMP_CKR_FUNCTION_FAILED;
    memcpy(out, blob, NCMP_TOKEN_UTC_LEN);
    return NCMP_CKR_OK;
}

unsigned long ncmp_admin_set_utc_time(ncmp_client_t *c, uint32_t slot,
                                      const uint8_t *utc)
{
    if (utc == NULL)
        return NCMP_CKR_ARGUMENTS_BAD;
    return admin_cmd(c, slot, NCMP_CMD_SET_UTC_TIME, utc, NCMP_TOKEN_UTC_LEN,
                     NULL, 0, NULL);
}

unsigned long ncmp_admin_get_token_params(ncmp_client_t *c, uint32_t slot,
                                          uint8_t *label, uint8_t *serial,
                                          uint32_t *min_pin, uint32_t *max_pin)
{
    uint8_t out[128];
    NCMP_Message rsp;
    const uint8_t *plabel, *pserial, *pmin, *pmax;
    uint32_t llabel, lserial, lmin, lmax;
    const uint8_t dummy = 0;         /* single zero-length request parameter */
    const uint8_t *parts[1] = { &dummy };
    uint32_t lens[1] = { 0 };
    int nrc;

    nrc = ncmp_client_command_mp(c, slot, NCMP_CMD_GET_TOKEN_PARAMS, parts,
                                 lens, 1, out, sizeof(out), &rsp);
    if (nrc != NCMP_OK)
        return ncmp_err_to_ckr(nrc);
    if (rsp.header.ack != NCMP_CKR_OK)
        return rsp.header.ack;

    if (ncmp_msg_param(&rsp, 0, &plabel, &llabel) != NCMP_OK ||
        llabel != NCMP_TI_LABEL_LEN ||
        ncmp_msg_param(&rsp, 1, &pserial, &lserial) != NCMP_OK ||
        lserial != NCMP_TI_SERIAL_LEN ||
        ncmp_msg_param(&rsp, 2, &pmin, &lmin) != NCMP_OK || lmin != 4 ||
        ncmp_msg_param(&rsp, 3, &pmax, &lmax) != NCMP_OK || lmax != 4)
        return NCMP_CKR_FUNCTION_FAILED;

    if (label != NULL)
        memcpy(label, plabel, NCMP_TI_LABEL_LEN);
    if (serial != NULL)
        memcpy(serial, pserial, NCMP_TI_SERIAL_LEN);
    if (min_pin != NULL)
        *min_pin = ncmp_rd_u32le(pmin);
    if (max_pin != NULL)
        *max_pin = ncmp_rd_u32le(pmax);
    return NCMP_CKR_OK;
}

unsigned long ncmp_admin_login(ncmp_client_t *c, uint32_t slot,
                               uint32_t user_type, uint32_t flags,
                               const uint8_t *pin, uint32_t pin_len)
{
    uint8_t ut[4], fl[4];
    const uint8_t *parts[3];
    uint32_t lens[3];

    if (pin_len > NCMP_MAX_PARAM_SIZE)
        return NCMP_CKR_PIN_LEN_RANGE;

    ncmp_wr_u32le(ut, user_type);
    ncmp_wr_u32le(fl, flags);
    parts[0] = ut;      lens[0] = sizeof(ut);
    parts[1] = fl;      lens[1] = sizeof(fl);
    parts[2] = pin;     lens[2] = pin_len;
    return admin_cmd_mp(c, slot, NCMP_CMD_LOGIN, parts, lens, 3);
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

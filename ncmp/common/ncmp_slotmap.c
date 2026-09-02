/*
 * Token NCMP - CK-slot <-> physical-token binding and identity cache.
 *
 * See ncmp_slotmap.h. Every mutating operation runs under the SHM global_lock
 * (robust, process-shared) so concurrent STDLL processes agree on the mapping.
 */
#include "ncmp/ncmp_slotmap.h"
#include "ncmp/ncmp_cmd.h"
#include "ncmp/ncmp_mutex.h"
#include "ncmp/ncmp_errno.h"

#include <string.h>

/**
 * @brief Compare a NUL/space-padded fixed identity field to a C string.
 * @return Non-zero when they name the same value (trailing padding ignored).
 */
static int ident_field_eq(const char *field, size_t cap, const char *want)
{
    size_t flen;

    /* Trim trailing NULs and spaces from the fixed-width field. */
    for (flen = 0; flen < cap && field[flen] != '\0'; ++flen)
        ;
    while (flen > 0 && field[flen - 1] == ' ')
        --flen;

    return flen == strlen(want) && memcmp(field, want, flen) == 0;
}

int ncmp_token_info_unpack(const uint8_t *blob, uint32_t len,
                           NCMP_TokenIdentity *out)
{
    if (!blob || !out)
        return NCMP_ERR_INVAL;
    if (len < NCMP_TOKEN_INFO_WIRE_SIZE)
        return NCMP_ERR_TRUNCATED;

    memset(out, 0, sizeof(*out));
    memcpy(out->label, blob + NCMP_TI_OFF_LABEL, NCMP_TI_LABEL_LEN);
    memcpy(out->serial, blob + NCMP_TI_OFF_SERIAL, NCMP_TI_SERIAL_LEN);
    memcpy(out->manufacturer, blob + NCMP_TI_OFF_MANUF, NCMP_TI_MANUF_LEN);
    memcpy(out->model, blob + NCMP_TI_OFF_MODEL, NCMP_TI_MODEL_LEN);
    out->hw_major = blob[NCMP_TI_OFF_HW_MAJOR];
    out->hw_minor = blob[NCMP_TI_OFF_HW_MINOR];
    out->fw_major = blob[NCMP_TI_OFF_FW_MAJOR];
    out->fw_minor = blob[NCMP_TI_OFF_FW_MINOR];
    out->flags = ncmp_rd_u32le(blob + NCMP_TI_OFF_FLAGS);
    out->valid = 1;
    return NCMP_OK;
}

int ncmp_slot_set_identity(void *base, uint32_t slot_id,
                           const NCMP_TokenIdentity *id)
{
    NCMP_ShmHeader *h = (NCMP_ShmHeader *)base;
    NCMP_Slot *slot;
    int lrc;

    if (!base || !id)
        return NCMP_ERR_INVAL;
    slot = ncmp_shm_slot(base, slot_id);
    if (!slot)
        return NCMP_ERR_INVAL;

    lrc = ncmp_mutex_lock(&h->global_lock);
    if (lrc < 0)
        return lrc;
    slot->token = *id;
    slot->token.valid = 1;
    ncmp_mutex_unlock(&h->global_lock);
    return NCMP_OK;
}

int ncmp_slot_get_identity(void *base, uint32_t slot_id,
                           NCMP_TokenIdentity *out)
{
    NCMP_ShmHeader *h = (NCMP_ShmHeader *)base;
    NCMP_Slot *slot;
    int lrc, rc = NCMP_OK;

    if (!base || !out)
        return NCMP_ERR_INVAL;
    slot = ncmp_shm_slot(base, slot_id);
    if (!slot)
        return NCMP_ERR_INVAL;

    lrc = ncmp_mutex_lock(&h->global_lock);
    if (lrc < 0)
        return lrc;
    if (slot->token.valid)
        *out = slot->token;
    else
        rc = NCMP_ERR_STATE;
    ncmp_mutex_unlock(&h->global_lock);
    return rc;
}

/** Non-empty string test (NULL and "" both mean "no preference"). */
static int want_set(const char *s)
{
    return s != NULL && s[0] != '\0';
}

int ncmp_slot_bind(void *base, uint32_t online_mask, int32_t ck_slot_id,
                   const char *want_label, const char *want_serial,
                   uint32_t *out_slot_id)
{
    NCMP_ShmHeader *h = (NCMP_ShmHeader *)base;
    int lrc, rc = NCMP_ERR_FULL;
    int chosen = -1;

    if (!base || !out_slot_id)
        return NCMP_ERR_INVAL;

    lrc = ncmp_mutex_lock(&h->global_lock);
    if (lrc < 0)
        return lrc;

    /* 1. Idempotent: this CK slot already owns a physical slot. */
    for (uint32_t s = 0; s < h->slot_count; ++s) {
        if ((online_mask & (1u << s)) == 0)
            continue;
        if (h->slots[s].bound_ck_slot == ck_slot_id) {
            chosen = (int)s;
            goto done;
        }
    }

    /* 2. Match an unclaimed slot by serial number. */
    if (want_set(want_serial)) {
        for (uint32_t s = 0; s < h->slot_count; ++s) {
            NCMP_Slot *slot = &h->slots[s];

            if ((online_mask & (1u << s)) == 0 ||
                slot->bound_ck_slot != NCMP_SLOT_UNBOUND || !slot->token.valid)
                continue;
            if (ident_field_eq(slot->token.serial, NCMP_TI_SERIAL_LEN,
                               want_serial)) {
                chosen = (int)s;
                goto claim;
            }
        }
    }

    /* 3. Match an unclaimed slot by label. */
    if (want_set(want_label)) {
        for (uint32_t s = 0; s < h->slot_count; ++s) {
            NCMP_Slot *slot = &h->slots[s];

            if ((online_mask & (1u << s)) == 0 ||
                slot->bound_ck_slot != NCMP_SLOT_UNBOUND || !slot->token.valid)
                continue;
            if (ident_field_eq(slot->token.label, NCMP_TI_LABEL_LEN,
                               want_label)) {
                chosen = (int)s;
                goto claim;
            }
        }
    }

    /* 4. Fall back to the first unclaimed online slot. */
    for (uint32_t s = 0; s < h->slot_count; ++s) {
        if ((online_mask & (1u << s)) == 0 ||
            h->slots[s].bound_ck_slot != NCMP_SLOT_UNBOUND)
            continue;
        chosen = (int)s;
        goto claim;
    }
    goto done; /* rc stays NCMP_ERR_FULL. */

claim:
    h->slots[chosen].bound_ck_slot = ck_slot_id;
done:
    if (chosen >= 0) {
        *out_slot_id = (uint32_t)chosen;
        rc = NCMP_OK;
    }
    ncmp_mutex_unlock(&h->global_lock);
    return rc;
}

int ncmp_slot_unbind(void *base, uint32_t slot_id, int32_t ck_slot_id)
{
    NCMP_ShmHeader *h = (NCMP_ShmHeader *)base;
    NCMP_Slot *slot;
    int lrc;

    if (!base)
        return NCMP_ERR_INVAL;
    slot = ncmp_shm_slot(base, slot_id);
    if (!slot)
        return NCMP_ERR_INVAL;

    lrc = ncmp_mutex_lock(&h->global_lock);
    if (lrc < 0)
        return lrc;
    if (slot->bound_ck_slot == ck_slot_id)
        slot->bound_ck_slot = NCMP_SLOT_UNBOUND;
    ncmp_mutex_unlock(&h->global_lock);
    return NCMP_OK;
}

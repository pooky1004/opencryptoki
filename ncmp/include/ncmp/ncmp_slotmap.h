/*
 * Token NCMP - CK-slot <-> physical-token binding and identity cache.
 *
 * ncmpd scans the USB bus at boot, queries each present token's identity
 * (NCMP_CMD_VD_TOKEN_INFO), and caches it per physical slot in SHM. When an
 * STDLL process opens a CK slot it binds that CK slot to a physical token: if a
 * token whose label or serial matches is online and unclaimed it wins, otherwise
 * the first unclaimed online token is taken. The binding is keyed by CK slot id
 * and lives in SHM, so every process opening the same CK slot resolves to the
 * same physical token (the ncmpd multiplexer fans their traffic onto it), while
 * distinct CK slots claim distinct tokens.
 *
 * All mutating calls take the SHM global_lock (robust, process-shared) so the
 * mapping is race-free across processes; identity fields are POD in SHM.
 */
#ifndef NCMP_SLOTMAP_H
#define NCMP_SLOTMAP_H

#include <stdint.h>

#include "ncmp_shm.h"

/**
 * @brief Decode a NCMP_CMD_VD_TOKEN_INFO identity blob into a struct.
 * @param blob Parameter-0 bytes returned by the token.
 * @param len  Blob length (must be >= NCMP_TOKEN_INFO_WIRE_SIZE).
 * @param out  Receives the decoded identity (out->valid set to 1).
 * @return NCMP_OK, or NCMP_ERR_TRUNCATED / NCMP_ERR_INVAL.
 */
int ncmp_token_info_unpack(const uint8_t *blob, uint32_t len,
                           NCMP_TokenIdentity *out);

/**
 * @brief Cache a physical slot's identity (daemon, at boot). Global-lock guarded.
 * @param base    Local SHM mapping base.
 * @param slot_id Physical slot index.
 * @param id      Identity to store (copied verbatim).
 * @return NCMP_OK or a negative NCMP error.
 */
int ncmp_slot_set_identity(void *base, uint32_t slot_id,
                           const NCMP_TokenIdentity *id);

/**
 * @brief Read a physical slot's cached identity. Global-lock guarded.
 * @param base    Local SHM mapping base.
 * @param slot_id Physical slot index.
 * @param out     Receives the identity copy.
 * @return NCMP_OK, or NCMP_ERR_STATE if the slot has no valid identity yet.
 */
int ncmp_slot_get_identity(void *base, uint32_t slot_id,
                           NCMP_TokenIdentity *out);

/**
 * @brief Bind a CK slot to a physical token, matching by label or serial.
 *
 * Resolution order, under the global lock, over online slots only:
 *   1. A slot already bound to @p ck_slot_id (idempotent for repeat opens).
 *   2. An unclaimed slot whose serial equals @p want_serial (if non-NULL/empty).
 *   3. An unclaimed slot whose label  equals @p want_label  (if non-NULL/empty).
 *   4. The first unclaimed online slot ("first unallocated device").
 *
 * @param base         Local SHM mapping base.
 * @param online_mask  Bitmask of online physical slots (bit s => slot s).
 * @param ck_slot_id   The opencryptoki CK slot id being opened.
 * @param want_label   Desired token label, or NULL/"" for no label preference.
 * @param want_serial  Desired serial number, or NULL/"" for no serial preference.
 * @param out_slot_id  Receives the chosen physical slot index.
 * @return NCMP_OK on success, NCMP_ERR_FULL if no online slot is available,
 *         or a negative NCMP error.
 */
int ncmp_slot_bind(void *base, uint32_t online_mask, int32_t ck_slot_id,
                   const char *want_label, const char *want_serial,
                   uint32_t *out_slot_id);

/**
 * @brief Release a physical slot's CK-slot binding. Global-lock guarded.
 *
 * Only clears the binding when it is currently held by @p ck_slot_id. Note the
 * STDLL does NOT call this on token final: the CK-slot -> physical mapping is a
 * daemon-lifetime property (many processes share one slot). Provided for admin
 * reset and the test suite.
 *
 * @param base       Local SHM mapping base.
 * @param slot_id    Physical slot index.
 * @param ck_slot_id CK slot id expected to own the binding.
 * @return NCMP_OK (also when nothing was bound), or a negative NCMP error.
 */
int ncmp_slot_unbind(void *base, uint32_t slot_id, int32_t ck_slot_id);

#endif /* NCMP_SLOTMAP_H */

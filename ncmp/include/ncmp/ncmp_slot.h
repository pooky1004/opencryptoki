/*
 * Token NCMP - Producer-side slot submission helpers.
 *
 * Shared by the STDLL client and by tests: a producer enqueues a request into
 * a slot's MPSC ring (claim -> encode into the entry's SHM request buffer ->
 * post) and later waits for the comm_thread to mark the entry DONE, then reads
 * back the response. All buffer access is by SHM offset (address-independent).
 */
#ifndef NCMP_SLOT_H
#define NCMP_SLOT_H

#include <stdint.h>

#include "ncmp_shm.h"
#include "ncmp_wire.h"

/**
 * @brief Enqueue one request onto @p slot (FREE -> CLAIMED -> POSTED).
 *
 * Claims a ring entry, encodes @p req into the entry's SHM request buffer, and
 * records the owner/sequence so the comm_thread can correlate the response.
 *
 * @param base       Local SHM mapping base.
 * @param slot       Target slot.
 * @param session_id Owning (app) session id; stored in owner_sess initially.
 * @param pid        Enqueuing process id (key for the session map).
 * @param sequence_id Per-session request id (matched against the response).
 * @param req        Request message to encode.
 * @param out_idx    Receives the claimed ring index on success.
 * @return NCMP_OK, NCMP_ERR_FULL if the ring is saturated, or an encode error.
 */
int ncmp_slot_enqueue(void *base, NCMP_Slot *slot, uint32_t session_id,
                      uint32_t pid, uint32_t sequence_id,
                      const NCMP_Message *req, int *out_idx);

/**
 * @brief Session-map helpers (ncmpd side). The slot's comm_thread is the single
 *        writer, so these take no lock; readers (display) tolerate a stale read.
 */
int  ncmp_sess_map_store(NCMP_Slot *slot, uint32_t pid, uint32_t app_sid,
                         uint32_t hsm_sid);
int  ncmp_sess_map_lookup(const NCMP_Slot *slot, uint32_t pid, uint32_t app_sid,
                          uint32_t *out_hsm);
void ncmp_sess_map_remove_hsm(NCMP_Slot *slot, uint32_t hsm_sid);

/**
 * @brief Capture the last comm<->HSM frame for Debug App inspection.
 * @param slot Target slot. @param buf Wire frame bytes. @param len Frame length.
 * Stores up to NCMP_LASTMSG_CAP bytes into slot->last_msg (tx or rx) with a
 * monotonic timestamp. Written by the slot owner (comm_thread) or the boot probe.
 */
void ncmp_slot_lastmsg_tx(NCMP_Slot *slot, const uint8_t *buf, uint32_t len);
void ncmp_slot_lastmsg_rx(NCMP_Slot *slot, const uint8_t *buf, uint32_t len);

/**
 * @brief Wait for entry @p idx to reach DONE, then decode its response.
 *
 * Spins (yielding) until the comm_thread transitions the entry to DONE or the
 * deadline elapses. On timeout the entry is marked ABANDONED so a late
 * response is discarded by the comm_thread. Releases the entry (DONE -> FREE)
 * on success.
 *
 * @param base        Local SHM mapping base.
 * @param slot        Owning slot.
 * @param idx         Ring index returned by ncmp_slot_enqueue().
 * @param rsp         Receives the decoded response (payload optional).
 * @param spin_budget Max yield iterations before declaring a timeout (0 = wait
 *                    indefinitely).
 * @return NCMP_OK or NCMP_ERR_TIMEOUT.
 */
int ncmp_slot_wait(void *base, NCMP_Slot *slot, int idx, NCMP_Message *rsp,
                   uint64_t spin_budget);

#endif /* NCMP_SLOT_H */

/*
 * Token NCMP - Shared memory layout (address-independent).
 *
 * STRICT RULE: no raw pointers are ever stored in SHM. Different processes
 * mmap/shmat the region at different virtual addresses, so all internal
 * references are array indices or byte offsets from the SHM base. Consumers
 * translate offsets to local addresses with ncmp_shm_ptr().
 */
#ifndef NCMP_SHM_H
#define NCMP_SHM_H

#include <stdint.h>
#include <pthread.h>
#include "ncmp_limits.h"
#include "ncmp_queue.h"
#include "ncmp_wire.h"

/** Magic and version stamped into the SHM header for sanity checks. */
#define NCMP_SHM_MAGIC 0x4E434D50u /* "NCMP" */
#define NCMP_SHM_VERSION 2u /* v2 adds per-slot token identity + allocation. */

#include "ncmp_cmd.h" /* NCMP_TI_* identity field sizes. */

/**
 * Per-entry scratch buffer size. Each ring entry owns one request and one
 * response buffer of this size, carved from its slot's SHM pool. Sized to the
 * largest possible encoded frame so any valid command fits.
 */
#define NCMP_ENTRY_BUF_SIZE NCMP_MAX_FRAME_SIZE

/** Bytes of SHM scratch pool reserved per slot (req + rsp for every entry). */
#define NCMP_SLOT_POOL_SIZE \
    ((uint64_t)NCMP_QUEUE_DEPTH * 2u * (uint64_t)NCMP_ENTRY_BUF_SIZE)

/** Per-slot lifecycle state. */
typedef enum ncmp_slot_state {
    NCMP_SLOT_ABSENT = 0,  /**< No token present. */
    NCMP_SLOT_ONLINE = 1,  /**< Token present and comm_thread running. */
    NCMP_SLOT_FAULTED = 2  /**< USB/token error; awaiting recovery. */
} ncmp_slot_state_t;

/**
 * Cached identity of the physical token backing a slot. Filled once by the
 * daemon at boot (from NCMP_CMD_VD_TOKEN_INFO) and read by every STDLL process
 * to match a CK slot to a physical token by label or serial number. POD only
 * (no pointers) so it lives directly in SHM. Character fields are NUL-padded.
 */
typedef struct ncmp_token_identity {
    char     label[NCMP_TI_LABEL_LEN];       /**< Token label. */
    char     serial[NCMP_TI_SERIAL_LEN];     /**< Serial number. */
    char     manufacturer[NCMP_TI_MANUF_LEN];/**< Manufacturer id. */
    char     model[NCMP_TI_MODEL_LEN];       /**< Model. */
    uint8_t  hw_major;                       /**< Hardware version major. */
    uint8_t  hw_minor;                       /**< Hardware version minor. */
    uint8_t  fw_major;                       /**< Firmware version major. */
    uint8_t  fw_minor;                       /**< Firmware version minor. */
    uint32_t flags;                          /**< Vendor status flags. */
    uint8_t  valid;                          /**< Non-zero once identify ran. */
    uint8_t  _pad[3];
} NCMP_TokenIdentity;

/** Sentinel bound_ck_slot meaning "physical slot not yet claimed". */
#define NCMP_SLOT_UNBOUND (-1)

/**
 * Per-slot in-flight tracking and statistics. Counters are updated by the
 * comm_thread around USB dispatch/receive.
 */
typedef struct ncmp_slot_stats {
    volatile uint32_t in_flight_cnt;        /**< Commands inside the token now. */
    uint32_t          stats_max_in_flight;  /**< Historical peak in_flight_cnt. */
    uint64_t          stats_total_sent_cmds;/**< Total commands sent to token. */
} NCMP_SlotStats;

/**
 * Per-slot metadata block. Sized and laid out identically in every process.
 * Contains no pointers; queue/session data are embedded or offset-addressed.
 */
typedef struct ncmp_slot {
    int32_t         state;         /**< ncmp_slot_state_t. */
    uint32_t        slot_id;       /**< 0 .. PKCS11_MAX_SLOT_COUNT-1. */
    uint32_t        max_inflight;  /**< Dispatch ceiling (<= containers). */

    /* Session accounting - guarded by sess_lock (NOT by atomics). */
    pthread_mutex_t sess_lock;     /**< Robust, process-shared. */
    uint32_t        cur_sessions;  /**< 0 .. PKCS11_MAX_SESSION_PER_SLOT. */

    NCMP_SlotStats  stats;         /**< In-flight + throughput counters. */

    /* Physical-token identity + cross-process allocation. Both are written
     * under the SHM global_lock (see ncmp_slotmap.c), never via raw atomics, so
     * concurrent STDLL processes agree on the CK-slot -> physical-slot mapping.
     * The binding is keyed by the CK slot id (not a pid): every process opening
     * the same CK slot resolves to the same physical token, while distinct CK
     * slots claim distinct tokens. The mapping persists for the daemon's life. */
    NCMP_TokenIdentity token;      /**< Cached identity (daemon fills at boot). */
    int32_t         bound_ck_slot; /**< Claiming CK slot id, or NCMP_SLOT_UNBOUND. */
    uint32_t        _bind_pad;

    /* MPSC command ring (pending queue). Producers CAS entries; the slot's
     * single comm_thread consumes them. Waiting clients poll their entry's
     * state transition to DONE (the "waiting queue" is the DONE view). */
    NCMP_QEntry     ring[NCMP_QUEUE_DEPTH];

    uint64_t        buf_pool_off;  /**< SHM offset of this slot's scratch pool. */
    uint64_t        buf_pool_len;  /**< Byte length of the scratch pool. */
} NCMP_Slot;

/**
 * SHM global header. Placed at offset 0. All offsets below are measured from
 * the SHM base address.
 */
typedef struct ncmp_shm_header {
    uint32_t        magic;         /**< NCMP_SHM_MAGIC. */
    uint32_t        version;       /**< NCMP_SHM_VERSION. */
    uint32_t        slot_count;    /**< Active slots (<= PKCS11_MAX_SLOT_COUNT). */
    uint32_t        _pad;
    uint64_t        total_size;    /**< Total SHM size in bytes. */
    uint64_t        slots_off;     /**< Offset of the NCMP_Slot array. */
    pthread_mutex_t global_lock;   /**< Robust; guards slot creation/teardown. */
    NCMP_Slot       slots[PKCS11_MAX_SLOT_COUNT];
} NCMP_ShmHeader;

/** Well-known POSIX SHM object name and IPC socket path. */
#define NCMP_SHM_NAME "/ncmpd_shm"

/**
 * @brief Translate a SHM byte offset to a local pointer.
 * @param base Local mapping base (from mmap/shmat).
 * @param off  Byte offset stored in SHM.
 * @return Local address, or NULL if @p off is 0 (sentinel for "none").
 */
static inline void *ncmp_shm_ptr(void *base, uint64_t off)
{
    return off ? (void *)((uint8_t *)base + off) : (void *)0;
}

/**
 * @brief Resolve a slot by index from a local SHM mapping.
 * @param base    Local mapping base.
 * @param slot_id Slot index.
 * @return Local pointer to the slot, or NULL if @p slot_id is out of range.
 */
static inline NCMP_Slot *ncmp_shm_slot(void *base, uint32_t slot_id)
{
    NCMP_ShmHeader *h = (NCMP_ShmHeader *)base;

    if (!base || slot_id >= h->slot_count)
        return (NCMP_Slot *)0;
    return &h->slots[slot_id];
}

/**
 * @brief Create and initialize the SHM region (daemon only).
 * @param out_base Receives the local mapping base on success.
 * @return 0 on success; negative NCMP error otherwise.
 */
int ncmp_shm_create(void **out_base);

/**
 * @brief Attach to an existing SHM region (STDLL clients).
 * @param out_base Receives the local mapping base on success.
 * @return 0 on success; negative NCMP error otherwise.
 */
int ncmp_shm_attach(void **out_base);

/**
 * @brief Unmap a SHM region obtained from create/attach.
 * @param base Local mapping base (may be NULL).
 * @return 0 on success; negative NCMP error otherwise.
 */
int ncmp_shm_detach(void *base);

/**
 * @brief Unmap and unlink the SHM object (daemon shutdown / test cleanup).
 * @param base Local mapping base (may be NULL).
 * @return 0 on success; negative NCMP error otherwise.
 */
int ncmp_shm_destroy(void *base);

#endif /* NCMP_SHM_H */

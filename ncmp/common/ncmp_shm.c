/*
 * Token NCMP - Shared memory create/attach/destroy.
 *
 * Only the daemon calls ncmp_shm_create(); STDLL clients call
 * ncmp_shm_attach(). All robust mutexes in the region are initialized by the
 * daemon during create. No raw pointers are ever written into the region.
 *
 * Layout (all offsets from the mapping base):
 *   [NCMP_ShmHeader | slots[4]]  then  [slot 0 pool][slot 1 pool]...[slot 3 pool]
 * Each slot pool holds, per ring entry, one request buffer immediately followed
 * by one response buffer (NCMP_ENTRY_BUF_SIZE each). The ring entry records
 * these as req_off/rsp_off so producers and the comm_thread address them by
 * offset, never by pointer.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "ncmp/ncmp_shm.h"
#include "ncmp/ncmp_mutex.h"
#include "ncmp/ncmp_errno.h"

#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/** Total SHM size: header (with embedded slot array) + one pool per slot. */
static size_t ncmp_shm_total_size(void)
{
    return sizeof(NCMP_ShmHeader) +
           (size_t)PKCS11_MAX_SLOT_COUNT * (size_t)NCMP_SLOT_POOL_SIZE;
}

int ncmp_shm_create(void **out_base)
{
    size_t total = ncmp_shm_total_size();
    void *base;
    NCMP_ShmHeader *h;
    int fd;

    if (!out_base)
        return NCMP_ERR_INVAL;

    fd = shm_open(NCMP_SHM_NAME, O_CREAT | O_RDWR, 0600);
    if (fd < 0)
        return NCMP_ERR_STATE;
    if (ftruncate(fd, (off_t)total) != 0) {
        close(fd);
        shm_unlink(NCMP_SHM_NAME);
        return NCMP_ERR_STATE;
    }

    base = mmap(NULL, total, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (base == MAP_FAILED)
        return NCMP_ERR_STATE;

    h = (NCMP_ShmHeader *)base;
    memset(h, 0, total);
    h->magic = NCMP_SHM_MAGIC;
    h->version = NCMP_SHM_VERSION;
    h->slot_count = PKCS11_MAX_SLOT_COUNT;
    h->total_size = total;
    h->slots_off = (uint64_t)((uint8_t *)h->slots - (uint8_t *)base);

    if (ncmp_mutex_init(&h->global_lock) != 0) {
        munmap(base, total);
        shm_unlink(NCMP_SHM_NAME);
        return NCMP_ERR_MUTEX;
    }

    for (uint32_t s = 0; s < PKCS11_MAX_SLOT_COUNT; ++s) {
        NCMP_Slot *slot = &h->slots[s];
        uint64_t pool_off = (uint64_t)sizeof(NCMP_ShmHeader) +
                            (uint64_t)s * NCMP_SLOT_POOL_SIZE;

        slot->slot_id = s;
        slot->state = NCMP_SLOT_ABSENT;
        slot->max_inflight = NCMP_DEFAULT_MAX_INFLIGHT;
        slot->cur_sessions = 0;
        slot->buf_pool_off = pool_off;
        slot->buf_pool_len = NCMP_SLOT_POOL_SIZE;

        if (ncmp_mutex_init(&slot->sess_lock) != 0) {
            munmap(base, total);
            shm_unlink(NCMP_SHM_NAME);
            return NCMP_ERR_MUTEX;
        }

        /* Single creator here, so plain stores of the initial FREE state are
         * safe; producers advance states via CAS thereafter. Each entry gets a
         * request buffer followed by a response buffer inside the slot pool. */
        for (uint32_t i = 0; i < NCMP_QUEUE_DEPTH; ++i) {
            uint64_t entry_off = pool_off +
                                 (uint64_t)i * 2u * NCMP_ENTRY_BUF_SIZE;

            slot->ring[i].req_off = entry_off;
            slot->ring[i].rsp_off = entry_off + NCMP_ENTRY_BUF_SIZE;
            slot->ring[i].req_len = 0;
            slot->ring[i].rsp_len = 0;
            slot->ring[i].state = NCMP_Q_FREE;
        }
    }

    *out_base = base;
    return NCMP_OK;
}

int ncmp_shm_attach(void **out_base)
{
    struct stat st;
    size_t total;
    void *base;
    NCMP_ShmHeader *h;
    int fd;

    if (!out_base)
        return NCMP_ERR_INVAL;

    fd = shm_open(NCMP_SHM_NAME, O_RDWR, 0600);
    if (fd < 0)
        return NCMP_ERR_NODAEMON;
    if (fstat(fd, &st) != 0 || (size_t)st.st_size < sizeof(NCMP_ShmHeader)) {
        close(fd);
        return NCMP_ERR_STATE;
    }
    total = (size_t)st.st_size;

    base = mmap(NULL, total, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (base == MAP_FAILED)
        return NCMP_ERR_STATE;

    h = (NCMP_ShmHeader *)base;
    if (h->magic != NCMP_SHM_MAGIC) {
        munmap(base, total);
        return NCMP_ERR_STATE;
    }
    if (h->version != NCMP_SHM_VERSION) {
        munmap(base, total);
        return NCMP_ERR_VERSION;
    }

    *out_base = base;
    return NCMP_OK;
}

int ncmp_shm_detach(void *base)
{
    NCMP_ShmHeader *h = (NCMP_ShmHeader *)base;
    size_t total;

    if (!base)
        return NCMP_OK;
    total = (size_t)h->total_size;
    if (total < sizeof(NCMP_ShmHeader))
        total = sizeof(NCMP_ShmHeader);

    return munmap(base, total) == 0 ? NCMP_OK : NCMP_ERR_STATE;
}

int ncmp_shm_destroy(void *base)
{
    int rc = ncmp_shm_detach(base);

    /* Best-effort unlink; ignore ENOENT so repeated calls are harmless. */
    shm_unlink(NCMP_SHM_NAME);
    return rc;
}

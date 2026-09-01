/*
 * Token NCMP - PKCS#11 general-purpose functions.
 *
 * C_Initialize / C_Finalize / C_GetInfo. C_GetFunctionList and the interface
 * discovery entry points live in p11_functionlist.c.
 */
#include "p11_provider.h"

#include "ncmp/ncmp_session.h"
#include "ncmp/ncmp_shm.h"

#include <string.h>

/** Library + Cryptoki versions this provider advertises. */
#define P11_CK_MAJOR 3
#define P11_CK_MINOR 2
#define P11_LIB_MAJOR 1
#define P11_LIB_MINOR 0

CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
{
    CK_C_INITIALIZE_ARGS_PTR args = (CK_C_INITIALIZE_ARGS_PTR)pInitArgs;

    p11_lock();

    if (g_p11.initialized) {
        p11_unlock();
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }

    /* Argument validation per PKCS#11: pReserved must be NULL; if any mutex
     * callback is supplied, all four must be. We always lock internally with
     * pthreads, which satisfies both the OS-locking and callback contracts. */
    if (args) {
        if (args->pReserved != NULL) {
            p11_unlock();
            return CKR_ARGUMENTS_BAD;
        }
        {
            int n = (args->CreateMutex ? 1 : 0) + (args->DestroyMutex ? 1 : 0) +
                    (args->LockMutex ? 1 : 0) + (args->UnlockMutex ? 1 : 0);
            if (n != 0 && n != 4) {
                p11_unlock();
                return CKR_ARGUMENTS_BAD;
            }
        }
        g_p11.os_locking = (args->flags & CKF_OS_LOCKING_OK) ? 1 : 0;
    } else {
        g_p11.os_locking = 0;
    }

    g_p11.initialized = 1;
    g_p11.next_session = 1;
    g_p11.next_object = 1;

    /* Best-effort connect: a token may legitimately be absent at init time. */
    (void)p11_ensure_client();

    p11_unlock();
    return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
    int i;

    if (pReserved != NULL)
        return CKR_ARGUMENTS_BAD;

    p11_lock();
    if (!g_p11.initialized) {
        p11_unlock();
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    /* Close every session (drops session-scoped objects). Token objects are
     * left in place to model token persistence across Initialize/Finalize. */
    for (i = 0; i < P11_MAX_SESSIONS; ++i) {
        p11_session_t *s = &g_p11.sessions[i];
        uint32_t phys = 0;

        if (!s->in_use)
            continue;
        /* Release the cross-process per-slot session reservation. */
        if (g_p11.client_ready &&
            p11_slotmap_phys(s->slot, &phys) == CKR_OK) {
            NCMP_Slot *shm_slot = ncmp_shm_slot(g_p11.client.shm_base, phys);
            if (shm_slot)
                ncmp_session_close(shm_slot);
        }
        p11_session_free(s);
    }
    for (i = 0; i < P11_MAX_SLOTS; ++i) {
        g_p11.slots[i].logged_in = 0;
        g_p11.slots[i].user_type = 0;
    }

    if (g_p11.client_ready) {
        ncmp_client_fini(&g_p11.client);
        g_p11.client_ready = 0;
    }
    /* Drop the slot map so a stale mask can't be read before the next
     * connection is re-established. */
    g_p11.slot_mask = 0;
    p11_slotmap_build(0);

    g_p11.initialized = 0;
    p11_unlock();
    return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!pInfo)
        return CKR_ARGUMENTS_BAD;

    memset(pInfo, 0, sizeof(*pInfo));
    pInfo->cryptokiVersion.major = P11_CK_MAJOR;
    pInfo->cryptokiVersion.minor = P11_CK_MINOR;
    pInfo->libraryVersion.major = P11_LIB_MAJOR;
    pInfo->libraryVersion.minor = P11_LIB_MINOR;
    pInfo->flags = 0;
    p11_pad(pInfo->manufacturerID, sizeof(pInfo->manufacturerID),
            "DYST");
    p11_pad(pInfo->libraryDescription, sizeof(pInfo->libraryDescription),
            "NCMP FX3 USB token library");
    return CKR_OK;
}

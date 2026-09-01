/*
 * Token NCMP - PKCS#11 session management + login functions.
 *
 * Sessions are tracked per process here, but each open also reserves a slot on
 * the daemon's process-shared session counter (ncmp_session_open), so the
 * PKCS11_MAX_SESSION_PER_SLOT ceiling holds across every process sharing the
 * token. Login state is per token (per slot) and shared by all its sessions.
 */
#include "p11_provider.h"

#include "ncmp/ncmp_session.h"
#include "ncmp/ncmp_shm.h"
#include "ncmp/ncmp_errno.h"

#include <string.h>

/** Recompute a session's CKS_* state from the slot login state + RW flag. */
static CK_STATE p11_session_state(const p11_session_t *s)
{
    uint32_t phys = 0;
    int rw = (s->flags & CKF_RW_SESSION) ? 1 : 0;

    if (p11_slotmap_phys(s->slot, &phys) != CKR_OK)
        return rw ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;

    if (g_p11.slots[phys].logged_in) {
        if (g_p11.slots[phys].user_type == CKU_SO)
            return CKS_RW_SO_FUNCTIONS;
        return rw ? CKS_RW_USER_FUNCTIONS : CKS_RO_USER_FUNCTIONS;
    }
    return rw ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
                    CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
    uint32_t phys = 0;
    CK_RV rv;
    NCMP_Slot *shm_slot;
    p11_session_t *s;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!phSession)
        return CKR_ARGUMENTS_BAD;
    /* PKCS#11 requires the serial-session flag to be set. */
    if ((flags & CKF_SERIAL_SESSION) == 0)
        return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

    p11_lock();
    rv = p11_ensure_client();
    if (rv != CKR_OK) {
        p11_unlock();
        return rv;
    }
    rv = p11_slotmap_phys(slotID, &phys);
    if (rv != CKR_OK) {
        p11_unlock();
        return rv;
    }
    /* Opening a RO session while the SO is logged in is illegal. */
    if ((flags & CKF_RW_SESSION) == 0 && g_p11.slots[phys].logged_in &&
        g_p11.slots[phys].user_type == CKU_SO) {
        p11_unlock();
        return CKR_SESSION_READ_WRITE_SO_EXISTS;
    }

    /* Reserve the cross-process per-slot session slot first. */
    shm_slot = ncmp_shm_slot(g_p11.client.shm_base, phys);
    if (!shm_slot) {
        p11_unlock();
        return CKR_TOKEN_NOT_PRESENT;
    }
    {
        int rc = ncmp_session_open(shm_slot);
        if (rc == NCMP_ERR_FULL) {
            p11_unlock();
            return CKR_SESSION_COUNT;
        }
        if (rc < 0) {
            p11_unlock();
            return CKR_DEVICE_ERROR;
        }
    }

    s = p11_session_alloc();
    if (!s) {
        ncmp_session_close(shm_slot);
        p11_unlock();
        return CKR_SESSION_COUNT;
    }
    s->slot = slotID;
    s->flags = flags;
    s->app = pApplication;
    s->notify = Notify;
    s->state = p11_session_state(s);
    *phSession = s->handle;
    p11_unlock();
    return CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
    p11_session_t *s;
    uint32_t phys = 0;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    p11_lock();
    s = p11_session_get(hSession);
    if (!s) {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (p11_slotmap_phys(s->slot, &phys) == CKR_OK) {
        NCMP_Slot *shm_slot = ncmp_shm_slot(g_p11.client.shm_base, phys);
        if (shm_slot)
            ncmp_session_close(shm_slot);
    }
    p11_session_free(s);
    p11_unlock();
    return CKR_OK;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
    uint32_t phys = 0;
    CK_RV rv;
    int i;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    p11_lock();
    rv = p11_slotmap_phys(slotID, &phys);
    if (rv != CKR_OK && rv != CKR_TOKEN_NOT_PRESENT) {
        p11_unlock();
        return rv;
    }
    for (i = 0; i < P11_MAX_SESSIONS; ++i) {
        p11_session_t *s = &g_p11.sessions[i];

        if (s->in_use && s->slot == slotID) {
            NCMP_Slot *shm_slot = ncmp_shm_slot(g_p11.client.shm_base, phys);
            if (shm_slot)
                ncmp_session_close(shm_slot);
            p11_session_free(s);
        }
    }
    p11_unlock();
    return CKR_OK;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    p11_session_t *s;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!pInfo)
        return CKR_ARGUMENTS_BAD;

    p11_lock();
    s = p11_session_get(hSession);
    if (!s) {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    memset(pInfo, 0, sizeof(*pInfo));
    pInfo->slotID = s->slot;
    pInfo->state = p11_session_state(s);
    pInfo->flags = s->flags;
    pInfo->ulDeviceError = 0;
    p11_unlock();
    return CKR_OK;
}

CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession,
                          CK_BYTE_PTR pOperationState,
                          CK_ULONG_PTR pulOperationStateLen)
{
    (void)pOperationState;
    (void)pulOperationStateLen;
    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!p11_session_get(hSession))
        return CKR_SESSION_HANDLE_INVALID;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession,
                          CK_BYTE_PTR pOperationState,
                          CK_ULONG ulOperationStateLen,
                          CK_OBJECT_HANDLE hEncryptionKey,
                          CK_OBJECT_HANDLE hAuthenticationKey)
{
    (void)pOperationState;
    (void)ulOperationStateLen;
    (void)hEncryptionKey;
    (void)hAuthenticationKey;
    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!p11_session_get(hSession))
        return CKR_SESSION_HANDLE_INVALID;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
              CK_CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    p11_session_t *s;
    uint32_t phys = 0;

    (void)pPin;
    (void)ulPinLen;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (userType != CKU_USER && userType != CKU_SO)
        return CKR_USER_TYPE_INVALID;

    p11_lock();
    s = p11_session_get(hSession);
    if (!s) {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (p11_slotmap_phys(s->slot, &phys) != CKR_OK) {
        p11_unlock();
        return CKR_TOKEN_NOT_PRESENT;
    }
    /* SO must log in via a R/W session. */
    if (userType == CKU_SO && (s->flags & CKF_RW_SESSION) == 0) {
        p11_unlock();
        return CKR_SESSION_READ_ONLY_EXISTS;
    }
    if (g_p11.slots[phys].logged_in) {
        p11_unlock();
        return CKR_USER_ALREADY_LOGGED_IN;
    }
    /* Mock token: any PIN is accepted. Hardware enforces the real PIN. */
    g_p11.slots[phys].logged_in = 1;
    g_p11.slots[phys].user_type = userType;
    if (userType == CKU_USER)
        g_p11.slots[phys].user_pin_set = 1;
    p11_unlock();
    return CKR_OK;
}

CK_RV C_LoginUser(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
                  CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
                  CK_UTF8CHAR_PTR pUsername, CK_ULONG ulUsernameLen)
{
    (void)pUsername;
    (void)ulUsernameLen;
    return C_Login(hSession, userType, (CK_CHAR_PTR)pPin, ulPinLen);
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
    p11_session_t *s;
    uint32_t phys = 0;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    p11_lock();
    s = p11_session_get(hSession);
    if (!s) {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (p11_slotmap_phys(s->slot, &phys) != CKR_OK) {
        p11_unlock();
        return CKR_TOKEN_NOT_PRESENT;
    }
    if (!g_p11.slots[phys].logged_in) {
        p11_unlock();
        return CKR_USER_NOT_LOGGED_IN;
    }
    g_p11.slots[phys].logged_in = 0;
    g_p11.slots[phys].user_type = 0;
    p11_unlock();
    return CKR_OK;
}

CK_RV C_SessionCancel(CK_SESSION_HANDLE hSession, CK_FLAGS flags)
{
    p11_session_t *s;

    (void)flags;
    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    p11_lock();
    s = p11_session_get(hSession);
    if (!s) {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    /* Cancel every in-progress operation on the session. */
    s->enc.kind = P11_OP_NONE;
    s->dec.kind = P11_OP_NONE;
    s->dig.kind = P11_OP_NONE;
    s->sig.kind = P11_OP_NONE;
    s->ver.kind = P11_OP_NONE;
    p11_unlock();
    return CKR_OK;
}

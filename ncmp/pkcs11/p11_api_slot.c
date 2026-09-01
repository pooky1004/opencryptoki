/*
 * Token NCMP - PKCS#11 slot and token management functions.
 */
#include "p11_provider.h"

#include <string.h>

/** Mechanisms this token advertises (forwarded to the FX3 via ncmpd). */
static const CK_MECHANISM_TYPE g_mechs[] = {
    CKM_AES_KEY_GEN, CKM_AES_ECB, CKM_AES_CBC, CKM_AES_CBC_PAD,
    CKM_AES_CTR, CKM_AES_GCM,
    CKM_DES3_KEY_GEN, CKM_GENERIC_SECRET_KEY_GEN,
    CKM_SHA_1, CKM_SHA224, CKM_SHA256, CKM_SHA384, CKM_SHA512,
    CKM_SHA_1_HMAC, CKM_SHA224_HMAC, CKM_SHA256_HMAC, CKM_SHA384_HMAC,
    CKM_SHA512_HMAC,
    CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_RSA_PKCS, CKM_RSA_PKCS_PSS,
    CKM_RSA_PKCS_OAEP,
    CKM_EC_KEY_PAIR_GEN, CKM_ECDSA, CKM_ECDSA_SHA256, CKM_ECDSA_SHA384,
    CKM_DH_PKCS_DERIVE, CKM_ECDH1_DERIVE,
};

#define P11_NMECHS ((CK_ULONG)(sizeof(g_mechs) / sizeof(g_mechs[0])))

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
                    CK_ULONG_PTR pulCount)
{
    CK_ULONG have;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!pulCount)
        return CKR_ARGUMENTS_BAD;

    p11_lock();
    (void)p11_ensure_client();       /* pick up a daemon started after init */
    have = p11_slotmap_count(tokenPresent ? 1 : 0);

    if (!pSlotList) {
        *pulCount = have;
        p11_unlock();
        return CKR_OK;
    }
    if (*pulCount < have) {
        *pulCount = have;
        p11_unlock();
        return CKR_BUFFER_TOO_SMALL;
    }
    *pulCount = p11_slotmap_list(tokenPresent ? 1 : 0, pSlotList, *pulCount);
    p11_unlock();
    return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    uint32_t phys = 0;
    CK_RV rv;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!pInfo)
        return CKR_ARGUMENTS_BAD;

    p11_lock();
    rv = p11_slotmap_phys(slotID, &phys);
    if (rv != CKR_OK && rv != CKR_TOKEN_NOT_PRESENT) {
        p11_unlock();
        return rv;
    }

    memset(pInfo, 0, sizeof(*pInfo));
    p11_pad(pInfo->slotDescription, sizeof(pInfo->slotDescription),
            p11_slotmap_label(slotID));
    p11_pad(pInfo->manufacturerID, sizeof(pInfo->manufacturerID),
            "Cypress EZ-USB FX3");
    pInfo->flags = CKF_HW_SLOT | CKF_REMOVABLE_DEVICE;
    if (rv == CKR_OK)
        pInfo->flags |= CKF_TOKEN_PRESENT;
    pInfo->hardwareVersion.major = 1;
    pInfo->firmwareVersion.major = 1;
    p11_unlock();
    return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    uint32_t phys = 0;
    CK_RV rv;
    int i;
    CK_ULONG open_sess = 0;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!pInfo)
        return CKR_ARGUMENTS_BAD;

    p11_lock();
    rv = p11_slotmap_phys(slotID, &phys);
    if (rv != CKR_OK) {
        p11_unlock();
        return rv; /* SLOT_ID_INVALID or TOKEN_NOT_PRESENT */
    }
    for (i = 0; i < P11_MAX_SESSIONS; ++i) {
        if (g_p11.sessions[i].in_use && g_p11.sessions[i].slot == slotID)
            open_sess++;
    }

    memset(pInfo, 0, sizeof(*pInfo));
    p11_pad(pInfo->label, sizeof(pInfo->label), p11_slotmap_label(slotID));
    p11_pad(pInfo->manufacturerID, sizeof(pInfo->manufacturerID),
            "Cypress EZ-USB FX3");
    p11_pad(pInfo->model, sizeof(pInfo->model), "NCMP");
    p11_pad(pInfo->serialNumber, sizeof(pInfo->serialNumber), "NCMP00000001");
    pInfo->flags = CKF_RNG | CKF_LOGIN_REQUIRED;
    if (g_p11.slots[phys].user_pin_set)
        pInfo->flags |= CKF_USER_PIN_INITIALIZED;
    pInfo->ulMaxSessionCount = PKCS11_MAX_SESSION_PER_SLOT;
    pInfo->ulSessionCount = open_sess;
    pInfo->ulMaxRwSessionCount = PKCS11_MAX_SESSION_PER_SLOT;
    pInfo->ulRwSessionCount = open_sess;
    pInfo->ulMaxPinLen = 64;
    pInfo->ulMinPinLen = 0;
    pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->hardwareVersion.major = 1;
    pInfo->firmwareVersion.major = 1;
    p11_unlock();
    return CKR_OK;
}

CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList,
                         CK_ULONG_PTR pulCount)
{
    uint32_t phys = 0;
    CK_RV rv;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!pulCount)
        return CKR_ARGUMENTS_BAD;

    p11_lock();
    rv = p11_slotmap_phys(slotID, &phys);
    p11_unlock();
    if (rv != CKR_OK)
        return rv;

    if (!pMechanismList) {
        *pulCount = P11_NMECHS;
        return CKR_OK;
    }
    if (*pulCount < P11_NMECHS) {
        *pulCount = P11_NMECHS;
        return CKR_BUFFER_TOO_SMALL;
    }
    memcpy(pMechanismList, g_mechs, sizeof(g_mechs));
    *pulCount = P11_NMECHS;
    return CKR_OK;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
                         CK_MECHANISM_INFO_PTR pInfo)
{
    uint32_t phys = 0;
    CK_RV rv;
    CK_ULONG i;
    int found = 0;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!pInfo)
        return CKR_ARGUMENTS_BAD;

    p11_lock();
    rv = p11_slotmap_phys(slotID, &phys);
    p11_unlock();
    if (rv != CKR_OK)
        return rv;

    for (i = 0; i < P11_NMECHS; ++i) {
        if (g_mechs[i] == type) {
            found = 1;
            break;
        }
    }
    if (!found)
        return CKR_MECHANISM_INVALID;

    memset(pInfo, 0, sizeof(*pInfo));
    pInfo->flags = CKF_HW;
    switch (type) {
    case CKM_AES_ECB: case CKM_AES_CBC: case CKM_AES_CBC_PAD:
    case CKM_AES_CTR: case CKM_AES_GCM:
        pInfo->ulMinKeySize = 16; pInfo->ulMaxKeySize = 32;
        pInfo->flags |= CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP;
        break;
    case CKM_RSA_PKCS: case CKM_RSA_PKCS_PSS: case CKM_RSA_PKCS_OAEP:
        pInfo->ulMinKeySize = 512; pInfo->ulMaxKeySize = 4096;
        pInfo->flags |= CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY |
                        CKF_WRAP | CKF_UNWRAP;
        break;
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
        pInfo->ulMinKeySize = 512; pInfo->ulMaxKeySize = 4096;
        pInfo->flags |= CKF_GENERATE_KEY_PAIR;
        break;
    case CKM_EC_KEY_PAIR_GEN:
        pInfo->ulMinKeySize = 256; pInfo->ulMaxKeySize = 521;
        pInfo->flags |= CKF_GENERATE_KEY_PAIR;
        break;
    case CKM_ECDSA: case CKM_ECDSA_SHA256: case CKM_ECDSA_SHA384:
        pInfo->ulMinKeySize = 256; pInfo->ulMaxKeySize = 521;
        pInfo->flags |= CKF_SIGN | CKF_VERIFY;
        break;
    case CKM_DH_PKCS_DERIVE: case CKM_ECDH1_DERIVE:
        pInfo->flags |= CKF_DERIVE;
        break;
    case CKM_AES_KEY_GEN: case CKM_DES3_KEY_GEN:
    case CKM_GENERIC_SECRET_KEY_GEN:
        pInfo->ulMinKeySize = 8; pInfo->ulMaxKeySize = 64;
        pInfo->flags |= CKF_GENERATE;
        break;
    default: /* digests + HMACs */
        pInfo->flags |= CKF_DIGEST | CKF_SIGN | CKF_VERIFY;
        break;
    }
    return CKR_OK;
}

CK_RV C_InitToken(CK_SLOT_ID slotID, CK_CHAR_PTR pPin, CK_ULONG ulPinLen,
                  CK_CHAR_PTR pLabel)
{
    uint32_t phys = 0;
    CK_RV rv;
    int i;

    (void)pPin;
    (void)ulPinLen;
    (void)pLabel;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    p11_lock();
    rv = p11_slotmap_phys(slotID, &phys);
    if (rv != CKR_OK) {
        p11_unlock();
        return rv;
    }
    /* A token cannot be re-initialised while sessions are open on its slot. */
    for (i = 0; i < P11_MAX_SESSIONS; ++i) {
        if (g_p11.sessions[i].in_use && g_p11.sessions[i].slot == slotID) {
            p11_unlock();
            return CKR_SESSION_EXISTS;
        }
    }
    /* Zeroization: destroy every object bound to this slot. */
    for (i = 0; i < P11_MAX_OBJECTS; ++i) {
        if (g_p11.objects[i].in_use && g_p11.objects[i].slot == slotID)
            p11_object_free(&g_p11.objects[i]);
    }
    g_p11.slots[phys].logged_in = 0;
    g_p11.slots[phys].user_type = 0;
    g_p11.slots[phys].user_pin_set = 0;
    p11_unlock();
    return CKR_OK;
}

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    p11_session_t *s;
    uint32_t phys = 0;

    (void)pPin;
    (void)ulPinLen;

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
    if (!g_p11.slots[phys].logged_in ||
        g_p11.slots[phys].user_type != CKU_SO) {
        p11_unlock();
        return CKR_USER_NOT_LOGGED_IN;
    }
    g_p11.slots[phys].user_pin_set = 1;
    p11_unlock();
    return CKR_OK;
}

CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_CHAR_PTR pOldPin,
               CK_ULONG ulOldLen, CK_CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
    p11_session_t *s;

    (void)pOldPin;
    (void)ulOldLen;
    (void)pNewPin;
    (void)ulNewLen;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    p11_lock();
    s = p11_session_get(hSession);
    p11_unlock();
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    return CKR_OK;
}

CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot,
                         CK_VOID_PTR pReserved)
{
    (void)pSlot;
    (void)pReserved;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    /* No asynchronous slot-event source; report "no event" for non-blocking
     * polls and decline the blocking form. */
    if (flags & CKF_DONT_BLOCK)
        return CKR_NO_EVENT;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

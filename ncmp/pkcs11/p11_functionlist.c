/*
 * Token NCMP - PKCS#11 function-list tables + interface discovery.
 *
 * Provides the three version-specific dispatch tables (2.40 / 3.0 / 3.2) and
 * the entry points an application uses to obtain them:
 *   - C_GetFunctionList  -> the 2.40-shaped table (every legacy caller).
 *   - C_GetInterfaceList / C_GetInterface -> named, versioned interfaces,
 *     including the vendor-defined "NCMP Vendor" table.
 */
#include "p11_provider.h"
#include "ncmp_vendor.h"

#include <string.h>

/* The 2.40 table: the classic 68-function set. */
static CK_FUNCTION_LIST g_flist_240 = {
    .version = { 3, 0 },
    .C_Initialize = C_Initialize, .C_Finalize = C_Finalize,
    .C_GetInfo = C_GetInfo, .C_GetFunctionList = C_GetFunctionList,
    .C_GetSlotList = C_GetSlotList, .C_GetSlotInfo = C_GetSlotInfo,
    .C_GetTokenInfo = C_GetTokenInfo, .C_GetMechanismList = C_GetMechanismList,
    .C_GetMechanismInfo = C_GetMechanismInfo, .C_InitToken = C_InitToken,
    .C_InitPIN = C_InitPIN, .C_SetPIN = C_SetPIN,
    .C_OpenSession = C_OpenSession, .C_CloseSession = C_CloseSession,
    .C_CloseAllSessions = C_CloseAllSessions,
    .C_GetSessionInfo = C_GetSessionInfo,
    .C_GetOperationState = C_GetOperationState,
    .C_SetOperationState = C_SetOperationState,
    .C_Login = C_Login, .C_Logout = C_Logout,
    .C_CreateObject = C_CreateObject, .C_CopyObject = C_CopyObject,
    .C_DestroyObject = C_DestroyObject, .C_GetObjectSize = C_GetObjectSize,
    .C_GetAttributeValue = C_GetAttributeValue,
    .C_SetAttributeValue = C_SetAttributeValue,
    .C_FindObjectsInit = C_FindObjectsInit, .C_FindObjects = C_FindObjects,
    .C_FindObjectsFinal = C_FindObjectsFinal,
    .C_EncryptInit = C_EncryptInit, .C_Encrypt = C_Encrypt,
    .C_EncryptUpdate = C_EncryptUpdate, .C_EncryptFinal = C_EncryptFinal,
    .C_DecryptInit = C_DecryptInit, .C_Decrypt = C_Decrypt,
    .C_DecryptUpdate = C_DecryptUpdate, .C_DecryptFinal = C_DecryptFinal,
    .C_DigestInit = C_DigestInit, .C_Digest = C_Digest,
    .C_DigestUpdate = C_DigestUpdate, .C_DigestKey = C_DigestKey,
    .C_DigestFinal = C_DigestFinal,
    .C_SignInit = C_SignInit, .C_Sign = C_Sign,
    .C_SignUpdate = C_SignUpdate, .C_SignFinal = C_SignFinal,
    .C_SignRecoverInit = C_SignRecoverInit, .C_SignRecover = C_SignRecover,
    .C_VerifyInit = C_VerifyInit, .C_Verify = C_Verify,
    .C_VerifyUpdate = C_VerifyUpdate, .C_VerifyFinal = C_VerifyFinal,
    .C_VerifyRecoverInit = C_VerifyRecoverInit,
    .C_VerifyRecover = C_VerifyRecover,
    .C_DigestEncryptUpdate = C_DigestEncryptUpdate,
    .C_DecryptDigestUpdate = C_DecryptDigestUpdate,
    .C_SignEncryptUpdate = C_SignEncryptUpdate,
    .C_DecryptVerifyUpdate = C_DecryptVerifyUpdate,
    .C_GenerateKey = C_GenerateKey, .C_GenerateKeyPair = C_GenerateKeyPair,
    .C_WrapKey = C_WrapKey, .C_UnwrapKey = C_UnwrapKey,
    .C_DeriveKey = C_DeriveKey, .C_SeedRandom = C_SeedRandom,
    .C_GenerateRandom = C_GenerateRandom,
    .C_GetFunctionStatus = C_GetFunctionStatus,
    .C_CancelFunction = C_CancelFunction,
    .C_WaitForSlotEvent = C_WaitForSlotEvent,
};

/* The 3.0 table adds interface discovery, LoginUser, SessionCancel and the
 * message-based operations. */
static CK_FUNCTION_LIST_3_0 g_flist_30 = {
    .version = { 3, 0 },
    .C_Initialize = C_Initialize, .C_Finalize = C_Finalize,
    .C_GetInfo = C_GetInfo, .C_GetFunctionList = C_GetFunctionList,
    .C_GetSlotList = C_GetSlotList, .C_GetSlotInfo = C_GetSlotInfo,
    .C_GetTokenInfo = C_GetTokenInfo, .C_GetMechanismList = C_GetMechanismList,
    .C_GetMechanismInfo = C_GetMechanismInfo, .C_InitToken = C_InitToken,
    .C_InitPIN = C_InitPIN, .C_SetPIN = C_SetPIN,
    .C_OpenSession = C_OpenSession, .C_CloseSession = C_CloseSession,
    .C_CloseAllSessions = C_CloseAllSessions,
    .C_GetSessionInfo = C_GetSessionInfo,
    .C_GetOperationState = C_GetOperationState,
    .C_SetOperationState = C_SetOperationState,
    .C_Login = C_Login, .C_Logout = C_Logout,
    .C_CreateObject = C_CreateObject, .C_CopyObject = C_CopyObject,
    .C_DestroyObject = C_DestroyObject, .C_GetObjectSize = C_GetObjectSize,
    .C_GetAttributeValue = C_GetAttributeValue,
    .C_SetAttributeValue = C_SetAttributeValue,
    .C_FindObjectsInit = C_FindObjectsInit, .C_FindObjects = C_FindObjects,
    .C_FindObjectsFinal = C_FindObjectsFinal,
    .C_EncryptInit = C_EncryptInit, .C_Encrypt = C_Encrypt,
    .C_EncryptUpdate = C_EncryptUpdate, .C_EncryptFinal = C_EncryptFinal,
    .C_DecryptInit = C_DecryptInit, .C_Decrypt = C_Decrypt,
    .C_DecryptUpdate = C_DecryptUpdate, .C_DecryptFinal = C_DecryptFinal,
    .C_DigestInit = C_DigestInit, .C_Digest = C_Digest,
    .C_DigestUpdate = C_DigestUpdate, .C_DigestKey = C_DigestKey,
    .C_DigestFinal = C_DigestFinal,
    .C_SignInit = C_SignInit, .C_Sign = C_Sign,
    .C_SignUpdate = C_SignUpdate, .C_SignFinal = C_SignFinal,
    .C_SignRecoverInit = C_SignRecoverInit, .C_SignRecover = C_SignRecover,
    .C_VerifyInit = C_VerifyInit, .C_Verify = C_Verify,
    .C_VerifyUpdate = C_VerifyUpdate, .C_VerifyFinal = C_VerifyFinal,
    .C_VerifyRecoverInit = C_VerifyRecoverInit,
    .C_VerifyRecover = C_VerifyRecover,
    .C_DigestEncryptUpdate = C_DigestEncryptUpdate,
    .C_DecryptDigestUpdate = C_DecryptDigestUpdate,
    .C_SignEncryptUpdate = C_SignEncryptUpdate,
    .C_DecryptVerifyUpdate = C_DecryptVerifyUpdate,
    .C_GenerateKey = C_GenerateKey, .C_GenerateKeyPair = C_GenerateKeyPair,
    .C_WrapKey = C_WrapKey, .C_UnwrapKey = C_UnwrapKey,
    .C_DeriveKey = C_DeriveKey, .C_SeedRandom = C_SeedRandom,
    .C_GenerateRandom = C_GenerateRandom,
    .C_GetFunctionStatus = C_GetFunctionStatus,
    .C_CancelFunction = C_CancelFunction,
    .C_WaitForSlotEvent = C_WaitForSlotEvent,
    .C_GetInterfaceList = C_GetInterfaceList,
    .C_GetInterface = C_GetInterface,
    .C_LoginUser = C_LoginUser, .C_SessionCancel = C_SessionCancel,
    .C_MessageEncryptInit = C_MessageEncryptInit,
    .C_EncryptMessage = C_EncryptMessage,
    .C_EncryptMessageBegin = C_EncryptMessageBegin,
    .C_EncryptMessageNext = C_EncryptMessageNext,
    .C_MessageEncryptFinal = C_MessageEncryptFinal,
    .C_MessageDecryptInit = C_MessageDecryptInit,
    .C_DecryptMessage = C_DecryptMessage,
    .C_DecryptMessageBegin = C_DecryptMessageBegin,
    .C_DecryptMessageNext = C_DecryptMessageNext,
    .C_MessageDecryptFinal = C_MessageDecryptFinal,
    .C_MessageSignInit = C_MessageSignInit,
    .C_SignMessage = C_SignMessage,
    .C_SignMessageBegin = C_SignMessageBegin,
    .C_SignMessageNext = C_SignMessageNext,
    .C_MessageSignFinal = C_MessageSignFinal,
    .C_MessageVerifyInit = C_MessageVerifyInit,
    .C_VerifyMessage = C_VerifyMessage,
    .C_VerifyMessageBegin = C_VerifyMessageBegin,
    .C_VerifyMessageNext = C_VerifyMessageNext,
    .C_MessageVerifyFinal = C_MessageVerifyFinal,
};

/* The 3.2 table adds encapsulation, single-pass verify, async and
 * authenticated wrap. */
static CK_FUNCTION_LIST_3_2 g_flist_32 = {
    .version = { 3, 2 },
    .C_Initialize = C_Initialize, .C_Finalize = C_Finalize,
    .C_GetInfo = C_GetInfo, .C_GetFunctionList = C_GetFunctionList,
    .C_GetSlotList = C_GetSlotList, .C_GetSlotInfo = C_GetSlotInfo,
    .C_GetTokenInfo = C_GetTokenInfo, .C_GetMechanismList = C_GetMechanismList,
    .C_GetMechanismInfo = C_GetMechanismInfo, .C_InitToken = C_InitToken,
    .C_InitPIN = C_InitPIN, .C_SetPIN = C_SetPIN,
    .C_OpenSession = C_OpenSession, .C_CloseSession = C_CloseSession,
    .C_CloseAllSessions = C_CloseAllSessions,
    .C_GetSessionInfo = C_GetSessionInfo,
    .C_GetOperationState = C_GetOperationState,
    .C_SetOperationState = C_SetOperationState,
    .C_Login = C_Login, .C_Logout = C_Logout,
    .C_CreateObject = C_CreateObject, .C_CopyObject = C_CopyObject,
    .C_DestroyObject = C_DestroyObject, .C_GetObjectSize = C_GetObjectSize,
    .C_GetAttributeValue = C_GetAttributeValue,
    .C_SetAttributeValue = C_SetAttributeValue,
    .C_FindObjectsInit = C_FindObjectsInit, .C_FindObjects = C_FindObjects,
    .C_FindObjectsFinal = C_FindObjectsFinal,
    .C_EncryptInit = C_EncryptInit, .C_Encrypt = C_Encrypt,
    .C_EncryptUpdate = C_EncryptUpdate, .C_EncryptFinal = C_EncryptFinal,
    .C_DecryptInit = C_DecryptInit, .C_Decrypt = C_Decrypt,
    .C_DecryptUpdate = C_DecryptUpdate, .C_DecryptFinal = C_DecryptFinal,
    .C_DigestInit = C_DigestInit, .C_Digest = C_Digest,
    .C_DigestUpdate = C_DigestUpdate, .C_DigestKey = C_DigestKey,
    .C_DigestFinal = C_DigestFinal,
    .C_SignInit = C_SignInit, .C_Sign = C_Sign,
    .C_SignUpdate = C_SignUpdate, .C_SignFinal = C_SignFinal,
    .C_SignRecoverInit = C_SignRecoverInit, .C_SignRecover = C_SignRecover,
    .C_VerifyInit = C_VerifyInit, .C_Verify = C_Verify,
    .C_VerifyUpdate = C_VerifyUpdate, .C_VerifyFinal = C_VerifyFinal,
    .C_VerifyRecoverInit = C_VerifyRecoverInit,
    .C_VerifyRecover = C_VerifyRecover,
    .C_DigestEncryptUpdate = C_DigestEncryptUpdate,
    .C_DecryptDigestUpdate = C_DecryptDigestUpdate,
    .C_SignEncryptUpdate = C_SignEncryptUpdate,
    .C_DecryptVerifyUpdate = C_DecryptVerifyUpdate,
    .C_GenerateKey = C_GenerateKey, .C_GenerateKeyPair = C_GenerateKeyPair,
    .C_WrapKey = C_WrapKey, .C_UnwrapKey = C_UnwrapKey,
    .C_DeriveKey = C_DeriveKey, .C_SeedRandom = C_SeedRandom,
    .C_GenerateRandom = C_GenerateRandom,
    .C_GetFunctionStatus = C_GetFunctionStatus,
    .C_CancelFunction = C_CancelFunction,
    .C_WaitForSlotEvent = C_WaitForSlotEvent,
    .C_GetInterfaceList = C_GetInterfaceList,
    .C_GetInterface = C_GetInterface,
    .C_LoginUser = C_LoginUser, .C_SessionCancel = C_SessionCancel,
    .C_MessageEncryptInit = C_MessageEncryptInit,
    .C_EncryptMessage = C_EncryptMessage,
    .C_EncryptMessageBegin = C_EncryptMessageBegin,
    .C_EncryptMessageNext = C_EncryptMessageNext,
    .C_MessageEncryptFinal = C_MessageEncryptFinal,
    .C_MessageDecryptInit = C_MessageDecryptInit,
    .C_DecryptMessage = C_DecryptMessage,
    .C_DecryptMessageBegin = C_DecryptMessageBegin,
    .C_DecryptMessageNext = C_DecryptMessageNext,
    .C_MessageDecryptFinal = C_MessageDecryptFinal,
    .C_MessageSignInit = C_MessageSignInit,
    .C_SignMessage = C_SignMessage,
    .C_SignMessageBegin = C_SignMessageBegin,
    .C_SignMessageNext = C_SignMessageNext,
    .C_MessageSignFinal = C_MessageSignFinal,
    .C_MessageVerifyInit = C_MessageVerifyInit,
    .C_VerifyMessage = C_VerifyMessage,
    .C_VerifyMessageBegin = C_VerifyMessageBegin,
    .C_VerifyMessageNext = C_VerifyMessageNext,
    .C_MessageVerifyFinal = C_MessageVerifyFinal,
    .C_EncapsulateKey = C_EncapsulateKey,
    .C_DecapsulateKey = C_DecapsulateKey,
    .C_VerifySignatureInit = C_VerifySignatureInit,
    .C_VerifySignature = C_VerifySignature,
    .C_VerifySignatureUpdate = C_VerifySignatureUpdate,
    .C_VerifySignatureFinal = C_VerifySignatureFinal,
    .C_GetSessionValidationFlags = C_GetSessionValidationFlags,
    .C_AsyncComplete = C_AsyncComplete,
    .C_AsyncGetID = C_AsyncGetID,
    .C_AsyncJoin = C_AsyncJoin,
    .C_WrapKeyAuthenticated = C_WrapKeyAuthenticated,
    .C_UnwrapKeyAuthenticated = C_UnwrapKeyAuthenticated,
};

CK_FUNCTION_LIST *p11_function_list_240(void) { return &g_flist_240; }
CK_FUNCTION_LIST_3_0 *p11_function_list_30(void) { return &g_flist_30; }
CK_FUNCTION_LIST_3_2 *p11_function_list_32(void) { return &g_flist_32; }

/* The interfaces this provider publishes, newest first. */
static CK_INTERFACE g_interfaces[] = {
    { (CK_UTF8CHAR_PTR) "PKCS 11", &g_flist_32, 0 },
    { (CK_UTF8CHAR_PTR) "PKCS 11", &g_flist_30, 0 },
    { (CK_UTF8CHAR_PTR) "PKCS 11", &g_flist_240, 0 },
    { (CK_UTF8CHAR_PTR) NCMP_VENDOR_INTERFACE_NAME, &ncmp_vendor_functions, 0 },
};

#define P11_NIFACES ((CK_ULONG)(sizeof(g_interfaces) / sizeof(g_interfaces[0])))

/** Interface version for entry @p i (major.minor from its function list). */
static CK_VERSION iface_version(const CK_INTERFACE *i)
{
    /* Every published function list begins with a CK_VERSION field. */
    return *(CK_VERSION *)i->pFunctionList;
}

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    if (!ppFunctionList)
        return CKR_ARGUMENTS_BAD;
    *ppFunctionList = &g_flist_240;
    return CKR_OK;
}

CK_RV C_GetInterfaceList(CK_INTERFACE_PTR pInterfaceList, CK_ULONG_PTR pulCount)
{
    if (!pulCount)
        return CKR_ARGUMENTS_BAD;
    if (!pInterfaceList) {
        *pulCount = P11_NIFACES;
        return CKR_OK;
    }
    if (*pulCount < P11_NIFACES) {
        *pulCount = P11_NIFACES;
        return CKR_BUFFER_TOO_SMALL;
    }
    memcpy(pInterfaceList, g_interfaces, sizeof(g_interfaces));
    *pulCount = P11_NIFACES;
    return CKR_OK;
}

CK_RV C_GetInterface(CK_UTF8CHAR_PTR pInterfaceName, CK_VERSION_PTR pVersion,
                     CK_INTERFACE_PTR_PTR ppInterface, CK_FLAGS flags)
{
    CK_ULONG i;

    if (!ppInterface)
        return CKR_ARGUMENTS_BAD;

    for (i = 0; i < P11_NIFACES; ++i) {
        CK_INTERFACE *cur = &g_interfaces[i];

        if (pInterfaceName &&
            strcmp((const char *)pInterfaceName,
                   (const char *)cur->pInterfaceName) != 0)
            continue;
        if (pVersion) {
            CK_VERSION v = iface_version(cur);

            if (v.major != pVersion->major || v.minor != pVersion->minor)
                continue;
        }
        /* Requested interface flags must be a subset of what we offer (0). */
        if ((flags & cur->flags) != flags)
            continue;
        *ppInterface = cur;
        return CKR_OK;
    }
    return CKR_ARGUMENTS_BAD;
}

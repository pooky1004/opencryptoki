/*
 * Token NCMP - Standalone PKCS#11 provider facade (mode 2).
 *
 * libpkcs11_ncmp.so can be used two ways:
 *   mode 1: App -> libopencryptoki.so (C_*) -> dlopen -> this .so's SC_* and
 *           ST_Initialize (opencryptoki STDLL path; new_host.c).
 *   mode 2: App -> dlopen(libpkcs11_ncmp.so) -> dlsym("C_GetFunctionList"/
 *           "C_GetInterface"/C_*) -> this facade.
 *
 * This file implements mode 2: a self-contained PKCS#11 provider that does NOT
 * use the opencryptoki common layer. It talks straight to ncmpd through the
 * pure-buffer ncmp adapters (ncmp_crypto / ncmp_admin) + ncmp_client, and keeps
 * its own slot/session/object state. The SC_* and ST_Initialize symbols (mode 1)
 * are untouched and still exported, so both modes coexist in one .so.
 *
 * Exposes PKCS#11 2.40 (C_GetFunctionList) and 3.0/3.2 (C_GetInterfaceList /
 * C_GetInterface). Only the advertised NCMP mechanisms are wired; everything
 * else returns CKR_FUNCTION_NOT_SUPPORTED. See docs/dual-mode-provider.md.
 *
 * NOTE: builds as part of libpkcs11_ncmp.so (needs a full opencryptoki build to
 * link; the ncmp adapters + ncmp_client provide the transport). Not runnable in
 * a bare checkout.
 *
 * Style: Google C Style.
 */
#include <pkcs11types.h>

#include "ncmp/ncmp_client.h"
#include "ncmp/ncmp_crypto.h"
#include "ncmp/ncmp_admin.h"
#include "ncmp/ncmp_cmd.h"
#include "ncmp/ncmp_limits.h"
#include "ncmp/ncmp_errno.h"

#include <pthread.h>
#include <string.h>
#include <stdint.h>

/* -------------------------------------------------------------------------- */
/* Local state (facade owns slots/sessions/objects)                           */
/* -------------------------------------------------------------------------- */

#define P11_MAX_SESSIONS 64
#define P11_MAX_OBJECTS  128
#define P11_MAX_ATTRS    24
#define P11_MAX_ATTR_VAL 1024

typedef struct p11_attr {
    CK_ATTRIBUTE_TYPE type;
    CK_ULONG          len;
    CK_BYTE           val[P11_MAX_ATTR_VAL];
} p11_attr_t;

typedef struct p11_object {
    int        in_use;
    CK_ULONG   natt;
    p11_attr_t att[P11_MAX_ATTRS];
} p11_object_t;

/* Active symmetric op state (one-shot AES-GCM / AES-CTR). */
typedef struct p11_cipher {
    int      active;
    int      encrypt;
    CK_MECHANISM_TYPE mech;
    uint8_t  key[32];
    uint32_t key_len;
    uint8_t  iv[16];
    uint32_t iv_len;
    uint8_t  aad[256];
    uint32_t aad_len;
    uint32_t tag_len;
} p11_cipher_t;

typedef struct p11_session {
    int          in_use;
    uint32_t     slot;
    uint32_t     dev_sid;   /* token-assigned session handle (OPEN_SESSION) */
    CK_FLAGS     flags;
    /* digest */
    int          dig_active;
    uint32_t     dig_ctx;
    uint32_t     dig_mech;
    /* symmetric */
    p11_cipher_t enc;
    p11_cipher_t dec;
    /* find */
    int          find_active;
    CK_ULONG     find_cursor;
} p11_session_t;

/* Forward declarations for functions referenced before their definitions. */
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
CK_RV C_GetInterfaceList(CK_INTERFACE_PTR pInterfaceList, CK_ULONG_PTR pulCount);
CK_RV C_GetInterface(CK_UTF8CHAR_PTR pInterfaceName, CK_VERSION_PTR pVersion,
                     CK_INTERFACE_PTR_PTR ppInterface, CK_FLAGS flags);

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static int             g_initialized;
static ncmp_client_t  g_client;
static uint32_t       g_slot;                 /* first online slot */
static p11_session_t  g_sessions[P11_MAX_SESSIONS];
static p11_object_t   g_objects[P11_MAX_OBJECTS];

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

static p11_session_t *sess_get(CK_SESSION_HANDLE h)
{
    if (h == CK_INVALID_HANDLE || h > P11_MAX_SESSIONS)
        return NULL;
    p11_session_t *s = &g_sessions[h - 1];
    if (!s->in_use)
        return NULL;
    /* Every session-scoped command that resolves its handle here then issues
     * wire commands carrying this token session id in the frame header. */
    g_client.active_session_id = s->dev_sid;
    return s;
}

static p11_object_t *obj_get(CK_OBJECT_HANDLE h)
{
    if (h == CK_INVALID_HANDLE || h > P11_MAX_OBJECTS)
        return NULL;
    p11_object_t *o = &g_objects[h - 1];
    return o->in_use ? o : NULL;
}

static const p11_attr_t *obj_find_attr(const p11_object_t *o,
                                       CK_ATTRIBUTE_TYPE t)
{
    for (CK_ULONG i = 0; i < o->natt; ++i)
        if (o->att[i].type == t)
            return &o->att[i];
    return NULL;
}

/* Map a PKCS#11 digest mechanism to the NCMP wire mech, or 0 if unsupported. */
static uint32_t dig_mech(CK_MECHANISM_TYPE m)
{
    switch (m) {
    case CKM_SHA256:       return NCMP_MECH_SHA256;
    case CKM_SHA512:       return NCMP_MECH_SHA512;
    case CKM_SHA3_224:     return NCMP_MECH_SHA3_224;
    case CKM_SHA3_256:     return NCMP_MECH_SHA3_256;
    case CKM_SHA3_384:     return NCMP_MECH_SHA3_384;
    case CKM_SHA3_512:     return NCMP_MECH_SHA3_512;
    default:               return 0;
    }
}

/* -------------------------------------------------------------------------- */
/* General                                                                    */
/* -------------------------------------------------------------------------- */

CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
{
    (void)pInitArgs;
    CK_RV rv = CKR_OK;

    pthread_mutex_lock(&g_lock);
    if (g_initialized) {
        pthread_mutex_unlock(&g_lock);
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }
    memset(g_sessions, 0, sizeof(g_sessions));
    memset(g_objects, 0, sizeof(g_objects));
    if (ncmp_client_init(&g_client, NULL) != NCMP_OK) {
        rv = CKR_TOKEN_NOT_PRESENT;        /* ncmpd not reachable */
        goto out;
    }
    /* Pick the lowest online slot the daemon reported. */
    g_slot = 0;
    for (uint32_t s = 0; s < NCMP_SLOT_SCAN_MAX; ++s) {
        if (NCMP_SLOT_IN_MASK(g_client.slot_mask, s)) { g_slot = s; break; }
    }
    g_initialized = 1;
out:
    pthread_mutex_unlock(&g_lock);
    return rv;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
    (void)pReserved;
    pthread_mutex_lock(&g_lock);
    if (g_initialized) {
        ncmp_client_fini(&g_client);
        g_initialized = 0;
    }
    pthread_mutex_unlock(&g_lock);
    return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
    if (!pInfo)
        return CKR_ARGUMENTS_BAD;
    memset(pInfo, 0, sizeof(*pInfo));
    pInfo->cryptokiVersion.major = 3;
    pInfo->cryptokiVersion.minor = 2;
    memcpy(pInfo->manufacturerID, "DYST            ", 16);
    memset(pInfo->manufacturerID + 4, ' ', 28);
    memcpy(pInfo->manufacturerID, "DYST", 4);
    pInfo->libraryVersion.major = 1;
    pInfo->libraryVersion.minor = 0;
    memset(pInfo->libraryDescription, ' ', sizeof(pInfo->libraryDescription));
    memcpy(pInfo->libraryDescription, "NCMP standalone provider", 24);
    return CKR_OK;
}

/* -------------------------------------------------------------------------- */
/* Slot / token                                                               */
/* -------------------------------------------------------------------------- */

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
                    CK_ULONG_PTR pulCount)
{
    (void)tokenPresent;
    CK_ULONG n = 0;
    CK_SLOT_ID ids[PKCS11_MAX_SLOT_COUNT];

    if (!g_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!pulCount)
        return CKR_ARGUMENTS_BAD;
    for (uint32_t s = 0; s < NCMP_SLOT_SCAN_MAX; ++s)
        if (NCMP_SLOT_IN_MASK(g_client.slot_mask, s))
            ids[n++] = s;
    if (!pSlotList) {
        *pulCount = n;
        return CKR_OK;
    }
    if (*pulCount < n) {
        *pulCount = n;
        return CKR_BUFFER_TOO_SMALL;
    }
    for (CK_ULONG i = 0; i < n; ++i)
        pSlotList[i] = ids[i];
    *pulCount = n;
    return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    if (!g_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!pInfo)
        return CKR_ARGUMENTS_BAD;
    if (slotID >= PKCS11_MAX_SLOT_COUNT ||
        !NCMP_SLOT_IN_MASK(g_client.slot_mask, slotID))
        return CKR_SLOT_ID_INVALID;
    memset(pInfo, 0, sizeof(*pInfo));
    memset(pInfo->slotDescription, ' ', sizeof(pInfo->slotDescription));
    memcpy(pInfo->slotDescription, "NCMP slot", 9);
    memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
    memcpy(pInfo->manufacturerID, "DYST", 4);
    pInfo->flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;
    return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    NCMP_TokenIdentity id;

    if (!g_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!pInfo)
        return CKR_ARGUMENTS_BAD;
    if (slotID >= PKCS11_MAX_SLOT_COUNT ||
        !NCMP_SLOT_IN_MASK(g_client.slot_mask, slotID))
        return CKR_SLOT_ID_INVALID;

    memset(pInfo, 0, sizeof(*pInfo));
    memset(pInfo->label, ' ', sizeof(pInfo->label));
    memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
    memset(pInfo->model, ' ', sizeof(pInfo->model));
    memset(pInfo->serialNumber, ' ', sizeof(pInfo->serialNumber));
    memset(&id, 0, sizeof(id));
    g_client.active_session_id = 0;   /* sessionless query */
    if (ncmp_admin_token_info(&g_client, slotID, &id) == CKR_OK) {
        memcpy(pInfo->label, id.label,
               strnlen(id.label, sizeof(pInfo->label)));
        memcpy(pInfo->manufacturerID, id.manufacturer,
               strnlen(id.manufacturer, sizeof(pInfo->manufacturerID)));
        memcpy(pInfo->model, id.model,
               strnlen(id.model, sizeof(pInfo->model)));
        memcpy(pInfo->serialNumber, id.serial,
               strnlen(id.serial, sizeof(pInfo->serialNumber)));
    }
    pInfo->ulMaxSessionCount = PKCS11_MAX_SESSION_PER_SLOT;
    pInfo->ulMaxRwSessionCount = PKCS11_MAX_SESSION_PER_SLOT;
    pInfo->ulMinPinLen = 4;
    pInfo->ulMaxPinLen = 32;
    pInfo->flags = CKF_TOKEN_INITIALIZED | CKF_RNG | CKF_LOGIN_REQUIRED;
    pInfo->hardwareVersion.major = 1;
    pInfo->firmwareVersion.major = 1;
    return CKR_OK;
}

/* Advertised mechanism surface (matches ncmp_mech_list). */
static const CK_MECHANISM_TYPE g_mechs[] = {
    CKM_AES_KEY_GEN, CKM_AES_GCM, CKM_AES_CTR,
    CKM_SHA256, CKM_SHA512,
    CKM_SHA3_224, CKM_SHA3_256, CKM_SHA3_384, CKM_SHA3_512,
};

CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pList,
                         CK_ULONG_PTR pulCount)
{
    const CK_ULONG n = sizeof(g_mechs) / sizeof(g_mechs[0]);
    (void)slotID;
    if (!pulCount)
        return CKR_ARGUMENTS_BAD;
    if (!pList) {
        *pulCount = n;
        return CKR_OK;
    }
    if (*pulCount < n) {
        *pulCount = n;
        return CKR_BUFFER_TOO_SMALL;
    }
    memcpy(pList, g_mechs, sizeof(g_mechs));
    *pulCount = n;
    return CKR_OK;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
                         CK_MECHANISM_INFO_PTR pInfo)
{
    (void)slotID;
    if (!pInfo)
        return CKR_ARGUMENTS_BAD;
    memset(pInfo, 0, sizeof(*pInfo));
    switch (type) {
    case CKM_AES_KEY_GEN:
        pInfo->ulMinKeySize = 16; pInfo->ulMaxKeySize = 32;
        pInfo->flags = CKF_GENERATE; return CKR_OK;
    case CKM_AES_GCM:
    case CKM_AES_CTR:
        pInfo->ulMinKeySize = 16; pInfo->ulMaxKeySize = 32;
        pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT; return CKR_OK;
    case CKM_SHA256: case CKM_SHA512:
    case CKM_SHA3_224: case CKM_SHA3_256: case CKM_SHA3_384: case CKM_SHA3_512:
        pInfo->flags = CKF_DIGEST; return CKR_OK;
    default:
        return CKR_MECHANISM_INVALID;
    }
}

/* -------------------------------------------------------------------------- */
/* Sessions / login                                                           */
/* -------------------------------------------------------------------------- */

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApp,
                    CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
    (void)pApp; (void)Notify;
    if (!g_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!phSession)
        return CKR_ARGUMENTS_BAD;
    if (!(flags & CKF_SERIAL_SESSION))
        return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    if (slotID >= PKCS11_MAX_SLOT_COUNT ||
        !NCMP_SLOT_IN_MASK(g_client.slot_mask, slotID))
        return CKR_SLOT_ID_INVALID;

    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < P11_MAX_SESSIONS; ++i) {
        if (!g_sessions[i].in_use) {
            uint32_t handle = 0;
            unsigned long ack;

            /* Open a session on the token: zero wire-header session_id + a
             * single flags parameter; the token returns the handle. */
            g_client.active_session_id = 0;
            ack = ncmp_admin_open_session(&g_client, (uint32_t)slotID,
                                          (uint32_t)flags, &handle);
            if (ack != CKR_OK) {
                pthread_mutex_unlock(&g_lock);
                return (CK_RV)ack;
            }
            memset(&g_sessions[i], 0, sizeof(g_sessions[i]));
            g_sessions[i].in_use = 1;
            g_sessions[i].slot = (uint32_t)slotID;
            g_sessions[i].flags = flags;
            g_sessions[i].dev_sid = handle;
            *phSession = (CK_SESSION_HANDLE)(i + 1);
            pthread_mutex_unlock(&g_lock);
            return CKR_OK;
        }
    }
    pthread_mutex_unlock(&g_lock);
    return CKR_SESSION_COUNT;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
    pthread_mutex_lock(&g_lock);
    p11_session_t *s = sess_get(hSession);
    if (!s) {
        pthread_mutex_unlock(&g_lock);
        return CKR_SESSION_HANDLE_INVALID;
    }
    /* Close it on the token: the handle rides in the wire header
     * (active_session_id, set by sess_get above); CLOSE takes no parameters.
     * The local slot is freed regardless so the handle is never reused. */
    (void)ncmp_admin_close_session(&g_client, s->slot);
    memset(s, 0, sizeof(*s));
    g_client.active_session_id = 0;
    pthread_mutex_unlock(&g_lock);
    return CKR_OK;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < P11_MAX_SESSIONS; ++i)
        if (g_sessions[i].in_use && g_sessions[i].slot == slotID)
            memset(&g_sessions[i], 0, sizeof(g_sessions[i]));
    pthread_mutex_unlock(&g_lock);
    return CKR_OK;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    p11_session_t *s = sess_get(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    if (!pInfo)
        return CKR_ARGUMENTS_BAD;
    memset(pInfo, 0, sizeof(*pInfo));
    pInfo->slotID = s->slot;
    pInfo->state = (s->flags & CKF_RW_SESSION) ? CKS_RW_PUBLIC_SESSION
                                               : CKS_RO_PUBLIC_SESSION;
    pInfo->flags = s->flags;
    return CKR_OK;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
              CK_CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    p11_session_t *s = sess_get(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    return ncmp_admin_login(&g_client, s->slot, (uint32_t)userType, 0,
                            (const uint8_t *)pPin, (uint32_t)ulPinLen);
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
    p11_session_t *s = sess_get(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    return ncmp_admin_logout(&g_client, s->slot);
}

/* -------------------------------------------------------------------------- */
/* Objects (local store; key material in CKA_VALUE)                           */
/* -------------------------------------------------------------------------- */

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
                     CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
    p11_session_t *s = sess_get(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    if ((!pTemplate && ulCount) || !phObject)
        return CKR_ARGUMENTS_BAD;
    if (ulCount > P11_MAX_ATTRS)
        return CKR_TEMPLATE_INCONSISTENT;

    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < P11_MAX_OBJECTS; ++i) {
        p11_object_t *o = &g_objects[i];
        if (o->in_use)
            continue;
        memset(o, 0, sizeof(*o));
        o->in_use = 1;
        o->natt = 0;
        for (CK_ULONG k = 0; k < ulCount; ++k) {
            CK_ULONG len = pTemplate[k].ulValueLen;
            if (len > P11_MAX_ATTR_VAL) {
                memset(o, 0, sizeof(*o));
                pthread_mutex_unlock(&g_lock);
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            o->att[o->natt].type = pTemplate[k].type;
            o->att[o->natt].len = len;
            if (len && pTemplate[k].pValue)
                memcpy(o->att[o->natt].val, pTemplate[k].pValue, len);
            o->natt++;
        }
        *phObject = (CK_OBJECT_HANDLE)(i + 1);
        pthread_mutex_unlock(&g_lock);
        return CKR_OK;
    }
    pthread_mutex_unlock(&g_lock);
    return CKR_HOST_MEMORY;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
    if (!sess_get(hSession))
        return CKR_SESSION_HANDLE_INVALID;
    pthread_mutex_lock(&g_lock);
    p11_object_t *o = obj_get(hObject);
    if (!o) {
        pthread_mutex_unlock(&g_lock);
        return CKR_OBJECT_HANDLE_INVALID;
    }
    memset(o, 0, sizeof(*o));
    pthread_mutex_unlock(&g_lock);
    return CKR_OK;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    if (!sess_get(hSession))
        return CKR_SESSION_HANDLE_INVALID;
    p11_object_t *o = obj_get(hObject);
    if (!o)
        return CKR_OBJECT_HANDLE_INVALID;
    CK_RV rv = CKR_OK;
    for (CK_ULONG i = 0; i < ulCount; ++i) {
        const p11_attr_t *a = obj_find_attr(o, pTemplate[i].type);
        if (!a) {
            pTemplate[i].ulValueLen = (CK_ULONG)-1;
            rv = CKR_ATTRIBUTE_TYPE_INVALID;
            continue;
        }
        if (!pTemplate[i].pValue) {
            pTemplate[i].ulValueLen = a->len;
        } else if (pTemplate[i].ulValueLen < a->len) {
            pTemplate[i].ulValueLen = (CK_ULONG)-1;
            rv = CKR_BUFFER_TOO_SMALL;
        } else {
            memcpy(pTemplate[i].pValue, a->val, a->len);
            pTemplate[i].ulValueLen = a->len;
        }
    }
    return rv;
}

/* Attribute match for find. */
static int obj_matches(const p11_object_t *o, CK_ATTRIBUTE_PTR t, CK_ULONG n)
{
    for (CK_ULONG i = 0; i < n; ++i) {
        const p11_attr_t *a = obj_find_attr(o, t[i].type);
        if (!a || a->len != t[i].ulValueLen)
            return 0;
        if (t[i].ulValueLen && memcmp(a->val, t[i].pValue, a->len) != 0)
            return 0;
    }
    return 1;
}

static CK_ATTRIBUTE g_find_tmpl[P11_MAX_ATTRS];
static CK_ULONG     g_find_n;

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
                        CK_ULONG ulCount)
{
    p11_session_t *s = sess_get(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    if (s->find_active)
        return CKR_OPERATION_ACTIVE;
    if (ulCount > P11_MAX_ATTRS)
        return CKR_ARGUMENTS_BAD;
    /* Snapshot the (small) match template; single find at a time (facade). */
    g_find_n = ulCount;
    for (CK_ULONG i = 0; i < ulCount; ++i)
        g_find_tmpl[i] = pTemplate[i];
    s->find_active = 1;
    s->find_cursor = 0;
    return CKR_OK;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject,
                    CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
    p11_session_t *s = sess_get(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    if (!s->find_active)
        return CKR_OPERATION_NOT_INITIALIZED;
    if (!phObject || !pulObjectCount)
        return CKR_ARGUMENTS_BAD;
    CK_ULONG found = 0;
    while (s->find_cursor < P11_MAX_OBJECTS && found < ulMaxObjectCount) {
        p11_object_t *o = &g_objects[s->find_cursor++];
        if (o->in_use && obj_matches(o, g_find_tmpl, g_find_n))
            phObject[found++] = (CK_OBJECT_HANDLE)((o - g_objects) + 1);
    }
    *pulObjectCount = found;
    return CKR_OK;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
    p11_session_t *s = sess_get(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    s->find_active = 0;
    return CKR_OK;
}

/* -------------------------------------------------------------------------- */
/* Random                                                                     */
/* -------------------------------------------------------------------------- */

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                       CK_ULONG ulLen)
{
    p11_session_t *s = sess_get(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    if (!pData && ulLen)
        return CKR_ARGUMENTS_BAD;
    return ncmp_crypto_rng(&g_client, s->slot, pData, (uint32_t)ulLen);
}

/* -------------------------------------------------------------------------- */
/* Digest                                                                     */
/* -------------------------------------------------------------------------- */

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
    p11_session_t *s = sess_get(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    if (!pMechanism)
        return CKR_ARGUMENTS_BAD;
    uint32_t m = dig_mech(pMechanism->mechanism);
    if (!m)
        return CKR_MECHANISM_INVALID;
    CK_RV rv = ncmp_crypto_digest_init(&g_client, s->slot, m, &s->dig_ctx);
    if (rv == CKR_OK) {
        s->dig_active = 1;
        s->dig_mech = m;
    }
    return rv;
}

CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
               CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
    p11_session_t *s = sess_get(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    if (!s->dig_active)
        return CKR_OPERATION_NOT_INITIALIZED;
    if (!pulDigestLen)
        return CKR_ARGUMENTS_BAD;
    uint32_t hsize = ncmp_digest_size(s->dig_mech);
    if (!pDigest) {
        *pulDigestLen = hsize;
        return CKR_OK;
    }
    if (*pulDigestLen < hsize) {
        *pulDigestLen = hsize;
        return CKR_BUFFER_TOO_SMALL;
    }
    CK_RV rv = ncmp_crypto_digest(&g_client, s->slot, s->dig_mech,
                                  pData, (uint32_t)ulDataLen,
                                  pDigest, *pulDigestLen, (uint32_t *)pulDigestLen);
    s->dig_active = 0;
    (void)ncmp_crypto_ctx_free(&g_client, s->slot, s->dig_ctx,
                               NCMP_CTX_KIND_DIGEST);
    return rv;
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                     CK_ULONG ulPartLen)
{
    p11_session_t *s = sess_get(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    if (!s->dig_active)
        return CKR_OPERATION_NOT_INITIALIZED;
    return ncmp_crypto_digest_update(&g_client, s->slot, s->dig_ctx,
                                     pPart, (uint32_t)ulPartLen);
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest,
                    CK_ULONG_PTR pulDigestLen)
{
    p11_session_t *s = sess_get(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    if (!s->dig_active)
        return CKR_OPERATION_NOT_INITIALIZED;
    if (!pulDigestLen)
        return CKR_ARGUMENTS_BAD;
    uint32_t hsize = ncmp_digest_size(s->dig_mech);
    if (!pDigest) {
        *pulDigestLen = hsize;
        return CKR_OK;
    }
    CK_RV rv = ncmp_crypto_digest_final(&g_client, s->slot, s->dig_ctx,
                                        pDigest, *pulDigestLen,
                                        (uint32_t *)pulDigestLen);
    s->dig_active = 0;
    return rv;
}

/* -------------------------------------------------------------------------- */
/* Encrypt / Decrypt (AES-GCM / AES-CTR, one-shot)                            */
/* -------------------------------------------------------------------------- */

static CK_RV cipher_init(p11_session_t *s, p11_cipher_t *c, int encrypt,
                         CK_MECHANISM_PTR m, CK_OBJECT_HANDLE hKey)
{
    p11_object_t *o = obj_get(hKey);
    const p11_attr_t *kv;

    (void)s;
    if (!m)
        return CKR_ARGUMENTS_BAD;
    if (!o)
        return CKR_KEY_HANDLE_INVALID;
    kv = obj_find_attr(o, CKA_VALUE);
    if (!kv || (kv->len != 16 && kv->len != 24 && kv->len != 32))
        return CKR_KEY_TYPE_INCONSISTENT;

    memset(c, 0, sizeof(*c));
    c->encrypt = encrypt;
    c->mech = m->mechanism;
    memcpy(c->key, kv->val, kv->len);
    c->key_len = (uint32_t)kv->len;

    if (m->mechanism == CKM_AES_GCM) {
        CK_GCM_PARAMS *p = (CK_GCM_PARAMS *)m->pParameter;
        if (!p || m->ulParameterLen < sizeof(*p) || !p->pIv ||
            p->ulIvLen == 0 || p->ulIvLen > sizeof(c->iv))
            return CKR_MECHANISM_PARAM_INVALID;
        memcpy(c->iv, p->pIv, p->ulIvLen);
        c->iv_len = (uint32_t)p->ulIvLen;
        c->tag_len = (uint32_t)(p->ulTagBits / 8);
        if (c->tag_len == 0 || c->tag_len > 16)
            c->tag_len = 16;
        c->aad_len = (uint32_t)((p->ulAADLen > sizeof(c->aad))
                                ? sizeof(c->aad) : p->ulAADLen);
        if (c->aad_len && p->pAAD)
            memcpy(c->aad, p->pAAD, c->aad_len);
    } else if (m->mechanism == CKM_AES_CTR) {
        CK_AES_CTR_PARAMS *p = (CK_AES_CTR_PARAMS *)m->pParameter;
        if (!p || m->ulParameterLen < sizeof(*p))
            return CKR_MECHANISM_PARAM_INVALID;
        memcpy(c->iv, p->cb, 16);
        c->iv_len = 16;
    } else {
        return CKR_MECHANISM_INVALID;
    }
    c->active = 1;
    return CKR_OK;
}

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                    CK_OBJECT_HANDLE hKey)
{
    p11_session_t *s = sess_get(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    return cipher_init(s, &s->enc, 1, pMechanism, hKey);
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                    CK_OBJECT_HANDLE hKey)
{
    p11_session_t *s = sess_get(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    return cipher_init(s, &s->dec, 0, pMechanism, hKey);
}

static CK_RV cipher_run(p11_session_t *s, p11_cipher_t *c, int encrypt,
                        CK_BYTE_PTR in, CK_ULONG in_len,
                        CK_BYTE_PTR out, CK_ULONG_PTR out_len)
{
    CK_RV rv;
    uint32_t got = 0;

    if (!c->active)
        return CKR_OPERATION_NOT_INITIALIZED;
    if (!out_len)
        return CKR_ARGUMENTS_BAD;
    /* Size query / upper bound. */
    CK_ULONG need = in_len + (c->mech == CKM_AES_GCM && encrypt ? c->tag_len : 0);
    if (!out) {
        *out_len = need;
        return CKR_OK;
    }
    if (*out_len < need) {
        *out_len = need;
        return CKR_BUFFER_TOO_SMALL;
    }
    if (c->mech == CKM_AES_GCM) {
        rv = ncmp_crypto_aes_gcm(&g_client, s->slot, encrypt,
                                 c->key, c->key_len, c->iv, c->iv_len,
                                 c->aad, c->aad_len, c->tag_len,
                                 in, (uint32_t)in_len, out, (uint32_t)*out_len,
                                 &got);
    } else { /* CKM_AES_CTR */
        rv = ncmp_crypto_aes_stream(&g_client, s->slot, NCMP_CMD_AES_CTR,
                                    encrypt, c->key, c->key_len, c->iv,
                                    c->iv_len, in, (uint32_t)in_len, out,
                                    (uint32_t)*out_len, &got);
    }
    if (rv == CKR_OK)
        *out_len = got;
    c->active = 0;
    return rv;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
    p11_session_t *s = sess_get(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    return cipher_run(s, &s->enc, 1, pData, ulDataLen,
                      pEncryptedData, pulEncryptedDataLen);
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData,
                CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData,
                CK_ULONG_PTR pulDataLen)
{
    p11_session_t *s = sess_get(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    return cipher_run(s, &s->dec, 0, pEncryptedData, ulEncryptedDataLen,
                      pData, pulDataLen);
}

/* -------------------------------------------------------------------------- */
/* Key generation (AES secret key stored locally)                            */
/* -------------------------------------------------------------------------- */

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                    CK_OBJECT_HANDLE_PTR phKey)
{
    p11_session_t *s = sess_get(hSession);
    if (!s)
        return CKR_SESSION_HANDLE_INVALID;
    if (!pMechanism || pMechanism->mechanism != CKM_AES_KEY_GEN)
        return CKR_MECHANISM_INVALID;
    if (!phKey)
        return CKR_ARGUMENTS_BAD;

    CK_ULONG keylen = 32;
    for (CK_ULONG i = 0; i < ulCount; ++i)
        if (pTemplate[i].type == CKA_VALUE_LEN && pTemplate[i].pValue)
            keylen = *(CK_ULONG *)pTemplate[i].pValue;
    if (keylen != 16 && keylen != 24 && keylen != 32)
        return CKR_ATTRIBUTE_VALUE_INVALID;

    uint8_t keybuf[32];
    CK_RV rv = ncmp_crypto_rng(&g_client, s->slot, keybuf, (uint32_t)keylen);
    if (rv != CKR_OK)
        return rv;

    CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
    CK_KEY_TYPE kt = CKK_AES;
    CK_ATTRIBUTE tmpl[3 + P11_MAX_ATTRS];
    CK_ULONG n = 0;
    tmpl[n].type = CKA_CLASS; tmpl[n].pValue = &cls;
    tmpl[n].ulValueLen = sizeof(cls); n++;
    tmpl[n].type = CKA_KEY_TYPE; tmpl[n].pValue = &kt;
    tmpl[n].ulValueLen = sizeof(kt); n++;
    tmpl[n].type = CKA_VALUE; tmpl[n].pValue = keybuf;
    tmpl[n].ulValueLen = keylen; n++;
    for (CK_ULONG i = 0; i < ulCount && n < (CK_ULONG)(3 + P11_MAX_ATTRS); ++i)
        if (pTemplate[i].type != CKA_VALUE)
            tmpl[n++] = pTemplate[i];
    return C_CreateObject(hSession, tmpl, n, phKey);
}

/* -------------------------------------------------------------------------- */
/* Unsupported functions (correct signatures, all return NOT_SUPPORTED)       */
/* -------------------------------------------------------------------------- */
#define NS CKR_FUNCTION_NOT_SUPPORTED

CK_RV C_InitToken(CK_SLOT_ID a, CK_CHAR_PTR b, CK_ULONG c, CK_CHAR_PTR d)
{ (void)a;(void)b;(void)c;(void)d; return NS; }
CK_RV C_InitPIN(CK_SESSION_HANDLE a, CK_CHAR_PTR b, CK_ULONG c)
{ (void)a;(void)b;(void)c; return NS; }
CK_RV C_SetPIN(CK_SESSION_HANDLE a, CK_CHAR_PTR b, CK_ULONG c, CK_CHAR_PTR d,
               CK_ULONG e){ (void)a;(void)b;(void)c;(void)d;(void)e; return NS; }
CK_RV C_GetOperationState(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG_PTR c)
{ (void)a;(void)b;(void)c; return NS; }
CK_RV C_SetOperationState(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c,
                          CK_OBJECT_HANDLE d, CK_OBJECT_HANDLE e)
{ (void)a;(void)b;(void)c;(void)d;(void)e; return NS; }
CK_RV C_CopyObject(CK_SESSION_HANDLE a, CK_OBJECT_HANDLE b, CK_ATTRIBUTE_PTR c,
                   CK_ULONG d, CK_OBJECT_HANDLE_PTR e)
{ (void)a;(void)b;(void)c;(void)d;(void)e; return NS; }
CK_RV C_GetObjectSize(CK_SESSION_HANDLE a, CK_OBJECT_HANDLE b, CK_ULONG_PTR c)
{ (void)a;(void)b;(void)c; return NS; }
CK_RV C_SetAttributeValue(CK_SESSION_HANDLE a, CK_OBJECT_HANDLE b,
                          CK_ATTRIBUTE_PTR c, CK_ULONG d)
{ (void)a;(void)b;(void)c;(void)d; return NS; }
CK_RV C_EncryptUpdate(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c,
                      CK_BYTE_PTR d, CK_ULONG_PTR e)
{ (void)a;(void)b;(void)c;(void)d;(void)e; return NS; }
CK_RV C_EncryptFinal(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG_PTR c)
{ (void)a;(void)b;(void)c; return NS; }
CK_RV C_DecryptUpdate(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c,
                      CK_BYTE_PTR d, CK_ULONG_PTR e)
{ (void)a;(void)b;(void)c;(void)d;(void)e; return NS; }
CK_RV C_DecryptFinal(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG_PTR c)
{ (void)a;(void)b;(void)c; return NS; }
CK_RV C_DigestKey(CK_SESSION_HANDLE a, CK_OBJECT_HANDLE b)
{ (void)a;(void)b; return NS; }
CK_RV C_SignInit(CK_SESSION_HANDLE a, CK_MECHANISM_PTR b, CK_OBJECT_HANDLE c)
{ (void)a;(void)b;(void)c; return NS; }
CK_RV C_Sign(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_BYTE_PTR d,
             CK_ULONG_PTR e){ (void)a;(void)b;(void)c;(void)d;(void)e; return NS; }
CK_RV C_SignUpdate(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c)
{ (void)a;(void)b;(void)c; return NS; }
CK_RV C_SignFinal(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG_PTR c)
{ (void)a;(void)b;(void)c; return NS; }
CK_RV C_SignRecoverInit(CK_SESSION_HANDLE a, CK_MECHANISM_PTR b,
                        CK_OBJECT_HANDLE c){ (void)a;(void)b;(void)c; return NS; }
CK_RV C_SignRecover(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c,
                    CK_BYTE_PTR d, CK_ULONG_PTR e)
{ (void)a;(void)b;(void)c;(void)d;(void)e; return NS; }
CK_RV C_VerifyInit(CK_SESSION_HANDLE a, CK_MECHANISM_PTR b, CK_OBJECT_HANDLE c)
{ (void)a;(void)b;(void)c; return NS; }
CK_RV C_Verify(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_BYTE_PTR d,
               CK_ULONG e){ (void)a;(void)b;(void)c;(void)d;(void)e; return NS; }
CK_RV C_VerifyUpdate(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c)
{ (void)a;(void)b;(void)c; return NS; }
CK_RV C_VerifyFinal(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c)
{ (void)a;(void)b;(void)c; return NS; }
CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE a, CK_MECHANISM_PTR b,
                          CK_OBJECT_HANDLE c){ (void)a;(void)b;(void)c; return NS; }
CK_RV C_VerifyRecover(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c,
                      CK_BYTE_PTR d, CK_ULONG_PTR e)
{ (void)a;(void)b;(void)c;(void)d;(void)e; return NS; }
CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c,
                            CK_BYTE_PTR d, CK_ULONG_PTR e)
{ (void)a;(void)b;(void)c;(void)d;(void)e; return NS; }
CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c,
                            CK_BYTE_PTR d, CK_ULONG_PTR e)
{ (void)a;(void)b;(void)c;(void)d;(void)e; return NS; }
CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c,
                          CK_BYTE_PTR d, CK_ULONG_PTR e)
{ (void)a;(void)b;(void)c;(void)d;(void)e; return NS; }
CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c,
                            CK_BYTE_PTR d, CK_ULONG_PTR e)
{ (void)a;(void)b;(void)c;(void)d;(void)e; return NS; }
CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE a, CK_MECHANISM_PTR b,
                        CK_ATTRIBUTE_PTR c, CK_ULONG d, CK_ATTRIBUTE_PTR e,
                        CK_ULONG f, CK_OBJECT_HANDLE_PTR g, CK_OBJECT_HANDLE_PTR h)
{ (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h; return NS; }
CK_RV C_WrapKey(CK_SESSION_HANDLE a, CK_MECHANISM_PTR b, CK_OBJECT_HANDLE c,
                CK_OBJECT_HANDLE d, CK_BYTE_PTR e, CK_ULONG_PTR f)
{ (void)a;(void)b;(void)c;(void)d;(void)e;(void)f; return NS; }
CK_RV C_UnwrapKey(CK_SESSION_HANDLE a, CK_MECHANISM_PTR b, CK_OBJECT_HANDLE c,
                  CK_BYTE_PTR d, CK_ULONG e, CK_ATTRIBUTE_PTR f, CK_ULONG g,
                  CK_OBJECT_HANDLE_PTR h)
{ (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h; return NS; }
CK_RV C_DeriveKey(CK_SESSION_HANDLE a, CK_MECHANISM_PTR b, CK_OBJECT_HANDLE c,
                  CK_ATTRIBUTE_PTR d, CK_ULONG e, CK_OBJECT_HANDLE_PTR f)
{ (void)a;(void)b;(void)c;(void)d;(void)e;(void)f; return NS; }
CK_RV C_SeedRandom(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c)
{ (void)a;(void)b;(void)c; return CKR_RANDOM_SEED_NOT_SUPPORTED; }
CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE a){ (void)a; return CKR_FUNCTION_NOT_PARALLEL; }
CK_RV C_CancelFunction(CK_SESSION_HANDLE a){ (void)a; return CKR_FUNCTION_NOT_PARALLEL; }
CK_RV C_WaitForSlotEvent(CK_FLAGS a, CK_SLOT_ID_PTR b, CK_VOID_PTR c)
{ (void)a;(void)b;(void)c; return NS; }

/* -------------------------------------------------------------------------- */
/* Function lists + interfaces                                                */
/* -------------------------------------------------------------------------- */

static CK_FUNCTION_LIST g_fl_2_40;
static CK_FUNCTION_LIST_3_0 g_fl_3_0;
static CK_FUNCTION_LIST_3_2 g_fl_3_2;

/* Fill the shared (2.40) prefix of any function-list struct via a macro so the
 * three versions stay in lockstep. */
#define FILL_CORE(fl, maj, min)                                                \
    do {                                                                       \
        (fl).version.major = (maj); (fl).version.minor = (min);               \
        (fl).C_Initialize = C_Initialize; (fl).C_Finalize = C_Finalize;       \
        (fl).C_GetInfo = C_GetInfo; (fl).C_GetFunctionList = C_GetFunctionList;\
        (fl).C_GetSlotList = C_GetSlotList; (fl).C_GetSlotInfo = C_GetSlotInfo;\
        (fl).C_GetTokenInfo = C_GetTokenInfo;                                  \
        (fl).C_GetMechanismList = C_GetMechanismList;                          \
        (fl).C_GetMechanismInfo = C_GetMechanismInfo;                          \
        (fl).C_InitToken = C_InitToken; (fl).C_InitPIN = C_InitPIN;            \
        (fl).C_SetPIN = C_SetPIN; (fl).C_OpenSession = C_OpenSession;          \
        (fl).C_CloseSession = C_CloseSession;                                  \
        (fl).C_CloseAllSessions = C_CloseAllSessions;                          \
        (fl).C_GetSessionInfo = C_GetSessionInfo;                             \
        (fl).C_GetOperationState = C_GetOperationState;                        \
        (fl).C_SetOperationState = C_SetOperationState;                        \
        (fl).C_Login = C_Login; (fl).C_Logout = C_Logout;                      \
        (fl).C_CreateObject = C_CreateObject; (fl).C_CopyObject = C_CopyObject;\
        (fl).C_DestroyObject = C_DestroyObject;                               \
        (fl).C_GetObjectSize = C_GetObjectSize;                               \
        (fl).C_GetAttributeValue = C_GetAttributeValue;                        \
        (fl).C_SetAttributeValue = C_SetAttributeValue;                        \
        (fl).C_FindObjectsInit = C_FindObjectsInit;                           \
        (fl).C_FindObjects = C_FindObjects;                                    \
        (fl).C_FindObjectsFinal = C_FindObjectsFinal;                         \
        (fl).C_EncryptInit = C_EncryptInit; (fl).C_Encrypt = C_Encrypt;        \
        (fl).C_EncryptUpdate = C_EncryptUpdate;                               \
        (fl).C_EncryptFinal = C_EncryptFinal;                                 \
        (fl).C_DecryptInit = C_DecryptInit; (fl).C_Decrypt = C_Decrypt;        \
        (fl).C_DecryptUpdate = C_DecryptUpdate;                               \
        (fl).C_DecryptFinal = C_DecryptFinal;                                 \
        (fl).C_DigestInit = C_DigestInit; (fl).C_Digest = C_Digest;            \
        (fl).C_DigestUpdate = C_DigestUpdate; (fl).C_DigestKey = C_DigestKey;  \
        (fl).C_DigestFinal = C_DigestFinal;                                    \
        (fl).C_SignInit = C_SignInit; (fl).C_Sign = C_Sign;                    \
        (fl).C_SignUpdate = C_SignUpdate; (fl).C_SignFinal = C_SignFinal;      \
        (fl).C_SignRecoverInit = C_SignRecoverInit;                           \
        (fl).C_SignRecover = C_SignRecover;                                    \
        (fl).C_VerifyInit = C_VerifyInit; (fl).C_Verify = C_Verify;            \
        (fl).C_VerifyUpdate = C_VerifyUpdate; (fl).C_VerifyFinal = C_VerifyFinal;\
        (fl).C_VerifyRecoverInit = C_VerifyRecoverInit;                        \
        (fl).C_VerifyRecover = C_VerifyRecover;                               \
        (fl).C_DigestEncryptUpdate = C_DigestEncryptUpdate;                   \
        (fl).C_DecryptDigestUpdate = C_DecryptDigestUpdate;                   \
        (fl).C_SignEncryptUpdate = C_SignEncryptUpdate;                       \
        (fl).C_DecryptVerifyUpdate = C_DecryptVerifyUpdate;                   \
        (fl).C_GenerateKey = C_GenerateKey;                                    \
        (fl).C_GenerateKeyPair = C_GenerateKeyPair;                           \
        (fl).C_WrapKey = C_WrapKey; (fl).C_UnwrapKey = C_UnwrapKey;            \
        (fl).C_DeriveKey = C_DeriveKey; (fl).C_SeedRandom = C_SeedRandom;      \
        (fl).C_GenerateRandom = C_GenerateRandom;                             \
        (fl).C_GetFunctionStatus = C_GetFunctionStatus;                       \
        (fl).C_CancelFunction = C_CancelFunction;                             \
        (fl).C_WaitForSlotEvent = C_WaitForSlotEvent;                         \
    } while (0)

static CK_INTERFACE g_interfaces[3];
static int g_lists_built;

static void build_lists(void)
{
    if (g_lists_built)
        return;
    memset(&g_fl_2_40, 0, sizeof(g_fl_2_40));
    memset(&g_fl_3_0, 0, sizeof(g_fl_3_0));
    memset(&g_fl_3_2, 0, sizeof(g_fl_3_2));
    FILL_CORE(g_fl_2_40, 2, 40);
    FILL_CORE(g_fl_3_0, 3, 0);
    FILL_CORE(g_fl_3_2, 3, 2);
    /* 3.0/3.2 extras we expose (the rest stay NULL = not provided). */
    g_fl_3_0.C_GetInterfaceList = C_GetInterfaceList;
    g_fl_3_0.C_GetInterface = C_GetInterface;
    g_fl_3_2.C_GetInterfaceList = C_GetInterfaceList;
    g_fl_3_2.C_GetInterface = C_GetInterface;

    g_interfaces[0].pInterfaceName = (CK_CHAR *)"PKCS 11";
    g_interfaces[0].pFunctionList = &g_fl_3_2;
    g_interfaces[0].flags = 0;
    g_interfaces[1].pInterfaceName = (CK_CHAR *)"PKCS 11";
    g_interfaces[1].pFunctionList = &g_fl_3_0;
    g_interfaces[1].flags = 0;
    g_interfaces[2].pInterfaceName = (CK_CHAR *)"PKCS 11";
    g_interfaces[2].pFunctionList = &g_fl_2_40;
    g_interfaces[2].flags = 0;
    g_lists_built = 1;
}

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    if (!ppFunctionList)
        return CKR_ARGUMENTS_BAD;
    build_lists();
    *ppFunctionList = &g_fl_2_40;
    return CKR_OK;
}

CK_RV C_GetInterfaceList(CK_INTERFACE_PTR pInterfaceList,
                         CK_ULONG_PTR pulCount)
{
    const CK_ULONG n = sizeof(g_interfaces) / sizeof(g_interfaces[0]);
    if (!pulCount)
        return CKR_ARGUMENTS_BAD;
    build_lists();
    if (!pInterfaceList) {
        *pulCount = n;
        return CKR_OK;
    }
    if (*pulCount < n) {
        *pulCount = n;
        return CKR_BUFFER_TOO_SMALL;
    }
    memcpy(pInterfaceList, g_interfaces, sizeof(g_interfaces));
    *pulCount = n;
    return CKR_OK;
}

CK_RV C_GetInterface(CK_UTF8CHAR_PTR pInterfaceName, CK_VERSION_PTR pVersion,
                     CK_INTERFACE_PTR_PTR ppInterface, CK_FLAGS flags)
{
    (void)flags;
    if (!ppInterface)
        return CKR_ARGUMENTS_BAD;
    build_lists();
    if (pInterfaceName &&
        strcmp((const char *)pInterfaceName, "PKCS 11") != 0)
        return CKR_ARGUMENTS_BAD;
    for (size_t i = 0; i < sizeof(g_interfaces) / sizeof(g_interfaces[0]); ++i) {
        CK_VERSION *v = &((CK_FUNCTION_LIST_PTR)g_interfaces[i].pFunctionList)
                            ->version;
        if (!pVersion ||
            (pVersion->major == v->major && pVersion->minor == v->minor)) {
            *ppInterface = &g_interfaces[i];
            return CKR_OK;
        }
    }
    return CKR_ARGUMENTS_BAD;
}

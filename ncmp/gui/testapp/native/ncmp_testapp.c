/*
 * Token NCMP - Test App native layer (implementation). See ncmp_testapp.h.
 *
 * Style: Google C Style. Not part of the shipped token; a developer tool that
 * the C# (Avalonia) GUI loads via P/Invoke.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "ncmp_testapp.h"

#include <pkcs11types.h>

#include <dlfcn.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * PKCS#11 entry points take non-const buffers even for read-only inputs, while
 * our ABI takes const pointers. Launder const away through uintptr_t (a no-op
 * that the token never writes) so -Wcast-qual stays clean.
 */
#define UNCONST(T, p) ((T)(uintptr_t)(const void *)(p))

/* ------------------------------------------------------------------ */
/* State                                                              */
/* ------------------------------------------------------------------ */

static void *g_lib;                 /* dlopen handle of the facade */
static char  g_err[512] = "";

/* Typed pointers for the entry points we call. */
static CK_C_Initialize        p_Initialize;
static CK_C_Finalize          p_Finalize;
static CK_C_GetInfo           p_GetInfo;
static CK_C_GetSlotList       p_GetSlotList;
static CK_C_GetSessionInfo    p_GetSessionInfo;
static CK_C_GetTokenInfo      p_GetTokenInfo;
static CK_C_GetMechanismList  p_GetMechanismList;
static CK_C_OpenSession       p_OpenSession;
static CK_C_CloseSession      p_CloseSession;
static CK_C_Login             p_Login;
static CK_C_Logout            p_Logout;
static CK_C_GenerateRandom    p_GenerateRandom;
static CK_C_DigestInit        p_DigestInit;
static CK_C_Digest            p_Digest;
static CK_C_DigestUpdate      p_DigestUpdate;
static CK_C_DigestFinal       p_DigestFinal;
static CK_C_GenerateKey       p_GenerateKey;
static CK_C_EncryptInit       p_EncryptInit;
static CK_C_Encrypt           p_Encrypt;
static CK_C_DecryptInit       p_DecryptInit;
static CK_C_Decrypt           p_Decrypt;

/* Every PKCS#11 entry point the facade exports (dlsym presence report). */
static const char *ALL_FUNCS[] = {
    "C_Initialize", "C_Finalize", "C_GetInfo", "C_GetFunctionList",
    "C_GetInterfaceList", "C_GetInterface", "C_GetSlotList", "C_GetSlotInfo",
    "C_GetTokenInfo", "C_GetMechanismList", "C_GetMechanismInfo",
    "C_InitToken", "C_InitPIN", "C_SetPIN", "C_OpenSession", "C_CloseSession",
    "C_CloseAllSessions", "C_GetSessionInfo", "C_GetOperationState",
    "C_SetOperationState", "C_Login", "C_Logout", "C_CreateObject",
    "C_CopyObject", "C_DestroyObject", "C_GetObjectSize", "C_GetAttributeValue",
    "C_SetAttributeValue", "C_FindObjectsInit", "C_FindObjects",
    "C_FindObjectsFinal", "C_EncryptInit", "C_Encrypt", "C_EncryptUpdate",
    "C_EncryptFinal", "C_DecryptInit", "C_Decrypt", "C_DecryptUpdate",
    "C_DecryptFinal", "C_DigestInit", "C_Digest", "C_DigestUpdate",
    "C_DigestKey", "C_DigestFinal", "C_SignInit", "C_Sign", "C_SignUpdate",
    "C_SignFinal", "C_SignRecoverInit", "C_SignRecover", "C_VerifyInit",
    "C_Verify", "C_VerifyUpdate", "C_VerifyFinal", "C_VerifyRecoverInit",
    "C_VerifyRecover", "C_DigestEncryptUpdate", "C_DecryptDigestUpdate",
    "C_SignEncryptUpdate", "C_DecryptVerifyUpdate", "C_GenerateKey",
    "C_GenerateKeyPair", "C_WrapKey", "C_UnwrapKey", "C_DeriveKey",
    "C_SeedRandom", "C_GenerateRandom", "C_GetFunctionStatus",
    "C_CancelFunction", "C_WaitForSlotEvent",
};
#define ALL_FUNCS_N ((int)(sizeof(ALL_FUNCS) / sizeof(ALL_FUNCS[0])))

static void set_err(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_err, sizeof(g_err), fmt, ap);
    va_end(ap);
}

const char *app_last_error(void) { return g_err; }

/* ------------------------------------------------------------------ */
/* Load / unload                                                     */
/* ------------------------------------------------------------------ */

#define SYM(dst, type, name)                                           \
    do {                                                               \
        *(void **)(&dst) = dlsym(g_lib, name);                         \
        if (!dst) {                                                    \
            set_err("dlsym(%s) failed: %s", name, dlerror());          \
            return APP_ERR_DLSYM;                                      \
        }                                                              \
    } while (0)

int app_load(const char *module_path)
{
    if (!module_path || !*module_path) {
        set_err("module path is empty");
        return APP_ERR_ARGS;
    }
    if (g_lib)
        app_unload();
    g_lib = dlopen(module_path, RTLD_NOW | RTLD_LOCAL);
    if (!g_lib) {
        set_err("dlopen(%s) failed: %s", module_path, dlerror());
        return APP_ERR_DLOPEN;
    }
    SYM(p_Initialize,       CK_C_Initialize,       "C_Initialize");
    SYM(p_Finalize,         CK_C_Finalize,         "C_Finalize");
    SYM(p_GetInfo,          CK_C_GetInfo,          "C_GetInfo");
    SYM(p_GetSlotList,      CK_C_GetSlotList,      "C_GetSlotList");
    SYM(p_GetSessionInfo,   CK_C_GetSessionInfo,   "C_GetSessionInfo");
    SYM(p_GetTokenInfo,     CK_C_GetTokenInfo,     "C_GetTokenInfo");
    SYM(p_GetMechanismList, CK_C_GetMechanismList, "C_GetMechanismList");
    SYM(p_OpenSession,      CK_C_OpenSession,      "C_OpenSession");
    SYM(p_CloseSession,     CK_C_CloseSession,     "C_CloseSession");
    SYM(p_Login,            CK_C_Login,            "C_Login");
    SYM(p_Logout,           CK_C_Logout,           "C_Logout");
    SYM(p_GenerateRandom,   CK_C_GenerateRandom,   "C_GenerateRandom");
    SYM(p_DigestInit,       CK_C_DigestInit,       "C_DigestInit");
    SYM(p_Digest,           CK_C_Digest,           "C_Digest");
    SYM(p_DigestUpdate,     CK_C_DigestUpdate,     "C_DigestUpdate");
    SYM(p_DigestFinal,      CK_C_DigestFinal,      "C_DigestFinal");
    SYM(p_GenerateKey,      CK_C_GenerateKey,      "C_GenerateKey");
    SYM(p_EncryptInit,      CK_C_EncryptInit,      "C_EncryptInit");
    SYM(p_Encrypt,          CK_C_Encrypt,          "C_Encrypt");
    SYM(p_DecryptInit,      CK_C_DecryptInit,      "C_DecryptInit");
    SYM(p_Decrypt,          CK_C_Decrypt,          "C_Decrypt");
    set_err("loaded %s", module_path);
    return 0;
}

int app_unload(void)
{
    if (g_lib) {
        dlclose(g_lib);
        g_lib = NULL;
    }
    return 0;
}

int app_dlsym_report(char *json_out, int cap)
{
    int o = 0, i;
    if (!json_out || cap < 4)
        return APP_ERR_ARGS;
    if (!g_lib) {
        set_err("not loaded");
        return APP_ERR_NOT_LOADED;
    }
    o += snprintf(json_out + o, cap - o, "{");
    for (i = 0; i < ALL_FUNCS_N; ++i) {
        void *s = dlsym(g_lib, ALL_FUNCS[i]);
        if (o > cap - 48)
            break;
        o += snprintf(json_out + o, cap - o, "%s\"%s\":%d",
                      i ? "," : "", ALL_FUNCS[i], s ? 1 : 0);
    }
    o += snprintf(json_out + o, cap - o, "}");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Lifecycle / slots                                                 */
/* ------------------------------------------------------------------ */

#define NEED(p) do { if (!(p)) { set_err("not loaded"); \
                                 return APP_ERR_NOT_LOADED; } } while (0)

int app_initialize(void)
{
    CK_RV rv;
    NEED(p_Initialize);
    rv = p_Initialize(NULL);
    if (rv != CKR_OK)
        set_err("C_Initialize -> 0x%08lX (ncmpd 미기동/연결 실패?)",
                (unsigned long)rv);
    return (int)rv;
}

int app_finalize(void)
{
    NEED(p_Finalize);
    return (int)p_Finalize(NULL);
}

int app_get_slots(unsigned long *out, int max, int *count)
{
    CK_ULONG n = 0;
    CK_RV rv;
    NEED(p_GetSlotList);
    if (!count)
        return APP_ERR_ARGS;
    rv = p_GetSlotList(CK_TRUE, NULL, &n);
    if (rv != CKR_OK)
        return (int)rv;
    if (!out) {                 /* count-only query */
        *count = (int)n;
        return 0;
    }
    if ((int)n > max)
        n = (CK_ULONG)max;
    rv = p_GetSlotList(CK_TRUE, (CK_SLOT_ID_PTR)out, &n);
    if (rv != CKR_OK)
        return (int)rv;
    *count = (int)n;
    return 0;
}

/* Trim trailing spaces from a blank-padded CK field into a C string. */
static void field(char *dst, const CK_CHAR *src, size_t n)
{
    size_t i = n;
    while (i > 0 && (src[i - 1] == ' ' || src[i - 1] == 0))
        i--;
    memcpy(dst, src, i);
    dst[i] = '\0';
}

int app_library_info(char *json_out, int cap)
{
    CK_INFO info;
    char manuf[48], desc[48];
    CK_RV rv;
    NEED(p_GetInfo);
    if (!json_out)
        return APP_ERR_ARGS;
    memset(&info, 0, sizeof(info));
    rv = p_GetInfo(&info);
    if (rv != CKR_OK)
        return (int)rv;
    field(manuf, info.manufacturerID, sizeof(info.manufacturerID));
    field(desc, info.libraryDescription, sizeof(info.libraryDescription));
    snprintf(json_out, cap,
             "{\"cryptokiVersion\":\"%u.%u\",\"manufacturer\":\"%s\","
             "\"libDescription\":\"%s\",\"libVersion\":\"%u.%u\",\"flags\":%lu}",
             info.cryptokiVersion.major, info.cryptokiVersion.minor, manuf,
             desc, info.libraryVersion.major, info.libraryVersion.minor,
             (unsigned long)info.flags);
    return 0;
}

int app_token_info(unsigned long slot, char *json_out, int cap)
{
    CK_TOKEN_INFO ti;
    char label[48], manuf[48], model[32], serial[32];
    CK_RV rv;
    NEED(p_GetTokenInfo);
    if (!json_out)
        return APP_ERR_ARGS;
    memset(&ti, 0, sizeof(ti));
    rv = p_GetTokenInfo((CK_SLOT_ID)slot, &ti);
    if (rv != CKR_OK)
        return (int)rv;
    field(label, ti.label, sizeof(ti.label));
    field(manuf, ti.manufacturerID, sizeof(ti.manufacturerID));
    field(model, ti.model, sizeof(ti.model));
    field(serial, ti.serialNumber, sizeof(ti.serialNumber));
    snprintf(json_out, cap,
             "{\"label\":\"%s\",\"manufacturer\":\"%s\",\"model\":\"%s\","
             "\"serial\":\"%s\",\"flags\":%lu,\"minPin\":%lu,\"maxPin\":%lu,"
             "\"maxSession\":%lu,\"hwVersion\":\"%u.%u\",\"fwVersion\":\"%u.%u\"}",
             label, manuf, model, serial, (unsigned long)ti.flags,
             (unsigned long)ti.ulMinPinLen, (unsigned long)ti.ulMaxPinLen,
             (unsigned long)ti.ulMaxSessionCount,
             ti.hardwareVersion.major, ti.hardwareVersion.minor,
             ti.firmwareVersion.major, ti.firmwareVersion.minor);
    return 0;
}

/* A few CKM names for the GUI; unknown -> hex. */
static const char *mech_name(CK_MECHANISM_TYPE m)
{
    switch (m) {
    case CKM_AES_KEY_GEN: return "CKM_AES_KEY_GEN";
    case CKM_AES_GCM:     return "CKM_AES_GCM";
    case CKM_AES_CTR:     return "CKM_AES_CTR";
    case CKM_SHA256:      return "CKM_SHA256";
    case CKM_SHA512:      return "CKM_SHA512";
    case CKM_SHA3_224:    return "CKM_SHA3_224";
    case CKM_SHA3_256:    return "CKM_SHA3_256";
    case CKM_SHA3_384:    return "CKM_SHA3_384";
    case CKM_SHA3_512:    return "CKM_SHA3_512";
    default:              return NULL;
    }
}

int app_mechanism_list(unsigned long slot, char *json_out, int cap)
{
    CK_MECHANISM_TYPE list[64];
    CK_ULONG n = 64;
    CK_RV rv;
    int o = 0;
    NEED(p_GetMechanismList);
    if (!json_out)
        return APP_ERR_ARGS;
    rv = p_GetMechanismList((CK_SLOT_ID)slot, list, &n);
    if (rv != CKR_OK)
        return (int)rv;
    o += snprintf(json_out + o, cap - o, "[");
    for (CK_ULONG i = 0; i < n && o < cap - 64; ++i) {
        const char *nm = mech_name(list[i]);
        char hex[16];
        if (!nm) { snprintf(hex, sizeof(hex), "0x%lX", (unsigned long)list[i]); nm = hex; }
        o += snprintf(json_out + o, cap - o, "%s{\"name\":\"%s\",\"code\":%lu}",
                      i ? "," : "", nm, (unsigned long)list[i]);
    }
    snprintf(json_out + o, cap - o, "]");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Sessions / login                                                  */
/* ------------------------------------------------------------------ */

int app_session_info(unsigned long session, char *json_out, int cap)
{
    CK_SESSION_INFO si;
    CK_RV rv;
    NEED(p_GetSessionInfo);
    if (!json_out)
        return APP_ERR_ARGS;
    memset(&si, 0, sizeof(si));
    rv = p_GetSessionInfo((CK_SESSION_HANDLE)session, &si);
    if (rv != CKR_OK)
        return (int)rv;
    snprintf(json_out, cap,
             "{\"slot\":%lu,\"state\":%lu,\"flags\":%lu,\"deviceError\":%lu}",
             (unsigned long)si.slotID, (unsigned long)si.state,
             (unsigned long)si.flags, (unsigned long)si.ulDeviceError);
    return 0;
}

int app_open_session(unsigned long slot, int rw, unsigned long *out_session)
{
    CK_SESSION_HANDLE h = 0;
    CK_FLAGS flags = CKF_SERIAL_SESSION | (rw ? CKF_RW_SESSION : 0);
    CK_RV rv;
    NEED(p_OpenSession);
    if (!out_session)
        return APP_ERR_ARGS;
    rv = p_OpenSession((CK_SLOT_ID)slot, flags, NULL, NULL, &h);
    if (rv == CKR_OK)
        *out_session = (unsigned long)h;
    return (int)rv;
}

int app_close_session(unsigned long session)
{
    NEED(p_CloseSession);
    return (int)p_CloseSession((CK_SESSION_HANDLE)session);
}

int app_login(unsigned long session, int user_type, const char *pin)
{
    NEED(p_Login);
    return (int)p_Login((CK_SESSION_HANDLE)session, (CK_USER_TYPE)user_type,
                        UNCONST(CK_UTF8CHAR_PTR, pin),
                        pin ? (CK_ULONG)strlen(pin) : 0);
}

int app_logout(unsigned long session)
{
    NEED(p_Logout);
    return (int)p_Logout((CK_SESSION_HANDLE)session);
}

/* ------------------------------------------------------------------ */
/* Crypto / hash                                                     */
/* ------------------------------------------------------------------ */

int app_generate_random(unsigned long session, unsigned char *out, int n)
{
    NEED(p_GenerateRandom);
    if (!out || n < 0)
        return APP_ERR_ARGS;
    return (int)p_GenerateRandom((CK_SESSION_HANDLE)session, out, (CK_ULONG)n);
}

int app_digest(unsigned long session, unsigned long mech,
               const unsigned char *in, int in_len,
               unsigned char *out, int cap, int *out_len)
{
    CK_MECHANISM m = { (CK_MECHANISM_TYPE)mech, NULL, 0 };
    CK_ULONG olen = (CK_ULONG)cap;
    CK_RV rv;
    NEED(p_DigestInit);
    NEED(p_Digest);
    if (!out || !out_len)
        return APP_ERR_ARGS;
    rv = p_DigestInit((CK_SESSION_HANDLE)session, &m);
    if (rv != CKR_OK)
        return (int)rv;
    rv = p_Digest((CK_SESSION_HANDLE)session, UNCONST(CK_BYTE_PTR, in),
                  (CK_ULONG)in_len, out, &olen);
    if (rv == CKR_OK)
        *out_len = (int)olen;
    return (int)rv;
}

int app_digest_multipart(unsigned long session, unsigned long mech,
                         const unsigned char *data, long data_len, int chunk,
                         unsigned char *out, int cap, int *out_len)
{
    CK_MECHANISM m = { (CK_MECHANISM_TYPE)mech, NULL, 0 };
    CK_ULONG olen = (CK_ULONG)cap;
    CK_RV rv;
    NEED(p_DigestInit);
    NEED(p_DigestUpdate);
    NEED(p_DigestFinal);
    if (!out || !out_len || data_len < 0 || (data_len > 0 && !data))
        return APP_ERR_ARGS;
    if (chunk <= 0)
        chunk = 32 * 1024;      /* safely under one 64 KB wire frame */

    rv = p_DigestInit((CK_SESSION_HANDLE)session, &m);
    if (rv != CKR_OK) {
        set_err("C_DigestInit -> 0x%08lX", (unsigned long)rv);
        return (int)rv;
    }
    for (long off = 0; off < data_len; off += chunk) {
        long part = data_len - off;
        if (part > chunk)
            part = chunk;
        rv = p_DigestUpdate((CK_SESSION_HANDLE)session,
                            UNCONST(CK_BYTE_PTR, data + off), (CK_ULONG)part);
        if (rv != CKR_OK) {
            set_err("C_DigestUpdate(off=%ld) -> 0x%08lX", off, (unsigned long)rv);
            return (int)rv;
        }
    }
    rv = p_DigestFinal((CK_SESSION_HANDLE)session, out, &olen);
    if (rv == CKR_OK)
        *out_len = (int)olen;
    else
        set_err("C_DigestFinal -> 0x%08lX", (unsigned long)rv);
    return (int)rv;
}

int app_aes_gcm_selftest(unsigned long session, char *detail, int cap)
{
    CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
    CK_KEY_TYPE kt = CKK_AES;
    CK_ULONG vlen = 16;
    CK_BBOOL yes = CK_TRUE, no = CK_FALSE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &cls, sizeof(cls) },
        { CKA_KEY_TYPE, &kt, sizeof(kt) },
        { CKA_VALUE_LEN, &vlen, sizeof(vlen) },
        { CKA_ENCRYPT, &yes, sizeof(yes) },
        { CKA_DECRYPT, &yes, sizeof(yes) },
        { CKA_TOKEN, &no, sizeof(no) },
    };
    CK_MECHANISM keygen = { CKM_AES_KEY_GEN, NULL, 0 };
    CK_OBJECT_HANDLE key = 0;
    CK_BYTE iv[12];
    CK_GCM_PARAMS gcm;
    CK_MECHANISM mg;
    CK_BYTE pt[] = "authenticated payload";
    CK_BYTE ct[64], back[64];
    CK_ULONG ctlen = sizeof(ct), blen = sizeof(back);
    CK_RV rv;

    NEED(p_GenerateKey); NEED(p_EncryptInit); NEED(p_Encrypt);
    NEED(p_DecryptInit); NEED(p_Decrypt);
    for (int i = 0; i < 12; ++i) iv[i] = (CK_BYTE)i;
    memset(&gcm, 0, sizeof(gcm));
    gcm.pIv = iv; gcm.ulIvLen = 12; gcm.ulIvBits = 96;
    gcm.pAAD = NULL; gcm.ulAADLen = 0; gcm.ulTagBits = 128;
    mg.mechanism = CKM_AES_GCM; mg.pParameter = &gcm; mg.ulParameterLen = sizeof(gcm);

    rv = p_GenerateKey((CK_SESSION_HANDLE)session, &keygen, tmpl, 6, &key);
    if (rv != CKR_OK) { set_err("C_GenerateKey -> 0x%08lX", (unsigned long)rv); return (int)rv; }
    rv = p_EncryptInit((CK_SESSION_HANDLE)session, &mg, key);
    if (rv != CKR_OK) { set_err("C_EncryptInit -> 0x%08lX", (unsigned long)rv); return (int)rv; }
    rv = p_Encrypt((CK_SESSION_HANDLE)session, pt, sizeof(pt) - 1, ct, &ctlen);
    if (rv != CKR_OK) { set_err("C_Encrypt -> 0x%08lX", (unsigned long)rv); return (int)rv; }
    rv = p_DecryptInit((CK_SESSION_HANDLE)session, &mg, key);
    if (rv != CKR_OK) { set_err("C_DecryptInit -> 0x%08lX", (unsigned long)rv); return (int)rv; }
    rv = p_Decrypt((CK_SESSION_HANDLE)session, ct, ctlen, back, &blen);
    if (rv != CKR_OK) { set_err("C_Decrypt -> 0x%08lX", (unsigned long)rv); return (int)rv; }
    {
        int ok = (blen == sizeof(pt) - 1) && memcmp(back, pt, blen) == 0;
        if (detail && cap > 0)
            snprintf(detail, cap, "ct=%luB, decrypt %s",
                     (unsigned long)ctlen, ok ? "OK" : "MISMATCH");
        return ok ? 0 : 1;
    }
}

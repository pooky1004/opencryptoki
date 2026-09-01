/*
 * Token NCMP - PKCS#11 provider (C_* API) test application.
 *
 * Exercises libpkcs11_ncmp.so exactly as a real application would: obtain the
 * function table via C_GetFunctionList / C_GetInterface, then drive every
 * category through the table's function pointers. An in-process ncmpd harness
 * (SHM + one comm_thread per slot + the conn_thread) stands in for the daemon,
 * and the mock FX3 backend stands in for hardware, so the whole stack runs
 * without privilege or a USB board.
 *
 * Contents:
 *   - 5 composite scenarios (S1..S5) covering concurrency, persistence,
 *     key wrapping, fault recovery, and zeroization.
 *   - 10 multi-slot / multi-session scenarios (M1..M10).
 *   - Version-mapping + vendor-interface smoke tests.
 */
#include <pkcs11types.h>
#include <apiclient.h>
#include "ncmp_vendor.h"

#include "ncmp/ncmp_shm.h"
#include "ncmp/ncmp_transport.h"
#include "ncmp/ncmp_errno.h"
#include "ncmpd.h"
#include "ncmp_test.h"

#include <pthread.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>

#define TEST_SOCK "/tmp/ncmp_ipc_p11.sock"

/* ------------------------------------------------------------------------- */
/* Multi-slot in-process daemon harness                                      */
/* ------------------------------------------------------------------------- */

typedef struct {
    void             *shm_base;
    int               nslots;
    ncmp_transport_t *t[PKCS11_MAX_SLOT_COUNT];
    ncmpd_slot_ctx_t  comm[PKCS11_MAX_SLOT_COUNT];
    ncmpd_conn_ctx_t  conn;
} mh_t;

/** Bring up @p nslots online slots (each with its own mock device). */
static int mh_up(mh_t *h, int nslots)
{
    int s;

    memset(h, 0, sizeof(*h));
    h->nslots = nslots;
    (void)ncmp_shm_destroy(NULL);
    if (ncmp_shm_create(&h->shm_base) != NCMP_OK)
        return -1;

    for (s = 0; s < nslots; ++s) {
        NCMP_Slot *slot = ncmp_shm_slot(h->shm_base, (uint32_t)s);

        slot->state = NCMP_SLOT_ONLINE;
        if (ncmp_transport_open((uint32_t)s, &h->t[s]) != NCMP_OK)
            return -1;
        h->comm[s].shm_base = h->shm_base;
        h->comm[s].slot = slot;
        h->comm[s].slot_id = (uint32_t)s;
        h->comm[s].transport = h->t[s];
        if (pthread_create(&h->comm[s].thread, NULL, ncmpd_comm_thread,
                           &h->comm[s]))
            return -1;
    }
    h->conn.shm_base = h->shm_base;
    h->conn.sock_path = TEST_SOCK;
    if (pthread_create(&h->conn.thread, NULL, ncmpd_conn_thread, &h->conn))
        return -1;
    return 0;
}

static void mh_down(mh_t *h)
{
    int s;

    ncmpd_request_stop(&h->conn.stop);
    pthread_join(h->conn.thread, NULL);
    for (s = 0; s < h->nslots; ++s) {
        ncmpd_request_stop(&h->comm[s].stop);
        pthread_join(h->comm[s].thread, NULL);
        ncmp_transport_close(h->t[s]);
    }
    ncmp_shm_destroy(h->shm_base);
}

/* ------------------------------------------------------------------------- */
/* Small helpers                                                             */
/* ------------------------------------------------------------------------- */

static CK_BBOOL CK_T = CK_TRUE;
static CK_BBOOL CK_F = CK_FALSE;

/** Obtain the 2.40 function list (retrying while conn_thread binds). */
static CK_RV get_functions(CK_FUNCTION_LIST **out)
{
    return C_GetFunctionList(out);
}

/** Initialize Cryptoki with OS locking and connect via the test socket. */
static CK_RV p11_up(CK_FUNCTION_LIST *F)
{
    CK_C_INITIALIZE_ARGS args;
    int i;
    CK_RV rv = CKR_TOKEN_NOT_PRESENT;

    memset(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    setenv("NCMP_SOCK_PATH", TEST_SOCK, 1);
    setenv("NCMP_SLOT_BASE", "0", 1);

    /* The conn_thread may not have bound the socket yet; retry Initialize. */
    for (i = 0; i < 2000; ++i) {
        CK_ULONG n = 0;

        rv = F->C_Initialize(&args);
        if (rv != CKR_OK)
            return rv;
        if (F->C_GetSlotList(CK_TRUE, NULL, &n) == CKR_OK && n > 0)
            return CKR_OK;
        F->C_Finalize(NULL);
        sched_yield();
    }
    return rv;
}

/** Destroy every token object on all slots (clean slate between tests). */
static void zeroize_all(CK_FUNCTION_LIST *F, int nslots)
{
    int s;

    for (s = 0; s < nslots; ++s)
        (void)F->C_InitToken((CK_SLOT_ID)s, (CK_CHAR_PTR)"sopin", 5,
                             (CK_CHAR_PTR)"tok");
}

/** Open an R/W session and log the USER in. */
static CK_RV open_user(CK_FUNCTION_LIST *F, CK_SLOT_ID slot,
                       CK_SESSION_HANDLE *hs)
{
    CK_RV rv = F->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                NULL, NULL, hs);
    if (rv != CKR_OK)
        return rv;
    rv = F->C_Login(*hs, CKU_USER, (CK_CHAR_PTR)"1234", 4);
    if (rv == CKR_USER_ALREADY_LOGGED_IN)
        rv = CKR_OK;
    return rv;
}

/** Generate a session AES-256 key with encrypt/decrypt usage. */
static CK_RV gen_aes(CK_FUNCTION_LIST *F, CK_SESSION_HANDLE hs, int token,
                     CK_OBJECT_HANDLE *hk)
{
    CK_MECHANISM m = { CKM_AES_KEY_GEN, NULL, 0 };
    CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
    CK_KEY_TYPE kt = CKK_AES;
    CK_ULONG len = 32;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &cls, sizeof(cls) },
        { CKA_KEY_TYPE, &kt, sizeof(kt) },
        { CKA_VALUE_LEN, &len, sizeof(len) },
        { CKA_TOKEN, token ? &CK_T : &CK_F, sizeof(CK_BBOOL) },
        { CKA_ENCRYPT, &CK_T, sizeof(CK_BBOOL) },
        { CKA_DECRYPT, &CK_T, sizeof(CK_BBOOL) },
    };
    return F->C_GenerateKey(hs, &m, tmpl, 6, hk);
}

/** One AES-GCM encrypt+decrypt round-trip; returns 0 on match. */
static int gcm_roundtrip(CK_FUNCTION_LIST *F, CK_SESSION_HANDLE hs,
                         CK_OBJECT_HANDLE hk)
{
    CK_BYTE iv[12], aad[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    CK_GCM_PARAMS gp;
    CK_MECHANISM m;
    CK_BYTE pt[40], ct[64], rt[64];
    CK_ULONG ctlen = sizeof(ct), rtlen = sizeof(rt);
    int i;

    for (i = 0; i < 12; ++i) iv[i] = (CK_BYTE)(0xA0 + i);
    for (i = 0; i < 40; ++i) pt[i] = (CK_BYTE)(i * 7 + 1);
    memset(&gp, 0, sizeof(gp));
    gp.pIv = iv; gp.ulIvLen = 12; gp.ulIvBits = 96;
    gp.pAAD = aad; gp.ulAADLen = sizeof(aad); gp.ulTagBits = 128;
    m.mechanism = CKM_AES_GCM; m.pParameter = &gp; m.ulParameterLen = sizeof(gp);

    if (F->C_EncryptInit(hs, &m, hk) != CKR_OK)
        return 1;
    if (F->C_Encrypt(hs, pt, sizeof(pt), ct, &ctlen) != CKR_OK)
        return 1;
    if (ctlen != sizeof(pt) + 16)
        return 1;
    if (F->C_DecryptInit(hs, &m, hk) != CKR_OK)
        return 1;
    if (F->C_Decrypt(hs, ct, ctlen, rt, &rtlen) != CKR_OK)
        return 1;
    if (rtlen != sizeof(pt) || memcmp(rt, pt, sizeof(pt)) != 0)
        return 1;
    return 0;
}

/* ========================================================================= */
/* Version mapping + vendor interface smoke tests                            */
/* ========================================================================= */

int test_p11_version_mapping(void)
{
    mh_t h;
    CK_FUNCTION_LIST *F = NULL;
    CK_FUNCTION_LIST_3_0 *F30 = NULL;
    CK_INTERFACE_PTR iface = NULL;
    CK_VERSION v30 = { 3, 0 };

    NCMP_CHECK(mh_up(&h, 1) == 0);
    NCMP_CHECK(get_functions(&F) == CKR_OK && F != NULL);
    NCMP_CHECK(F->C_GetFunctionList != NULL);
    NCMP_CHECK(F->C_Encrypt != NULL && F->C_GenerateKeyPair != NULL);
    NCMP_CHECK(p11_up(F) == CKR_OK);

    /* 3.0 interface exposes the message-based entry points. */
    NCMP_CHECK(C_GetInterface((CK_UTF8CHAR_PTR)"PKCS 11", &v30, &iface, 0)
               == CKR_OK);
    F30 = (CK_FUNCTION_LIST_3_0 *)iface->pFunctionList;
    NCMP_CHECK(F30->version.major == 3 && F30->version.minor == 0);
    NCMP_CHECK(F30->C_MessageEncryptInit != NULL && F30->C_LoginUser != NULL);

    /* Default interface (name+version NULL) is the newest (3.2). */
    NCMP_CHECK(C_GetInterface(NULL, NULL, &iface, 0) == CKR_OK);
    NCMP_CHECK(((CK_VERSION *)iface->pFunctionList)->major == 3);

    F->C_Finalize(NULL);
    mh_down(&h);
    return 0;
}

int test_p11_vendor_interface(void)
{
    mh_t h;
    CK_FUNCTION_LIST *F = NULL;
    CK_INTERFACE_PTR iface = NULL;
    CK_NCMP_VENDOR_FUNCTION_LIST *V;
    CK_SESSION_HANDLE hs;
    CK_BYTE msg[16], echo[16], readback[16];
    CK_ULONG n = sizeof(echo), epoch = 0, st = 0xFF, crc = 0;
    int i;

    NCMP_CHECK(mh_up(&h, 1) == 0);
    NCMP_CHECK(get_functions(&F) == CKR_OK);
    NCMP_CHECK(p11_up(F) == CKR_OK);
    NCMP_CHECK(F->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL,
                                NULL, &hs) == CKR_OK);

    NCMP_CHECK(C_GetInterface((CK_UTF8CHAR_PTR)NCMP_VENDOR_INTERFACE_NAME, NULL,
                              &iface, 0) == CKR_OK);
    V = (CK_NCMP_VENDOR_FUNCTION_LIST *)iface->pFunctionList;

    /* Token loopback. */
    for (i = 0; i < 16; ++i) msg[i] = (CK_BYTE)(i + 0x11);
    NCMP_CHECK(V->NCMP_Loopback(hs, msg, sizeof(msg), echo, &n) == CKR_OK);
    NCMP_CHECK(n == sizeof(msg) && memcmp(msg, echo, 16) == 0);

    /* Memory write then read-back. */
    NCMP_CHECK(V->NCMP_MemWrite(hs, 0x40, msg, sizeof(msg)) == CKR_OK);
    memset(readback, 0, sizeof(readback));
    NCMP_CHECK(V->NCMP_MemRead(hs, 0x40, readback, sizeof(readback)) == CKR_OK);
    NCMP_CHECK(memcmp(msg, readback, 16) == 0);

    /* Fill + CRC is stable across identical fills. */
    NCMP_CHECK(V->NCMP_MemFill(hs, 0, 256, 0xAB) == CKR_OK);
    NCMP_CHECK(V->NCMP_MemCRC(hs, 0, 256, &crc) == CKR_OK);
    {
        CK_ULONG crc2 = 0;
        NCMP_CHECK(V->NCMP_MemCRC(hs, 0, 256, &crc2) == CKR_OK && crc2 == crc);
    }

    /* Health + identity. */
    NCMP_CHECK(V->NCMP_SelfTest(hs, &st) == CKR_OK && st == 0);
    NCMP_CHECK(V->NCMP_Ping(hs, &epoch) == CKR_OK && epoch >= 1); /* bumped */
    {
        CK_ULONG maj = 0, min = 9, pat = 9, bld = 0;
        NCMP_CHECK(V->NCMP_FirmwareInfo(hs, &maj, &min, &pat, &bld) == CKR_OK);
        NCMP_CHECK(maj == 1 && min == 0);
    }

    /* Host-side introspection. */
    {
        CK_ULONG cur = 9, mx = 9, tot = 0, phys = 9, lvl = 9;
        CK_CHAR label[64];
        NCMP_CHECK(V->NCMP_GetInFlight(hs, &cur, &mx, &tot) == CKR_OK);
        NCMP_CHECK(V->NCMP_GetSlotMap(0, &phys, label, sizeof(label)) == CKR_OK);
        NCMP_CHECK(phys == 0);
        NCMP_CHECK(V->NCMP_SetLogLevel(2) == CKR_OK);
        NCMP_CHECK(V->NCMP_GetLogLevel(&lvl) == CKR_OK && lvl == 2);
    }
    {
        CK_BYTE hin[4] = { 9, 8, 7, 6 }, hout[4];
        CK_ULONG hn = sizeof(hout);
        NCMP_CHECK(V->NCMP_HostEcho(hin, 4, hout, &hn) == CKR_OK);
        NCMP_CHECK(hn == 4 && memcmp(hin, hout, 4) == 0);
    }

    F->C_CloseSession(hs);
    F->C_Finalize(NULL);
    mh_down(&h);
    return 0;
}

/* ========================================================================= */
/* S1: Multi-threaded concurrency & session isolation                        */
/* ========================================================================= */

#define S1_THREADS 8
#define S1_ITERS 200

typedef struct {
    CK_FUNCTION_LIST *F;
    CK_SLOT_ID slot;
    int fail;
    CK_OBJECT_HANDLE key;
} s1_arg_t;

static void *s1_worker(void *p)
{
    s1_arg_t *a = (s1_arg_t *)p;
    CK_SESSION_HANDLE hs;
    int i;

    if (open_user(a->F, a->slot, &hs) != CKR_OK) { a->fail = 1; return NULL; }
    if (gen_aes(a->F, hs, 0, &a->key) != CKR_OK) { a->fail = 2;
        a->F->C_CloseSession(hs); return NULL; }

    for (i = 0; i < S1_ITERS; ++i) {
        if (gcm_roundtrip(a->F, hs, a->key) != 0) { a->fail = 3; break; }
    }

    /* Handle validation: a bogus key handle is rejected. */
    {
        CK_MECHANISM m = { CKM_AES_ECB, NULL, 0 };
        if (a->F->C_EncryptInit(hs, &m, (CK_OBJECT_HANDLE)0xDEADBEEF)
            != CKR_KEY_HANDLE_INVALID)
            a->fail = 4;
    }

    a->F->C_DestroyObject(hs, a->key);
    a->F->C_Logout(hs);
    a->F->C_CloseSession(hs);
    return NULL;
}

int test_p11_s1_concurrency(void)
{
    mh_t h;
    CK_FUNCTION_LIST *F = NULL;
    pthread_t th[S1_THREADS];
    s1_arg_t args[S1_THREADS];
    int i;

    NCMP_CHECK(mh_up(&h, 1) == 0);
    NCMP_CHECK(get_functions(&F) == CKR_OK);
    NCMP_CHECK(p11_up(F) == CKR_OK);
    zeroize_all(F, 1);

    for (i = 0; i < S1_THREADS; ++i) {
        args[i].F = F; args[i].slot = 0; args[i].fail = 0; args[i].key = 0;
        NCMP_CHECK(pthread_create(&th[i], NULL, s1_worker, &args[i]) == 0);
    }
    for (i = 0; i < S1_THREADS; ++i) {
        pthread_join(th[i], NULL);
        NCMP_CHECK(args[i].fail == 0);
    }
    /* Each worker used a distinct key handle. */
    for (i = 1; i < S1_THREADS; ++i)
        NCMP_CHECK(args[i].key != args[0].key);

    F->C_Finalize(NULL);
    mh_down(&h);
    return 0;
}

/* ========================================================================= */
/* S2: Token key persistence + backup/restore integrity (ECDSA P-384)        */
/*                                                                           */
/* "Power cycle" is modeled as C_Finalize + C_Initialize in-process; token   */
/* objects persist across it (this provider keeps them until zeroization).   */
/* The non-extractable private key is re-used after the cycle; the public    */
/* key is exported (backup) and re-imported (restore) to verify a stored     */
/* signature.                                                                */
/* ========================================================================= */

int test_p11_s2_persistence(void)
{
    mh_t h;
    CK_FUNCTION_LIST *F = NULL;
    CK_SESSION_HANDLE hs;
    CK_OBJECT_HANDLE hpub, hpriv;
    CK_BYTE ecparams[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 }; /* P-384 */
    CK_MECHANISM kg = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_MECHANISM sig = { CKM_ECDSA, NULL, 0 };
    CK_BYTE data[48], signature[256], point[256];
    CK_ULONG siglen = sizeof(signature), pointlen = sizeof(point);
    int i;

    NCMP_CHECK(mh_up(&h, 1) == 0);
    NCMP_CHECK(get_functions(&F) == CKR_OK);
    NCMP_CHECK(p11_up(F) == CKR_OK);
    zeroize_all(F, 1);

    /* Generate a token EC key pair (private non-extractable). */
    {
        CK_OBJECT_CLASS pubc = CKO_PUBLIC_KEY, privc = CKO_PRIVATE_KEY;
        CK_ATTRIBUTE pub[] = {
            { CKA_CLASS, &pubc, sizeof(pubc) },
            { CKA_EC_PARAMS, ecparams, sizeof(ecparams) },
            { CKA_TOKEN, &CK_T, sizeof(CK_BBOOL) },
            { CKA_VERIFY, &CK_T, sizeof(CK_BBOOL) },
        };
        CK_ATTRIBUTE priv[] = {
            { CKA_CLASS, &privc, sizeof(privc) },
            { CKA_TOKEN, &CK_T, sizeof(CK_BBOOL) },
            { CKA_PRIVATE, &CK_T, sizeof(CK_BBOOL) },
            { CKA_SIGN, &CK_T, sizeof(CK_BBOOL) },
            { CKA_EXTRACTABLE, &CK_F, sizeof(CK_BBOOL) },
        };
        NCMP_CHECK(open_user(F, 0, &hs) == CKR_OK);
        NCMP_CHECK(F->C_GenerateKeyPair(hs, &kg, pub, 4, priv, 5, &hpub, &hpriv)
                   == CKR_OK);
    }

    for (i = 0; i < 48; ++i) data[i] = (CK_BYTE)(i + 3);
    NCMP_CHECK(F->C_SignInit(hs, &sig, hpriv) == CKR_OK);
    NCMP_CHECK(F->C_Sign(hs, data, sizeof(data), signature, &siglen) == CKR_OK);

    /* Backup: export the public EC point. */
    {
        CK_ATTRIBUTE q = { CKA_EC_POINT, point, sizeof(point) };
        NCMP_CHECK(F->C_GetAttributeValue(hs, hpub, &q, 1) == CKR_OK);
        pointlen = q.ulValueLen;
    }
    /* Non-extractable private key: CKA_VALUE must be sensitive. */
    {
        CK_ATTRIBUTE v = { CKA_VALUE, NULL, 0 };
        NCMP_CHECK(F->C_GetAttributeValue(hs, hpriv, &v, 1)
                   == CKR_ATTRIBUTE_SENSITIVE);
    }

    /* Power cycle. */
    NCMP_CHECK(F->C_CloseSession(hs) == CKR_OK);
    NCMP_CHECK(F->C_Finalize(NULL) == CKR_OK);
    NCMP_CHECK(F->C_Initialize(NULL) == CKR_OK);
    NCMP_CHECK(open_user(F, 0, &hs) == CKR_OK);

    /* The token key pair survived the cycle: find the private key again. */
    {
        CK_OBJECT_CLASS privc = CKO_PRIVATE_KEY;
        CK_ATTRIBUTE find[] = { { CKA_CLASS, &privc, sizeof(privc) } };
        CK_OBJECT_HANDLE found[4];
        CK_ULONG nf = 0;

        NCMP_CHECK(F->C_FindObjectsInit(hs, find, 1) == CKR_OK);
        NCMP_CHECK(F->C_FindObjects(hs, found, 4, &nf) == CKR_OK);
        NCMP_CHECK(F->C_FindObjectsFinal(hs) == CKR_OK);
        NCMP_CHECK(nf >= 1);
        hpriv = found[0];
    }
    /* Restore: re-import the public key as a session object from the backup. */
    {
        CK_OBJECT_CLASS pubc = CKO_PUBLIC_KEY;
        CK_KEY_TYPE kt = CKK_EC;
        CK_ATTRIBUTE imp[] = {
            { CKA_CLASS, &pubc, sizeof(pubc) },
            { CKA_KEY_TYPE, &kt, sizeof(kt) },
            { CKA_EC_PARAMS, ecparams, sizeof(ecparams) },
            { CKA_EC_POINT, point, pointlen },
            { CKA_VERIFY, &CK_T, sizeof(CK_BBOOL) },
        };
        NCMP_CHECK(F->C_CreateObject(hs, imp, 5, &hpub) == CKR_OK);
    }
    /* Verify the stored signature with the restored public key. */
    NCMP_CHECK(F->C_VerifyInit(hs, &sig, hpub) == CKR_OK);
    NCMP_CHECK(F->C_Verify(hs, data, sizeof(data), signature, siglen)
               == CKR_OK);
    /* Tamper detection still works after restore. */
    signature[0] ^= 0xFF;
    NCMP_CHECK(F->C_VerifyInit(hs, &sig, hpub) == CKR_OK);
    NCMP_CHECK(F->C_Verify(hs, data, sizeof(data), signature, siglen)
               == CKR_SIGNATURE_INVALID);

    NCMP_CHECK(F->C_CloseAllSessions(0) == CKR_OK);
    F->C_Finalize(NULL);
    mh_down(&h);
    return 0;
}

/* ========================================================================= */
/* S3: Hybrid key wrapping + multi-algorithm pipeline                        */
/* ========================================================================= */

int test_p11_s3_keywrap(void)
{
    mh_t h;
    CK_FUNCTION_LIST *F = NULL;
    CK_SESSION_HANDLE hs;
    CK_OBJECT_HANDLE hwpub, hwpriv, hkeyA, hkeyB;
    CK_MECHANISM rsagen = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
    CK_MECHANISM oaep = { CKM_RSA_PKCS_OAEP, NULL, 0 };
    CK_BYTE wrapped[512];
    CK_ULONG wlen = sizeof(wrapped);
    CK_BYTE iv[16], pt[64], ct[128], rt[128];
    CK_ULONG ctlen = sizeof(ct), rtlen = sizeof(rt);
    int i;

    NCMP_CHECK(mh_up(&h, 1) == 0);
    NCMP_CHECK(get_functions(&F) == CKR_OK);
    NCMP_CHECK(p11_up(F) == CKR_OK);
    zeroize_all(F, 1);
    NCMP_CHECK(open_user(F, 0, &hs) == CKR_OK);

    /* 4096-bit RSA wrapping key pair. */
    {
        CK_OBJECT_CLASS pubc = CKO_PUBLIC_KEY, privc = CKO_PRIVATE_KEY;
        CK_ULONG bits = 4096;
        CK_BYTE e[] = { 0x01, 0x00, 0x01 };
        CK_ATTRIBUTE pub[] = {
            { CKA_CLASS, &pubc, sizeof(pubc) },
            { CKA_MODULUS_BITS, &bits, sizeof(bits) },
            { CKA_PUBLIC_EXPONENT, e, sizeof(e) },
            { CKA_WRAP, &CK_T, sizeof(CK_BBOOL) },
        };
        CK_ATTRIBUTE priv[] = {
            { CKA_CLASS, &privc, sizeof(privc) },
            { CKA_PRIVATE, &CK_T, sizeof(CK_BBOOL) },
            { CKA_UNWRAP, &CK_T, sizeof(CK_BBOOL) },
        };
        NCMP_CHECK(F->C_GenerateKeyPair(hs, &rsagen, pub, 4, priv, 2,
                                        &hwpub, &hwpriv) == CKR_OK);
    }
    /* Extractable AES key (Key-A). */
    {
        CK_MECHANISM m = { CKM_AES_KEY_GEN, NULL, 0 };
        CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
        CK_KEY_TYPE kt = CKK_AES;
        CK_ULONG len = 32;
        CK_ATTRIBUTE t[] = {
            { CKA_CLASS, &cls, sizeof(cls) },
            { CKA_KEY_TYPE, &kt, sizeof(kt) },
            { CKA_VALUE_LEN, &len, sizeof(len) },
            { CKA_EXTRACTABLE, &CK_T, sizeof(CK_BBOOL) },
            { CKA_ENCRYPT, &CK_T, sizeof(CK_BBOOL) },
            { CKA_DECRYPT, &CK_T, sizeof(CK_BBOOL) },
        };
        NCMP_CHECK(F->C_GenerateKey(hs, &m, t, 6, &hkeyA) == CKR_OK);
    }

    /* Wrap Key-A with the RSA public key. */
    NCMP_CHECK(F->C_WrapKey(hs, &oaep, hwpub, hkeyA, wrapped, &wlen) == CKR_OK);
    NCMP_CHECK(wlen == 512);
    /* Destroy the original Key-A. */
    NCMP_CHECK(F->C_DestroyObject(hs, hkeyA) == CKR_OK);
    /* Unwrap into Key-B. */
    {
        CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
        CK_KEY_TYPE kt = CKK_AES;
        CK_ATTRIBUTE t[] = {
            { CKA_CLASS, &cls, sizeof(cls) },
            { CKA_KEY_TYPE, &kt, sizeof(kt) },
            { CKA_ENCRYPT, &CK_T, sizeof(CK_BBOOL) },
            { CKA_DECRYPT, &CK_T, sizeof(CK_BBOOL) },
        };
        NCMP_CHECK(F->C_UnwrapKey(hs, &oaep, hwpriv, wrapped, wlen, t, 4,
                                  &hkeyB) == CKR_OK);
    }

    /* Multi-boundary CBC_PAD pipeline with Key-B. */
    for (i = 0; i < 16; ++i) iv[i] = (CK_BYTE)(0xC0 + i);
    for (i = 0; i < 64; ++i) pt[i] = (CK_BYTE)(i * 3 + 5);
    {
        CK_MECHANISM m = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
        CK_ULONG off = 0, part;
        CK_BYTE tmp[128];
        CK_ULONG tlen;

        NCMP_CHECK(F->C_EncryptInit(hs, &m, hkeyB) == CKR_OK);
        /* Feed in three uneven parts. */
        ctlen = 0;
        { CK_ULONG chunks[3] = { 20, 30, 14 }; int k;
          for (k = 0; k < 3; ++k) {
            part = chunks[k]; tlen = sizeof(tmp);
            NCMP_CHECK(F->C_EncryptUpdate(hs, pt + off, part, tmp, &tlen)
                       == CKR_OK);
            memcpy(ct + ctlen, tmp, tlen); ctlen += tlen; off += part;
          } }
        tlen = sizeof(tmp);
        NCMP_CHECK(F->C_EncryptFinal(hs, tmp, &tlen) == CKR_OK);
        memcpy(ct + ctlen, tmp, tlen); ctlen += tlen;
        NCMP_CHECK(ctlen == 80); /* 64 padded up to next block multiple */
    }
    {
        CK_MECHANISM m = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
        NCMP_CHECK(F->C_DecryptInit(hs, &m, hkeyB) == CKR_OK);
        rtlen = sizeof(rt);
        {
            CK_BYTE tmp[128]; CK_ULONG tlen = sizeof(tmp), rt_off = 0;
            NCMP_CHECK(F->C_DecryptUpdate(hs, ct, ctlen, tmp, &tlen) == CKR_OK);
            memcpy(rt, tmp, tlen); rt_off = tlen;
            tlen = sizeof(tmp);
            NCMP_CHECK(F->C_DecryptFinal(hs, tmp, &tlen) == CKR_OK);
            memcpy(rt + rt_off, tmp, tlen); rt_off += tlen;
            rtlen = rt_off;
        }
    }
    NCMP_CHECK(rtlen == 64 && memcmp(rt, pt, 64) == 0);

    NCMP_CHECK(F->C_CloseSession(hs) == CKR_OK);
    F->C_Finalize(NULL);
    mh_down(&h);
    return 0;
}

/* ========================================================================= */
/* S4: Fault injection & exception recovery                                  */
/* ========================================================================= */

int test_p11_s4_faults(void)
{
    mh_t h;
    CK_FUNCTION_LIST *F = NULL;
    CK_SESSION_HANDLE hs, hs2;
    CK_OBJECT_HANDLE hk;
    CK_MECHANISM m;
    CK_BYTE data[32], out[64];
    CK_ULONG outlen = sizeof(out);
    int i;

    NCMP_CHECK(mh_up(&h, 1) == 0);
    NCMP_CHECK(get_functions(&F) == CKR_OK);
    NCMP_CHECK(p11_up(F) == CKR_OK);
    zeroize_all(F, 1);
    NCMP_CHECK(open_user(F, 0, &hs) == CKR_OK);

    /* AES key that may NOT encrypt (CKA_ENCRYPT=FALSE, CKA_DECRYPT=TRUE). */
    {
        CK_MECHANISM kg = { CKM_AES_KEY_GEN, NULL, 0 };
        CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
        CK_KEY_TYPE kt = CKK_AES;
        CK_ULONG len = 32;
        CK_ATTRIBUTE t[] = {
            { CKA_CLASS, &cls, sizeof(cls) },
            { CKA_KEY_TYPE, &kt, sizeof(kt) },
            { CKA_VALUE_LEN, &len, sizeof(len) },
            { CKA_ENCRYPT, &CK_F, sizeof(CK_BBOOL) },
            { CKA_DECRYPT, &CK_T, sizeof(CK_BBOOL) },
        };
        NCMP_CHECK(F->C_GenerateKey(hs, &kg, t, 5, &hk) == CKR_OK);
    }
    /* Unauthorized use -> CKR_KEY_FUNCTION_NOT_PERMITTED. */
    m.mechanism = CKM_AES_ECB; m.pParameter = NULL; m.ulParameterLen = 0;
    NCMP_CHECK(F->C_EncryptInit(hs, &m, hk) == CKR_KEY_FUNCTION_NOT_PERMITTED);

    /* Bad GCM parameters (zero-length IV) -> CKR_MECHANISM_PARAM_INVALID. */
    {
        CK_GCM_PARAMS gp;
        memset(&gp, 0, sizeof(gp));
        gp.pIv = NULL; gp.ulIvLen = 0; gp.ulTagBits = 128;
        m.mechanism = CKM_AES_GCM; m.pParameter = &gp;
        m.ulParameterLen = sizeof(gp);
        NCMP_CHECK(F->C_DecryptInit(hs, &m, hk) == CKR_MECHANISM_PARAM_INVALID);
    }

    /* State recovered: a correct key + operation succeeds afterwards. */
    {
        CK_OBJECT_HANDLE hk2;
        NCMP_CHECK(gen_aes(F, hs, 0, &hk2) == CKR_OK);
        for (i = 0; i < 32; ++i) data[i] = (CK_BYTE)(i + 1);
        m.mechanism = CKM_AES_ECB; m.pParameter = NULL; m.ulParameterLen = 0;
        outlen = sizeof(out);
        NCMP_CHECK(F->C_EncryptInit(hs, &m, hk2) == CKR_OK);
        NCMP_CHECK(F->C_Encrypt(hs, data, 32, out, &outlen) == CKR_OK);
        NCMP_CHECK(outlen == 32);
    }

    /* "Timeout": close the session; the stale handle is then invalid. */
    NCMP_CHECK(F->C_CloseSession(hs) == CKR_OK);
    m.mechanism = CKM_AES_ECB; m.pParameter = NULL; m.ulParameterLen = 0;
    NCMP_CHECK(F->C_EncryptInit(hs, &m, hk) == CKR_SESSION_HANDLE_INVALID);

    /* Recovery: a fresh session + login works. */
    NCMP_CHECK(open_user(F, 0, &hs2) == CKR_OK);
    NCMP_CHECK(F->C_CloseSession(hs2) == CKR_OK);

    F->C_Finalize(NULL);
    mh_down(&h);
    return 0;
}

/* ========================================================================= */
/* S5: Slot state scan + zeroization / factory reset                         */
/* ========================================================================= */

int test_p11_s5_zeroize(void)
{
    mh_t h;
    CK_FUNCTION_LIST *F = NULL;
    CK_SESSION_HANDLE hs;
    CK_SLOT_ID slots[PKCS11_MAX_SLOT_COUNT];
    CK_ULONG nslots = PKCS11_MAX_SLOT_COUNT;
    CK_SLOT_INFO si;
    CK_TOKEN_INFO ti;
    int i;

    NCMP_CHECK(mh_up(&h, 3) == 0);
    NCMP_CHECK(get_functions(&F) == CKR_OK);
    NCMP_CHECK(p11_up(F) == CKR_OK);
    zeroize_all(F, 3);

    /* Scan slots. */
    NCMP_CHECK(F->C_GetSlotList(CK_TRUE, slots, &nslots) == CKR_OK);
    NCMP_CHECK(nslots == 3);
    NCMP_CHECK(F->C_GetSlotInfo(slots[0], &si) == CKR_OK);
    NCMP_CHECK((si.flags & CKF_TOKEN_PRESENT) && (si.flags & CKF_HW_SLOT));
    NCMP_CHECK(F->C_GetTokenInfo(slots[0], &ti) == CKR_OK);
    NCMP_CHECK(ti.flags & CKF_RNG);

    /* Populate slot 0 with many temporary token keys. */
    NCMP_CHECK(open_user(F, slots[0], &hs) == CKR_OK);
    for (i = 0; i < 20; ++i) {
        CK_OBJECT_HANDLE hk;
        NCMP_CHECK(gen_aes(F, hs, 1 /* token */, &hk) == CKR_OK);
    }
    /* Enumerate them. */
    {
        CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
        CK_ATTRIBUTE find[] = { { CKA_CLASS, &cls, sizeof(cls) } };
        CK_OBJECT_HANDLE found[64];
        CK_ULONG nf = 0;
        NCMP_CHECK(F->C_FindObjectsInit(hs, find, 1) == CKR_OK);
        NCMP_CHECK(F->C_FindObjects(hs, found, 64, &nf) == CKR_OK);
        NCMP_CHECK(F->C_FindObjectsFinal(hs) == CKR_OK);
        NCMP_CHECK(nf == 20);
    }
    /* Close the session, then zeroize via C_InitToken (SO). */
    NCMP_CHECK(F->C_CloseSession(hs) == CKR_OK);
    NCMP_CHECK(F->C_InitToken(slots[0], (CK_CHAR_PTR)"sopin", 5,
                              (CK_CHAR_PTR)"tok") == CKR_OK);
    /* After reset, no objects remain. */
    NCMP_CHECK(open_user(F, slots[0], &hs) == CKR_OK);
    {
        CK_OBJECT_HANDLE found[64];
        CK_ULONG nf = 0;
        NCMP_CHECK(F->C_FindObjectsInit(hs, NULL, 0) == CKR_OK);
        NCMP_CHECK(F->C_FindObjects(hs, found, 64, &nf) == CKR_OK);
        NCMP_CHECK(F->C_FindObjectsFinal(hs) == CKR_OK);
        NCMP_CHECK(nf == 0);
    }
    NCMP_CHECK(F->C_CloseSession(hs) == CKR_OK);
    F->C_Finalize(NULL);
    mh_down(&h);
    return 0;
}

/* ========================================================================= */
/* M1..M10: Multi-slot / multi-session scenarios                             */
/* ========================================================================= */

/* M1: per-slot session ceiling (PKCS11_MAX_SESSION_PER_SLOT). */
int test_p11_m1_session_ceiling(void)
{
    mh_t h;
    CK_FUNCTION_LIST *F = NULL;
    CK_SESSION_HANDLE hs[PKCS11_MAX_SESSION_PER_SLOT + 1];
    CK_SESSION_HANDLE extra;
    int i;

    NCMP_CHECK(mh_up(&h, 1) == 0);
    NCMP_CHECK(get_functions(&F) == CKR_OK);
    NCMP_CHECK(p11_up(F) == CKR_OK);
    zeroize_all(F, 1);

    for (i = 0; i < PKCS11_MAX_SESSION_PER_SLOT; ++i)
        NCMP_CHECK(F->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                    NULL, NULL, &hs[i]) == CKR_OK);
    /* One past the ceiling is rejected. */
    NCMP_CHECK(F->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL,
                                NULL, &extra) == CKR_SESSION_COUNT);
    /* Freeing one lets a new session open. */
    NCMP_CHECK(F->C_CloseSession(hs[0]) == CKR_OK);
    NCMP_CHECK(F->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL,
                                NULL, &hs[0]) == CKR_OK);

    NCMP_CHECK(F->C_CloseAllSessions(0) == CKR_OK);
    F->C_Finalize(NULL);
    mh_down(&h);
    return 0;
}

/* M2: one session per slot, each drawing random bytes. */
int test_p11_m2_per_slot_rng(void)
{
    mh_t h;
    CK_FUNCTION_LIST *F = NULL;
    CK_SESSION_HANDLE hs;
    CK_BYTE buf[32];
    int s;

    NCMP_CHECK(mh_up(&h, 3) == 0);
    NCMP_CHECK(get_functions(&F) == CKR_OK);
    NCMP_CHECK(p11_up(F) == CKR_OK);

    for (s = 0; s < 3; ++s) {
        NCMP_CHECK(F->C_OpenSession((CK_SLOT_ID)s,
                                    CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL,
                                    NULL, &hs) == CKR_OK);
        memset(buf, 0, sizeof(buf));
        NCMP_CHECK(F->C_GenerateRandom(hs, buf, sizeof(buf)) == CKR_OK);
        NCMP_CHECK(F->C_CloseSession(hs) == CKR_OK);
    }
    F->C_Finalize(NULL);
    mh_down(&h);
    return 0;
}

/* M3: round-robin AES-GCM encrypt/decrypt across every slot. */
int test_p11_m3_roundrobin_aes(void)
{
    mh_t h;
    CK_FUNCTION_LIST *F = NULL;
    CK_SESSION_HANDLE hs;
    CK_OBJECT_HANDLE hk;
    int s;

    NCMP_CHECK(mh_up(&h, 3) == 0);
    NCMP_CHECK(get_functions(&F) == CKR_OK);
    NCMP_CHECK(p11_up(F) == CKR_OK);
    zeroize_all(F, 3);

    for (s = 0; s < 3; ++s) {
        NCMP_CHECK(open_user(F, (CK_SLOT_ID)s, &hs) == CKR_OK);
        NCMP_CHECK(gen_aes(F, hs, 0, &hk) == CKR_OK);
        NCMP_CHECK(gcm_roundtrip(F, hs, hk) == 0);
        NCMP_CHECK(F->C_CloseSession(hs) == CKR_OK);
    }
    F->C_Finalize(NULL);
    mh_down(&h);
    return 0;
}

/* M4: objects created on one slot are invisible on another. */
int test_p11_m4_slot_isolation(void)
{
    mh_t h;
    CK_FUNCTION_LIST *F = NULL;
    CK_SESSION_HANDLE hs0, hs0b, hs1;
    CK_OBJECT_HANDLE hk;
    CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
    CK_ATTRIBUTE find[] = { { CKA_CLASS, &cls, sizeof(cls) } };
    CK_OBJECT_HANDLE found[8];
    CK_ULONG nf;

    NCMP_CHECK(mh_up(&h, 2) == 0);
    NCMP_CHECK(get_functions(&F) == CKR_OK);
    NCMP_CHECK(p11_up(F) == CKR_OK);
    zeroize_all(F, 2);

    NCMP_CHECK(open_user(F, 0, &hs0) == CKR_OK);
    NCMP_CHECK(gen_aes(F, hs0, 1 /* token */, &hk) == CKR_OK);

    /* Another session on the SAME slot sees the token object. */
    NCMP_CHECK(open_user(F, 0, &hs0b) == CKR_OK);
    nf = 0;
    NCMP_CHECK(F->C_FindObjectsInit(hs0b, find, 1) == CKR_OK);
    NCMP_CHECK(F->C_FindObjects(hs0b, found, 8, &nf) == CKR_OK);
    NCMP_CHECK(F->C_FindObjectsFinal(hs0b) == CKR_OK);
    NCMP_CHECK(nf == 1);

    /* A session on the OTHER slot does not. */
    NCMP_CHECK(open_user(F, 1, &hs1) == CKR_OK);
    nf = 0;
    NCMP_CHECK(F->C_FindObjectsInit(hs1, find, 1) == CKR_OK);
    NCMP_CHECK(F->C_FindObjects(hs1, found, 8, &nf) == CKR_OK);
    NCMP_CHECK(F->C_FindObjectsFinal(hs1) == CKR_OK);
    NCMP_CHECK(nf == 0);

    F->C_CloseAllSessions(0);
    F->C_CloseAllSessions(1);
    F->C_Finalize(NULL);
    mh_down(&h);
    return 0;
}

/* M5: concurrent RSA key-pair generation + sign/verify, one thread per slot. */
typedef struct {
    CK_FUNCTION_LIST *F;
    CK_SLOT_ID slot;
    int fail;
} slot_arg_t;

static void *m5_worker(void *p)
{
    slot_arg_t *a = (slot_arg_t *)p;
    CK_SESSION_HANDLE hs;
    CK_OBJECT_HANDLE hpub, hpriv;
    CK_MECHANISM kg = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
    CK_MECHANISM sig = { CKM_RSA_PKCS, NULL, 0 };
    CK_BYTE data[32], s[512];
    CK_ULONG slen = sizeof(s);
    CK_OBJECT_CLASS pubc = CKO_PUBLIC_KEY, privc = CKO_PRIVATE_KEY;
    CK_ULONG bits = 2048;
    CK_BYTE e[] = { 0x01, 0x00, 0x01 };
    int i;
    CK_ATTRIBUTE pub[] = {
        { CKA_CLASS, &pubc, sizeof(pubc) },
        { CKA_MODULUS_BITS, &bits, sizeof(bits) },
        { CKA_PUBLIC_EXPONENT, e, sizeof(e) },
        { CKA_VERIFY, &CK_T, sizeof(CK_BBOOL) },
    };
    CK_ATTRIBUTE priv[] = {
        { CKA_CLASS, &privc, sizeof(privc) },
        { CKA_SIGN, &CK_T, sizeof(CK_BBOOL) },
    };

    if (open_user(a->F, a->slot, &hs) != CKR_OK) { a->fail = 1; return NULL; }
    if (a->F->C_GenerateKeyPair(hs, &kg, pub, 4, priv, 2, &hpub, &hpriv)
        != CKR_OK) { a->fail = 2; goto out; }
    for (i = 0; i < 32; ++i) data[i] = (CK_BYTE)(i + a->slot);
    if (a->F->C_SignInit(hs, &sig, hpriv) != CKR_OK) { a->fail = 3; goto out; }
    if (a->F->C_Sign(hs, data, 32, s, &slen) != CKR_OK) { a->fail = 4; goto out; }
    if (a->F->C_VerifyInit(hs, &sig, hpub) != CKR_OK) { a->fail = 5; goto out; }
    if (a->F->C_Verify(hs, data, 32, s, slen) != CKR_OK) { a->fail = 6; goto out; }
out:
    a->F->C_CloseSession(hs);
    return NULL;
}

int test_p11_m5_concurrent_keygen(void)
{
    mh_t h;
    CK_FUNCTION_LIST *F = NULL;
    pthread_t th[3];
    slot_arg_t args[3];
    int s;

    NCMP_CHECK(mh_up(&h, 3) == 0);
    NCMP_CHECK(get_functions(&F) == CKR_OK);
    NCMP_CHECK(p11_up(F) == CKR_OK);
    zeroize_all(F, 3);

    for (s = 0; s < 3; ++s) {
        args[s].F = F; args[s].slot = (CK_SLOT_ID)s; args[s].fail = 0;
        NCMP_CHECK(pthread_create(&th[s], NULL, m5_worker, &args[s]) == 0);
    }
    for (s = 0; s < 3; ++s) {
        pthread_join(th[s], NULL);
        NCMP_CHECK(args[s].fail == 0);
    }
    F->C_Finalize(NULL);
    mh_down(&h);
    return 0;
}

/* M6: cross-session sharing of session and token objects on the same slot. */
int test_p11_m6_cross_session(void)
{
    mh_t h;
    CK_FUNCTION_LIST *F = NULL;
    CK_SESSION_HANDLE hsA, hsB;
    CK_OBJECT_HANDLE htok, hsess;
    CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
    CK_ATTRIBUTE find[] = { { CKA_CLASS, &cls, sizeof(cls) } };
    CK_OBJECT_HANDLE found[8];
    CK_ULONG nf;

    NCMP_CHECK(mh_up(&h, 1) == 0);
    NCMP_CHECK(get_functions(&F) == CKR_OK);
    NCMP_CHECK(p11_up(F) == CKR_OK);
    zeroize_all(F, 1);

    NCMP_CHECK(open_user(F, 0, &hsA) == CKR_OK);
    NCMP_CHECK(gen_aes(F, hsA, 1 /* token */, &htok) == CKR_OK);
    NCMP_CHECK(gen_aes(F, hsA, 0 /* session */, &hsess) == CKR_OK);

    /* Session B (same application, same slot) sees both objects. */
    NCMP_CHECK(open_user(F, 0, &hsB) == CKR_OK);
    nf = 0;
    NCMP_CHECK(F->C_FindObjectsInit(hsB, find, 1) == CKR_OK);
    NCMP_CHECK(F->C_FindObjects(hsB, found, 8, &nf) == CKR_OK);
    NCMP_CHECK(F->C_FindObjectsFinal(hsB) == CKR_OK);
    NCMP_CHECK(nf == 2);

    /* Closing session A drops its session object but keeps the token object. */
    NCMP_CHECK(F->C_CloseSession(hsA) == CKR_OK);
    nf = 0;
    NCMP_CHECK(F->C_FindObjectsInit(hsB, find, 1) == CKR_OK);
    NCMP_CHECK(F->C_FindObjects(hsB, found, 8, &nf) == CKR_OK);
    NCMP_CHECK(F->C_FindObjectsFinal(hsB) == CKR_OK);
    NCMP_CHECK(nf == 1);

    F->C_CloseAllSessions(0);
    F->C_Finalize(NULL);
    mh_down(&h);
    return 0;
}

/* M7: many threads, each a distinct session, computing multipart SHA-256. */
#define M7_THREADS 6

typedef struct {
    CK_FUNCTION_LIST *F;
    int fail;
} m7_arg_t;

static void *m7_worker(void *p)
{
    m7_arg_t *a = (m7_arg_t *)p;
    CK_SESSION_HANDLE hs;
    CK_MECHANISM m = { CKM_SHA256, NULL, 0 };
    CK_BYTE d1[32], d2[32];
    CK_ULONG l1 = sizeof(d1), l2 = sizeof(d2);
    int i;

    if (a->F->C_OpenSession(0, CKF_SERIAL_SESSION, NULL, NULL, &hs) != CKR_OK) {
        a->fail = 1; return NULL;
    }
    for (i = 0; i < 50; ++i) {
        l1 = sizeof(d1); l2 = sizeof(d2);
        if (a->F->C_DigestInit(hs, &m) != CKR_OK) { a->fail = 2; break; }
        if (a->F->C_DigestUpdate(hs, (CK_BYTE_PTR)"hel", 3) != CKR_OK) { a->fail = 3; break; }
        if (a->F->C_DigestUpdate(hs, (CK_BYTE_PTR)"lo", 2) != CKR_OK) { a->fail = 4; break; }
        if (a->F->C_DigestFinal(hs, d1, &l1) != CKR_OK) { a->fail = 5; break; }
        if (a->F->C_DigestInit(hs, &m) != CKR_OK) { a->fail = 6; break; }
        if (a->F->C_Digest(hs, (CK_BYTE_PTR)"hello", 5, d2, &l2) != CKR_OK) { a->fail = 7; break; }
        if (l1 != 32 || l2 != 32 || memcmp(d1, d2, 32) != 0) { a->fail = 8; break; }
    }
    a->F->C_CloseSession(hs);
    return NULL;
}

int test_p11_m7_concurrent_digest(void)
{
    mh_t h;
    CK_FUNCTION_LIST *F = NULL;
    pthread_t th[M7_THREADS];
    m7_arg_t args[M7_THREADS];
    int i;

    NCMP_CHECK(mh_up(&h, 1) == 0);
    NCMP_CHECK(get_functions(&F) == CKR_OK);
    NCMP_CHECK(p11_up(F) == CKR_OK);

    for (i = 0; i < M7_THREADS; ++i) {
        args[i].F = F; args[i].fail = 0;
        NCMP_CHECK(pthread_create(&th[i], NULL, m7_worker, &args[i]) == 0);
    }
    for (i = 0; i < M7_THREADS; ++i) {
        pthread_join(th[i], NULL);
        NCMP_CHECK(args[i].fail == 0);
    }
    F->C_Finalize(NULL);
    mh_down(&h);
    return 0;
}

/* M8: login on one slot does not leak into another slot's session state. */
int test_p11_m8_login_isolation(void)
{
    mh_t h;
    CK_FUNCTION_LIST *F = NULL;
    CK_SESSION_HANDLE hs0, hs1;
    CK_SESSION_INFO si;

    NCMP_CHECK(mh_up(&h, 2) == 0);
    NCMP_CHECK(get_functions(&F) == CKR_OK);
    NCMP_CHECK(p11_up(F) == CKR_OK);

    NCMP_CHECK(open_user(F, 0, &hs0) == CKR_OK);
    NCMP_CHECK(F->C_OpenSession(1, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL,
                                NULL, &hs1) == CKR_OK);

    NCMP_CHECK(F->C_GetSessionInfo(hs0, &si) == CKR_OK);
    NCMP_CHECK(si.state == CKS_RW_USER_FUNCTIONS);
    NCMP_CHECK(F->C_GetSessionInfo(hs1, &si) == CKR_OK);
    NCMP_CHECK(si.state == CKS_RW_PUBLIC_SESSION); /* slot 1 not logged in */

    F->C_CloseAllSessions(0);
    F->C_CloseAllSessions(1);
    F->C_Finalize(NULL);
    mh_down(&h);
    return 0;
}

/* M9: concurrent sign then tamper-detect across slots. */
static void *m9_worker(void *p)
{
    slot_arg_t *a = (slot_arg_t *)p;
    CK_SESSION_HANDLE hs;
    CK_OBJECT_HANDLE hpub, hpriv;
    CK_MECHANISM kg = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
    CK_MECHANISM sig = { CKM_RSA_PKCS_PSS, NULL, 0 };
    CK_BYTE data[32], s[512];
    CK_ULONG slen = sizeof(s);
    CK_OBJECT_CLASS pubc = CKO_PUBLIC_KEY, privc = CKO_PRIVATE_KEY;
    CK_ULONG bits = 2048;
    CK_BYTE e[] = { 0x01, 0x00, 0x01 };
    int i;
    CK_ATTRIBUTE pub[] = {
        { CKA_CLASS, &pubc, sizeof(pubc) },
        { CKA_MODULUS_BITS, &bits, sizeof(bits) },
        { CKA_PUBLIC_EXPONENT, e, sizeof(e) },
        { CKA_VERIFY, &CK_T, sizeof(CK_BBOOL) },
    };
    CK_ATTRIBUTE priv[] = {
        { CKA_CLASS, &privc, sizeof(privc) },
        { CKA_SIGN, &CK_T, sizeof(CK_BBOOL) },
    };

    if (open_user(a->F, a->slot, &hs) != CKR_OK) { a->fail = 1; return NULL; }
    if (a->F->C_GenerateKeyPair(hs, &kg, pub, 4, priv, 2, &hpub, &hpriv)
        != CKR_OK) { a->fail = 2; goto out; }
    for (i = 0; i < 32; ++i) data[i] = (CK_BYTE)(i * 2 + 1);
    if (a->F->C_SignInit(hs, &sig, hpriv) != CKR_OK) { a->fail = 3; goto out; }
    if (a->F->C_Sign(hs, data, 32, s, &slen) != CKR_OK) { a->fail = 4; goto out; }
    if (a->F->C_VerifyInit(hs, &sig, hpub) != CKR_OK) { a->fail = 5; goto out; }
    if (a->F->C_Verify(hs, data, 32, s, slen) != CKR_OK) { a->fail = 6; goto out; }
    s[0] ^= 0xFF;
    if (a->F->C_VerifyInit(hs, &sig, hpub) != CKR_OK) { a->fail = 7; goto out; }
    if (a->F->C_Verify(hs, data, 32, s, slen) != CKR_SIGNATURE_INVALID) {
        a->fail = 8; goto out;
    }
out:
    a->F->C_CloseSession(hs);
    return NULL;
}

int test_p11_m9_concurrent_signverify(void)
{
    mh_t h;
    CK_FUNCTION_LIST *F = NULL;
    pthread_t th[3];
    slot_arg_t args[3];
    int s;

    NCMP_CHECK(mh_up(&h, 3) == 0);
    NCMP_CHECK(get_functions(&F) == CKR_OK);
    NCMP_CHECK(p11_up(F) == CKR_OK);
    zeroize_all(F, 3);

    for (s = 0; s < 3; ++s) {
        args[s].F = F; args[s].slot = (CK_SLOT_ID)s; args[s].fail = 0;
        NCMP_CHECK(pthread_create(&th[s], NULL, m9_worker, &args[s]) == 0);
    }
    for (s = 0; s < 3; ++s) {
        pthread_join(th[s], NULL);
        NCMP_CHECK(args[s].fail == 0);
    }
    F->C_Finalize(NULL);
    mh_down(&h);
    return 0;
}

/* M10: system-wide session ceiling across all slots + CloseAllSessions reuse. */
int test_p11_m10_total_ceiling(void)
{
    mh_t h;
    CK_FUNCTION_LIST *F = NULL;
    CK_SESSION_HANDLE hs, extra;
    int s, i, opened = 0;

    NCMP_CHECK(mh_up(&h, PKCS11_MAX_SLOT_COUNT) == 0);
    NCMP_CHECK(get_functions(&F) == CKR_OK);
    NCMP_CHECK(p11_up(F) == CKR_OK);

    /* Fill every slot to its ceiling: 4 * 8 = 32 total. */
    for (s = 0; s < PKCS11_MAX_SLOT_COUNT; ++s) {
        for (i = 0; i < PKCS11_MAX_SESSION_PER_SLOT; ++i) {
            NCMP_CHECK(F->C_OpenSession((CK_SLOT_ID)s, CKF_SERIAL_SESSION,
                                        NULL, NULL, &hs) == CKR_OK);
            opened++;
        }
    }
    NCMP_CHECK(opened == PKCS11_MAX_TOTAL_SESSIONS);
    /* Every slot is at its per-slot ceiling now. */
    NCMP_CHECK(F->C_OpenSession(0, CKF_SERIAL_SESSION, NULL, NULL, &extra)
               == CKR_SESSION_COUNT);
    /* Free slot 0 entirely and reopen there. */
    NCMP_CHECK(F->C_CloseAllSessions(0) == CKR_OK);
    NCMP_CHECK(F->C_OpenSession(0, CKF_SERIAL_SESSION, NULL, NULL, &hs)
               == CKR_OK);

    for (s = 0; s < PKCS11_MAX_SLOT_COUNT; ++s)
        F->C_CloseAllSessions((CK_SLOT_ID)s);
    F->C_Finalize(NULL);
    mh_down(&h);
    return 0;
}

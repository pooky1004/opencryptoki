/*
 * Token NCMP - Vendor-defined PKCS#11 interface (public application header).
 *
 * Applications obtain this table with:
 *     CK_INTERFACE *iface;
 *     C_GetInterface((CK_UTF8CHAR *)"NCMP Vendor", NULL, &iface, 0);
 *     CK_NCMP_VENDOR_FUNCTION_LIST *v = iface->pFunctionList;
 *     v->NCMP_Loopback(session, ...);
 *
 * The table groups vendor-defined callbacks that exercise the FX3 datapath and
 * query host/token-side state - functionality outside standard PKCS#11. Every
 * function returns a CK_RV. Data-moving callbacks forward to the token through
 * the same ncmpd multiplexer as the standard crypto functions, so they are
 * safe to call from many threads and processes concurrently.
 */
#ifndef NCMP_VENDOR_H
#define NCMP_VENDOR_H

#include <pkcs11types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Interface name passed to C_GetInterface / listed by C_GetInterfaceList. */
#define NCMP_VENDOR_INTERFACE_NAME "NCMP Vendor"

/** Vendor interface version. */
#define NCMP_VENDOR_VERSION_MAJOR 1
#define NCMP_VENDOR_VERSION_MINOR 0

/** Vendor-defined function table (versioned like a Cryptoki interface). */
typedef struct CK_NCMP_VENDOR_FUNCTION_LIST {
    CK_VERSION version; /**< {NCMP_VENDOR_VERSION_MAJOR, _MINOR}. */

    /* --- Datapath primitives --- */

    /** @brief Echo @p pIn back through the token (round-trip loopback). */
    CK_RV (*NCMP_Loopback)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pIn,
                           CK_ULONG ulInLen, CK_BYTE_PTR pOut,
                           CK_ULONG_PTR pulOutLen);

    /** @brief Write @p ulLen bytes to token vendor scratch RAM at @p ulAddr. */
    CK_RV (*NCMP_MemWrite)(CK_SESSION_HANDLE hSession, CK_ULONG ulAddr,
                           CK_BYTE_PTR pData, CK_ULONG ulLen);

    /** @brief Read @p ulLen bytes from token vendor scratch RAM at @p ulAddr. */
    CK_RV (*NCMP_MemRead)(CK_SESSION_HANDLE hSession, CK_ULONG ulAddr,
                          CK_BYTE_PTR pOut, CK_ULONG ulLen);

    /** @brief Fill token scratch RAM [@p ulAddr, +ulLen) with @p byte. */
    CK_RV (*NCMP_MemFill)(CK_SESSION_HANDLE hSession, CK_ULONG ulAddr,
                          CK_ULONG ulLen, CK_BYTE byte);

    /** @brief CRC32 over token scratch RAM [@p ulAddr, +ulLen). */
    CK_RV (*NCMP_MemCRC)(CK_SESSION_HANDLE hSession, CK_ULONG ulAddr,
                         CK_ULONG ulLen, CK_ULONG_PTR pulCrc);

    /* --- Health / identity --- */

    /** @brief Round-trip liveness ping; returns the token epoch. */
    CK_RV (*NCMP_Ping)(CK_SESSION_HANDLE hSession, CK_ULONG_PTR pulEpoch);

    /** @brief Run the token self-test; *pulStatus == 0 means all subsystems OK. */
    CK_RV (*NCMP_SelfTest)(CK_SESSION_HANDLE hSession, CK_ULONG_PTR pulStatus);

    /** @brief Query firmware version components. */
    CK_RV (*NCMP_FirmwareInfo)(CK_SESSION_HANDLE hSession, CK_ULONG_PTR pulMajor,
                               CK_ULONG_PTR pulMinor, CK_ULONG_PTR pulPatch,
                               CK_ULONG_PTR pulBuild);

    /* --- Host-side introspection (no token round-trip) --- */

    /** @brief Read the slot's in-flight command counters from shared memory. */
    CK_RV (*NCMP_GetInFlight)(CK_SESSION_HANDLE hSession, CK_ULONG_PTR pulCurrent,
                              CK_ULONG_PTR pulMaxSeen, CK_ULONG_PTR pulTotalSent);

    /** @brief Resolve a CK slot id to its physical daemon slot + label. */
    CK_RV (*NCMP_GetSlotMap)(CK_SLOT_ID ckSlot, CK_ULONG_PTR pulPhys,
                             CK_CHAR_PTR pLabel, CK_ULONG ulLabelCap);

    /** @brief Set the library host-side log verbosity (0=quiet..3=debug). */
    CK_RV (*NCMP_SetLogLevel)(CK_ULONG ulLevel);

    /** @brief Get the library host-side log verbosity. */
    CK_RV (*NCMP_GetLogLevel)(CK_ULONG_PTR pulLevel);

    /** @brief Pure host-side echo (no token); validates the call path. */
    CK_RV (*NCMP_HostEcho)(CK_BYTE_PTR pIn, CK_ULONG ulInLen, CK_BYTE_PTR pOut,
                           CK_ULONG_PTR pulOutLen);
} CK_NCMP_VENDOR_FUNCTION_LIST;

typedef CK_NCMP_VENDOR_FUNCTION_LIST CK_PTR CK_NCMP_VENDOR_FUNCTION_LIST_PTR;

/** The single vendor function table instance (defined in p11_vendor.c). */
extern CK_NCMP_VENDOR_FUNCTION_LIST ncmp_vendor_functions;

#ifdef __cplusplus
}
#endif

#endif /* NCMP_VENDOR_H */

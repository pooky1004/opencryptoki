/*
 * Token NCMP - Minimal PKCS#11 CKR_* subset + NCMP->CKR mapping.
 *
 * The standalone build does not pull opencryptoki's pkcs11types.h; only the
 * CKR_* values the STDLL boundary needs are defined here. When integrated into
 * the opencryptoki tree these are replaced by the real header and this mapping
 * is the single place that turns internal NCMP_ERR_* codes into CK_RV.
 *
 * NOTE: the token's ACK field already carries CKR_* values verbatim, so a
 * successful transport with a non-OK ACK is surfaced as that ACK, not remapped.
 */
#ifndef NCMP_CKR_H
#define NCMP_CKR_H

/* Subset of PKCS#11 return values (numeric values are ABI-stable). */
#define NCMP_CKR_OK                    0x00000000UL
#define NCMP_CKR_SLOT_ID_INVALID       0x00000003UL
#define NCMP_CKR_GENERAL_ERROR         0x00000005UL
#define NCMP_CKR_FUNCTION_FAILED       0x00000006UL
#define NCMP_CKR_ARGUMENTS_BAD         0x00000007UL
#define NCMP_CKR_DEVICE_ERROR          0x00000030UL
#define NCMP_CKR_DEVICE_MEMORY         0x00000031UL
#define NCMP_CKR_SESSION_COUNT         0x000000B0UL /* CKR_SESSION_COUNT */
#define NCMP_CKR_TOKEN_NOT_PRESENT     0x000000E0UL
#define NCMP_CKR_FUNCTION_CANCELED     0x00000050UL

/**
 * @brief Map an internal NCMP_ERR_* code to a PKCS#11 CK_RV value.
 * @param ncmp_rc One of the NCMP_OK / NCMP_ERR_* codes.
 * @return The corresponding CKR_* value (as unsigned long).
 */
unsigned long ncmp_err_to_ckr(int ncmp_rc);

#endif /* NCMP_CKR_H */

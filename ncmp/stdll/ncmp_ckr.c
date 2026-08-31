/*
 * Token NCMP - NCMP_ERR_* -> CKR_* mapping (STDLL boundary).
 *
 * This is the single place internal transport error codes become PKCS#11
 * return values. The token's ACK field already holds a CKR_* value and is
 * surfaced as-is by the caller; this mapping only covers transport failures
 * that never reached (or returned from) the token.
 */
#include "ncmp/ncmp_ckr.h"
#include "ncmp/ncmp_errno.h"

unsigned long ncmp_err_to_ckr(int ncmp_rc)
{
    switch (ncmp_rc) {
    case NCMP_OK:
        return NCMP_CKR_OK;

    case NCMP_ERR_NODAEMON:
        /* Daemon not running / slot offline -> token unavailable. */
        return NCMP_CKR_TOKEN_NOT_PRESENT;

    case NCMP_ERR_TIMEOUT:
        return NCMP_CKR_FUNCTION_CANCELED;

    case NCMP_ERR_FULL:
        /* Ring or session capacity exhausted. */
        return NCMP_CKR_SESSION_COUNT;

    case NCMP_ERR_INVAL:
    case NCMP_ERR_PARAM_SIZE:
    case NCMP_ERR_PAYLOAD:
        return NCMP_CKR_ARGUMENTS_BAD;

    case NCMP_ERR_NOSPACE:
        return NCMP_CKR_DEVICE_MEMORY;

    case NCMP_ERR_USB:
    case NCMP_ERR_TRUNCATED:
        return NCMP_CKR_DEVICE_ERROR;

    case NCMP_ERR_VERSION:
    case NCMP_ERR_STATE:
    case NCMP_ERR_MUTEX:
    default:
        return NCMP_CKR_GENERAL_ERROR;
    }
}

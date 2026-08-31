/*
 * Token NCMP - Internal (transport-layer) error codes.
 *
 * These are negative values distinct from PKCS#11 CKR_* codes. The STDLL
 * maps them to CKR_* before returning to the PKCS#11 caller. The token's
 * ACK field carries CKR_* codes, not these.
 */
#ifndef NCMP_ERRNO_H
#define NCMP_ERRNO_H

#define NCMP_OK 0
#define NCMP_ERR_INVAL      (-1)  /**< Invalid argument. */
#define NCMP_ERR_NOSPACE    (-2)  /**< Buffer/queue/payload capacity exceeded. */
#define NCMP_ERR_PARAM_SIZE (-3)  /**< Single parameter > NCMP_MAX_PARAM_SIZE. */
#define NCMP_ERR_PAYLOAD    (-4)  /**< Total payload > NCMP_MAX_PAYLOAD_SIZE. */
#define NCMP_ERR_TRUNCATED  (-5)  /**< Wire buffer shorter than declared. */
#define NCMP_ERR_STATE      (-6)  /**< Illegal queue/CAS state transition. */
#define NCMP_ERR_TIMEOUT    (-7)  /**< Response not received before deadline. */
#define NCMP_ERR_NODAEMON   (-8)  /**< ncmpd not running / socket absent. */
#define NCMP_ERR_VERSION    (-9)  /**< IPC/SHM version mismatch. */
#define NCMP_ERR_MUTEX      (-10) /**< Unrecoverable robust-mutex failure. */
#define NCMP_ERR_USB        (-11) /**< libusb transport failure. */
#define NCMP_ERR_FULL       (-12) /**< Session/slot capacity reached. */

#endif /* NCMP_ERRNO_H */

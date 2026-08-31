/*
 * Token NCMP - Daemon <-> STDLL IPC handshake.
 *
 * The STDLL connects to ncmpd over a UNIX domain socket to obtain access to
 * the shared memory region. Only control/handshake messages travel on the
 * socket; all bulk command traffic goes through SHM. ncmpd MUST already be
 * running before libpkcs11_ncmp.so is loaded.
 */
#ifndef NCMP_IPC_H
#define NCMP_IPC_H

#include <stdint.h>

/** Filesystem path of the daemon's listening UNIX socket. */
#define NCMP_IPC_SOCK_PATH "/run/ncmpd/ncmpd.sock"

/** Protocol version negotiated at connect time. */
#define NCMP_IPC_VERSION 1u

/** IPC message opcodes. */
typedef enum ncmp_ipc_op {
    NCMP_IPC_HELLO = 1,      /**< Client -> daemon: announce + version. */
    NCMP_IPC_ATTACH = 2,     /**< Daemon -> client: SHM name + slot map. */
    NCMP_IPC_BYE = 3,        /**< Client -> daemon: graceful detach. */
    NCMP_IPC_ERROR = 0xFF    /**< Daemon -> client: rejection with code. */
} ncmp_ipc_op_t;

/** Fixed-size control message exchanged on the socket. */
typedef struct ncmp_ipc_msg {
    uint32_t op;             /**< ncmp_ipc_op_t. */
    uint32_t version;        /**< NCMP_IPC_VERSION. */
    uint32_t status;         /**< NCMP error/result code. */
    uint32_t slot_mask;      /**< Bitmask of online slots. */
    char     shm_name[32];   /**< SHM object name (NCMP_SHM_NAME). */
} NCMP_IpcMsg;

/**
 * @brief STDLL: connect to ncmpd and perform the HELLO/ATTACH handshake.
 * @param sock_path     Socket path, or NULL for NCMP_IPC_SOCK_PATH.
 * @param out_fd        Receives the connected socket fd on success.
 * @param out_slot_mask Receives the online-slot bitmask on success.
 * @return 0 on success; negative NCMP error if the daemon is absent or the
 *         version handshake fails.
 */
int ncmp_ipc_connect(const char *sock_path, int *out_fd,
                     uint32_t *out_slot_mask);

/**
 * @brief Daemon: bind and listen on @p sock_path.
 * @param sock_path     Socket path, or NULL for NCMP_IPC_SOCK_PATH.
 * @param out_listen_fd Receives the listening socket fd on success.
 * @return 0 on success; negative NCMP error otherwise.
 */
int ncmp_ipc_listen(const char *sock_path, int *out_listen_fd);

#endif /* NCMP_IPC_H */

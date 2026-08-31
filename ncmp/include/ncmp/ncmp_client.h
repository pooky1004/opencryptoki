/*
 * Token NCMP - STDLL client handle and command execution API.
 *
 * A client (one per process) connects to ncmpd over the IPC socket, attaches
 * the shared memory region, and then submits PKCS#11 commands by enqueuing
 * them onto the target slot's ring and waiting for the comm_thread's response.
 */
#ifndef NCMP_CLIENT_H
#define NCMP_CLIENT_H

#include <stdint.h>

#include "ncmp_wire.h"

/** Process-wide client handle to the NCMP subsystem. */
typedef struct ncmp_client {
    int      ipc_fd;    /**< Connected control socket (-1 when detached). */
    void    *shm_base;  /**< Local SHM mapping base. */
    uint32_t slot_mask; /**< Bitmask of online slots reported by the daemon. */
    uint32_t seq;       /**< Monotonic request id source (atomic increment). */
} ncmp_client_t;

/**
 * @brief Connect to ncmpd and attach shared memory.
 * @param c         Client handle to initialize.
 * @param sock_path IPC socket path, or NULL for the default (NCMP_IPC_SOCK_PATH).
 * @return NCMP_OK, NCMP_ERR_NODAEMON (daemon absent), or NCMP_ERR_VERSION.
 */
int ncmp_client_init(ncmp_client_t *c, const char *sock_path);

/**
 * @brief Submit one command to @p slot_id and wait for the response.
 * @param c           Initialized client handle.
 * @param slot_id     Target slot.
 * @param req         Request message (header.session_id/sequence_id identify it).
 * @param rsp         Receives the decoded response; rsp->header.ack holds the
 *                    token's CKR_* result.
 * @param spin_budget Yield iterations before timeout (0 = wait indefinitely).
 * @return NCMP_OK when a response was received (check rsp->header.ack for the
 *         token's status), NCMP_ERR_SLOT_* / NCMP_ERR_TIMEOUT / NCMP_ERR_FULL
 *         on transport-level failure.
 */
int ncmp_client_exec(ncmp_client_t *c, uint32_t slot_id,
                     const NCMP_Message *req, NCMP_Message *rsp,
                     uint64_t spin_budget);

/**
 * @brief Execute one opcode-tagged command carrying opaque byte buffers.
 *
 * PKCS#11-agnostic transport primitive: sends @p in as parameter 0 tagged with
 * @p opcode, waits for the token's response, and returns its first parameter in
 * @p out. Assigns a fresh sequence id internally (thread-safe). The token's
 * CKR_* result is returned via @p out_ack (transport success does not imply the
 * operation succeeded).
 *
 * @param c        Initialized client handle.
 * @param slot_id  Target slot.
 * @param opcode   Operation opcode (low 16 bits) plus optional flags.
 * @param in       Request bytes (may be NULL when @p in_len is 0).
 * @param in_len   Request length (<= NCMP_MAX_PARAM_SIZE).
 * @param out      Buffer receiving the response's parameter 0.
 * @param out_cap  Capacity of @p out.
 * @param out_len  Receives the response parameter length (may be NULL).
 * @param out_ack  Receives the token's CKR_* result (may be NULL).
 * @return NCMP_OK on a completed round-trip, or a negative NCMP error.
 */
int ncmp_client_command(ncmp_client_t *c, uint32_t slot_id, uint32_t opcode,
                        const uint8_t *in, uint32_t in_len,
                        uint8_t *out, uint32_t out_cap, uint32_t *out_len,
                        uint32_t *out_ack);

/**
 * @brief Execute a multi-parameter command (genuine multi-buffer operations).
 *
 * Packs @p n_in input parameters into one request tagged with @p opcode, waits
 * for the response, and returns the decoded response in @p out_msg (parameters
 * extractable via ncmp_msg_param, token result in out_msg->header.ack). Assigns
 * a fresh sequence id internally (thread-safe).
 *
 * @param c            Initialized client handle.
 * @param slot_id      Target slot.
 * @param opcode       Operation opcode (+ optional flags).
 * @param in           Array of @p n_in input parameter pointers.
 * @param in_len       Array of @p n_in input parameter lengths.
 * @param n_in         Number of input parameters (1..NCMP_MAX_PARAM_COUNT).
 * @param out_payload  Buffer receiving the response parameter bytes.
 * @param out_cap      Capacity of @p out_payload.
 * @param out_msg      Receives the decoded response message.
 * @return NCMP_OK on a completed round-trip, or a negative NCMP error.
 */
int ncmp_client_command_mp(ncmp_client_t *c, uint32_t slot_id, uint32_t opcode,
                           const uint8_t *const in[], const uint32_t in_len[],
                           int n_in, uint8_t *out_payload, uint32_t out_cap,
                           NCMP_Message *out_msg);

/**
 * @brief Detach shared memory and close the control socket.
 * @param c Client handle (may be partially initialized).
 * @return NCMP_OK.
 */
int ncmp_client_fini(ncmp_client_t *c);

#endif /* NCMP_CLIENT_H */

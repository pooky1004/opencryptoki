/*
 * Token NCMP - Bi-directional wire packet protocol (4-byte aligned).
 *
 * Frame layout on USB (little-endian, every field 4-byte aligned):
 *
 *   +--------------------------------------------------------------+
 *   | frame_len (4B)  : total length of everything AFTER this field |
 *   +--------------------------------------------------------------+
 *   | NCMP_Header (20B):                                            |
 *   |   session_id  (4B)                                            |
 *   |   sequence_id (4B)                                            |
 *   |   command_id  (4B)  command id / flags                       |
 *   |   ack         (4B)  CKR_* status (request + response)         |
 *   |   payload_len (4B)  bytes AFTER the header (array + params)   |
 *   +--------------------------------------------------------------+
 *   | param_len[8]  (32B) : per-parameter length array             |
 *   | payload bytes       : param 1..8 concatenated (len 0 = omit) |
 *   +--------------------------------------------------------------+
 *
 * Invariants:
 *   frame_len   == sizeof(NCMP_Header) + payload_len
 *   payload_len == sizeof(param_len[8]) + sum(param_len[i])
 */
#ifndef NCMP_WIRE_H
#define NCMP_WIRE_H

#include <stddef.h>
#include <stdint.h>
#include "ncmp_limits.h"

/** Fixed message header. Excludes the leading 4-byte frame_len prefix. */
typedef struct ncmp_header {
    uint32_t session_id;   /**< Owning PKCS#11 session handle. */
    uint32_t sequence_id;  /**< Monotonic per-session request id. */
    uint32_t command_id;   /**< Command id in low bits; flags in high bits. */
    uint32_t ack;          /**< CKR_* result; CKR_OK on a fresh request. */
    uint32_t payload_len;  /**< Bytes after header (param array + params). */
} NCMP_Header;

/** Size (bytes) of the on-wire frame length prefix that precedes the header. */
#define NCMP_FRAME_PREFIX_SIZE ((size_t)4)

/** Fixed on-wire size of NCMP_Header (5 x uint32, no padding). */
#define NCMP_HEADER_WIRE_SIZE ((size_t)20)

/** Size of the parameter length array segment. */
#define NCMP_PARAM_LEN_ARRAY_SIZE (NCMP_MAX_PARAM_COUNT * sizeof(uint32_t))

/** Largest possible encoded frame: prefix + header + array + max payload. */
#define NCMP_MAX_FRAME_SIZE \
    (NCMP_FRAME_PREFIX_SIZE + NCMP_HEADER_WIRE_SIZE + NCMP_MAX_PAYLOAD_SIZE)

/**
 * Host-side view of a message being assembled or parsed. Owns no memory;
 * @p payload points into a caller-provided or SHM-resident buffer.
 */
typedef struct ncmp_message {
    NCMP_Header header;
    uint32_t    param_len[NCMP_MAX_PARAM_COUNT];
    uint8_t    *payload;      /**< Concatenated parameter bytes. */
    size_t      payload_cap;  /**< Capacity of @p payload in bytes. */
} NCMP_Message;

/** Round @p n up to the next NCMP_WIRE_ALIGN boundary. */
static inline size_t ncmp_align4(size_t n)
{
    return (n + (NCMP_WIRE_ALIGN - 1)) & ~((size_t)NCMP_WIRE_ALIGN - 1);
}

/**
 * @brief Validate parameter sizes against the NCMP limits.
 * @param param_len Array of NCMP_MAX_PARAM_COUNT lengths.
 * @return 0 if valid; negative NCMP error if any single parameter exceeds
 *         NCMP_MAX_PARAM_SIZE or the total payload exceeds
 *         NCMP_MAX_PAYLOAD_SIZE.
 */
int ncmp_wire_validate_params(const uint32_t param_len[NCMP_MAX_PARAM_COUNT]);

/**
 * @brief Serialize @p msg into @p buf as a 4-byte-aligned wire frame.
 * @param msg     Message to encode (header.payload_len is recomputed).
 * @param buf     Destination buffer.
 * @param buf_len Capacity of @p buf in bytes.
 * @param out_len On success, total encoded length including frame prefix.
 * @return 0 on success; negative NCMP error on validation or space failure.
 */
int ncmp_wire_encode(const NCMP_Message *msg, uint8_t *buf, size_t buf_len,
                     size_t *out_len);

/**
 * @brief Parse the fixed header (frame prefix + NCMP_Header) from @p buf.
 * @param buf     Buffer holding at least NCMP_FRAME_PREFIX_SIZE + header bytes.
 * @param buf_len Bytes available in @p buf.
 * @param out     Header fields populated on success.
 * @return 0 on success; negative NCMP error if truncated or inconsistent.
 *
 * Used by the comm_thread's step-1 read before issuing the payload read.
 */
int ncmp_wire_decode_header(const uint8_t *buf, size_t buf_len,
                            NCMP_Header *out);

/**
 * @brief Pack multiple parameters into a message's payload.
 *
 * Concatenates @p parts[0..nparts) into @p payload_buf and sets the message's
 * param_len[] accordingly (remaining entries zeroed). @p m->payload is pointed
 * at @p payload_buf. Genuine multi-buffer operations (e.g. AES: flags|key|iv|
 * data) use this instead of hand-marshalling a single parameter.
 *
 * @param m         Message to populate (header untouched).
 * @param payload_buf Destination buffer for the concatenated parameters.
 * @param cap       Capacity of @p payload_buf.
 * @param parts     Array of @p nparts parameter pointers (NULL allowed if len 0).
 * @param lens      Array of @p nparts parameter lengths.
 * @param nparts    Number of parameters (1..NCMP_MAX_PARAM_COUNT).
 * @return 0 on success; negative NCMP error on bad args, over-count, per-param
 *         (>32KB) or total-payload (>40KB) overflow, or insufficient capacity.
 */
int ncmp_msg_pack(NCMP_Message *m, uint8_t *payload_buf, size_t cap,
                  const uint8_t *const parts[], const uint32_t lens[],
                  int nparts);

/**
 * @brief Locate parameter @p idx within a decoded message's payload.
 * @param m       Decoded message (param_len[] and payload populated).
 * @param idx     Parameter index (0..NCMP_MAX_PARAM_COUNT-1).
 * @param out     Receives a pointer into @p m->payload (NULL if the param is
 *                empty).
 * @param out_len Receives the parameter length.
 * @return 0 on success; negative NCMP error if @p idx is out of range.
 */
int ncmp_msg_param(const NCMP_Message *m, int idx, const uint8_t **out,
                   uint32_t *out_len);

/**
 * @brief Parse a whole frame into @p out (header, param lengths, payload).
 * @param buf     Buffer holding the complete frame.
 * @param buf_len Bytes available in @p buf.
 * @param out     Populated on success. If @p out->payload is non-NULL the
 *                parameter bytes are copied into it (bounded by payload_cap);
 *                otherwise only the header and param_len[] are filled.
 * @return 0 on success; negative NCMP error if truncated, inconsistent, or
 *         the destination payload buffer is too small.
 */
int ncmp_wire_decode(const uint8_t *buf, size_t buf_len, NCMP_Message *out);

#endif /* NCMP_WIRE_H */

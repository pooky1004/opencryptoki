#ifndef MPF_PEM_CIFX_PROTOCOL_H
#define MPF_PEM_CIFX_PROTOCOL_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#define CIFX_HEADER_BYTES 16u
#define CIFX_PROTOCOL_VERSION 1u
#define CIFX_MAX_PAYLOAD_BYTES 4080u

#define CIFX_OPCODE_PING 0x01u
#define CIFX_OPCODE_ECHO 0x02u
#define CIFX_OPCODE_PING_RESPONSE 0x81u
#define CIFX_OPCODE_ECHO_RESPONSE 0x82u

#define CIFX_CI_COMMAND_ECHO 0x0002u
#define CIFX_CI_COMMAND_CAPABILITIES 0x0001u
#define CIFX_CI_API_VERSION 7u
#define CIFX_CI_API_VERSION_LEGACY 6u
#define CIFX_CI_COMMAND_SESSION 0x0023u
#define CIFX_CI_COMMAND_KEYTABLE_INFO 0x0024u
#define CIFX_CI_COMMAND_PERF_QUERY 0x00f0u
#define CIFX_CI_COMMAND_AES_ONESHOT 0x0116u
#define CIFX_CI_COMMAND_AES_GCM_KEY_ID 0x0117u
#define CIFX_CI_COMMAND_AES_KEY_ID 0x0118u
#define CIFX_CI_COMMAND_AES_CONTEXT 0x0120u
#define CIFX_CI_COMMAND_AES_CTR_INIT 0x0130u
#define CIFX_CI_COMMAND_AES_CTR_UPDATE 0x0131u
#define CIFX_CI_COMMAND_AES_CTR_FINAL 0x0132u
#define CIFX_CI_COMMAND_AES_GCM_INIT 0x0133u
#define CIFX_CI_COMMAND_AES_GCM_UPDATE 0x0134u
#define CIFX_CI_COMMAND_AES_GCM_FINAL 0x0135u
#define CIFX_CI_COMMAND_SHA3_256_ONESHOT 0x0310u
#define CIFX_CI_COMMAND_SHA3_384_ONESHOT 0x0311u
#define CIFX_CI_COMMAND_SHA3_512_ONESHOT 0x0312u
#define CIFX_CI_COMMAND_SHA3_256_INIT 0x0340u
#define CIFX_CI_COMMAND_SHA3_256_UPDATE 0x0341u
#define CIFX_CI_COMMAND_SHA3_256_FINAL 0x0342u
#define CIFX_CI_COMMAND_SHA3_384_INIT 0x0343u
#define CIFX_CI_COMMAND_SHA3_384_UPDATE 0x0344u
#define CIFX_CI_COMMAND_SHA3_384_FINAL 0x0345u
#define CIFX_CI_COMMAND_SHA3_512_INIT 0x0346u
#define CIFX_CI_COMMAND_SHA3_512_UPDATE 0x0347u
#define CIFX_CI_COMMAND_SHA3_512_FINAL 0x0348u
#define CI_CMD_MLDSA_KEYGEN 0x0050u
#define CI_CMD_MLDSA_SIGN 0x0051u
#define CI_CMD_MLDSA_VERIFY 0x0052u
#define CI_CMD_MLKEM_KEYGEN 0x0053u
#define CI_CMD_MLKEM_ENCAPS 0x0054u
#define CI_CMD_MLKEM_DECAPS 0x0055u
#define CI_CMD_MLDSA_SIGN_KEY_ID 0x005au
#define CI_CMD_MLDSA_VERIFY_KEY_ID 0x005bu
#define CI_CMD_MLKEM_ENCAPS_KEY_ID 0x005cu
#define CI_CMD_MLKEM_DECAPS_KEY_ID 0x005du
#define CIFX_CI_COMMAND_MLDSA_SIGN_KEY_ID CI_CMD_MLDSA_SIGN_KEY_ID
#define CIFX_CI_COMMAND_MLDSA_VERIFY_KEY_ID CI_CMD_MLDSA_VERIFY_KEY_ID
#define CIFX_CI_COMMAND_MLKEM_ENCAPS_KEY_ID CI_CMD_MLKEM_ENCAPS_KEY_ID
#define CIFX_CI_COMMAND_MLKEM_DECAPS_KEY_ID CI_CMD_MLKEM_DECAPS_KEY_ID
#define CIFX_CI_V4_HEADER_BYTES 16u
#define CIFX_CI_V4_REQUEST_MAX_BYTES 65504u
#define CIFX_CI_V4_RESPONSE_MAX_BYTES 65520u
#define CIFX_CI_V4_MAX_ECHO_BYTES \
    (CIFX_CI_V4_REQUEST_MAX_BYTES - CIFX_CI_V4_HEADER_BYTES - 8u)
#define CIFX_CI_MAX_ECHO_PAYLOAD_BYTES \
    (CIFX_MAX_PAYLOAD_BYTES - CIFX_CI_V4_HEADER_BYTES - 8u)

enum cifx_status {
    CIFX_OK = 0,
    CIFX_ERR_ARGUMENT = -1,
    CIFX_ERR_CAPACITY = -2,
    CIFX_ERR_FORMAT = -3,
    CIFX_ERR_RANGE = -4,
    CIFX_ERR_UNSUPPORTED = -5
};

struct cifx_packet {
    uint8_t opcode;
    uint32_t sequence;
    const uint8_t *payload;
    uint32_t payload_length;
};

int cifx_encode_request(uint8_t opcode, uint32_t sequence,
                        const uint8_t *payload, uint32_t payload_length,
                        uint8_t *frame, size_t frame_capacity,
                        size_t *frame_length);

int cifx_parse_response(const uint8_t *frame, size_t frame_length,
                        uint8_t expected_opcode, uint32_t expected_sequence,
                        struct cifx_packet *packet);

/* Every wire message is TOTAL_BYTES, SESSION_ID, CMD, ACK, then command args.
 * Message bytes exclude unused byte lanes added only for GPIF word transfers. */
int cifx_build_ci_v4_message(uint32_t session_id, uint32_t command,
                             uint32_t ack, const uint8_t *args,
                             size_t args_bytes, uint8_t *message,
                             size_t capacity, size_t *message_bytes);
int cifx_parse_ci_v4_message(const uint8_t *message, size_t message_bytes,
                             bool request, uint32_t *session_id,
                             uint32_t *command, uint32_t *ack,
                             const uint8_t **args, size_t *args_bytes);
int cifx_ci_v4_transfer_size(size_t message_bytes, size_t *transfer_bytes);
int cifx_build_ci_v4_transfer(const uint8_t *message, size_t message_bytes,
                              uint8_t *transfer, size_t capacity,
                              size_t *transfer_bytes);
int cifx_parse_ci_v4_response(uint32_t expected_session_id,
                              uint32_t expected_command,
                              size_t expected_message_bytes,
                              const uint8_t *transfer, size_t transfer_bytes,
                              const uint8_t **message, uint32_t *status);

int cifx_build_ci_hil_echo_request(uint32_t session_id, const uint8_t *payload,
                                   uint32_t payload_length, uint8_t *message,
                                   size_t capacity, size_t *message_bytes);
int cifx_validate_ci_hil_echo_response(uint32_t session_id,
                                       const uint8_t *expected_payload,
                                       uint32_t expected_payload_length,
                                       const uint8_t *message,
                                       size_t message_bytes);

#endif

#include "cifx_protocol.h"

#include <string.h>

static const uint8_t cifx_magic[4] = { 'C', 'I', 'F', 'X' };

static uint16_t cifx_get_le16(const uint8_t *data)
{
    return (uint16_t)((uint16_t)data[0] | ((uint16_t)data[1] << 8));
}

static uint32_t cifx_get_le32(const uint8_t *data)
{
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
        ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

static void cifx_put_le32(uint8_t *data, uint32_t value)
{
    data[0] = (uint8_t)value;
    data[1] = (uint8_t)(value >> 8);
    data[2] = (uint8_t)(value >> 16);
    data[3] = (uint8_t)(value >> 24);
}

static uint64_t cifx_get_le64(const uint8_t *data)
{
    return (uint64_t)cifx_get_le32(data) |
        ((uint64_t)cifx_get_le32(data + 4u) << 32);
}

static void cifx_put_le64(uint8_t *data, uint64_t value)
{
    cifx_put_le32(data, (uint32_t)value);
    cifx_put_le32(data + 4u, (uint32_t)(value >> 32));
}

static int cifx_is_supported_request(uint8_t opcode, uint32_t payload_length)
{
    if (opcode == CIFX_OPCODE_PING) {
        return payload_length == 0u ? CIFX_OK : CIFX_ERR_FORMAT;
    }
    if (opcode == CIFX_OPCODE_ECHO) {
        return CIFX_OK;
    }
    return CIFX_ERR_UNSUPPORTED;
}

int cifx_encode_request(uint8_t opcode, uint32_t sequence,
                        const uint8_t *payload, uint32_t payload_length,
                        uint8_t *frame, size_t frame_capacity,
                        size_t *frame_length)
{
    size_t total_length;
    int status;

    if (frame == NULL || frame_length == NULL ||
        (payload_length != 0u && payload == NULL)) {
        return CIFX_ERR_ARGUMENT;
    }
    if (payload_length > CIFX_MAX_PAYLOAD_BYTES) {
        return CIFX_ERR_RANGE;
    }
    status = cifx_is_supported_request(opcode, payload_length);
    if (status != CIFX_OK) {
        return status;
    }
    total_length = CIFX_HEADER_BYTES + (size_t)payload_length;
    if (frame_capacity < total_length) {
        return CIFX_ERR_CAPACITY;
    }

    memcpy(frame, cifx_magic, sizeof(cifx_magic));
    frame[4] = CIFX_PROTOCOL_VERSION;
    frame[5] = opcode;
    frame[6] = 0u;
    frame[7] = 0u;
    cifx_put_le32(frame + 8u, sequence);
    cifx_put_le32(frame + 12u, payload_length);
    if (payload_length != 0u) {
        memcpy(frame + CIFX_HEADER_BYTES, payload, payload_length);
    }
    *frame_length = total_length;
    return CIFX_OK;
}

int cifx_parse_response(const uint8_t *frame, size_t frame_length,
                        uint8_t expected_opcode, uint32_t expected_sequence,
                        struct cifx_packet *packet)
{
    uint32_t payload_length;

    if (frame == NULL || packet == NULL || frame_length < CIFX_HEADER_BYTES) {
        return CIFX_ERR_ARGUMENT;
    }
    if (memcmp(frame, cifx_magic, sizeof(cifx_magic)) != 0 ||
        frame[4] != CIFX_PROTOCOL_VERSION || frame[5] != expected_opcode ||
        cifx_get_le16(frame + 6u) != 0u ||
        cifx_get_le32(frame + 8u) != expected_sequence) {
        return CIFX_ERR_FORMAT;
    }
    payload_length = cifx_get_le32(frame + 12u);
    if (payload_length > CIFX_MAX_PAYLOAD_BYTES ||
        frame_length != CIFX_HEADER_BYTES + (size_t)payload_length) {
        return CIFX_ERR_FORMAT;
    }

    packet->opcode = frame[5];
    packet->sequence = expected_sequence;
    packet->payload = frame + CIFX_HEADER_BYTES;
    packet->payload_length = payload_length;
    return CIFX_OK;
}

int cifx_build_ci_v4_message(uint32_t session_id, uint32_t command,
                             uint32_t ack, const uint8_t *args,
                             size_t args_bytes, uint8_t *message,
                             size_t capacity, size_t *message_bytes)
{
    const size_t maximum = ack == UINT32_C(0x0000ffff)
        ? CIFX_CI_V4_REQUEST_MAX_BYTES : CIFX_CI_V4_RESPONSE_MAX_BYTES;
    size_t total;

    if (message == NULL || message_bytes == NULL ||
        (args_bytes != 0u && args == NULL)) {
        return CIFX_ERR_ARGUMENT;
    }
    if (args_bytes > maximum - CIFX_CI_V4_HEADER_BYTES) {
        return CIFX_ERR_RANGE;
    }
    total = CIFX_CI_V4_HEADER_BYTES + args_bytes;
    if (capacity < total) {
        return CIFX_ERR_CAPACITY;
    }
    cifx_put_le32(message, (uint32_t)total);
    cifx_put_le32(message + 4u, session_id);
    cifx_put_le32(message + 8u, command);
    cifx_put_le32(message + 12u, ack);
    if (args_bytes != 0u) {
        memcpy(message + CIFX_CI_V4_HEADER_BYTES, args, args_bytes);
    }
    *message_bytes = total;
    return CIFX_OK;
}

int cifx_parse_ci_v4_message(const uint8_t *message, size_t message_bytes,
                             bool request, uint32_t *session_id,
                             uint32_t *command, uint32_t *ack,
                             const uint8_t **args, size_t *args_bytes)
{
    uint32_t total;

    if (message == NULL || session_id == NULL || command == NULL || ack == NULL ||
        args == NULL || args_bytes == NULL) {
        return CIFX_ERR_ARGUMENT;
    }
    if (message_bytes < CIFX_CI_V4_HEADER_BYTES ||
        message_bytes > (request ? CIFX_CI_V4_REQUEST_MAX_BYTES :
                                  CIFX_CI_V4_RESPONSE_MAX_BYTES)) {
        return CIFX_ERR_RANGE;
    }
    total = cifx_get_le32(message);
    if (total != message_bytes) {
        return CIFX_ERR_FORMAT;
    }
    *session_id = cifx_get_le32(message + 4u);
    *command = cifx_get_le32(message + 8u);
    *ack = cifx_get_le32(message + 12u);
    if (request && *ack != UINT32_C(0x0000ffff)) {
        return CIFX_ERR_FORMAT;
    }
    *args = message + CIFX_CI_V4_HEADER_BYTES;
    *args_bytes = message_bytes - CIFX_CI_V4_HEADER_BYTES;
    return CIFX_OK;
}

int cifx_ci_v4_transfer_size(size_t message_bytes, size_t *transfer_bytes)
{
    if (transfer_bytes == NULL) {
        return CIFX_ERR_ARGUMENT;
    }
    if (message_bytes < CIFX_CI_V4_HEADER_BYTES ||
        message_bytes > CIFX_CI_V4_RESPONSE_MAX_BYTES) {
        return CIFX_ERR_RANGE;
    }
    *transfer_bytes = (message_bytes + 3u) & ~(size_t)3u;
    return CIFX_OK;
}

int cifx_build_ci_v4_transfer(const uint8_t *message, size_t message_bytes,
                              uint8_t *transfer, size_t capacity,
                              size_t *transfer_bytes)
{
    size_t aligned_bytes;

    if (message == NULL || transfer == NULL || transfer_bytes == NULL) {
        return CIFX_ERR_ARGUMENT;
    }
    if (message_bytes < CIFX_CI_V4_HEADER_BYTES ||
        message_bytes > CIFX_CI_V4_RESPONSE_MAX_BYTES ||
        cifx_get_le32(message) != message_bytes ||
        (cifx_get_le32(message + 12u) == UINT32_C(0x0000ffff) &&
         message_bytes > CIFX_CI_V4_REQUEST_MAX_BYTES) ||
        cifx_ci_v4_transfer_size(message_bytes, &aligned_bytes) != CIFX_OK) {
        return CIFX_ERR_FORMAT;
    }
    if (capacity < aligned_bytes) {
        return CIFX_ERR_CAPACITY;
    }
    /* Initialize only unused lanes so no uninitialized bytes are read; those
     * lanes have no wire meaning and are not validated by the receiver. */
    if (transfer != message) {
        memcpy(transfer, message, message_bytes);
    }
    if (aligned_bytes > message_bytes) {
        memset(transfer + message_bytes, 0, aligned_bytes - message_bytes);
    }
    *transfer_bytes = aligned_bytes;
    return CIFX_OK;
}

int cifx_parse_ci_v4_response(uint32_t expected_session_id,
                              uint32_t expected_command,
                              size_t expected_message_bytes,
                              const uint8_t *transfer, size_t transfer_bytes,
                              const uint8_t **message, uint32_t *status)
{
    uint32_t session_id;
    uint32_t command;
    uint32_t ack;
    const uint8_t *args;
    size_t args_bytes;
    size_t expected_transfer_bytes;
    size_t actual_message_bytes;
    size_t actual_transfer_bytes;
    int result;

    if (transfer == NULL || message == NULL || status == NULL) {
        return CIFX_ERR_ARGUMENT;
    }
    if (expected_message_bytes < CIFX_CI_V4_HEADER_BYTES ||
        expected_message_bytes > CIFX_CI_V4_RESPONSE_MAX_BYTES ||
        cifx_ci_v4_transfer_size(expected_message_bytes,
                                 &expected_transfer_bytes) != CIFX_OK ||
        transfer_bytes < CIFX_CI_V4_HEADER_BYTES ||
        transfer_bytes > expected_transfer_bytes) {
        return CIFX_ERR_FORMAT;
    }
    actual_message_bytes = cifx_get_le32(transfer);
    if (actual_message_bytes == expected_message_bytes) {
        if (cifx_ci_v4_transfer_size(actual_message_bytes,
                                     &actual_transfer_bytes) != CIFX_OK ||
            transfer_bytes != actual_transfer_bytes) {
            return CIFX_ERR_FORMAT;
        }
    } else if (expected_message_bytes > CIFX_CI_V4_HEADER_BYTES &&
               actual_message_bytes == CIFX_CI_V4_HEADER_BYTES &&
               transfer_bytes == CIFX_CI_V4_HEADER_BYTES &&
               cifx_get_le32(transfer + 12u) != 0u) {
        /* A command can fail before producing its success arguments. V4
         * error responses are exactly the common header and a nonzero ACK. */
    } else {
        return CIFX_ERR_FORMAT;
    }
    result = cifx_parse_ci_v4_message(transfer, actual_message_bytes, false,
                                      &session_id, &command, &ack,
                                      &args, &args_bytes);
    if (result != CIFX_OK || session_id != expected_session_id ||
        command != expected_command || (ack != 0u && args_bytes != 0u)) {
        return CIFX_ERR_FORMAT;
    }
    *message = transfer;
    *status = ack;
    return CIFX_OK;
}

int cifx_build_ci_hil_echo_request(uint32_t session_id, const uint8_t *payload,
                                   uint32_t payload_length, uint8_t *message,
                                   size_t capacity, size_t *message_bytes)
{
    uint8_t args[CIFX_CI_V4_MAX_ECHO_BYTES + 8u];
    const size_t padded_length = ((size_t)payload_length + 7u) & ~(size_t)7u;

    if (payload_length > CIFX_CI_V4_MAX_ECHO_BYTES) {
        return CIFX_ERR_RANGE;
    }
    if (payload_length != 0u && payload == NULL) {
        return CIFX_ERR_ARGUMENT;
    }
    cifx_put_le64(args, payload_length);
    memset(args + 8u, 0, padded_length);
    if (payload_length != 0u) {
        memcpy(args + 8u, payload, payload_length);
    }
    return cifx_build_ci_v4_message(
        session_id, CIFX_CI_COMMAND_ECHO, UINT32_C(0x0000ffff), args,
        padded_length + 8u, message, capacity, message_bytes);
}

int cifx_validate_ci_hil_echo_response(uint32_t session_id,
                                       const uint8_t *expected_payload,
                                       uint32_t expected_payload_length,
                                       const uint8_t *message,
                                       size_t message_bytes)
{
    uint32_t actual_session;
    uint32_t command;
    uint32_t ack;
    const uint8_t *args;
    size_t args_bytes;
    size_t index;
    const size_t padded_length = ((size_t)expected_payload_length + 7u) & ~(size_t)7u;

    if (message == NULL ||
        (expected_payload_length != 0u && expected_payload == NULL)) {
        return CIFX_ERR_ARGUMENT;
    }
    if (expected_payload_length > CIFX_CI_V4_MAX_ECHO_BYTES) {
        return CIFX_ERR_RANGE;
    }
    if (cifx_parse_ci_v4_message(message, message_bytes, false,
                                 &actual_session, &command, &ack,
                                 &args, &args_bytes) != CIFX_OK ||
        actual_session != session_id || command != CIFX_CI_COMMAND_ECHO ||
        ack != 0u || args_bytes != padded_length + 8u ||
        cifx_get_le64(args) != expected_payload_length ||
        (expected_payload_length != 0u &&
         memcmp(args + 8u, expected_payload, expected_payload_length) != 0)) {
        return CIFX_ERR_FORMAT;
    }
    for (index = expected_payload_length; index < padded_length; ++index) {
        if (args[8u + index] != 0u) {
            return CIFX_ERR_FORMAT;
        }
    }
    return CIFX_OK;
}

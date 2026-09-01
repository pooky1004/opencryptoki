/*
 * Token NCMP - Software mock / emulator (mock-private declarations).
 *
 * Emulates the FX3 datapath so the host stack can be developed and tested
 * without hardware: Rx 64KB / Tx 128KB DMA rings, 4 SRAM containers, a mover
 * that reads the 4-byte length prefix, and a round-robin MCU scheduler that
 * produces valid response frames with correct ACK and payload_len fields.
 */
#ifndef MOCK_TOKEN_NCMP_H
#define MOCK_TOKEN_NCMP_H

#include <stddef.h>
#include <stdint.h>

#include "ncmp/ncmp_limits.h"
#include "ncmp/ncmp_cmd.h"

/**
 * Test hook: if this bit is set in a request's command_id, the emulator
 * returns a failing ACK (CKR_FUNCTION_FAILED) instead of CKR_OK. Lets the test
 * suite exercise token-side error propagation without real hardware.
 */
#define NCMP_MOCK_CMD_FAIL_BIT 0x80000000u

/** One emulated 64KB SRAM container. */
typedef struct mock_container {
    uint8_t  data[NCMP_DEV_CONTAINER_SIZE];
    uint32_t used;   /**< Bytes currently held (0 = free). */
    int      busy;   /**< Non-zero while the MCU is processing it. */
} mock_container_t;

/** Max concurrent multipart-digest contexts the mock token holds. */
#define NCMP_MOCK_DIGEST_CTX_MAX 8

/** One in-progress multipart digest (token-side state across commands). */
typedef struct mock_digest_ctx {
    int      in_use; /**< Non-zero when allocated. */
    uint32_t mech;   /**< Digest mechanism (NCMP_MECH_*). */
    uint32_t acc;    /**< Running accumulator. */
} mock_digest_ctx_t;

/** Emulated device state. */
typedef struct mock_device {
    mock_container_t  container[NCMP_DEV_CONTAINER_COUNT];
    uint32_t          rr_cursor; /**< Round-robin scheduler position. */
    mock_digest_ctx_t digest_ctx[NCMP_MOCK_DIGEST_CTX_MAX];
    uint8_t           vd_mem[NCMP_VD_MEM_SIZE]; /**< Vendor scratch RAM. */
    uint32_t          epoch;     /**< Bumped on selftest; vendor PING readback. */
} mock_device_t;

/**
 * @brief Mover: read the 4-byte length prefix and stage a frame into a free
 *        container. Blocks (returns BUSY) while all containers are full.
 * @return NCMP_OK when staged, NCMP_ERR_FULL if no container is free.
 */
int mock_mover_ingest(mock_device_t *dev, const uint8_t *frame, size_t len);

/**
 * @brief MCU: pick the next busy container round-robin, "execute" it, and
 *        emit a response frame with a valid ACK and payload_len.
 * @return NCMP_OK if a response was produced, NCMP_ERR_STATE if idle.
 */
int mock_mcu_step(mock_device_t *dev, uint8_t *rsp, size_t rsp_cap,
                  size_t *rsp_len);

#endif /* MOCK_TOKEN_NCMP_H */

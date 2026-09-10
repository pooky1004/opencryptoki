/*
 * Token NCMP - Wire protocol boundary tests.
 * Verifies per-parameter and combined-payload limit enforcement. Both ceilings
 * derive from the device container size (NCMP_MAX_PARAM_SIZE /
 * NCMP_MAX_PAYLOAD_SIZE == NCMP_DEV_CONTAINER_SIZE - NCMP_WIRE_FRAME_OVERHEAD).
 */
#include "ncmp/ncmp_wire.h"
#include "ncmp/ncmp_errno.h"
#include "ncmp_test.h"

#include <string.h>

int test_wire_param_within_limits(void)
{
    uint32_t p[NCMP_MAX_PARAM_COUNT];
    memset(p, 0, sizeof(p));
    /* Largest single param that still fits the payload alongside the 8-entry
     * length array: total == NCMP_PARAM_LEN_ARRAY_SIZE + param == ceiling. */
    p[0] = NCMP_MAX_PARAM_SIZE - NCMP_PARAM_LEN_ARRAY_SIZE;
    NCMP_CHECK(ncmp_wire_validate_params(p) == NCMP_OK);
    return 0;
}

int test_wire_single_param_too_big(void)
{
    uint32_t p[NCMP_MAX_PARAM_COUNT];
    memset(p, 0, sizeof(p));
    p[0] = NCMP_MAX_PARAM_SIZE + 1;      /* one byte over the per-param cap */
    NCMP_CHECK(ncmp_wire_validate_params(p) == NCMP_ERR_PARAM_SIZE);
    return 0;
}

int test_wire_total_payload_too_big(void)
{
    uint32_t p[NCMP_MAX_PARAM_COUNT];
    memset(p, 0, sizeof(p));
    /* Two max-size params exceed the combined-payload ceiling. */
    p[0] = NCMP_MAX_PARAM_SIZE;
    p[1] = NCMP_MAX_PARAM_SIZE;
    NCMP_CHECK(ncmp_wire_validate_params(p) == NCMP_ERR_PAYLOAD);
    return 0;
}

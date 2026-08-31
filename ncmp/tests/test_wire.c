/*
 * Token NCMP - Wire protocol boundary tests.
 * Verifies parameter/payload limit enforcement (32KB / 40KB).
 */
#include "ncmp/ncmp_wire.h"
#include "ncmp/ncmp_errno.h"
#include "ncmp_test.h"

#include <string.h>

int test_wire_param_within_limits(void)
{
    uint32_t p[NCMP_MAX_PARAM_COUNT];
    memset(p, 0, sizeof(p));
    p[0] = NCMP_MAX_PARAM_SIZE;          /* exactly 32KB single param */
    NCMP_CHECK(ncmp_wire_validate_params(p) == NCMP_OK);
    return 0;
}

int test_wire_single_param_too_big(void)
{
    uint32_t p[NCMP_MAX_PARAM_COUNT];
    memset(p, 0, sizeof(p));
    p[0] = NCMP_MAX_PARAM_SIZE + 1;      /* one byte over the 32KB cap */
    NCMP_CHECK(ncmp_wire_validate_params(p) == NCMP_ERR_PARAM_SIZE);
    return 0;
}

int test_wire_total_payload_too_big(void)
{
    uint32_t p[NCMP_MAX_PARAM_COUNT];
    memset(p, 0, sizeof(p));
    /* Two 32KB params = 64KB > 40KB combined-payload ceiling. */
    p[0] = NCMP_MAX_PARAM_SIZE;
    p[1] = NCMP_MAX_PARAM_SIZE;
    NCMP_CHECK(ncmp_wire_validate_params(p) == NCMP_ERR_PAYLOAD);
    return 0;
}

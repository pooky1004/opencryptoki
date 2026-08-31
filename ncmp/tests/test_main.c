/*
 * Token NCMP - Test suite runner.
 *
 * Aggregates every test function and returns non-zero if any failed so ctest
 * reports the suite result.
 */
#include "ncmp_test.h"

/* Wire */
int test_wire_param_within_limits(void);
int test_wire_single_param_too_big(void);
int test_wire_total_payload_too_big(void);
/* Queue */
int test_queue_claim_post_cycle(void);
int test_queue_full(void);
int test_queue_post_requires_claimed(void);
/* Session */
int test_session_ceiling(void);
/* Mutex */
int test_mutex_recovers_dead_owner(void);
/* Stats */
int test_inflight_stats_tracking(void);
/* Concurrency */
int test_concurrent_enqueue_single_slot(void);
int test_ack_error_propagation(void);
/* End-to-end skeleton: SHM + mock loopback */
int test_shm_create_attach(void);
int test_shm_cross_mapping_visibility(void);
int test_mock_loopback_echo(void);
/* STDLL client round-trip over IPC */
int test_client_roundtrip(void);
int test_client_rng_forward(void);
int test_client_digest_forward(void);
int test_client_digest_multipart(void);
int test_client_aes_cbc_forward(void);
int test_client_aes_ecb_forward(void);
int test_client_aes_gcm_forward(void);
int test_client_aes_stream_forward(void);
int test_client_rsa_sign_forward(void);
int test_client_rsa_verify_forward(void);
int test_client_ec_sign_forward(void);
int test_client_ec_verify_forward(void);
int test_client_rsa_keygen_forward(void);
int test_client_ec_keygen_forward(void);
int test_client_hmac_forward(void);
int test_client_rsa_oaep_forward(void);
int test_client_dh_derive_forward(void);
int test_client_ecdh_derive_forward(void);

int main(void)
{
    int failures = 0;

    NCMP_RUN(test_wire_param_within_limits);
    NCMP_RUN(test_wire_single_param_too_big);
    NCMP_RUN(test_wire_total_payload_too_big);
    NCMP_RUN(test_queue_claim_post_cycle);
    NCMP_RUN(test_queue_full);
    NCMP_RUN(test_queue_post_requires_claimed);
    NCMP_RUN(test_session_ceiling);
    NCMP_RUN(test_mutex_recovers_dead_owner);
    NCMP_RUN(test_inflight_stats_tracking);
    NCMP_RUN(test_concurrent_enqueue_single_slot);
    NCMP_RUN(test_ack_error_propagation);
    NCMP_RUN(test_shm_create_attach);
    NCMP_RUN(test_shm_cross_mapping_visibility);
    NCMP_RUN(test_mock_loopback_echo);
    NCMP_RUN(test_client_roundtrip);
    NCMP_RUN(test_client_rng_forward);
    NCMP_RUN(test_client_digest_forward);
    NCMP_RUN(test_client_digest_multipart);
    NCMP_RUN(test_client_aes_cbc_forward);
    NCMP_RUN(test_client_aes_ecb_forward);
    NCMP_RUN(test_client_aes_gcm_forward);
    NCMP_RUN(test_client_aes_stream_forward);
    NCMP_RUN(test_client_rsa_sign_forward);
    NCMP_RUN(test_client_rsa_verify_forward);
    NCMP_RUN(test_client_ec_sign_forward);
    NCMP_RUN(test_client_ec_verify_forward);
    NCMP_RUN(test_client_rsa_keygen_forward);
    NCMP_RUN(test_client_ec_keygen_forward);
    NCMP_RUN(test_client_hmac_forward);
    NCMP_RUN(test_client_rsa_oaep_forward);
    NCMP_RUN(test_client_dh_derive_forward);
    NCMP_RUN(test_client_ecdh_derive_forward);

    fprintf(stderr, "\n%s (%d failure%s)\n",
            failures ? "SUITE FAILED" : "SUITE PASSED",
            failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}

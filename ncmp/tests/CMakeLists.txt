# Token NCMP - test suite (Module D).
add_executable(ncmp_tests
    test_main.c
    test_wire.c
    test_queue_cas.c
    test_session_limits.c
    test_mutex_robust.c
    test_inflight_stats.c
    test_concurrency.c
    test_loopback.c
    test_client.c
    # Crypto marshalling adapter (ncmp_crypto) exercised end-to-end vs the mock.
    test_crypto.c
    # Daemon consumer + connection server exercised by the STEP 2/3 tests.
    ${CMAKE_SOURCE_DIR}/daemon/comm_thread.c
    ${CMAKE_SOURCE_DIR}/daemon/conn_thread.c
)
target_include_directories(ncmp_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/daemon
    ${CMAKE_SOURCE_DIR}/../usr/include)
# ncmp_stdll_client supplies the STDLL transport + crypto adapter under test
# (ncmp_client/session/ckr/crypto); ncmp_mock provides the loopback
# ncmp_transport_* used by test_loopback.c. Both transitively link ncmp_common.
target_link_libraries(ncmp_tests PRIVATE ncmp_stdll_client ncmp_mock)

add_test(NAME ncmp_tests COMMAND ncmp_tests)

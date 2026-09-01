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
    # STDLL units under test (compiled directly rather than linking the .so).
    ${CMAKE_SOURCE_DIR}/stdll/ncmp_session.c
    ${CMAKE_SOURCE_DIR}/stdll/ncmp_client.c
    ${CMAKE_SOURCE_DIR}/stdll/ncmp_ckr.c
    # Daemon consumer + connection server exercised by the STEP 2/3 tests.
    ${CMAKE_SOURCE_DIR}/daemon/comm_thread.c
    ${CMAKE_SOURCE_DIR}/daemon/conn_thread.c
)
target_include_directories(ncmp_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/daemon
    ${CMAKE_SOURCE_DIR}/../usr/include)
# ncmp_mock provides the loopback ncmp_transport_* used by test_loopback.c and
# transitively links ncmp_common.
target_link_libraries(ncmp_tests PRIVATE ncmp_mock)

add_test(NAME ncmp_tests COMMAND ncmp_tests)

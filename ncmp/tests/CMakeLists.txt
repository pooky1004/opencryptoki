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
    # PKCS#11 provider (C_* API) test application: version mapping, vendor
    # interface, 5 composite + 10 multi-slot/multi-session scenarios.
    test_pkcs11_api.c
    # STDLL units under test (compiled directly rather than linking the .so).
    ${CMAKE_SOURCE_DIR}/stdll/ncmp_session.c
    ${CMAKE_SOURCE_DIR}/stdll/ncmp_client.c
    ${CMAKE_SOURCE_DIR}/stdll/ncmp_ckr.c
    # Self-contained PKCS#11 provider under test (compiled directly).
    ${CMAKE_SOURCE_DIR}/pkcs11/p11_state.c
    ${CMAKE_SOURCE_DIR}/pkcs11/p11_slotmap.c
    ${CMAKE_SOURCE_DIR}/pkcs11/p11_api_general.c
    ${CMAKE_SOURCE_DIR}/pkcs11/p11_api_slot.c
    ${CMAKE_SOURCE_DIR}/pkcs11/p11_api_session.c
    ${CMAKE_SOURCE_DIR}/pkcs11/p11_api_object.c
    ${CMAKE_SOURCE_DIR}/pkcs11/p11_api_crypt.c
    ${CMAKE_SOURCE_DIR}/pkcs11/p11_api_key.c
    ${CMAKE_SOURCE_DIR}/pkcs11/p11_functionlist.c
    ${CMAKE_SOURCE_DIR}/pkcs11/p11_vendor.c
    # Daemon consumer + connection server exercised by the STEP 2/3 tests.
    ${CMAKE_SOURCE_DIR}/daemon/comm_thread.c
    ${CMAKE_SOURCE_DIR}/daemon/conn_thread.c
)
target_include_directories(ncmp_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/daemon
    ${CMAKE_SOURCE_DIR}/pkcs11
    ${CMAKE_SOURCE_DIR}/../usr/include)
# ncmp_mock provides the loopback ncmp_transport_* used by test_loopback.c and
# transitively links ncmp_common.
target_link_libraries(ncmp_tests PRIVATE ncmp_mock)

add_test(NAME ncmp_tests COMMAND ncmp_tests)

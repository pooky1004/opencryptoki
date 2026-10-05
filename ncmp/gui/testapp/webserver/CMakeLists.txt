# Token NCMP - Test App web server (ncmp_web).
#
# A self-contained HTTP/JSON server that compiles the native app_* layer
# (../native/ncmp_testapp.c) directly in, so a single binary serves the web UI
# and drives the token. It dlopen's the facade STDLL at runtime (no build-time
# link). Built together with the Test App native layer (ENABLE_TESTAPP).

if(ENABLE_TESTAPP)
    find_package(Threads REQUIRED)
    # OpenSSL provides the software reference digests (real-target vs SW compare).
    find_package(OpenSSL REQUIRED)

    add_executable(ncmp_web
        ncmp_web.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../native/ncmp_testapp.c)

    target_include_directories(ncmp_web PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../native
        ${CMAKE_SOURCE_DIR}/../usr/include)

    target_compile_definitions(ncmp_web PRIVATE _GNU_SOURCE)
    set_target_properties(ncmp_web PROPERTIES C_STANDARD 11)
    target_link_libraries(ncmp_web PRIVATE
        ${CMAKE_DL_LIBS} Threads::Threads OpenSSL::Crypto)

    message(STATUS "Token NCMP: building Test App web server (ncmp_web)")
endif()

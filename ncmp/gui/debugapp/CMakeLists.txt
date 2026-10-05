# Token NCMP - Debug App server (ncmp_dbg).
#
# A self-contained HTTP/JSON server that handshakes with ncmpd's connection
# thread (ncmp_ipc), attaches the shared memory read-only, and serves a browser
# UI to inspect per-slot SHM metadata. Links ncmp_common for the IPC + SHM
# helpers; no PKCS#11 / facade dependency. Built with the Test App toggle.
option(ENABLE_DEBUGAPP "Build the Debug App server (ncmp_dbg)" ON)

if(ENABLE_DEBUGAPP)
    find_package(Threads REQUIRED)

    add_executable(ncmp_dbg server/ncmp_dbg.c)
    target_include_directories(ncmp_dbg PRIVATE ${CMAKE_SOURCE_DIR}/include)
    target_compile_definitions(ncmp_dbg PRIVATE _GNU_SOURCE)
    set_target_properties(ncmp_dbg PROPERTIES C_STANDARD 11)
    # ncmp_stdll_client provides ncmp_client_init(): the conn-thread HELLO
    # handshake plus the read-only SHM attach the inspector reads. It links
    # ncmp_common (IPC + SHM) too.
    target_link_libraries(ncmp_dbg PRIVATE ncmp_stdll_client Threads::Threads)

    message(STATUS "Token NCMP: building Debug App server (ncmp_dbg, SHM inspector)")
endif()

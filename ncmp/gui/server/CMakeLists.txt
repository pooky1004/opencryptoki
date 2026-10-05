# Token NCMP - mock HSM socket server + real-HSM bridge (developer tools).
#
# Both share frame_server.c (sockets/stats/debug/control); they differ only in
# the backend. Built by default; disable with -DENABLE_GUI_SERVER=OFF.
option(ENABLE_GUI_SERVER "Build the mock HSM server + real-HSM bridge" ON)

if(ENABLE_GUI_SERVER)
    find_package(Threads REQUIRED)

    # Shared scaffolding.
    add_library(ncmp_frame_server STATIC frame_server.c)
    target_include_directories(ncmp_frame_server PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/include)
    target_link_libraries(ncmp_frame_server PUBLIC ncmp_common Threads::Threads)

    # Mock server: emulator backend (always available; reuses ncmp_mock).
    add_executable(mock_server mock_server.c)
    target_include_directories(mock_server PRIVATE ${CMAKE_SOURCE_DIR}/mock)
    target_link_libraries(mock_server PRIVATE ncmp_frame_server ncmp_mock)

    # Real-HSM bridge: drives a real FX3 through the transport dispatcher
    # (ncmp_transport_*), exactly like ncmpd. The dispatcher (transport.c)
    # references all three backend ops tables, so link the same transport stack
    # as the daemon (the bridge keeps the default "real"/USB backend). The mock
    # backend pulls in the emulator sources (NOT ncmp_mock, which would re-export
    # the public ncmp_transport_* and clash with the dispatcher). usb_transport.c
    # compiles a no-device stub when libusb is absent, so the bridge always
    # builds; link libusb when found.
    add_executable(hsm_bridge
        hsm_bridge.c
        ${CMAKE_SOURCE_DIR}/daemon/transport.c
        ${CMAKE_SOURCE_DIR}/daemon/usb_transport.c
        ${CMAKE_SOURCE_DIR}/daemon/socket_transport.c
        ${CMAKE_SOURCE_DIR}/daemon/mock_backend.c
        ${CMAKE_SOURCE_DIR}/mock/mcu_scheduler.c
        ${CMAKE_SOURCE_DIR}/mock/container.c
        ${CMAKE_SOURCE_DIR}/mock/fx3_dma.c)
    target_include_directories(hsm_bridge PRIVATE ${CMAKE_SOURCE_DIR}/mock)
    target_link_libraries(hsm_bridge PRIVATE ncmp_frame_server)
    find_package(LibUSB QUIET)
    if(LibUSB_FOUND OR TARGET LibUSB::LibUSB)
        target_link_libraries(hsm_bridge PRIVATE LibUSB::LibUSB)
        message(STATUS "Token NCMP: hsm_bridge linked against libusb")
    else()
        message(STATUS "Token NCMP: libusb not found; hsm_bridge builds as a stub "
                       "(reports no device)")
    endif()
endif()

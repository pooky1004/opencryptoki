# Token NCMP - ncmpd daemon.
#
# The daemon links ALL transport backends and selects one at RUNTIME via the
# transport dispatcher (transport.c): --transport real|mock|socket (default
# real) / $NCMP_TRANSPORT. So one ncmpd binary can drive the real FX3 (libusb),
# the in-process mock emulator, or a socket frame server (mock_server).
add_executable(ncmpd
    main.c
    conn_thread.c
    comm_thread.c
    transport.c                 # runtime dispatcher (ncmp_transport_*)
    usb_transport.c             # ncmp_usb_ops   (real; libusb or stub)
    socket_transport.c          # ncmp_socket_ops
    pem_transport.c             # ncmp_pem_ops   (PEM token: NCMP<->CI v4)
    ${CMAKE_SOURCE_DIR}/pem/cifx_protocol.c   # PEM CI v4 codec
    ${CMAKE_SOURCE_DIR}/pem/ci_usb_lib.c      # PEM USB transport (usbfs ioctl, or
                                              # libusb with -DENABLE_PEM_LIBUSB)
    mock_backend.c              # ncmp_mock_ops  (uses the emulator below)
    # emulator sources for the mock backend (NOT ncmp_mock, which would also
    # export the public ncmp_transport_* and clash with the dispatcher):
    ${CMAKE_SOURCE_DIR}/mock/mcu_scheduler.c
    ${CMAKE_SOURCE_DIR}/mock/container.c
    ${CMAKE_SOURCE_DIR}/mock/fx3_dma.c
)
target_include_directories(ncmpd PRIVATE ${CMAKE_SOURCE_DIR}/mock ${CMAKE_SOURCE_DIR}/pem)
target_link_libraries(ncmpd PRIVATE ncmp_common)

# libusb is optional: usb_transport.c auto-detects it via __has_include and
# compiles a no-device stub when absent. Link it when found so the real path
# is built.
find_package(LibUSB QUIET)
if(LibUSB_FOUND OR TARGET LibUSB::LibUSB)
    target_link_libraries(ncmpd PRIVATE LibUSB::LibUSB)
    message(STATUS "Token NCMP: ncmpd linked against libusb (real transport active)")
else()
    message(STATUS "Token NCMP: libusb not found; ncmpd real transport is a "
                   "no-device stub (mock/socket still work)")
endif()

install(TARGETS ncmpd RUNTIME DESTINATION sbin)

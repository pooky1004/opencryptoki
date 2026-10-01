# Token NCMP - ncmpd daemon.
#
# Transport backend is chosen at configure time: the in-process mock loopback
# (ncmp_mock) when ENABLE_MOCK_TOKEN is set, otherwise the real libusb path in
# usb_transport.c. Exactly one implementation of ncmp_transport_* is linked.
set(NCMPD_SOURCES
    main.c
    conn_thread.c
    comm_thread.c
)

add_executable(ncmpd ${NCMPD_SOURCES})
target_link_libraries(ncmpd PRIVATE ncmp_common)

# Transport backend selection (exactly one):
#   ENABLE_MOCK_TOKEN   -> in-process emulator (ncmp_mock)
#   ENABLE_SOCKET_TOKEN -> TCP socket to a frame server (GUI mock_server); lets
#                          ncmpd drive the real STDLL stack without hardware.
#   (default)           -> real libusb FX3 transport (usb_transport.c)
option(ENABLE_SOCKET_TOKEN
       "Route the daemon transport over a TCP socket to a frame server (mock_server)"
       OFF)

if(ENABLE_MOCK_TOKEN)
    target_compile_definitions(ncmpd PRIVATE NCMP_USE_MOCK_TRANSPORT=1)
    target_link_libraries(ncmpd PRIVATE ncmp_mock)
elseif(ENABLE_SOCKET_TOKEN)
    target_compile_definitions(ncmpd PRIVATE NCMP_USE_SOCKET_TRANSPORT=1)
    target_sources(ncmpd PRIVATE socket_transport.c)
else()
    target_sources(ncmpd PRIVATE usb_transport.c)
    find_package(LibUSB REQUIRED)
    target_link_libraries(ncmpd PRIVATE LibUSB::LibUSB)
endif()

install(TARGETS ncmpd RUNTIME DESTINATION sbin)

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

if(ENABLE_MOCK_TOKEN)
    target_compile_definitions(ncmpd PRIVATE NCMP_USE_MOCK_TRANSPORT=1)
    target_link_libraries(ncmpd PRIVATE ncmp_mock)
else()
    target_sources(ncmpd PRIVATE usb_transport.c)
    find_package(LibUSB REQUIRED)
    target_link_libraries(ncmpd PRIVATE LibUSB::LibUSB)
endif()

install(TARGETS ncmpd RUNTIME DESTINATION sbin)

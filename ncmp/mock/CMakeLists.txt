# Token NCMP - software mock / emulator.
#
# The emulator + loopback transport are packaged as a static library
# (ncmp_mock) that is ALWAYS built: the daemon links it in mock mode and the
# test suite links it for the end-to-end loopback tests. Only the standalone
# mock_token_ncmp executable is gated behind ENABLE_MOCK_TOKEN.
add_library(ncmp_mock STATIC
    mock_transport.c
    fx3_dma.c
    container.c
    mcu_scheduler.c
)
target_include_directories(ncmp_mock PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(ncmp_mock PUBLIC ncmp_common)

if(ENABLE_MOCK_TOKEN)
    add_executable(mock_token_ncmp mock_main.c)
    target_link_libraries(mock_token_ncmp PRIVATE ncmp_mock)
endif()

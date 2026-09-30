# Token NCMP - mock HSM socket server (developer tool).
#
# Wraps the emulator (ncmp_mock) in a TCP server so the PySide6 GUIs (and any
# socket client) can drive one or more emulated tokens over a link. Built by
# default; disable with -DENABLE_GUI_SERVER=OFF.
option(ENABLE_GUI_SERVER "Build the mock HSM socket server for the GUIs" ON)

if(ENABLE_GUI_SERVER)
    find_package(Threads REQUIRED)
    add_executable(mock_server mock_server.c)
    target_include_directories(mock_server PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/mock)
    target_link_libraries(mock_server PRIVATE ncmp_mock Threads::Threads)
endif()

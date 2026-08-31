# Token NCMP - shared library of transport primitives (mutex, queue, wire,
# SHM). Linked statically into the daemon, STDLL, and test suite.
add_library(ncmp_common STATIC
    ncmp_mutex.c
    ncmp_queue.c
    ncmp_wire.c
    ncmp_shm.c
    ncmp_slot.c
    ncmp_ipc.c
)

# Robust process-shared mutexes and shm_open require pthread + rt.
find_package(Threads REQUIRED)
target_link_libraries(ncmp_common PUBLIC Threads::Threads)
if(NOT APPLE)
    target_link_libraries(ncmp_common PUBLIC rt)
endif()

target_include_directories(ncmp_common PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

# Token NCMP - top-level CMake build for the NCMP subsystem.
#
# This tree builds the standalone daemon (ncmpd), the PKCS#11 STDLL
# (libpkcs11_ncmp.so), the software mock token, and the test suite. It is
# self-contained so it can be developed without the full opencryptoki
# autotools build; integration into opencryptoki proper is documented in
# ../docs/architecture.md ("opencryptoki integration").
cmake_minimum_required(VERSION 3.16)
project(token_ncmp C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Google C style leans on warnings-as-signal; keep the build strict.
add_compile_options(-Wall -Wextra -Wshadow -Wpointer-arith -Wcast-qual)

# Robust process-shared mutexes need the GNU/POSIX-2008 feature set on glibc.
add_compile_definitions(_GNU_SOURCE)

option(ENABLE_MOCK_TOKEN
       "Build the software mock token and route the daemon transport to it"
       OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Public headers shared by every target.
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

enable_testing()

add_subdirectory(common)
# The mock subtree always builds the ncmp_mock library (loopback transport +
# emulator); the standalone executable inside it is gated by ENABLE_MOCK_TOKEN.
add_subdirectory(mock)
add_subdirectory(daemon)
add_subdirectory(stdll)
add_subdirectory(tests)

message(STATUS "Token NCMP: ENABLE_MOCK_TOKEN=${ENABLE_MOCK_TOKEN}")

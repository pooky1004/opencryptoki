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

# Static libraries are linked into the shared PKCS#11 STDLL, so build all
# objects position-independent.
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(ENABLE_MOCK_TOKEN
       "Build the software mock token and route the daemon transport to it"
       OFF)

# Multipart context placement (digest, AES-GCM): OFF keeps the context on the
# physical token; ON makes the token stateless and has the daemon's comm_thread
# manage the context blobs host-side (HSM storage is scarce). See
# docs/command-interface.md and ncmp/daemon/comm_thread.c.
option(NCMP_HOST_MANAGED_CTX
       "Keep multipart operation contexts host-side (comm_thread) instead of on the token"
       OFF)
if(NCMP_HOST_MANAGED_CTX)
    add_compile_definitions(NCMP_HOST_MANAGED_CTX)
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# PEM token USB transport (ncmp/pem/ci_usb_lib.c): OFF drives the device with
# direct usbfs ioctl (USBDEVFS_BULK, no libusb); ON routes it through
# libusb-1.0. Selected at compile time via the CI_USB_USE_LIBUSB macro; when ON,
# libusb is required and every target that compiles ci_usb_lib.c links it (the
# ncmpd / hsm_bridge targets already link libusb when found).
option(ENABLE_PEM_LIBUSB
       "Drive the PEM token over libusb-1.0 instead of direct usbfs ioctl"
       OFF)
if(ENABLE_PEM_LIBUSB)
    add_compile_definitions(CI_USB_USE_LIBUSB)
    find_package(LibUSB REQUIRED)
    message(STATUS "Token NCMP: PEM USB transport = libusb-1.0 (CI_USB_USE_LIBUSB)")
else()
    message(STATUS "Token NCMP: PEM USB transport = usbfs ioctl (default)")
endif()

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
# Developer GUIs: the mock HSM socket server (C) that the PySide6 apps drive.
add_subdirectory(gui/server)
# Test App native layer: libncmp_testapp.so (C application layer). It dlopen's
# the facade STDLL at runtime, so it has no build-time dependency on it.
add_subdirectory(gui/testapp/native)
# Test App web server: ncmp_web serves the browser UI and a JSON REST API over
# the native app_* layer, for use from an external host.
add_subdirectory(gui/testapp/webserver)
# Debug App server: ncmp_dbg handshakes with the ncmpd conn thread and serves a
# browser view of the shared memory per slot.
add_subdirectory(gui/debugapp)

message(STATUS "Token NCMP: ENABLE_MOCK_TOKEN=${ENABLE_MOCK_TOKEN}")

# Token NCMP - Test App native layer (libncmp_testapp.so).
#
# The C "Application" (app_* ABI) that the web server (ncmp_web) compiles in and
# drives. It dlopen's the facade STDLL (libpkcs11_ncmp[_p11].so) at RUNTIME and
# dlsym's every C_* entry point, so this target has NO build-time link against
# the STDLL - only the PKCS#11 headers are needed. The shared library is also
# useful on its own (dlopen from any host app). Disable with -DENABLE_TESTAPP=OFF.
option(ENABLE_TESTAPP "Build the Test App native layer (libncmp_testapp.so)" ON)

if(ENABLE_TESTAPP)
    add_library(ncmp_testapp SHARED ncmp_testapp.c)

    # opencryptoki PKCS#11 headers live under <repo>/usr/include; the ncmp build
    # root (CMAKE_SOURCE_DIR) is <repo>/ncmp, so they are one level up.
    target_include_directories(ncmp_testapp PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/../usr/include)

    target_compile_definitions(ncmp_testapp PRIVATE _GNU_SOURCE)
    set_target_properties(ncmp_testapp PROPERTIES
        OUTPUT_NAME ncmp_testapp
        C_STANDARD 11)

    # dlopen/dlsym of the facade.
    target_link_libraries(ncmp_testapp PRIVATE ${CMAKE_DL_LIBS})

    message(STATUS "Token NCMP: building Test App native layer "
                   "(libncmp_testapp.so, app_* ABI for ncmp_web)")
endif()

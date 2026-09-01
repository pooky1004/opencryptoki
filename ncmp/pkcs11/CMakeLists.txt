# Token NCMP - self-contained PKCS#11 provider (libpkcs11_ncmp.so).
#
# Unlike the opencryptoki STDLL adapter (usr/lib/ncmp_stdll, which gets its C_*
# entry points from opencryptoki's new_host.c), this target is a complete,
# directly-loadable PKCS#11 provider: it exports C_GetFunctionList /
# C_GetInterfaceList / C_GetInterface and every C_* function itself, forwarding
# crypto to ncmpd over the shared-memory transport. It also publishes the
# vendor-defined "NCMP Vendor" interface (ncmp_vendor.h).
add_library(pkcs11_ncmp SHARED
    p11_state.c
    p11_slotmap.c
    p11_api_general.c
    p11_api_slot.c
    p11_api_session.c
    p11_api_object.c
    p11_api_crypt.c
    p11_api_key.c
    p11_functionlist.c
    p11_vendor.c
)

set_target_properties(pkcs11_ncmp PROPERTIES
    OUTPUT_NAME pkcs11_ncmp
    VERSION 0.0.0
    SOVERSION 0)

# The PKCS#11 headers (pkcs11types.h, apiclient.h) live in the opencryptoki
# tree one level above this CMake project.
target_include_directories(pkcs11_ncmp PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/../usr/include)

target_link_libraries(pkcs11_ncmp PRIVATE ncmp_stdll_client ncmp_common)

install(TARGETS pkcs11_ncmp LIBRARY DESTINATION lib/opencryptoki/stdll)
install(FILES ncmp_vendor.h DESTINATION include/opencryptoki)

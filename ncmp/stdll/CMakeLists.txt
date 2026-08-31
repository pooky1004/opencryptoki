# Token NCMP - PKCS#11 STDLL (libpkcs11_ncmp.so).
#
# Built as a shared object loadable by the opencryptoki API layer. When wired
# into the opencryptoki autotools tree this becomes stdll/libpkcs11_ncmp.so;
# here it is produced standalone for unit/integration testing.
add_library(pkcs11_ncmp SHARED
    ncmp_specific.c
    ncmp_client.c
    ncmp_session.c
    ncmp_ckr.c
)
set_target_properties(pkcs11_ncmp PROPERTIES
    OUTPUT_NAME pkcs11_ncmp
    VERSION 0.0.0
    SOVERSION 0)

target_link_libraries(pkcs11_ncmp PRIVATE ncmp_common)

install(TARGETS pkcs11_ncmp LIBRARY DESTINATION lib/opencryptoki/stdll)

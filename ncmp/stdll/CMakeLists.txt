# Token NCMP - reusable STDLL client transport.
#
# ncmp_client.c / ncmp_session.c / ncmp_ckr.c form the process-side transport to
# ncmpd (connect, attach SHM, enqueue commands, map errors). They are packaged
# as a static library consumed by the self-contained PKCS#11 provider
# (../pkcs11) and by the test suite.
#
# ncmp_specific.c and tok_struct.h are the opencryptoki token_specific SPI
# adapter; they require usr/lib/common and are built ONLY inside the opencryptoki
# autotools tree (see usr/lib/ncmp_stdll/ncmp_stdll.mk), never in this standalone
# CMake build.
add_library(ncmp_stdll_client STATIC
    ncmp_client.c
    ncmp_session.c
    ncmp_ckr.c
)

target_link_libraries(ncmp_stdll_client PUBLIC ncmp_common)

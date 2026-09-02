# Token NCMP - reusable STDLL client transport + crypto adapter.
#
# ncmp_client.c / ncmp_session.c / ncmp_ckr.c form the process-side transport to
# ncmpd (connect, attach SHM, enqueue commands, map errors); ncmp_crypto.c is
# the pure-buffer crypto marshalling adapter layered on top. They are packaged as
# a static library consumed by the test suite (and, in the opencryptoki autotools
# tree, the same sources are compiled directly into libpkcs11_ncmp.so).
#
# The opencryptoki token_specific SPI adapter (ncmp_specific.c + tok_struct.h)
# lives under usr/lib/ncmp_stdll/ and is built ONLY inside the opencryptoki
# autotools tree (see usr/lib/ncmp_stdll/ncmp_stdll.mk), where it forwards each
# token_specific_* callback through the ncmp_crypto adapter above.
add_library(ncmp_stdll_client STATIC
    ncmp_client.c
    ncmp_session.c
    ncmp_ckr.c
    ncmp_crypto.c
    ncmp_admin.c
)

target_link_libraries(ncmp_stdll_client PUBLIC ncmp_common)

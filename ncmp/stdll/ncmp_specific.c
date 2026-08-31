/*
 * Token NCMP - opencryptoki STDLL token-specific SPI.
 *
 * This is the seam where libpkcs11_ncmp.so plugs into opencryptoki. The real
 * build exports a `token_spec_t token_specific` describing the NCMP token and
 * maps the token_specific_* callbacks onto NCMP client operations. Only the
 * NCMP-facing skeleton is scaffolded here; the SPI struct is wired up when the
 * STDLL is integrated into the opencryptoki autotools tree (see
 * docs/architecture.md, "opencryptoki integration").
 */
#include "ncmp/ncmp_errno.h"

/**
 * @brief Initialize the NCMP token backend for a slot.
 * @param slot_id opencryptoki slot number.
 * @return CKR_OK equivalent on success. Maps NCMP_ERR_NODAEMON to
 *         CKR_TOKEN_NOT_PRESENT so PKCS#11 callers see a clean error when
 *         ncmpd is not running.
 */
int ncmp_token_specific_init(unsigned long slot_id)
{
    (void)slot_id;
    /* TODO: ncmp_client_init(); verify slot_id is in slot_mask. */
    return NCMP_ERR_NODAEMON;
}

/**
 * @brief Final teardown of the NCMP token backend for a slot.
 */
int ncmp_token_specific_final(unsigned long slot_id)
{
    (void)slot_id;
    return NCMP_OK;
}

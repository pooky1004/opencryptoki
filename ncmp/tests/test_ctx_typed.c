/*
 * Token NCMP - typed per-mechanism context tests (ncmp_ctx.h).
 *
 * Verifies that each context-bearing mechanism has its own typed context
 * structure, that the serialized form is self-describing (common header), and -
 * the security property - that an AES-GCM context carries only a key id, never
 * key bytes. This is the exact shape the daemon stores/relays under
 * NCMP_HOST_MANAGED_CTX, so a keyless GCM context means the middleware never
 * holds key material.
 */
#include "ncmp/ncmp_ctx.h"
#include "ncmp_test.h"

#include <string.h>

/* The GCM context is far too small to hold a key: it is exactly key_id + acc +
 * offset + flags + IV. This guards against anyone re-introducing a key field. */
_Static_assert(NCMP_CTX_GCM_WIRE == 39,
               "GCM context must be keyless (key referenced by id)");
_Static_assert(NCMP_CTX_DIGEST_WIRE == 16, "digest context wire size");

int test_ctx_digest_roundtrip(void)
{
    uint8_t blob[NCMP_HOST_CTX_BLOB_MAX];
    ncmp_ctx_digest_t a, b;
    uint32_t n;

    a.mech = NCMP_MECH_SHA256;
    a.acc = 0xDEADBEEFu;
    n = ncmp_ctx_digest_put(blob, &a);
    NCMP_CHECK(n == NCMP_CTX_DIGEST_WIRE);
    NCMP_CHECK(ncmp_ctx_type_of(blob, n) == NCMP_CTX_TYPE_DIGEST);
    NCMP_CHECK(ncmp_ctx_digest_get(blob, n, &b) == 0);
    NCMP_CHECK(b.mech == a.mech && b.acc == a.acc);

    /* A GCM parse of a digest blob must be rejected (typed dispatch). */
    {
        ncmp_ctx_gcm_t g;
        NCMP_CHECK(ncmp_ctx_gcm_get(blob, n, &g) == -1);
    }
    return 0;
}

int test_ctx_gcm_roundtrip(void)
{
    uint8_t blob[NCMP_HOST_CTX_BLOB_MAX];
    ncmp_ctx_gcm_t a, b;
    uint32_t n;

    memset(&a, 0, sizeof(a));
    a.key_id = 5;
    a.acc = 0x01020304u;
    a.offset = 48;
    a.enc = 1;
    a.taglen = 16;
    a.ivlen = 12;
    for (int i = 0; i < 12; ++i)
        a.iv[i] = (uint8_t)(0x20 + i);

    n = ncmp_ctx_gcm_put(blob, &a);
    NCMP_CHECK(n == NCMP_CTX_GCM_WIRE);
    NCMP_CHECK(ncmp_ctx_type_of(blob, n) == NCMP_CTX_TYPE_GCM);
    /* key_id occupies the word right after the header. */
    NCMP_CHECK(ncmp_rd_u32le(blob + NCMP_CTX_HDR_LEN) == a.key_id);

    NCMP_CHECK(ncmp_ctx_gcm_get(blob, n, &b) == 0);
    NCMP_CHECK(b.key_id == a.key_id && b.acc == a.acc && b.offset == a.offset);
    NCMP_CHECK(b.enc == a.enc && b.taglen == a.taglen && b.ivlen == a.ivlen);
    NCMP_CHECK(memcmp(b.iv, a.iv, sizeof(a.iv)) == 0);

    /* A digest parse of a GCM blob must be rejected. */
    {
        ncmp_ctx_digest_t d;
        NCMP_CHECK(ncmp_ctx_digest_get(blob, n, &d) == -1);
    }
    return 0;
}

int test_ctx_gcm_has_no_key(void)
{
    uint8_t blob[NCMP_HOST_CTX_BLOB_MAX];
    ncmp_ctx_gcm_t a;
    uint32_t n;
    /* A recognizable "key" pattern that must NOT appear anywhere in a context. */
    static const uint8_t key_pat[16] = {
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB
    };

    memset(&a, 0, sizeof(a));
    a.key_id = 3;            /* a key with these bytes would live under this id */
    a.taglen = 16;
    a.ivlen = 12;
    n = ncmp_ctx_gcm_put(blob, &a);

    /* The serialized context is fixed-size regardless of key length, and the
     * key pattern is absent: the context cannot and does not carry key bytes. */
    NCMP_CHECK(n == NCMP_CTX_GCM_WIRE);
    for (uint32_t i = 0; i + sizeof(key_pat) <= n; ++i)
        NCMP_CHECK(memcmp(blob + i, key_pat, sizeof(key_pat)) != 0);
    return 0;
}

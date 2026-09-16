/*
 * Token NCMP - Typed per-mechanism multipart operation contexts.
 *
 * Each context-bearing mechanism family carries a distinct context structure;
 * a common 8-byte header (type + length) prefixes every serialized context so
 * the token and the daemon can dispatch on it. The daemon (middleware) inspects
 * ONLY this header and copies the remainder opaquely.
 *
 * SECURITY: no sensitive material ever appears in a context. Keys are held by
 * the token (HSM-resident) and referenced by a small key id; the AES-GCM
 * context carries `key_id`, never key bytes. So a host-managed context
 * (NCMP_HOST_MANAGED_CTX; see comm_thread.c) that the middleware stores and
 * relays on every UPDATE/FINAL never exposes key material. Key bytes appear
 * only in the one-shot INIT request while in transit to the token.
 *
 * The on-wire layout is fixed little-endian (built with ncmp_rd/wr_u32le), so it
 * is independent of struct padding and stable across the STDLL, the daemon and
 * the token.
 */
#ifndef NCMP_CTX_H
#define NCMP_CTX_H

#include <stdint.h>
#include <string.h>

#include "ncmp_cmd.h" /* ncmp_rd_u32le / ncmp_wr_u32le */

/** Context kind tag (first word of every serialized context). */
enum ncmp_ctx_type {
    NCMP_CTX_TYPE_NONE   = 0u,
    NCMP_CTX_TYPE_DIGEST = 1u, /**< SHA-2 / SHA-3 multipart digest. */
    NCMP_CTX_TYPE_GCM    = 2u  /**< AES-GCM multipart. */
};

/** Sentinel: context references no token key (e.g. digest). */
#define NCMP_KEY_ID_NONE 0xFFFFFFFFu

/** Common header prefixing every serialized context: type(4) + len(4). */
#define NCMP_CTX_HDR_LEN 8u

/**
 * Digest (SHA-2/SHA-3) running context. The mechanism distinguishes
 * SHA-256/512/SHA3-*; there is no sensitive field. `acc` is the mock's running
 * accumulator (real firmware carries the true hash state instead).
 */
typedef struct ncmp_ctx_digest {
    uint32_t mech; /**< NCMP_MECH_* */
    uint32_t acc;  /**< Running accumulator (mock). */
} ncmp_ctx_digest_t;

/** Serialized size of a digest context (header + mech + acc). */
#define NCMP_CTX_DIGEST_WIRE (NCMP_CTX_HDR_LEN + 8u) /* 16 */

/**
 * AES-GCM running context. The key is referenced by `key_id` (a token-resident
 * key handle); key BYTES are never stored here, so the middleware never sees key
 * material. The IV is not secret and travels in the context. `acc`/`offset` are
 * the mock's running tag accumulator and keystream position.
 */
typedef struct ncmp_ctx_gcm {
    uint32_t key_id; /**< Token key handle (NOT the key bytes). */
    uint32_t acc;    /**< Running tag accumulator (mock). */
    uint32_t offset; /**< Keystream position (bytes processed). */
    uint8_t  enc;    /**< Non-zero for encrypt. */
    uint8_t  taglen; /**< Tag length in bytes. */
    uint8_t  ivlen;  /**< IV length in bytes. */
    uint8_t  iv[16]; /**< Initialization vector (not secret). */
} ncmp_ctx_gcm_t;

/** Serialized size of a GCM context (header + key_id/acc/offset + flags + iv). */
#define NCMP_CTX_GCM_WIRE (NCMP_CTX_HDR_LEN + 12u + 3u + 16u) /* 39 */

/** Read the context kind from a serialized blob, or NONE if too short. */
static inline uint32_t ncmp_ctx_type_of(const uint8_t *b, uint32_t len)
{
    if (b == NULL || len < NCMP_CTX_HDR_LEN)
        return NCMP_CTX_TYPE_NONE;
    return ncmp_rd_u32le(b);
}

/** Serialize @p c into @p b (>= NCMP_CTX_DIGEST_WIRE); returns bytes written. */
static inline uint32_t ncmp_ctx_digest_put(uint8_t *b,
                                           const ncmp_ctx_digest_t *c)
{
    ncmp_wr_u32le(b + 0, NCMP_CTX_TYPE_DIGEST);
    ncmp_wr_u32le(b + 4, NCMP_CTX_DIGEST_WIRE);
    ncmp_wr_u32le(b + 8, c->mech);
    ncmp_wr_u32le(b + 12, c->acc);
    return NCMP_CTX_DIGEST_WIRE;
}

/** Parse a digest context from @p b; returns 0 on success, -1 on mismatch. */
static inline int ncmp_ctx_digest_get(const uint8_t *b, uint32_t len,
                                      ncmp_ctx_digest_t *c)
{
    if (len < NCMP_CTX_DIGEST_WIRE || ncmp_rd_u32le(b) != NCMP_CTX_TYPE_DIGEST)
        return -1;
    c->mech = ncmp_rd_u32le(b + 8);
    c->acc = ncmp_rd_u32le(b + 12);
    return 0;
}

/** Serialize @p c into @p b (>= NCMP_CTX_GCM_WIRE); returns bytes written. */
static inline uint32_t ncmp_ctx_gcm_put(uint8_t *b, const ncmp_ctx_gcm_t *c)
{
    ncmp_wr_u32le(b + 0, NCMP_CTX_TYPE_GCM);
    ncmp_wr_u32le(b + 4, NCMP_CTX_GCM_WIRE);
    ncmp_wr_u32le(b + 8, c->key_id);
    ncmp_wr_u32le(b + 12, c->acc);
    ncmp_wr_u32le(b + 16, c->offset);
    b[20] = c->enc;
    b[21] = c->taglen;
    b[22] = c->ivlen;
    memcpy(b + 23, c->iv, sizeof(c->iv));
    return NCMP_CTX_GCM_WIRE;
}

/** Parse a GCM context from @p b; returns 0 on success, -1 on mismatch. */
static inline int ncmp_ctx_gcm_get(const uint8_t *b, uint32_t len,
                                   ncmp_ctx_gcm_t *c)
{
    if (len < NCMP_CTX_GCM_WIRE || ncmp_rd_u32le(b) != NCMP_CTX_TYPE_GCM)
        return -1;
    c->key_id = ncmp_rd_u32le(b + 8);
    c->acc = ncmp_rd_u32le(b + 12);
    c->offset = ncmp_rd_u32le(b + 16);
    c->enc = b[20];
    c->taglen = b[21];
    c->ivlen = b[22];
    memcpy(c->iv, b + 23, sizeof(c->iv));
    return 0;
}

#endif /* NCMP_CTX_H */

/*
 * Token NCMP - STEP 3 tests: STDLL client round-trip over real IPC.
 *
 * Brings up an in-process "daemon" (SHM + one comm_thread + the conn_thread
 * serving a real UNIX socket) and drives it through the public client API:
 *   - ncmp_client_init() performs the IPC HELLO/ATTACH handshake + SHM attach,
 *   - ncmp_client_exec() enqueues a command and returns the token's response,
 *   - offline slots are rejected and map to CKR_TOKEN_NOT_PRESENT,
 *   - a token ACK error is surfaced verbatim (CKR_FUNCTION_FAILED).
 */
#include "ncmp/ncmp_client.h"
#include "ncmp/ncmp_ckr.h"
#include "ncmp/ncmp_cmd.h"
#include "ncmp/ncmp_shm.h"
#include "ncmp/ncmp_transport.h"
#include "ncmp/ncmp_wire.h"
#include "ncmp/ncmp_errno.h"
#include "ncmpd.h"
#include "mock_token_ncmp.h"
#include "ncmp_test.h"

#include <pthread.h>
#include <sched.h>
#include <string.h>

#define TEST_SOCK "/tmp/ncmp_ipc_test.sock"

typedef struct {
    void             *shm_base;
    ncmp_transport_t *t;
    ncmpd_slot_ctx_t  comm;
    ncmpd_conn_ctx_t  conn;
} harness_t;

/** Stand up SHM, mark slot 0 online, and start comm + conn threads. */
static int harness_up(harness_t *hz)
{
    NCMP_Slot *slot;

    memset(hz, 0, sizeof(*hz));
    (void)ncmp_shm_destroy(NULL);
    if (ncmp_shm_create(&hz->shm_base) != NCMP_OK)
        return -1;

    slot = ncmp_shm_slot(hz->shm_base, 0);
    slot->state = NCMP_SLOT_ONLINE;

    if (ncmp_transport_open(0, &hz->t) != NCMP_OK)
        return -1;

    hz->comm.shm_base = hz->shm_base;
    hz->comm.slot = slot;
    hz->comm.slot_id = 0;
    hz->comm.transport = hz->t;
    if (pthread_create(&hz->comm.thread, NULL, ncmpd_comm_thread, &hz->comm))
        return -1;

    hz->conn.shm_base = hz->shm_base;
    hz->conn.sock_path = TEST_SOCK;
    if (pthread_create(&hz->conn.thread, NULL, ncmpd_conn_thread, &hz->conn))
        return -1;

    return 0;
}

static void harness_down(harness_t *hz)
{
    ncmpd_request_stop(&hz->conn.stop);
    pthread_join(hz->conn.thread, NULL);
    ncmpd_request_stop(&hz->comm.stop);
    pthread_join(hz->comm.thread, NULL);
    ncmp_transport_close(hz->t);
    ncmp_shm_destroy(hz->shm_base);
}

/** Connect with retry: the conn_thread may not have bound the socket yet. */
static int client_connect_retry(ncmp_client_t *c)
{
    for (int i = 0; i < 100000; ++i) {
        if (ncmp_client_init(c, TEST_SOCK) == NCMP_OK)
            return NCMP_OK;
        sched_yield();
    }
    return NCMP_ERR_NODAEMON;
}

static void fill_req(NCMP_Message *req, uint8_t *body, uint32_t session,
                     uint32_t seq, uint32_t command, const char *tag)
{
    memset(req, 0, sizeof(*req));
    req->header.session_id = session;
    req->header.sequence_id = seq;
    req->header.command_id = command;
    memcpy(body, tag, 4);
    req->param_len[0] = 4;
    req->payload = body;
    req->payload_cap = 4;
}

int test_client_roundtrip(void)
{
    harness_t hz;
    ncmp_client_t c;
    NCMP_Message req, rsp;
    uint8_t body[8], rpl[32];

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);
    NCMP_CHECK((c.slot_mask & 1u) != 0);          /* slot 0 online */
    NCMP_CHECK((c.slot_mask & (1u << 1)) == 0);   /* slot 1 offline */

    /* Successful command: echoed identity + payload, ACK == CKR_OK. Uses the
     * NOP opcode (a bare command_id could now collide with a real opcode). */
    fill_req(&req, body, 7u, 1u, NCMP_CMD_NOP, "HELO");
    memset(&rsp, 0, sizeof(rsp));
    rsp.payload = rpl;
    rsp.payload_cap = sizeof(rpl);

    NCMP_CHECK(ncmp_client_exec(&c, 0, &req, &rsp, 0) == NCMP_OK);
    NCMP_CHECK(ncmp_err_to_ckr(NCMP_OK) == NCMP_CKR_OK);
    NCMP_CHECK(rsp.header.ack == NCMP_CKR_OK);
    NCMP_CHECK(rsp.header.session_id == 7u);
    NCMP_CHECK(rsp.header.sequence_id == 1u);
    NCMP_CHECK(rsp.param_len[0] == 4);
    NCMP_CHECK(memcmp(rsp.payload, "HELO", 4) == 0);

    /* Command to an offline slot is rejected -> CKR_TOKEN_NOT_PRESENT. */
    {
        int rc = ncmp_client_exec(&c, 1, &req, &rsp, 0);
        NCMP_CHECK(rc == NCMP_ERR_NODAEMON);
        NCMP_CHECK(ncmp_err_to_ckr(rc) == NCMP_CKR_TOKEN_NOT_PRESENT);
    }

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_client_rng_forward(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint8_t lenbuf[4];
    uint8_t out[64];
    uint32_t out_len = 0;
    uint32_t ack = 0xdead;
    int rc;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    /* Request 64 random bytes via the RNG opcode. */
    ncmp_wr_u32le(lenbuf, sizeof(out));
    rc = ncmp_client_command(&c, 0, NCMP_CMD_RNG, lenbuf, sizeof(lenbuf),
                             out, sizeof(out), &out_len, &ack);
    NCMP_CHECK(rc == NCMP_OK);
    NCMP_CHECK(ack == NCMP_CKR_OK);
    NCMP_CHECK(out_len == sizeof(out));

    /* Mock RNG is a deterministic pattern; verify it byte-for-byte. */
    for (uint32_t i = 0; i < sizeof(out); ++i)
        NCMP_CHECK(out[i] == NCMP_MOCK_RNG_BYTE(i));

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

/* Build a digest request blob: [mech LE u32 | data] into buf; returns length. */
static uint32_t build_digest_req(uint8_t *buf, uint32_t mech,
                                 const char *data, uint32_t data_len)
{
    ncmp_wr_u32le(buf, mech);
    for (uint32_t i = 0; i < data_len; ++i)
        buf[4 + i] = (uint8_t)data[i];
    return 4 + data_len;
}

int test_client_digest_forward(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint8_t req[64];
    uint8_t d1[32], d1b[32], d2[32], bad[8];
    uint32_t rl, out_len, ack;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    /* SHA-256 over "hello": 32-byte digest, ACK ok. */
    rl = build_digest_req(req, NCMP_MECH_SHA256, "hello", 5);
    out_len = 0; ack = 0xdead;
    NCMP_CHECK(ncmp_client_command(&c, 0, NCMP_CMD_DIGEST, req, rl,
                                   d1, sizeof(d1), &out_len, &ack) == NCMP_OK);
    NCMP_CHECK(ack == NCMP_CKR_OK);
    NCMP_CHECK(out_len == ncmp_digest_size(NCMP_MECH_SHA256)); /* 32 */

    /* Deterministic: same input -> identical digest. */
    rl = build_digest_req(req, NCMP_MECH_SHA256, "hello", 5);
    NCMP_CHECK(ncmp_client_command(&c, 0, NCMP_CMD_DIGEST, req, rl,
                                   d1b, sizeof(d1b), &out_len, &ack) == NCMP_OK);
    NCMP_CHECK(memcmp(d1, d1b, 32) == 0);

    /* Input-sensitive: different input -> different digest. */
    rl = build_digest_req(req, NCMP_MECH_SHA256, "world", 5);
    NCMP_CHECK(ncmp_client_command(&c, 0, NCMP_CMD_DIGEST, req, rl,
                                   d2, sizeof(d2), &out_len, &ack) == NCMP_OK);
    NCMP_CHECK(memcmp(d1, d2, 32) != 0);

    /* Unsupported mechanism -> token reports CKR_MECHANISM_INVALID. */
    rl = build_digest_req(req, 0x00000999u, "x", 1);
    ack = NCMP_CKR_OK;
    NCMP_CHECK(ncmp_client_command(&c, 0, NCMP_CMD_DIGEST, req, rl,
                                   bad, sizeof(bad), &out_len, &ack) == NCMP_OK);
    NCMP_CHECK(ack == 0x70u); /* CKR_MECHANISM_INVALID */

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_client_digest_multipart(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint8_t mechbuf[4], idbuf[4], out_mp[32], out_1shot[64], req[64];
    const uint8_t *parts[2];
    uint32_t lens[2], out_len, ack;
    NCMP_Message rsp;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    /* INIT -> context id. */
    ncmp_wr_u32le(mechbuf, NCMP_MECH_SHA256);
    NCMP_CHECK(ncmp_client_command(&c, 0, NCMP_CMD_DIGEST_INIT, mechbuf, 4,
                                   idbuf, sizeof(idbuf), &out_len, &ack)
               == NCMP_OK);
    NCMP_CHECK(ack == NCMP_CKR_OK && out_len == 4);

    /* UPDATE("hel") then UPDATE("lo") - two chunks of the same total input.
     * The opaque context id in idbuf is echoed straight back to the token. */
    parts[0] = idbuf; lens[0] = 4;
    parts[1] = (const uint8_t *)"hel"; lens[1] = 3;
    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_DIGEST_UPDATE, parts, lens,
                                      2, NULL, 0, &rsp) == NCMP_OK);
    NCMP_CHECK(rsp.header.ack == NCMP_CKR_OK);
    parts[1] = (const uint8_t *)"lo"; lens[1] = 2;
    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_DIGEST_UPDATE, parts, lens,
                                      2, NULL, 0, &rsp) == NCMP_OK);
    NCMP_CHECK(rsp.header.ack == NCMP_CKR_OK);

    /* FINAL -> multipart digest. */
    NCMP_CHECK(ncmp_client_command(&c, 0, NCMP_CMD_DIGEST_FINAL, idbuf, 4,
                                   out_mp, sizeof(out_mp), &out_len, &ack)
               == NCMP_OK);
    NCMP_CHECK(ack == NCMP_CKR_OK && out_len == 32);

    /* Context freed: a second FINAL on the same id must fail. */
    NCMP_CHECK(ncmp_client_command(&c, 0, NCMP_CMD_DIGEST_FINAL, idbuf, 4,
                                   out_mp, sizeof(out_mp), &out_len, &ack)
               == NCMP_OK);
    NCMP_CHECK(ack == 0x6u); /* CKR_FUNCTION_FAILED */

    /* Re-run FINAL clobbered out_mp; recompute the multipart digest cleanly. */
    ncmp_wr_u32le(mechbuf, NCMP_MECH_SHA256);
    NCMP_CHECK(ncmp_client_command(&c, 0, NCMP_CMD_DIGEST_INIT, mechbuf, 4,
                                   idbuf, sizeof(idbuf), &out_len, &ack)
               == NCMP_OK);
    parts[0] = idbuf; lens[0] = 4;
    parts[1] = (const uint8_t *)"hello"; lens[1] = 5;
    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_DIGEST_UPDATE, parts, lens,
                                      2, NULL, 0, &rsp) == NCMP_OK);
    NCMP_CHECK(ncmp_client_command(&c, 0, NCMP_CMD_DIGEST_FINAL, idbuf, 4,
                                   out_mp, sizeof(out_mp), &out_len, &ack)
               == NCMP_OK);

    /* Multipart("hello") must equal one-shot("hello"). */
    ncmp_wr_u32le(req, NCMP_MECH_SHA256);
    memcpy(req + 4, "hello", 5);
    NCMP_CHECK(ncmp_client_command(&c, 0, NCMP_CMD_DIGEST, req, 4 + 5,
                                   out_1shot, sizeof(out_1shot), &out_len, &ack)
               == NCMP_OK);
    NCMP_CHECK(ack == NCMP_CKR_OK && out_len == 32);
    NCMP_CHECK(memcmp(out_mp, out_1shot, 32) == 0);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_client_aes_cbc_forward(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint8_t key[16], iv[16], data[32], ct[32], pt[32], flags[4];
    const uint8_t *parts[4];
    uint32_t lens[4];
    NCMP_Message rsp;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    for (int i = 0; i < 16; ++i) { key[i] = (uint8_t)(i + 1); iv[i] = (uint8_t)(0xF0 + i); }
    for (int i = 0; i < 32; ++i) data[i] = (uint8_t)(i * 7 + 3);

    parts[1] = key; lens[1] = sizeof(key);
    parts[2] = iv;  lens[2] = sizeof(iv);

    /* Encrypt. */
    ncmp_wr_u32le(flags, NCMP_AES_FLAG_ENCRYPT);
    parts[0] = flags; lens[0] = 4;
    parts[3] = data;  lens[3] = sizeof(data);
    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_AES_CBC, parts, lens, 4,
                                      ct, sizeof(ct), &rsp) == NCMP_OK);
    NCMP_CHECK(rsp.header.ack == NCMP_CKR_OK);
    NCMP_CHECK(rsp.param_len[0] == sizeof(ct));
    NCMP_CHECK(memcmp(ct, data, sizeof(data)) != 0);  /* transformed */

    /* Decrypt the ciphertext -> must recover the plaintext (round-trip). */
    ncmp_wr_u32le(flags, 0u);
    parts[0] = flags; lens[0] = 4;
    parts[3] = ct;    lens[3] = sizeof(ct);
    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_AES_CBC, parts, lens, 4,
                                      pt, sizeof(pt), &rsp) == NCMP_OK);
    NCMP_CHECK(rsp.header.ack == NCMP_CKR_OK);
    NCMP_CHECK(memcmp(pt, data, sizeof(data)) == 0);

    /* Bad data length (not a block multiple) -> token rejects. */
    parts[3] = data; lens[3] = 20;
    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_AES_CBC, parts, lens, 4,
                                      ct, sizeof(ct), &rsp) == NCMP_OK);
    NCMP_CHECK(rsp.header.ack == 0x70u); /* CKR_MECHANISM_INVALID */

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_client_rsa_sign_forward(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint8_t mod[256], exp[256], data[32], sig[256], sig2[256];
    const uint8_t *parts[3];
    uint32_t lens[3];
    NCMP_Message rsp;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    for (int i = 0; i < 256; ++i) { mod[i] = (uint8_t)(i ^ 0x5A); exp[i] = (uint8_t)(i * 3 + 1); }
    for (int i = 0; i < 32; ++i) data[i] = (uint8_t)(i + 100);

    parts[0] = mod;  lens[0] = sizeof(mod);
    parts[1] = exp;  lens[1] = sizeof(exp);
    parts[2] = data; lens[2] = sizeof(data);

    /* Sign: signature length == modulus length (256 = RSA-2048). */
    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_RSA_SIGN, parts, lens, 3,
                                      sig, sizeof(sig), &rsp) == NCMP_OK);
    NCMP_CHECK(rsp.header.ack == NCMP_CKR_OK);
    NCMP_CHECK(rsp.param_len[0] == sizeof(mod));

    /* Deterministic: identical inputs -> identical signature. */
    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_RSA_SIGN, parts, lens, 3,
                                      sig2, sizeof(sig2), &rsp) == NCMP_OK);
    NCMP_CHECK(memcmp(sig, sig2, sizeof(sig)) == 0);

    /* Input-sensitive: different data -> different signature. */
    data[0] ^= 0xFF;
    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_RSA_SIGN, parts, lens, 3,
                                      sig2, sizeof(sig2), &rsp) == NCMP_OK);
    NCMP_CHECK(memcmp(sig, sig2, sizeof(sig)) != 0);
    data[0] ^= 0xFF;

    /* Key-sensitive: different modulus -> different signature (the modulus is
     * the key component both sign and verify fold). */
    mod[0] ^= 0xFF;
    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_RSA_SIGN, parts, lens, 3,
                                      sig2, sizeof(sig2), &rsp) == NCMP_OK);
    NCMP_CHECK(memcmp(sig, sig2, sizeof(sig)) != 0);
    mod[0] ^= 0xFF;

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_client_aes_gcm_forward(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint8_t key[16], iv[12], aad[8], data[32], ct[48], pt[32], flags[4], tl[4];
    const uint8_t *parts[6];
    uint32_t lens[6];
    NCMP_Message rsp;
    const uint32_t taglen = 16;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    for (int i = 0; i < 16; ++i) key[i] = (uint8_t)(i + 3);
    for (int i = 0; i < 12; ++i) iv[i] = (uint8_t)(0xA0 + i);
    for (int i = 0; i < 8; ++i) aad[i] = (uint8_t)(i * 2);
    for (int i = 0; i < 32; ++i) data[i] = (uint8_t)(i * 11 + 4);

    ncmp_wr_u32le(tl, taglen);
    parts[1] = key; lens[1] = sizeof(key);
    parts[2] = iv;  lens[2] = sizeof(iv);
    parts[3] = aad; lens[3] = sizeof(aad);
    parts[4] = tl;  lens[4] = 4;

    /* Encrypt -> ciphertext || tag. */
    ncmp_wr_u32le(flags, NCMP_AES_FLAG_ENCRYPT);
    parts[0] = flags; lens[0] = 4;
    parts[5] = data;  lens[5] = sizeof(data);
    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_AES_GCM, parts, lens, 6,
                                      ct, sizeof(ct), &rsp) == NCMP_OK);
    NCMP_CHECK(rsp.header.ack == NCMP_CKR_OK);
    NCMP_CHECK(rsp.param_len[0] == sizeof(data) + taglen); /* 48 */
    NCMP_CHECK(memcmp(ct, data, sizeof(data)) != 0);

    /* Decrypt ct||tag -> plaintext, tag verified. */
    ncmp_wr_u32le(flags, 0u);
    parts[0] = flags; lens[0] = 4;
    parts[5] = ct;    lens[5] = sizeof(ct);
    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_AES_GCM, parts, lens, 6,
                                      pt, sizeof(pt), &rsp) == NCMP_OK);
    NCMP_CHECK(rsp.header.ack == NCMP_CKR_OK);
    NCMP_CHECK(rsp.param_len[0] == sizeof(data));
    NCMP_CHECK(memcmp(pt, data, sizeof(data)) == 0);

    /* Tamper the ciphertext -> authentication must fail. */
    ct[0] ^= 0xFF;
    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_AES_GCM, parts, lens, 6,
                                      pt, sizeof(pt), &rsp) == NCMP_OK);
    NCMP_CHECK(rsp.header.ack == 0x40u); /* CKR_ENCRYPTED_DATA_INVALID */

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_client_aes_stream_forward(void)
{
    harness_t hz;
    ncmp_client_t c;
    const uint32_t modes[3] = { NCMP_CMD_AES_CTR, NCMP_CMD_AES_OFB,
                                NCMP_CMD_AES_CFB };
    uint8_t key[16], iv[16], data[20], ct[20], pt[20], flags[4];
    const uint8_t *parts[4];
    uint32_t lens[4];
    NCMP_Message rsp;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    for (int i = 0; i < 16; ++i) { key[i] = (uint8_t)(i + 8); iv[i] = (uint8_t)(0xB0 + i); }
    for (int i = 0; i < 20; ++i) data[i] = (uint8_t)(i * 13 + 2); /* non-block-multiple */

    parts[1] = key; lens[1] = sizeof(key);
    parts[2] = iv;  lens[2] = sizeof(iv);

    for (int m = 0; m < 3; ++m) {
        /* Encrypt a 20-byte (non-block-aligned) buffer. */
        ncmp_wr_u32le(flags, NCMP_AES_FLAG_ENCRYPT);
        parts[0] = flags; lens[0] = 4;
        parts[3] = data;  lens[3] = sizeof(data);
        NCMP_CHECK(ncmp_client_command_mp(&c, 0, modes[m], parts, lens, 4,
                                          ct, sizeof(ct), &rsp) == NCMP_OK);
        NCMP_CHECK(rsp.header.ack == NCMP_CKR_OK);
        NCMP_CHECK(rsp.param_len[0] == sizeof(data)); /* stream: out len == in */
        NCMP_CHECK(memcmp(ct, data, sizeof(data)) != 0);

        /* Decrypt -> recover the plaintext. */
        ncmp_wr_u32le(flags, 0u);
        parts[0] = flags; lens[0] = 4;
        parts[3] = ct;    lens[3] = sizeof(ct);
        NCMP_CHECK(ncmp_client_command_mp(&c, 0, modes[m], parts, lens, 4,
                                          pt, sizeof(pt), &rsp) == NCMP_OK);
        NCMP_CHECK(memcmp(pt, data, sizeof(data)) == 0);
    }

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_client_aes_ecb_forward(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint8_t key[16], data[32], ct[32], pt[32], flags[4];
    const uint8_t *parts[3];
    uint32_t lens[3];
    NCMP_Message rsp;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    for (int i = 0; i < 16; ++i) key[i] = (uint8_t)(i + 5);
    for (int i = 0; i < 32; ++i) data[i] = (uint8_t)(i * 9 + 1);

    parts[1] = key; lens[1] = sizeof(key);

    ncmp_wr_u32le(flags, NCMP_AES_FLAG_ENCRYPT);
    parts[0] = flags; lens[0] = 4;
    parts[2] = data;  lens[2] = sizeof(data);
    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_AES_ECB, parts, lens, 3,
                                      ct, sizeof(ct), &rsp) == NCMP_OK);
    NCMP_CHECK(rsp.header.ack == NCMP_CKR_OK && rsp.param_len[0] == sizeof(ct));
    NCMP_CHECK(memcmp(ct, data, sizeof(data)) != 0);

    ncmp_wr_u32le(flags, 0u);
    parts[0] = flags; lens[0] = 4;
    parts[2] = ct;    lens[2] = sizeof(ct);
    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_AES_ECB, parts, lens, 3,
                                      pt, sizeof(pt), &rsp) == NCMP_OK);
    NCMP_CHECK(memcmp(pt, data, sizeof(data)) == 0);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_client_ec_sign_forward(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint8_t ecp[10], priv[32], data[32], sig[64], sig2[64];
    const uint8_t *parts[3];
    uint32_t lens[3];
    NCMP_Message rsp;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    for (int i = 0; i < 10; ++i) ecp[i] = (uint8_t)(0x30 + i);   /* curve OID-ish */
    for (int i = 0; i < 32; ++i) { priv[i] = (uint8_t)(i * 5 + 7); data[i] = (uint8_t)(i + 2); }

    parts[0] = ecp;  lens[0] = sizeof(ecp);
    parts[1] = priv; lens[1] = sizeof(priv);
    parts[2] = data; lens[2] = sizeof(data);

    /* ECDSA signature length == 2 * private-scalar length. */
    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_EC_SIGN, parts, lens, 3,
                                      sig, sizeof(sig), &rsp) == NCMP_OK);
    NCMP_CHECK(rsp.header.ack == NCMP_CKR_OK);
    NCMP_CHECK(rsp.param_len[0] == 2 * sizeof(priv));

    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_EC_SIGN, parts, lens, 3,
                                      sig2, sizeof(sig2), &rsp) == NCMP_OK);
    NCMP_CHECK(memcmp(sig, sig2, sizeof(sig)) == 0);         /* deterministic */

    data[0] ^= 0xFF;                                          /* input-sensitive */
    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_EC_SIGN, parts, lens, 3,
                                      sig2, sizeof(sig2), &rsp) == NCMP_OK);
    NCMP_CHECK(memcmp(sig, sig2, sizeof(sig)) != 0);
    data[0] ^= 0xFF;

    ecp[0] ^= 0xFF;                                  /* curve-sensitive (mock) */
    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_EC_SIGN, parts, lens, 3,
                                      sig2, sizeof(sig2), &rsp) == NCMP_OK);
    NCMP_CHECK(memcmp(sig, sig2, sizeof(sig)) != 0);
    ecp[0] ^= 0xFF;

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_client_rsa_verify_forward(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint8_t mod[256], exp[256], data[32], sig[256];
    const uint8_t *parts[4];
    uint32_t lens[4];
    NCMP_Message rsp;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    for (int i = 0; i < 256; ++i) { mod[i] = (uint8_t)(i ^ 0x33); exp[i] = (uint8_t)(i + 1); }
    for (int i = 0; i < 32; ++i) data[i] = (uint8_t)(i * 3 + 5);

    /* Sign to obtain a valid signature. */
    parts[0] = mod;  lens[0] = sizeof(mod);
    parts[1] = exp;  lens[1] = sizeof(exp);
    parts[2] = data; lens[2] = sizeof(data);
    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_RSA_SIGN, parts, lens, 3,
                                      sig, sizeof(sig), &rsp) == NCMP_OK);
    NCMP_CHECK(rsp.header.ack == NCMP_CKR_OK);

    /* Verify: [modulus | pub_exp | data | sig] -> CKR_OK. */
    parts[3] = sig; lens[3] = sizeof(sig);
    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_RSA_VERIFY, parts, lens, 4,
                                      NULL, 0, &rsp) == NCMP_OK);
    NCMP_CHECK(rsp.header.ack == NCMP_CKR_OK);

    /* Tampered signature -> CKR_SIGNATURE_INVALID. */
    sig[0] ^= 0xFF;
    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_RSA_VERIFY, parts, lens, 4,
                                      NULL, 0, &rsp) == NCMP_OK);
    NCMP_CHECK(rsp.header.ack == 0xC0u); /* CKR_SIGNATURE_INVALID */

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_client_ec_verify_forward(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint8_t ecp[10], priv[32], point[20], data[32], sig[64];
    const uint8_t *parts[4];
    uint32_t lens[4];
    NCMP_Message rsp;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    for (int i = 0; i < 10; ++i) ecp[i] = (uint8_t)(0x30 + i);
    for (int i = 0; i < 20; ++i) point[i] = (uint8_t)(0x40 + i);
    for (int i = 0; i < 32; ++i) { priv[i] = (uint8_t)(i * 5 + 7); data[i] = (uint8_t)(i + 2); }

    /* Sign: [ec_params | priv | data]. */
    parts[0] = ecp;  lens[0] = sizeof(ecp);
    parts[1] = priv; lens[1] = sizeof(priv);
    parts[2] = data; lens[2] = sizeof(data);
    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_EC_SIGN, parts, lens, 3,
                                      sig, sizeof(sig), &rsp) == NCMP_OK);
    NCMP_CHECK(rsp.header.ack == NCMP_CKR_OK);

    /* Verify: [ec_params | ec_point | data | sig] -> CKR_OK. */
    parts[1] = point; lens[1] = sizeof(point);
    parts[3] = sig;   lens[3] = sizeof(sig);
    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_EC_VERIFY, parts, lens, 4,
                                      NULL, 0, &rsp) == NCMP_OK);
    NCMP_CHECK(rsp.header.ack == NCMP_CKR_OK);

    /* Tampered signature -> CKR_SIGNATURE_INVALID. */
    sig[0] ^= 0xFF;
    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_EC_VERIFY, parts, lens, 4,
                                      NULL, 0, &rsp) == NCMP_OK);
    NCMP_CHECK(rsp.header.ack == 0xC0u); /* CKR_SIGNATURE_INVALID */

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_client_rsa_keygen_forward(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint8_t bits[4], pubexp[3] = { 0x01, 0x00, 0x01 };
    static uint8_t out[8192];
    const uint8_t *parts[2];
    uint32_t lens[2];
    NCMP_Message rsp;
    const uint32_t mod_bits = 2048, nbytes = 256, hbytes = 128;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    ncmp_wr_u32le(bits, mod_bits);
    parts[0] = bits;   lens[0] = 4;
    parts[1] = pubexp; lens[1] = sizeof(pubexp);
    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_RSA_KEYGEN, parts, lens, 2,
                                      out, sizeof(out), &rsp) == NCMP_OK);
    NCMP_CHECK(rsp.header.ack == NCMP_CKR_OK);
    /* Components n, d, p, q, dp, dq, qinv with the expected sizes. */
    NCMP_CHECK(rsp.param_len[0] == nbytes); /* modulus */
    NCMP_CHECK(rsp.param_len[1] == nbytes); /* private exponent */
    NCMP_CHECK(rsp.param_len[2] == hbytes); /* prime1 */
    NCMP_CHECK(rsp.param_len[3] == hbytes); /* prime2 */
    NCMP_CHECK(rsp.param_len[4] == hbytes); /* exp1 */
    NCMP_CHECK(rsp.param_len[5] == hbytes); /* exp2 */
    NCMP_CHECK(rsp.param_len[6] == hbytes); /* coefficient */

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_client_ec_keygen_forward(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint8_t ecp[10], out[256];
    const uint8_t *parts[1];
    uint32_t lens[1];
    NCMP_Message rsp;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    for (int i = 0; i < 10; ++i) ecp[i] = (uint8_t)(0x30 + i);
    parts[0] = ecp; lens[0] = sizeof(ecp);
    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_EC_KEYGEN, parts, lens, 1,
                                      out, sizeof(out), &rsp) == NCMP_OK);
    NCMP_CHECK(rsp.header.ack == NCMP_CKR_OK);
    NCMP_CHECK(rsp.param_len[0] == 65); /* uncompressed EC point (P-256) */
    NCMP_CHECK(rsp.param_len[1] == 32); /* private scalar */

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_client_hmac_forward(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint8_t mechbuf[4], key[32], data[40], mac[32];
    const uint8_t *parts[4];
    uint32_t lens[4];
    NCMP_Message rsp;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    for (int i = 0; i < 32; ++i) key[i] = (uint8_t)(i + 11);
    for (int i = 0; i < 40; ++i) data[i] = (uint8_t)(i * 3 + 1);
    ncmp_wr_u32le(mechbuf, 0x00000251u); /* CKM_SHA256_HMAC -> 32-byte MAC */

    parts[0] = mechbuf; lens[0] = 4;
    parts[1] = key;     lens[1] = sizeof(key);
    parts[2] = data;    lens[2] = sizeof(data);
    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_HMAC_SIGN, parts, lens, 3,
                                      mac, sizeof(mac), &rsp) == NCMP_OK);
    NCMP_CHECK(rsp.header.ack == NCMP_CKR_OK && rsp.param_len[0] == 32);

    /* Verify: [mech | key | data | mac] -> CKR_OK. */
    parts[3] = mac; lens[3] = sizeof(mac);
    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_HMAC_VERIFY, parts, lens,
                                      4, NULL, 0, &rsp) == NCMP_OK);
    NCMP_CHECK(rsp.header.ack == NCMP_CKR_OK);

    /* Tampered MAC -> CKR_SIGNATURE_INVALID. */
    mac[0] ^= 0xFF;
    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_HMAC_VERIFY, parts, lens,
                                      4, NULL, 0, &rsp) == NCMP_OK);
    NCMP_CHECK(rsp.header.ack == 0xC0u); /* CKR_SIGNATURE_INVALID */

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_client_rsa_oaep_forward(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint8_t mod[256], exp[3] = { 0x01, 0x00, 0x01 }, data[32];
    static uint8_t ct[256], pt[256];
    const uint8_t *parts[3];
    uint32_t lens[3];
    NCMP_Message rsp;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    for (int i = 0; i < 256; ++i) mod[i] = (uint8_t)(i ^ 0x77);
    for (int i = 0; i < 32; ++i) data[i] = (uint8_t)(i * 9 + 4);

    /* Encrypt: [modulus | pub_exp | data] -> ciphertext (modulus length). */
    parts[0] = mod;  lens[0] = sizeof(mod);
    parts[1] = exp;  lens[1] = sizeof(exp);
    parts[2] = data; lens[2] = sizeof(data);
    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_RSA_OAEP_ENC, parts, lens,
                                      3, ct, sizeof(ct), &rsp) == NCMP_OK);
    NCMP_CHECK(rsp.header.ack == NCMP_CKR_OK);
    NCMP_CHECK(rsp.param_len[0] == sizeof(mod)); /* 256 */
    NCMP_CHECK(memcmp(ct, data, sizeof(data)) != 0);

    /* Decrypt: [modulus | priv_exp | ciphertext] -> recover plaintext. */
    parts[2] = ct; lens[2] = sizeof(ct);
    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_RSA_OAEP_DEC, parts, lens,
                                      3, pt, sizeof(pt), &rsp) == NCMP_OK);
    NCMP_CHECK(rsp.header.ack == NCMP_CKR_OK);
    NCMP_CHECK(rsp.param_len[0] == sizeof(data)); /* 32 */
    NCMP_CHECK(memcmp(pt, data, sizeof(data)) == 0);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_client_dh_derive_forward(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint8_t prime[128], priv[128], pub[128], secret[128], secret2[128];
    const uint8_t *parts[3];
    uint32_t lens[3];
    NCMP_Message rsp;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    for (int i = 0; i < 128; ++i) {
        prime[i] = (uint8_t)(0x80 + i); priv[i] = (uint8_t)(i * 3 + 1);
        pub[i] = (uint8_t)(i * 5 + 2);
    }
    parts[0] = prime; lens[0] = sizeof(prime);
    parts[1] = priv;  lens[1] = sizeof(priv);
    parts[2] = pub;   lens[2] = sizeof(pub);

    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_DH_DERIVE, parts, lens, 3,
                                      secret, sizeof(secret), &rsp) == NCMP_OK);
    NCMP_CHECK(rsp.header.ack == NCMP_CKR_OK);
    NCMP_CHECK(rsp.param_len[0] == sizeof(prime)); /* secret == prime length */

    /* Deterministic: same inputs -> same shared secret. */
    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_DH_DERIVE, parts, lens, 3,
                                      secret2, sizeof(secret2), &rsp) == NCMP_OK);
    NCMP_CHECK(memcmp(secret, secret2, sizeof(secret)) == 0);

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_client_ecdh_derive_forward(void)
{
    harness_t hz;
    ncmp_client_t c;
    uint8_t oid[10], priv[32], pub[65], secret[64];
    const uint8_t *parts[3];
    uint32_t lens[3];
    NCMP_Message rsp;

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    for (int i = 0; i < 10; ++i) oid[i] = (uint8_t)(0x30 + i);
    for (int i = 0; i < 32; ++i) priv[i] = (uint8_t)(i * 7 + 3);
    pub[0] = 0x04; /* uncompressed point */
    for (int i = 1; i < 65; ++i) pub[i] = (uint8_t)(i * 2 + 1);

    parts[0] = oid;  lens[0] = sizeof(oid);
    parts[1] = priv; lens[1] = sizeof(priv);
    parts[2] = pub;  lens[2] = sizeof(pub);
    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_ECDH_DERIVE, parts, lens,
                                      3, secret, sizeof(secret), &rsp)
               == NCMP_OK);
    NCMP_CHECK(rsp.header.ack == NCMP_CKR_OK);
    NCMP_CHECK(rsp.param_len[0] == 32); /* field size = (65-1)/2 */

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

int test_ack_error_propagation(void)
{
    harness_t hz;
    ncmp_client_t c;
    NCMP_Message req, rsp;
    uint8_t body[8], rpl[32];

    NCMP_CHECK(harness_up(&hz) == 0);
    NCMP_CHECK(client_connect_retry(&c) == NCMP_OK);

    /* Fail-injection bit set in command_id -> token returns CKR_FUNCTION_FAILED
     * in the ACK, while the transport call itself still succeeds. */
    fill_req(&req, body, 9u, 2u, 0x20u | NCMP_MOCK_CMD_FAIL_BIT, "FAIL");
    memset(&rsp, 0, sizeof(rsp));
    rsp.payload = rpl;
    rsp.payload_cap = sizeof(rpl);

    NCMP_CHECK(ncmp_client_exec(&c, 0, &req, &rsp, 0) == NCMP_OK);
    NCMP_CHECK(rsp.header.ack == NCMP_CKR_FUNCTION_FAILED);
    NCMP_CHECK(rsp.header.sequence_id == 2u); /* identity preserved */

    NCMP_CHECK(ncmp_client_fini(&c) == NCMP_OK);
    harness_down(&hz);
    return 0;
}

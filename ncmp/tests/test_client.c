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

    /* AES-CTR is the only advertised AES stream mode. Encrypt a 20-byte
     * (non-block-aligned) buffer, then decrypt it back. */
    ncmp_wr_u32le(flags, NCMP_AES_FLAG_ENCRYPT);
    parts[0] = flags; lens[0] = 4;
    parts[3] = data;  lens[3] = sizeof(data);
    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_AES_CTR, parts, lens, 4,
                                      ct, sizeof(ct), &rsp) == NCMP_OK);
    NCMP_CHECK(rsp.header.ack == NCMP_CKR_OK);
    NCMP_CHECK(rsp.param_len[0] == sizeof(data)); /* stream: out len == in */
    NCMP_CHECK(memcmp(ct, data, sizeof(data)) != 0);

    ncmp_wr_u32le(flags, 0u);
    parts[0] = flags; lens[0] = 4;
    parts[3] = ct;    lens[3] = sizeof(ct);
    NCMP_CHECK(ncmp_client_command_mp(&c, 0, NCMP_CMD_AES_CTR, parts, lens, 4,
                                      pt, sizeof(pt), &rsp) == NCMP_OK);
    NCMP_CHECK(memcmp(pt, data, sizeof(data)) == 0);

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
    fill_req(&req, body, 9u, 2u, NCMP_CMD_NOP | NCMP_MOCK_CMD_FAIL_BIT, "FAIL");
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

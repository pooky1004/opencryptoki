/*
 * Token NCMP - Step-1 end-to-end tests: SHM lifecycle + mock loopback.
 *
 * These validate the hardware-free skeleton:
 *   - ncmp_shm_create/attach/detach/destroy round-trip and cross-mapping
 *     visibility (two mappings of the same object see each other's writes),
 *   - a full request frame travels encode -> mock transport -> MCU echo ->
 *     decode with identity fields and payload preserved and ack == CKR_OK.
 */
#include "ncmp/ncmp_shm.h"
#include "ncmp/ncmp_wire.h"
#include "ncmp/ncmp_cmd.h"
#include "ncmp/ncmp_transport.h"
#include "ncmp/ncmp_limits.h"
#include "ncmp/ncmp_errno.h"
#include "ncmp_test.h"

#include <string.h>

int test_shm_create_attach(void)
{
    void *daemon_base = NULL;
    void *client_base = NULL;
    NCMP_ShmHeader *h;

    /* Clean any stale object from a prior aborted run. */
    (void)ncmp_shm_destroy(NULL);

    NCMP_CHECK(ncmp_shm_create(&daemon_base) == NCMP_OK);
    NCMP_CHECK(daemon_base != NULL);

    h = (NCMP_ShmHeader *)daemon_base;
    NCMP_CHECK(h->magic == NCMP_SHM_MAGIC);
    NCMP_CHECK(h->version == NCMP_SHM_VERSION);
    NCMP_CHECK(h->slot_count == PKCS11_MAX_SLOT_COUNT);
    NCMP_CHECK(h->slots[0].max_inflight == NCMP_DEFAULT_MAX_INFLIGHT);
    NCMP_CHECK(h->slots[0].ring[0].state == NCMP_Q_FREE);

    /* A client in the same process attaches to the same object. */
    NCMP_CHECK(ncmp_shm_attach(&client_base) == NCMP_OK);
    NCMP_CHECK(client_base != NULL);

    NCMP_CHECK(ncmp_shm_detach(client_base) == NCMP_OK);
    NCMP_CHECK(ncmp_shm_destroy(daemon_base) == NCMP_OK);
    return 0;
}

int test_shm_cross_mapping_visibility(void)
{
    void *daemon_base = NULL;
    void *client_base = NULL;
    NCMP_ShmHeader *dh;
    NCMP_ShmHeader *ch;

    (void)ncmp_shm_destroy(NULL);
    NCMP_CHECK(ncmp_shm_create(&daemon_base) == NCMP_OK);
    NCMP_CHECK(ncmp_shm_attach(&client_base) == NCMP_OK);

    dh = (NCMP_ShmHeader *)daemon_base;
    ch = (NCMP_ShmHeader *)client_base;

    /* A write through the daemon mapping is visible via the client mapping. */
    dh->slots[2].state = NCMP_SLOT_ONLINE;
    dh->slots[2].cur_sessions = 5;
    NCMP_CHECK(ch->slots[2].state == NCMP_SLOT_ONLINE);
    NCMP_CHECK(ch->slots[2].cur_sessions == 5);

    NCMP_CHECK(ncmp_shm_detach(client_base) == NCMP_OK);
    NCMP_CHECK(ncmp_shm_destroy(daemon_base) == NCMP_OK);
    return 0;
}

int test_mock_loopback_echo(void)
{
    ncmp_transport_t *t = NULL;
    static uint8_t req_frame[NCMP_MAX_FRAME_SIZE];
    static uint8_t rsp_frame[NCMP_MAX_FRAME_SIZE];
    static uint8_t rsp_payload[NCMP_MAX_PAYLOAD_SIZE];
    const char *body = "ABCD";
    NCMP_Message req;
    NCMP_Message rsp;
    size_t enc_len = 0;
    size_t rx_len = 0;

    /* Build a one-parameter request. */
    memset(&req, 0, sizeof(req));
    req.header.session_id = 0x11;
    req.header.sequence_id = 0x22;
    req.header.command_id = NCMP_CMD_NOP; /* NOP serves as loopback (echo). */
    req.header.ack = 0; /* fresh request */
    req.param_len[0] = 4;
    req.payload = (uint8_t *)body;
    req.payload_cap = 4;

    NCMP_CHECK(ncmp_wire_encode(&req, req_frame, sizeof(req_frame),
                                &enc_len) == NCMP_OK);
    NCMP_CHECK(enc_len == NCMP_FRAME_PREFIX_SIZE + NCMP_HEADER_WIRE_SIZE +
                          NCMP_PARAM_LEN_ARRAY_SIZE + 4);

    /* Round-trip through the mock transport (mover -> MCU echo). */
    NCMP_CHECK(ncmp_transport_open(0, &t) == NCMP_OK);
    NCMP_CHECK(ncmp_transport_send(t, req_frame, enc_len) == NCMP_OK);
    NCMP_CHECK(ncmp_transport_recv(t, rsp_frame, sizeof(rsp_frame),
                                   &rx_len) == NCMP_OK);

    /* Decode and verify the echoed response. */
    memset(&rsp, 0, sizeof(rsp));
    rsp.payload = rsp_payload;
    rsp.payload_cap = sizeof(rsp_payload);
    NCMP_CHECK(ncmp_wire_decode(rsp_frame, rx_len, &rsp) == NCMP_OK);

    NCMP_CHECK(rsp.header.session_id == 0x11);
    NCMP_CHECK(rsp.header.sequence_id == 0x22);
    NCMP_CHECK(rsp.header.command_id == NCMP_CMD_NOP);
    NCMP_CHECK(rsp.header.ack == 0);          /* CKR_OK from the emulator */
    NCMP_CHECK(rsp.param_len[0] == 4);
    NCMP_CHECK(memcmp(rsp.payload, body, 4) == 0);

    NCMP_CHECK(ncmp_transport_close(t) == NCMP_OK);
    return 0;
}

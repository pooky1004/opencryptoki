/*
 * Token NCMP - Vendor-defined PKCS#11 callbacks (implementation).
 *
 * Backs the CK_NCMP_VENDOR_FUNCTION_LIST advertised through the "NCMP Vendor"
 * interface. Data-moving callbacks forward to the token via p11_forward(),
 * releasing the provider lock around the round-trip like the standard crypto
 * functions; introspection callbacks read host/shared-memory state directly.
 */
#include "p11_provider.h"
#include "ncmp_vendor.h"

#include "ncmp/ncmp_cmd.h"
#include "ncmp/ncmp_wire.h"
#include "ncmp/ncmp_shm.h"

#include <string.h>

/** Host-side log verbosity (0=quiet .. 3=debug). */
static CK_ULONG g_log_level;

/** Resolve a session handle to its CK slot id. */
static CK_RV session_slot(CK_SESSION_HANDLE h, CK_SLOT_ID *slot)
{
    p11_session_t *s;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    p11_lock();
    s = p11_session_get(h);
    if (!s) {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    *slot = s->slot;
    p11_unlock();
    return CKR_OK;
}

static CK_RV vd_loopback(CK_SESSION_HANDLE h, CK_BYTE_PTR in, CK_ULONG inlen,
                         CK_BYTE_PTR out, CK_ULONG_PTR outlen)
{
    CK_SLOT_ID slot;
    CK_RV rv;
    uint32_t got = 0;

    if (!outlen)
        return CKR_ARGUMENTS_BAD;
    rv = session_slot(h, &slot);
    if (rv != CKR_OK)
        return rv;
    if (!out) {
        *outlen = inlen;
        return CKR_OK;
    }
    if (*outlen < inlen)
        return CKR_BUFFER_TOO_SMALL;
    rv = p11_forward(slot, NCMP_CMD_VD_LOOPBACK, in, (uint32_t)inlen, out,
                     (uint32_t)*outlen, &got);
    if (rv == CKR_OK)
        *outlen = got;
    return rv;
}

static CK_RV vd_mem_write(CK_SESSION_HANDLE h, CK_ULONG addr, CK_BYTE_PTR data,
                          CK_ULONG len)
{
    CK_SLOT_ID slot;
    CK_RV rv;
    const uint8_t *parts[2];
    uint32_t lens[2];
    uint8_t abuf[4];
    NCMP_Message rsp;

    rv = session_slot(h, &slot);
    if (rv != CKR_OK)
        return rv;
    ncmp_wr_u32le(abuf, (uint32_t)addr);
    parts[0] = abuf; lens[0] = 4;
    parts[1] = data; lens[1] = (uint32_t)len;
    memset(&rsp, 0, sizeof(rsp));
    return p11_forward_mp(slot, NCMP_CMD_VD_MEM_WRITE, parts, lens, 2, NULL, 0,
                          &rsp);
}

static CK_RV vd_mem_read(CK_SESSION_HANDLE h, CK_ULONG addr, CK_BYTE_PTR out,
                         CK_ULONG len)
{
    CK_SLOT_ID slot;
    CK_RV rv;
    const uint8_t *parts[2];
    uint32_t lens[2];
    uint8_t abuf[4], lbuf[4];
    NCMP_Message rsp;

    if (!out)
        return CKR_ARGUMENTS_BAD;
    rv = session_slot(h, &slot);
    if (rv != CKR_OK)
        return rv;
    ncmp_wr_u32le(abuf, (uint32_t)addr);
    ncmp_wr_u32le(lbuf, (uint32_t)len);
    parts[0] = abuf; lens[0] = 4;
    parts[1] = lbuf; lens[1] = 4;
    memset(&rsp, 0, sizeof(rsp));
    rsp.payload = out;
    rsp.payload_cap = (uint32_t)len;
    return p11_forward_mp(slot, NCMP_CMD_VD_MEM_READ, parts, lens, 2, out,
                          (uint32_t)len, &rsp);
}

static CK_RV vd_mem_fill(CK_SESSION_HANDLE h, CK_ULONG addr, CK_ULONG len,
                         CK_BYTE byte)
{
    CK_SLOT_ID slot;
    CK_RV rv;
    const uint8_t *parts[3];
    uint32_t lens[3];
    uint8_t abuf[4], lbuf[4], vbuf[1];
    NCMP_Message rsp;

    rv = session_slot(h, &slot);
    if (rv != CKR_OK)
        return rv;
    ncmp_wr_u32le(abuf, (uint32_t)addr);
    ncmp_wr_u32le(lbuf, (uint32_t)len);
    vbuf[0] = byte;
    parts[0] = abuf; lens[0] = 4;
    parts[1] = lbuf; lens[1] = 4;
    parts[2] = vbuf; lens[2] = 1;
    memset(&rsp, 0, sizeof(rsp));
    return p11_forward_mp(slot, NCMP_CMD_VD_MEM_FILL, parts, lens, 3, NULL, 0,
                          &rsp);
}

static CK_RV vd_mem_crc(CK_SESSION_HANDLE h, CK_ULONG addr, CK_ULONG len,
                        CK_ULONG_PTR crc)
{
    CK_SLOT_ID slot;
    CK_RV rv;
    const uint8_t *parts[2];
    uint32_t lens[2];
    uint8_t abuf[4], lbuf[4], out[4];
    NCMP_Message rsp;

    if (!crc)
        return CKR_ARGUMENTS_BAD;
    rv = session_slot(h, &slot);
    if (rv != CKR_OK)
        return rv;
    ncmp_wr_u32le(abuf, (uint32_t)addr);
    ncmp_wr_u32le(lbuf, (uint32_t)len);
    parts[0] = abuf; lens[0] = 4;
    parts[1] = lbuf; lens[1] = 4;
    memset(&rsp, 0, sizeof(rsp));
    rv = p11_forward_mp(slot, NCMP_CMD_VD_MEM_CRC, parts, lens, 2, out,
                        sizeof(out), &rsp);
    if (rv == CKR_OK && rsp.param_len[0] >= 4)
        *crc = ncmp_rd_u32le(out);
    return rv;
}

/** Shared helper for the no-argument, one-u32-out token queries. */
static CK_RV vd_query_u32(CK_SESSION_HANDLE h, uint32_t opcode, CK_ULONG_PTR out)
{
    CK_SLOT_ID slot;
    CK_RV rv;
    uint8_t buf[4];
    uint32_t got = 0;

    if (!out)
        return CKR_ARGUMENTS_BAD;
    rv = session_slot(h, &slot);
    if (rv != CKR_OK)
        return rv;
    rv = p11_forward(slot, opcode, NULL, 0, buf, sizeof(buf), &got);
    if (rv == CKR_OK && got >= 4)
        *out = ncmp_rd_u32le(buf);
    return rv;
}

static CK_RV vd_ping(CK_SESSION_HANDLE h, CK_ULONG_PTR epoch)
{
    return vd_query_u32(h, NCMP_CMD_VD_PING, epoch);
}

static CK_RV vd_selftest(CK_SESSION_HANDLE h, CK_ULONG_PTR status)
{
    return vd_query_u32(h, NCMP_CMD_VD_SELFTEST, status);
}

static CK_RV vd_fw_info(CK_SESSION_HANDLE h, CK_ULONG_PTR major,
                        CK_ULONG_PTR minor, CK_ULONG_PTR patch,
                        CK_ULONG_PTR build)
{
    CK_SLOT_ID slot;
    CK_RV rv;
    uint8_t buf[16];
    uint32_t got = 0;

    rv = session_slot(h, &slot);
    if (rv != CKR_OK)
        return rv;
    rv = p11_forward(slot, NCMP_CMD_VD_FW_INFO, NULL, 0, buf, sizeof(buf), &got);
    if (rv != CKR_OK)
        return rv;
    if (got < 16)
        return CKR_DEVICE_ERROR;
    if (major) *major = ncmp_rd_u32le(buf + 0);
    if (minor) *minor = ncmp_rd_u32le(buf + 4);
    if (patch) *patch = ncmp_rd_u32le(buf + 8);
    if (build) *build = ncmp_rd_u32le(buf + 12);
    return CKR_OK;
}

static CK_RV vd_get_inflight(CK_SESSION_HANDLE h, CK_ULONG_PTR cur,
                             CK_ULONG_PTR maxseen, CK_ULONG_PTR total)
{
    CK_SLOT_ID ckslot;
    uint32_t phys = 0;
    NCMP_Slot *slot;
    CK_RV rv;

    rv = session_slot(h, &ckslot);
    if (rv != CKR_OK)
        return rv;
    p11_lock();
    rv = p11_slotmap_phys(ckslot, &phys);
    if (rv != CKR_OK) {
        p11_unlock();
        return rv;
    }
    slot = ncmp_shm_slot(g_p11.client.shm_base, phys);
    if (!slot) {
        p11_unlock();
        return CKR_TOKEN_NOT_PRESENT;
    }
    if (cur)     *cur = slot->stats.in_flight_cnt;
    if (maxseen) *maxseen = slot->stats.stats_max_in_flight;
    if (total)   *total = (CK_ULONG)slot->stats.stats_total_sent_cmds;
    p11_unlock();
    return CKR_OK;
}

static CK_RV vd_get_slotmap(CK_SLOT_ID ckslot, CK_ULONG_PTR phys,
                            CK_CHAR_PTR label, CK_ULONG labelcap)
{
    uint32_t p = 0;
    CK_RV rv;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    p11_lock();
    rv = p11_slotmap_phys(ckslot, &p);
    if (rv == CKR_OK || rv == CKR_TOKEN_NOT_PRESENT) {
        if (phys)
            *phys = p;
        if (label && labelcap > 0) {
            const char *l = p11_slotmap_label(ckslot);
            CK_ULONG n = 0;
            while (l[n] && n + 1 < labelcap) { label[n] = (CK_CHAR)l[n]; n++; }
            label[n] = '\0';
        }
    }
    p11_unlock();
    return (rv == CKR_TOKEN_NOT_PRESENT) ? CKR_OK : rv;
}

static CK_RV vd_set_log(CK_ULONG level)
{
    p11_lock();
    g_log_level = level;
    p11_unlock();
    return CKR_OK;
}

static CK_RV vd_get_log(CK_ULONG_PTR level)
{
    if (!level)
        return CKR_ARGUMENTS_BAD;
    p11_lock();
    *level = g_log_level;
    p11_unlock();
    return CKR_OK;
}

static CK_RV vd_host_echo(CK_BYTE_PTR in, CK_ULONG inlen, CK_BYTE_PTR out,
                          CK_ULONG_PTR outlen)
{
    if (!outlen)
        return CKR_ARGUMENTS_BAD;
    if (!out) {
        *outlen = inlen;
        return CKR_OK;
    }
    if (*outlen < inlen)
        return CKR_BUFFER_TOO_SMALL;
    if (inlen)
        memcpy(out, in, inlen);
    *outlen = inlen;
    return CKR_OK;
}

CK_NCMP_VENDOR_FUNCTION_LIST ncmp_vendor_functions = {
    .version = { NCMP_VENDOR_VERSION_MAJOR, NCMP_VENDOR_VERSION_MINOR },
    .NCMP_Loopback = vd_loopback,
    .NCMP_MemWrite = vd_mem_write,
    .NCMP_MemRead = vd_mem_read,
    .NCMP_MemFill = vd_mem_fill,
    .NCMP_MemCRC = vd_mem_crc,
    .NCMP_Ping = vd_ping,
    .NCMP_SelfTest = vd_selftest,
    .NCMP_FirmwareInfo = vd_fw_info,
    .NCMP_GetInFlight = vd_get_inflight,
    .NCMP_GetSlotMap = vd_get_slotmap,
    .NCMP_SetLogLevel = vd_set_log,
    .NCMP_GetLogLevel = vd_get_log,
    .NCMP_HostEcho = vd_host_echo,
};

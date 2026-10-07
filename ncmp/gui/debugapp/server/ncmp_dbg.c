/*
 * Token NCMP - Debug App server.
 *
 * A small, dependency-free HTTP/1.1 server (thread-per-connection) that lets a
 * browser inspect ncmpd's shared memory per slot:
 *
 *   Browser --HTTP/JSON--> ncmp_dbg (this) --IPC handshake--> ncmpd conn_thread
 *                                           --attach(read-only) SHM--> NCMP_ShmHeader/NCMP_Slot
 *
 * It does NOT go through the PKCS#11 facade. It performs the ncmp_ipc HELLO
 * handshake with ncmpd's connection thread to confirm the daemon and learn the
 * online-slot mask, attaches the well-known SHM object read-only, and renders
 * the live per-slot metadata (state, token identity, in-flight stats, session
 * count, and the MPSC command ring). No ncmpd changes are required.
 *
 * SECURITY: exposes ncmpd internals over the network with no transport
 * encryption. When NCMP_DBG_TOKEN is set, every API request must carry
 * "Authorization: Bearer <token>". Bind to a trusted interface / use an SSH
 * tunnel. See docs/debugapp-deployment.md.
 *
 * Style: Google C Style. A developer tool, not part of the shipped token.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "ncmp/ncmp_ipc.h"
#include "ncmp/ncmp_shm.h"
#include "ncmp/ncmp_queue.h"
#include "ncmp/ncmp_limits.h"
#include "ncmp/ncmp_errno.h"
#include "ncmp/ncmp_client.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Config + state                                                     */
/* ------------------------------------------------------------------ */

static char g_host[64] = "0.0.0.0";
static int g_port = 8090;
static char g_webroot[1024] = "web";
/* Directory where oversized comm<->HSM parameters are spilled as Hex text files
 * and served from under /lmfile/. Overridable with $NCMP_DBG_LMDIR. */
static char g_lmdir[1024] = "/tmp/ncmp_dbg_lm";
static char g_sock_path[1024] = "";   /* NCMP_SOCK_PATH for the handshake */
static char g_token[256] = "";        /* bearer token; empty = auth off */
static char g_config[1024] = "";

static ncmp_client_t g_cli;            /* conn-thread handshake + SHM attach */
static int g_cli_ok = 0;
static void *g_shm = NULL;             /* = g_cli.shm_base (read-only SHM view) */
static uint32_t g_slot_mask = 0;       /* online mask from the handshake */
static int g_connected = 0;
static int g_last_rc = 0;              /* last ncmp_client_init rc (0 = ok) */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

/* Human-readable reason for a failed attach, to surface in the UI. */
static const char *dbg_conn_reason(void)
{
    if (g_connected)
        return "";
    switch (g_last_rc) {
    case NCMP_ERR_NODAEMON:
        return "ncmpd 미연결: 소켓에 데몬이 없습니다. Web Test App의 [데몬 시작]으로 ncmpd를 띄우거나 --sock 경로를 맞추세요(기본 /tmp/ncmpd.sock).";
    case NCMP_ERR_VERSION:
        return "SHM 버전 불일치: ncmpd와 다른 빌드입니다. ncmp_dbg를 최신 소스로 재빌드하세요(Web Test App/ncmpd와 동일 버전).";
    case 0:
        return "ncmpd 미연결.";
    default:
        return "ncmpd 연결 실패(내부 오류).";
    }
}

static volatile sig_atomic_t g_running = 1;
static void on_signal(int s) { (void)s; g_running = 0; }

/* ------------------------------------------------------------------ */
/* Config file (key = value)                                          */
/* ------------------------------------------------------------------ */

static void set_cfg(const char *k, const char *v)
{
    if      (!strcmp(k, "host"))    snprintf(g_host, sizeof(g_host), "%s", v);
    else if (!strcmp(k, "port"))    g_port = atoi(v);
    else if (!strcmp(k, "webroot")) snprintf(g_webroot, sizeof(g_webroot), "%s", v);
    else if (!strcmp(k, "sock"))    snprintf(g_sock_path, sizeof(g_sock_path), "%s", v);
    else if (!strcmp(k, "token"))   snprintf(g_token, sizeof(g_token), "%s", v);
}

static int load_config(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[2048];
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == ';' || *p == '\n' || *p == '\r' || *p == '\0') continue;
        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = p, *val = eq + 1;
        char *ke = key + strlen(key);
        while (ke > key && (ke[-1] == ' ' || ke[-1] == '\t')) *--ke = '\0';
        while (*val == ' ' || *val == '\t') val++;
        size_t vl = strlen(val);
        while (vl && (val[vl-1]=='\n'||val[vl-1]=='\r'||val[vl-1]==' '||val[vl-1]=='\t')) val[--vl]='\0';
        if (vl >= 2 && ((val[0]=='"'&&val[vl-1]=='"')||(val[0]=='\''&&val[vl-1]=='\''))) { val[vl-1]='\0'; val++; }
        set_cfg(key, val);
    }
    fclose(f);
    snprintf(g_config, sizeof(g_config), "%s", path);
    return 0;
}

/* ------------------------------------------------------------------ */
/* HTTP helpers                                                       */
/* ------------------------------------------------------------------ */

static void write_all(int fd, const char *b, size_t n)
{
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, b + off, n - off);
        if (w <= 0) { if (w < 0 && errno == EINTR) continue; break; }
        off += (size_t)w;
    }
}
static void send_raw(int fd, int st, const char *txt, const char *ct, const char *b, size_t n)
{
    char h[512];
    int k = snprintf(h, sizeof(h),
        "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
        "Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: Authorization, Content-Type\r\n"
        "Connection: close\r\n\r\n", st, txt, ct, n);
    write_all(fd, h, (size_t)k);
    if (b && n) write_all(fd, b, n);
}
static void send_json(int fd, int st, const char *j)
{
    const char *t = st==200?"OK":st==401?"Unauthorized":st==404?"Not Found":"Bad Request";
    send_raw(fd, st, t, "application/json; charset=utf-8", j, strlen(j));
}

static const char *mime_of(const char *p)
{
    const char *d = strrchr(p, '.');
    if (!d) return "application/octet-stream";
    if (!strcmp(d,".html")) return "text/html; charset=utf-8";
    if (!strcmp(d,".js"))   return "application/javascript; charset=utf-8";
    if (!strcmp(d,".css"))  return "text/css; charset=utf-8";
    return "text/plain; charset=utf-8";
}
static void serve_static(int fd, const char *url)
{
    char rel[1024];
    if (!strcmp(url, "/")) snprintf(rel, sizeof(rel), "index.html");
    else snprintf(rel, sizeof(rel), "%s", url[0]=='/'?url+1:url);
    if (strstr(rel, "..")) { send_json(fd, 400, "{\"error\":\"bad path\"}"); return; }
    char full[2200];
    snprintf(full, sizeof(full), "%s/%s", g_webroot, rel);
    FILE *f = fopen(full, "rb");
    if (!f) { send_json(fd, 404, "{\"error\":\"not found\"}"); return; }
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz < 0) sz = 0;
    char *b = malloc((size_t)sz + 1);
    if (!b) { fclose(f); send_json(fd, 500, "{\"error\":\"oom\"}"); return; }
    size_t rd = fread(b, 1, (size_t)sz, f);
    fclose(f);
    send_raw(fd, 200, "OK", mime_of(full), b, rd);
    free(b);
}

/* Reject file names that are not a plain basename (no path separators / dotdot). */
static int lm_name_ok(const char *name)
{
    if (!name || !*name || strstr(name, "..") || strchr(name, '/') ||
        strchr(name, '\\'))
        return 0;
    for (const char *p = name; *p; ++p)
        if (!(isalnum((unsigned char)*p) || *p == '_' || *p == '.' || *p == '-'))
            return 0;
    return 1;
}

/* Write one oversized parameter to g_lmdir/<name> as a Hex text file: a short
 * header comment then the hex grouped 64 bytes (128 chars) per line. Overwritten
 * on every refresh so the file always holds the latest capture. */
static void lm_write_param_file(const char *name, const uint8_t *b, uint32_t n,
                                uint32_t full_len, const char *dir,
                                const char *idxlabel)
{
    char full[2200];
    FILE *f;

    (void)mkdir(g_lmdir, 0755);           /* best-effort; ignore EEXIST */
    snprintf(full, sizeof(full), "%s/%s", g_lmdir, name);
    f = fopen(full, "w");
    if (!f)
        return;
    fprintf(f, "# NCMP comm<->HSM %s %s : param length %u bytes",
            dir, idxlabel, full_len);
    if (n < full_len)
        fprintf(f, " (captured %u; frame capture truncated)", n);
    fprintf(f, "\n");
    for (uint32_t i = 0; i < n; i++) {
        fprintf(f, "%02x", b[i]);
        if ((i & 63u) == 63u)        /* 64 bytes (128 hex chars) per line */
            fputc('\n', f);
    }
    if (n == 0 || (n & 63u) != 0)
        fputc('\n', f);
    fclose(f);
}

/* Serve a spilled parameter file (GET /lmfile/<name>) as plain text. */
static void serve_lmfile(int fd, const char *name)
{
    char full[2200];
    FILE *f;
    long sz;
    char *b;
    size_t rd;

    if (!lm_name_ok(name)) { send_json(fd, 400, "{\"error\":\"bad name\"}"); return; }
    snprintf(full, sizeof(full), "%s/%s", g_lmdir, name);
    f = fopen(full, "rb");
    if (!f) { send_json(fd, 404, "{\"error\":\"not found\"}"); return; }
    fseek(f, 0, SEEK_END); sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz < 0) sz = 0;
    b = malloc((size_t)sz + 1);
    if (!b) { fclose(f); send_json(fd, 500, "{\"error\":\"oom\"}"); return; }
    rd = fread(b, 1, (size_t)sz, f);
    fclose(f);
    send_raw(fd, 200, "OK", "text/plain; charset=utf-8", b, rd);
    free(b);
}

/* JSON-escape a (possibly NUL-padded) fixed field into out. */
static void json_field(char *out, size_t cap, const char *src, size_t n)
{
    size_t len = 0;
    while (len < n && src[len] != '\0') len++;
    size_t o = 0;
    for (size_t i = 0; i < len && o + 2 < cap; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"' || c == '\\') { out[o++] = '\\'; out[o++] = (char)c; }
        else if (c >= 0x20) out[o++] = (char)c;
    }
    out[o] = '\0';
}

/* ------------------------------------------------------------------ */
/* SHM access (handshake with ncmpd conn_thread, then attach)         */
/* ------------------------------------------------------------------ */

/* Perform the ncmp_ipc handshake (confirms the daemon + refreshes the online
 * mask) and attach the SHM read view if not already attached. Returns the SHM
 * base or NULL. Call under g_lock. */
static void *shm_ensure(void)
{
    if (!g_cli_ok) {
        /* ncmp_client_init does the conn_thread HELLO handshake AND attaches
         * the SHM, and gives us the command path (enqueue ring) for the CI
         * send/receive tab. */
        int rc = ncmp_client_init(&g_cli, g_sock_path[0] ? g_sock_path : NULL);
        g_last_rc = rc;
        if (rc == NCMP_OK) {
            g_cli_ok = 1;
            g_shm = g_cli.shm_base;
            g_slot_mask = g_cli.slot_mask;
        }
    } else {
        /* Refresh the online mask via a lightweight handshake (daemon liveness). */
        int fd = -1;
        uint32_t mask = 0;
        if (ncmp_ipc_connect(g_sock_path[0] ? g_sock_path : NULL, &fd, &mask) == NCMP_OK) {
            g_slot_mask = mask;
            if (fd >= 0) close(fd);
        } else {
            g_cli_ok = 0;           /* daemon went away */
        }
    }
    g_connected = g_cli_ok && g_shm;
    return g_connected ? g_shm : NULL;
}

static void shm_drop(void)
{
    if (g_cli_ok) { ncmp_client_fini(&g_cli); g_cli_ok = 0; }
    g_shm = NULL; g_connected = 0;
}

static const char *state_name(int32_t s)
{
    switch (s) {
    case NCMP_SLOT_ABSENT:  return "ABSENT";
    case NCMP_SLOT_ONLINE:  return "ONLINE";
    case NCMP_SLOT_FAULTED: return "FAULTED";
    default:                return "UNKNOWN";
    }
}
static const char *qstate_name(int32_t s)
{
    switch (s) {
    case NCMP_Q_FREE: return "FREE";
    case NCMP_Q_CLAIMED: return "CLAIMED";
    case NCMP_Q_POSTED: return "POSTED";
    case NCMP_Q_SENT: return "SENT";
    case NCMP_Q_DONE: return "DONE";
    case NCMP_Q_ABANDONED: return "ABANDONED";
    default: return "?";
    }
}

/* Append one slot's summary object to buf at offset o; returns new offset.
 * No-op (returns o unchanged) when fewer than 400 bytes remain, so o never
 * overshoots cap even though snprintf returns the untruncated length. */
static int emit_slot_summary(char *buf, int cap, int o, NCMP_Slot *s)
{
    if (cap - o < 400)
        return o;
    char label[2 * NCMP_TI_LABEL_LEN];
    json_field(label, sizeof(label), s->token.label, NCMP_TI_LABEL_LEN);
    int w = snprintf(buf + o, (size_t)(cap - o),
        "{\"slot\":%u,\"state\":%d,\"stateName\":\"%s\",\"boundCkSlot\":%d,"
        "\"hsmType\":%u,\"hsmTypeName\":\"%s\","
        "\"curSessions\":%u,\"maxInflight\":%u,\"inFlight\":%u,\"maxInFlightSeen\":%u,"
        "\"totalSent\":%llu,\"tokenValid\":%u,\"tokenLabel\":\"%s\"}",
        s->slot_id, s->state, state_name(s->state), s->bound_ck_slot,
        s->hsm_type, s->hsm_type == NCMP_HSM_TYPE_PEM ? "PEM" : "NCMP",
        s->cur_sessions, s->max_inflight,
        (unsigned)s->stats.in_flight_cnt, s->stats.stats_max_in_flight,
        (unsigned long long)s->stats.stats_total_sent_cmds,
        s->token.valid, label);
    if (w < 0) return o;
    if (w >= cap - o) w = cap - o - 1;   /* clamp: never advance past the buffer */
    return o + w;
}

#define BUF (64 * 1024)

/* ------------------------------------------------------------------ */
/* Last comm<->HSM message (TX/RX) rendering                           */
/* ------------------------------------------------------------------ */

static uint32_t lm_rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* A parameter larger than this (bytes) is NOT inlined as hex; its captured bytes
 * are spilled to a Hex text file under /lmfile/ and the JSON carries "file". */
#define LM_PARAM_FILE_THRESHOLD 512u

/* Emit "key":{len,cap,ms,hex, [parsed header + params]} from a captured frame.
 * @p b holds @p caplen bytes of a @p fulllen-byte wire frame (may be truncated).
 * @p slot and @p key ("tx"/"rx") name any spilled per-parameter files.
 * Wire layout: frame_len(4) hdr{sid,seq,cmd,ack,paylen}(20) param_len[8](32) params. */
static int lm_emit(char *buf, int cap, int o, const char *key,
                   const uint8_t *b, uint32_t caplen, uint32_t fulllen,
                   unsigned long long ms, long slot)
{
    o += snprintf(buf + o, cap - o,
                  "\"%s\":{\"len\":%u,\"cap\":%u,\"ms\":%llu,\"hex\":\"",
                  key, fulllen, caplen, ms);
    for (uint32_t i = 0; i < caplen && o < cap - 4; i++)
        o += snprintf(buf + o, cap - o, "%02x", b[i]);
    o += snprintf(buf + o, cap - o, "\"");
    if (caplen >= 56) {
        uint32_t fl = lm_rd32(b), sid = lm_rd32(b + 4), seq = lm_rd32(b + 8);
        uint32_t cmd = lm_rd32(b + 12), ack = lm_rd32(b + 16), pl = lm_rd32(b + 20);
        uint32_t off = 56;
        int first = 1;
        o += snprintf(buf + o, cap - o,
            ",\"parsed\":true,\"frameLen\":%u,\"sessionId\":%u,\"sequenceId\":%u,"
            "\"commandId\":%u,\"ack\":%u,\"payloadLen\":%u,\"params\":[",
            fl, sid, seq, cmd, ack, pl);
        for (int i = 0; i < 8; i++) {
            uint32_t plen = lm_rd32(b + 24 + i * 4);
            if (!plen) continue;
            if (o < cap - 160) {
                uint32_t avail = (off < caplen) ? (caplen - off) : 0;
                if (avail > plen) avail = plen;
                if (plen > LM_PARAM_FILE_THRESHOLD) {
                    /* Oversized: spill the captured bytes to a Hex text file and
                     * reference it instead of inlining the hex. */
                    char fname[80], idxlabel[16];
                    snprintf(fname, sizeof(fname), "slot%ld_%s_p%d.txt", slot, key, i);
                    snprintf(idxlabel, sizeof(idxlabel), "param[%d]", i);
                    lm_write_param_file(fname, b + off, avail, plen, key, idxlabel);
                    o += snprintf(buf + o, cap - o,
                                  "%s{\"idx\":%d,\"len\":%u,\"captured\":%u,\"file\":\"%s\"}",
                                  first ? "" : ",", i, plen, avail, fname);
                } else {
                    o += snprintf(buf + o, cap - o,
                                  "%s{\"idx\":%d,\"len\":%u,\"shown\":%u,\"truncated\":%s,\"hex\":\"",
                                  first ? "" : ",", i, plen, avail,
                                  (avail < plen) ? "true" : "false");
                    for (uint32_t k = 0; k < avail && o < cap - 4; k++)
                        o += snprintf(buf + o, cap - o, "%02x", b[off + k]);
                    o += snprintf(buf + o, cap - o, "\"}");
                }
                first = 0;
            }
            off += plen;
        }
        o += snprintf(buf + o, cap - o, "]");
    } else {
        o += snprintf(buf + o, cap - o, ",\"parsed\":false");
    }
    o += snprintf(buf + o, cap - o, "}");
    return o;
}

/* ------------------------------------------------------------------ */
/* API routes                                                         */
/* ------------------------------------------------------------------ */

static void route_api(int fd, const char *method, const char *path, const char *body)
{
    (void)method;
    char *buf = malloc(BUF);
    if (!buf) { send_json(fd, 500, "{\"error\":\"oom\"}"); return; }

    pthread_mutex_lock(&g_lock);
    void *base = shm_ensure();
    NCMP_ShmHeader *h = (NCMP_ShmHeader *)base;

    if (!strcmp(path, "/api/status")) {
        snprintf(buf, BUF,
            "{\"connected\":%s,\"shmName\":\"%s\",\"sockPath\":\"%s\",\"configPath\":\"%s\","
            "\"host\":\"%s\",\"port\":%d,\"authRequired\":%s,\"slotMask\":%u,"
            "\"reason\":\"%s\""
            "%s%s%s}",
            g_connected ? "true" : "false", NCMP_SHM_NAME,
            g_sock_path[0] ? g_sock_path : "(default)", g_config,
            g_host, g_port, g_token[0] ? "true" : "false", g_slot_mask,
            dbg_conn_reason(),
            h ? ",\"magic\":" : "", "", "");
        /* append header fields when attached */
        if (h) {
            int o = (int)strlen(buf) - 1;   /* drop closing brace */
            o += snprintf(buf + o, BUF - o,
                "\"0x%08X\",\"version\":%u,\"slotCount\":%u,\"totalSize\":%llu}",
                h->magic, h->version, h->slot_count,
                (unsigned long long)h->total_size);
        }
        send_json(fd, 200, buf);
    } else if (!strcmp(path, "/api/slots")) {
        /* Emit only slots the daemon actually populated (state != ABSENT).
         * slot_count is PKCS11_MAX_SLOT_COUNT (up to 256), almost all empty. */
        int o = snprintf(buf, BUF, "{\"connected\":%s,\"slots\":[",
                         g_connected ? "true" : "false");
        int emitted = 0;
        uint32_t total = h ? h->slot_count : 0;
        if (h) {
            for (uint32_t i = 0; i < h->slot_count; i++) {
                NCMP_Slot *s = &h->slots[i];
                if (s->state == NCMP_SLOT_ABSENT)
                    continue;              /* skip empty slots */
                if (BUF - o < 420)
                    break;                 /* out of room; stop cleanly */
                if (emitted) o += snprintf(buf + o, (size_t)(BUF - o), ",");
                o = emit_slot_summary(buf, BUF, o, s);
                emitted++;
            }
        }
        snprintf(buf + o, (size_t)(BUF - o),
                 "],\"slotCount\":%u,\"shown\":%d}", total, emitted);
        send_json(fd, 200, buf);
    } else if (!strcmp(path, "/api/slot")) {
        /* body: {"slot":N} */
        long slot = -1;
        const char *q = body ? strstr(body, "\"slot\"") : NULL;
        if (q) { q = strchr(q, ':'); if (q) slot = strtol(q + 1, NULL, 0); }
        if (!h || slot < 0 || (uint32_t)slot >= h->slot_count) {
            send_json(fd, 200, g_connected ? "{\"error\":\"bad slot\"}"
                                           : "{\"connected\":false}");
        } else {
            NCMP_Slot *s = &h->slots[slot];
            char label[2*NCMP_TI_LABEL_LEN], serial[2*NCMP_TI_SERIAL_LEN];
            char manuf[2*NCMP_TI_MANUF_LEN], model[2*NCMP_TI_MODEL_LEN];
            json_field(label, sizeof(label), s->token.label, NCMP_TI_LABEL_LEN);
            json_field(serial, sizeof(serial), s->token.serial, NCMP_TI_SERIAL_LEN);
            json_field(manuf, sizeof(manuf), s->token.manufacturer, NCMP_TI_MANUF_LEN);
            json_field(model, sizeof(model), s->token.model, NCMP_TI_MODEL_LEN);

            /* queue state histogram + busy (non-FREE) entries */
            int cnt[6] = {0,0,0,0,0,0};
            int o = snprintf(buf, BUF,
                "{\"connected\":true,\"slot\":%u,\"state\":%d,\"stateName\":\"%s\","
                "\"boundCkSlot\":%d,\"curSessions\":%u,\"maxInflight\":%u,"
                "\"stats\":{\"inFlight\":%u,\"maxInFlightSeen\":%u,\"totalSent\":%llu},"
                "\"token\":{\"valid\":%u,\"label\":\"%s\",\"serial\":\"%s\","
                "\"manufacturer\":\"%s\",\"model\":\"%s\",\"hw\":\"%u.%u\",\"fw\":\"%u.%u\","
                "\"flags\":%u},\"bufPool\":{\"off\":%llu,\"len\":%llu},"
                "\"queueDepth\":%d,\"busy\":[",
                s->slot_id, s->state, state_name(s->state), s->bound_ck_slot,
                s->cur_sessions, s->max_inflight,
                (unsigned)s->stats.in_flight_cnt, s->stats.stats_max_in_flight,
                (unsigned long long)s->stats.stats_total_sent_cmds,
                s->token.valid, label, serial, manuf, model,
                s->token.hw_major, s->token.hw_minor, s->token.fw_major, s->token.fw_minor,
                s->token.flags,
                (unsigned long long)s->buf_pool_off, (unsigned long long)s->buf_pool_len,
                NCMP_QUEUE_DEPTH);
            int first = 1;
            for (int i = 0; i < NCMP_QUEUE_DEPTH; i++) {
                NCMP_QEntry *e = &s->ring[i];
                int32_t st = ncmp_qentry_state(e);
                if (st >= 0 && st < 6) cnt[st]++;
                if (st != NCMP_Q_FREE && o < BUF - 256) {
                    o += snprintf(buf + o, BUF - o,
                        "%s{\"idx\":%d,\"state\":\"%s\",\"ownerSess\":%u,\"seq\":%u,"
                        "\"reqLen\":%u,\"rspLen\":%u}",
                        first ? "" : ",", i, qstate_name(st), e->owner_sess,
                        e->sequence_id, e->req_len, e->rsp_len);
                    first = 0;
                }
            }
            o += snprintf(buf + o, BUF - o,
                "],\"queue\":{\"FREE\":%d,\"CLAIMED\":%d,\"POSTED\":%d,\"SENT\":%d,"
                "\"DONE\":%d,\"ABANDONED\":%d}}",
                cnt[0], cnt[1], cnt[2], cnt[3], cnt[4], cnt[5]);
            send_json(fd, 200, buf);
        }
    } else if (!strcmp(path, "/api/lastmsg")) {
        /* body: {"slot":N} -> last comm<->HSM TX/RX (raw + parsed). */
        long slot = -1;
        const char *q = body ? strstr(body, "\"slot\"") : NULL;
        if (q) { q = strchr(q, ':'); if (q) slot = strtol(q + 1, NULL, 0); }
        if (!h || slot < 0 || (uint32_t)slot >= h->slot_count) {
            send_json(fd, 200, g_connected ? "{\"error\":\"bad slot\"}"
                                           : "{\"connected\":false}");
        } else {
            NCMP_LastMsg lm = h->slots[slot].last_msg;  /* snapshot copy */
            uint32_t txc = lm.tx_cap > NCMP_LASTMSG_CAP ? NCMP_LASTMSG_CAP : lm.tx_cap;
            uint32_t rxc = lm.rx_cap > NCMP_LASTMSG_CAP ? NCMP_LASTMSG_CAP : lm.rx_cap;
            int o = snprintf(buf, BUF, "{\"connected\":true,\"slot\":%ld,", slot);
            o = lm_emit(buf, BUF, o, "tx", lm.tx, txc, lm.tx_len,
                        (unsigned long long)lm.tx_ms, slot);
            o += snprintf(buf + o, BUF - o, ",");
            o = lm_emit(buf, BUF, o, "rx", lm.rx, rxc, lm.rx_len,
                        (unsigned long long)lm.rx_ms, slot);
            snprintf(buf + o, BUF - o, "}");
            send_json(fd, 200, buf);
        }
    } else if (!strcmp(path, "/api/reconnect")) {
        shm_drop();
        shm_ensure();
        snprintf(buf, BUF, "{\"connected\":%s,\"reason\":\"%s\"}",
                 g_connected ? "true" : "false", dbg_conn_reason());
        send_json(fd, 200, buf);
    } else {
        send_json(fd, 404, "{\"error\":\"no such api\"}");
    }
    pthread_mutex_unlock(&g_lock);
    free(buf);
}

/* ------------------------------------------------------------------ */
/* Request handling                                                   */
/* ------------------------------------------------------------------ */

static int has_bearer(const char *headers)
{
    if (!g_token[0]) return 1;
    const char *a = strcasestr(headers, "authorization:");
    if (!a) return 0;
    const char *b = strcasestr(a, "bearer ");
    if (!b) return 0;
    b += 7;
    size_t tl = strlen(g_token);
    return strncmp(b, g_token, tl) == 0 &&
           (b[tl]=='\r'||b[tl]=='\n'||b[tl]=='\0'||b[tl]==' ');
}

static void *handle_client(void *arg)
{
    int fd = (int)(intptr_t)arg;
    char *req = malloc(1 << 16);
    if (!req) { close(fd); return NULL; }
    size_t len = 0, cap = 1 << 16, hend = 0;
    while (len + 1 < cap) {
        ssize_t n = read(fd, req + len, cap - len - 1);
        if (n <= 0) break;
        len += (size_t)n; req[len] = '\0';
        char *he = strstr(req, "\r\n\r\n");
        if (he) { hend = (size_t)(he - req) + 4; break; }
    }
    if (hend == 0) { free(req); close(fd); return NULL; }
    char method[8] = "", path[1024] = "";
    sscanf(req, "%7s %1023s", method, path);
    char *qs = strchr(path, '?'); if (qs) *qs = '\0';
    if (!strcmp(method, "OPTIONS")) { send_raw(fd, 204, "No Content", "text/plain", "", 0); free(req); close(fd); return NULL; }

    const char *bodyp = req + hend;
    if (!strncmp(path, "/api/", 5)) {
        if (!has_bearer(req)) {
            send_json(fd, 401, "{\"error\":\"unauthorized (set Authorization: Bearer <NCMP_DBG_TOKEN>)\"}");
        } else {
            const char *cl = strcasestr(req, "content-length:");
            long want = cl ? strtol(cl + 15, NULL, 10) : 0;
            while ((long)(len - hend) < want && len + 1 < cap) {
                ssize_t n = read(fd, req + len, cap - len - 1);
                if (n <= 0) break;
                len += (size_t)n; req[len] = '\0';
            }
            route_api(fd, method, path, bodyp);
        }
    } else if (!strcmp(method, "GET") && !strncmp(path, "/lmfile/", 8)) {
        serve_lmfile(fd, path + 8);
    } else if (!strcmp(method, "GET")) {
        serve_static(fd, path);
    } else {
        send_json(fd, 404, "{\"error\":\"not found\"}");
    }
    free(req); close(fd);
    return NULL;
}

static void usage(const char *p)
{
    fprintf(stderr,
      "usage: %s [--config PATH] [--host H] [--port N] [--webroot DIR] [--sock PATH]\n"
      "config: --config, else $NCMP_DBG_CONFIG, else ./.config/config\n"
      "        (keys: host port webroot sock token). defaults < file < env < CLI.\n"
      "env: NCMP_DBG_HOST NCMP_DBG_PORT NCMP_DBG_ROOT NCMP_DBG_TOKEN NCMP_SOCK_PATH\n", p);
}

int main(int argc, char **argv)
{
    char cfgpath[1024] = "";
    for (int i = 1; i < argc - 1; i++)
        if (!strcmp(argv[i], "--config")) snprintf(cfgpath, sizeof(cfgpath), "%s", argv[i+1]);
    if (!cfgpath[0]) { const char *c = getenv("NCMP_DBG_CONFIG"); if (c && *c) snprintf(cfgpath, sizeof(cfgpath), "%s", c); }
    if (!cfgpath[0]) snprintf(cfgpath, sizeof(cfgpath), ".config/config");
    load_config(cfgpath);

    const char *e;
    if ((e = getenv("NCMP_DBG_HOST"))) snprintf(g_host, sizeof(g_host), "%s", e);
    if ((e = getenv("NCMP_DBG_PORT"))) g_port = atoi(e);
    if ((e = getenv("NCMP_DBG_ROOT"))) snprintf(g_webroot, sizeof(g_webroot), "%s", e);
    if ((e = getenv("NCMP_DBG_TOKEN"))) snprintf(g_token, sizeof(g_token), "%s", e);
    if ((e = getenv("NCMP_SOCK_PATH"))) snprintf(g_sock_path, sizeof(g_sock_path), "%s", e);
    if ((e = getenv("NCMP_DBG_LMDIR"))) snprintf(g_lmdir, sizeof(g_lmdir), "%s", e);
    (void)mkdir(g_lmdir, 0755);   /* oversized-parameter spill dir */

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--config") && i + 1 < argc) { ++i; continue; }
        else if (!strcmp(argv[i], "--host") && i + 1 < argc) snprintf(g_host, sizeof(g_host), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--port") && i + 1 < argc) g_port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--webroot") && i + 1 < argc) snprintf(g_webroot, sizeof(g_webroot), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--sock") && i + 1 < argc) snprintf(g_sock_path, sizeof(g_sock_path), "%s", argv[++i]);
        else { usage(argv[0]); return 2; }
    }

    /* Default to the shared user-space socket the Web Test App's ncmpd uses, so
     * launching the Debug App alongside it connects with no --sock. Overridable
     * by config/env/CLI; set to the system path for a systemd-run ncmpd. */
    if (!g_sock_path[0])
        snprintf(g_sock_path, sizeof(g_sock_path), "/tmp/ncmpd.sock");

    struct sigaction sa; memset(&sa, 0, sizeof(sa)); sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL); sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return 1; }
    int one = 1; setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a; memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET; a.sin_port = htons((uint16_t)g_port);
    if (inet_pton(AF_INET, g_host, &a.sin_addr) != 1) a.sin_addr.s_addr = INADDR_ANY;
    if (bind(srv, (struct sockaddr *)&a, sizeof(a)) != 0) { perror("bind"); return 1; }
    if (listen(srv, 32) != 0) { perror("listen"); return 1; }

    pthread_mutex_lock(&g_lock); shm_ensure(); pthread_mutex_unlock(&g_lock);
    fprintf(stderr, "ncmp_dbg: http://%s:%d  (webroot=%s, sock=%s, auth=%s, shm=%s)\n",
        g_host, g_port, g_webroot, g_sock_path[0] ? g_sock_path : "(default)",
        g_token[0] ? "bearer-token" : "OFF", g_connected ? "attached" : "not-attached");

    while (g_running) {
        int c = accept(srv, NULL, NULL);
        if (c < 0) { if (errno == EINTR) continue; break; }
        pthread_t th;
        if (pthread_create(&th, NULL, handle_client, (void *)(intptr_t)c) == 0)
            pthread_detach(th);
        else close(c);
    }
    shm_drop();
    close(srv);
    fprintf(stderr, "ncmp_dbg: stopped\n");
    return 0;
}

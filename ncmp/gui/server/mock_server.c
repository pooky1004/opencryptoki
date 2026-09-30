/*
 * Token NCMP - Mock HSM socket server.
 *
 * Wraps the in-process FX3 emulator (mcu_scheduler.c / container.c) in a TCP
 * server so an external "host" (the test App GUI, or any client) can drive one
 * or more emulated tokens over a socket instead of libusb. It reuses the
 * authoritative emulation path unchanged:
 *
 *     data socket --frame--> mock_mover_ingest() --> mock_mcu_step() --frame-->
 *
 * Each slot owns one mock_device_t. The server exposes two channels:
 *
 *   - DATA  (one TCP port per slot, base + slot): carries raw wire frames
 *     (the same single-shot 4-byte-prefixed framing the daemon uses). This is
 *     the emulated USB "host link"; connecting/disconnecting the socket is the
 *     link up/down event.
 *   - CONTROL (one TCP port): newline-delimited JSON used by the Mock GUI to
 *     read/edit token identity, read statistics, tail a debug ring of recent
 *     messages, and force a slot's link up/down.
 *
 * Dependency-free (POSIX sockets + pthreads); no JSON library - control
 * messages are tiny and both ends are ours.
 *
 * Style: Google C Style. Not part of the shipped token; a developer tool.
 */
#define _GNU_SOURCE
#include "mock_token_ncmp.h"
#include "ncmp/ncmp_wire.h"
#include "ncmp/ncmp_cmd.h"
#include "ncmp/ncmp_limits.h"
#include "ncmp/ncmp_errno.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* -------------------------------------------------------------------------- */
/* Configuration                                                              */
/* -------------------------------------------------------------------------- */

#define MOCK_SRV_DEBUG_RING 128        /**< Recent messages kept per slot. */
#define MOCK_SRV_DEFAULT_DATA_PORT 7010
#define MOCK_SRV_DEFAULT_CTRL_PORT 7000

/** One recorded request/response pair for the debug view. */
typedef struct dbg_event {
    long long ts_ms;      /**< Wall-clock timestamp (ms). */
    uint32_t  opcode;     /**< Opcode (command_id low 16 bits). */
    uint32_t  session;    /**< Session id from the header. */
    uint32_t  sequence;   /**< Sequence id from the header. */
    uint32_t  ack;        /**< Response ack (CKR_*). */
    uint32_t  req_len;    /**< Request frame length (bytes). */
    uint32_t  rsp_len;    /**< Response frame length (bytes). */
} dbg_event_t;

/** Per-slot statistics (server-side view of the emulated token). */
typedef struct slot_stats {
    uint64_t requests;    /**< Frames ingested. */
    uint64_t responses;   /**< Frames returned. */
    uint64_t bytes_in;    /**< Request bytes received. */
    uint64_t bytes_out;   /**< Response bytes sent. */
    uint64_t errors;      /**< Parse/step/encode failures. */
    uint64_t connects;    /**< Data-link connections accepted. */
    uint32_t in_flight;   /**< Requests currently being processed. */
    uint32_t max_in_flight; /**< Historical peak of in_flight. */
    uint32_t last_opcode; /**< Opcode of the most recent request. */
} slot_stats_t;

/** Server-side wrapper around one emulated device (slot). */
typedef struct srv_slot {
    uint32_t        slot_id;
    mock_device_t   dev;              /**< The emulated token. */
    pthread_mutex_t lock;            /**< Guards dev + stats + ring + link. */
    int             link_up;         /**< 0 = refuse/drop data connections. */
    int             data_fd;         /**< Current data connection, or -1. */
    slot_stats_t    stats;
    dbg_event_t     ring[MOCK_SRV_DEBUG_RING];
    uint32_t        ring_head;       /**< Next write index. */
    uint32_t        ring_count;      /**< Valid entries (<= ring size). */
} srv_slot_t;

/** Global server state. */
typedef struct server {
    uint32_t   n_slots;
    int        data_port_base;
    int        ctrl_port;
    srv_slot_t slot[PKCS11_MAX_SLOT_COUNT];
    volatile sig_atomic_t running;
} server_t;

static server_t g_srv;

/* -------------------------------------------------------------------------- */
/* Small helpers                                                              */
/* -------------------------------------------------------------------------- */

static long long now_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/** Read exactly @p n bytes into @p buf; return 0 on success, -1 on EOF/error. */
static int read_full(int fd, void *buf, size_t n)
{
    uint8_t *p = (uint8_t *)buf;
    size_t got = 0;
    while (got < n) {
        ssize_t r = recv(fd, p + got, n - got, 0);
        if (r == 0)
            return -1;              /* peer closed */
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        got += (size_t)r;
    }
    return 0;
}

/** Write exactly @p n bytes; return 0 on success, -1 on error. */
static int write_full(int fd, const void *buf, size_t n)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = send(fd, p + sent, n - sent, MSG_NOSIGNAL);
        if (w <= 0) {
            if (w < 0 && errno == EINTR)
                continue;
            return -1;
        }
        sent += (size_t)w;
    }
    return 0;
}

/** Create, bind and listen a TCP socket on @p port; return fd or -1. */
static int listen_tcp(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int yes = 1;
    struct sockaddr_in addr;

    if (fd < 0)
        return -1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "bind(port=%d): %s\n", port, strerror(errno));
        close(fd);
        return -1;
    }
    if (listen(fd, 8) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* -------------------------------------------------------------------------- */
/* Debug ring + stats                                                         */
/* -------------------------------------------------------------------------- */

/** Record a processed message into the slot's debug ring (lock held). */
static void ring_push(srv_slot_t *s, const dbg_event_t *ev)
{
    s->ring[s->ring_head] = *ev;
    s->ring_head = (s->ring_head + 1) % MOCK_SRV_DEBUG_RING;
    if (s->ring_count < MOCK_SRV_DEBUG_RING)
        s->ring_count++;
}

/* -------------------------------------------------------------------------- */
/* Data channel: one emulated USB host link per slot                          */
/* -------------------------------------------------------------------------- */

/**
 * @brief Serve one data connection: loop reading frames, feeding the mover +
 *        MCU, and writing back response frames. One connection per slot at a
 *        time; a second connection is refused elsewhere.
 */
static void serve_data_conn(srv_slot_t *s, int fd)
{
    uint8_t *req = (uint8_t *)malloc(NCMP_MAX_FRAME_SIZE);
    uint8_t *rsp = (uint8_t *)malloc(NCMP_MAX_FRAME_SIZE);

    if (!req || !rsp) {
        free(req);
        free(rsp);
        close(fd);
        return;
    }

    for (;;) {
        uint32_t frame_len;
        size_t total, rsp_len = 0;
        dbg_event_t ev;
        NCMP_Header hdr;
        int rc;

        /* Frame prefix: 4-byte little-endian length of everything after it. */
        if (read_full(fd, req, NCMP_FRAME_PREFIX_SIZE) != 0)
            break;
        memcpy(&frame_len, req, sizeof(frame_len));
        if (frame_len == 0 ||
            (size_t)frame_len + NCMP_FRAME_PREFIX_SIZE > NCMP_MAX_FRAME_SIZE)
            break;
        if (read_full(fd, req + NCMP_FRAME_PREFIX_SIZE, frame_len) != 0)
            break;
        total = NCMP_FRAME_PREFIX_SIZE + frame_len;

        memset(&ev, 0, sizeof(ev));
        ev.ts_ms = now_ms();
        ev.req_len = (uint32_t)total;
        if (ncmp_wire_decode_header(req, total, &hdr) == NCMP_OK) {
            ev.opcode = ncmp_cmd_opcode(hdr.command_id);
            ev.session = hdr.session_id;
            ev.sequence = hdr.sequence_id;
        }

        pthread_mutex_lock(&s->lock);
        if (!s->link_up) {
            pthread_mutex_unlock(&s->lock);
            break;                  /* link forced down: drop the connection */
        }
        s->stats.requests++;
        s->stats.bytes_in += total;
        s->stats.last_opcode = ev.opcode;
        s->stats.in_flight++;
        if (s->stats.in_flight > s->stats.max_in_flight)
            s->stats.max_in_flight = s->stats.in_flight;

        /* Reuse the authoritative emulation: stage then execute one step. */
        rc = mock_mover_ingest(&s->dev, req, total);
        if (rc == NCMP_OK)
            rc = mock_mcu_step(&s->dev, rsp, NCMP_MAX_FRAME_SIZE, &rsp_len);

        s->stats.in_flight--;
        if (rc == NCMP_OK) {
            s->stats.responses++;
            s->stats.bytes_out += rsp_len;
            if (ncmp_wire_decode_header(rsp, rsp_len, &hdr) == NCMP_OK)
                ev.ack = hdr.ack;
            ev.rsp_len = (uint32_t)rsp_len;
        } else {
            s->stats.errors++;
        }
        ring_push(s, &ev);
        pthread_mutex_unlock(&s->lock);

        if (rc != NCMP_OK)
            break;                  /* malformed frame: drop the link */
        if (write_full(fd, rsp, rsp_len) != 0)
            break;
    }

    pthread_mutex_lock(&s->lock);
    if (s->data_fd == fd)
        s->data_fd = -1;
    pthread_mutex_unlock(&s->lock);
    close(fd);
    free(req);
    free(rsp);
}

/** Per-slot data listener thread argument. */
typedef struct data_thread_arg {
    srv_slot_t *slot;
    int         listen_fd;
} data_thread_arg_t;

static void *data_listener(void *arg)
{
    data_thread_arg_t *a = (data_thread_arg_t *)arg;
    srv_slot_t *s = a->slot;

    while (g_srv.running) {
        int cfd = accept(a->listen_fd, NULL, NULL);
        int one = 1;
        int refuse = 0;

        if (cfd < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

        pthread_mutex_lock(&s->lock);
        if (!s->link_up || s->data_fd >= 0) {
            refuse = 1;             /* link down or already connected */
        } else {
            s->data_fd = cfd;
            s->stats.connects++;
        }
        pthread_mutex_unlock(&s->lock);

        if (refuse) {
            close(cfd);
            continue;
        }
        serve_data_conn(s, cfd);    /* blocks until the link closes */
    }
    free(a);
    return NULL;
}

/* -------------------------------------------------------------------------- */
/* Control channel: newline-delimited JSON                                    */
/* -------------------------------------------------------------------------- */

/** Extract a quoted string value for "key" from a flat JSON object. */
static int json_get_str(const char *buf, const char *key, char *out, size_t cap)
{
    char pat[64];
    const char *p, *q;
    size_t n;

    snprintf(pat, sizeof(pat), "\"%s\"", key);
    p = strstr(buf, pat);
    if (!p)
        return -1;
    p = strchr(p + strlen(pat), ':');
    if (!p)
        return -1;
    p++;
    while (*p == ' ' || *p == '\t')
        p++;
    if (*p != '"')
        return -1;
    p++;
    q = strchr(p, '"');
    if (!q)
        return -1;
    n = (size_t)(q - p);
    if (n >= cap)
        n = cap - 1;
    memcpy(out, p, n);
    out[n] = '\0';
    return 0;
}

/** Extract an integer value for "key" from a flat JSON object. */
static int json_get_int(const char *buf, const char *key, long *out)
{
    char pat[64];
    const char *p;

    snprintf(pat, sizeof(pat), "\"%s\"", key);
    p = strstr(buf, pat);
    if (!p)
        return -1;
    p = strchr(p + strlen(pat), ':');
    if (!p)
        return -1;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '"')
        p++;
    *out = strtol(p, NULL, 0);
    return 0;
}

/** JSON-escape @p in into @p out (handles the characters our fields use). */
static void json_escape(const char *in, size_t inlen, char *out, size_t cap)
{
    size_t o = 0;
    for (size_t i = 0; i < inlen && o + 2 < cap; ++i) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"' || c == '\\') {
            out[o++] = '\\';
            out[o++] = (char)c;
        } else if (c >= 0x20 && c < 0x7f) {
            out[o++] = (char)c;
        } else {
            if (o + 6 >= cap)
                break;
            o += (size_t)snprintf(out + o, cap - o, "\\u%04x", c);
        }
    }
    out[o] = '\0';
}

/** Copy a NUL-or-length-bounded field to a C string for JSON output. */
static void field_str(const char *src, size_t maxlen, char *out, size_t cap)
{
    size_t n = 0;
    while (n < maxlen && src[n] != '\0')
        n++;
    json_escape(src, n, out, cap);
}

/** Append token identity as JSON key/values into @p buf (lock held). */
static int fmt_identity(srv_slot_t *s, char *buf, size_t cap)
{
    mock_token_admin_t *a = &s->dev.admin;
    char label[80], serial[64], manuf[80], model[64], utc[48];

    field_str(a->label, sizeof(a->label), label, sizeof(label));
    field_str(a->serial, sizeof(a->serial), serial, sizeof(serial));
    field_str(a->manufacturer, sizeof(a->manufacturer), manuf, sizeof(manuf));
    field_str(a->model, sizeof(a->model), model, sizeof(model));
    field_str(a->utc, sizeof(a->utc), utc, sizeof(utc));

    return snprintf(buf, cap,
        "\"label\":\"%s\",\"serial\":\"%s\",\"manufacturer\":\"%s\","
        "\"model\":\"%s\",\"hw_major\":%u,\"hw_minor\":%u,"
        "\"fw_major\":%u,\"fw_minor\":%u,\"flags\":%u,\"utc\":\"%s\","
        "\"logged_in\":%d,\"login_user\":%u,\"obj_count\":%u",
        label, serial, manuf, model,
        a->hw_major, a->hw_minor, a->fw_major, a->fw_minor, a->flags, utc,
        a->logged_in, a->login_user, a->obj_count);
}

/** Set an identity string field from a JSON body, bounded to @p maxlen. */
static void set_field(const char *body, const char *key, char *dst,
                      size_t maxlen)
{
    char tmp[128];
    if (json_get_str(body, key, tmp, sizeof(tmp)) == 0) {
        size_t n = strlen(tmp);
        if (n > maxlen)
            n = maxlen;
        memset(dst, 0, maxlen);
        memcpy(dst, tmp, n);
    }
}

/** Handle one control request line; write a JSON response line to @p fd. */
static void handle_ctrl_line(int fd, char *line)
{
    char op[32];
    char out[8192];
    long slot_l = -1;
    int slot;
    srv_slot_t *s;

    if (json_get_str(line, "op", op, sizeof(op)) != 0) {
        write_full(fd, "{\"ok\":0,\"err\":\"no op\"}\n", 23);
        return;
    }

    /* op=list needs no slot. */
    if (strcmp(op, "list") == 0) {
        size_t o = 0;
        o += (size_t)snprintf(out + o, sizeof(out) - o,
                              "{\"ok\":1,\"slots\":[");
        for (uint32_t i = 0; i < g_srv.n_slots; ++i) {
            srv_slot_t *si = &g_srv.slot[i];
            char label[80], serial[64];
            pthread_mutex_lock(&si->lock);
            field_str(si->dev.admin.label, sizeof(si->dev.admin.label),
                      label, sizeof(label));
            field_str(si->dev.admin.serial, sizeof(si->dev.admin.serial),
                      serial, sizeof(serial));
            o += (size_t)snprintf(out + o, sizeof(out) - o,
                "%s{\"slot\":%u,\"link\":%d,\"connected\":%d,\"label\":\"%s\","
                "\"serial\":\"%s\",\"requests\":%llu,\"responses\":%llu,"
                "\"data_port\":%d}",
                i ? "," : "", si->slot_id, si->link_up,
                si->data_fd >= 0 ? 1 : 0, label, serial,
                (unsigned long long)si->stats.requests,
                (unsigned long long)si->stats.responses,
                g_srv.data_port_base + (int)i);
            pthread_mutex_unlock(&si->lock);
        }
        o += (size_t)snprintf(out + o, sizeof(out) - o, "]}\n");
        write_full(fd, out, o);
        return;
    }

    json_get_int(line, "slot", &slot_l);
    slot = (int)slot_l;
    if (slot < 0 || (uint32_t)slot >= g_srv.n_slots) {
        write_full(fd, "{\"ok\":0,\"err\":\"bad slot\"}\n", 26);
        return;
    }
    s = &g_srv.slot[slot];

    if (strcmp(op, "get") == 0) {
        char id[4096];
        size_t o;
        pthread_mutex_lock(&s->lock);
        fmt_identity(s, id, sizeof(id));
        pthread_mutex_unlock(&s->lock);
        o = (size_t)snprintf(out, sizeof(out),
                             "{\"ok\":1,\"slot\":%d,%s}\n", slot, id);
        write_full(fd, out, o);
    } else if (strcmp(op, "set") == 0) {
        long v;
        pthread_mutex_lock(&s->lock);
        set_field(line, "label", s->dev.admin.label, NCMP_TI_LABEL_LEN);
        set_field(line, "serial", s->dev.admin.serial, NCMP_TI_SERIAL_LEN);
        set_field(line, "manufacturer", s->dev.admin.manufacturer,
                  NCMP_TI_MANUF_LEN);
        set_field(line, "model", s->dev.admin.model, NCMP_TI_MODEL_LEN);
        set_field(line, "utc", s->dev.admin.utc, NCMP_TOKEN_UTC_LEN);
        if (json_get_int(line, "hw_major", &v) == 0)
            s->dev.admin.hw_major = (uint8_t)v;
        if (json_get_int(line, "hw_minor", &v) == 0)
            s->dev.admin.hw_minor = (uint8_t)v;
        if (json_get_int(line, "fw_major", &v) == 0)
            s->dev.admin.fw_major = (uint8_t)v;
        if (json_get_int(line, "fw_minor", &v) == 0)
            s->dev.admin.fw_minor = (uint8_t)v;
        if (json_get_int(line, "flags", &v) == 0)
            s->dev.admin.flags = (uint32_t)v;
        s->dev.admin.valid = 1;
        pthread_mutex_unlock(&s->lock);
        write_full(fd, "{\"ok\":1}\n", 9);
    } else if (strcmp(op, "stats") == 0) {
        size_t o;
        pthread_mutex_lock(&s->lock);
        o = (size_t)snprintf(out, sizeof(out),
            "{\"ok\":1,\"slot\":%d,\"requests\":%llu,\"responses\":%llu,"
            "\"bytes_in\":%llu,\"bytes_out\":%llu,\"errors\":%llu,"
            "\"connects\":%llu,\"in_flight\":%u,\"max_in_flight\":%u,"
            "\"last_opcode\":%u,\"link\":%d,\"connected\":%d}\n",
            slot,
            (unsigned long long)s->stats.requests,
            (unsigned long long)s->stats.responses,
            (unsigned long long)s->stats.bytes_in,
            (unsigned long long)s->stats.bytes_out,
            (unsigned long long)s->stats.errors,
            (unsigned long long)s->stats.connects,
            s->stats.in_flight, s->stats.max_in_flight,
            s->stats.last_opcode, s->link_up, s->data_fd >= 0 ? 1 : 0);
        pthread_mutex_unlock(&s->lock);
        write_full(fd, out, o);
    } else if (strcmp(op, "debug") == 0) {
        size_t o = 0;
        o += (size_t)snprintf(out + o, sizeof(out) - o,
                              "{\"ok\":1,\"slot\":%d,\"events\":[", slot);
        pthread_mutex_lock(&s->lock);
        for (uint32_t k = 0; k < s->ring_count; ++k) {
            uint32_t idx = (s->ring_head + MOCK_SRV_DEBUG_RING - s->ring_count
                            + k) % MOCK_SRV_DEBUG_RING;
            dbg_event_t *e = &s->ring[idx];
            if (o > sizeof(out) - 256)
                break;
            o += (size_t)snprintf(out + o, sizeof(out) - o,
                "%s{\"ts\":%lld,\"opcode\":%u,\"session\":%u,\"seq\":%u,"
                "\"ack\":%u,\"req_len\":%u,\"rsp_len\":%u}",
                k ? "," : "", e->ts_ms, e->opcode, e->session, e->sequence,
                e->ack, e->req_len, e->rsp_len);
        }
        pthread_mutex_unlock(&s->lock);
        o += (size_t)snprintf(out + o, sizeof(out) - o, "]}\n");
        write_full(fd, out, o);
    } else if (strcmp(op, "link") == 0) {
        long up = 1;
        int drop_fd = -1;
        json_get_int(line, "up", &up);
        pthread_mutex_lock(&s->lock);
        s->link_up = up ? 1 : 0;
        if (!s->link_up && s->data_fd >= 0) {
            drop_fd = s->data_fd;   /* force the current link down */
            s->data_fd = -1;
        }
        pthread_mutex_unlock(&s->lock);
        if (drop_fd >= 0)
            shutdown(drop_fd, SHUT_RDWR);
        write_full(fd, "{\"ok\":1}\n", 9);
    } else if (strcmp(op, "reset") == 0) {
        pthread_mutex_lock(&s->lock);
        memset(&s->stats, 0, sizeof(s->stats));
        s->ring_head = 0;
        s->ring_count = 0;
        /* Reset device state (keys/contexts/containers) but keep identity. */
        {
            mock_token_admin_t saved = s->dev.admin;
            memset(&s->dev, 0, sizeof(s->dev));
            s->dev.admin = saved;
        }
        pthread_mutex_unlock(&s->lock);
        write_full(fd, "{\"ok\":1}\n", 9);
    } else {
        write_full(fd, "{\"ok\":0,\"err\":\"unknown op\"}\n", 28);
    }
}

static void *ctrl_conn_thread(void *arg)
{
    int fd = (int)(intptr_t)arg;
    char buf[16384];
    size_t used = 0;

    for (;;) {
        ssize_t r;
        char *nl;

        if (used == sizeof(buf)) /* overlong line: reset */
            used = 0;
        r = recv(fd, buf + used, sizeof(buf) - used, 0);
        if (r <= 0)
            break;
        used += (size_t)r;
        while ((nl = memchr(buf, '\n', used)) != NULL) {
            *nl = '\0';
            handle_ctrl_line(fd, buf);
            size_t consumed = (size_t)(nl - buf) + 1;
            memmove(buf, buf + consumed, used - consumed);
            used -= consumed;
        }
    }
    close(fd);
    return NULL;
}

static void *ctrl_listener(void *arg)
{
    int listen_fd = (int)(intptr_t)arg;

    while (g_srv.running) {
        int cfd = accept(listen_fd, NULL, NULL);
        pthread_t tid;
        if (cfd < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (pthread_create(&tid, NULL, ctrl_conn_thread,
                           (void *)(intptr_t)cfd) == 0)
            pthread_detach(tid);
        else
            close(cfd);
    }
    return NULL;
}

/* -------------------------------------------------------------------------- */
/* main                                                                       */
/* -------------------------------------------------------------------------- */

static void on_signal(int sig)
{
    (void)sig;
    g_srv.running = 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [--slots N] [--data-port P] [--ctrl-port P]\n"
        "  --slots N       number of emulated tokens (1..%d, default 1)\n"
        "  --data-port P   base TCP port; slot s listens on P+s (default %d)\n"
        "  --ctrl-port P   control TCP port (default %d)\n",
        prog, PKCS11_MAX_SLOT_COUNT, MOCK_SRV_DEFAULT_DATA_PORT,
        MOCK_SRV_DEFAULT_CTRL_PORT);
}

int main(int argc, char **argv)
{
    pthread_t ctrl_tid;
    int ctrl_listen_fd;

    g_srv.n_slots = 1;
    g_srv.data_port_base = MOCK_SRV_DEFAULT_DATA_PORT;
    g_srv.ctrl_port = MOCK_SRV_DEFAULT_CTRL_PORT;

    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--slots") && i + 1 < argc) {
            g_srv.n_slots = (uint32_t)atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--data-port") && i + 1 < argc) {
            g_srv.data_port_base = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--ctrl-port") && i + 1 < argc) {
            g_srv.ctrl_port = atoi(argv[++i]);
        } else {
            usage(argv[0]);
            return 2;
        }
    }
    if (g_srv.n_slots < 1 || g_srv.n_slots > PKCS11_MAX_SLOT_COUNT) {
        usage(argv[0]);
        return 2;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);
    g_srv.running = 1;

    /* Bring up each slot: emulated device + identity + data listener. */
    for (uint32_t i = 0; i < g_srv.n_slots; ++i) {
        srv_slot_t *s = &g_srv.slot[i];
        data_thread_arg_t *a;
        pthread_t tid;
        int lfd;

        memset(s, 0, sizeof(*s));
        s->slot_id = i;
        pthread_mutex_init(&s->lock, NULL);
        s->link_up = 1;
        s->data_fd = -1;
        mock_device_set_identity(&s->dev, i);

        lfd = listen_tcp(g_srv.data_port_base + (int)i);
        if (lfd < 0) {
            fprintf(stderr, "failed to listen on data port %d\n",
                    g_srv.data_port_base + (int)i);
            return 1;
        }
        a = (data_thread_arg_t *)calloc(1, sizeof(*a));
        a->slot = s;
        a->listen_fd = lfd;
        pthread_create(&tid, NULL, data_listener, a);
        pthread_detach(tid);
        printf("slot %u: data link on 127.0.0.1:%d (%.*s)\n", i,
               g_srv.data_port_base + (int)i,
               (int)NCMP_TI_LABEL_LEN, s->dev.admin.label);
    }

    ctrl_listen_fd = listen_tcp(g_srv.ctrl_port);
    if (ctrl_listen_fd < 0) {
        fprintf(stderr, "failed to listen on control port %d\n",
                g_srv.ctrl_port);
        return 1;
    }
    printf("control channel on 127.0.0.1:%d, %u slot(s). Ctrl-C to stop.\n",
           g_srv.ctrl_port, g_srv.n_slots);
    fflush(stdout);

    pthread_create(&ctrl_tid, NULL, ctrl_listener,
                   (void *)(intptr_t)ctrl_listen_fd);

    /* Idle until a signal flips running; detached workers do the rest. */
    while (g_srv.running)
        pause();

    printf("\nshutting down.\n");
    return 0;
}

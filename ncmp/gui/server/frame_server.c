/*
 * Token NCMP - Generic wire-frame socket server (implementation).
 *
 * See frame_server.h. Owns the sockets, threads, per-slot statistics, the debug
 * ring, and the JSON control protocol; delegates request execution and identity
 * get/set to a backend vtable. Dependency-free (POSIX sockets + pthreads).
 */
#define _GNU_SOURCE
#include "frame_server.h"

#include "ncmp/ncmp_wire.h"
#include "ncmp/ncmp_cmd.h"
#include "ncmp/ncmp_errno.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define FS_DEBUG_RING 128

typedef struct dbg_event {
    long long ts_ms;
    uint32_t  opcode, session, sequence, ack, req_len, rsp_len;
} dbg_event_t;

typedef struct slot_stats {
    uint64_t requests, responses, bytes_in, bytes_out, errors, connects;
    uint32_t in_flight, max_in_flight, last_opcode;
} slot_stats_t;

typedef struct fs_slot {
    uint32_t        slot_id;
    void           *ctx;             /* backend per-slot context */
    pthread_mutex_t lock;
    int             link_up;
    int             data_fd;
    slot_stats_t    stats;
    dbg_event_t     ring[FS_DEBUG_RING];
    uint32_t        ring_head, ring_count;
} fs_slot_t;

typedef struct fs_state {
    fs_config_t cfg;
    fs_slot_t   slot[FS_MAX_SLOTS];
    volatile sig_atomic_t running;
} fs_state_t;

static fs_state_t g_fs;

/* -------------------------------------------------------------------------- */
static long long now_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static int read_full(int fd, void *buf, size_t n)
{
    uint8_t *p = buf;
    size_t got = 0;
    while (got < n) {
        ssize_t r = recv(fd, p + got, n - got, 0);
        if (r == 0)
            return -1;
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        got += (size_t)r;
    }
    return 0;
}

static int write_full(int fd, const void *buf, size_t n)
{
    const uint8_t *p = buf;
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

/* --- JSON helpers --------------------------------------------------------- */
int fs_json_get_str(const char *buf, const char *key, char *out, size_t cap)
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

int fs_json_get_int(const char *buf, const char *key, long *out)
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

void fs_json_escape(const char *in, size_t inlen, char *out, size_t cap)
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

/* --- debug ring ----------------------------------------------------------- */
static void ring_push(fs_slot_t *s, const dbg_event_t *ev)
{
    s->ring[s->ring_head] = *ev;
    s->ring_head = (s->ring_head + 1) % FS_DEBUG_RING;
    if (s->ring_count < FS_DEBUG_RING)
        s->ring_count++;
}

/* --- data channel --------------------------------------------------------- */
static void serve_data_conn(fs_slot_t *s, int fd)
{
    const fs_backend_t *be = g_fs.cfg.backend;
    uint8_t *req = malloc(NCMP_MAX_FRAME_SIZE);
    uint8_t *rsp = malloc(NCMP_MAX_FRAME_SIZE);

    if (!req || !rsp) {
        free(req); free(rsp); close(fd);
        return;
    }
    for (;;) {
        uint32_t frame_len;
        size_t total, rsp_len = 0;
        dbg_event_t ev;
        NCMP_Header hdr;
        int rc;

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
            break;
        }
        s->stats.requests++;
        s->stats.bytes_in += total;
        s->stats.last_opcode = ev.opcode;
        s->stats.in_flight++;
        if (s->stats.in_flight > s->stats.max_in_flight)
            s->stats.max_in_flight = s->stats.in_flight;

        rc = be->exec(s->ctx, req, total, rsp, NCMP_MAX_FRAME_SIZE, &rsp_len);

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
            break;
        if (write_full(fd, rsp, rsp_len) != 0)
            break;
    }
    pthread_mutex_lock(&s->lock);
    if (s->data_fd == fd)
        s->data_fd = -1;
    pthread_mutex_unlock(&s->lock);
    close(fd);
    free(req); free(rsp);
}

typedef struct { fs_slot_t *slot; int listen_fd; } data_arg_t;

static void *data_listener(void *arg)
{
    data_arg_t *a = arg;
    fs_slot_t *s = a->slot;

    while (g_fs.running) {
        int cfd = accept(a->listen_fd, NULL, NULL);
        int one = 1, refuse = 0;

        if (cfd < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        pthread_mutex_lock(&s->lock);
        if (!s->link_up || s->data_fd >= 0) {
            refuse = 1;
        } else {
            s->data_fd = cfd;
            s->stats.connects++;
        }
        pthread_mutex_unlock(&s->lock);
        if (refuse) {
            close(cfd);
            continue;
        }
        serve_data_conn(s, cfd);
    }
    free(a);
    return NULL;
}

/* --- control channel ------------------------------------------------------ */
static void handle_ctrl_line(int fd, char *line)
{
    const fs_backend_t *be = g_fs.cfg.backend;
    char op[32], out[8192];
    long slot_l = -1;
    int slot;
    fs_slot_t *s;

    if (fs_json_get_str(line, "op", op, sizeof(op)) != 0) {
        write_full(fd, "{\"ok\":0,\"err\":\"no op\"}\n", 23);
        return;
    }

    if (strcmp(op, "list") == 0) {
        size_t o = (size_t)snprintf(out, sizeof(out), "{\"ok\":1,\"slots\":[");
        for (uint32_t i = 0; i < g_fs.cfg.n_slots; ++i) {
            fs_slot_t *si = &g_fs.slot[i];
            char label[96] = "", esc[128];
            pthread_mutex_lock(&si->lock);
            if (be->label)
                be->label(si->ctx, label, sizeof(label));
            fs_json_escape(label, strlen(label), esc, sizeof(esc));
            o += (size_t)snprintf(out + o, sizeof(out) - o,
                "%s{\"slot\":%u,\"link\":%d,\"connected\":%d,\"label\":\"%s\","
                "\"requests\":%llu,\"responses\":%llu,\"data_port\":%d}",
                i ? "," : "", si->slot_id, si->link_up,
                si->data_fd >= 0 ? 1 : 0, esc,
                (unsigned long long)si->stats.requests,
                (unsigned long long)si->stats.responses,
                g_fs.cfg.data_port_base + (int)i);
            pthread_mutex_unlock(&si->lock);
        }
        o += (size_t)snprintf(out + o, sizeof(out) - o, "]}\n");
        write_full(fd, out, o);
        return;
    }

    fs_json_get_int(line, "slot", &slot_l);
    slot = (int)slot_l;
    if (slot < 0 || (uint32_t)slot >= g_fs.cfg.n_slots) {
        write_full(fd, "{\"ok\":0,\"err\":\"bad slot\"}\n", 26);
        return;
    }
    s = &g_fs.slot[slot];

    if (strcmp(op, "get") == 0) {
        char id[4096];
        int n = -1;
        pthread_mutex_lock(&s->lock);
        if (be->get_identity)
            n = be->get_identity(s->ctx, id, sizeof(id));
        pthread_mutex_unlock(&s->lock);
        if (n < 0) {
            write_full(fd, "{\"ok\":0,\"err\":\"identity not supported\"}\n", 40);
        } else {
            size_t o = (size_t)snprintf(out, sizeof(out),
                                        "{\"ok\":1,\"slot\":%d,%s}\n", slot, id);
            write_full(fd, out, o);
        }
    } else if (strcmp(op, "set") == 0) {
        int rc = -1;
        pthread_mutex_lock(&s->lock);
        if (be->set_identity)
            rc = be->set_identity(s->ctx, line);
        pthread_mutex_unlock(&s->lock);
        write_full(fd, rc == 0 ? "{\"ok\":1}\n"
                   : "{\"ok\":0,\"err\":\"identity not supported\"}\n",
                   rc == 0 ? 9 : 40);
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
        size_t o = (size_t)snprintf(out, sizeof(out),
                                    "{\"ok\":1,\"slot\":%d,\"events\":[", slot);
        pthread_mutex_lock(&s->lock);
        for (uint32_t k = 0; k < s->ring_count; ++k) {
            uint32_t idx = (s->ring_head + FS_DEBUG_RING - s->ring_count + k)
                           % FS_DEBUG_RING;
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
        fs_json_get_int(line, "up", &up);
        pthread_mutex_lock(&s->lock);
        s->link_up = up ? 1 : 0;
        if (!s->link_up && s->data_fd >= 0) {
            drop_fd = s->data_fd;
            s->data_fd = -1;
        }
        pthread_mutex_unlock(&s->lock);
        if (drop_fd >= 0)
            shutdown(drop_fd, SHUT_RDWR);
        write_full(fd, "{\"ok\":1}\n", 9);
    } else if (strcmp(op, "reset") == 0) {
        pthread_mutex_lock(&s->lock);
        memset(&s->stats, 0, sizeof(s->stats));
        s->ring_head = s->ring_count = 0;
        if (be->reset)
            be->reset(s->ctx);
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
        if (used == sizeof(buf))
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
    while (g_fs.running) {
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

/* --- lifecycle ------------------------------------------------------------ */
static void on_signal(int sig)
{
    (void)sig;
    g_fs.running = 0;
}

int fs_run(const fs_config_t *cfg)
{
    pthread_t ctrl_tid;
    int ctrl_fd;

    if (!cfg || !cfg->backend || !cfg->backend->exec ||
        cfg->n_slots < 1 || cfg->n_slots > FS_MAX_SLOTS)
        return 2;

    g_fs.cfg = *cfg;
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);
    g_fs.running = 1;

    for (uint32_t i = 0; i < cfg->n_slots; ++i) {
        fs_slot_t *s = &g_fs.slot[i];
        data_arg_t *a;
        pthread_t tid;
        int lfd;
        char label[96] = "";

        memset(s, 0, sizeof(*s));
        s->slot_id = i;
        s->ctx = cfg->ctx[i];
        pthread_mutex_init(&s->lock, NULL);
        s->link_up = 1;
        s->data_fd = -1;

        lfd = listen_tcp(cfg->data_port_base + (int)i);
        if (lfd < 0) {
            fprintf(stderr, "failed to listen on data port %d\n",
                    cfg->data_port_base + (int)i);
            return 1;
        }
        a = calloc(1, sizeof(*a));
        a->slot = s;
        a->listen_fd = lfd;
        pthread_create(&tid, NULL, data_listener, a);
        pthread_detach(tid);
        if (cfg->backend->label)
            cfg->backend->label(s->ctx, label, sizeof(label));
        printf("slot %u: data link on 127.0.0.1:%d  [%s]\n", i,
               cfg->data_port_base + (int)i, label);
    }

    ctrl_fd = listen_tcp(cfg->ctrl_port);
    if (ctrl_fd < 0) {
        fprintf(stderr, "failed to listen on control port %d\n", cfg->ctrl_port);
        return 1;
    }
    printf("%s: control on 127.0.0.1:%d, %u slot(s). Ctrl-C to stop.\n",
           cfg->name ? cfg->name : "frame-server", cfg->ctrl_port, cfg->n_slots);
    fflush(stdout);

    pthread_create(&ctrl_tid, NULL, ctrl_listener, (void *)(intptr_t)ctrl_fd);
    while (g_fs.running)
        pause();
    printf("\nshutting down.\n");
    return 0;
}

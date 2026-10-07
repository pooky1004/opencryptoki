/*
 * Token NCMP - Test App web server.
 *
 * A small, dependency-free HTTP/1.1 server (thread-per-connection) that turns
 * the C application layer (ncmp_testapp.c, the app_* ABI) into a JSON REST API
 * and serves the static web UI. A browser anywhere on the network can then
 * drive the token:
 *
 *   Browser --HTTP/JSON--> ncmp_web (this) --app_*--> libncmp_testapp
 *       --dlopen/dlsym C_*--> libpkcs11_ncmp.so(facade) --> ncmpd --> FX3(USB)
 *
 * It also launches/stops ncmpd for the "run the daemon" controls, sharing
 * NCMP_SOCK_PATH with the facade.
 *
 * SECURITY: this exposes module load + PKCS#11 + daemon spawn over the network
 * and has NO transport encryption. When NCMP_WEB_TOKEN is set, every API
 * request must carry "Authorization: Bearer <token>". Bind to a trusted
 * interface / use an SSH tunnel for anything beyond a lab. See
 * docs/testapp-web-deployment.md.
 *
 * Style: Google C Style. A developer tool, not part of the shipped token.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "ncmp_testapp.h"

/* Raw CI (Command Interface) send path: a second ncmp_client straight to the
 * daemon, independent of the dlopen'd facade, used by the "CI 송수신" tab. */
#include "ncmp/ncmp_client.h"
#include "ncmp/ncmp_ipc.h"
#include "ncmp/ncmp_shm.h"
#include "ncmp/ncmp_slot.h"
#include "ncmp/ncmp_wire.h"
#include "ncmp/ncmp_errno.h"
#include "ncmp/ncmp_limits.h"

#include <openssl/evp.h>

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Config + global state                                              */
/* ------------------------------------------------------------------ */

static char g_host[64] = "0.0.0.0";
static int g_port = 8080;
static char g_webroot[1024] = "web";
static char g_module[1024] = "";       /* default facade module path */
static char g_ncmpd[1024] = "ncmpd";   /* ncmpd binary path */
static char g_transport[16] = "real";  /* default --transport (real FX3) */
static char g_sock_path[1024] = "";     /* NCMP_SOCK_PATH shared with facade */
static char g_token[256] = "";          /* bearer token; empty = auth off */
static char g_filedir[1024] = "/tmp/ncmp_web_files"; /* generated test files */
static char g_scendir[1024] = ".config/scenarios";  /* saved scenarios (JSON) */
static char g_config[1024] = "";        /* loaded config file path (for status) */

/* Upper bound for a generated/verified test file held in memory at once. */
#define NCMP_WEB_MAX_FILE (64L * 1024 * 1024)

/* All PKCS#11 state in ncmp_testapp.c is process-global, so serialise every
 * API call: one token, one facade, many browser tabs. */
static pthread_mutex_t g_api_lock = PTHREAD_MUTEX_INITIALIZER;

/* ncmpd child lifecycle. */
static pid_t g_ncmpd_pid = 0;
static pthread_mutex_t g_daemon_lock = PTHREAD_MUTEX_INITIALIZER;

/* Raw-CI client: a dedicated ncmp_client to the same daemon socket, separate
 * from the facade's. Lazily connected; its own lock serialises CI exchanges
 * (which can take up to the daemon's ~5 s no-response timeout) without blocking
 * the facade/status routes. */
static ncmp_client_t g_ci_cli;
static int g_ci_ok = 0;
static pthread_mutex_t g_ci_lock = PTHREAD_MUTEX_INITIALIZER;
/* Generous backstop; the daemon reaps a non-responding command at ~5 s. */
#define WEB_CI_SPIN_BUDGET 200000000ull

static volatile sig_atomic_t g_running = 1;
static void on_signal(int sig) { (void)sig; g_running = 0; }

/* ------------------------------------------------------------------ */
/* Tiny JSON field extraction (flat objects only)                     */
/* ------------------------------------------------------------------ */

/* Find "key" in a flat JSON object body; copy its string value (unescaped for
 * simple cases) into out. Returns 1 on success. */
static int json_str(const char *body, const char *key, char *out, size_t cap)
{
    char pat[96];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = body ? strstr(body, pat) : NULL;
    if (!p)
        return 0;
    p = strchr(p + strlen(pat), ':');
    if (!p)
        return 0;
    p++;
    while (*p == ' ' || *p == '\t')
        p++;
    if (*p != '"')
        return 0;
    p++;
    size_t o = 0;
    while (*p && *p != '"' && o + 1 < cap) {
        if (*p == '\\' && p[1])
            p++;            /* copy the escaped char literally (good enough) */
        out[o++] = *p++;
    }
    out[o] = '\0';
    return 1;
}

/* Find "key" and parse an integer value. Returns 1 on success. */
static int json_long(const char *body, const char *key, long *out)
{
    char pat[96];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = body ? strstr(body, pat) : NULL;
    if (!p)
        return 0;
    p = strchr(p + strlen(pat), ':');
    if (!p)
        return 0;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '"')
        p++;
    char *end = NULL;
    long v = strtol(p, &end, 0);
    if (end == p)
        return 0;
    *out = v;
    return 1;
}

/* ------------------------------------------------------------------ */
/* Config file (.config/config): key = value, '#' comments            */
/* ------------------------------------------------------------------ */

/* Assign one config/CLI key to the matching global. Unknown keys ignored. */
static void set_cfg(const char *k, const char *v)
{
    if      (!strcmp(k, "host"))      snprintf(g_host, sizeof(g_host), "%s", v);
    else if (!strcmp(k, "port"))      g_port = atoi(v);
    else if (!strcmp(k, "webroot"))   snprintf(g_webroot, sizeof(g_webroot), "%s", v);
    else if (!strcmp(k, "module"))    snprintf(g_module, sizeof(g_module), "%s", v);
    else if (!strcmp(k, "ncmpd"))     snprintf(g_ncmpd, sizeof(g_ncmpd), "%s", v);
    else if (!strcmp(k, "transport")) snprintf(g_transport, sizeof(g_transport), "%s", v);
    else if (!strcmp(k, "sock"))      snprintf(g_sock_path, sizeof(g_sock_path), "%s", v);
    else if (!strcmp(k, "filedir"))   snprintf(g_filedir, sizeof(g_filedir), "%s", v);
    else if (!strcmp(k, "scendir"))   snprintf(g_scendir, sizeof(g_scendir), "%s", v);
    else if (!strcmp(k, "token"))     snprintf(g_token, sizeof(g_token), "%s", v);
}

/* Load a "key = value" config file. Returns 0 if read, -1 if absent. */
static int load_config(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    char line[2048];
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == ';' || *p == '\n' || *p == '\r' || *p == '\0')
            continue;
        char *eq = strchr(p, '=');
        if (!eq)
            continue;
        *eq = '\0';
        char *key = p, *val = eq + 1;
        /* trim key trailing ws */
        char *ke = key + strlen(key);
        while (ke > key && (ke[-1] == ' ' || ke[-1] == '\t')) *--ke = '\0';
        /* trim val leading ws */
        while (*val == ' ' || *val == '\t') val++;
        /* strip optional surrounding quotes, then trailing ws/newline */
        size_t vl = strlen(val);
        while (vl && (val[vl - 1] == '\n' || val[vl - 1] == '\r' ||
                      val[vl - 1] == ' '  || val[vl - 1] == '\t')) val[--vl] = '\0';
        if (vl >= 2 && ((val[0] == '"' && val[vl - 1] == '"') ||
                        (val[0] == '\'' && val[vl - 1] == '\''))) {
            val[vl - 1] = '\0';
            val++;
        }
        set_cfg(key, val);
    }
    fclose(f);
    snprintf(g_config, sizeof(g_config), "%s", path);
    return 0;
}

/* ------------------------------------------------------------------ */
/* HTTP response helpers                                              */
/* ------------------------------------------------------------------ */

static void write_all(int fd, const char *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n <= 0) {
            if (n < 0 && errno == EINTR)
                continue;
            break;
        }
        off += (size_t)n;
    }
}

static void send_raw(int fd, int status, const char *status_text,
                     const char *ctype, const char *body, size_t body_len)
{
    char hdr[512];
    int n = snprintf(hdr, sizeof(hdr),
                     "HTTP/1.1 %d %s\r\n"
                     "Content-Type: %s\r\n"
                     "Content-Length: %zu\r\n"
                     "Access-Control-Allow-Origin: *\r\n"
                     "Access-Control-Allow-Headers: Authorization, Content-Type\r\n"
                     "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
                     "Connection: close\r\n"
                     "\r\n",
                     status, status_text, ctype, body_len);
    write_all(fd, hdr, (size_t)n);
    if (body && body_len)
        write_all(fd, body, body_len);
}

static void send_json(int fd, int status, const char *json)
{
    const char *txt = status == 200 ? "OK" : (status == 400 ? "Bad Request"
             : status == 401 ? "Unauthorized" : status == 404 ? "Not Found"
             : "Internal Server Error");
    send_raw(fd, status, txt, "application/json; charset=utf-8", json, strlen(json));
}

/* Emit {"rc":N,"status":"...","...":...}. rc 0 => ok. */
static void send_result(int fd, int rc, const char *extra_json)
{
    char buf[18 * 1024];
    const char *err = app_last_error();
    char errbuf[1024];
    size_t o = 0;
    for (size_t i = 0; err[i] && o + 2 < sizeof(errbuf); i++) {
        if (err[i] == '"' || err[i] == '\\')
            errbuf[o++] = '\\';
        errbuf[o++] = err[i];
    }
    errbuf[o] = '\0';
    snprintf(buf, sizeof(buf),
             "{\"rc\":%d,\"ok\":%s,\"error\":\"%s\"%s%s}",
             rc, rc == 0 ? "true" : "false", errbuf,
             (extra_json && *extra_json) ? "," : "",
             (extra_json && *extra_json) ? extra_json : "");
    send_json(fd, 200, buf);
}

/* ------------------------------------------------------------------ */
/* Static file serving                                               */
/* ------------------------------------------------------------------ */

static const char *mime_of(const char *path)
{
    const char *dot = strrchr(path, '.');
    if (!dot)
        return "application/octet-stream";
    if (!strcmp(dot, ".html")) return "text/html; charset=utf-8";
    if (!strcmp(dot, ".js"))   return "application/javascript; charset=utf-8";
    if (!strcmp(dot, ".css"))  return "text/css; charset=utf-8";
    if (!strcmp(dot, ".json")) return "application/json; charset=utf-8";
    if (!strcmp(dot, ".svg"))  return "image/svg+xml";
    if (!strcmp(dot, ".ico"))  return "image/x-icon";
    return "text/plain; charset=utf-8";
}

/* Serve a file under g_webroot. Rejects any path containing "..". */
static int safe_name(const char *name);   /* defined later */

static void serve_static(int fd, const char *url_path)
{
    char rel[1024];
    if (!strcmp(url_path, "/"))
        snprintf(rel, sizeof(rel), "index.html");
    else
        snprintf(rel, sizeof(rel), "%s", url_path[0] == '/' ? url_path + 1 : url_path);

    if (strstr(rel, "..")) {
        send_json(fd, 400, "{\"error\":\"bad path\"}");
        return;
    }
    char full[2200];
    snprintf(full, sizeof(full), "%s/%s", g_webroot, rel);

    FILE *f = fopen(full, "rb");
    if (!f) {
        send_json(fd, 404, "{\"error\":\"not found\"}");
        return;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) sz = 0;
    char *body = malloc((size_t)sz + 1);
    if (!body) { fclose(f); send_json(fd, 500, "{\"error\":\"oom\"}"); return; }
    size_t rd = fread(body, 1, (size_t)sz, f);
    fclose(f);
    send_raw(fd, 200, "OK", mime_of(full), body, rd);
    free(body);
}

/* Serve a generated test file (GET /files/<name>) from g_filedir as plain text
 * so the UI can open Hex test/ciphertext/plaintext files in a new window. */
static void serve_test_file(int fd, const char *name)
{
    if (!safe_name(name)) { send_json(fd, 400, "{\"error\":\"bad name\"}"); return; }
    char full[2200];
    snprintf(full, sizeof(full), "%s/%s", g_filedir, name);
    FILE *f = fopen(full, "rb");
    if (!f) { send_json(fd, 404, "{\"error\":\"not found\"}"); return; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) sz = 0;
    char *body = malloc((size_t)sz + 1);
    if (!body) { fclose(f); send_json(fd, 500, "{\"error\":\"oom\"}"); return; }
    size_t rd = fread(body, 1, (size_t)sz, f);
    fclose(f);
    send_raw(fd, 200, "OK", "text/plain; charset=utf-8", body, rd);
    free(body);
}

/* ------------------------------------------------------------------ */
/* ncmpd daemon control                                              */
/* ------------------------------------------------------------------ */

/* True if the ncmpd control socket accepts a connection right now (i.e. the
 * daemon has bound and is listening). */
static int daemon_socket_ready(void)
{
    if (!g_sock_path[0])
        return 0;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return 0;
    struct sockaddr_un a;
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    if (strlen(g_sock_path) >= sizeof(a.sun_path)) { close(fd); return 0; }
    strncpy(a.sun_path, g_sock_path, sizeof(a.sun_path) - 1);
    int ok = connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0;
    close(fd);
    return ok;
}

/**
 * @brief Decide whether an already-listening ncmpd is actually usable.
 *
 * A connectable socket is NOT proof of health: an ncmpd can keep listening
 * after its POSIX SHM object (/dev/shm/ncmpd_shm) has been unlinked - for
 * example by the unit-test suite (ncmp_shm_destroy uses the same name) or by a
 * second daemon that briefly started and exited. Such a "zombie" still answers
 * HELLO with a cached slot mask, but every client's ncmp_shm_attach() then
 * fails with ENOENT, so C_Initialize returns CKR_TOKEN_NOT_PRESENT (0xE0) and
 * no slots ever appear. Reuse a daemon only when it (a) completes the
 * HELLO/ATTACH handshake and (b) advertises an SHM object that still exists.
 *
 * @return 1 if the existing daemon is healthy and reusable, 0 otherwise.
 */
static int daemon_healthy(void)
{
    struct sockaddr_un a;
    NCMP_IpcMsg hello, reply;
    char shm_name[sizeof(reply.shm_name) + 1];
    int fd, sfd, ok = 0;

    if (!g_sock_path[0])
        return 0;
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return 0;
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    if (strlen(g_sock_path) >= sizeof(a.sun_path)) { close(fd); return 0; }
    strncpy(a.sun_path, g_sock_path, sizeof(a.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) { close(fd); return 0; }

    memset(&hello, 0, sizeof(hello));
    hello.op = NCMP_IPC_HELLO;
    hello.version = NCMP_IPC_VERSION;
    shm_name[0] = '\0';
    if (write(fd, &hello, sizeof(hello)) == (ssize_t)sizeof(hello) &&
        read(fd, &reply, sizeof(reply)) == (ssize_t)sizeof(reply) &&
        reply.op == NCMP_IPC_ATTACH && reply.version == NCMP_IPC_VERSION) {
        memcpy(shm_name, reply.shm_name, sizeof(reply.shm_name));
        shm_name[sizeof(reply.shm_name)] = '\0';
        ok = 1;
    }
    close(fd);
    if (!ok)
        return 0;

    /* The advertised SHM object must still exist, or no client can attach. */
    sfd = shm_open(shm_name[0] ? shm_name : NCMP_SHM_NAME, O_RDWR, 0);
    if (sfd < 0)
        return 0;
    close(sfd);
    return 1;
}

/** Read the PID an ncmpd recorded in its single-instance lock file (0 if none). */
static pid_t daemon_lock_pid(void)
{
    const char *path = getenv("NCMP_LOCK_PATH");
    FILE *f;
    int pid = 0;

    if (!path || !*path)
        path = "/tmp/ncmpd.lock";
    f = fopen(path, "r");
    if (!f)
        return 0;
    if (fscanf(f, "%d", &pid) != 1)
        pid = 0;
    fclose(f);
    return (pid_t)pid;
}

static int daemon_running(void)
{
    if (g_ncmpd_pid <= 0)
        return 0;
    int status;
    pid_t r = waitpid(g_ncmpd_pid, &status, WNOHANG);
    if (r == 0)
        return 1;           /* still alive */
    g_ncmpd_pid = 0;        /* reaped */
    return 0;
}

static int daemon_start(const char *transport)
{
    pthread_mutex_lock(&g_daemon_lock);
    if (daemon_running()) {
        pthread_mutex_unlock(&g_daemon_lock);
        return 0;
    }
    pthread_mutex_unlock(&g_daemon_lock);
    /* An ncmpd is already listening on our socket (started externally, or by
     * another ncmp_web sharing this --sock)? Reuse it - do NOT unlink its
     * socket and spawn a second daemon, which would fight over the single FX3
     * (the loser logs "slot 0 transport open failed" and reports no slots). */
    if (daemon_socket_ready()) {
        if (daemon_healthy()) {
            fprintf(stderr, "ncmp_web: reusing existing ncmpd at %s\n",
                    g_sock_path);
            return 0;
        }
        /* A daemon is listening but is unusable (its SHM is gone or it fails the
         * handshake): a zombie that would make every C_Initialize fail with
         * CKR_TOKEN_NOT_PRESENT and show no slots. Reclaim it - terminate the
         * lock owner so a fresh daemon can take over the single-instance lock
         * and the FX3 - then fall through to spawn a new one. */
        pid_t zpid = daemon_lock_pid();

        fprintf(stderr, "ncmp_web: existing ncmpd at %s is stale "
                "(SHM missing / unresponsive); reclaiming (pid %d)\n",
                g_sock_path, (int)zpid);
        if (zpid > 1 && (kill(zpid, 0) == 0 || errno == EPERM)) {
            kill(zpid, SIGTERM);
            for (int i = 0; i < 30 && daemon_socket_ready(); i++)
                usleep(100 * 1000);
            if (daemon_socket_ready()) {
                kill(zpid, SIGKILL);
                for (int i = 0; i < 20 && daemon_socket_ready(); i++)
                    usleep(100 * 1000);
            }
        }
        if (daemon_socket_ready()) {
            fprintf(stderr, "ncmp_web: could not reclaim stale ncmpd at %s "
                    "(pid %d) - stop it manually and retry\n",
                    g_sock_path, (int)zpid);
            return -1;
        }
        fprintf(stderr, "ncmp_web: stale ncmpd reclaimed; starting fresh\n");
        /* fall through to spawn a new daemon */
    }
    pthread_mutex_lock(&g_daemon_lock);
    /* Guard the self-overlap: callers may pass g_transport itself (when the
     * request carried no transport), and snprintf() with overlapping src/dst
     * is undefined behaviour (observed to yield ""). Only copy a distinct src. */
    if (transport && *transport && transport != g_transport)
        snprintf(g_transport, sizeof(g_transport), "%s", transport);
    unlink(g_sock_path);

    pid_t pid = fork();
    if (pid < 0) {
        pthread_mutex_unlock(&g_daemon_lock);
        return -1;
    }
    if (pid == 0) {
        /* child: run ncmpd with our socket path + transport */
        setenv("NCMP_SOCK_PATH", g_sock_path, 1);
        execlp(g_ncmpd, g_ncmpd, "--transport", g_transport, (char *)NULL);
        _exit(127);
    }
    g_ncmpd_pid = pid;
    pthread_mutex_unlock(&g_daemon_lock);

    /* Return only once the daemon is actually reachable, so a client that loads
     * the facade right after this never races the socket bind. The real FX3
     * probe (token identity scan) can take several seconds, so poll up to ~10s;
     * also give up early if the child died (e.g. exec failed). */
    for (int i = 0; i < 100; i++) {
        if (daemon_socket_ready())
            return 0;
        pthread_mutex_lock(&g_daemon_lock);
        int alive = daemon_running();
        pthread_mutex_unlock(&g_daemon_lock);
        if (!alive)
            return -1;
        usleep(100 * 1000);
    }
    return 0;   /* timed out waiting; report started anyway */
}

static void daemon_stop(void)
{
    pthread_mutex_lock(&g_daemon_lock);
    if (g_ncmpd_pid > 0) {
        kill(g_ncmpd_pid, SIGTERM);
        for (int i = 0; i < 30; i++) {
            if (waitpid(g_ncmpd_pid, NULL, WNOHANG) != 0)
                break;
            usleep(100 * 1000);
        }
        kill(g_ncmpd_pid, SIGKILL);
        waitpid(g_ncmpd_pid, NULL, 0);
        g_ncmpd_pid = 0;
    }
    pthread_mutex_unlock(&g_daemon_lock);
}

/* ------------------------------------------------------------------ */
/* Test files + software (OpenSSL) reference digest                   */
/* ------------------------------------------------------------------ */

/* Map our CKM_* code to the matching OpenSSL EVP_MD. */
static const EVP_MD *md_of(long mech)
{
    switch (mech) {
    case 0x250: return EVP_sha256();     /* CKM_SHA256   */
    case 0x270: return EVP_sha512();     /* CKM_SHA512   */
    case 0x2B5: return EVP_sha3_224();   /* CKM_SHA3_224 */
    case 0x2B0: return EVP_sha3_256();   /* CKM_SHA3_256 */
    case 0x2C0: return EVP_sha3_384();   /* CKM_SHA3_384 */
    case 0x2D0: return EVP_sha3_512();   /* CKM_SHA3_512 */
    default:    return NULL;
    }
}

/* Software reference digest of a buffer. Returns digest length, or -1. */
static int sw_digest(long mech, const unsigned char *data, size_t len,
                     unsigned char *out, unsigned int *out_len)
{
    const EVP_MD *md = md_of(mech);
    if (!md)
        return -1;
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    if (!c)
        return -1;
    int ok = EVP_DigestInit_ex(c, md, NULL) == 1 &&
             EVP_DigestUpdate(c, data, len) == 1 &&
             EVP_DigestFinal_ex(c, out, out_len) == 1;
    EVP_MD_CTX_free(c);
    return ok ? (int)*out_len : -1;
}

/* Reject anything but a plain basename (no path separators / "..") so files
 * only ever resolve inside g_filedir. */
static int safe_name(const char *name)
{
    if (!name || !*name || strlen(name) > 128)
        return 0;
    if (strchr(name, '/') || strstr(name, ".."))
        return 0;
    return 1;
}

static void hex_of(const unsigned char *b, int n, char *out)
{
    static const char *H = "0123456789abcdef";
    for (int i = 0; i < n; i++) { out[2 * i] = H[b[i] >> 4]; out[2 * i + 1] = H[b[i] & 0xF]; }
    out[2 * n] = '\0';
}

/* Create g_filedir if missing. */
static void ensure_filedir(void) { mkdir(g_filedir, 0755); }

/* Generate a size-byte test file filled with a reproducible LCG pattern. */
/* Generate a @p size-byte pseudo-random test file. With @p as_hex, the data is
 * written as a Hex text file (a header comment, then hex grouped 64 bytes = 128
 * chars per line) so large multipart inputs are human-readable; otherwise the
 * raw bytes are written. The DATA is always @p size bytes either way. */
static int gen_test_file(const char *name, long size, unsigned seed, int as_hex)
{
    char full[2200];
    snprintf(full, sizeof(full), "%s/%s", g_filedir, name);
    FILE *f = fopen(full, as_hex ? "w" : "wb");
    if (!f)
        return -1;
    unsigned char buf[65536];
    uint32_t x = seed ? seed : 0x1234567u;
    long written = 0;
    if (as_hex)
        fprintf(f, "# NCMP test data : %ld bytes (Hex, 64 bytes per line)\n", size);
    long line = 0;   /* bytes emitted on the current hex line */
    while (written < size) {
        size_t n = (size_t)((size - written) < (long)sizeof(buf) ? (size - written) : (long)sizeof(buf));
        for (size_t i = 0; i < n; i++) { x = x * 1103515245u + 12345u; buf[i] = (unsigned char)(x >> 24); }
        if (as_hex) {
            for (size_t i = 0; i < n; i++) {
                fprintf(f, "%02x", buf[i]);
                if (++line == 64) { fputc('\n', f); line = 0; }
            }
        } else if (fwrite(buf, 1, n, f) != n) {
            fclose(f); return -1;
        }
        written += (long)n;
    }
    if (as_hex && line != 0)
        fputc('\n', f);
    fclose(f);
    return 0;
}

/* Write @p data as a Hex text file (header + 64 bytes/line) into g_filedir. */
static int write_hex_file(const char *name, const unsigned char *data, long len)
{
    char full[2200];
    snprintf(full, sizeof(full), "%s/%s", g_filedir, name);
    FILE *f = fopen(full, "w");
    if (!f)
        return -1;
    fprintf(f, "# NCMP data : %ld bytes (Hex, 64 bytes per line)\n", len);
    for (long i = 0; i < len; i++) {
        fprintf(f, "%02x", data[i]);
        if ((i & 63) == 63) fputc('\n', f);
    }
    if (len == 0 || (len & 63) != 0) fputc('\n', f);
    fclose(f);
    return 0;
}

/* True if @p name looks like a Hex text file (.hex or .txt). */
static int name_is_hex(const char *name)
{
    size_t n = strlen(name);
    return (n > 4 && !strcasecmp(name + n - 4, ".hex")) ||
           (n > 4 && !strcasecmp(name + n - 4, ".txt"));
}

/* Read a whole test file into a malloc'd buffer (<= NCMP_WEB_MAX_FILE). */
static unsigned char *read_test_file(const char *name, long *out_len)
{
    char full[2200];
    snprintf(full, sizeof(full), "%s/%s", g_filedir, name);
    FILE *f = fopen(full, "rb");
    if (!f)
        return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0 || sz > NCMP_WEB_MAX_FILE) { fclose(f); return NULL; }
    unsigned char *buf = malloc((size_t)sz ? (size_t)sz : 1);
    if (!buf) { fclose(f); return NULL; }
    long rd = (long)fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (rd != sz) { free(buf); return NULL; }
    *out_len = sz;
    return buf;
}

/* Read a test file as raw DATA bytes: a .hex/.txt file is decoded from its Hex
 * text (comment lines starting with '#' and all whitespace are skipped); any
 * other file is returned as-is. Returns a malloc'd buffer; caller frees. */
static unsigned char *read_test_file_data(const char *name, long *out_len)
{
    long raw_len = 0;
    unsigned char *raw = read_test_file(name, &raw_len);
    if (!raw)
        return NULL;
    if (!name_is_hex(name)) {
        *out_len = raw_len;
        return raw;
    }
    /* Decode hex, skipping '#' comment lines and whitespace. */
    unsigned char *out = malloc((size_t)(raw_len / 2) + 1);
    if (!out) { free(raw); return NULL; }
    long n = 0;
    int hi = -1, in_comment = 0;
    for (long i = 0; i < raw_len; i++) {
        unsigned char c = raw[i];
        if (c == '\n') { in_comment = 0; continue; }
        if (in_comment) continue;
        if (c == '#') { in_comment = 1; continue; }
        if (c == ' ' || c == '\t' || c == '\r') continue;
        int v;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else { free(raw); free(out); return NULL; }   /* bad hex char */
        if (hi < 0) hi = v;
        else { out[n++] = (unsigned char)((hi << 4) | v); hi = -1; }
    }
    free(raw);
    if (hi >= 0) { free(out); return NULL; }           /* odd hex nibble count */
    *out_len = n;
    return out;
}

/* ------------------------------------------------------------------ */
/* Saved scenarios (server-side JSON files => permanent, shared)      */
/* ------------------------------------------------------------------ */

static void ensure_scendir(void) { mkdir(g_scendir, 0755); }

/* Write the raw scenario JSON body to <scendir>/<name>.json. */
static int scenario_save(const char *name, const char *json, size_t len)
{
    ensure_scendir();
    char full[2200];
    snprintf(full, sizeof(full), "%s/%s.json", g_scendir, name);
    FILE *f = fopen(full, "wb");
    if (!f)
        return -1;
    size_t w = fwrite(json, 1, len, f);
    fclose(f);
    return w == len ? 0 : -1;
}

/* Read <scendir>/<name>.json into out (NUL-terminated). Returns length or -1. */
static int scenario_read(const char *name, char *out, int cap)
{
    char full[2200];
    snprintf(full, sizeof(full), "%s/%s.json", g_scendir, name);
    FILE *f = fopen(full, "rb");
    if (!f)
        return -1;
    int n = (int)fread(out, 1, (size_t)cap - 1, f);
    fclose(f);
    if (n < 0) return -1;
    out[n] = '\0';
    return n;
}

static int scenario_delete(const char *name)
{
    char full[2200];
    snprintf(full, sizeof(full), "%s/%s.json", g_scendir, name);
    return unlink(full) == 0 ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* Raw CI (Command Interface) send/receive                            */
/* ------------------------------------------------------------------ */

#define CI_BUF (256 * 1024)   /* room for req+rsp hex + parsed fields */

/* Ensure the dedicated raw-CI client is connected to the daemon socket.
 * Caller holds g_ci_lock. Returns 1 if connected. */
static int ci_ensure(void)
{
    if (g_ci_ok)
        return 1;
    if (ncmp_client_init(&g_ci_cli, g_sock_path[0] ? g_sock_path : NULL) == NCMP_OK)
        g_ci_ok = 1;
    return g_ci_ok;
}

/* Decode a hex string (spaces/colons ignored) into bytes. Returns length or -1. */
static int ci_hex2bytes(const char *s, uint8_t *out, int cap)
{
    int n = 0, hi = -1;
    for (; *s; s++) {
        int v;
        if (*s == ' ' || *s == ':' || *s == '\t' || *s == '\n' || *s == '\r') continue;
        if (*s >= '0' && *s <= '9') v = *s - '0';
        else if (*s >= 'a' && *s <= 'f') v = *s - 'a' + 10;
        else if (*s >= 'A' && *s <= 'F') v = *s - 'A' + 10;
        else return -1;
        if (hi < 0) hi = v;
        else { if (n >= cap) return -1; out[n++] = (uint8_t)((hi << 4) | v); hi = -1; }
    }
    return hi < 0 ? n : -1;   /* odd number of nibbles => error */
}

/* Emit a frame object: raw hex + parsed header/params. Returns new offset. */
static int ci_emit_frame(char *buf, int cap, int o, const char *key,
                         const uint8_t *raw, size_t rawlen, const NCMP_Message *m)
{
    o += snprintf(buf + o, cap - o, "\"%s\":{\"hex\":\"", key);
    for (size_t i = 0; i < rawlen && o < cap - 4; i++)
        o += snprintf(buf + o, cap - o, "%02x", raw[i]);
    /* payload_len = param-length array (32B) + sum of parameter bytes. */
    uint32_t paylen = 4u * NCMP_MAX_PARAM_COUNT;
    for (int i = 0; i < NCMP_MAX_PARAM_COUNT; i++) paylen += m->param_len[i];
    o += snprintf(buf + o, cap - o,
        "\",\"frameLen\":%zu,\"sessionId\":%u,\"sequenceId\":%u,\"commandId\":%u,"
        "\"ack\":%u,\"payloadLen\":%u,\"params\":[",
        rawlen >= 4 ? rawlen - 4 : 0, m->header.session_id, m->header.sequence_id,
        m->header.command_id, m->header.ack, paylen);
    size_t off = 0;
    int first = 1;
    for (int i = 0; i < NCMP_MAX_PARAM_COUNT; i++) {
        uint32_t pl = m->param_len[i];
        if (pl == 0) continue;
        if (o < cap - 80) {
            o += snprintf(buf + o, cap - o, "%s{\"idx\":%d,\"len\":%u,\"hex\":\"",
                          first ? "" : ",", i, pl);
            for (uint32_t k = 0; k < pl && off + k < m->payload_cap && o < cap - 4; k++)
                o += snprintf(buf + o, cap - o, "%02x", m->payload[off + k]);
            o += snprintf(buf + o, cap - o, "\"}");
            first = 0;
        }
        off += pl;
    }
    o += snprintf(buf + o, cap - o, "]}");
    return o;
}

/* POST /api/ci : send one raw CI to the token and return request + response as
 * raw hex AND parsed fields. Uses the dedicated g_ci_cli (own lock), so it does
 * NOT take g_api_lock and never blocks status/SHM polling. */
static void handle_ci(int fd, const char *body)
{
    long slot = 0, command = 0, session = 0;
    json_long(body, "slot", &slot);
    json_long(body, "command", &command);
    json_long(body, "session", &session);

    uint8_t *payload = malloc(NCMP_MAX_PAYLOAD_SIZE);
    uint8_t *rpayload = malloc(NCMP_MAX_PAYLOAD_SIZE);
    uint8_t *reqframe = malloc(NCMP_MAX_FRAME_SIZE);
    uint8_t *rspframe = malloc(NCMP_MAX_FRAME_SIZE);
    char *out = malloc(CI_BUF);
    if (!payload || !rpayload || !reqframe || !rspframe || !out) {
        free(payload); free(rpayload); free(reqframe); free(rspframe); free(out);
        send_json(fd, 500, "{\"ok\":false,\"error\":\"oom\"}");
        return;
    }

    uint32_t plen[NCMP_MAX_PARAM_COUNT] = {0};
    size_t poff = 0;
    int bad = 0;
    for (int i = 0; i < NCMP_MAX_PARAM_COUNT; i++) {
        char key[4]; snprintf(key, sizeof(key), "p%d", i);
        char hv[8192];
        if (json_str(body, key, hv, sizeof(hv)) && hv[0]) {
            int n = ci_hex2bytes(hv, payload + poff, (int)(NCMP_MAX_PAYLOAD_SIZE - poff));
            if (n < 0) { bad = 1; break; }
            plen[i] = (uint32_t)n; poff += (size_t)n;
        }
    }
    if (bad) {
        free(payload); free(rpayload); free(reqframe); free(rspframe); free(out);
        send_json(fd, 200, "{\"ok\":false,\"error\":\"bad hex parameter\"}");
        return;
    }

    pthread_mutex_lock(&g_ci_lock);
    if (!ci_ensure()) {
        pthread_mutex_unlock(&g_ci_lock);
        free(payload); free(rpayload); free(reqframe); free(rspframe); free(out);
        send_json(fd, 200, "{\"ok\":false,\"error\":\"ncmpd not connected (데몬 시작 후 재시도)\"}");
        return;
    }
    uint32_t mask = g_ci_cli.slot_mask;
    if (slot < 0 || !NCMP_SLOT_IN_MASK(mask, (uint32_t)slot)) {
        pthread_mutex_unlock(&g_ci_lock);
        free(payload); free(rpayload); free(reqframe); free(rspframe); free(out);
        send_json(fd, 200, "{\"ok\":false,\"error\":\"slot not online\"}");
        return;
    }

    NCMP_Message req; memset(&req, 0, sizeof(req));
    req.header.session_id = (uint32_t)session;
    req.header.command_id = (uint32_t)command;
    req.header.sequence_id = __atomic_add_fetch(&g_ci_cli.seq, 1, __ATOMIC_RELAXED);
    for (int i = 0; i < NCMP_MAX_PARAM_COUNT; i++) req.param_len[i] = plen[i];
    req.payload = payload; req.payload_cap = poff;

    size_t reqlen = 0;
    ncmp_wire_encode(&req, reqframe, NCMP_MAX_FRAME_SIZE, &reqlen);

    NCMP_Message rsp; memset(&rsp, 0, sizeof(rsp));
    rsp.payload = rpayload; rsp.payload_cap = NCMP_MAX_PAYLOAD_SIZE;

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int rc = ncmp_client_exec(&g_ci_cli, (uint32_t)slot, &req, &rsp, WEB_CI_SPIN_BUDGET);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    pthread_mutex_unlock(&g_ci_lock);
    double ms = (t1.tv_sec - t0.tv_sec) * 1000.0 + (t1.tv_nsec - t0.tv_nsec) / 1e6;

    int o = snprintf(out, CI_BUF, "{\"ok\":%s,\"rc\":%d,\"elapsedMs\":%.1f,",
                     rc == NCMP_OK ? "true" : "false", rc, ms);
    o = ci_emit_frame(out, CI_BUF, o, "request", reqframe, reqlen, &req);
    o += snprintf(out + o, CI_BUF - o, ",");
    if (rc == NCMP_OK) {
        size_t rsplen = 0;
        ncmp_wire_encode(&rsp, rspframe, NCMP_MAX_FRAME_SIZE, &rsplen);
        o = ci_emit_frame(out, CI_BUF, o, "response", rspframe, rsplen, &rsp);
    } else {
        o += snprintf(out + o, CI_BUF - o, "\"response\":null");
    }
    snprintf(out + o, CI_BUF - o, "}");
    send_json(fd, 200, out);

    free(payload); free(rpayload); free(reqframe); free(rspframe); free(out);
}

/* ------------------------------------------------------------------ */
/* API routes (all under the API lock)                               */
/* ------------------------------------------------------------------ */

#define BUF (16 * 1024)

/* Append a JSON key:rawvalue pair into a growing buffer; returns new offset. */
static int route_api(int fd, const char *method, const char *path, const char *body)
{
    char extra[BUF];

    /* ---- status / daemon (no API lock needed for status) ---- */
    if (!strcmp(path, "/api/status") && !strcmp(method, "GET")) {
        int dr;
        pthread_mutex_lock(&g_daemon_lock);
        dr = daemon_running();
        pthread_mutex_unlock(&g_daemon_lock);
        if (!dr)
            dr = daemon_socket_ready();   /* also detect an externally-started ncmpd */
        snprintf(extra, sizeof(extra),
                 "\"daemonRunning\":%s,\"transport\":\"%s\",\"sockPath\":\"%s\","
                 "\"defaultModule\":\"%s\",\"ncmpd\":\"%s\",\"configPath\":\"%s\","
                 "\"host\":\"%s\",\"port\":%d,\"filedir\":\"%s\",\"authRequired\":%s",
                 dr ? "true" : "false", g_transport, g_sock_path, g_module, g_ncmpd,
                 g_config, g_host, g_port, g_filedir, g_token[0] ? "true" : "false");
        send_result(fd, 0, extra);
        return 0;
    }
    if (!strcmp(path, "/api/daemon/start") && !strcmp(method, "POST")) {
        char t[16] = "";
        json_str(body, "transport", t, sizeof(t));
        int rc = daemon_start(t[0] ? t : g_transport);
        snprintf(extra, sizeof(extra), "\"pid\":%d", (int)g_ncmpd_pid);
        if (rc != 0) { app_last_error(); send_result(fd, rc, "\"detail\":\"ncmpd 시작 실패: fork/exec 실패 또는 기존 ncmpd가 비정상(SHM 없음)이어서 회수 불가 - 수동으로 종료 후 재시도\""); }
        else send_result(fd, 0, extra);
        return 0;
    }
    if (!strcmp(path, "/api/daemon/stop") && !strcmp(method, "POST")) {
        daemon_stop();
        send_result(fd, 0, "");
        return 0;
    }

    /* ---- test files (no token access: outside the API lock) ---- */
    if (!strcmp(path, "/api/genfile") && !strcmp(method, "POST")) {
        long size = 0, seed = 0;
        char name[160] = "", fmt[8] = "";
        json_long(body, "size", &size);
        json_long(body, "seed", &seed);
        json_str(body, "name", name, sizeof(name));
        json_str(body, "format", fmt, sizeof(fmt));
        int as_hex = !strcmp(fmt, "hex");
        if (!name[0])
            snprintf(name, sizeof(name), "test_%ld.%s", size, as_hex ? "hex" : "bin");
        if (!safe_name(name)) { send_result(fd, -4, "\"detail\":\"bad name\""); return 0; }
        if (size < 0 || size > NCMP_WEB_MAX_FILE) {
            snprintf(extra, sizeof(extra), "\"detail\":\"size out of range (0..%ld)\"", NCMP_WEB_MAX_FILE);
            send_result(fd, -4, extra);
            return 0;
        }
        ensure_filedir();
        if (gen_test_file(name, size, (unsigned)seed, as_hex) != 0) {
            send_result(fd, -4, "\"detail\":\"write failed\"");
            return 0;
        }
        /* report a SHA-256 (software) of the DATA bytes as a reference tag */
        long flen = 0;
        unsigned char *buf = read_test_file_data(name, &flen);
        char sha[65] = "";
        if (buf) {
            unsigned char dg[32]; unsigned int dl = 0;
            if (sw_digest(0x250, buf, (size_t)flen, dg, &dl) > 0) hex_of(dg, (int)dl, sha);
            free(buf);
        }
        snprintf(extra, sizeof(extra),
                 "\"name\":\"%s\",\"size\":%ld,\"sha256\":\"%s\"", name, size, sha);
        send_result(fd, 0, extra);
        return 0;
    }
    if (!strcmp(path, "/api/files") && !strcmp(method, "GET")) {
        ensure_filedir();
        DIR *d = opendir(g_filedir);
        int o = snprintf(extra, sizeof(extra), "\"files\":[");
        int first = 1;
        if (d) {
            struct dirent *de;
            while ((de = readdir(d)) != NULL) {
                if (de->d_name[0] == '.') continue;
                char full[2200];
                snprintf(full, sizeof(full), "%s/%s", g_filedir, de->d_name);
                struct stat st;
                if (stat(full, &st) != 0 || !S_ISREG(st.st_mode)) continue;
                if (o < (int)sizeof(extra) - 200)
                    o += snprintf(extra + o, sizeof(extra) - o, "%s{\"name\":\"%s\",\"size\":%ld}",
                                  first ? "" : ",", de->d_name, (long)st.st_size);
                first = 0;
            }
            closedir(d);
        }
        snprintf(extra + o, sizeof(extra) - o, "],\"dir\":\"%s\"", g_filedir);
        send_result(fd, 0, extra);
        return 0;
    }

    /* ---- saved scenarios (server-side JSON, permanent) ---- */
    if (!strcmp(path, "/api/scenarios") && !strcmp(method, "GET")) {
        ensure_scendir();
        DIR *d = opendir(g_scendir);
        int o = snprintf(extra, sizeof(extra), "\"scenarios\":[");
        int first = 1;
        if (d) {
            struct dirent *de;
            while ((de = readdir(d)) != NULL) {
                size_t nl = strlen(de->d_name);
                if (de->d_name[0] == '.' || nl < 6 ||
                    strcmp(de->d_name + nl - 5, ".json") != 0)
                    continue;
                if (o < (int)sizeof(extra) - 160) {
                    o += snprintf(extra + o, sizeof(extra) - o, "%s\"", first ? "" : ",");
                    /* name without ".json", escaping quotes/backslashes */
                    for (size_t i = 0; i < nl - 5 && o < (int)sizeof(extra) - 8; i++) {
                        char ch = de->d_name[i];
                        if (ch == '"' || ch == '\\') extra[o++] = '\\';
                        extra[o++] = ch;
                    }
                    extra[o] = '\0';
                    o += snprintf(extra + o, sizeof(extra) - o, "\"");
                }
                first = 0;
            }
            closedir(d);
        }
        snprintf(extra + o, sizeof(extra) - o, "],\"dir\":\"%s\"", g_scendir);
        send_result(fd, 0, extra);
        return 0;
    }
    if (!strcmp(path, "/api/scenario/get") && !strcmp(method, "POST")) {
        char name[160] = "";
        json_str(body, "name", name, sizeof(name));
        if (!safe_name(name)) { send_result(fd, -4, "\"detail\":\"bad name\""); return 0; }
        static char sbuf[64 * 1024];
        int n = scenario_read(name, sbuf, sizeof(sbuf));
        if (n < 0) { send_result(fd, -4, "\"detail\":\"not found\""); return 0; }
        /* The scenario JSON can exceed the small extra[] buffer, so build and
         * send the response directly. */
        char *resp = malloc((size_t)n + 128);
        if (!resp) { send_result(fd, -4, "\"detail\":\"oom\""); return 0; }
        int m = snprintf(resp, (size_t)n + 128,
                         "{\"rc\":0,\"ok\":true,\"error\":\"\",\"scenario\":%s}", sbuf);
        send_json(fd, 200, resp);
        free(resp);
        (void)m;
        return 0;
    }
    if (!strcmp(path, "/api/scenario/save") && !strcmp(method, "POST")) {
        char name[160] = "";
        json_str(body, "name", name, sizeof(name));
        if (!safe_name(name)) { send_result(fd, -4, "\"detail\":\"bad name\""); return 0; }
        if (scenario_save(name, body, strlen(body)) != 0) {
            send_result(fd, -4, "\"detail\":\"write failed\"");
            return 0;
        }
        snprintf(extra, sizeof(extra), "\"name\":\"%s\"", name);
        send_result(fd, 0, extra);
        return 0;
    }
    if (!strcmp(path, "/api/scenario/delete") && !strcmp(method, "POST")) {
        char name[160] = "";
        json_str(body, "name", name, sizeof(name));
        if (!safe_name(name)) { send_result(fd, -4, "\"detail\":\"bad name\""); return 0; }
        scenario_delete(name);
        send_result(fd, 0, "");
        return 0;
    }

    /* ---- raw CI send/receive (own client + lock, not g_api_lock) ---- */
    if (!strcmp(path, "/api/ci") && !strcmp(method, "POST")) {
        handle_ci(fd, body);
        return 0;
    }

    /* ---- ncmpd session map: (pid, app_sid) -> hsm_sid, read from SHM ---- */
    if (!strcmp(path, "/api/sessmap") && !strcmp(method, "POST")) {
        long slot = 0;
        char *out = malloc(8192);
        if (!out) { send_json(fd, 500, "{\"ok\":false,\"error\":\"oom\"}"); return 0; }
        json_long(body, "slot", &slot);
        pthread_mutex_lock(&g_ci_lock);
        if (!ci_ensure()) {
            pthread_mutex_unlock(&g_ci_lock);
            free(out);
            send_json(fd, 200, "{\"ok\":false,\"error\":\"ncmpd not connected\"}");
            return 0;
        }
        NCMP_Slot *sl = (slot >= 0) ? ncmp_shm_slot(g_ci_cli.shm_base, (uint32_t)slot) : NULL;
        int o = snprintf(out, 8192, "{\"ok\":true,\"slot\":%ld,\"entries\":[", slot);
        int first = 1;
        if (sl) {
            for (int i = 0; i < PKCS11_MAX_SESSION_PER_SLOT; ++i) {
                NCMP_SessMap *m = &sl->sess_map[i];
                if (!m->in_use) continue;
                o += snprintf(out + o, 8192 - o,
                              "%s{\"pid\":%u,\"appSid\":%u,\"hsmSid\":%u}",
                              first ? "" : ",", m->pid, m->app_sid, m->hsm_sid);
                first = 0;
            }
        }
        pthread_mutex_unlock(&g_ci_lock);
        snprintf(out + o, 8192 - o, "]}");
        send_json(fd, 200, out);
        free(out);
        return 0;
    }

    /* ---- everything below drives the token: serialise ---- */
    pthread_mutex_lock(&g_api_lock);
    int rc = -4;        /* APP_ERR_ARGS by default */
    extra[0] = '\0';

    if (!strcmp(path, "/api/load") && !strcmp(method, "POST")) {
        char mod[1024] = "";
        if (!json_str(body, "module", mod, sizeof(mod)) || !mod[0])
            snprintf(mod, sizeof(mod), "%s", g_module);
        rc = app_load(mod);
    } else if (!strcmp(path, "/api/initialize") && !strcmp(method, "POST")) {
        rc = app_initialize();
    } else if (!strcmp(path, "/api/finalize") && !strcmp(method, "POST")) {
        rc = app_finalize();
    } else if (!strcmp(path, "/api/unload") && !strcmp(method, "POST")) {
        rc = app_unload();
    } else if (!strcmp(path, "/api/dlsym") && !strcmp(method, "GET")) {
        char js[4096];      /* 70 entries ~ 1.7 KB; fits with margin in extra[] */
        rc = app_dlsym_report(js, sizeof(js));
        if (rc == 0) snprintf(extra, sizeof(extra), "\"report\":%s", js);
    } else if (!strcmp(path, "/api/library") && !strcmp(method, "GET")) {
        char js[2048];
        rc = app_library_info(js, sizeof(js));
        if (rc == 0) snprintf(extra, sizeof(extra), "\"info\":%s", js);
    } else if (!strcmp(path, "/api/slots") && !strcmp(method, "GET")) {
        unsigned long ids[512];
        int n = 0;
        rc = app_get_slots(ids, 512, &n);
        if (rc == 0) {
            int o = snprintf(extra, sizeof(extra), "\"slots\":[");
            for (int i = 0; i < n; i++)
                o += snprintf(extra + o, sizeof(extra) - o, "%s%lu", i ? "," : "", ids[i]);
            o += snprintf(extra + o, sizeof(extra) - o, "],\"slotTypes\":{");
            /* Per-slot HSM type from SHM (0=NCMP, 1=PEM): lets the UI switch the
             * right panel to the PEM CI console for PEM slots. */
            pthread_mutex_lock(&g_ci_lock);
            if (ci_ensure()) {
                for (int i = 0; i < n; i++) {
                    NCMP_Slot *sl = ncmp_shm_slot(g_ci_cli.shm_base, (uint32_t)ids[i]);
                    o += snprintf(extra + o, sizeof(extra) - o, "%s\"%lu\":%u",
                                  i ? "," : "", ids[i], sl ? sl->hsm_type : 0u);
                }
            }
            pthread_mutex_unlock(&g_ci_lock);
            snprintf(extra + o, sizeof(extra) - o, "}");
        }
    } else if (!strcmp(path, "/api/token") && !strcmp(method, "POST")) {
        long slot = 0;
        char js[4096];
        if (json_long(body, "slot", &slot)) {
            rc = app_token_info((unsigned long)slot, js, sizeof(js));
            if (rc == 0) snprintf(extra, sizeof(extra), "\"token\":%s", js);
        }
    } else if (!strcmp(path, "/api/mechanisms") && !strcmp(method, "POST")) {
        long slot = 0;
        char js[8192];
        if (json_long(body, "slot", &slot)) {
            rc = app_mechanism_list((unsigned long)slot, js, sizeof(js));
            if (rc == 0) snprintf(extra, sizeof(extra), "\"mechanisms\":%s", js);
        }
    } else if (!strcmp(path, "/api/session/open") && !strcmp(method, "POST")) {
        long slot = 0, rw = 1;
        unsigned long h = 0;
        json_long(body, "slot", &slot);
        json_long(body, "rw", &rw);
        rc = app_open_session((unsigned long)slot, (int)rw, &h);
        if (rc == 0) snprintf(extra, sizeof(extra), "\"session\":%lu", h);
    } else if (!strcmp(path, "/api/session/adopt") && !strcmp(method, "POST")) {
        /* Open a session with a caller-supplied wire session_id (no token
         * OPEN_SESSION); lets the UI drive a specific id, incl. 0. */
        long slot = 0, sid = 0;
        unsigned long h = 0;
        json_long(body, "slot", &slot);
        json_long(body, "session", &sid);
        rc = app_session_adopt((unsigned long)slot, (unsigned long)sid, &h);
        if (rc == 0) snprintf(extra, sizeof(extra), "\"session\":%lu,\"wireSid\":%ld", h, sid);
    } else if (!strcmp(path, "/api/session/close") && !strcmp(method, "POST")) {
        long h = 0;
        if (json_long(body, "session", &h))
            rc = app_close_session((unsigned long)h);
    } else if (!strcmp(path, "/api/session/info") && !strcmp(method, "POST")) {
        long h = 0;
        char js[1024];
        if (json_long(body, "session", &h)) {
            rc = app_session_info((unsigned long)h, js, sizeof(js));
            if (rc == 0) snprintf(extra, sizeof(extra), "\"session\":%s", js);
        }
    } else if (!strcmp(path, "/api/login") && !strcmp(method, "POST")) {
        long h = 0, ut = 1;
        char pin[128] = "";
        json_long(body, "session", &h);
        json_long(body, "userType", &ut);
        json_str(body, "pin", pin, sizeof(pin));
        rc = app_login((unsigned long)h, (int)ut, pin);
    } else if (!strcmp(path, "/api/logout") && !strcmp(method, "POST")) {
        long h = 0;
        if (json_long(body, "session", &h))
            rc = app_logout((unsigned long)h);
    } else if (!strcmp(path, "/api/random") && !strcmp(method, "POST")) {
        long h = 0, n = 16;
        json_long(body, "session", &h);
        json_long(body, "length", &n);
        if (n < 1) n = 1;
        if (n > 1024) n = 1024;
        unsigned char *rb = malloc((size_t)n);
        if (rb) {
            rc = app_generate_random((unsigned long)h, rb, (int)n);
            if (rc == 0) {
                int o = snprintf(extra, sizeof(extra), "\"hex\":\"");
                for (long i = 0; i < n; i++)
                    o += snprintf(extra + o, sizeof(extra) - o, "%02x", rb[i]);
                snprintf(extra + o, sizeof(extra) - o, "\",\"length\":%ld", n);
            }
            free(rb);
        } else rc = -4;
    } else if (!strcmp(path, "/api/digest") && !strcmp(method, "POST")) {
        long h = 0, mech = 0x250;    /* CKM_SHA256 */
        char in[4096] = "";
        json_long(body, "session", &h);
        json_long(body, "mech", &mech);
        json_str(body, "input", in, sizeof(in));
        unsigned char out[128];
        int outlen = 0;
        rc = app_digest((unsigned long)h, (unsigned long)mech,
                        (unsigned char *)in, (int)strlen(in), out, sizeof(out), &outlen);
        if (rc == 0) {
            int o = snprintf(extra, sizeof(extra), "\"hex\":\"");
            for (int i = 0; i < outlen; i++)
                o += snprintf(extra + o, sizeof(extra) - o, "%02x", out[i]);
            snprintf(extra + o, sizeof(extra) - o, "\",\"length\":%d", outlen);
        }
    } else if (!strcmp(path, "/api/gcm-selftest") && !strcmp(method, "POST")) {
        long h = 0;
        char detail[256];
        json_long(body, "session", &h);
        rc = app_aes_gcm_selftest((unsigned long)h, detail, sizeof(detail));
        /* escape detail quickly (no quotes expected) */
        snprintf(extra, sizeof(extra), "\"detail\":\"%s\"", detail);
    } else if (!strcmp(path, "/api/encrypt") && !strcmp(method, "POST")) {
        /* AES-GCM / AES-CTR one-shot via PKCS#11 (C_CreateObject + C_Encrypt/
         * C_Decrypt) with a caller-supplied key. algo="gcm"|"ctr";
         * encrypt=1 encrypt, 0 decrypt. key/iv/counter/aad/data are hex. */
        long h = 0, enc = 1, tagb = 16;
        char algo[8] = "gcm";
        char *keyh = malloc(4096), *ivh = malloc(4096), *aadh = malloc(9000),
             *datah = malloc(9000);
        uint8_t *key = malloc(64), *iv = malloc(64), *aad = malloc(4096),
                *din = malloc(4096), *dout = malloc(4096 + 64);
        if (!keyh || !ivh || !aadh || !datah || !key || !iv || !aad || !din || !dout) {
            free(keyh); free(ivh); free(aadh); free(datah);
            free(key); free(iv); free(aad); free(din); free(dout);
            rc = -4;
        } else {
            keyh[0] = ivh[0] = aadh[0] = datah[0] = '\0';
            json_long(body, "session", &h);
            json_long(body, "encrypt", &enc);
            json_long(body, "tagBytes", &tagb);
            json_str(body, "algo", algo, sizeof(algo));
            json_str(body, "key", keyh, 4096);
            json_str(body, "iv", ivh, 4096);         /* GCM IV or CTR counter */
            json_str(body, "aad", aadh, 9000);
            json_str(body, "data", datah, 9000);
            int kl = ci_hex2bytes(keyh, key, 64);
            int il = ci_hex2bytes(ivh, iv, 64);
            int al = aadh[0] ? ci_hex2bytes(aadh, aad, 4096) : 0;
            int dl = datah[0] ? ci_hex2bytes(datah, din, 4096) : 0;
            if (kl < 0 || il < 0 || al < 0 || dl < 0) {
                app_set_last_error("bad hex in key/iv/aad/data");
                rc = APP_ERR_ARGS;
            } else {
                unsigned long olen = 4096 + 64;
                if (!strcmp(algo, "ctr")) {
                    if (il != 16) { app_set_last_error("AES-CTR counter must be 16 bytes"); rc = APP_ERR_ARGS; }
                    else rc = app_aes_ctr((unsigned long)h, (int)enc, key, (unsigned long)kl,
                                          iv, din, (unsigned long)dl, dout, &olen);
                } else {
                    rc = app_aes_gcm((unsigned long)h, (int)enc, key, (unsigned long)kl,
                                     iv, (unsigned long)il, aad, (unsigned long)al,
                                     (unsigned long)tagb, din, (unsigned long)dl, dout, &olen);
                }
                if (rc == 0) {
                    int o = snprintf(extra, sizeof(extra), "\"hex\":\"");
                    for (unsigned long i = 0; i < olen && o < BUF - 4; i++)
                        o += snprintf(extra + o, sizeof(extra) - o, "%02x", dout[i]);
                    snprintf(extra + o, sizeof(extra) - o, "\",\"length\":%lu", olen);
                }
            }
            free(keyh); free(ivh); free(aadh); free(datah);
            free(key); free(iv); free(aad); free(din); free(dout);
        }
    } else if (!strcmp(path, "/api/encrypt-file") && !strcmp(method, "POST")) {
        /* AES-GCM multipart (streaming) over a test file: read the input file's
         * DATA bytes, run C_EncryptInit+Update×N+Final (or Decrypt*), and spill
         * the result to a Hex text file (results are too large to inline). */
        long h = 0, enc = 1, tagb = 16, chunk = 0;
        char name[160] = "", outn[160] = "", keyh[160] = "", ivh[80] = "", aadh[600] = "";
        json_long(body, "session", &h);
        json_long(body, "encrypt", &enc);
        json_long(body, "tagBytes", &tagb);
        json_long(body, "chunk", &chunk);
        json_str(body, "name", name, sizeof(name));
        json_str(body, "outName", outn, sizeof(outn));
        json_str(body, "key", keyh, sizeof(keyh));
        json_str(body, "iv", ivh, sizeof(ivh));
        json_str(body, "aad", aadh, sizeof(aadh));
        uint8_t key[64], iv[64], aad[256];
        int kl = ci_hex2bytes(keyh, key, sizeof(key));
        int il = ci_hex2bytes(ivh, iv, sizeof(iv));
        int al = aadh[0] ? ci_hex2bytes(aadh, aad, sizeof(aad)) : 0;
        long flen = 0;
        unsigned char *in = safe_name(name) ? read_test_file_data(name, &flen) : NULL;
        if (!in) { rc = -4; snprintf(extra, sizeof(extra), "\"detail\":\"input file read/hex-decode failed\""); }
        else if (kl < 0 || il < 0 || al < 0) { rc = APP_ERR_ARGS; free(in); app_set_last_error("bad hex in key/iv/aad"); }
        else {
            unsigned long ocap = (unsigned long)flen + 64, olen = ocap;
            unsigned char *outbuf = malloc(ocap ? ocap : 1);
            if (!outbuf) { rc = -4; free(in); }
            else {
                rc = app_aes_gcm_multipart((unsigned long)h, (int)enc, key, (unsigned long)kl,
                                           iv, (unsigned long)il, aad, (unsigned long)al,
                                           (unsigned long)tagb, in, (unsigned long)flen,
                                           chunk, outbuf, &olen);
                if (rc == 0) {
                    if (!outn[0])
                        snprintf(outn, sizeof(outn), "%s_%s.hex", name, enc ? "ct" : "pt");
                    if (!safe_name(outn) || write_hex_file(outn, outbuf, (long)olen) != 0) {
                        rc = -4; snprintf(extra, sizeof(extra), "\"detail\":\"output write failed\"");
                    } else {
                        unsigned char dg[32]; unsigned int dl = 0; char sha[65] = "";
                        if (sw_digest(0x250, outbuf, (size_t)olen, dg, &dl) > 0) hex_of(dg, (int)dl, sha);
                        long updates = flen > 0 ? (flen + (chunk > 0 ? chunk : 32768) - 1) / (chunk > 0 ? chunk : 32768) : 0;
                        snprintf(extra, sizeof(extra),
                                 "\"outName\":\"%s\",\"inBytes\":%ld,\"outBytes\":%lu,\"updates\":%ld,\"sha256\":\"%s\"",
                                 outn, flen, olen, updates, sha);
                    }
                }
                free(outbuf); free(in);
            }
        }
    } else if (!strcmp(path, "/api/digest-file") && !strcmp(method, "POST")) {
        /* Multipart (init/update/final) digest of a test file on the token. */
        long h = 0, mech = 0x250, chunk = 0;
        char name[160] = "";
        json_long(body, "session", &h);
        json_long(body, "mech", &mech);
        json_long(body, "chunk", &chunk);
        json_str(body, "name", name, sizeof(name));
        if (chunk <= 0) chunk = 3968;
        if (chunk > 3968) chunk = 3968;   /* token per-update digest data limit */
        long flen = 0;
        unsigned char *buf = safe_name(name) ? read_test_file_data(name, &flen) : NULL;
        if (!buf) { rc = -4; snprintf(extra, sizeof(extra), "\"detail\":\"file read/hex-decode failed\""); }
        else {
            unsigned char out[128]; int olen = 0;
            rc = app_digest_multipart((unsigned long)h, (unsigned long)mech, buf, flen, (int)chunk, out, sizeof(out), &olen);
            if (rc == 0) {
                char hex[260]; hex_of(out, olen, hex);
                long updates = flen > 0 ? (flen + chunk - 1) / chunk : 0;
                snprintf(extra, sizeof(extra),
                         "\"hex\":\"%s\",\"length\":%d,\"bytes\":%ld,\"chunk\":%ld,\"updates\":%ld",
                         hex, olen, flen, chunk, updates);
            }
            free(buf);
        }
    } else if (!strcmp(path, "/api/digest-compare") && !strcmp(method, "POST")) {
        /* Token multipart digest vs. software (OpenSSL) digest of the same file. */
        long h = 0, mech = 0x250;
        char name[160] = "";
        json_long(body, "session", &h);
        json_long(body, "mech", &mech);
        json_str(body, "name", name, sizeof(name));
        long flen = 0;
        unsigned char *buf = safe_name(name) ? read_test_file_data(name, &flen) : NULL;
        if (!buf) { rc = -4; snprintf(extra, sizeof(extra), "\"detail\":\"file read/hex-decode failed\""); }
        else if (!md_of(mech)) { rc = -4; snprintf(extra, sizeof(extra), "\"detail\":\"mechanism has no SW reference\""); free(buf); }
        else {
            unsigned char tok[128]; int tlen = 0;
            unsigned char sw[64]; unsigned int slen = 0;
            rc = app_digest_multipart((unsigned long)h, (unsigned long)mech, buf, flen, 0, tok, sizeof(tok), &tlen);
            int sr = sw_digest(mech, buf, (size_t)flen, sw, &slen);
            free(buf);
            char thex[260] = "", shex[260] = "";
            if (rc == 0) hex_of(tok, tlen, thex);
            if (sr > 0) hex_of(sw, (int)slen, shex);
            int match = (rc == 0 && sr > 0 && tlen == (int)slen && memcmp(tok, sw, (size_t)slen) == 0);
            snprintf(extra, sizeof(extra),
                     "\"bytes\":%ld,\"tokenHex\":\"%s\",\"swHex\":\"%s\",\"match\":%s",
                     flen, thex, shex, match ? "true" : "false");
            /* rc reflects the token call; the comparison verdict is in "match". */
        }
    } else {
        pthread_mutex_unlock(&g_api_lock);
        send_json(fd, 404, "{\"error\":\"no such api\"}");
        return 0;
    }

    send_result(fd, rc, extra);
    pthread_mutex_unlock(&g_api_lock);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Request read + dispatch                                           */
/* ------------------------------------------------------------------ */

static int header_has_bearer(const char *headers)
{
    if (!g_token[0])
        return 1;      /* auth disabled */
    const char *a = strcasestr(headers, "authorization:");
    if (!a)
        return 0;
    const char *b = strcasestr(a, "bearer ");
    if (!b)
        return 0;
    b += 7;
    size_t tl = strlen(g_token);
    return strncmp(b, g_token, tl) == 0 &&
           (b[tl] == '\r' || b[tl] == '\n' || b[tl] == '\0' || b[tl] == ' ');
}

static void *handle_client(void *arg)
{
    int fd = (int)(intptr_t)arg;
    char *req = malloc(1 << 20);        /* 1 MiB cap */
    if (!req) { close(fd); return NULL; }
    size_t len = 0, cap = 1 << 20;
    size_t header_end = 0;

    /* Read until headers complete. */
    while (len + 1 < cap) {
        ssize_t n = read(fd, req + len, cap - len - 1);
        if (n <= 0)
            break;
        len += (size_t)n;
        req[len] = '\0';
        char *he = strstr(req, "\r\n\r\n");
        if (he) { header_end = (size_t)(he - req) + 4; break; }
    }
    if (header_end == 0) { free(req); close(fd); return NULL; }

    /* Parse request line. */
    char method[8] = "", path[1024] = "";
    sscanf(req, "%7s %1023s", method, path);

    /* Strip query string. */
    char *q = strchr(path, '?');
    if (q) *q = '\0';

    /* CORS preflight. */
    if (!strcmp(method, "OPTIONS")) {
        send_raw(fd, 204, "No Content", "text/plain", "", 0);
        free(req); close(fd); return NULL;
    }

    /* For API paths read the full body per Content-Length. */
    const char *body = req + header_end;
    if (!strncmp(path, "/api/", 5)) {
        if (!header_has_bearer(req)) {
            send_json(fd, 401, "{\"error\":\"unauthorized (set Authorization: Bearer <NCMP_WEB_TOKEN>)\"}");
            free(req); close(fd); return NULL;
        }
        const char *cl = strcasestr(req, "content-length:");
        long want = 0;
        if (cl) want = strtol(cl + 15, NULL, 10);
        while ((long)(len - header_end) < want && len + 1 < cap) {
            ssize_t n = read(fd, req + len, cap - len - 1);
            if (n <= 0) break;
            len += (size_t)n;
            req[len] = '\0';
        }
        route_api(fd, method, path, body);
    } else if (!strcmp(method, "GET") && !strncmp(path, "/files/", 7)) {
        serve_test_file(fd, path + 7);
    } else if (!strcmp(method, "GET")) {
        serve_static(fd, path);
    } else {
        send_json(fd, 404, "{\"error\":\"not found\"}");
    }

    free(req);
    close(fd);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* main                                                              */
/* ------------------------------------------------------------------ */

static void usage(const char *p)
{
    fprintf(stderr,
      "usage: %s [--config PATH] [--host H] [--port N] [--webroot DIR]\n"
      "          [--module PATH] [--ncmpd PATH] [--transport real|mock|socket]\n"
      "          [--sock PATH] [--filedir DIR] [--scendir DIR]\n"
      "config: --config, else $NCMP_WEB_CONFIG, else ./.config/config\n"
      "        (key = value; keys: host port webroot module ncmpd transport\n"
      "         sock filedir scendir token). Precedence: defaults < file < env < CLI.\n"
      "env: NCMP_WEB_HOST NCMP_WEB_PORT NCMP_WEB_ROOT NCMP_WEB_TOKEN\n"
      "     NCMP_PKCS11_MODULE NCMP_SOCK_PATH NCMP_WEB_FILEDIR NCMP_WEB_SCENDIR\n"
      "     NCMP_WEB_CONFIG\n", p);
}

int main(int argc, char **argv)
{
    /* Precedence (low -> high): built-in defaults < config file < env < CLI.
     * 1) config file: --config, else $NCMP_WEB_CONFIG, else ./.config/config. */
    char cfgpath[1024] = "";
    for (int i = 1; i < argc - 1; i++)
        if (!strcmp(argv[i], "--config")) snprintf(cfgpath, sizeof(cfgpath), "%s", argv[i + 1]);
    if (!cfgpath[0]) {
        const char *c = getenv("NCMP_WEB_CONFIG");
        if (c && *c) snprintf(cfgpath, sizeof(cfgpath), "%s", c);
    }
    if (!cfgpath[0])
        snprintf(cfgpath, sizeof(cfgpath), ".config/config");
    load_config(cfgpath);   /* -1 (absent) is fine */

    /* 2) environment overrides the config file. */
    const char *e;
    if ((e = getenv("NCMP_WEB_HOST"))) snprintf(g_host, sizeof(g_host), "%s", e);
    if ((e = getenv("NCMP_WEB_PORT"))) g_port = atoi(e);
    if ((e = getenv("NCMP_WEB_ROOT"))) snprintf(g_webroot, sizeof(g_webroot), "%s", e);
    if ((e = getenv("NCMP_PKCS11_MODULE"))) snprintf(g_module, sizeof(g_module), "%s", e);
    if ((e = getenv("NCMP_WEB_TOKEN"))) snprintf(g_token, sizeof(g_token), "%s", e);
    if ((e = getenv("NCMP_SOCK_PATH"))) snprintf(g_sock_path, sizeof(g_sock_path), "%s", e);
    if ((e = getenv("NCMP_WEB_FILEDIR"))) snprintf(g_filedir, sizeof(g_filedir), "%s", e);
    if ((e = getenv("NCMP_WEB_SCENDIR"))) snprintf(g_scendir, sizeof(g_scendir), "%s", e);

    /* 3) CLI arguments override everything. */
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--config") && i + 1 < argc) { ++i; continue; } /* handled above */
        if (!strcmp(argv[i], "--host") && i + 1 < argc) snprintf(g_host, sizeof(g_host), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--port") && i + 1 < argc) g_port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--webroot") && i + 1 < argc) snprintf(g_webroot, sizeof(g_webroot), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--module") && i + 1 < argc) snprintf(g_module, sizeof(g_module), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--ncmpd") && i + 1 < argc) snprintf(g_ncmpd, sizeof(g_ncmpd), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--transport") && i + 1 < argc) snprintf(g_transport, sizeof(g_transport), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--sock") && i + 1 < argc) snprintf(g_sock_path, sizeof(g_sock_path), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--filedir") && i + 1 < argc) snprintf(g_filedir, sizeof(g_filedir), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--scendir") && i + 1 < argc) snprintf(g_scendir, sizeof(g_scendir), "%s", argv[++i]);
        else { usage(argv[0]); return 2; }
    }
    if (!g_sock_path[0]) {
        /* Stable, well-known user-space path (not per-pid) so the facade, a
         * separately-launched Debug App (ncmp_dbg) and any other client all
         * rendezvous on this ncmpd without passing --sock. A second ncmp_web
         * reuses an ncmpd already listening here (see daemon_start). Set an
         * explicit --sock/NCMP_SOCK_PATH to run isolated instances. */
        snprintf(g_sock_path, sizeof(g_sock_path), "/tmp/ncmpd.sock");
    }
    /* The facade (loaded in-process) must see the same socket path. */
    setenv("NCMP_SOCK_PATH", g_sock_path, 1);
    ensure_filedir();
    ensure_scendir();

    /* Install SIGINT/SIGTERM WITHOUT SA_RESTART so a signal interrupts the
     * blocking accept() (EINTR) and the loop can observe g_running == 0.
     * SIGCHLD is left at its default so waitpid()/WNOHANG works for ncmpd. */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;        /* sa_flags = 0: no SA_RESTART */
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)g_port);
    if (inet_pton(AF_INET, g_host, &addr.sin_addr) != 1)
        addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind"); return 1;
    }
    if (listen(srv, 32) != 0) { perror("listen"); return 1; }

    fprintf(stderr,
        "ncmp_web: http://%s:%d  (config=%s, webroot=%s, module=%s, sock=%s,\n"
        "          filedir=%s, auth=%s)\n",
        g_host, g_port, g_config[0] ? g_config : "(none)", g_webroot,
        g_module[0] ? g_module : "(none)", g_sock_path, g_filedir,
        g_token[0] ? "bearer-token" : "OFF");

    while (g_running) {
        int c = accept(srv, NULL, NULL);
        if (c < 0) {
            if (errno == EINTR) continue;
            break;
        }
        pthread_t th;
        if (pthread_create(&th, NULL, handle_client, (void *)(intptr_t)c) == 0)
            pthread_detach(th);
        else
            close(c);
    }

    daemon_stop();
    close(srv);
    fprintf(stderr, "ncmp_web: stopped\n");
    return 0;
}

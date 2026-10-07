#define _POSIX_C_SOURCE 200809L
#include "ci_usb_lib.h"

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* USB backend selection (compile-time):
 *   - default: direct usbfs ioctl (USBDEVFS_BULK) on Linux, no libusb needed.
 *   - -DCI_USB_USE_LIBUSB: drive the device through libusb-1.0 instead.
 * Both implement the same bulk OUT -> (ZLP if max-packet multiple) -> IN
 * exchange behind CI_USB_CreateBackend(); the rest of the file is shared. */
#if defined(CI_USB_USE_LIBUSB)
#include <libusb-1.0/libusb.h>
#elif defined(__linux__)
#include <dirent.h>
#include <fcntl.h>
#include <linux/usbdevice_fs.h>
#include <sys/ioctl.h>
#include <unistd.h>
#endif

struct CI_USB {
    CI_USB_Backend exchange;
    CI_USB_SendFn send;             /* OUT-only (real backends); NULL otherwise */
    CI_USB_RecvFn recv;             /* IN-only  (real backends); NULL otherwise */
    CI_USB_BackendDestroy destroy;
    void *backend_context;
    CI_USB_TraceCallback trace;
    void *trace_context;
    pthread_mutex_t lock;
    int poisoned;
    char error[256];
};

static uint64_t monotonic_ns(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) return 0;
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}

const char *CI_USB_StrError(int status)
{
    switch (status) {
    case CI_USB_OK: return "success";
    case CI_USB_ERR_ARGUMENT: return "invalid USB argument";
    case CI_USB_ERR_IO: return "USB I/O failed (check access permissions and device state)";
    case CI_USB_ERR_NOT_FOUND: return "FX3 GPIF device 04b4:5054 not found";
    case CI_USB_ERR_MULTIPLE: return "multiple FX3 devices; select an exact device_path";
    case CI_USB_ERR_TIMEOUT: return "USB timeout; connection state is uncertain";
    case CI_USB_ERR_MEMORY: return "allocation failed";
    case CI_USB_ERR_SHORT: return "unexpected USB transfer length";
    case CI_USB_ERR_STATE: return "connection stopped after uncertain transfer; recover board state before reconnecting";
    case CI_USB_ERR_UNSUPPORTED: return "unsupported USB backend or target";
    default: return "USB backend failed";
    }
}

void CI_USB_DefaultOptions(CI_USB_Options *options)
{
    if (options != NULL) {
        options->vendor_id = 0x04b4u;
        options->product_id = 0x5054u;
        options->timeout_ms = 10000u;
        options->device_path = NULL;
    }
}

int CI_USB_CreateBackend(CI_USB_Backend exchange, void *context,
                         CI_USB_BackendDestroy destroy, CI_USB **connection)
{
    CI_USB *usb;
    if (connection == NULL || exchange == NULL) return CI_USB_ERR_ARGUMENT;
    *connection = NULL;
    usb = calloc(1, sizeof(*usb));
    if (usb == NULL) return CI_USB_ERR_MEMORY;
    if (pthread_mutex_init(&usb->lock, NULL) != 0) {
        free(usb);
        return CI_USB_ERR_IO;
    }
    usb->exchange = exchange;
    usb->destroy = destroy;
    usb->backend_context = context;
    *connection = usb;
    return CI_USB_OK;
}

void CI_USB_SetTrace(CI_USB *connection, CI_USB_TraceCallback callback,
                     void *context)
{
    if (connection == NULL) return;
    (void)pthread_mutex_lock(&connection->lock);
    connection->trace = callback;
    connection->trace_context = context;
    (void)pthread_mutex_unlock(&connection->lock);
}

int CI_USB_Exchange(CI_USB *connection,
                    const uint8_t *request, size_t request_len,
                    uint8_t *response, size_t expected_response_len,
                    size_t *response_len, CI_USB_Timing *timing)
{
    CI_USB_Trace event;
    int result;
    if (connection == NULL || request == NULL || response == NULL ||
        response_len == NULL || request_len < 16u || request_len > 65504u ||
        expected_response_len < 16u || expected_response_len > 65520u ||
        request_len % 4u != 0u || expected_response_len % 4u != 0u)
        return CI_USB_ERR_ARGUMENT;
    *response_len = 0;
    if (timing != NULL) memset(timing, 0, sizeof(*timing));
    (void)pthread_mutex_lock(&connection->lock);
    if (connection->poisoned) {
        (void)pthread_mutex_unlock(&connection->lock);
        return CI_USB_ERR_STATE;
    }
    memset(&event, 0, sizeof(event));
    event.request = request;
    event.request_len = request_len;
    event.response = response;
    event.expected_response_len = expected_response_len;
    event.timing.out_start_ns = monotonic_ns();
    result = connection->exchange(connection->backend_context, request,
                                  request_len, response, expected_response_len,
                                  response_len, &event.timing);
    if (event.timing.in_end_ns == 0) event.timing.in_end_ns = monotonic_ns();
    if (*response_len > expected_response_len) {
        *response_len = 0;
        result = CI_USB_ERR_SHORT;
    }
    if (result == CI_USB_OK && (*response_len < 16u || *response_len % 4u != 0u))
        result = CI_USB_ERR_SHORT;
    if (result != CI_USB_OK) {
        connection->poisoned = 1;
        (void)snprintf(connection->error, sizeof(connection->error), "%s",
                       CI_USB_StrError(result));
    } else {
        connection->error[0] = '\0';
    }
    event.response_len = *response_len;
    event.status = result;
    if (timing != NULL) *timing = event.timing;
    if (connection->trace != NULL)
        connection->trace(connection->trace_context, &event);
    (void)pthread_mutex_unlock(&connection->lock);
    return result;
}

int CI_USB_Send(CI_USB *connection, const uint8_t *request, size_t request_len,
                CI_USB_Timing *timing)
{
    int result;
    if (connection == NULL || request == NULL || request_len < 16u ||
        request_len > 65504u || request_len % 4u != 0u)
        return CI_USB_ERR_ARGUMENT;
    if (timing != NULL) memset(timing, 0, sizeof(*timing));
    (void)pthread_mutex_lock(&connection->lock);
    if (connection->send == NULL) {
        (void)pthread_mutex_unlock(&connection->lock);
        return CI_USB_ERR_UNSUPPORTED;
    }
    if (connection->poisoned) {
        (void)pthread_mutex_unlock(&connection->lock);
        return CI_USB_ERR_STATE;
    }
    result = connection->send(connection->backend_context, request, request_len,
                              timing);
    if (result != CI_USB_OK) {
        connection->poisoned = 1;
        (void)snprintf(connection->error, sizeof(connection->error), "%s",
                       CI_USB_StrError(result));
    }
    (void)pthread_mutex_unlock(&connection->lock);
    return result;
}

int CI_USB_Recv(CI_USB *connection, uint8_t *response,
                size_t expected_response_len, size_t *response_len,
                CI_USB_Timing *timing)
{
    int result;
    if (connection == NULL || response == NULL || response_len == NULL ||
        expected_response_len < 16u || expected_response_len > 65520u ||
        expected_response_len % 4u != 0u)
        return CI_USB_ERR_ARGUMENT;
    *response_len = 0;
    if (timing != NULL) memset(timing, 0, sizeof(*timing));
    (void)pthread_mutex_lock(&connection->lock);
    if (connection->recv == NULL) {
        (void)pthread_mutex_unlock(&connection->lock);
        return CI_USB_ERR_UNSUPPORTED;
    }
    if (connection->poisoned) {
        (void)pthread_mutex_unlock(&connection->lock);
        return CI_USB_ERR_STATE;
    }
    result = connection->recv(connection->backend_context, response,
                              expected_response_len, response_len, timing);
    if (result == CI_USB_OK && (*response_len > expected_response_len ||
                                *response_len < 16u || *response_len % 4u != 0u)) {
        *response_len = 0;
        result = CI_USB_ERR_SHORT;
    }
    if (result != CI_USB_OK) {
        connection->poisoned = 1;
        (void)snprintf(connection->error, sizeof(connection->error), "%s",
                       CI_USB_StrError(result));
    }
    (void)pthread_mutex_unlock(&connection->lock);
    return result;
}

const char *CI_USB_LastError(const CI_USB *connection)
{
    return connection == NULL ? "no USB connection" : connection->error;
}

void CI_USB_Close(CI_USB *connection)
{
    if (connection == NULL) return;
    if (connection->destroy != NULL) connection->destroy(connection->backend_context);
    (void)pthread_mutex_destroy(&connection->lock);
    free(connection);
}

#if defined(__linux__) && !defined(CI_USB_USE_LIBUSB)
struct usbfs_backend { int fd; uint32_t timeout_ms; uint16_t max_packet; };

static int read_number(const char *path, int base, unsigned int *number)
{
    char buffer[64], *end;
    unsigned long value;
    FILE *file = fopen(path, "r");
    if (file == NULL) return -1;
    if (fgets(buffer, sizeof(buffer), file) == NULL) { fclose(file); return -1; }
    fclose(file);
    errno = 0;
    value = strtoul(buffer, &end, base);
    if (errno != 0 || end == buffer || value > UINT_MAX) return -1;
    while (*end == ' ' || *end == '\n' || *end == '\r' || *end == '\t') ++end;
    if (*end != '\0') return -1;
    *number = (unsigned int)value;
    return 0;
}

static int descriptor_packet(const char *path, uint16_t *packet)
{
    uint8_t data[4096];
    int iface = -1, alt = -1, have_in = 0;
    uint16_t out_packet = 0;
    size_t offset = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    ssize_t length;
    if (fd < 0) return CI_USB_ERR_IO;
    length = read(fd, data, sizeof(data));
    close(fd);
    if (length < 0) return CI_USB_ERR_IO;
    while (offset + 2u <= (size_t)length) {
        uint8_t n = data[offset], type = data[offset + 1u];
        if (n < 2u || offset + n > (size_t)length) return CI_USB_ERR_IO;
        if (type == 4u && n >= 9u) {
            iface = data[offset + 2u]; alt = data[offset + 3u];
        } else if (type == 5u && n >= 7u && iface == 0 && alt == 0 &&
                   (data[offset + 3u] & 3u) == 2u) {
            uint16_t size = (uint16_t)data[offset + 4u] |
                ((uint16_t)data[offset + 5u] << 8);
            if (size == 0u || size > 1024u) return CI_USB_ERR_UNSUPPORTED;
            if (data[offset + 2u] == 0x01u) out_packet = size;
            if (data[offset + 2u] == 0x81u) have_in = 1;
        }
        offset += n;
    }
    if (!have_in || !out_packet) return CI_USB_ERR_UNSUPPORTED;
    *packet = out_packet;
    return CI_USB_OK;
}

static int find_device(const CI_USB_Options *options, char path[256], uint16_t *packet)
{
    DIR *dir = opendir("/sys/bus/usb/devices");
    struct dirent *entry;
    unsigned int matches = 0;
    int result = CI_USB_ERR_NOT_FOUND;
    if (dir == NULL) return CI_USB_ERR_IO;
    while ((entry = readdir(dir)) != NULL) {
        char field[512], candidate[256];
        unsigned int vendor, product, bus, dev;
        if (entry->d_name[0] == '.') continue;
#define READ_FIELD(name, base, value) \
        (snprintf(field, sizeof(field), "/sys/bus/usb/devices/%s/" name, entry->d_name) >= (int)sizeof(field) || read_number(field, base, value) != 0)
        if (READ_FIELD("idVendor", 16, &vendor) || READ_FIELD("idProduct", 16, &product) ||
            vendor != options->vendor_id || product != options->product_id) continue;
        if (READ_FIELD("busnum", 10, &bus) || READ_FIELD("devnum", 10, &dev)) continue;
#undef READ_FIELD
        if (snprintf(candidate, sizeof(candidate), "/dev/bus/usb/%03u/%03u", bus, dev) >= (int)sizeof(candidate)) continue;
        if (options->device_path != NULL && strcmp(options->device_path, candidate) != 0) continue;
        if (++matches > 1u) { result = CI_USB_ERR_MULTIPLE; break; }
        if (snprintf(field, sizeof(field), "/sys/bus/usb/devices/%s/descriptors", entry->d_name) >= (int)sizeof(field)) {
            result = CI_USB_ERR_IO; break;
        }
        result = descriptor_packet(field, packet);
        if (result != CI_USB_OK) break;
        memcpy(path, candidate, strlen(candidate) + 1u);
    }
    closedir(dir);
    return result;
}

static int bulk_until(struct usbfs_backend *backend, uint8_t endpoint,
                       void *data, size_t size, uint64_t deadline)
{
    struct usbdevfs_bulktransfer transfer;
    uint64_t now = monotonic_ns(), remaining;
    if (now >= deadline) { errno = ETIMEDOUT; return -1; }
    remaining = (deadline - now + 999999u) / 1000000u;
    memset(&transfer, 0, sizeof(transfer));
    transfer.ep = endpoint;
    transfer.len = (unsigned int)size;
    transfer.timeout = remaining > UINT_MAX ? UINT_MAX : (unsigned int)remaining;
    transfer.data = data;
    return ioctl(backend->fd, USBDEVFS_BULK, &transfer);
}

/* Bulk OUT only: request frame + conditional ZLP (fills one device container). */
static int usbfs_send(void *context, const uint8_t *request, size_t request_len,
                      CI_USB_Timing *timing)
{
    struct usbfs_backend *backend = context;
    uint64_t deadline;
    int n;
    timing->out_start_ns = monotonic_ns();
    deadline = timing->out_start_ns + (uint64_t)backend->timeout_ms * 1000000u;
    n = bulk_until(backend, 0x01u, (void *)request, request_len, deadline);
    if (n < 0) return errno == ETIMEDOUT ? CI_USB_ERR_TIMEOUT : CI_USB_ERR_IO;
    if ((size_t)n != request_len) return CI_USB_ERR_SHORT;
    /* AUTO DMA needs a short packet boundary. Explicit OUT ZLP is necessary
     * for a complete request which is exactly a max-packet multiple. */
    if (request_len % backend->max_packet == 0u &&
        bulk_until(backend, 0x01u, NULL, 0u, deadline) != 0)
        return errno == ETIMEDOUT ? CI_USB_ERR_TIMEOUT : CI_USB_ERR_IO;
    timing->out_end_ns = monotonic_ns();
    return CI_USB_OK;
}

/* Bulk IN only: one response frame (firmware short-packets at the true length). */
static int usbfs_recv(void *context, uint8_t *response, size_t expected,
                      size_t *actual, CI_USB_Timing *timing)
{
    struct usbfs_backend *backend = context;
    uint64_t deadline;
    int n;
    timing->in_start_ns = monotonic_ns();
    deadline = timing->in_start_ns + (uint64_t)backend->timeout_ms * 1000000u;
    /* Request exact success length: firmware does not append an IN ZLP.
     * A short 16-byte CI error is accepted for protocol-layer validation. */
    n = bulk_until(backend, 0x81u, response, expected, deadline);
    timing->in_end_ns = monotonic_ns();
    if (n < 0) return errno == ETIMEDOUT ? CI_USB_ERR_TIMEOUT : CI_USB_ERR_IO;
    *actual = (size_t)n;
    return CI_USB_OK;
}

static int usbfs_exchange(void *context, const uint8_t *request, size_t request_len,
                           uint8_t *response, size_t expected, size_t *actual,
                           CI_USB_Timing *timing)
{
    int rc = usbfs_send(context, request, request_len, timing);
    if (rc != CI_USB_OK) return rc;
    return usbfs_recv(context, response, expected, actual, timing);
}

static void usbfs_destroy(void *context)
{
    struct usbfs_backend *backend = context;
    int iface = 0;
    (void)ioctl(backend->fd, USBDEVFS_RELEASEINTERFACE, &iface);
    close(backend->fd);
    free(backend);
}
#endif /* __linux__ && !CI_USB_USE_LIBUSB */

#if defined(CI_USB_USE_LIBUSB)
struct ci_libusb_backend {
    libusb_context *ctx;
    libusb_device_handle *handle;
    uint32_t timeout_ms;
    uint16_t max_packet;
};

/* Enumerate, match VID/PID (and device_path = /dev/bus/usb/BBB/DDD when set),
 * read the OUT endpoint (0x01) max packet size, then open + claim interface 0. */
static int ci_libusb_find_open(const CI_USB_Options *options,
                               struct ci_libusb_backend *be)
{
    libusb_device **list = NULL;
    libusb_device *found = NULL;
    struct libusb_config_descriptor *cfg = NULL;
    ssize_t count, i;
    unsigned int matches = 0;
    uint16_t mp = 0;
    int rc;

    count = libusb_get_device_list(be->ctx, &list);
    if (count < 0) return CI_USB_ERR_IO;
    for (i = 0; i < count; ++i) {
        struct libusb_device_descriptor dd;
        if (libusb_get_device_descriptor(list[i], &dd) != 0) continue;
        if (dd.idVendor != options->vendor_id || dd.idProduct != options->product_id)
            continue;
        if (options->device_path != NULL) {
            char cand[64];
            unsigned int bus = libusb_get_bus_number(list[i]);
            unsigned int addr = libusb_get_device_address(list[i]);
            if (snprintf(cand, sizeof(cand), "/dev/bus/usb/%03u/%03u", bus, addr) >=
                (int)sizeof(cand) || strcmp(cand, options->device_path) != 0)
                continue;
        }
        if (++matches > 1u) { libusb_free_device_list(list, 1); return CI_USB_ERR_MULTIPLE; }
        found = list[i];
    }
    if (found == NULL) { libusb_free_device_list(list, 1); return CI_USB_ERR_NOT_FOUND; }

    if (libusb_get_active_config_descriptor(found, &cfg) == 0 && cfg != NULL) {
        for (int ii = 0; ii < cfg->bNumInterfaces && mp == 0u; ++ii) {
            const struct libusb_interface *itf = &cfg->interface[ii];
            for (int a = 0; a < itf->num_altsetting && mp == 0u; ++a) {
                const struct libusb_interface_descriptor *id = &itf->altsetting[a];
                if (id->bInterfaceNumber != 0 || id->bAlternateSetting != 0) continue;
                for (int e = 0; e < id->bNumEndpoints; ++e) {
                    const struct libusb_endpoint_descriptor *ep = &id->endpoint[e];
                    if (ep->bEndpointAddress == 0x01u)
                        mp = (uint16_t)(ep->wMaxPacketSize & 0x7ffu);
                }
            }
        }
        libusb_free_config_descriptor(cfg);
    }
    if (mp == 0u) { libusb_free_device_list(list, 1); return CI_USB_ERR_UNSUPPORTED; }
    be->max_packet = mp;

    rc = libusb_open(found, &be->handle);
    libusb_free_device_list(list, 1);
    if (rc != 0) return CI_USB_ERR_IO;
    (void)libusb_set_auto_detach_kernel_driver(be->handle, 1);
    if (libusb_claim_interface(be->handle, 0) != 0) {
        libusb_close(be->handle); be->handle = NULL;
        return CI_USB_ERR_IO;
    }
    return CI_USB_OK;
}

static int ci_libusb_bulk(struct ci_libusb_backend *be, unsigned char endpoint,
                          unsigned char *data, int length, int *transferred)
{
    int rc = libusb_bulk_transfer(be->handle, endpoint, data, length,
                                  transferred, be->timeout_ms);
    if (rc == LIBUSB_ERROR_TIMEOUT) return CI_USB_ERR_TIMEOUT;
    if (rc != 0) return CI_USB_ERR_IO;
    return CI_USB_OK;
}

/* Bulk OUT only: request frame + conditional ZLP (fills one device container). */
static int ci_libusb_send(void *context, const uint8_t *request, size_t request_len,
                          CI_USB_Timing *timing)
{
    struct ci_libusb_backend *be = context;
    int transferred = 0, rc;
    timing->out_start_ns = monotonic_ns();
    rc = ci_libusb_bulk(be, 0x01u, (unsigned char *)(uintptr_t)request,
                        (int)request_len, &transferred);
    if (rc != CI_USB_OK) return rc;
    if ((size_t)transferred != request_len) return CI_USB_ERR_SHORT;
    /* AUTO DMA needs a short-packet boundary: send an explicit OUT ZLP when the
     * request is exactly a max-packet multiple (same rule as the usbfs path). */
    if (request_len % be->max_packet == 0u) {
        transferred = 0;
        rc = ci_libusb_bulk(be, 0x01u, (unsigned char *)(uintptr_t)request, 0, &transferred);
        if (rc != CI_USB_OK) return rc;
    }
    timing->out_end_ns = monotonic_ns();
    return CI_USB_OK;
}

/* Bulk IN only: one response frame (firmware short-packets at the true length). */
static int ci_libusb_recv(void *context, uint8_t *response, size_t expected,
                          size_t *actual, CI_USB_Timing *timing)
{
    struct ci_libusb_backend *be = context;
    int transferred = 0, rc;
    timing->in_start_ns = monotonic_ns();
    /* Request the exact success length; firmware does not append an IN ZLP. A
     * short 16-byte CI error frame is accepted for protocol-layer validation. */
    rc = ci_libusb_bulk(be, 0x81u, response, (int)expected, &transferred);
    timing->in_end_ns = monotonic_ns();
    if (rc != CI_USB_OK) return rc;
    *actual = (size_t)transferred;
    return CI_USB_OK;
}

static int ci_libusb_exchange(void *context, const uint8_t *request, size_t request_len,
                              uint8_t *response, size_t expected, size_t *actual,
                              CI_USB_Timing *timing)
{
    int rc = ci_libusb_send(context, request, request_len, timing);
    if (rc != CI_USB_OK) return rc;
    return ci_libusb_recv(context, response, expected, actual, timing);
}

static void ci_libusb_destroy(void *context)
{
    struct ci_libusb_backend *be = context;
    if (be == NULL) return;
    if (be->handle != NULL) {
        (void)libusb_release_interface(be->handle, 0);
        libusb_close(be->handle);
    }
    if (be->ctx != NULL) libusb_exit(be->ctx);
    free(be);
}
#endif /* CI_USB_USE_LIBUSB */

int CI_USB_Open(const CI_USB_Options *options, CI_USB **connection)
{
    CI_USB_Options defaults;
    if (connection == NULL) return CI_USB_ERR_ARGUMENT;
    *connection = NULL;
    if (options == NULL) { CI_USB_DefaultOptions(&defaults); options = &defaults; }
    if (options->vendor_id != 0x04b4u || options->product_id != 0x5054u)
        return CI_USB_ERR_UNSUPPORTED;
    if (options->timeout_ms == 0u || options->timeout_ms > 60000u)
        return CI_USB_ERR_ARGUMENT;
#if defined(CI_USB_USE_LIBUSB)
    {
        struct ci_libusb_backend *be;
        int result;
        be = calloc(1, sizeof(*be));
        if (be == NULL) return CI_USB_ERR_MEMORY;
        be->timeout_ms = options->timeout_ms;
        if (libusb_init(&be->ctx) != 0) { free(be); return CI_USB_ERR_IO; }
        result = ci_libusb_find_open(options, be);
        if (result != CI_USB_OK) {
            if (be->ctx != NULL) libusb_exit(be->ctx);
            free(be);
            return result;
        }
        result = CI_USB_CreateBackend(ci_libusb_exchange, be, ci_libusb_destroy, connection);
        if (result != CI_USB_OK) { ci_libusb_destroy(be); return result; }
        (*connection)->send = ci_libusb_send;   /* enable pipelined OUT/IN */
        (*connection)->recv = ci_libusb_recv;
        return result;
    }
#elif defined(__linux__)
    {
        char path[256];
        uint16_t packet;
        struct usbfs_backend *backend;
        int result, iface = 0;
        result = find_device(options, path, &packet);
        if (result != CI_USB_OK) return result;
        backend = calloc(1, sizeof(*backend));
        if (backend == NULL) return CI_USB_ERR_MEMORY;
        backend->fd = open(path, O_RDWR | O_CLOEXEC);
        if (backend->fd < 0) { free(backend); return CI_USB_ERR_IO; }
        if (ioctl(backend->fd, USBDEVFS_CLAIMINTERFACE, &iface) != 0) {
            close(backend->fd); free(backend); return CI_USB_ERR_IO;
        }
        backend->timeout_ms = options->timeout_ms;
        backend->max_packet = packet;
        result = CI_USB_CreateBackend(usbfs_exchange, backend, usbfs_destroy, connection);
        if (result != CI_USB_OK) { usbfs_destroy(backend); return result; }
        (*connection)->send = usbfs_send;       /* enable pipelined OUT/IN */
        (*connection)->recv = usbfs_recv;
        return result;
    }
#else
    return CI_USB_ERR_UNSUPPORTED;
#endif
}

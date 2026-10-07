#ifndef CI_USB_LIB_H
#define CI_USB_LIB_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct CI_USB CI_USB;

enum {
    CI_USB_OK = 0,
    CI_USB_ERR_ARGUMENT = -1001,
    CI_USB_ERR_IO = -1002,
    CI_USB_ERR_NOT_FOUND = -1003,
    CI_USB_ERR_MULTIPLE = -1004,
    CI_USB_ERR_TIMEOUT = -1005,
    CI_USB_ERR_MEMORY = -1006,
    CI_USB_ERR_SHORT = -1007,
    CI_USB_ERR_STATE = -1008,
    CI_USB_ERR_UNSUPPORTED = -1009
};

typedef struct {
    uint16_t vendor_id;
    uint16_t product_id;
    uint32_t timeout_ms;
    /* Optional exact /dev/bus/usb path; NULL selects exactly one VID/PID. */
    const char *device_path;
} CI_USB_Options;

typedef struct {
    uint64_t out_start_ns;
    uint64_t out_end_ns;
    uint64_t in_start_ns;
    uint64_t in_end_ns;
} CI_USB_Timing;

typedef struct {
    const uint8_t *request;
    size_t request_len;
    const uint8_t *response;
    size_t response_len;
    size_t expected_response_len;
    CI_USB_Timing timing;
    int status;
} CI_USB_Trace;

/* Callbacks run synchronously; trace byte pointers are valid only in callback.
 * Do not call this connection again from its trace/backend callback. Close is
 * a lifetime operation; callers must finish in-flight calls before closing.
 * The exchange callback is for alternate transports and test fixtures. Public
 * PEM applications normally use CI_USB_Open() instead. No implicit retry. */
typedef int (*CI_USB_Backend)(void *context,
                             const uint8_t *request, size_t request_len,
                             uint8_t *response, size_t expected_response_len,
                             size_t *response_len, CI_USB_Timing *timing);
typedef void (*CI_USB_BackendDestroy)(void *context);
typedef void (*CI_USB_TraceCallback)(void *context, const CI_USB_Trace *trace);

void CI_USB_DefaultOptions(CI_USB_Options *options);
int CI_USB_Open(const CI_USB_Options *options, CI_USB **connection);
int CI_USB_CreateBackend(CI_USB_Backend exchange, void *context,
                         CI_USB_BackendDestroy destroy, CI_USB **connection);
void CI_USB_Close(CI_USB *connection);
int CI_USB_Exchange(CI_USB *connection,
                    const uint8_t *request, size_t request_len,
                    uint8_t *response, size_t expected_response_len,
                    size_t *response_len, CI_USB_Timing *timing);
void CI_USB_SetTrace(CI_USB *connection, CI_USB_TraceCallback callback,
                     void *context);
/* Borrowed diagnostic text; read it between exchanges, without concurrent
 * Exchange/Close. The next exchange can replace its contents. */
const char *CI_USB_LastError(const CI_USB *connection);
const char *CI_USB_StrError(int status);

#ifdef __cplusplus
}
#endif
#endif

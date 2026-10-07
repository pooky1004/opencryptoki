/*
 * Token NCMP - Transport dispatcher (runtime backend selection).
 *
 * The daemon links every backend (real USB, mock emulator, socket) and this
 * file implements the public ncmp_transport_* API by forwarding to the backend
 * chosen via ncmp_transport_set_backend(). main.c selects it from the
 * --transport argument / NCMP_TRANSPORT env (default: real target).
 *
 * The backend is set once at startup before any probe/open, so forwarding a
 * handle returned by open() to send/recv/close of the same (active) backend is
 * always consistent.
 */
#include "ncmp/ncmp_transport.h"
#include "ncmp/ncmp_errno.h"

static const ncmp_transport_ops *g_ops = &ncmp_usb_ops;  /* default: real */

int ncmp_transport_set_backend(ncmp_backend_kind kind)
{
    switch (kind) {
    case NCMP_BACKEND_REAL:   g_ops = &ncmp_usb_ops;    return NCMP_OK;
    case NCMP_BACKEND_MOCK:   g_ops = &ncmp_mock_ops;   return NCMP_OK;
    case NCMP_BACKEND_SOCKET: g_ops = &ncmp_socket_ops; return NCMP_OK;
    case NCMP_BACKEND_PEM:    g_ops = &ncmp_pem_ops;    return NCMP_OK;
    default:                  return NCMP_ERR_INVAL;
    }
}

int ncmp_transport_probe(uint32_t *out_slot_mask)
{
    return g_ops->probe(out_slot_mask);
}

int ncmp_transport_open(uint32_t slot_id, ncmp_transport_t **out)
{
    return g_ops->open(slot_id, out);
}

int ncmp_transport_send(ncmp_transport_t *t, const uint8_t *frame, size_t len)
{
    return g_ops->send(t, frame, len);
}

int ncmp_transport_recv(ncmp_transport_t *t, uint8_t *buf, size_t buf_len,
                        size_t *out_len)
{
    return g_ops->recv(t, buf, buf_len, out_len);
}

int ncmp_transport_close(ncmp_transport_t *t)
{
    return g_ops->close(t);
}

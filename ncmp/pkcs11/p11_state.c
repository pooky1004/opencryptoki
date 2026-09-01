/*
 * Token NCMP - PKCS#11 provider state, locking, object store, transport glue.
 *
 * Central per-process bookkeeping shared by every C_* function. The global
 * lock here is a fast process-private mutex; it is held only while the
 * provider inspects or mutates its own tables and is always released around the
 * blocking token round-trip (see p11_forward*), so application threads execute
 * concurrently through the lock-free ncmp transport.
 */
#include "p11_provider.h"

#include "ncmp/ncmp_cmd.h"
#include "ncmp/ncmp_errno.h"
#include "ncmp/ncmp_wire.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Process-global state. The lock is statically initialised so p11_lock() is
 * usable before C_Initialize runs (it guards the initialize path itself). */
p11_state_t g_p11 = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .lock_ready = 1,
};

void p11_lock(void)
{
    pthread_mutex_lock(&g_p11.lock);
}

void p11_unlock(void)
{
    pthread_mutex_unlock(&g_p11.lock);
}

int p11_is_initialized(void)
{
    int v;

    p11_lock();
    v = g_p11.initialized;
    p11_unlock();
    return v;
}

/* ------------------------------------------------------------------------- */
/* Transport                                                                 */
/* ------------------------------------------------------------------------- */

CK_RV p11_ensure_client(void)
{
    const char *sock;
    int rc;

    if (g_p11.client_ready)
        return CKR_OK;

    sock = getenv("NCMP_SOCK_PATH"); /* NULL => NCMP_IPC_SOCK_PATH */
    rc = ncmp_client_init(&g_p11.client, sock);
    if (rc != NCMP_OK)
        return CKR_TOKEN_NOT_PRESENT;

    g_p11.client_ready = 1;
    g_p11.slot_mask = g_p11.client.slot_mask;
    p11_slotmap_build(g_p11.slot_mask);
    return CKR_OK;
}

ncmp_client_t *p11_client(void)
{
    return &g_p11.client;
}

void p11_pad(CK_CHAR *dst, size_t n, const char *src)
{
    size_t i = 0;

    for (; src && src[i] && i < n; ++i)
        dst[i] = (CK_CHAR)src[i];
    for (; i < n; ++i)
        dst[i] = ' ';
}

CK_RV p11_ck_from_ncmp(int ncmp_rc)
{
    switch (ncmp_rc) {
    case NCMP_OK:            return CKR_OK;
    case NCMP_ERR_NODAEMON:  return CKR_TOKEN_NOT_PRESENT;
    case NCMP_ERR_FULL:      return CKR_SESSION_COUNT;
    case NCMP_ERR_TIMEOUT:   return CKR_DEVICE_ERROR;
    case NCMP_ERR_PARAM_SIZE:return CKR_DATA_LEN_RANGE;
    case NCMP_ERR_NOSPACE:   return CKR_DEVICE_MEMORY;
    default:                 return CKR_FUNCTION_FAILED;
    }
}

CK_RV p11_forward(CK_SLOT_ID ck_slot, uint32_t opcode, const uint8_t *in,
                  uint32_t in_len, uint8_t *out, uint32_t out_cap,
                  uint32_t *out_len)
{
    uint32_t phys = 0, ack = 0;
    CK_RV rv;
    int rc;

    rv = p11_slotmap_phys(ck_slot, &phys);
    if (rv != CKR_OK)
        return rv;

    rc = ncmp_client_command(&g_p11.client, phys, opcode, in, in_len,
                             out, out_cap, out_len, &ack);
    if (rc != NCMP_OK)
        return p11_ck_from_ncmp(rc);
    return (CK_RV)ack;
}

CK_RV p11_forward_mp(CK_SLOT_ID ck_slot, uint32_t opcode,
                     const uint8_t *const in[], const uint32_t in_len[],
                     int n_in, uint8_t *out_payload, uint32_t out_cap,
                     NCMP_Message *out_msg)
{
    uint32_t phys = 0;
    CK_RV rv;
    int rc;

    rv = p11_slotmap_phys(ck_slot, &phys);
    if (rv != CKR_OK)
        return rv;

    rc = ncmp_client_command_mp(&g_p11.client, phys, opcode, in, in_len, n_in,
                                out_payload, out_cap, out_msg);
    if (rc != NCMP_OK)
        return p11_ck_from_ncmp(rc);
    return (CK_RV)out_msg->header.ack;
}

/* ------------------------------------------------------------------------- */
/* Sessions                                                                  */
/* ------------------------------------------------------------------------- */

p11_session_t *p11_session_get(CK_SESSION_HANDLE h)
{
    int i;

    if (h == CK_INVALID_HANDLE)
        return NULL;
    for (i = 0; i < P11_MAX_SESSIONS; ++i) {
        if (g_p11.sessions[i].in_use && g_p11.sessions[i].handle == h)
            return &g_p11.sessions[i];
    }
    return NULL;
}

p11_session_t *p11_session_alloc(void)
{
    int i;

    for (i = 0; i < P11_MAX_SESSIONS; ++i) {
        if (!g_p11.sessions[i].in_use) {
            p11_session_t *s = &g_p11.sessions[i];

            memset(s, 0, sizeof(*s));
            s->in_use = 1;
            if (g_p11.next_session == 0)
                g_p11.next_session = 1;
            s->handle = g_p11.next_session++;
            s->dig.digest_ctx = NCMP_DIGEST_CTX_NONE;
            return s;
        }
    }
    return NULL;
}

/** Free any heap buffers held by a session's operation contexts. */
static void p11_opctx_reset(p11_opctx_t *c)
{
    if (c->buf) {
        free(c->buf);
        c->buf = NULL;
    }
    memset(c, 0, sizeof(*c));
    c->digest_ctx = NCMP_DIGEST_CTX_NONE;
}

void p11_session_free(p11_session_t *s)
{
    int i;

    if (!s || !s->in_use)
        return;

    /* Drop this session's session-scoped (non-token) objects. */
    for (i = 0; i < P11_MAX_OBJECTS; ++i) {
        p11_object_t *o = &g_p11.objects[i];

        if (o->in_use && !o->is_token && o->session == s->handle)
            p11_object_free(o);
    }

    p11_opctx_reset(&s->enc);
    p11_opctx_reset(&s->dec);
    p11_opctx_reset(&s->dig);
    p11_opctx_reset(&s->sig);
    p11_opctx_reset(&s->ver);
    memset(s, 0, sizeof(*s));
}

/* ------------------------------------------------------------------------- */
/* Objects + attributes                                                      */
/* ------------------------------------------------------------------------- */

p11_object_t *p11_object_get(CK_OBJECT_HANDLE h)
{
    int i;

    if (h == CK_INVALID_HANDLE)
        return NULL;
    for (i = 0; i < P11_MAX_OBJECTS; ++i) {
        if (g_p11.objects[i].in_use && g_p11.objects[i].handle == h)
            return &g_p11.objects[i];
    }
    return NULL;
}

p11_object_t *p11_object_alloc(void)
{
    int i;

    for (i = 0; i < P11_MAX_OBJECTS; ++i) {
        if (!g_p11.objects[i].in_use) {
            p11_object_t *o = &g_p11.objects[i];

            memset(o, 0, sizeof(*o));
            o->in_use = 1;
            if (g_p11.next_object == 0)
                g_p11.next_object = 1;
            o->handle = g_p11.next_object++;
            return o;
        }
    }
    return NULL;
}

void p11_object_free(p11_object_t *o)
{
    int i;

    if (!o || !o->in_use)
        return;
    for (i = 0; i < o->n_attrs; ++i) {
        if (o->attrs[i].val)
            free(o->attrs[i].val);
    }
    memset(o, 0, sizeof(*o));
}

p11_attr_t *p11_obj_attr(p11_object_t *o, CK_ATTRIBUTE_TYPE t)
{
    int i;

    for (i = 0; i < o->n_attrs; ++i) {
        if (o->attrs[i].type == t)
            return &o->attrs[i];
    }
    return NULL;
}

CK_RV p11_obj_set(p11_object_t *o, CK_ATTRIBUTE_TYPE t, const void *v,
                  CK_ULONG len)
{
    p11_attr_t *a = p11_obj_attr(o, t);
    void *copy = NULL;

    if (len > P11_MAX_ATTR_LEN)
        return CKR_ATTRIBUTE_VALUE_INVALID;
    if (len > 0) {
        copy = malloc(len);
        if (!copy)
            return CKR_DEVICE_MEMORY;
        memcpy(copy, v, len);
    }

    if (a) {
        if (a->val)
            free(a->val);
        a->val = copy;
        a->len = len;
        return CKR_OK;
    }
    if (o->n_attrs >= P11_MAX_ATTRS) {
        if (copy)
            free(copy);
        return CKR_DEVICE_MEMORY;
    }
    o->attrs[o->n_attrs].type = t;
    o->attrs[o->n_attrs].val = copy;
    o->attrs[o->n_attrs].len = len;
    o->n_attrs++;
    return CKR_OK;
}

CK_BBOOL p11_obj_bool(p11_object_t *o, CK_ATTRIBUTE_TYPE t, CK_BBOOL dflt)
{
    p11_attr_t *a = p11_obj_attr(o, t);

    if (a && a->len >= 1 && a->val)
        return *(CK_BBOOL *)a->val ? CK_TRUE : CK_FALSE;
    return dflt;
}

CK_ULONG p11_obj_ulong(p11_object_t *o, CK_ATTRIBUTE_TYPE t, CK_ULONG dflt)
{
    p11_attr_t *a = p11_obj_attr(o, t);

    if (a && a->len == sizeof(CK_ULONG) && a->val)
        return *(CK_ULONG *)a->val;
    return dflt;
}

CK_RV p11_obj_from_template(p11_object_t *o, CK_ATTRIBUTE_PTR tmpl,
                            CK_ULONG count)
{
    CK_ULONG i;

    for (i = 0; i < count; ++i) {
        CK_RV rv = p11_obj_set(o, tmpl[i].type, tmpl[i].pValue,
                               tmpl[i].ulValueLen);
        if (rv != CKR_OK)
            return rv;
    }
    o->is_token = p11_obj_bool(o, CKA_TOKEN, CK_FALSE);
    o->is_private = p11_obj_bool(o, CKA_PRIVATE, CK_FALSE);
    return CKR_OK;
}

int p11_obj_matches(p11_object_t *o, CK_ATTRIBUTE_PTR tmpl, CK_ULONG count)
{
    CK_ULONG i;

    for (i = 0; i < count; ++i) {
        p11_attr_t *a = p11_obj_attr(o, tmpl[i].type);

        if (!a)
            return 0;
        if (a->len != tmpl[i].ulValueLen)
            return 0;
        if (tmpl[i].ulValueLen > 0 &&
            memcmp(a->val, tmpl[i].pValue, tmpl[i].ulValueLen) != 0)
            return 0;
    }
    return 1;
}

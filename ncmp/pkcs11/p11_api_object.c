/*
 * Token NCMP - PKCS#11 object management + find functions.
 *
 * Objects live in the per-process object store (p11_state.c). The mock token
 * is object-stateless (crypto forwards raw key material), so key attributes are
 * held here; real hardware would keep sensitive material on the token.
 */
#include "p11_provider.h"

#include <string.h>

/** Fetch and validate a session; returns NULL and sets *rv on failure. */
static p11_session_t *session_ck(CK_SESSION_HANDLE h, CK_RV *rv)
{
    p11_session_t *s = p11_session_get(h);

    if (!s) {
        *rv = CKR_SESSION_HANDLE_INVALID;
        return NULL;
    }
    *rv = CKR_OK;
    return s;
}

/** True if @p type names a sensitive key component. */
static int attr_is_sensitive(CK_ATTRIBUTE_TYPE t)
{
    return t == CKA_VALUE || t == CKA_PRIVATE_EXPONENT || t == CKA_PRIME_1;
}

/** True if the caller may see object @p o on session @p s. */
static int object_visible(const p11_session_t *s, const p11_object_t *o)
{
    uint32_t phys = 0;

    if (o->slot != s->slot)
        return 0;
    if (!o->is_private)
        return 1;
    if (p11_slotmap_phys(s->slot, &phys) != CKR_OK)
        return 0;
    return g_p11.slots[phys].logged_in ? 1 : 0;
}

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
                     CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
    p11_session_t *s;
    p11_object_t *o;
    CK_RV rv;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!phObject || (!pTemplate && ulCount))
        return CKR_ARGUMENTS_BAD;

    p11_lock();
    s = session_ck(hSession, &rv);
    if (!s) {
        p11_unlock();
        return rv;
    }
    o = p11_object_alloc();
    if (!o) {
        p11_unlock();
        return CKR_DEVICE_MEMORY;
    }
    rv = p11_obj_from_template(o, pTemplate, ulCount);
    if (rv != CKR_OK) {
        p11_object_free(o);
        p11_unlock();
        return rv;
    }
    o->slot = s->slot;
    o->session = o->is_token ? CK_INVALID_HANDLE : s->handle;
    *phObject = o->handle;
    p11_unlock();
    return CKR_OK;
}

CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                   CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                   CK_OBJECT_HANDLE_PTR phNewObject)
{
    p11_session_t *s;
    p11_object_t *src, *dst;
    CK_RV rv;
    int i;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!phNewObject)
        return CKR_ARGUMENTS_BAD;

    p11_lock();
    s = session_ck(hSession, &rv);
    if (!s) {
        p11_unlock();
        return rv;
    }
    src = p11_object_get(hObject);
    if (!src || !object_visible(s, src)) {
        p11_unlock();
        return CKR_OBJECT_HANDLE_INVALID;
    }
    dst = p11_object_alloc();
    if (!dst) {
        p11_unlock();
        return CKR_DEVICE_MEMORY;
    }
    /* Copy all source attributes, then overlay the supplied template. */
    for (i = 0; i < src->n_attrs; ++i) {
        rv = p11_obj_set(dst, src->attrs[i].type, src->attrs[i].val,
                         src->attrs[i].len);
        if (rv != CKR_OK) {
            p11_object_free(dst);
            p11_unlock();
            return rv;
        }
    }
    rv = p11_obj_from_template(dst, pTemplate, ulCount);
    if (rv != CKR_OK) {
        p11_object_free(dst);
        p11_unlock();
        return rv;
    }
    dst->slot = s->slot;
    dst->session = dst->is_token ? CK_INVALID_HANDLE : s->handle;
    *phNewObject = dst->handle;
    p11_unlock();
    return CKR_OK;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
    p11_session_t *s;
    p11_object_t *o;
    CK_RV rv;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    p11_lock();
    s = session_ck(hSession, &rv);
    if (!s) {
        p11_unlock();
        return rv;
    }
    o = p11_object_get(hObject);
    if (!o || !object_visible(s, o)) {
        p11_unlock();
        return CKR_OBJECT_HANDLE_INVALID;
    }
    p11_object_free(o);
    p11_unlock();
    return CKR_OK;
}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                      CK_ULONG_PTR pulSize)
{
    p11_session_t *s;
    p11_object_t *o;
    CK_RV rv;
    CK_ULONG total = 0;
    int i;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!pulSize)
        return CKR_ARGUMENTS_BAD;

    p11_lock();
    s = session_ck(hSession, &rv);
    if (!s) {
        p11_unlock();
        return rv;
    }
    o = p11_object_get(hObject);
    if (!o || !object_visible(s, o)) {
        p11_unlock();
        return CKR_OBJECT_HANDLE_INVALID;
    }
    for (i = 0; i < o->n_attrs; ++i)
        total += (CK_ULONG)sizeof(CK_ATTRIBUTE) + o->attrs[i].len;
    *pulSize = total;
    p11_unlock();
    return CKR_OK;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    p11_session_t *s;
    p11_object_t *o;
    CK_RV rv, ret = CKR_OK;
    CK_ULONG i;
    int sensitive_obj;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!pTemplate && ulCount)
        return CKR_ARGUMENTS_BAD;

    p11_lock();
    s = session_ck(hSession, &rv);
    if (!s) {
        p11_unlock();
        return rv;
    }
    o = p11_object_get(hObject);
    if (!o || !object_visible(s, o)) {
        p11_unlock();
        return CKR_OBJECT_HANDLE_INVALID;
    }
    sensitive_obj = p11_obj_bool(o, CKA_SENSITIVE, CK_FALSE) ||
                    !p11_obj_bool(o, CKA_EXTRACTABLE, CK_TRUE);

    for (i = 0; i < ulCount; ++i) {
        p11_attr_t *a = p11_obj_attr(o, pTemplate[i].type);

        if (!a) {
            pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
            ret = CKR_ATTRIBUTE_TYPE_INVALID;
            continue;
        }
        if (sensitive_obj && attr_is_sensitive(pTemplate[i].type)) {
            pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
            ret = CKR_ATTRIBUTE_SENSITIVE;
            continue;
        }
        if (!pTemplate[i].pValue) {
            pTemplate[i].ulValueLen = a->len;
            continue;
        }
        if (pTemplate[i].ulValueLen < a->len) {
            pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
            ret = CKR_BUFFER_TOO_SMALL;
            continue;
        }
        if (a->len > 0)
            memcpy(pTemplate[i].pValue, a->val, a->len);
        pTemplate[i].ulValueLen = a->len;
    }
    p11_unlock();
    return ret;
}

CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    p11_session_t *s;
    p11_object_t *o;
    CK_RV rv;
    CK_ULONG i;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!pTemplate && ulCount)
        return CKR_ARGUMENTS_BAD;

    p11_lock();
    s = session_ck(hSession, &rv);
    if (!s) {
        p11_unlock();
        return rv;
    }
    o = p11_object_get(hObject);
    if (!o || !object_visible(s, o)) {
        p11_unlock();
        return CKR_OBJECT_HANDLE_INVALID;
    }
    for (i = 0; i < ulCount; ++i) {
        rv = p11_obj_set(o, pTemplate[i].type, pTemplate[i].pValue,
                         pTemplate[i].ulValueLen);
        if (rv != CKR_OK) {
            p11_unlock();
            return rv;
        }
    }
    o->is_token = p11_obj_bool(o, CKA_TOKEN, o->is_token);
    o->is_private = p11_obj_bool(o, CKA_PRIVATE, o->is_private);
    p11_unlock();
    return CKR_OK;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
                        CK_ULONG ulCount)
{
    p11_session_t *s;
    CK_RV rv;
    int i;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!pTemplate && ulCount)
        return CKR_ARGUMENTS_BAD;

    p11_lock();
    s = session_ck(hSession, &rv);
    if (!s) {
        p11_unlock();
        return rv;
    }
    if (s->find_active) {
        p11_unlock();
        return CKR_OPERATION_ACTIVE;
    }
    s->find_count = 0;
    s->find_pos = 0;
    for (i = 0; i < P11_MAX_OBJECTS; ++i) {
        p11_object_t *o = &g_p11.objects[i];

        if (!o->in_use || !object_visible(s, o))
            continue;
        if (!p11_obj_matches(o, pTemplate, ulCount))
            continue;
        if (s->find_count < P11_MAX_OBJECTS)
            s->find_results[s->find_count++] = o->handle;
    }
    s->find_active = 1;
    p11_unlock();
    return CKR_OK;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject,
                    CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
    p11_session_t *s;
    CK_RV rv;
    CK_ULONG n = 0;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!phObject || !pulObjectCount)
        return CKR_ARGUMENTS_BAD;

    p11_lock();
    s = session_ck(hSession, &rv);
    if (!s) {
        p11_unlock();
        return rv;
    }
    if (!s->find_active) {
        p11_unlock();
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    while (n < ulMaxObjectCount && s->find_pos < s->find_count) {
        /* Skip handles destroyed since FindObjectsInit. */
        CK_OBJECT_HANDLE h = s->find_results[s->find_pos++];

        if (p11_object_get(h))
            phObject[n++] = h;
    }
    *pulObjectCount = n;
    p11_unlock();
    return CKR_OK;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
    p11_session_t *s;
    CK_RV rv;

    if (!p11_is_initialized())
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    p11_lock();
    s = session_ck(hSession, &rv);
    if (!s) {
        p11_unlock();
        return rv;
    }
    if (!s->find_active) {
        p11_unlock();
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    s->find_active = 0;
    s->find_count = 0;
    s->find_pos = 0;
    p11_unlock();
    return CKR_OK;
}

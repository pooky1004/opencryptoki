/*
 * Token NCMP - STDLL object-management marshalling adapter.
 *
 * As a secure-key token the physical token owns all key material, so a key
 * object created/imported (C_CreateObject) or modified (C_SetAttributeValue)
 * through the opencryptoki common object manager is forwarded here to the
 * token, which registers or re-validates it as a secure key. Object storage,
 * handle mapping, enumeration (find), size and destroy remain in the common
 * layer; only the two token_specific object hooks that exist (t_object_add,
 * t_set_attribute_values) forward. Mirrors the ncmp_crypto / ncmp_admin
 * adapters: pack request parameters, forward via the client transport, surface
 * the token's CKR_* ack (or a mapped transport error). Testable standalone
 * against the mock token.
 */
#ifndef NCMP_OBJECT_H
#define NCMP_OBJECT_H

#include <stdint.h>

#include "ncmp_client.h"

/**
 * @brief Register/import a key object with the token (C_CreateObject path).
 *
 * Wire: NCMP_CMD_OBJECT_ADD [class(LE u32) | key_type(LE u32) | value].
 *
 * @param c         Initialized client handle.
 * @param slot      Physical slot index.
 * @param obj_class PKCS#11 object class (CKO_*).
 * @param key_type  PKCS#11 key type (CKK_*).
 * @param value     Key material bytes (CKA_VALUE).
 * @param value_len Key material length (<= NCMP_MAX_PARAM_SIZE).
 * @return NCMP_CKR_OK, the token's CKR_* ack (e.g. CKR_TEMPLATE_INCOMPLETE /
 *         CKR_ATTRIBUTE_VALUE_INVALID), or a mapped transport error.
 */
unsigned long ncmp_object_add(ncmp_client_t *c, uint32_t slot,
                              uint32_t obj_class, uint32_t key_type,
                              const uint8_t *value, uint32_t value_len);

/**
 * @brief Forward changed attributes of a key object to the token
 *        (C_SetAttributeValue / C_CopyObject path).
 *
 * Wire: NCMP_CMD_OBJECT_SET_ATTR [class(LE u32) | key_type(LE u32) | attrs].
 * The @p attrs blob is a self-describing list:
 *   count(LE u32), then @p count entries of { type(LE u32) | len(LE u32) | value[len] }.
 *
 * @param c         Initialized client handle.
 * @param slot      Physical slot index.
 * @param obj_class PKCS#11 object class (CKO_*).
 * @param key_type  PKCS#11 key type (CKK_*).
 * @param attrs     Serialized changed-attribute list (see above).
 * @param attrs_len Serialized list length (<= NCMP_MAX_PARAM_SIZE).
 * @return NCMP_CKR_OK, the token's CKR_* ack, or a mapped transport error.
 */
unsigned long ncmp_object_set_attrs(ncmp_client_t *c, uint32_t slot,
                                    uint32_t obj_class, uint32_t key_type,
                                    const uint8_t *attrs, uint32_t attrs_len);

#endif /* NCMP_OBJECT_H */

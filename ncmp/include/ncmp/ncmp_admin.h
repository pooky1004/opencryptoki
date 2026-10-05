/*
 * Token NCMP - STDLL token-administration marshalling adapter.
 *
 * Pure-buffer forwards for the non-crypto token operations the opencryptoki
 * token_specific hooks need: identity query (get_token_info), and the PIN /
 * login lifecycle (login/logout/init_pin/set_pin/init_token). Each packs the
 * request into the NCMP wire parameter layout, forwards it via the client
 * transport, and returns the token's CKR_* ack (or a mapped transport error),
 * exactly like the ncmp_crypto adapter. Testable standalone against the mock.
 */
#ifndef NCMP_ADMIN_H
#define NCMP_ADMIN_H

#include <stdint.h>

#include "ncmp_client.h"
#include "ncmp_shm.h" /* NCMP_TokenIdentity */

/**
 * @brief Query the token's identity (label/serial/manufacturer/model/versions).
 * @param c    Initialized client handle.
 * @param slot Physical slot index.
 * @param out  Receives the decoded identity on CKR_OK.
 * @return NCMP_CKR_OK, a token ack, or a mapped transport error.
 */
unsigned long ncmp_admin_token_info(ncmp_client_t *c, uint32_t slot,
                                    NCMP_TokenIdentity *out);

/**
 * @brief Query the token's current UTC time (CK_TOKEN_INFO.utcTime).
 * @param c    Initialized client handle.
 * @param slot Physical slot index.
 * @param out  Receives NCMP_TOKEN_UTC_LEN bytes ("YYYYMMDDhhmmssxx").
 * @return NCMP_CKR_OK, a token ack, or a mapped transport error.
 */
unsigned long ncmp_admin_get_utc_time(ncmp_client_t *c, uint32_t slot,
                                      uint8_t *out);

/**
 * @brief Set the token's UTC time (SO only; NCMP_TOKEN_UTC_LEN bytes).
 * @param c    Initialized client handle.
 * @param slot Physical slot index.
 * @param utc  NCMP_TOKEN_UTC_LEN-byte time field ("YYYYMMDDhhmmssxx").
 * @return NCMP_CKR_OK, CKR_USER_NOT_LOGGED_IN / CKR_ARGUMENTS_BAD, or a mapped
 *         transport error.
 */
unsigned long ncmp_admin_set_utc_time(ncmp_client_t *c, uint32_t slot,
                                      const uint8_t *utc);

/**
 * @brief Query the token label, serial number, and PIN-length bounds.
 * @param c       Initialized client handle.
 * @param slot    Physical slot index.
 * @param label   Receives NCMP_TI_LABEL_LEN bytes (may be NULL to skip).
 * @param serial  Receives NCMP_TI_SERIAL_LEN bytes (may be NULL to skip).
 * @param min_pin Receives ulMinPinLen (may be NULL to skip).
 * @param max_pin Receives ulMaxPinLen (may be NULL to skip).
 * @return NCMP_CKR_OK, a token ack, or a mapped transport error.
 */
unsigned long ncmp_admin_get_token_params(ncmp_client_t *c, uint32_t slot,
                                          uint8_t *label, uint8_t *serial,
                                          uint32_t *min_pin, uint32_t *max_pin);

/**
 * @brief Forward a login (PIN verification) to the token.
 * @param c         Initialized client handle.
 * @param slot      Physical slot index.
 * @param user_type PKCS#11 user type (NCMP_CKU_SO / NCMP_CKU_USER /
 *                  NCMP_CKU_CONTEXT_SPECIFIC).
 * @param flags     Login modifiers (NCMP_LOGIN_FLAG_*): protected-auth path,
 *                  context-specific re-authentication.
 * @param pin       PIN bytes (may be NULL when @p pin_len is 0).
 * @param pin_len   PIN length in bytes.
 * @return NCMP_CKR_OK, or CKR_PIN_INCORRECT / CKR_* / mapped transport error.
 */
unsigned long ncmp_admin_login(ncmp_client_t *c, uint32_t slot,
                               uint32_t user_type, uint32_t flags,
                               const uint8_t *pin, uint32_t pin_len);

/**
 * @brief Forward a logout to the token.
 * @return NCMP_CKR_OK, a token ack, or a mapped transport error.
 */
unsigned long ncmp_admin_logout(ncmp_client_t *c, uint32_t slot);

/**
 * @brief Open a session on the token (NCMP_CMD_OPEN_SESSION, reference target).
 *
 * The STDLL must set c->active_session_id = 0 before calling so the OPEN frame
 * carries a zero wire-header session_id; the token allocates a session and
 * returns the handle, which is stored in @p out_handle. The STDLL then applies
 * that handle (via c->active_session_id) to every subsequent command.
 *
 * @param c          Client handle.
 * @param slot       Physical slot.
 * @param flags      PKCS#11 session flags (CKF_SERIAL_SESSION | CKF_RW_SESSION).
 * @param out_handle Receives the token-assigned session handle (may be NULL).
 * @return NCMP_CKR_OK, a token ack (e.g. CKR_SESSION_COUNT), or a transport error.
 */
unsigned long ncmp_admin_open_session(ncmp_client_t *c, uint32_t slot,
                                      uint32_t flags, uint32_t *out_handle);

/**
 * @brief Close the session carried in c->active_session_id (NCMP_CMD_CLOSE_SESSION).
 * @return NCMP_CKR_OK, a token ack, or a mapped transport error.
 */
unsigned long ncmp_admin_close_session(ncmp_client_t *c, uint32_t slot);

/**
 * @brief SO sets the (new) user PIN on the token.
 * @return NCMP_CKR_OK, a token ack, or a mapped transport error.
 */
unsigned long ncmp_admin_init_pin(ncmp_client_t *c, uint32_t slot,
                                  const uint8_t *pin, uint32_t pin_len);

/**
 * @brief Change the current user's PIN (old -> new) on the token.
 * @return NCMP_CKR_OK, or CKR_PIN_INCORRECT / CKR_* / mapped transport error.
 */
unsigned long ncmp_admin_set_pin(ncmp_client_t *c, uint32_t slot,
                                 const uint8_t *old_pin, uint32_t old_len,
                                 const uint8_t *new_pin, uint32_t new_len);

/**
 * @brief Initialize the token (verify SO PIN, set label).
 * @param c        Initialized client handle.
 * @param slot     Physical slot index.
 * @param so_pin   SO PIN bytes.
 * @param so_len   SO PIN length.
 * @param label    Token label; padded to NCMP_TI_LABEL_LEN on the wire.
 * @return NCMP_CKR_OK, or CKR_PIN_INCORRECT / CKR_* / mapped transport error.
 */
unsigned long ncmp_admin_init_token(ncmp_client_t *c, uint32_t slot,
                                    const uint8_t *so_pin, uint32_t so_len,
                                    const char *label);

#endif /* NCMP_ADMIN_H */

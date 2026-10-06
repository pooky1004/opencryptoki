/*
 * Token NCMP - Test App native layer (C "Application" ABI).
 *
 * This layer (libncmp_testapp.so, also compiled into the web server ncmp_web)
 * is the "Application" in:
 *
 *   Browser --HTTP/JSON--> ncmp_web --app_*--> this layer
 *       -> dlopen/dlsym libpkcs11_ncmp.so (facade, C_*)
 *           -> ncmp_client -> IPC + SHM -> ncmpd -> comm thread -> FX3 (USB)
 *
 * On app_load() it dlopen's the facade and dlsym's every PKCS#11 entry point;
 * app_initialize() runs C_Initialize (which connects to ncmpd and attaches the
 * shared memory), and each app_* call drives the matching C_* so per-slot
 * commands flow through the SHM slot ring to ncmpd.
 *
 * ABI is deliberately simple for any caller (web server, or dlopen from another
 * host app): C strings, ints, and byte buffers. Return convention:
 * 0 = CKR_OK; >0 = a CKR_* code; <0 = an app-level error (not loaded / dlopen /
 * dlsym / bad args). app_last_error() has details.
 */
#ifndef NCMP_TESTAPP_H
#define NCMP_TESTAPP_H

#ifdef __cplusplus
extern "C" {
#endif

/* App-level (negative) error codes. */
#define APP_ERR_NOT_LOADED  (-1)
#define APP_ERR_DLOPEN      (-2)
#define APP_ERR_DLSYM       (-3)
#define APP_ERR_ARGS        (-4)
#define APP_ERR_NO_FUNC     (-5)

/** dlopen the facade and dlsym all PKCS#11 entry points. 0/neg. */
int app_load(const char *module_path);
/** dlclose and reset. */
int app_unload(void);

/** JSON {"C_Initialize":1,"C_GetSlotList":1,...} of dlsym presence. */
int app_dlsym_report(char *json_out, int cap);

/** C_Initialize (connects to ncmpd + attaches SHM) / C_Finalize. */
int app_initialize(void);
int app_finalize(void);

/** Active (token-present) slot ids into out[0..max); *count set. */
int app_get_slots(unsigned long *out, int max, int *count);

/** C_GetInfo -> JSON (cryptokiVersion/manufacturer/libDescription/libVersion). */
int app_library_info(char *json_out, int cap);
/** C_GetTokenInfo(slot) -> JSON (label/manufacturer/model/serial/flags/pin...). */
int app_token_info(unsigned long slot, char *json_out, int cap);
/** C_GetMechanismList(slot) -> JSON array of {name,code}. */
int app_mechanism_list(unsigned long slot, char *json_out, int cap);
/** C_GetSessionInfo(session) -> JSON (slot/state/flags/deviceError). */
int app_session_info(unsigned long session, char *json_out, int cap);

/** Session + login. */
int app_open_session(unsigned long slot, int rw, unsigned long *out_session);
int app_close_session(unsigned long session);
/** Open a session carrying a caller-supplied wire session_id (no token
 *  OPEN_SESSION); for bring-up/debug or driving a specific id. Needs the NCMP
 *  standalone facade (NCMP_OpenSessionWithId); returns APP_ERR_NO_FUNC otherwise. */
int app_session_adopt(unsigned long slot, unsigned long wire_sid,
                      unsigned long *out_session);
int app_login(unsigned long session, int user_type, const char *pin);
int app_logout(unsigned long session);

/** Crypto / hash. */
int app_generate_random(unsigned long session, unsigned char *out, int n);
int app_digest(unsigned long session, unsigned long mech,
               const unsigned char *in, int in_len,
               unsigned char *out, int cap, int *out_len);
/**
 * Multipart digest (C_DigestInit -> C_DigestUpdate* -> C_DigestFinal) over an
 * arbitrary-size buffer, feeding it to the token in <= chunk-byte parts. This
 * is the init/update/final path required for data larger than one wire frame
 * (>= 64 KB). chunk <= 0 selects a safe default.
 */
int app_digest_multipart(unsigned long session, unsigned long mech,
                         const unsigned char *data, long data_len, int chunk,
                         unsigned char *out, int cap, int *out_len);
/** Generate an AES key then C_Encrypt/C_Decrypt (AES-GCM) round-trip; detail
 *  string filled. Returns 0 on success (round-trip matched). */
int app_aes_gcm_selftest(unsigned long session, char *detail, int cap);

/** AES-GCM one-shot with a caller-supplied key (C_CreateObject + C_Encrypt/
 *  C_Decrypt). Encrypt output is ciphertext||tag; decrypt input is
 *  ciphertext||tag. *io_len in=out buffer cap, out=produced. Returns 0/CK_RV. */
int app_aes_gcm(unsigned long session, int encrypt,
                const unsigned char *key, unsigned long key_len,
                const unsigned char *iv, unsigned long iv_len,
                const unsigned char *aad, unsigned long aad_len,
                unsigned long tag_bytes,
                const unsigned char *in, unsigned long in_len,
                unsigned char *out, unsigned long *io_len);

/** AES-CTR one-shot with a caller-supplied key + 16-byte counter block. Returns
 *  0/CK_RV; *io_len in=cap, out=produced. */
int app_aes_ctr(unsigned long session, int encrypt,
                const unsigned char *key, unsigned long key_len,
                const unsigned char *counter,
                const unsigned char *in, unsigned long in_len,
                unsigned char *out, unsigned long *io_len);

/** Human-readable last error (never NULL). */
const char *app_last_error(void);
/** Set the last-error string (used by the web layer for arg validation). */
void app_set_last_error(const char *msg);

#ifdef __cplusplus
}
#endif

#endif /* NCMP_TESTAPP_H */

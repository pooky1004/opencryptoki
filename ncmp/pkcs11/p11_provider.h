/*
 * Token NCMP - Self-contained PKCS#11 provider (internal declarations).
 *
 * libpkcs11_ncmp.so can be loaded directly by an application: it exports the
 * standard C_GetFunctionList / C_GetInterfaceList / C_GetInterface entry
 * points and returns version-specific CK_FUNCTION_LIST tables (2.40 / 3.0 /
 * 3.2). Every C_* function marshals its arguments and forwards the crypto
 * operation to the ncmpd daemon over the shared-memory transport
 * (ncmp_client_*); ncmpd multiplexes many client threads across many processes
 * onto the single USB token.
 *
 * State model (per process; the .so is mapped once per process even if
 * dlopen()ed from several places):
 *   - One global lock guards the provider bookkeeping (sessions, objects, login
 *     state). It is a fast per-process mutex, NOT the SHM robust mutex; the
 *     latter (owned by ncmpd) coordinates the token across processes.
 *   - The lock is released around every blocking token round-trip so that
 *     threads run concurrently through the lock-free ncmp transport - the
 *     library serialises only its own metadata, never the datapath.
 *
 * Style: Google C Style, Doxygen on every function. Code/comments in English.
 */
#ifndef NCMP_P11_PROVIDER_H
#define NCMP_P11_PROVIDER_H

#include <pkcs11types.h>
#include <apiclient.h> /* prototypes for every C_* entry point (2.40/3.0/3.2) */
#include <pthread.h>
#include <stdint.h>

#include "ncmp/ncmp_client.h"
#include "ncmp/ncmp_limits.h"

/* -------------------------------------------------------------------------
 * Provider capacity limits (bounded so all state is fixed-size and lock-safe).
 * ------------------------------------------------------------------------- */

/** Slots the provider can expose (mirrors the daemon's physical slot count). */
#define P11_MAX_SLOTS PKCS11_MAX_SLOT_COUNT

/** Concurrent sessions the provider tracks (system-wide ceiling). */
#define P11_MAX_SESSIONS PKCS11_MAX_TOTAL_SESSIONS

/** Objects (keys + data) the provider stores per process. */
#define P11_MAX_OBJECTS 512

/** Attributes stored per object. */
#define P11_MAX_ATTRS 40

/** Largest single attribute value stored (bytes) - fits an RSA-4096 modulus. */
#define P11_MAX_ATTR_LEN 1024

/** Largest buffered multipart plaintext/ciphertext (bytes). */
#define P11_MAX_OP_BUF (32 * 1024)

/* -------------------------------------------------------------------------
 * Object model.
 * ------------------------------------------------------------------------- */

/** One stored attribute (owns a heap copy of its value). */
typedef struct p11_attr {
    CK_ATTRIBUTE_TYPE type; /**< CKA_* attribute type. */
    CK_ULONG          len;  /**< Value length in bytes. */
    void             *val;  /**< Heap copy of the value (NULL if len == 0). */
} p11_attr_t;

/** One PKCS#11 object (key or data). Lives in the per-process object store. */
typedef struct p11_object {
    int               in_use;  /**< Slot occupied. */
    CK_OBJECT_HANDLE  handle;  /**< Application-visible handle (never 0). */
    CK_SLOT_ID        slot;    /**< Owning CK slot id. */
    CK_SESSION_HANDLE session; /**< Owning session (0 for token objects). */
    int               is_token;   /**< CKA_TOKEN. */
    int               is_private; /**< CKA_PRIVATE. */
    p11_attr_t        attrs[P11_MAX_ATTRS];
    int               n_attrs;
} p11_object_t;

/* -------------------------------------------------------------------------
 * Per-session cryptographic operation context.
 * ------------------------------------------------------------------------- */

/** Active operation kind held in a session context slot. */
typedef enum p11_op_kind {
    P11_OP_NONE = 0,
    P11_OP_ENCRYPT,
    P11_OP_DECRYPT,
    P11_OP_DIGEST,
    P11_OP_SIGN,
    P11_OP_VERIFY
} p11_op_kind_t;

/** State for one in-progress operation (per session, per direction). */
typedef struct p11_opctx {
    p11_op_kind_t     kind;   /**< P11_OP_NONE when idle. */
    CK_MECHANISM_TYPE mech;   /**< CKM_* mechanism. */
    CK_OBJECT_HANDLE  key;    /**< Key object handle (0 for keyless digest). */
    int               message; /**< Non-zero for a message-based operation. */

    /* Captured mechanism parameters (copied at *Init time). */
    uint8_t  iv[16];
    uint32_t iv_len;
    uint8_t  aad[512];
    uint32_t aad_len;
    uint32_t tag_len;         /**< AEAD tag length in bytes. */

    /* Multipart buffering / token-side digest context. */
    uint8_t *buf;             /**< Accumulated plaintext/ciphertext/data. */
    uint32_t buf_len;
    uint32_t buf_cap;
    uint32_t digest_ctx;      /**< Token multipart digest id, or NONE. */
} p11_opctx_t;

/** One open session. */
typedef struct p11_session {
    int               in_use;
    CK_SESSION_HANDLE handle;
    CK_SLOT_ID        slot;   /**< CK slot id this session belongs to. */
    CK_FLAGS          flags;
    CK_STATE          state;  /**< CKS_* (recomputed on login/logout). */
    CK_VOID_PTR       app;
    CK_NOTIFY         notify;

    /* Find-objects iteration state. */
    int               find_active;
    CK_OBJECT_HANDLE  find_results[P11_MAX_OBJECTS];
    int               find_count;
    int               find_pos;

    /* Operation contexts (independent per direction, per PKCS#11 rules). */
    p11_opctx_t       enc;
    p11_opctx_t       dec;
    p11_opctx_t       dig;
    p11_opctx_t       sig;
    p11_opctx_t       ver;
} p11_session_t;

/** Per-slot login / token state. */
typedef struct p11_slot_state {
    int          token_present;    /**< Slot is online per the daemon. */
    int          logged_in;        /**< A user/SO is logged in. */
    CK_USER_TYPE user_type;        /**< CKU_USER / CKU_SO when logged in. */
    int          user_pin_set;     /**< CKF_USER_PIN_INITIALIZED. */
} p11_slot_state_t;

/** Process-global provider state. */
typedef struct p11_state {
    int               initialized;
    pthread_mutex_t   lock;        /**< Guards everything below. */
    int               lock_ready;  /**< Lock has been initialized. */

    /* C_Initialize argument handling. */
    int               os_locking;  /**< CKF_OS_LOCKING_OK negotiated. */

    /* Transport to the daemon (one connection per process). */
    ncmp_client_t     client;
    int               client_ready;
    uint32_t          slot_mask;   /**< Online physical slots from the daemon. */

    p11_session_t     sessions[P11_MAX_SESSIONS];
    CK_SESSION_HANDLE next_session;

    p11_object_t      objects[P11_MAX_OBJECTS];
    CK_OBJECT_HANDLE  next_object;

    p11_slot_state_t  slots[P11_MAX_SLOTS];
} p11_state_t;

/** The single process-global provider state instance. */
extern p11_state_t g_p11;

/* -------------------------------------------------------------------------
 * Locking + lifecycle helpers (p11_state.c).
 * ------------------------------------------------------------------------- */

/** @brief Acquire the provider lock (blocks). */
void p11_lock(void);
/** @brief Release the provider lock. */
void p11_unlock(void);

/** @brief True if C_Initialize has completed. Caller need not hold the lock. */
int p11_is_initialized(void);

/**
 * @brief Ensure the daemon connection is established (lazy connect).
 * @return CKR_OK, or CKR_TOKEN_NOT_PRESENT if the daemon is unreachable.
 *         Caller MUST hold the lock.
 */
CK_RV p11_ensure_client(void);

/** @brief Return the shared client handle (valid after p11_ensure_client). */
ncmp_client_t *p11_client(void);

/* -------------------------------------------------------------------------
 * Session helpers (p11_state.c). All require the caller to hold the lock.
 * ------------------------------------------------------------------------- */

/** @brief Look up a session by handle, or NULL. */
p11_session_t *p11_session_get(CK_SESSION_HANDLE h);
/** @brief Allocate a session slot, or NULL when full. */
p11_session_t *p11_session_alloc(void);
/** @brief Release a session and all its session-scoped objects. */
void p11_session_free(p11_session_t *s);

/* -------------------------------------------------------------------------
 * Object + attribute helpers (p11_state.c). Require the lock unless noted.
 * ------------------------------------------------------------------------- */

/** @brief Look up an object by handle, or NULL. */
p11_object_t *p11_object_get(CK_OBJECT_HANDLE h);
/** @brief Allocate an object slot, or NULL when full. */
p11_object_t *p11_object_alloc(void);
/** @brief Release an object and free its attribute values. */
void p11_object_free(p11_object_t *o);

/** @brief Set/replace an attribute value on an object. */
CK_RV p11_obj_set(p11_object_t *o, CK_ATTRIBUTE_TYPE t, const void *v,
                  CK_ULONG len);
/** @brief Find an attribute on an object, or NULL. */
p11_attr_t *p11_obj_attr(p11_object_t *o, CK_ATTRIBUTE_TYPE t);
/** @brief Read a CK_BBOOL attribute, returning @p dflt if absent. */
CK_BBOOL p11_obj_bool(p11_object_t *o, CK_ATTRIBUTE_TYPE t, CK_BBOOL dflt);
/** @brief Read a CK_ULONG attribute, returning @p dflt if absent/short. */
CK_ULONG p11_obj_ulong(p11_object_t *o, CK_ATTRIBUTE_TYPE t, CK_ULONG dflt);

/**
 * @brief Populate an object from a supplied attribute template.
 * @return CKR_OK or a CKR_ error. Caches CKA_TOKEN/CKA_PRIVATE flags.
 */
CK_RV p11_obj_from_template(p11_object_t *o, CK_ATTRIBUTE_PTR tmpl,
                            CK_ULONG count);

/**
 * @brief Test whether an object matches every attribute in a find template.
 * @return Non-zero on a full match.
 */
int p11_obj_matches(p11_object_t *o, CK_ATTRIBUTE_PTR tmpl, CK_ULONG count);

/* -------------------------------------------------------------------------
 * Slot mapping (p11_slotmap.c).
 * ------------------------------------------------------------------------- */

/**
 * @brief Rebuild the CK-slot <-> physical-slot map from the daemon slot mask
 *        and the ncmptok.conf configuration (env NCMP_TOK_CONF / NCMP_SLOT_BASE).
 * @param slot_mask Online physical slot bitmask reported by the daemon.
 */
void p11_slotmap_build(uint32_t slot_mask);

/**
 * @brief Number of CK slots currently exposed (token-present slots only when
 *        @p present_only is set, else all mapped slots).
 */
CK_ULONG p11_slotmap_count(int present_only);

/**
 * @brief Fill @p out with the exposed CK slot ids.
 * @return Number written (bounded by @p cap).
 */
CK_ULONG p11_slotmap_list(int present_only, CK_SLOT_ID *out, CK_ULONG cap);

/**
 * @brief Translate a CK slot id to a physical daemon slot index.
 * @param ck_slot CK slot id from the application.
 * @param out_phys Receives the physical slot index.
 * @return CKR_OK or CKR_SLOT_ID_INVALID.
 */
CK_RV p11_slotmap_phys(CK_SLOT_ID ck_slot, uint32_t *out_phys);

/** @brief Human label configured for a CK slot (never NULL). */
const char *p11_slotmap_label(CK_SLOT_ID ck_slot);

/* -------------------------------------------------------------------------
 * Error mapping (p11_state.c).
 * ------------------------------------------------------------------------- */

/** @brief Map an ncmp transport return code to a CK_RV. */
CK_RV p11_ck_from_ncmp(int ncmp_rc);

/**
 * @brief Copy @p src into a blank-padded PKCS#11 fixed field (no NUL).
 * @param dst Destination CK_CHAR field.
 * @param n   Field size in bytes.
 * @param src Source C string.
 */
void p11_pad(CK_CHAR *dst, size_t n, const char *src);

/* -------------------------------------------------------------------------
 * Transport convenience (p11_state.c): forward a command to the CK slot's
 * physical token, releasing the provider lock around the round-trip.
 * The caller MUST NOT hold the lock when calling these.
 * ------------------------------------------------------------------------- */

/**
 * @brief Forward a single-buffer command to the token behind @p ck_slot.
 * @return CKR_OK on a completed round-trip with an OK ack; otherwise the token
 *         ack (already a CK_RV) or a transport-mapped CK_RV.
 */
CK_RV p11_forward(CK_SLOT_ID ck_slot, uint32_t opcode, const uint8_t *in,
                  uint32_t in_len, uint8_t *out, uint32_t out_cap,
                  uint32_t *out_len);

/**
 * @brief Forward a multi-parameter command to the token behind @p ck_slot.
 * @param out_msg Receives the decoded response (params via ncmp_msg_param).
 * @return CKR_OK when the ack is OK; else the ack/transport CK_RV.
 */
CK_RV p11_forward_mp(CK_SLOT_ID ck_slot, uint32_t opcode,
                     const uint8_t *const in[], const uint32_t in_len[],
                     int n_in, uint8_t *out_payload, uint32_t out_cap,
                     NCMP_Message *out_msg);

/* -------------------------------------------------------------------------
 * Function-list tables + interface discovery (p11_functionlist.c).
 * ------------------------------------------------------------------------- */

/** @brief Return the v2.40 function list. */
CK_FUNCTION_LIST *p11_function_list_240(void);
/** @brief Return the v3.0 function list. */
CK_FUNCTION_LIST_3_0 *p11_function_list_30(void);
/** @brief Return the v3.2 function list. */
CK_FUNCTION_LIST_3_2 *p11_function_list_32(void);

#endif /* NCMP_P11_PROVIDER_H */

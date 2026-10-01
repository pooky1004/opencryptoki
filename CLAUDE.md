# CLAUDE.md — Token NCMP (opencryptoki private fork)

Lightweight rules file. Deep design lives in `docs/architecture.md` and
`docs/INDEX.md` — read those on demand to keep context small.

## What this project is
A new PKCS#11 token, **Token NCMP**, added to this opencryptoki fork. The
physical token is a Cypress EZ-USB FX3 board (CYUSB3KIT-003) reached over USB
via libusb. A standalone daemon `ncmpd` multiplexes many client threads across
many processes onto the single USB link. `ncmpd` is NOT a replacement for, or
hook into, `pkcsslotd` — it is a separate pipe/proxy daemon.

## Modules (all under `ncmp/`)
- **A — `ncmpd`** (`ncmp/daemon/`): system daemon; owns SHM + USB; 1 connection
  thread, up to 4 comm threads (1 per active slot). Must run before the STDLL
  loads.
- **B — `libpkcs11_ncmp.so`** (STDLL, `usr/lib/ncmp_stdll/`): opencryptoki
  token; C_* API comes from opencryptoki `new_host.c`, crypto from
  `token_specific` (`usr/lib/ncmp_stdll/ncmp_specific.c` + `tok_struct.h`).
  Each callback extracts key material from OBJECT templates and forwards through
  the pure-buffer `ncmp_crypto` marshalling adapter. Transport + adapter live in
  `ncmp/stdll/` (ncmp_client/session/ckr/crypto).
- **C — `mock_token_ncmp`** (`ncmp/mock/`): SW emulator of the FX3 datapath;
  enabled with `-DENABLE_MOCK_TOKEN=ON`.
- **D — tests** (`ncmp/tests/`): C suite for APIs, concurrency, limits, stats,
  single-shot frame read, robust-mutex recovery, ACK errors.
- Shared primitives: `ncmp/common/`, public headers `ncmp/include/ncmp/`.

## Tech stack
- Language: C11. Build: CMake (>= 3.16). Transport: libusb-1.0.
- Concurrency: POSIX threads, process-shared robust mutexes, C11/GCC atomics.
- IPC: UNIX domain socket (control only) + POSIX shared memory (bulk data).

## Directory map (`ncmp/`)
```
include/ncmp/   ncmp_limits.h ncmp_wire.h ncmp_mutex.h ncmp_queue.h
                ncmp_shm.h ncmp_ipc.h ncmp_errno.h   (shared public headers)
common/         ncmp_mutex.c ncmp_queue.c ncmp_wire.c ncmp_shm.c
                ncmp_slot.c ncmp_slotmap.c ncmp_ipc.c
daemon/         main.c conn_thread.c comm_thread.c usb_transport.c  (Module A)
stdll/          ncmp_client.c ncmp_session.c ncmp_ckr.c ncmp_crypto.c
                ncmp_admin.c  (Module B transport + crypto/admin adapters;
                token_specific SPI is in usr/lib/ncmp_stdll/)
mock/           mock_main.c fx3_dma.c container.c mcu_scheduler.c   (Module C)
tests/          test_*.c + ncmp_test.h                              (Module D)
cmake/          FindLibUSB.cmake
```

## Token identity, slot binding & login
- At boot `ncmpd` scans each present token's identity (label/serial/manufacturer/
  model/versions) via `NCMP_CMD_VD_TOKEN_INFO` and caches it per physical slot in
  SHM (`NCMP_TokenIdentity` in `ncmp_shm.h`; probe in `daemon/main.c`).
- `t_init` binds a CK slot to a physical token with `ncmp_slot_bind()`
  (`common/ncmp_slotmap.c`): match by desired serial then label, else claim the
  first unallocated online token. The binding is **keyed by CK slot id** and held
  in SHM under `global_lock`, so all processes opening the same CK slot resolve to
  the same token and it persists for the daemon's life (not released on final).
  Desired label/serial come from env `NCMP_TOK_LABEL[<n>]` / `NCMP_TOK_SERIAL[<n>]`
  (per-CK-slot suffix overrides the generic form); unset ⇒ first-free.
- PIN/login lifecycle (`t_login`/`t_logout`/`t_init_pin`/`t_set_pin`/
  `t_init_token`) is forwarded to the physical token via the `ncmp_admin` adapter
  (`stdll/ncmp_admin.c`, opcodes `NCMP_CMD_LOGIN`..`NCMP_CMD_INIT_TOKEN`); the
  mock token stores/verifies PINs (default user `1234`, SO `12345678`).
- `t_login` forwards the role **plus flags**: protected-auth (PIN entered on the
  token pad, empty wire PIN) and context-specific re-auth
  (`CKU_CONTEXT_SPECIFIC`, re-verifies the logged-in user's PIN without changing
  login state).
- `t_init_token` now does set→read-back→validate→persist: it sets PIN+label on
  the token, reads the label back via `NCMP_CMD_VD_TOKEN_INFO` and validates it
  matches, caches the identity into `nv_token_data`, persists it with
  `save_token_data()` (data-store hooks `t_init_token_data`/`t_load_token_data`/
  `t_save_token_data`), then zeroizes the temporary SO-PIN/label buffers. The
  token is a secure-key token (`token_specific.secure_key_token = TRUE`): the
  physical token owns all secrets; the STDLL only proxies and scrubs temporaries.

## Slot map & vendor opcodes
- Slot map: `ncmptok.conf` (env `NCMP_TOK_CONF`) or `NCMP_SLOT_BASE` maps CK
  slot ids to physical ncmpd slots; keep it in sync with `opencryptoki.conf`.
- Vendor-defined wire opcodes (0x0101+: mem read·write·fill·crc / ping /
  selftest / fw / token-info) exercise the token datapath and query device
  state. Echo/loopback is served by `NCMP_CMD_NOP` (no dedicated opcode).
  Token queries `NCMP_CMD_GET_UTC_TIME` (0x0035) and `NCMP_CMD_GET_TOKEN_PARAMS`
  (0x0036, label/serial/ulMin·MaxPinLen) feed `C_GetTokenInfo`. Defined in
  `ncmp/include/ncmp/ncmp_cmd.h`; mock implementation in
  `ncmp/mock/mcu_scheduler.c`.

> Note: the standalone provider now lives **inside** the STDLL as a facade
> (`usr/lib/ncmp_stdll/ncmp_p11.c`), so `libpkcs11_ncmp.so` serves two modes at
> once: ① via libopencryptoki (`SC_*`/`ST_Initialize`), and ② direct
> `dlopen`+`dlsym` of `C_GetFunctionList`/`C_GetInterface(List)`/`C_*`
> (2.40/3.0/3.2). See `docs/dual-mode-provider.md`. (The earlier separate
> `ncmp/pkcs11/` build shape remains removed.)

## Build & test
```bash
cd ncmp && cmake -S . -B build -DENABLE_MOCK_TOKEN=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```
Real hardware build: omit `-DENABLE_MOCK_TOKEN` (requires libusb-1.0 dev pkg).

## Resource limits (STRICT — never exceed)
- `PKCS11_MAX_SLOT_COUNT` = 4
- `PKCS11_MAX_SESSION_PER_SLOT` = 8
- `PKCS11_MAX_TOTAL_SESSIONS` = 32
- Single parameter and combined payload (len array + params) each
  <= `NCMP_DEV_CONTAINER_SIZE - NCMP_WIRE_FRAME_OVERHEAD` = 65512 B, so an
  encoded frame fills exactly one 64 KB device container
  (`NCMP_MAX_FRAME_SIZE == NCMP_DEV_CONTAINER_SIZE`).
- Per-slot in-flight ceiling defaults to the 4 device SRAM containers.
All limits are defined once in `ncmp/include/ncmp/ncmp_limits.h`.

## Concurrency rules (STRICT)
1. **No raw pointers in SHM.** Use array indices or byte offsets only; translate
   with `ncmp_shm_ptr()`. Mappings differ per process.
2. **Robust mutexes only.** Every SHM mutex is `PTHREAD_PROCESS_SHARED` +
   `PTHREAD_MUTEX_ROBUST`. Never call `pthread_mutex_lock/unlock` directly —
   use `ncmp_mutex_lock()` / `ncmp_mutex_unlock()`, which recover `EOWNERDEAD`
   via `pthread_mutex_consistent()`.
3. **Queue state via CAS only.** Never assign an entry state directly; use
   `__atomic_compare_exchange_n` (wrapped by `ncmp_qentry_cas()`). Lifecycle:
   `FREE -> CLAIMED -> POSTED -> SENT -> DONE -> FREE`; timeout:
   `SENT -> ABANDONED`. Multiple producers enqueue to one slot with no
   slot-level lock (MPSC); the slot's comm thread is the sole consumer.
4. **Session counter under lock.** `cur_sessions` is changed ONLY inside
   `sess_lock`; do not swap it for raw atomics. Reject with
   `CKR_SESSION_COUNT_EXCEEDED` at the ceiling.
5. **Async-signal-safety.** Signal handlers set only a
   `volatile sig_atomic_t g_running` flag — no printf/malloc/locks. Each thread
   prints its own in-flight/throughput summary as it exits its loop.

## In-flight stats (per slot, in SHM)
Updated by the comm thread immediately before each USB send:
- `in_flight_cnt` — commands currently inside the token (++ on dispatch,
  -- on response). Checked against `slot->max_inflight` before sending.
- `stats_max_in_flight` — historical peak of `in_flight_cnt`.
- `stats_total_sent_cmds` — total commands transmitted to the token.

## Wire protocol (4-byte aligned, little-endian)
`frame_len(4)` then `NCMP_Header{session_id, sequence_id, command_id, ack,
payload_len}` (20B), then `param_len[8]` (32B), then params 1..8.
`ack` carries a `CKR_*` code in both directions. Invariants:
`frame_len == 20 + payload_len` and
`payload_len == 32 + sum(param_len[i])`. The FX3 bulk IN endpoint is read
**single-shot**: one transfer fills a max-size buffer (`NCMP_MAX_FRAME_SIZE`),
then the frame is parsed - never a header-then-remainder read.
See `ncmp/include/ncmp/ncmp_wire.h`.

## Coding style
- Google C Style. Doxygen comments on every new function.
- Comments, identifiers, and code in **English**; chat explanations in Korean.
- Internal transport errors use `NCMP_ERR_*` (negative); the STDLL maps them to
  `CKR_*` at the PKCS#11 boundary. The token's `ack` field carries `CKR_*`.

## opencryptoki integration (later)
The STDLL plugs in via a `token_spec_t token_specific` (see other tokens'
`tok_struct.h`). Autotools wiring — a `--enable-ncmptok` toggle and an
`ncmp_stdll` dir — is the follow-up step; see `docs/architecture.md`.

## Advertised mechanism surface (token's defined capability)
`ncmp_mech_list` in `usr/lib/ncmp_stdll/ncmp_specific.c` advertises exactly:
- **Symmetric**: AES-GCM, AES-CTR.
- **Hash/XOF**: SHA-256, SHA-512, SHA3-224/256/384/512; SHAKE-128/256 key
  derivation (XOF via `t_shake_key_derive`, opcode `NCMP_CMD_SHAKE_DERIVE`).
- **PQC (PKCS#11 3.2)**: ML-KEM (strengths 1/3/5 = CKP_ML_KEM_512/768/1024) for
  keypair-gen + encapsulate/decapsulate (shared-secret key agreement); ML-DSA
  (strengths 1/3/5 = CKP_ML_DSA_44/65/87) for keypair-gen + sign/verify.
  Strength is selected per key via `CKA_PARAMETER_SET`; opcodes
  `NCMP_CMD_MLDSA_*` / `NCMP_CMD_MLKEM_*`.
PQC keys are opaque blobs stored whole in `CKA_VALUE` (private blob is prefixed
with the public blob); blob sizes come from `struct pqc_oid` (pqc_supported.c).
The standard `t_ml_dsa_*` / `t_ml_kem_*` / `t_shake_key_derive` hooks are used
(NOT the IBM `t_ibm_*` variants). Tests: `ncmp/tests/test_pqc.c`.
The wire opcodes (`enum ncmp_opcode`) and the CI (`CI_Cmd`, defined as opcode
aliases) now contain **only** these mechanisms plus RNG / AES key-gen / admin /
object management — all legacy RSA/EC/DH/ECDH/HMAC/AES-block (CBC·ECB·OFB·CFB)
paths were removed across opcodes, adapters, mock, and tests.

## Object handling
Object CRUD, handle mapping, find, size and destroy are handled generically by
the opencryptoki common object manager (`obj_mgr.c`/`object.c`) + local data
store — no token_specific hook exists for them. As a secure-key token, NCMP only
forwards *key* objects to the physical token: `t_object_add` (C_CreateObject)
sends `NCMP_CMD_OBJECT_ADD` `[class|key_type|value]`, and
`t_set_attribute_values` (C_SetAttributeValue/C_CopyObject) sends
`NCMP_CMD_OBJECT_SET_ATTR` `[class|key_type|attrs]` (attrs = `count` then
`{type|len|value}*`). Non-key objects (data/certificate) stay local.
`t_set_attrs_for_new_object` / `t_check_obj_access` are left NULL (a NULL hook ==
one returning CKR_OK). Adapter `ncmp/stdll/ncmp_object.c`; mock in
`mcu_scheduler.c`; tests `ncmp/tests/test_object.c`.

## Multipart operation context (host-managed option)
Multipart ops (INIT/UPDATE/FINAL families: digest, AES-GCM) keep a per-operation
context. Two placement models, selected at **daemon build time** by the
`NCMP_HOST_MANAGED_CTX` macro (CMake option, default OFF):
- **default (macro off)**: the physical token owns the context. INIT returns a
  context id; UPDATE/FINAL carry the id; the token holds the state.
- **`NCMP_HOST_MANAGED_CTX` (macro on)**: the token is **stateless** (HSM storage
  is scarce). It returns the whole context blob on INIT and every UPDATE, and
  expects it back on UPDATE/FINAL. The daemon's `comm_thread` keeps the blobs
  host-side, keyed by a small id, and bridges the wire so the STDLL is unchanged.
  Convention (see `ncmp_cmd.h`): parameter 0 is the context slot (id STDLL-side,
  blob token-side) on the INIT response and every UPDATE/FINAL request; the
  operation's own data is in parameters 1+. The generic bridge lives in
  `comm_thread.c` (`ctx_xform_request`/`ctx_xform_response`, guarded by the
  macro) and applies to every context-bearing opcode via `ctx_phase_of()`.

Each context-bearing mechanism has its own **typed** context struct
(`ncmp/include/ncmp/ncmp_ctx.h`): `ncmp_ctx_digest_t` (mech, acc) and
`ncmp_ctx_gcm_t`; a common header (type, len) prefixes the serialized blob so the
token and daemon dispatch on it. **Keys are never in a context**: they live in a
token key table (HSM-resident) and the GCM context carries only `key_id`, so the
middleware's stored/relayed context holds no key material (key bytes appear only
in the one-shot INIT request in transit). The daemon inspects only the header.

Context-bearing opcodes: `NCMP_CMD_DIGEST_{INIT,UPDATE,FINAL}` and
`NCMP_CMD_AES_GCM_{INIT,UPDATE,FINAL}`. Aborting a multipart op (context freed
without a `*Final`) releases the context via `NCMP_CMD_CTX_FREE`
`[ctx|kind]`: the STDLL context-free hooks send it when the context is still
live; the daemon frees the host-side slot (`NCMP_HOST_MANAGED_CTX`) or the token
frees its table entry (default). Idempotent; best-effort at teardown. The STDLL reserves
`NCMP_HOST_CTX_BLOB_MAX` headroom in a multipart UPDATE so the id→blob swap never
overflows a frame. Single-shot ops (AES-GCM one-shot, AES-CTR — the CTR counter
rides in each command) hold no cross-call token state and are unaffected.
Adapters: `ncmp_crypto_digest_*` / `ncmp_crypto_aes_gcm_{init,update,final}`;
mock in `mcu_scheduler.c` (both models, `#ifdef`); tests
`test_gcm_multipart.c` + the digest multipart tests, run in both models.

> STDLL PKCS#11 binding: digest multipart (`t_sha_*`) and AES-GCM multipart
> (`t_aes_gcm_update`/`t_aes_gcm_final`) are wired to `C_Encrypt/DecryptUpdate`.
> The GCM hooks reuse the common `AES_GCM_CONTEXT` (`ctx->context`) for
> partial-block buffering as `mech_aes.c` requires — `data[]`/`len` per the
> contract, the token context id + established flag in the unused
> `ulAlen`/`ulClen` — and hold back the tag on decrypt. Status: compiles clean
> against the opencryptoki headers and the wire/adapter/mock path is tested in
> both context models; end-to-end `C_EncryptUpdate` needs a full opencryptoki
> build to exercise (the standalone suite can't load `ncmp_specific.c`).

## PKCS#11 support target
Full PKCS#11 2.x, 3.0, and 3.2; multi-application concurrent access.

## After finishing a task
Prompt the user to summarize progress + remaining work into a `.md` status
file (예: "지금까지 한 일과 남은 과제를 .md 파일로 요약해줘").

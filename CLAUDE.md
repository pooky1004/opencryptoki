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
- **B — `libpkcs11_ncmp.so`**: two build shapes of the same name.
  - *STDLL* (`usr/lib/ncmp_stdll/`): opencryptoki token; C_* API comes from
    opencryptoki `new_host.c`, crypto from `token_specific` (ncmp_specific.c).
  - *Self-contained provider* (`ncmp/pkcs11/`, p11_*.c): directly dlopen-able;
    exports `C_GetFunctionList`/`C_GetInterfaceList`/`C_GetInterface` with
    2.40/3.0/3.2 tables + the **NCMP Vendor** interface (`ncmp_vendor.h`), and
    forwards to `ncmpd`. Separate target (avoids C_* symbol clash with new_host).
  Both share the transport in `ncmp/stdll/` (ncmp_client/session/ckr).
- **C — `mock_token_ncmp`** (`ncmp/mock/`): SW emulator of the FX3 datapath;
  enabled with `-DENABLE_MOCK_TOKEN=ON`.
- **D — tests** (`ncmp/tests/`): C suite for APIs, concurrency, limits, stats,
  2-step read, robust-mutex recovery, ACK errors.
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
daemon/         main.c conn_thread.c comm_thread.c usb_transport.c  (Module A)
stdll/          ncmp_specific.c ncmp_client.c ncmp_session.c        (Module B)
pkcs11/         p11_*.c ncmp_vendor.h   (self-contained PKCS#11 provider, B')
mock/           mock_main.c fx3_dma.c container.c mcu_scheduler.c   (Module C)
tests/          test_*.c + ncmp_test.h                              (Module D)
cmake/          FindLibUSB.cmake
```

## Self-contained PKCS#11 provider (`ncmp/pkcs11/`)
- Per-process state (sessions/objects/login) under one fast mutex; the lock is
  released around every token round-trip so threads run concurrently through the
  lock-free transport. Cross-process session ceiling via the SHM robust counter.
- Slot map: `ncmptok.conf` (env `NCMP_TOK_CONF`) or `NCMP_SLOT_BASE` maps CK
  slot ids to physical ncmpd slots; keep it in sync with `opencryptoki.conf`.
- Vendor callbacks (loopback / mem read·write·fill·crc / ping / selftest / fw /
  inflight / slotmap / loglevel) via wire opcodes 0x0100+.

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
- Single parameter <= 32 KB; combined payload (len array + params) <= 40 KB.
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
`payload_len == 32 + sum(param_len[i])`. Receive is **two-step**: read the
fixed header, parse `payload_len`, then read exactly that many payload bytes.
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

## PKCS#11 support target
Full PKCS#11 2.x, 3.0, and 3.2; multi-application concurrent access.

## After finishing a task
Prompt the user to summarize progress + remaining work into a `.md` status
file (예: "지금까지 한 일과 남은 과제를 .md 파일로 요약해줘").

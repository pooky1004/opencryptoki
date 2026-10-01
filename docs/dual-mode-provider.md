# libpkcs11_ncmp.so 이중 사용 모드 (STDLL + 독립 PKCS#11 provider)

`libpkcs11_ncmp.so` 하나를 **두 가지 방식**으로 쓸 수 있도록 한 설계·구현.

- 모드 1 (기존): App → `libopencryptoki.so`(`C_*`) → dlopen → 이 .so의
  `SC_*`/`ST_Initialize`(opencryptoki STDLL 경로, `usr/lib/common/new_host.c`).
- 모드 2 (신규): App → `dlopen("libpkcs11_ncmp.so")` → `dlsym("C_GetFunctionList"
  /"C_GetInterface"/C_*)` → **독립 PKCS#11 provider 파사드**(`ncmp_p11.c`).

관련: [`cryptoki_app_api.md`](cryptoki_app_api.md)(모드 1 C_*↔SC_*),
[`pure_app_api.md`](pure_app_api.md), [`app-stdll-path-design.md`](app-stdll-path-design.md).

## 1. 두 모드는 한 .so에 공존한다

```
          ┌───────────────────────── libpkcs11_ncmp.so ─────────────────────────┐
 모드 1   │  SC_* + ST_Initialize  (new_host.c, token_specific=ncmp_specific.c)  │
 (경유)   │        ▲ libopencryptoki가 dlopen 후 ST_*로 호출                      │
          │                                                                      │
 모드 2   │  C_GetFunctionList / C_GetInterface(List) / C_*   (ncmp_p11.c)        │
 (직접)   │        ▲ App이 dlopen 후 dlsym으로 직접 호출                          │
          │                                                                      │
          │  공통 하부: ncmp 어댑터(ncmp_crypto/admin/object) + ncmp_client → ncmpd │
          └──────────────────────────────────────────────────────────────────────┘
```

- libopencryptoki는 STDLL의 `C_*`를 호출하지 않고 `ST_Initialize`로 얻은 함수목록의
  `SC_*`만 호출한다. 따라서 `C_*`를 추가 export 해도 **모드 1은 영향 없음**.
- 두 심볼 집합은 서로 **중복 정의가 없다**: `C_*`는 `ncmp_p11.c`만, `SC_*`는
  `new_host.c`만 정의. (api 계층 `api_interface.c`는 STDLL에 링크되지 않음.)

## 2. 모드 2 파사드 (`usr/lib/ncmp_stdll/ncmp_p11.c`)

**완전 독립**: opencryptoki 공통계층(obj_mgr/mech_* 등)을 쓰지 않고, 순수버퍼 **ncmp
어댑터를 직접 호출**해 ncmpd로 간다. 자체적으로 슬롯/세션/오브젝트를 로컬 관리한다.

- `C_Initialize` → `ncmp_client_init()`(ncmpd 연결), online 슬롯 탐색.
- `C_Finalize` → `ncmp_client_fini()`.
- 슬롯/토큰: `C_GetSlotList/SlotInfo`(online 마스크), `C_GetTokenInfo`
  (`ncmp_admin_token_info`), `C_GetMechanismList/Info`(광고 목록).
- 세션: `C_OpenSession/CloseSession/CloseAllSessions/GetSessionInfo`(로컬 테이블),
  `C_Login/Logout`(`ncmp_admin_login/logout`).
- 난수: `C_GenerateRandom`(`ncmp_crypto_rng`).
- 다이제스트: `C_DigestInit/Digest/Update/Final`(`ncmp_crypto_digest*`, 세션별 ctx).
- 대칭: `C_EncryptInit/Encrypt`, `C_DecryptInit/Decrypt` — AES-GCM(`ncmp_crypto_aes_gcm`,
  `CK_GCM_PARAMS` 파싱) / AES-CTR(`ncmp_crypto_aes_stream`, `CK_AES_CTR_PARAMS`).
- 오브젝트: `C_CreateObject/DestroyObject/GetAttributeValue/FindObjects*`(로컬 저장,
  키는 `CKA_VALUE`에 보관). `C_GenerateKey`(AES: RNG로 키 생성 후 로컬 오브젝트).

### 2.1 PKCS#11 버전별 진입점 (2.40 / 3.0 / 3.2)
- `C_GetFunctionList` → 2.40 `CK_FUNCTION_LIST`.
- `C_GetInterfaceList` / `C_GetInterface("PKCS 11", version)` → 3.0/3.2/2.40 중 선택
  (`CK_FUNCTION_LIST_3_0` / `CK_FUNCTION_LIST_3_2`). 버전 미지정 시 최신(3.2).
- 세 함수목록은 `FILL_CORE` 매크로로 2.40 공통부를 lockstep 채우고, 3.x는
  `C_GetInterface(List)`만 추가로 노출(message/async 등 나머지는 NULL=미제공).

## 3. 빌드 배선
- `usr/lib/ncmp_stdll/ncmp_stdll.mk`: `ncmp_p11.c`를 SOURCES에 추가(어댑터·ncmp_client·
  공통 ncmp는 이미 포함).
- `opencryptoki_tok.map`: 버전 노드에 `C_*`(2.40 전체) + `C_GetFunctionList` +
  `C_GetInterfaceList`/`C_GetInterface` 심볼을 추가 export(그 외 `local: *;` 유지).

## 4. 사용 예 (모드 2)

```c
void *h = dlopen("libpkcs11_ncmp.so", RTLD_NOW);
CK_RV (*get)(CK_FUNCTION_LIST_PTR_PTR) = dlsym(h, "C_GetFunctionList");
CK_FUNCTION_LIST_PTR fl; get(&fl);
fl->C_Initialize(NULL);
CK_SLOT_ID slots[4]; CK_ULONG n = 4; fl->C_GetSlotList(CK_TRUE, slots, &n);
CK_SESSION_HANDLE s;
fl->C_OpenSession(slots[0], CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL, NULL, &s);
fl->C_Login(s, CKU_USER, (CK_CHAR*)"1234", 4);
CK_BYTE r[16]; fl->C_GenerateRandom(s, r, sizeof r);
/* 3.x: */ CK_INTERFACE_PTR itf; CK_RV (*gi)(CK_UTF8CHAR*,CK_VERSION*,CK_INTERFACE**,CK_FLAGS)
          = dlsym(h, "C_GetInterface"); gi((CK_UTF8CHAR*)"PKCS 11", NULL, &itf, 0);
```
> **전제**: `ncmpd`가 떠 있어야 한다(`C_Initialize`가 ncmpd에 연결). pkcsslotd는 불필요.

## 5. 구현/검증 상태
- **구현 완료**: 위 wired 연산 + 2.40/3.0/3.2 함수목록·인터페이스. `ncmp_p11.c`는
  opencryptoki+ncmp 헤더로 **gcc 경고 0 컴파일 확인**(`-Wall -Wextra`).
- **미구현(현재 `CKR_FUNCTION_NOT_SUPPORTED`)**: 서명/검증(`C_Sign*`/`C_Verify*`),
  PQC(`C_GenerateKeyPair`/encaps/decaps), `C_DeriveKey`(SHAKE), wrap/unwrap, 멀티파트
  encrypt/decrypt, dual-function, message/async(3.x). ML-DSA/ML-KEM/SHAKE 어댑터는
  이미 있으므로 C_* 배선은 후속으로 가능(§6).
- **런타임 검증**: full opencryptoki 빌드 + 기동된 ncmpd 필요 → 이 환경에선 불가(컴파일
  까지). 빌드 환경에서 `pkcs11-tool --module ./libpkcs11_ncmp.so ...`로 확인 가능.

## 5.0 모드 2에서 C_Initialize가 실제로 하는 일 (ncmpd 연동)

모드 2 `C_Initialize`는 facade가 `ncmp_client_init()`를 호출해 **ncmpd의 conn 스레드에
접속(IPC HELLO/ATTACH)하고 공유메모리(동적 메모리)를 부착**한다. 이후:

- `C_GetSlotList`는 ncmpd가 HELLO로 돌려준 **online 슬롯 마스크**(SHM 기준)를 반환.
- `C_OpenSession(slot)`은 그 **slot 값으로 SHM의 해당 슬롯**(`ncmp_shm_slot`)을 가리킨다.
- 각 `C_*`(예: `C_GenerateRandom`)는 어댑터→`ncmp_client_command_mp`→`ncmp_slot_enqueue`
  로 **해당 슬롯의 링 큐에 인큐**하고, ncmpd의 **comm 스레드가 큐를 드레인**해 토큰(실
  USB 또는 mock)으로 보낸 뒤 응답을 돌려준다.

즉 `dlopen → dlsym → C_Initialize`가 곧바로 ncmpd 전송 경로(conn 스레드 + SHM + 슬롯
큐)에 연결된다. 비-root에서는 `NCMP_SOCK_PATH`로 ncmpd와 클라이언트가 같은 UNIX 소켓을
공유하면 된다(기본값 `/run/ncmpd/ncmpd.sock`은 root 필요).

### 5.0.1 풀빌드 없이 돌려보는 데모 (검증됨)
opencryptoki 전체 빌드 없이 **모드 2 전용 provider**와 mock 데몬만 빌드해 실행한다:
```bash
sh ncmp/gui/build_standalone_p11.sh                # → build-standalone/{libpkcs11_ncmp_p11.so, ncmpd}
export NCMP_SOCK_PATH=/tmp/ncmpd.sock
./ncmp/gui/build-standalone/ncmpd --transport mock &   # SHM 생성 + conn/comm 스레드(mock 대상)
NCMP_PKCS11_MODULE=$PWD/ncmp/gui/build-standalone/libpkcs11_ncmp_p11.so \
    python3 ncmp/gui/py/app_gui.py                 # PKCS#11 탭 → Load+Open → GenerateRandom
```
- `build_standalone_p11.sh`는 facade(`ncmp_p11.c`) + ncmp 어댑터/클라이언트/common 으로
  **`libpkcs11_ncmp_p11.so`**(C_* 만, 모드 2 전용)와 **`ncmpd`**(전 백엔드; `--transport`로
  real/mock/socket 선택)을 gcc로 빌드한다.
  (운영용 `libpkcs11_ncmp.so`는 autotools 빌드로 SC_*/ST_Initialize(모드 1)까지 포함.)
- **검증**: GUI의 ctypes 링크로 이 `.so`를 dlopen → `C_Initialize`(ncmpd 접속+SHM) →
  `C_GetSlotList=[0]` → `C_OpenSession` → `C_GenerateRandom(16)` = `5a5b5c…`(mock RNG와
  정확히 일치) 까지 **실 ncmpd(mock)에 대해 end-to-end 통과**.

## 5.1 Test App GUI의 모드 2 사용

`ncmp/gui/py/app_gui.py`의 **"PKCS#11 (real stack)" 탭**이 모드 2로 동작한다
(어댑터 `ncmp/gui/py/ncmp_gui/pkcs11_ctypes.py`, **ctypes만** 사용 — PyKCS11·
libopencryptoki 불사용):
- **Resolve (dlsym)**: `.so`를 dlopen 하고 `C_GetFunctionList`/`C_GetInterfaceList`/
  `C_GetInterface` 를 dlsym 으로 찾았는지 표시(모드 2 발견 과정 시연).
- **Load+Open**: dlopen → `C_Initialize` → `C_GetSlotList` → `C_OpenSession`.
  `C_Initialize`(ncmpd conn 스레드 접속)가 **실패하면 ncmpd 생존을 진단**한다:
  - ncmpd가 **살아있는데 연결 실패** → 경고 팝업(버전/SHM 불일치 등, 로그 확인 안내).
  - ncmpd가 **미실행** → "실행할까요?" 팝업 → 예 선택 시 ncmpd 데몬을 실행하고
    `C_Initialize`를 자동 재시도. (ncmpd 바이너리는 `NCMP_DAEMON` 또는 자동 탐색,
    없으면 파일 선택. 소켓은 `NCMP_SOCK_PATH` 공유. GUI가 띄운 ncmpd는 종료 시 정리.)
- **Login / GenerateRandom / Digest / AES-GCM / Token Info / Close**: 각 `C_*` 직접 호출.
- 모듈 경로 기본값은 `libpkcs11_ncmp.so`(env `NCMP_PKCS11_MODULE` 우선, Browse 가능).
- 검증: stub `.so`로 dlopen+dlsym+호출 경로를 종단 확인(C_Initialize/SlotList/
  OpenSession/GenerateRandom/Finalize). 실 `.so`는 빌드 + 기동된 ncmpd 필요.

## 6. 후속
1. `C_Sign/Verify`(ML-DSA), `C_GenerateKeyPair`(ML-DSA/ML-KEM),
   `C_EncapsulateKey/DecapsulateKey`(ML-KEM), `C_DeriveKey`(SHAKE)를 기존 어댑터로 배선.
2. 멀티파트 `C_EncryptUpdate/Final`(AES-GCM) 배선(`ncmp_crypto_aes_gcm_*`).
3. 모드 2에서도 세션을 토큰 세션 CI(OPEN/CLOSE_SESSION)와 연동(선택).
4. 빌드 환경 end-to-end 검증(pkcs11-tool / PyKCS11).

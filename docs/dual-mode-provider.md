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

## 6. 후속
1. `C_Sign/Verify`(ML-DSA), `C_GenerateKeyPair`(ML-DSA/ML-KEM),
   `C_EncapsulateKey/DecapsulateKey`(ML-KEM), `C_DeriveKey`(SHAKE)를 기존 어댑터로 배선.
2. 멀티파트 `C_EncryptUpdate/Final`(AES-GCM) 배선(`ncmp_crypto_aes_gcm_*`).
3. 모드 2에서도 세션을 토큰 세션 CI(OPEN/CLOSE_SESSION)와 연동(선택).
4. 빌드 환경 end-to-end 검증(pkcs11-tool / PyKCS11).

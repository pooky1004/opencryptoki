# NCMP 애플리케이션 API — `libpkcs11_ncmp.so` 함수 레퍼런스

opencryptoki 애플리케이션이 `libpkcs11_ncmp.so`(STDLL)를 통해 사용하는 **모든
공개 API 함수**의 **기능 / 원형 및 인자 / 반환값**을 정리한다.

## 이 문서가 다루는 API 표면

`libpkcs11_ncmp.so`가 실제로 export 하는 심볼은 버전 스크립트
[`opencryptoki_tok.map`](../opencryptoki_tok.map)의 `global:` 목록 = **73개**이며
(`local: *;`로 나머지는 모두 숨겨진다), 그 실체는 `usr/lib/common/new_host.c`의
`SC_*` 함수들이다. 애플리케이션은 이 심볼을 직접 호출하지 않고 다음 경로로 사용한다.

```
app → libopencryptoki (C_*, api 계층) → dlopen 된 STDLL(function_list.ST_*) → SC_*
                                                                              → token_specific 훅 → ncmp/stdll 어댑터 → ncmpd → FX3 토큰
```

즉 애플리케이션이 호출하는 것은 표준 PKCS#11 `C_*`이고, 그 호출은 STDLL의 `ST_*`
함수 포인터(= 이 문서의 `SC_*`)로 1:1 위임된다. 따라서 각 함수는 **애플리케이션이
호출하는 `C_*` 이름**과 **STDLL이 export 하는 `SC_*` 원형**을 함께 표기한다.

- **`SC_*` 공통 인자**: 모든 `SC_*`는 첫 인자로 `STDLL_TokData_t *tokdata`(토큰
  인스턴스 데이터, api 계층이 주입)를 받고, 세션 기반 함수는 이어서
  `ST_SESSION_HANDLE *sSession`(= `ST_SESSION_T *`, 슬롯 id + 세션 핸들 쌍)을 받는다.
  애플리케이션의 `C_*`에서는 이 자리에 `CK_SESSION_HANDLE hSession` 하나만 노출된다.
- **반환형**: 모든 함수는 PKCS#11 `CK_RV`(= `unsigned long`, `CKR_*`)를 반환한다.

## 반환값 공통 규약

개별 함수의 "반환값"은 아래 공통값 위에 **함수 고유 값만** 추가로 명시한다.

- `CKR_OK` — 성공.
- `CKR_CRYPTOKI_NOT_INITIALIZED` — `C_Initialize` 이전 호출.
- `CKR_SESSION_HANDLE_INVALID` — (세션 함수) 잘못된 세션 핸들.
- `CKR_ARGUMENTS_BAD` / `CKR_BUFFER_TOO_SMALL` — 인자 오류 / 출력 버퍼 부족.
- `CKR_HOST_MEMORY` / `CKR_GENERAL_ERROR` — 내부 자원/일반 오류.
- **전송 계층 실패**(ncmpd 부재·USB 오류·타임아웃)는 STDLL 어댑터의
  `ncmp_err_to_ckr()`를 거쳐 `CKR_TOKEN_NOT_PRESENT` / `CKR_DEVICE_ERROR` /
  `CKR_FUNCTION_CANCELED` / `CKR_DEVICE_MEMORY` 등으로 매핑된다(→
  [`middleware_api.md`](middleware_api.md)).
- **토큰이 거부**하면 물리 토큰이 실은 `ack`(그대로 `CKR_*`)가 그대로 반환된다.

## NCMP 지원 범위 (중요)

NCMP는 **secure-key 프록시 토큰**이라 `token_specific`
([`tok_struct.h`](../usr/lib/ncmp_stdll/tok_struct.h))에 채워진 훅만 실제 동작한다.
NULL 훅에 대응하는 연산은 공통 계층이 **`CKR_MECHANISM_INVALID` /
`CKR_FUNCTION_NOT_SUPPORTED`**로 거부한다. 광고 메커니즘은 AES-GCM·AES-CTR,
SHA-256/512·SHA3-224/256/384/512, SHAKE-128/256(KDF), ML-KEM(1/3/5)·ML-DSA(1/3/5),
RNG, AES 키 생성뿐이다. RSA·EC·DH·ECDH·HMAC·AES-블록(CBC/ECB/OFB/CFB)·키 wrap 은
지원하지 않는다. 각 함수의 "반환값"에 지원/미지원을 명시한다.

관련: [`stdll-call-flow.md`](stdll-call-flow.md)(호출 흐름),
[`command-interface.md`](command-interface.md)(opcode별 request/response),
[`middleware_api.md`](middleware_api.md)(STDLL 내부 어댑터),
[`architecture.md`](architecture.md).

---

## 0. 타입 · 구조체 · 상수

아래 함수 원형에 등장하는 구조체와 `#define`을 먼저 정리한다. 출처는 PKCS#11 표준
헤더 [`usr/include/pkcs11types.h`](../usr/include/pkcs11types.h), STDLL 계층
[`usr/include/stdll.h`](../usr/include/stdll.h), NCMP 한계 상수
[`ncmp/include/ncmp/ncmp_limits.h`](../ncmp/include/ncmp/ncmp_limits.h) /
[`ncmp_cmd.h`](../ncmp/include/ncmp/ncmp_cmd.h)이다.

### 0.1 STDLL 진입점 인자 타입 (애플리케이션에는 노출되지 않음)

`SC_*` 원형의 첫 인자들은 api 계층이 주입하는 STDLL 내부 타입이다. **애플리케이션이
호출하는 `C_*`에는 나타나지 않는다**(대신 `CK_SESSION_HANDLE hSession` 하나로 노출).

```c
/* 토큰 인스턴스 데이터: 슬롯별 nv_token_data, private_data(ncmp_client_t 등),
 * 세션/오브젝트 상태를 담는 불투명 핸들. api 계층이 슬롯 로드시 생성해 넘긴다. */
typedef struct _STDLL_TokData_t STDLL_TokData_t;   /* 정의는 host_defs.h */

/* 세션 핸들 = (슬롯 id, 세션 핸들, R/W 여부) 쌍. app의 CK_SESSION_HANDLE 하나가
 * api 계층에서 이 구조체로 변환되어 SC_*에 전달된다. */
typedef struct {
    struct bt_ref_hdr hdr;      /* 레퍼런스 카운트 헤더(내부) */
    CK_SLOT_ID        slotID;   /* 슬롯 id */
    CK_SESSION_HANDLE sessionh; /* 세션 핸들 */
    CK_BBOOL          rw_session; /* R/W 세션 여부 */
} ST_SESSION_T;
typedef ST_SESSION_T ST_SESSION_HANDLE;   /* 동의어 */

typedef struct API_Slot_t     API_Slot_t;      /* ST_Initialize용 슬롯 엔트리(불투명) */
typedef struct trace_handle_t trace_handle;    /* 트레이스 핸들(불투명) */
/* SLOT_INFO: opencryptoki.conf의 슬롯 설정(slotmgr.h). */
```

### 0.2 PKCS#11 표준 구조체 (인자로 직접 쓰임)

```c
/* 메커니즘 지정: CK_MECHANISM_PTR로 EncryptInit/SignInit/DeriveKey 등에 전달 */
typedef struct CK_MECHANISM {
    CK_MECHANISM_TYPE mechanism;     /* CKM_AES_GCM, CKM_ML_DSA, CKM_SHAKE_256_KDF ... */
    CK_VOID_PTR       pParameter;    /* 메커니즘 파라미터(예: CK_GCM_PARAMS) */
    CK_ULONG          ulParameterLen;/* 파라미터 바이트 수 */
} CK_MECHANISM;

/* 오브젝트 속성 하나: CK_ATTRIBUTE_PTR 배열로 템플릿을 구성 */
typedef struct CK_ATTRIBUTE {
    CK_ATTRIBUTE_TYPE type;          /* CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE, CKA_PARAMETER_SET ... */
    CK_VOID_PTR       pValue;        /* 값 버퍼(NULL이면 길이 조회) */
    CK_ULONG          ulValueLen;    /* 값 바이트 수 */
} CK_ATTRIBUTE;

/* C_GetSessionInfo 출력 */
typedef struct CK_SESSION_INFO {
    CK_SLOT_ID slotID;               /* 슬롯 id */
    CK_STATE   state;                /* RO/RW·public/user/SO 상태 */
    CK_FLAGS   flags;                /* CKF_SERIAL_SESSION | CKF_RW_SESSION */
    CK_ULONG   ulDeviceError;        /* 디바이스 의존 오류 코드 */
} CK_SESSION_INFO;

/* C_GetTokenInfo 출력 (NCMP는 VD_TOKEN_INFO/GET_TOKEN_PARAMS/GET_UTC_TIME로 채움) */
typedef struct CK_TOKEN_INFO {
    CK_CHAR    label[32];            /* 라벨(공백 패딩) */
    CK_CHAR    manufacturerID[32];   /* 제조사 */
    CK_CHAR    model[16];            /* 모델 */
    CK_CHAR    serialNumber[16];     /* 시리얼 */
    CK_FLAGS   flags;                /* 토큰 flags */
    CK_ULONG   ulMaxSessionCount;    /* 최대 세션 수 */
    CK_ULONG   ulSessionCount;       /* 현재 세션 수 */
    CK_ULONG   ulMaxRwSessionCount;  /* 최대 R/W 세션 수 */
    CK_ULONG   ulRwSessionCount;     /* 현재 R/W 세션 수 */
    CK_ULONG   ulMaxPinLen;          /* 최대 PIN 길이 */
    CK_ULONG   ulMinPinLen;          /* 최소 PIN 길이 */
    CK_ULONG   ulTotalPublicMemory;  /* (해당 없으면 CK_UNAVAILABLE_INFORMATION) */
    CK_ULONG   ulFreePublicMemory;
    CK_ULONG   ulTotalPrivateMemory;
    CK_ULONG   ulFreePrivateMemory;
    CK_VERSION hardwareVersion;      /* 하드웨어 버전 */
    CK_VERSION firmwareVersion;      /* 펌웨어 버전 */
    CK_CHAR    utcTime[16];          /* UTC 시각 */
} CK_TOKEN_INFO;

/* C_GetMechanismInfo 출력 */
typedef struct CK_MECHANISM_INFO {
    CK_ULONG ulMinKeySize;           /* 최소 키 크기 */
    CK_ULONG ulMaxKeySize;           /* 최대 키 크기 */
    CK_FLAGS flags;                  /* CKF_ENCRYPT/DECRYPT/SIGN/VERIFY/DERIVE ... */
} CK_MECHANISM_INFO;

typedef struct CK_VERSION {          /* CK_TOKEN_INFO 내 버전 필드 */
    CK_BYTE major;                   /* 정수부 */
    CK_BYTE minor;                   /* 1/100 단위 소수부 */
} CK_VERSION;
```

### 0.3 스칼라 · 포인터 타입 요약

| 타입 | 의미 |
|------|------|
| `CK_RV` | 반환 코드(`unsigned long`, `CKR_*`). 모든 API의 반환형. |
| `CK_SLOT_ID` / `CK_SESSION_HANDLE` / `CK_OBJECT_HANDLE` | 슬롯 · 세션 · 오브젝트 식별자(`CK_ULONG`). |
| `CK_ULONG` / `CK_ULONG_PTR` | 부호 없는 정수 / 그 포인터(길이 in/out에 사용). |
| `CK_BYTE_PTR` / `CK_CHAR_PTR` | 바이트 · 문자 버퍼 포인터(데이터·PIN·라벨). |
| `CK_FLAGS` | 비트 플래그(`CK_ULONG`). |
| `CK_MECHANISM_TYPE` / `CK_USER_TYPE` / `CK_STATE` | 메커니즘 · 사용자 역할 · 세션 상태 열거값. |
| `CK_BBOOL` | 불리언(`CK_TRUE`/`CK_FALSE`). |
| `CK_VOID_PTR` | 임의 포인터(예약·파라미터). |
| `..._PTR` (`CK_MECHANISM_PTR` 등) | 위 구조체의 포인터형(`CK_MECHANISM *` 등). |

### 0.4 주요 상수 · `#define`

**세션 flags** (`C_OpenSession` / `CK_SESSION_INFO.flags`):

| 상수 | 값 | 의미 |
|------|----|------|
| `CKF_SERIAL_SESSION` | `0x00000004` | 직렬 세션(필수). |
| `CKF_RW_SESSION` | `0x00000002` | 읽기/쓰기 세션(미설정 시 RO). |
| `CKF_DONT_BLOCK` | `1` | `C_WaitForSlotEvent` 논블로킹 폴링. |

**사용자 역할** (`C_Login` / `SC_Login`의 `userType`):

| 상수 | 의미 |
|------|------|
| `CKU_SO` | 보안 담당자(Security Officer). |
| `CKU_USER` | 일반 사용자. |
| `CKU_CONTEXT_SPECIFIC` | 진행 중 연산에 대한 재인증(로그인 상태 유지). |

**NCMP 자원 한계** ([`ncmp_limits.h`](../ncmp/include/ncmp/ncmp_limits.h) — 세션
관리/멀티파트 청크 크기의 근거):

| 상수 | 값 | 의미 |
|------|----|------|
| `PKCS11_MAX_SLOT_COUNT` | 4 | 최대 CK 슬롯 수. |
| `PKCS11_MAX_SESSION_PER_SLOT` | 8 | 슬롯당 최대 세션(`C_OpenSession` 상한). |
| `PKCS11_MAX_TOTAL_SESSIONS` | 32 | 전체 세션 상한(`4 × 8`). |
| `NCMP_MAX_PARAM_SIZE` | 65512 | 단일 파라미터 최대 바이트(프레임 1개=64KB 컨테이너). |
| `NCMP_HOST_CTX_BLOB_MAX` | 256 | 멀티파트 UPDATE에서 id→blob 치환 대비 예약 헤드룸. |
| `NCMP_MP_UPDATE_MAX_DATA` | 파생 | `Digest/EncryptUpdate` 1회 최대 데이터(위 헤드룸을 뺀 값, `ncmp_specific.c`). |

**메커니즘 상수**(`CK_MECHANISM.mechanism`): 지원 목록은
`CKM_AES_GCM`, `CKM_AES_CTR`, `CKM_AES_KEY_GEN`, `CKM_SHA256`, `CKM_SHA512`,
`CKM_SHA3_224/256/384/512`, `CKM_SHAKE_128_KDF`, `CKM_SHAKE_256_KDF`,
`CKM_ML_DSA`·`CKM_ML_DSA_KEY_PAIR_GEN`, `CKM_ML_KEM`·`CKM_ML_KEM_KEY_PAIR_GEN`
뿐이다(→ [NCMP 지원 범위](#ncmp-지원-범위-중요)). strength는 키의
`CKA_PARAMETER_SET`로 선택한다.

---

## 1. 초기화 · 함수 목록 (인프라 진입점)

### 1.1 `ST_Initialize` (app: `C_Initialize` 경로)
- **기능**: STDLL 토큰 인스턴스를 초기화하는 진입점. api 계층이 슬롯 로딩 시 호출하며
  `token_specific.t_init`(`token_specific_init`)를 통해 **ncmpd에 연결**하고 SHM을
  부착한다. 이후 모든 세션/크립토 호출의 전제.
- **원형 및 인자**:
  ```c
  CK_RV ST_Initialize(
      API_Slot_t *sltp,               // api 계층 슬롯 엔트리(함수 목록/tokdata 수신)
      CK_SLOT_ID SlotNumber,          // 초기화 대상 슬롯 id
      SLOT_INFO *sinfp,               // opencryptoki.conf 슬롯 설정
      struct trace_handle_t t         // 트레이스 핸들
  );
  ```
- **반환값**: `CKR_OK`; `CKR_TOKEN_NOT_PRESENT`(ncmpd/토큰 부재),
  `CKR_FUNCTION_FAILED`(SHM 부착·설정 오류), `CKR_HOST_MEMORY`.

### 1.2 `SC_SetFunctionList` (내부)
- **기능**: STDLL 내부 `function_list`(`ST_*` 포인터 테이블)를 채우는 등록 함수.
  애플리케이션이 직접 호출하지 않으며 `ST_Initialize` 초기화 경로에서 1회 실행된다.
- **원형 및 인자**:
  ```c
  void SC_SetFunctionList(void);      // 인자 없음, 반환 없음
  ```
- **반환값**: 없음(`void`).

### 1.3 `SC_Finalize` (app: `C_Finalize`)
- **기능**: 토큰 인스턴스를 정리한다. `token_specific.t_final`
  (`token_specific_final`)로 **ncmpd 연결/SHM을 해제**하고 열린 세션을 닫는다.
- **원형 및 인자**:
  ```c
  CK_RV SC_Finalize(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      CK_SLOT_ID sid,                 // 슬롯 id
      SLOT_INFO *sinfp,               // 슬롯 설정
      struct trace_handle_t *t,       // 트레이스 핸들
      CK_BBOOL in_fork_initializer    // fork 후 재초기화 경로 여부
  );
  ```
- **반환값**: `CKR_OK`, `CKR_CRYPTOKI_NOT_INITIALIZED`.

---

## 2. 슬롯 · 토큰 관리

### 2.1 `SC_GetTokenInfo` (app: `C_GetTokenInfo`)
- **기능**: 슬롯에 바인딩된 물리 토큰의 `CK_TOKEN_INFO`(라벨/제조사/모델/시리얼,
  세션·PIN 길이 한계, flags)를 반환한다. `token_specific.t_get_token_info`가
  `NCMP_CMD_VD_TOKEN_INFO`/`GET_TOKEN_PARAMS`/`GET_UTC_TIME` 결과로 채운다.
- **원형 및 인자**:
  ```c
  CK_RV SC_GetTokenInfo(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      CK_SLOT_ID sid,                 // 슬롯 id
      CK_TOKEN_INFO_PTR pInfo         // [out] 토큰 정보
  );
  ```
- **반환값**: `CKR_OK`; `CKR_SLOT_ID_INVALID`, `CKR_TOKEN_NOT_PRESENT`,
  `CKR_ARGUMENTS_BAD`(pInfo==NULL).

### 2.2 `SC_GetMechanismList` (app: `C_GetMechanismList`)
- **기능**: 토큰이 광고하는 메커니즘 타입 목록(`ncmp_mech_list`)을 반환한다.
  `pMechList==NULL`이면 개수만 반환(2-패스 규약).
- **원형 및 인자**:
  ```c
  CK_RV SC_GetMechanismList(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      CK_SLOT_ID sid,                 // 슬롯 id
      CK_MECHANISM_TYPE_PTR pMechList,// [out] 메커니즘 배열(NULL=개수만)
      CK_ULONG_PTR count              // [in/out] 배열 용량 / 실제 개수
  );
  ```
- **반환값**: `CKR_OK`; `CKR_BUFFER_TOO_SMALL`, `CKR_ARGUMENTS_BAD`(count==NULL).

### 2.3 `SC_GetMechanismInfo` (app: `C_GetMechanismInfo`)
- **기능**: 특정 메커니즘의 `CK_MECHANISM_INFO`(키 길이 범위·flags)를 반환한다.
- **원형 및 인자**:
  ```c
  CK_RV SC_GetMechanismInfo(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      CK_SLOT_ID sid,                 // 슬롯 id
      CK_MECHANISM_TYPE type,         // 조회할 메커니즘 타입
      CK_MECHANISM_INFO_PTR pInfo     // [out] 메커니즘 정보
  );
  ```
- **반환값**: `CKR_OK`; `CKR_MECHANISM_INVALID`(광고 목록 밖),
  `CKR_ARGUMENTS_BAD`(pInfo==NULL).

### 2.4 `SC_InitToken` (app: `C_InitToken`)
- **기능**: SO PIN으로 토큰을 초기화하고 라벨을 설정한다. `token_specific.t_init_token`
  이 **set→read-back→validate→persist** 순으로 물리 토큰에 PIN/라벨을 설정하고,
  라벨을 되읽어 검증한 뒤 `nv_token_data`에 캐시·저장하고 임시 버퍼를 zeroize 한다.
- **원형 및 인자**:
  ```c
  CK_RV SC_InitToken(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      CK_SLOT_ID sid,                 // 슬롯 id
      CK_CHAR_PTR pPin,               // SO PIN
      CK_ULONG ulPinLen,              // SO PIN 길이
      CK_CHAR_PTR pLabel              // 32바이트 토큰 라벨(공백 패딩)
  );
  ```
- **반환값**: `CKR_OK`; `CKR_PIN_INCORRECT`, `CKR_PIN_LEN_RANGE`,
  `CKR_SESSION_EXISTS`(열린 세션 존재), `CKR_ARGUMENTS_BAD`.

### 2.5 `SC_InitPIN` (app: `C_InitPIN`)
- **기능**: SO 로그인 상태에서 사용자(user) PIN을 초기화한다.
  `token_specific.t_init_pin`이 `NCMP_CMD_INIT_PIN`으로 물리 토큰에 전달한다.
- **원형 및 인자**:
  ```c
  CK_RV SC_InitPIN(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션(SO 로그인 필요)
      CK_CHAR_PTR pPin,               // 새 user PIN
      CK_ULONG ulPinLen               // PIN 길이
  );
  ```
- **반환값**: `CKR_OK`; `CKR_USER_NOT_LOGGED_IN`(SO 아님),
  `CKR_PIN_LEN_RANGE`, `CKR_SESSION_READ_ONLY`.

### 2.6 `SC_SetPIN` (app: `C_SetPIN`)
- **기능**: 로그인한 사용자의 PIN을 변경한다. `token_specific.t_set_pin`이
  `NCMP_CMD_SET_PIN`으로 old/new PIN을 물리 토큰에 전달한다.
- **원형 및 인자**:
  ```c
  CK_RV SC_SetPIN(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_CHAR_PTR pOldPin,            // 기존 PIN
      CK_ULONG ulOldLen,              // 기존 PIN 길이
      CK_CHAR_PTR pNewPin,            // 새 PIN
      CK_ULONG ulNewLen               // 새 PIN 길이
  );
  ```
- **반환값**: `CKR_OK`; `CKR_PIN_INCORRECT`, `CKR_PIN_LEN_RANGE`,
  `CKR_SESSION_READ_ONLY`.

### 2.7 `SC_WaitForSlotEvent` (app: `C_WaitForSlotEvent`)
- **기능**: 슬롯 삽입/제거 이벤트를 대기(또는 `CKF_DONT_BLOCK`으로 폴링)한다.
  NCMP 슬롯 이벤트는 공통 계층에서 처리된다.
- **원형 및 인자**:
  ```c
  CK_RV SC_WaitForSlotEvent(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      CK_FLAGS flags,                 // 0 또는 CKF_DONT_BLOCK
      CK_SLOT_ID_PTR pSlot,           // [out] 이벤트 발생 슬롯
      CK_VOID_PTR pReserved           // 예약(NULL)
  );
  ```
- **반환값**: `CKR_OK`; `CKR_NO_EVENT`(DONT_BLOCK인데 이벤트 없음),
  `CKR_FUNCTION_NOT_SUPPORTED`.

---

## 3. 세션 관리 · 로그인

### 3.1 `SC_OpenSession` (app: `C_OpenSession`)
- **기능**: 슬롯에 세션을 연다. 세션 카운터는 `ncmp_session.c`가 `sess_lock` 하에
  증가시키며 슬롯당 `PKCS11_MAX_SESSION_PER_SLOT`(8), 전체
  `PKCS11_MAX_TOTAL_SESSIONS`(32) 상한을 강제한다.
- **원형 및 인자**:
  ```c
  CK_RV SC_OpenSession(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      CK_SLOT_ID sid,                 // 슬롯 id
      CK_FLAGS flags,                 // CKF_SERIAL_SESSION | (CKF_RW_SESSION)
      CK_SESSION_HANDLE_PTR phSession // [out] 세션 핸들
  );
  ```
- **반환값**: `CKR_OK`; `CKR_SESSION_COUNT`/`CKR_SESSION_COUNT_EXCEEDED`(상한),
  `CKR_SESSION_PARALLEL_NOT_SUPPORTED`(CKF_SERIAL_SESSION 누락), `CKR_SLOT_ID_INVALID`.

### 3.2 `SC_CloseSession` (app: `C_CloseSession`)
- **기능**: 세션 하나를 닫고 세션 카운터를 감소시키며, 그 세션의 진행 중 연산
  컨텍스트를 정리한다(멀티파트 컨텍스트는 `NCMP_CMD_CTX_FREE`로 해제).
- **원형 및 인자**:
  ```c
  CK_RV SC_CloseSession(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 닫을 세션
      CK_BBOOL in_fork_initializer    // fork 후 정리 경로 여부
  );
  ```
- **반환값**: `CKR_OK`, `CKR_SESSION_HANDLE_INVALID`.

### 3.3 `SC_CloseAllSessions` (app: `C_CloseAllSessions`)
- **기능**: 슬롯의 모든 세션을 닫고 로그인 상태를 해제한다.
- **원형 및 인자**:
  ```c
  CK_RV SC_CloseAllSessions(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      CK_SLOT_ID sid                  // 슬롯 id
  );
  ```
- **반환값**: `CKR_OK`, `CKR_SLOT_ID_INVALID`.

### 3.4 `SC_GetSessionInfo` (app: `C_GetSessionInfo`)
- **기능**: 세션의 `CK_SESSION_INFO`(슬롯 id, state, flags, 디바이스 오류)를 반환한다.
- **원형 및 인자**:
  ```c
  CK_RV SC_GetSessionInfo(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_SESSION_INFO_PTR pInfo       // [out] 세션 정보
  );
  ```
- **반환값**: `CKR_OK`, `CKR_SESSION_HANDLE_INVALID`, `CKR_ARGUMENTS_BAD`.

### 3.5 `SC_Login` (app: `C_Login`)
- **기능**: 사용자/SO 로그인. `token_specific.t_login`이 역할과 **플래그**(protected-auth:
  토큰 패드 입력·빈 wire PIN / `CKU_CONTEXT_SPECIFIC`: 로그인 상태 유지 재인증)를 함께
  `NCMP_CMD_LOGIN`으로 전달한다.
- **원형 및 인자**:
  ```c
  CK_RV SC_Login(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_USER_TYPE userType,          // CKU_USER / CKU_SO / CKU_CONTEXT_SPECIFIC
      CK_CHAR_PTR pPin,               // PIN(protected-auth 시 NULL)
      CK_ULONG ulPinLen               // PIN 길이(protected-auth 시 0)
  );
  ```
- **반환값**: `CKR_OK`; `CKR_PIN_INCORRECT`, `CKR_USER_ALREADY_LOGGED_IN`,
  `CKR_USER_PIN_NOT_INITIALIZED`, `CKR_OPERATION_NOT_INITIALIZED`(context-specific인데
  진행 중 연산 없음).

### 3.6 `SC_Logout` (app: `C_Logout`)
- **기능**: 현재 로그인 상태를 해제한다(`token_specific.t_logout` →
  `NCMP_CMD_LOGOUT`). 세션 내 개인 오브젝트 접근 권한을 회수한다.
- **원형 및 인자**:
  ```c
  CK_RV SC_Logout(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession     // 세션
  );
  ```
- **반환값**: `CKR_OK`, `CKR_USER_NOT_LOGGED_IN`.

### 3.7 `SC_SessionCancel` (app: `C_SessionCancel`, PKCS#11 3.0)
- **기능**: 세션에서 지정한 유형(flags)의 진행 중 연산을 취소한다. 취소되는 멀티파트
  컨텍스트는 `NCMP_CMD_CTX_FREE`로 해제된다.
- **원형 및 인자**:
  ```c
  CK_RV SC_SessionCancel(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_FLAGS flags                  // 취소할 연산 종류 비트마스크
  );
  ```
- **반환값**: `CKR_OK`, `CKR_SESSION_HANDLE_INVALID`, `CKR_ARGUMENTS_BAD`.

### 3.8 `SC_CancelFunction` (app: `C_CancelFunction`, deprecated)
- **기능**: 레거시 취소 API. opencryptoki에서는 항상 미지원으로 처리된다.
- **원형 및 인자**:
  ```c
  CK_RV SC_CancelFunction(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession     // 세션
  );
  ```
- **반환값**: `CKR_FUNCTION_NOT_PARALLEL`(규격상 항상).

### 3.9 `SC_GetFunctionStatus` (app: `C_GetFunctionStatus`, deprecated)
- **기능**: 레거시 병렬 함수 상태 조회. 항상 미지원.
- **원형 및 인자**:
  ```c
  CK_RV SC_GetFunctionStatus(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession     // 세션
  );
  ```
- **반환값**: `CKR_FUNCTION_NOT_PARALLEL`(규격상 항상).

### 3.10 `SC_GetOperationState` (app: `C_GetOperationState`)
- **기능**: 진행 중 연산 상태를 직렬화해 반환한다. NCMP의 타입드 컨텍스트는
  저장 불가로 표시되므로 지원하지 않는다.
- **원형 및 인자**:
  ```c
  CK_RV SC_GetOperationState(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_BYTE_PTR pOperationState,    // [out] 직렬화 상태(NULL=길이만)
      CK_ULONG_PTR pulOperationStateLen // [in/out] 버퍼 길이 / 실제 길이
  );
  ```
- **반환값**: **미지원** → `CKR_STATE_UNSAVEABLE`; `CKR_OPERATION_NOT_INITIALIZED`.

### 3.11 `SC_SetOperationState` (app: `C_SetOperationState`)
- **기능**: 직렬화된 연산 상태를 복원한다. NCMP는 상태 저장을 지원하지 않으므로 미지원.
- **원형 및 인자**:
  ```c
  CK_RV SC_SetOperationState(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_BYTE_PTR pOperationState,    // 복원할 상태 blob
      CK_ULONG ulOperationStateLen,   // blob 길이
      CK_OBJECT_HANDLE hEncryptionKey,// 암복호 키 핸들(해당 시)
      CK_OBJECT_HANDLE hAuthenticationKey // 인증 키 핸들(해당 시)
  );
  ```
- **반환값**: **미지원** → `CKR_STATE_UNSAVEABLE` / `CKR_SAVED_STATE_INVALID`.

---

## 4. 오브젝트 관리

> 오브젝트 CRUD·핸들 매핑·find·size·destroy 는 opencryptoki 공통 오브젝트 매니저
> (`obj_mgr.c`/`object.c`) + 로컬 데이터 스토어가 일반 처리한다. secure-key 토큰인
> NCMP는 **키 오브젝트만** 물리 토큰으로 전달한다(`t_object_add` /
> `t_set_attribute_values` → `NCMP_CMD_OBJECT_ADD` / `OBJECT_SET_ATTR`). 데이터/인증서
> 등 비-키 오브젝트는 로컬에만 존재한다.

### 4.1 `SC_CreateObject` (app: `C_CreateObject`)
- **기능**: 템플릿으로 오브젝트를 생성한다. 키 오브젝트면 `t_object_add`가
  `[class|key_type|value]`를 물리 토큰에 등록한다.
- **원형 및 인자**:
  ```c
  CK_RV SC_CreateObject(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_ATTRIBUTE_PTR pTemplate,     // 속성 템플릿
      CK_ULONG ulCount,               // 속성 개수
      CK_OBJECT_HANDLE_PTR phObject   // [out] 생성된 오브젝트 핸들
  );
  ```
- **반환값**: `CKR_OK`; `CKR_TEMPLATE_INCOMPLETE`/`CKR_TEMPLATE_INCONSISTENT`,
  `CKR_ATTRIBUTE_VALUE_INVALID`, `CKR_USER_NOT_LOGGED_IN`(개인 오브젝트),
  `CKR_SESSION_READ_ONLY`.

### 4.2 `SC_CopyObject` (app: `C_CopyObject`)
- **기능**: 기존 오브젝트를 복사하며 추가 템플릿을 덮어쓴다. 키 복사 시
  `t_set_attribute_values`가 변경 속성을 물리 토큰에 반영한다.
- **원형 및 인자**:
  ```c
  CK_RV SC_CopyObject(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_OBJECT_HANDLE hObject,       // 원본 오브젝트
      CK_ATTRIBUTE_PTR pTemplate,     // 덮어쓸 속성
      CK_ULONG ulCount,               // 속성 개수
      CK_OBJECT_HANDLE_PTR phNewObject// [out] 사본 핸들
  );
  ```
- **반환값**: `CKR_OK`; `CKR_OBJECT_HANDLE_INVALID`,
  `CKR_ATTRIBUTE_READ_ONLY`, `CKR_TEMPLATE_INCONSISTENT`.

### 4.3 `SC_DestroyObject` (app: `C_DestroyObject`)
- **기능**: 오브젝트를 삭제한다.
- **원형 및 인자**:
  ```c
  CK_RV SC_DestroyObject(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_OBJECT_HANDLE hObject        // 삭제할 오브젝트
  );
  ```
- **반환값**: `CKR_OK`; `CKR_OBJECT_HANDLE_INVALID`, `CKR_ACTION_PROHIBITED`,
  `CKR_SESSION_READ_ONLY`.

### 4.4 `SC_GetObjectSize` (app: `C_GetObjectSize`)
- **기능**: 오브젝트의 바이트 크기를 반환한다.
- **원형 및 인자**:
  ```c
  CK_RV SC_GetObjectSize(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_OBJECT_HANDLE hObject,       // 대상 오브젝트
      CK_ULONG_PTR pulSize            // [out] 크기(바이트)
  );
  ```
- **반환값**: `CKR_OK`; `CKR_OBJECT_HANDLE_INVALID`, `CKR_INFORMATION_SENSITIVE`.

### 4.5 `SC_GetAttributeValue` (app: `C_GetAttributeValue`)
- **기능**: 오브젝트 속성값을 읽는다. secure-key 토큰이라 `CKA_VALUE` 등 민감 속성은
  `CKR_ATTRIBUTE_SENSITIVE`로 가려질 수 있다.
- **원형 및 인자**:
  ```c
  CK_RV SC_GetAttributeValue(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_OBJECT_HANDLE hObject,       // 대상 오브젝트
      CK_ATTRIBUTE_PTR pTemplate,     // [in/out] 조회할 속성/값 수신
      CK_ULONG ulCount                // 속성 개수
  );
  ```
- **반환값**: `CKR_OK`; `CKR_ATTRIBUTE_SENSITIVE`, `CKR_ATTRIBUTE_TYPE_INVALID`,
  `CKR_BUFFER_TOO_SMALL`, `CKR_OBJECT_HANDLE_INVALID`.

### 4.6 `SC_SetAttributeValue` (app: `C_SetAttributeValue`)
- **기능**: 오브젝트 속성을 변경한다. 키 오브젝트면 `t_set_attribute_values`가
  `NCMP_CMD_OBJECT_SET_ATTR`로 물리 토큰에 반영한다.
- **원형 및 인자**:
  ```c
  CK_RV SC_SetAttributeValue(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_OBJECT_HANDLE hObject,       // 대상 오브젝트
      CK_ATTRIBUTE_PTR pTemplate,     // 변경할 속성
      CK_ULONG ulCount                // 속성 개수
  );
  ```
- **반환값**: `CKR_OK`; `CKR_ATTRIBUTE_READ_ONLY`, `CKR_ATTRIBUTE_VALUE_INVALID`,
  `CKR_OBJECT_HANDLE_INVALID`, `CKR_SESSION_READ_ONLY`.

### 4.7 `SC_FindObjectsInit` (app: `C_FindObjectsInit`)
- **기능**: 템플릿 조건으로 오브젝트 검색을 시작한다.
- **원형 및 인자**:
  ```c
  CK_RV SC_FindObjectsInit(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_ATTRIBUTE_PTR pTemplate,     // 매칭 템플릿(NULL/0=전체)
      CK_ULONG ulCount                // 속성 개수
  );
  ```
- **반환값**: `CKR_OK`; `CKR_OPERATION_ACTIVE`(이미 검색 중),
  `CKR_ATTRIBUTE_TYPE_INVALID`.

### 4.8 `SC_FindObjects` (app: `C_FindObjects`)
- **기능**: 검색 결과 오브젝트 핸들을 최대 개수만큼 반환한다.
- **원형 및 인자**:
  ```c
  CK_RV SC_FindObjects(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_OBJECT_HANDLE_PTR phObject,  // [out] 핸들 배열
      CK_ULONG ulMaxObjectCount,      // 배열 용량
      CK_ULONG_PTR pulObjectCount     // [out] 반환된 핸들 수
  );
  ```
- **반환값**: `CKR_OK`; `CKR_OPERATION_NOT_INITIALIZED`(Init 누락), `CKR_ARGUMENTS_BAD`.

### 4.9 `SC_FindObjectsFinal` (app: `C_FindObjectsFinal`)
- **기능**: 오브젝트 검색을 종료한다.
- **원형 및 인자**:
  ```c
  CK_RV SC_FindObjectsFinal(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession     // 세션
  );
  ```
- **반환값**: `CKR_OK`, `CKR_OPERATION_NOT_INITIALIZED`.

---

## 5. 암호화 (Encrypt) — AES-GCM / AES-CTR

> 지원 메커니즘: `CKM_AES_GCM`(one-shot + 멀티파트), `CKM_AES_CTR`(one-shot).
> 그 외(`CKM_AES_CBC/ECB/...`, RSA 등)는 `EncryptInit`에서 `CKR_MECHANISM_INVALID`.

### 5.1 `SC_EncryptInit` (app: `C_EncryptInit`)
- **기능**: 암호화 연산을 초기화한다. GCM은 `t_aes_gcm_init`이 컨텍스트를 생성(멀티파트
  대비)하고, 키는 토큰 키 테이블에 두고 `key_id`로만 컨텍스트에 참조된다.
- **원형 및 인자**:
  ```c
  CK_RV SC_EncryptInit(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_MECHANISM_PTR pMechanism,    // CKM_AES_GCM / CKM_AES_CTR (+파라미터)
      CK_OBJECT_HANDLE hKey           // 대칭 키 핸들
  );
  ```
- **반환값**: `CKR_OK`; `CKR_MECHANISM_INVALID`(미지원 메커니즘),
  `CKR_MECHANISM_PARAM_INVALID`, `CKR_KEY_TYPE_INCONSISTENT`,
  `CKR_KEY_FUNCTION_NOT_PERMITTED`, `CKR_OPERATION_ACTIVE`.

### 5.2 `SC_Encrypt` (app: `C_Encrypt`)
- **기능**: 단발 암호화. `pEncryptedData==NULL`이면 출력 길이만 반환.
- **원형 및 인자**:
  ```c
  CK_RV SC_Encrypt(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_BYTE_PTR pData,              // 평문
      CK_ULONG ulDataLen,             // 평문 길이
      CK_BYTE_PTR pEncryptedData,     // [out] 암호문(NULL=길이만)
      CK_ULONG_PTR pulEncryptedDataLen// [in/out] 버퍼 길이 / 실제 길이
  );
  ```
- **반환값**: `CKR_OK`; `CKR_BUFFER_TOO_SMALL`, `CKR_OPERATION_NOT_INITIALIZED`,
  `CKR_DATA_LEN_RANGE`.

### 5.3 `SC_EncryptUpdate` (app: `C_EncryptUpdate`)
- **기능**: 멀티파트 암호화의 데이터 청크를 처리한다(AES-GCM). 호스트 관리 컨텍스트
  모델에서는 컨텍스트 blob이 STDLL↔데몬 사이를 오간다.
- **원형 및 인자**:
  ```c
  CK_RV SC_EncryptUpdate(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_BYTE_PTR pPart,              // 평문 청크
      CK_ULONG ulPartLen,             // 청크 길이
      CK_BYTE_PTR pEncryptedPart,     // [out] 암호문 청크(NULL=길이만)
      CK_ULONG_PTR pulEncryptedPartLen// [in/out] 버퍼 길이 / 실제 길이
  );
  ```
- **반환값**: `CKR_OK`; `CKR_BUFFER_TOO_SMALL`, `CKR_OPERATION_NOT_INITIALIZED`.
  (CTR은 단발 전용이라 update 사용 시 `CKR_OPERATION_NOT_INITIALIZED` 계열.)

### 5.4 `SC_EncryptFinal` (app: `C_EncryptFinal`)
- **기능**: 멀티파트 암호화를 종료하고 잔여 블록/GCM 태그를 산출한다.
- **원형 및 인자**:
  ```c
  CK_RV SC_EncryptFinal(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_BYTE_PTR pLastEncryptedPart, // [out] 잔여 암호문+태그(NULL=길이만)
      CK_ULONG_PTR pulLastEncryptedPartLen // [in/out] 버퍼 길이 / 실제 길이
  );
  ```
- **반환값**: `CKR_OK`; `CKR_BUFFER_TOO_SMALL`, `CKR_OPERATION_NOT_INITIALIZED`.

---

## 6. 복호화 (Decrypt) — AES-GCM / AES-CTR

> 지원/미지원 범위는 5장(Encrypt)과 동일. 복호는 GCM 태그를 마지막까지 보류해 검증한다.

### 6.1 `SC_DecryptInit` (app: `C_DecryptInit`)
- **기능**: 복호화 연산을 초기화한다(§5.1의 복호 방향).
- **원형 및 인자**:
  ```c
  CK_RV SC_DecryptInit(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_MECHANISM_PTR pMechanism,    // CKM_AES_GCM / CKM_AES_CTR (+파라미터)
      CK_OBJECT_HANDLE hKey           // 대칭 키 핸들
  );
  ```
- **반환값**: `CKR_OK`; `CKR_MECHANISM_INVALID`, `CKR_KEY_FUNCTION_NOT_PERMITTED`,
  `CKR_OPERATION_ACTIVE`.

### 6.2 `SC_Decrypt` (app: `C_Decrypt`)
- **기능**: 단발 복호화. GCM은 태그 검증 실패 시 거부한다.
- **원형 및 인자**:
  ```c
  CK_RV SC_Decrypt(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_BYTE_PTR pEncryptedData,     // 암호문
      CK_ULONG ulEncryptedDataLen,    // 암호문 길이
      CK_BYTE_PTR pData,              // [out] 평문(NULL=길이만)
      CK_ULONG_PTR pulDataLen         // [in/out] 버퍼 길이 / 실제 길이
  );
  ```
- **반환값**: `CKR_OK`; `CKR_ENCRYPTED_DATA_INVALID`, `CKR_ENCRYPTED_DATA_LEN_RANGE`,
  `CKR_BUFFER_TOO_SMALL`, `CKR_OPERATION_NOT_INITIALIZED`.

### 6.3 `SC_DecryptUpdate` (app: `C_DecryptUpdate`)
- **기능**: 멀티파트 복호화 청크 처리(AES-GCM). 복호에서는 태그 길이만큼 보류한다.
- **원형 및 인자**:
  ```c
  CK_RV SC_DecryptUpdate(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_BYTE_PTR pEncryptedPart,     // 암호문 청크
      CK_ULONG ulEncryptedPartLen,    // 청크 길이
      CK_BYTE_PTR pPart,              // [out] 평문 청크(NULL=길이만)
      CK_ULONG_PTR pulPartLen         // [in/out] 버퍼 길이 / 실제 길이
  );
  ```
- **반환값**: `CKR_OK`; `CKR_BUFFER_TOO_SMALL`, `CKR_OPERATION_NOT_INITIALIZED`.

### 6.4 `SC_DecryptFinal` (app: `C_DecryptFinal`)
- **기능**: 멀티파트 복호화 종료 + GCM 태그 검증.
- **원형 및 인자**:
  ```c
  CK_RV SC_DecryptFinal(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_BYTE_PTR pLastPart,          // [out] 잔여 평문(NULL=길이만)
      CK_ULONG_PTR pulLastPartLen     // [in/out] 버퍼 길이 / 실제 길이
  );
  ```
- **반환값**: `CKR_OK`; `CKR_ENCRYPTED_DATA_INVALID`(태그 불일치),
  `CKR_BUFFER_TOO_SMALL`, `CKR_OPERATION_NOT_INITIALIZED`.

---

## 7. 다이제스트 (Digest) — SHA-2 / SHA-3

> 지원: `CKM_SHA256`, `CKM_SHA512`, `CKM_SHA3_224/256/384/512`(one-shot + 멀티파트).
> `t_sha_*` 훅으로 `NCMP_CMD_DIGEST_{INIT,UPDATE,FINAL}`에 전달되며, 멀티파트
> 컨텍스트는 `ncmp_ctx_digest_t{mech,acc}`로 직렬화된다.

### 7.1 `SC_DigestInit` (app: `C_DigestInit`)
- **기능**: 다이제스트 연산을 초기화한다.
- **원형 및 인자**:
  ```c
  CK_RV SC_DigestInit(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_MECHANISM_PTR pMechanism     // CKM_SHA256/SHA512/SHA3_*
  );
  ```
- **반환값**: `CKR_OK`; `CKR_MECHANISM_INVALID`(미지원 해시), `CKR_OPERATION_ACTIVE`.

### 7.2 `SC_Digest` (app: `C_Digest`)
- **기능**: 단발 다이제스트.
- **원형 및 인자**:
  ```c
  CK_RV SC_Digest(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_BYTE_PTR pData,              // 입력 데이터
      CK_ULONG ulDataLen,             // 입력 길이
      CK_BYTE_PTR pDigest,            // [out] 해시(NULL=길이만)
      CK_ULONG_PTR pulDigestLen       // [in/out] 버퍼 길이 / 실제 길이
  );
  ```
- **반환값**: `CKR_OK`; `CKR_BUFFER_TOO_SMALL`, `CKR_OPERATION_NOT_INITIALIZED`.

### 7.3 `SC_DigestUpdate` (app: `C_DigestUpdate`)
- **기능**: 멀티파트 다이제스트 청크를 누적한다.
- **원형 및 인자**:
  ```c
  CK_RV SC_DigestUpdate(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_BYTE_PTR pPart,              // 데이터 청크
      CK_ULONG ulPartLen              // 청크 길이(<= NCMP_MP_UPDATE_MAX_DATA)
  );
  ```
- **반환값**: `CKR_OK`; `CKR_OPERATION_NOT_INITIALIZED`, `CKR_DATA_LEN_RANGE`.

### 7.4 `SC_DigestKey` (app: `C_DigestKey`)
- **기능**: 키 오브젝트의 값을 다이제스트에 공급한다. secure-key 토큰은 키 값이 외부에
  노출되지 않으므로 일반적으로 미지원.
- **원형 및 인자**:
  ```c
  CK_RV SC_DigestKey(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_OBJECT_HANDLE hKey           // 다이제스트할 키
  );
  ```
- **반환값**: `CKR_KEY_INDIGESTIBLE` / `CKR_FUNCTION_NOT_SUPPORTED`;
  `CKR_OPERATION_NOT_INITIALIZED`.

### 7.5 `SC_DigestFinal` (app: `C_DigestFinal`)
- **기능**: 멀티파트 다이제스트를 종료하고 최종 해시를 산출한다.
- **원형 및 인자**:
  ```c
  CK_RV SC_DigestFinal(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_BYTE_PTR pDigest,            // [out] 최종 해시(NULL=길이만)
      CK_ULONG_PTR pulDigestLen       // [in/out] 버퍼 길이 / 실제 길이
  );
  ```
- **반환값**: `CKR_OK`; `CKR_BUFFER_TOO_SMALL`, `CKR_OPERATION_NOT_INITIALIZED`.

---

## 8. 서명 (Sign) — ML-DSA

> 지원: `CKM_ML_DSA`(strength 1/3/5 = ML-DSA-44/65/87), 단발 서명(`t_ml_dsa_sign`).
> ML-DSA는 멀티파트 훅이 없어 `SignUpdate`/`SignFinal` 시퀀스는 미지원. RSA/EC/HMAC
> 서명은 미지원(`CKR_MECHANISM_INVALID`). Recover 계열은 RSA 전용이라 미지원.

### 8.1 `SC_SignInit` (app: `C_SignInit`)
- **기능**: 서명 연산을 초기화한다.
- **원형 및 인자**:
  ```c
  CK_RV SC_SignInit(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_MECHANISM_PTR pMechanism,    // CKM_ML_DSA
      CK_OBJECT_HANDLE hKey           // 서명 개인키 핸들
  );
  ```
- **반환값**: `CKR_OK`; `CKR_MECHANISM_INVALID`, `CKR_KEY_TYPE_INCONSISTENT`,
  `CKR_KEY_FUNCTION_NOT_PERMITTED`, `CKR_OPERATION_ACTIVE`.

### 8.2 `SC_Sign` (app: `C_Sign`)
- **기능**: 단발 서명 생성(ML-DSA).
- **원형 및 인자**:
  ```c
  CK_RV SC_Sign(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_BYTE_PTR pData,              // 서명 대상 데이터
      CK_ULONG ulDataLen,             // 데이터 길이
      CK_BYTE_PTR pSignature,         // [out] 서명(NULL=길이만)
      CK_ULONG_PTR pulSignatureLen    // [in/out] 버퍼 길이 / 실제 길이
  );
  ```
- **반환값**: `CKR_OK`; `CKR_BUFFER_TOO_SMALL`, `CKR_OPERATION_NOT_INITIALIZED`,
  `CKR_DATA_LEN_RANGE`.

### 8.3 `SC_SignUpdate` (app: `C_SignUpdate`)
- **기능**: 멀티파트 서명 청크 처리. ML-DSA는 단발 전용이므로 미지원.
- **원형 및 인자**:
  ```c
  CK_RV SC_SignUpdate(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_BYTE_PTR pPart,              // 데이터 청크
      CK_ULONG ulPartLen              // 청크 길이
  );
  ```
- **반환값**: `CKR_FUNCTION_NOT_SUPPORTED` / `CKR_OPERATION_NOT_INITIALIZED`.

### 8.4 `SC_SignFinal` (app: `C_SignFinal`)
- **기능**: 멀티파트 서명 종료. ML-DSA는 단발 전용이므로 미지원.
- **원형 및 인자**:
  ```c
  CK_RV SC_SignFinal(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_BYTE_PTR pSignature,         // [out] 서명(NULL=길이만)
      CK_ULONG_PTR pulSignatureLen    // [in/out] 버퍼 길이 / 실제 길이
  );
  ```
- **반환값**: `CKR_FUNCTION_NOT_SUPPORTED` / `CKR_OPERATION_NOT_INITIALIZED`.

### 8.5 `SC_SignRecoverInit` (app: `C_SignRecoverInit`)
- **기능**: 복원형 서명 초기화(RSA 전용). NCMP 미지원.
- **원형 및 인자**:
  ```c
  CK_RV SC_SignRecoverInit(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_MECHANISM_PTR pMechanism,    // 복원형 서명 메커니즘
      CK_OBJECT_HANDLE hKey           // 개인키 핸들
  );
  ```
- **반환값**: **미지원** → `CKR_MECHANISM_INVALID` / `CKR_FUNCTION_NOT_SUPPORTED`.

### 8.6 `SC_SignRecover` (app: `C_SignRecover`)
- **기능**: 복원형 서명 생성(RSA 전용). NCMP 미지원.
- **원형 및 인자**:
  ```c
  CK_RV SC_SignRecover(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_BYTE_PTR pData,              // 데이터
      CK_ULONG ulDataLen,             // 데이터 길이
      CK_BYTE_PTR pSignature,         // [out] 서명(NULL=길이만)
      CK_ULONG_PTR pulSignatureLen    // [in/out] 버퍼 길이 / 실제 길이
  );
  ```
- **반환값**: **미지원** → `CKR_OPERATION_NOT_INITIALIZED` / `CKR_FUNCTION_NOT_SUPPORTED`.

---

## 9. 검증 (Verify) — ML-DSA

> 지원: `CKM_ML_DSA` 단발 검증(`t_ml_dsa_verify`). Update/Final(멀티파트)·Recover는
> 8장과 같은 이유로 미지원.

### 9.1 `SC_VerifyInit` (app: `C_VerifyInit`)
- **기능**: 검증 연산을 초기화한다.
- **원형 및 인자**:
  ```c
  CK_RV SC_VerifyInit(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_MECHANISM_PTR pMechanism,    // CKM_ML_DSA
      CK_OBJECT_HANDLE hKey           // 검증 공개키 핸들
  );
  ```
- **반환값**: `CKR_OK`; `CKR_MECHANISM_INVALID`, `CKR_KEY_TYPE_INCONSISTENT`,
  `CKR_OPERATION_ACTIVE`.

### 9.2 `SC_Verify` (app: `C_Verify`)
- **기능**: 단발 서명 검증(ML-DSA).
- **원형 및 인자**:
  ```c
  CK_RV SC_Verify(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_BYTE_PTR pData,              // 원본 데이터
      CK_ULONG ulDataLen,             // 데이터 길이
      CK_BYTE_PTR pSignature,         // 검증할 서명
      CK_ULONG ulSignatureLen         // 서명 길이
  );
  ```
- **반환값**: `CKR_OK`; `CKR_SIGNATURE_INVALID`, `CKR_SIGNATURE_LEN_RANGE`,
  `CKR_OPERATION_NOT_INITIALIZED`.

### 9.3 `SC_VerifyUpdate` (app: `C_VerifyUpdate`)
- **기능**: 멀티파트 검증 청크 처리. ML-DSA는 단발 전용이므로 미지원.
- **원형 및 인자**:
  ```c
  CK_RV SC_VerifyUpdate(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_BYTE_PTR pPart,              // 데이터 청크
      CK_ULONG ulPartLen              // 청크 길이
  );
  ```
- **반환값**: `CKR_FUNCTION_NOT_SUPPORTED` / `CKR_OPERATION_NOT_INITIALIZED`.

### 9.4 `SC_VerifyFinal` (app: `C_VerifyFinal`)
- **기능**: 멀티파트 검증 종료. ML-DSA는 단발 전용이므로 미지원.
- **원형 및 인자**:
  ```c
  CK_RV SC_VerifyFinal(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_BYTE_PTR pSignature,         // 검증할 서명
      CK_ULONG ulSignatureLen         // 서명 길이
  );
  ```
- **반환값**: `CKR_FUNCTION_NOT_SUPPORTED` / `CKR_OPERATION_NOT_INITIALIZED`.

### 9.5 `SC_VerifyRecoverInit` (app: `C_VerifyRecoverInit`)
- **기능**: 복원형 검증 초기화(RSA 전용). NCMP 미지원.
- **원형 및 인자**:
  ```c
  CK_RV SC_VerifyRecoverInit(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_MECHANISM_PTR pMechanism,    // 복원형 검증 메커니즘
      CK_OBJECT_HANDLE hKey           // 공개키 핸들
  );
  ```
- **반환값**: **미지원** → `CKR_MECHANISM_INVALID` / `CKR_FUNCTION_NOT_SUPPORTED`.

### 9.6 `SC_VerifyRecover` (app: `C_VerifyRecover`)
- **기능**: 복원형 검증(서명에서 데이터 복원, RSA 전용). NCMP 미지원.
- **원형 및 인자**:
  ```c
  CK_RV SC_VerifyRecover(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_BYTE_PTR pSignature,         // 서명
      CK_ULONG ulSignatureLen,        // 서명 길이
      CK_BYTE_PTR pData,              // [out] 복원 데이터(NULL=길이만)
      CK_ULONG_PTR pulDataLen         // [in/out] 버퍼 길이 / 실제 길이
  );
  ```
- **반환값**: **미지원** → `CKR_OPERATION_NOT_INITIALIZED` / `CKR_FUNCTION_NOT_SUPPORTED`.

---

## 10. 서명 검증 (VerifySignature, PKCS#11 3.2) — ML-DSA

> 3.2 신규 API: 검증할 서명을 `Init` 시점에 미리 제공하고 데이터로 검증한다.
> ML-DSA는 단발형(`VerifySignature`)만 지원, Update/Final(멀티파트)은 미지원.

### 10.1 `SC_VerifySignatureInit` (app: `C_VerifySignatureInit`)
- **기능**: 서명을 미리 지정하여 검증 연산을 초기화한다.
- **원형 및 인자**:
  ```c
  CK_RV SC_VerifySignatureInit(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_T *sSession,         // 세션
      CK_MECHANISM_PTR pMechanism,    // CKM_ML_DSA
      CK_OBJECT_HANDLE hKey,          // 검증 공개키 핸들
      CK_BYTE_PTR pSignature,         // 검증할 서명(미리 제공)
      CK_ULONG ulSignatureLen         // 서명 길이
  );
  ```
- **반환값**: `CKR_OK`; `CKR_MECHANISM_INVALID`, `CKR_SIGNATURE_LEN_RANGE`,
  `CKR_OPERATION_ACTIVE`.

### 10.2 `SC_VerifySignature` (app: `C_VerifySignature`)
- **기능**: `Init`에서 준 서명을 데이터에 대해 단발 검증한다.
- **원형 및 인자**:
  ```c
  CK_RV SC_VerifySignature(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_T *sSession,         // 세션
      CK_BYTE_PTR pData,              // 원본 데이터
      CK_ULONG ulDataLen              // 데이터 길이
  );
  ```
- **반환값**: `CKR_OK`; `CKR_SIGNATURE_INVALID`, `CKR_OPERATION_NOT_INITIALIZED`.

### 10.3 `SC_VerifySignatureUpdate` (app: `C_VerifySignatureUpdate`)
- **기능**: 멀티파트 서명 검증 청크. ML-DSA는 단발 전용이므로 미지원.
- **원형 및 인자**:
  ```c
  CK_RV SC_VerifySignatureUpdate(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_T *sSession,         // 세션
      CK_BYTE_PTR pPart,              // 데이터 청크
      CK_ULONG ulPartLen              // 청크 길이
  );
  ```
- **반환값**: `CKR_FUNCTION_NOT_SUPPORTED` / `CKR_OPERATION_NOT_INITIALIZED`.

### 10.4 `SC_VerifySignatureFinal` (app: `C_VerifySignatureFinal`)
- **기능**: 멀티파트 서명 검증 종료. ML-DSA는 단발 전용이므로 미지원.
- **원형 및 인자**:
  ```c
  CK_RV SC_VerifySignatureFinal(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_T *sSession          // 세션
  );
  ```
- **반환값**: `CKR_FUNCTION_NOT_SUPPORTED` / `CKR_OPERATION_NOT_INITIALIZED`.

---

## 11. 이중 기능 (Dual-function) 연산

> 두 연산을 한 호출로 겹치는 API. **두 하위 연산이 모두 지원될 때만** 동작한다.
> NCMP는 digest(SHA-2/3)와 encrypt/decrypt(AES-GCM/CTR)를 지원하므로
> digest+encrypt / decrypt+digest 조합은 가능하나, sign/verify는 ML-DSA가 멀티파트
> 미지원이라 sign-encrypt / decrypt-verify 조합은 사실상 미지원이다.

### 11.1 `SC_DigestEncryptUpdate` (app: `C_DigestEncryptUpdate`)
- **기능**: 한 청크를 다이제스트하면서 동시에 암호화한다.
- **원형 및 인자**:
  ```c
  CK_RV SC_DigestEncryptUpdate(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_BYTE_PTR pPart,              // 평문 청크
      CK_ULONG ulPartLen,             // 청크 길이
      CK_BYTE_PTR pEncryptedPart,     // [out] 암호문 청크(NULL=길이만)
      CK_ULONG_PTR pulEncryptedPartLen// [in/out] 버퍼 길이 / 실제 길이
  );
  ```
- **반환값**: `CKR_OK`(digest+GCM 모두 init된 경우); `CKR_OPERATION_NOT_INITIALIZED`,
  `CKR_BUFFER_TOO_SMALL`.

### 11.2 `SC_DecryptDigestUpdate` (app: `C_DecryptDigestUpdate`)
- **기능**: 한 청크를 복호화하면서 동시에 다이제스트한다.
- **원형 및 인자**:
  ```c
  CK_RV SC_DecryptDigestUpdate(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_BYTE_PTR pEncryptedPart,     // 암호문 청크
      CK_ULONG ulEncryptedPartLen,    // 청크 길이
      CK_BYTE_PTR pPart,              // [out] 평문 청크(NULL=길이만)
      CK_ULONG_PTR pulPartLen         // [in/out] 버퍼 길이 / 실제 길이
  );
  ```
- **반환값**: `CKR_OK`; `CKR_OPERATION_NOT_INITIALIZED`, `CKR_BUFFER_TOO_SMALL`.

### 11.3 `SC_SignEncryptUpdate` (app: `C_SignEncryptUpdate`)
- **기능**: 한 청크를 서명하면서 동시에 암호화한다. ML-DSA 멀티파트 서명 미지원이라
  사실상 미지원.
- **원형 및 인자**:
  ```c
  CK_RV SC_SignEncryptUpdate(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_BYTE_PTR pPart,              // 평문 청크
      CK_ULONG ulPartLen,             // 청크 길이
      CK_BYTE_PTR pEncryptedPart,     // [out] 암호문 청크(NULL=길이만)
      CK_ULONG_PTR pulEncryptedPartLen// [in/out] 버퍼 길이 / 실제 길이
  );
  ```
- **반환값**: `CKR_OPERATION_NOT_INITIALIZED` / `CKR_FUNCTION_NOT_SUPPORTED`.

### 11.4 `SC_DecryptVerifyUpdate` (app: `C_DecryptVerifyUpdate`)
- **기능**: 한 청크를 복호화하면서 동시에 검증한다. ML-DSA 멀티파트 검증 미지원이라
  사실상 미지원.
- **원형 및 인자**:
  ```c
  CK_RV SC_DecryptVerifyUpdate(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_BYTE_PTR pEncryptedPart,     // 암호문 청크
      CK_ULONG ulEncryptedPartLen,    // 청크 길이
      CK_BYTE_PTR pPart,              // [out] 평문 청크(NULL=길이만)
      CK_ULONG_PTR pulPartLen         // [in/out] 버퍼 길이 / 실제 길이
  );
  ```
- **반환값**: `CKR_OPERATION_NOT_INITIALIZED` / `CKR_FUNCTION_NOT_SUPPORTED`.

---

## 12. 키 관리

### 12.1 `SC_GenerateKey` (app: `C_GenerateKey`)
- **기능**: 대칭 키를 생성한다. NCMP는 `t_aes_key_gen`으로 **AES 키**(`CKM_AES_KEY_GEN`)만
  지원한다. 생성 키는 토큰이 소유하고 STDLL은 핸들만 받는다.
- **원형 및 인자**:
  ```c
  CK_RV SC_GenerateKey(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_MECHANISM_PTR pMechanism,    // CKM_AES_KEY_GEN
      CK_ATTRIBUTE_PTR pTemplate,     // 키 속성 템플릿
      CK_ULONG ulCount,               // 속성 개수
      CK_OBJECT_HANDLE_PTR phKey      // [out] 생성된 키 핸들
  );
  ```
- **반환값**: `CKR_OK`; `CKR_MECHANISM_INVALID`(AES 외), `CKR_TEMPLATE_INCONSISTENT`,
  `CKR_ATTRIBUTE_VALUE_INVALID`, `CKR_USER_NOT_LOGGED_IN`.

### 12.2 `SC_GenerateKeyPair` (app: `C_GenerateKeyPair`)
- **기능**: 비대칭 키쌍을 생성한다. NCMP는 **ML-DSA**(`t_ml_dsa_generate_keypair`)와
  **ML-KEM**(`t_ml_kem_generate_keypair`)만 지원한다. strength는 `CKA_PARAMETER_SET`로
  선택. PQC 키는 `CKA_VALUE`에 blob 통째로 저장(개인 blob은 공개 blob 접두).
- **원형 및 인자**:
  ```c
  CK_RV SC_GenerateKeyPair(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_MECHANISM_PTR pMechanism,    // CKM_ML_DSA_KEY_PAIR_GEN / CKM_ML_KEM_KEY_PAIR_GEN
      CK_ATTRIBUTE_PTR pPublicKeyTemplate,   // 공개키 템플릿
      CK_ULONG ulPublicKeyAttributeCount,    // 공개키 속성 개수
      CK_ATTRIBUTE_PTR pPrivateKeyTemplate,  // 개인키 템플릿
      CK_ULONG ulPrivateKeyAttributeCount,   // 개인키 속성 개수
      CK_OBJECT_HANDLE_PTR phPublicKey,      // [out] 공개키 핸들
      CK_OBJECT_HANDLE_PTR phPrivateKey      // [out] 개인키 핸들
  );
  ```
- **반환값**: `CKR_OK`; `CKR_MECHANISM_INVALID`(ML-DSA/ML-KEM 외),
  `CKR_TEMPLATE_INCONSISTENT`, `CKR_ATTRIBUTE_VALUE_INVALID`(잘못된 PARAMETER_SET),
  `CKR_USER_NOT_LOGGED_IN`.

### 12.3 `SC_DeriveKey` (app: `C_DeriveKey`)
- **기능**: 기존 키에서 새 키를 유도한다. NCMP는 **SHAKE-128/256 KDF**
  (`t_shake_key_derive`, `NCMP_CMD_SHAKE_DERIVE`)만 지원한다.
- **원형 및 인자**:
  ```c
  CK_RV SC_DeriveKey(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_MECHANISM_PTR pMechanism,    // CKM_SHAKE_128_KDF / CKM_SHAKE_256_KDF
      CK_OBJECT_HANDLE hBaseKey,      // 기반 키 핸들
      CK_ATTRIBUTE_PTR pTemplate,     // 유도 키 속성 템플릿
      CK_ULONG ulCount,               // 속성 개수
      CK_OBJECT_HANDLE_PTR phKey      // [out] 유도된 키 핸들
  );
  ```
- **반환값**: `CKR_OK`; `CKR_MECHANISM_INVALID`(SHAKE 외),
  `CKR_KEY_TYPE_INCONSISTENT`, `CKR_TEMPLATE_INCONSISTENT`.

### 12.4 `SC_WrapKey` (app: `C_WrapKey`)
- **기능**: 키를 다른 키로 래핑(암호화 export)한다. NCMP는 wrap 훅이 없어 미지원.
- **원형 및 인자**:
  ```c
  CK_RV SC_WrapKey(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_MECHANISM_PTR pMechanism,    // 래핑 메커니즘
      CK_OBJECT_HANDLE hWrappingKey,  // 래핑 키 핸들
      CK_OBJECT_HANDLE hKey,          // 래핑될 키 핸들
      CK_BYTE_PTR pWrappedKey,        // [out] 래핑 결과(NULL=길이만)
      CK_ULONG_PTR pulWrappedKeyLen   // [in/out] 버퍼 길이 / 실제 길이
  );
  ```
- **반환값**: **미지원** → `CKR_MECHANISM_INVALID` / `CKR_FUNCTION_NOT_SUPPORTED`.

### 12.5 `SC_UnwrapKey` (app: `C_UnwrapKey`)
- **기능**: 래핑된 키를 언래핑(복호 import)한다. NCMP는 unwrap 훅이 없어 미지원.
- **원형 및 인자**:
  ```c
  CK_RV SC_UnwrapKey(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_MECHANISM_PTR pMechanism,    // 언래핑 메커니즘
      CK_OBJECT_HANDLE hUnwrappingKey,// 언래핑 키 핸들
      CK_BYTE_PTR pWrappedKey,        // 래핑된 키 바이트
      CK_ULONG ulWrappedKeyLen,       // 길이
      CK_ATTRIBUTE_PTR pTemplate,     // 결과 키 속성 템플릿
      CK_ULONG ulCount,               // 속성 개수
      CK_OBJECT_HANDLE_PTR phKey      // [out] 언래핑된 키 핸들
  );
  ```
- **반환값**: **미지원** → `CKR_MECHANISM_INVALID` / `CKR_FUNCTION_NOT_SUPPORTED`.

### 12.6 `SC_EncapsulateKey` (app: `C_EncapsulateKey`, PKCS#11 3.2)
- **기능**: KEM 캡슐화. 공개키로 공유비밀(대칭 키)을 만들고 암호문을 반환한다. NCMP는
  **ML-KEM**(`t_ml_kem_encapsulate_key`, `NCMP_CMD_MLKEM_*`)만 지원.
- **원형 및 인자**:
  ```c
  CK_RV SC_EncapsulateKey(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_T *sSession,         // 세션
      CK_MECHANISM_PTR pMechanism,    // CKM_ML_KEM
      CK_OBJECT_HANDLE hPublicKey,    // 캡슐화용 공개키 핸들
      CK_ATTRIBUTE_PTR pTemplate,     // 생성 공유키 속성 템플릿
      CK_ULONG ulAttributeCount,      // 속성 개수
      CK_BYTE_PTR pCiphertext,        // [out] 캡슐 암호문(NULL=길이만)
      CK_ULONG_PTR pulCiphertextLen,  // [in/out] 버퍼 길이 / 실제 길이
      CK_OBJECT_HANDLE_PTR phKey      // [out] 생성된 공유 대칭키 핸들
  );
  ```
- **반환값**: `CKR_OK`; `CKR_MECHANISM_INVALID`(ML-KEM 외),
  `CKR_KEY_TYPE_INCONSISTENT`, `CKR_BUFFER_TOO_SMALL`, `CKR_TEMPLATE_INCONSISTENT`.

### 12.7 `SC_DecapsulateKey` (app: `C_DecapsulateKey`, PKCS#11 3.2)
- **기능**: KEM 역캡슐화. 개인키와 암호문으로 공유비밀(대칭 키)을 복원한다. NCMP는
  **ML-KEM**(`t_ml_kem_decapsulate_key`)만 지원.
- **원형 및 인자**:
  ```c
  CK_RV SC_DecapsulateKey(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_T *sSession,         // 세션
      CK_MECHANISM_PTR pMechanism,    // CKM_ML_KEM
      CK_OBJECT_HANDLE hPrivateKey,   // 역캡슐화용 개인키 핸들
      CK_ATTRIBUTE_PTR pTemplate,     // 복원 공유키 속성 템플릿
      CK_ULONG ulAttributeCount,      // 속성 개수
      CK_BYTE_PTR pCiphertext,        // 캡슐 암호문
      CK_ULONG ulCiphertextLen,       // 암호문 길이
      CK_OBJECT_HANDLE_PTR phKey      // [out] 복원된 공유 대칭키 핸들
  );
  ```
- **반환값**: `CKR_OK`; `CKR_MECHANISM_INVALID`(ML-KEM 외),
  `CKR_ENCAPSULATED_DATA_INVALID` / `CKR_ENCAPSULATED_KEY_INVALID`,
  `CKR_TEMPLATE_INCONSISTENT`.

---

## 13. 난수 (Random)

### 13.1 `SC_GenerateRandom` (app: `C_GenerateRandom`)
- **기능**: 토큰 RNG에서 난수를 생성한다(`t_rng` → `NCMP_CMD_RNG`).
- **원형 및 인자**:
  ```c
  CK_RV SC_GenerateRandom(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_BYTE_PTR pRandomData,        // [out] 난수 버퍼
      CK_ULONG ulRandomLen            // 요청 바이트 수
  );
  ```
- **반환값**: `CKR_OK`; `CKR_ARGUMENTS_BAD`(pRandomData==NULL),
  `CKR_DEVICE_ERROR`(전송 실패 매핑).

### 13.2 `SC_SeedRandom` (app: `C_SeedRandom`)
- **기능**: RNG에 시드를 공급한다. NCMP는 시드 훅이 없어 미지원(토큰이 자체 엔트로피
  사용).
- **원형 및 인자**:
  ```c
  CK_RV SC_SeedRandom(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_BYTE_PTR pSeed,              // 시드 바이트
      CK_ULONG ulSeedLen              // 시드 길이
  );
  ```
- **반환값**: **미지원** → `CKR_RANDOM_SEED_NOT_SUPPORTED` /
  `CKR_FUNCTION_NOT_SUPPORTED`.

---

## 14. 벤더 확장 (IBM)

### 14.1 `SC_IBM_ReencryptSingle` (app: `C_IBM_ReencryptSingle`)
- **기능**: IBM 벤더 확장. 복호와 재암호화를 토큰 내부에서 단일 호출로 수행한다. NCMP는
  전용 훅이 없어 미지원.
- **원형 및 인자**:
  ```c
  CK_RV SC_IBM_ReencryptSingle(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_T *sSession,         // 세션
      CK_MECHANISM_PTR pDecrMech,     // 복호 메커니즘
      CK_OBJECT_HANDLE hDecrKey,      // 복호 키 핸들
      CK_MECHANISM_PTR pEncrMech,     // 재암호 메커니즘
      CK_OBJECT_HANDLE hEncrKey,      // 재암호 키 핸들
      CK_BYTE_PTR pEncryptedData,     // 입력 암호문
      CK_ULONG ulEncryptedDataLen,    // 입력 길이
      CK_BYTE_PTR pReencryptedData,   // [out] 재암호문(NULL=길이만)
      CK_ULONG_PTR pulReencryptedDataLen // [in/out] 버퍼 길이 / 실제 길이
  );
  ```
- **반환값**: **미지원** → `CKR_FUNCTION_NOT_SUPPORTED` / `CKR_MECHANISM_INVALID`.

---

## 부록 A. export 심볼 ↔ 애플리케이션 `C_*` 대응 (73개)

| # | export 심볼(`SC_*`) | 애플리케이션 `C_*` | NCMP 지원 |
|---|---------------------|--------------------|-----------|
| 1 | `ST_Initialize` | `C_Initialize` 경로 | ✅ (ncmpd 연결) |
| 2 | `SC_SetFunctionList` | (내부 등록) | — |
| 3 | `SC_Finalize` | `C_Finalize` | ✅ |
| 4 | `SC_GetTokenInfo` | `C_GetTokenInfo` | ✅ |
| 5 | `SC_GetMechanismList` | `C_GetMechanismList` | ✅ |
| 6 | `SC_GetMechanismInfo` | `C_GetMechanismInfo` | ✅ |
| 7 | `SC_InitToken` | `C_InitToken` | ✅ |
| 8 | `SC_InitPIN` | `C_InitPIN` | ✅ |
| 9 | `SC_SetPIN` | `C_SetPIN` | ✅ |
| 10 | `SC_WaitForSlotEvent` | `C_WaitForSlotEvent` | ✅(공통) |
| 11 | `SC_OpenSession` | `C_OpenSession` | ✅ |
| 12 | `SC_CloseSession` | `C_CloseSession` | ✅ |
| 13 | `SC_CloseAllSessions` | `C_CloseAllSessions` | ✅ |
| 14 | `SC_GetSessionInfo` | `C_GetSessionInfo` | ✅ |
| 15 | `SC_Login` | `C_Login` | ✅ |
| 16 | `SC_Logout` | `C_Logout` | ✅ |
| 17 | `SC_SessionCancel` | `C_SessionCancel` | ✅ |
| 18 | `SC_CancelFunction` | `C_CancelFunction` | ⛔ deprecated |
| 19 | `SC_GetFunctionStatus` | `C_GetFunctionStatus` | ⛔ deprecated |
| 20 | `SC_GetOperationState` | `C_GetOperationState` | ⛔ 상태저장 불가 |
| 21 | `SC_SetOperationState` | `C_SetOperationState` | ⛔ 상태저장 불가 |
| 22 | `SC_CreateObject` | `C_CreateObject` | ✅ |
| 23 | `SC_CopyObject` | `C_CopyObject` | ✅ |
| 24 | `SC_DestroyObject` | `C_DestroyObject` | ✅ |
| 25 | `SC_GetObjectSize` | `C_GetObjectSize` | ✅ |
| 26 | `SC_GetAttributeValue` | `C_GetAttributeValue` | ✅ |
| 27 | `SC_SetAttributeValue` | `C_SetAttributeValue` | ✅ |
| 28 | `SC_FindObjectsInit` | `C_FindObjectsInit` | ✅ |
| 29 | `SC_FindObjects` | `C_FindObjects` | ✅ |
| 30 | `SC_FindObjectsFinal` | `C_FindObjectsFinal` | ✅ |
| 31 | `SC_EncryptInit` | `C_EncryptInit` | ✅ AES-GCM/CTR |
| 32 | `SC_Encrypt` | `C_Encrypt` | ✅ |
| 33 | `SC_EncryptUpdate` | `C_EncryptUpdate` | ✅ GCM |
| 34 | `SC_EncryptFinal` | `C_EncryptFinal` | ✅ GCM |
| 35 | `SC_DecryptInit` | `C_DecryptInit` | ✅ AES-GCM/CTR |
| 36 | `SC_Decrypt` | `C_Decrypt` | ✅ |
| 37 | `SC_DecryptUpdate` | `C_DecryptUpdate` | ✅ GCM |
| 38 | `SC_DecryptFinal` | `C_DecryptFinal` | ✅ GCM |
| 39 | `SC_DigestInit` | `C_DigestInit` | ✅ SHA-2/3 |
| 40 | `SC_Digest` | `C_Digest` | ✅ |
| 41 | `SC_DigestUpdate` | `C_DigestUpdate` | ✅ |
| 42 | `SC_DigestKey` | `C_DigestKey` | ⛔ secure-key |
| 43 | `SC_DigestFinal` | `C_DigestFinal` | ✅ |
| 44 | `SC_SignInit` | `C_SignInit` | ✅ ML-DSA |
| 45 | `SC_Sign` | `C_Sign` | ✅ ML-DSA |
| 46 | `SC_SignUpdate` | `C_SignUpdate` | ⛔ 단발전용 |
| 47 | `SC_SignFinal` | `C_SignFinal` | ⛔ 단발전용 |
| 48 | `SC_SignRecoverInit` | `C_SignRecoverInit` | ⛔ RSA전용 |
| 49 | `SC_SignRecover` | `C_SignRecover` | ⛔ RSA전용 |
| 50 | `SC_VerifyInit` | `C_VerifyInit` | ✅ ML-DSA |
| 51 | `SC_Verify` | `C_Verify` | ✅ ML-DSA |
| 52 | `SC_VerifyUpdate` | `C_VerifyUpdate` | ⛔ 단발전용 |
| 53 | `SC_VerifyFinal` | `C_VerifyFinal` | ⛔ 단발전용 |
| 54 | `SC_VerifyRecoverInit` | `C_VerifyRecoverInit` | ⛔ RSA전용 |
| 55 | `SC_VerifyRecover` | `C_VerifyRecover` | ⛔ RSA전용 |
| 56 | `SC_VerifySignatureInit` | `C_VerifySignatureInit` | ✅ ML-DSA |
| 57 | `SC_VerifySignature` | `C_VerifySignature` | ✅ ML-DSA |
| 58 | `SC_VerifySignatureUpdate` | `C_VerifySignatureUpdate` | ⛔ 단발전용 |
| 59 | `SC_VerifySignatureFinal` | `C_VerifySignatureFinal` | ⛔ 단발전용 |
| 60 | `SC_DigestEncryptUpdate` | `C_DigestEncryptUpdate` | ✅(조합) |
| 61 | `SC_DecryptDigestUpdate` | `C_DecryptDigestUpdate` | ✅(조합) |
| 62 | `SC_SignEncryptUpdate` | `C_SignEncryptUpdate` | ⛔ |
| 63 | `SC_DecryptVerifyUpdate` | `C_DecryptVerifyUpdate` | ⛔ |
| 64 | `SC_GenerateKey` | `C_GenerateKey` | ✅ AES |
| 65 | `SC_GenerateKeyPair` | `C_GenerateKeyPair` | ✅ ML-DSA/ML-KEM |
| 66 | `SC_DeriveKey` | `C_DeriveKey` | ✅ SHAKE KDF |
| 67 | `SC_WrapKey` | `C_WrapKey` | ⛔ |
| 68 | `SC_UnwrapKey` | `C_UnwrapKey` | ⛔ |
| 69 | `SC_EncapsulateKey` | `C_EncapsulateKey` | ✅ ML-KEM |
| 70 | `SC_DecapsulateKey` | `C_DecapsulateKey` | ✅ ML-KEM |
| 71 | `SC_GenerateRandom` | `C_GenerateRandom` | ✅ |
| 72 | `SC_SeedRandom` | `C_SeedRandom` | ⛔ |
| 73 | `SC_IBM_ReencryptSingle` | `C_IBM_ReencryptSingle` | ⛔ |

> 참고: `SC_HandleEvent`는 `new_host.c`에 정의되어 있으나 `opencryptoki_tok.map`에서
> export 되지 않으므로(내부적으로 `function_list.ST_HandleEvent`에만 연결) 애플리케이션
> API 표면이 아니다.

# NCMP 직접 사용 API — opencryptoki 없이 `libpkcs11_ncmp.so` 구동

opencryptoki(pkcsslotd)와 그 슬롯매니저 공유메모리를 **사용하지 않는**
애플리케이션이 `libpkcs11_ncmp.so`를 직접 로드해 쓸 때의 공개 API 함수 각각을
**기능 / 원형 및 인자 / 반환값** 형식으로 정리한다.

> **함께 보기**: opencryptoki를 통해(표준 `C_*` 경유) 사용하는 경우는
> [`cryptoki_app_api.md`](cryptoki_app_api.md)에 정리되어 있다. 두 문서는 **같은 73개
> export 심볼**을 다루되, 이 문서는 앱이 심볼을 **직접** 호출하는 관점,
> `cryptoki_app_api.md`는 libopencryptoki가 대신 호출해 주는 관점이다.

> **갱신(중요)**: 아래 §전제는 "STDLL이 `C_*`/`C_GetFunctionList`를 export 하지 않는다"
> 고 서술하지만, 이후 **독립 PKCS#11 provider 파사드**(`ncmp_p11.c`)가 추가되어
> `libpkcs11_ncmp.so`가 이제 **`C_GetFunctionList`/`C_GetInterface(List)`/`C_*`도
> export** 한다. 즉 앱이 `dlopen`+`dlsym`으로 **직접 표준 PKCS#11 모듈처럼** 쓸 수 있다
> (→ [`dual-mode-provider.md`](dual-mode-provider.md)). 본문의 `SC_*` 설명은 "모드 1"
> (libopencryptoki 경유 SPI) 관점으로 읽을 것.

---

## 반드시 먼저 이해할 전제 (중요)

`libpkcs11_ncmp.so`는 **독립형 PKCS#11 프로바이더가 아니라 opencryptoki STDLL(토큰
SPI)**이다. 다음이 사실이므로 "직접 사용"의 의미와 한계를 먼저 규정한다.

1. **export 심볼은 `SC_*`(72개) + `ST_Initialize`(1개) = 73개뿐이다.**
   ([`opencryptoki_tok.map`](../opencryptoki_tok.map), 나머지는 `local: *;`로 은닉.)
   **`C_GetFunctionList`도, 표준 `C_*` 함수도 export 하지 않는다.** 따라서 일반적인
   PKCS#11 로더(`dlopen` + `C_GetFunctionList`)로는 이 `.so`를 표준 모듈로 적재할 수
   없다.
2. 그러므로 opencryptoki를 쓰지 않는 앱이 이 `.so`를 직접 쓰려면, 앱이
   **libopencryptoki(api 계층)가 하던 일을 스스로 대신** 해야 한다:
   - `STDLL_TokData_t`(토큰 인스턴스 데이터)를 **직접 할당·초기화**하고
     (`policy`, `data_store` 설정 포함) 수명을 관리,
   - `API_Slot_t` / `SLOT_INFO`를 구성해 `ST_Initialize` 호출,
   - `SC_OpenSession`이 돌려준 세션 핸들을 **`ST_SESSION_T`로 감싸** 세션 함수에 전달,
   - 오브젝트/세션 btree, XProcLock 등 공통 계층 요구사항 충족.
   - 즉, 실질적으로 **api 계층 상당 부분을 재구현**하는 셈이며, 표준 `C_*` 시맨틱
     (2-패스 길이 조회, 상태 전이 등)도 앱이 지켜야 한다.
3. **공유메모리에 대한 정정**: 앱이 피하는 것은 **opencryptoki의 pkcsslotd와 그
   슬롯매니저 SHM/프로세스 등록**이다. 그러나 토큰까지의 실제 전송은 **여전히 별도
   데몬 `ncmpd`를 UNIX 도메인 소켓(`/run/ncmpd/ncmpd.sock`) + POSIX 공유메모리**로
   거친다(STDLL의 `t_init`이 `ncmp_client_init`으로 ncmpd에 연결·SHM 부착). 이
   전송용 SHM은 **회피 대상이 아니며 NCMP 구조상 필수**다. 과거 존재하던 독립형
   프로바이더(`ncmp/pkcs11/`)도 동일한 `ncmp_client` SHM 전송을 사용했고 현재는
   제거되었다.
4. **권장 경로**: 표준 PKCS#11 애플리케이션은 opencryptoki를 통해
   ([`cryptoki_app_api.md`](cryptoki_app_api.md)) 사용하는 것이 정상 경로다. 이 문서의
   직접 SPI 구동은 opencryptoki 프레임워크를 대체·임베드하려는 고급/특수 용도를 위한
   레퍼런스다.

관련: [`ncmpd-vs-pkcsslotd.md`](ncmpd-vs-pkcsslotd.md)(데몬 역할 구분),
[`middleware_api.md`](middleware_api.md)(STDLL 내부 어댑터/전송),
[`stdll-call-flow.md`](stdll-call-flow.md), [`architecture.md`](architecture.md).

---

## 0. 타입 · 구조체 · 상수

원형에 등장하는 구조체와 `#define`을 먼저 정리한다. 출처는
[`usr/include/stdll.h`](../usr/include/stdll.h)(STDLL SPI 타입),
[`usr/include/pkcs11types.h`](../usr/include/pkcs11types.h)(PKCS#11 표준 타입),
[`ncmp/include/ncmp/ncmp_limits.h`](../ncmp/include/ncmp/ncmp_limits.h) /
[`ncmp_ipc.h`](../ncmp/include/ncmp/ncmp_ipc.h)(NCMP 한계·전송 상수).

### 0.1 STDLL SPI 타입 — **직접 사용 시 앱이 공급·관리해야 하는 것**

opencryptoki 경유일 때는 api 계층이 만들어 주지만, 직접 사용 시에는 **앱이 직접
채워야** 한다.

```c
/* 토큰 인스턴스 데이터(불투명, host_defs.h). 슬롯별 nv_token_data, private_data
 * (내부에 ncmpd 연결 ncmp_client_t), 세션/오브젝트 btree, policy, data_store,
 * XProcLock 상태를 담는다. 직접 사용 시 앱이 할당하고 policy/data_store 등을
 * 채운 뒤 ST_Initialize에 넘겨야 한다. 모든 SC_*의 첫 인자. */
typedef struct _STDLL_TokData_t STDLL_TokData_t;

/* ST_Initialize에 넘기는 슬롯 엔트리(불투명, apictl.h). 최소한 TokData 포인터를
 * 담아야 하며(ST_Initialize가 sltp->TokData를 사용), 함수목록 포인터 등을 보관. */
typedef struct API_Slot_t API_Slot_t;

/* 슬롯 설정(slotmgr.h): 토큰 디렉터리명(tokname), 데이터스토어 버전(version) 등.
 * ST_Initialize / SC_Finalize / SC_...가 참조. */
typedef struct SLOT_INFO SLOT_INFO;

/* 트레이스 핸들(불투명). 로깅 대상. */
typedef struct trace_handle_t trace_handle;

/* 세션 핸들 = (슬롯 id, 세션 핸들, R/W 여부) 쌍. SC_OpenSession이 채운
 * CK_SESSION_HANDLE로부터 앱이 이 구조체를 구성해 세션 함수에 &로 전달한다. */
typedef struct {
    struct bt_ref_hdr hdr;      /* 레퍼런스 카운트 헤더(내부) */
    CK_SLOT_ID        slotID;   /* 슬롯 id */
    CK_SESSION_HANDLE sessionh; /* 세션 핸들 */
    CK_BBOOL          rw_session; /* R/W 세션 여부 */
} ST_SESSION_T;
typedef ST_SESSION_T ST_SESSION_HANDLE;   /* 동의어 */
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

/* SC_GetSessionInfo 출력 */
typedef struct CK_SESSION_INFO {
    CK_SLOT_ID slotID;               /* 슬롯 id */
    CK_STATE   state;                /* RO/RW·public/user/SO 상태 */
    CK_FLAGS   flags;                /* CKF_SERIAL_SESSION | CKF_RW_SESSION */
    CK_ULONG   ulDeviceError;        /* 디바이스 의존 오류 코드 */
} CK_SESSION_INFO;

/* SC_GetTokenInfo 출력 (NCMP는 VD_TOKEN_INFO/GET_TOKEN_PARAMS/GET_UTC_TIME로 채움) */
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

/* SC_GetMechanismInfo 출력 */
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
| `CK_ULONG` / `CK_ULONG_PTR` | 부호 없는 정수 / 그 포인터(길이 in/out). |
| `CK_BYTE_PTR` / `CK_CHAR_PTR` | 바이트 · 문자 버퍼 포인터(데이터·PIN·라벨). |
| `CK_FLAGS` | 비트 플래그(`CK_ULONG`). |
| `CK_MECHANISM_TYPE` / `CK_USER_TYPE` / `CK_STATE` | 메커니즘 · 사용자 역할 · 세션 상태 열거값. |
| `CK_BBOOL` | 불리언(`CK_TRUE`/`CK_FALSE`). |
| `CK_VOID_PTR` | 임의 포인터(예약·파라미터). |
| `..._PTR` (`CK_MECHANISM_PTR` 등) | 위 구조체의 포인터형. |

### 0.4 주요 상수 · `#define`

**세션 flags** (`SC_OpenSession` / `CK_SESSION_INFO.flags`):

| 상수 | 값 | 의미 |
|------|----|------|
| `CKF_SERIAL_SESSION` | `0x00000004` | 직렬 세션(필수). |
| `CKF_RW_SESSION` | `0x00000002` | 읽기/쓰기 세션(미설정 시 RO). |
| `CKF_DONT_BLOCK` | `1` | `SC_WaitForSlotEvent` 논블로킹 폴링. |

**사용자 역할** (`SC_Login`의 `userType`): `CKU_SO`, `CKU_USER`,
`CKU_CONTEXT_SPECIFIC`(로그인 상태 유지 재인증).

**NCMP 자원 한계 · 전송 상수**:

| 상수 | 값 | 의미 |
|------|----|------|
| `PKCS11_MAX_SLOT_COUNT` | 4 | 최대 CK 슬롯 수. |
| `PKCS11_MAX_SESSION_PER_SLOT` | 8 | 슬롯당 최대 세션(`SC_OpenSession` 상한). |
| `PKCS11_MAX_TOTAL_SESSIONS` | 32 | 전체 세션 상한(`4 × 8`). |
| `NCMP_MAX_PARAM_SIZE` | 65512 | 단일 파라미터 최대 바이트(프레임 1개=64KB). |
| `NCMP_HOST_CTX_BLOB_MAX` | 256 | 멀티파트 UPDATE id→blob 치환 대비 헤드룸. |
| `NCMP_MP_UPDATE_MAX_DATA` | 파생 | `Digest/EncryptUpdate` 1회 최대 데이터. |
| `NCMP_IPC_SOCK_PATH` | `/run/ncmpd/ncmpd.sock` | STDLL↔ncmpd UNIX 소켓 기본 경로. |

**메커니즘 상수**(`CK_MECHANISM.mechanism`, 지원 목록): `CKM_AES_GCM`,
`CKM_AES_CTR`, `CKM_AES_KEY_GEN`, `CKM_SHA256`, `CKM_SHA512`,
`CKM_SHA3_224/256/384/512`, `CKM_SHAKE_128_KDF`, `CKM_SHAKE_256_KDF`,
`CKM_ML_DSA`·`CKM_ML_DSA_KEY_PAIR_GEN`, `CKM_ML_KEM`·`CKM_ML_KEM_KEY_PAIR_GEN`
뿐(→ [지원 범위](#지원-범위)). strength는 키의 `CKA_PARAMETER_SET`로 선택.

### 0.5 직접 사용 초기화 시퀀스 (개요)

직접 사용 앱이 크립토 호출 전에 밟아야 하는 순서:

```text
1) dlopen("libpkcs11_ncmp.so")
2) dlsym: ST_Initialize, 필요한 SC_* 심볼 확보
3) STDLL_TokData_t 할당 + policy/data_store/nv_token_data 등 초기화
4) API_Slot_t{ .TokData = &tokdata }, SLOT_INFO{ .tokname, .version } 구성
5) ST_Initialize(&slot, slotID, &slotinfo, trace)   // t_init이 ncmpd에 연결
6) SC_OpenSession(&tokdata, slotID, CKF_SERIAL_SESSION[|CKF_RW_SESSION], &h)
7) (필요시) SC_Login(&tokdata, &sess, CKU_USER, pin, pinlen)
8) SC_EncryptInit/Encrypt ... 등 SPI 직접 호출
9) SC_CloseSession / SC_Finalize
```

### 0.6 공통 호출 규약 (모든 `SC_*`에 적용)

아래는 개별 함수 설명에서 반복하지 않는다.

- **첫 인자 `tokdata`**: 5)에서 초기화한 `STDLL_TokData_t *`를 그대로 넘긴다.
- **세션 인자 `sSession`**: `SC_OpenSession`이 채운 `CK_SESSION_HANDLE`로부터 앱이
  `ST_SESSION_T{ slotID, sessionh, rw_session }`를 구성해 `&`로 넘긴다.
- **반환형**: 모든 함수 `CK_RV`(`CKR_*`).
- **공통 반환값**: `CKR_OK`; `CKR_CRYPTOKI_NOT_INITIALIZED`(ST_Initialize 이전),
  `CKR_SESSION_HANDLE_INVALID`(세션 함수), `CKR_ARGUMENTS_BAD`/`CKR_BUFFER_TOO_SMALL`,
  `CKR_HOST_MEMORY`/`CKR_GENERAL_ERROR`. **전송 실패**(ncmpd 부재·USB 오류·타임아웃)는
  `ncmp_err_to_ckr()`를 거쳐 `CKR_TOKEN_NOT_PRESENT`/`CKR_DEVICE_ERROR`/
  `CKR_FUNCTION_CANCELED`/`CKR_DEVICE_MEMORY`로 매핑되고, **토큰 거부**는 물리 토큰의
  `ack`(그대로 `CKR_*`)가 반환된다. 개별 "반환값"은 이 위에 함수 고유 값만 명시한다.

### <a id="지원-범위"></a>0.7 지원 범위

NCMP는 secure-key 프록시 토큰이라 `token_specific`
([`tok_struct.h`](../usr/lib/ncmp_stdll/tok_struct.h))에 채워진 훅만 동작하고, NULL
훅은 공통 계층이 `CKR_MECHANISM_INVALID`/`CKR_FUNCTION_NOT_SUPPORTED`로 거부한다.
지원: AES-GCM·AES-CTR, SHA-256/512·SHA3-224/256/384/512, SHAKE-128/256 KDF,
ML-KEM(1/3/5)·ML-DSA(1/3/5), RNG, AES 키 생성. 미지원: RSA·EC·DH·ECDH·HMAC·AES-블록,
키 wrap/unwrap, recover, 연산상태 저장, seed-random, 멀티파트 서명/검증.

---

## 1. 초기화 · 함수 목록

### 1.1 `ST_Initialize`
- **기능**: STDLL 토큰 인스턴스 초기화 진입점. 직접 사용 시 앱이 채운
  `sltp->TokData`를 받아 btree·데이터스토어·정책·XProcLock을 세팅하고
  `token_specific.t_init`으로 **ncmpd에 연결**한다. 모든 SC_* 호출의 전제.
- **원형 및 인자**:
  ```c
  CK_RV ST_Initialize(
      API_Slot_t *sltp,               // 앱이 구성한 슬롯 엔트리(sltp->TokData 필수)
      CK_SLOT_ID SlotNumber,          // 슬롯 id
      SLOT_INFO *sinfp,               // 슬롯 설정(tokname/version)
      struct trace_handle_t t         // 트레이스 핸들
  );
  ```
- **반환값**: `CKR_OK`; `CKR_TOKEN_NOT_PRESENT`(ncmpd/토큰 부재),
  `CKR_FUNCTION_FAILED`(btree/데이터스토어/락 실패), `CKR_HOST_MEMORY`.

### 1.2 `SC_SetFunctionList`
- **기능**: STDLL 내부 `function_list`(`ST_*` 포인터 테이블)를 채운다. 직접 사용 시
  이 테이블은 필요 없지만(앱이 `SC_*`를 직접 호출), export 되어 있어 호출 가능하다.
- **원형 및 인자**:
  ```c
  void SC_SetFunctionList(void);      // 인자 없음, 반환 없음
  ```
- **반환값**: 없음(`void`).

### 1.3 `SC_Finalize`
- **기능**: 토큰 인스턴스 정리. `token_specific.t_final`로 **ncmpd 연결/SHM 해제**하고
  열린 세션을 닫는다.
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

### 2.1 `SC_GetTokenInfo`
- **기능**: 슬롯에 바인딩된 물리 토큰의 `CK_TOKEN_INFO`를 반환한다.
- **원형 및 인자**:
  ```c
  CK_RV SC_GetTokenInfo(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      CK_SLOT_ID sid,                 // 슬롯 id
      CK_TOKEN_INFO_PTR pInfo         // [out] 토큰 정보
  );
  ```
- **반환값**: `CKR_OK`; `CKR_SLOT_ID_INVALID`, `CKR_TOKEN_NOT_PRESENT`,
  `CKR_ARGUMENTS_BAD`.

### 2.2 `SC_GetMechanismList`
- **기능**: 광고 메커니즘 타입 목록을 반환한다(`pMechList==NULL`이면 개수만).
- **원형 및 인자**:
  ```c
  CK_RV SC_GetMechanismList(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      CK_SLOT_ID sid,                 // 슬롯 id
      CK_MECHANISM_TYPE_PTR pMechList,// [out] 메커니즘 배열(NULL=개수만)
      CK_ULONG_PTR count              // [in/out] 용량 / 실제 개수
  );
  ```
- **반환값**: `CKR_OK`; `CKR_BUFFER_TOO_SMALL`, `CKR_ARGUMENTS_BAD`.

### 2.3 `SC_GetMechanismInfo`
- **기능**: 특정 메커니즘의 `CK_MECHANISM_INFO`를 반환한다.
- **원형 및 인자**:
  ```c
  CK_RV SC_GetMechanismInfo(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      CK_SLOT_ID sid,                 // 슬롯 id
      CK_MECHANISM_TYPE type,         // 조회할 메커니즘
      CK_MECHANISM_INFO_PTR pInfo     // [out] 메커니즘 정보
  );
  ```
- **반환값**: `CKR_OK`; `CKR_MECHANISM_INVALID`(광고 목록 밖), `CKR_ARGUMENTS_BAD`.

### 2.4 `SC_InitToken`
- **기능**: SO PIN으로 토큰을 초기화하고 라벨을 설정한다(set→read-back→validate→
  persist→zeroize).
- **원형 및 인자**:
  ```c
  CK_RV SC_InitToken(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      CK_SLOT_ID sid,                 // 슬롯 id
      CK_CHAR_PTR pPin,               // SO PIN
      CK_ULONG ulPinLen,              // SO PIN 길이
      CK_CHAR_PTR pLabel              // 32바이트 라벨(공백 패딩)
  );
  ```
- **반환값**: `CKR_OK`; `CKR_PIN_INCORRECT`, `CKR_PIN_LEN_RANGE`,
  `CKR_SESSION_EXISTS`, `CKR_ARGUMENTS_BAD`.

### 2.5 `SC_InitPIN`
- **기능**: SO 로그인 상태에서 user PIN을 초기화한다(`NCMP_CMD_INIT_PIN`).
- **원형 및 인자**:
  ```c
  CK_RV SC_InitPIN(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션(SO 로그인 필요)
      CK_CHAR_PTR pPin,               // 새 user PIN
      CK_ULONG ulPinLen               // PIN 길이
  );
  ```
- **반환값**: `CKR_OK`; `CKR_USER_NOT_LOGGED_IN`, `CKR_PIN_LEN_RANGE`,
  `CKR_SESSION_READ_ONLY`.

### 2.6 `SC_SetPIN`
- **기능**: 로그인 사용자의 PIN을 변경한다(`NCMP_CMD_SET_PIN`).
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

### 2.7 `SC_WaitForSlotEvent`
- **기능**: 슬롯 삽입/제거 이벤트 대기(또는 `CKF_DONT_BLOCK` 폴링). 직접 사용 시 앱이
  이벤트 루프를 직접 구동해야 한다.
- **원형 및 인자**:
  ```c
  CK_RV SC_WaitForSlotEvent(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      CK_FLAGS flags,                 // 0 또는 CKF_DONT_BLOCK
      CK_SLOT_ID_PTR pSlot,           // [out] 이벤트 슬롯
      CK_VOID_PTR pReserved           // 예약(NULL)
  );
  ```
- **반환값**: `CKR_OK`; `CKR_NO_EVENT`, `CKR_FUNCTION_NOT_SUPPORTED`.

---

## 3. 세션 관리 · 로그인

### 3.1 `SC_OpenSession`
- **기능**: 슬롯에 세션을 연다. 세션 카운터는 `sess_lock` 하에서 슬롯당 8·전체 32
  상한을 강제한다. **반환된 핸들로 앱이 `ST_SESSION_T`를 구성**해 이후 세션 함수에
  넘긴다.
- **원형 및 인자**:
  ```c
  CK_RV SC_OpenSession(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      CK_SLOT_ID sid,                 // 슬롯 id
      CK_FLAGS flags,                 // CKF_SERIAL_SESSION | (CKF_RW_SESSION)
      CK_SESSION_HANDLE_PTR phSession // [out] 세션 핸들
  );
  ```
- **반환값**: `CKR_OK`; `CKR_SESSION_COUNT`/`CKR_SESSION_COUNT_EXCEEDED`,
  `CKR_SESSION_PARALLEL_NOT_SUPPORTED`, `CKR_SLOT_ID_INVALID`.

### 3.2 `SC_CloseSession`
- **기능**: 세션 하나를 닫고 카운터를 감소시키며, 진행 중 멀티파트 컨텍스트를
  `NCMP_CMD_CTX_FREE`로 해제한다.
- **원형 및 인자**:
  ```c
  CK_RV SC_CloseSession(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 닫을 세션
      CK_BBOOL in_fork_initializer    // fork 후 정리 경로 여부
  );
  ```
- **반환값**: `CKR_OK`, `CKR_SESSION_HANDLE_INVALID`.

### 3.3 `SC_CloseAllSessions`
- **기능**: 슬롯의 모든 세션을 닫고 로그인 상태를 해제한다.
- **원형 및 인자**:
  ```c
  CK_RV SC_CloseAllSessions(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      CK_SLOT_ID sid                  // 슬롯 id
  );
  ```
- **반환값**: `CKR_OK`, `CKR_SLOT_ID_INVALID`.

### 3.4 `SC_GetSessionInfo`
- **기능**: 세션의 `CK_SESSION_INFO`(슬롯·state·flags·디바이스 오류)를 반환한다.
- **원형 및 인자**:
  ```c
  CK_RV SC_GetSessionInfo(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_SESSION_INFO_PTR pInfo       // [out] 세션 정보
  );
  ```
- **반환값**: `CKR_OK`, `CKR_SESSION_HANDLE_INVALID`, `CKR_ARGUMENTS_BAD`.

### 3.5 `SC_Login`
- **기능**: 사용자/SO 로그인. 역할과 **플래그**(protected-auth: 토큰 패드 입력·빈 wire
  PIN / `CKU_CONTEXT_SPECIFIC`: 로그인 유지 재인증)를 `NCMP_CMD_LOGIN`으로 전달한다.
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
  `CKR_USER_PIN_NOT_INITIALIZED`, `CKR_OPERATION_NOT_INITIALIZED`.

### 3.6 `SC_Logout`
- **기능**: 로그인 상태를 해제한다(`NCMP_CMD_LOGOUT`).
- **원형 및 인자**:
  ```c
  CK_RV SC_Logout(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession     // 세션
  );
  ```
- **반환값**: `CKR_OK`, `CKR_USER_NOT_LOGGED_IN`.

### 3.7 `SC_SessionCancel` (PKCS#11 3.0)
- **기능**: 세션에서 지정 유형(flags)의 진행 중 연산을 취소한다(컨텍스트
  `NCMP_CMD_CTX_FREE`).
- **원형 및 인자**:
  ```c
  CK_RV SC_SessionCancel(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_FLAGS flags                  // 취소할 연산 종류 비트마스크
  );
  ```
- **반환값**: `CKR_OK`, `CKR_SESSION_HANDLE_INVALID`, `CKR_ARGUMENTS_BAD`.

### 3.8 `SC_CancelFunction` (deprecated)
- **기능**: 레거시 취소 API. 항상 미지원.
- **원형 및 인자**:
  ```c
  CK_RV SC_CancelFunction(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession     // 세션
  );
  ```
- **반환값**: `CKR_FUNCTION_NOT_PARALLEL`.

### 3.9 `SC_GetFunctionStatus` (deprecated)
- **기능**: 레거시 병렬 함수 상태 조회. 항상 미지원.
- **원형 및 인자**:
  ```c
  CK_RV SC_GetFunctionStatus(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession     // 세션
  );
  ```
- **반환값**: `CKR_FUNCTION_NOT_PARALLEL`.

### 3.10 `SC_GetOperationState`
- **기능**: 진행 중 연산 상태를 직렬화. NCMP 타입드 컨텍스트는 저장 불가라 미지원.
- **원형 및 인자**:
  ```c
  CK_RV SC_GetOperationState(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_BYTE_PTR pOperationState,    // [out] 상태(NULL=길이만)
      CK_ULONG_PTR pulOperationStateLen // [in/out] 버퍼 길이 / 실제 길이
  );
  ```
- **반환값**: **미지원** → `CKR_STATE_UNSAVEABLE`; `CKR_OPERATION_NOT_INITIALIZED`.

### 3.11 `SC_SetOperationState`
- **기능**: 직렬화된 연산 상태 복원. 미지원.
- **원형 및 인자**:
  ```c
  CK_RV SC_SetOperationState(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_BYTE_PTR pOperationState,    // 복원할 상태 blob
      CK_ULONG ulOperationStateLen,   // blob 길이
      CK_OBJECT_HANDLE hEncryptionKey,// 암복호 키 핸들
      CK_OBJECT_HANDLE hAuthenticationKey // 인증 키 핸들
  );
  ```
- **반환값**: **미지원** → `CKR_STATE_UNSAVEABLE` / `CKR_SAVED_STATE_INVALID`.

---

## 4. 오브젝트 관리

> 오브젝트 CRUD·핸들 매핑·find·size·destroy 는 공통 오브젝트 매니저 + 로컬 데이터
> 스토어가 처리한다. 직접 사용 시 이 데이터 스토어(파일 기반)를 앱이 초기화해 두어야
> 한다. 키 오브젝트만 물리 토큰에 등록/재검증된다(`t_object_add` /
> `t_set_attribute_values`).

### 4.1 `SC_CreateObject`
- **기능**: 템플릿으로 오브젝트 생성. 키면 `[class|key_type|value]`를 토큰에 등록.
- **원형 및 인자**:
  ```c
  CK_RV SC_CreateObject(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_ATTRIBUTE_PTR pTemplate,     // 속성 템플릿
      CK_ULONG ulCount,               // 속성 개수
      CK_OBJECT_HANDLE_PTR phObject   // [out] 오브젝트 핸들
  );
  ```
- **반환값**: `CKR_OK`; `CKR_TEMPLATE_INCOMPLETE`/`INCONSISTENT`,
  `CKR_ATTRIBUTE_VALUE_INVALID`, `CKR_USER_NOT_LOGGED_IN`, `CKR_SESSION_READ_ONLY`.

### 4.2 `SC_CopyObject`
- **기능**: 오브젝트 복사(+추가 템플릿). 키면 변경 속성을 토큰에 반영.
- **원형 및 인자**:
  ```c
  CK_RV SC_CopyObject(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_OBJECT_HANDLE hObject,       // 원본
      CK_ATTRIBUTE_PTR pTemplate,     // 덮어쓸 속성
      CK_ULONG ulCount,               // 속성 개수
      CK_OBJECT_HANDLE_PTR phNewObject// [out] 사본 핸들
  );
  ```
- **반환값**: `CKR_OK`; `CKR_OBJECT_HANDLE_INVALID`, `CKR_ATTRIBUTE_READ_ONLY`,
  `CKR_TEMPLATE_INCONSISTENT`.

### 4.3 `SC_DestroyObject`
- **기능**: 오브젝트 삭제.
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

### 4.4 `SC_GetObjectSize`
- **기능**: 오브젝트 바이트 크기 반환.
- **원형 및 인자**:
  ```c
  CK_RV SC_GetObjectSize(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_OBJECT_HANDLE hObject,       // 대상
      CK_ULONG_PTR pulSize            // [out] 크기
  );
  ```
- **반환값**: `CKR_OK`; `CKR_OBJECT_HANDLE_INVALID`, `CKR_INFORMATION_SENSITIVE`.

### 4.5 `SC_GetAttributeValue`
- **기능**: 오브젝트 속성값 읽기. 민감 속성은 `CKR_ATTRIBUTE_SENSITIVE`로 가려짐.
- **원형 및 인자**:
  ```c
  CK_RV SC_GetAttributeValue(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_OBJECT_HANDLE hObject,       // 대상
      CK_ATTRIBUTE_PTR pTemplate,     // [in/out] 조회 속성 / 값 수신
      CK_ULONG ulCount                // 속성 개수
  );
  ```
- **반환값**: `CKR_OK`; `CKR_ATTRIBUTE_SENSITIVE`, `CKR_ATTRIBUTE_TYPE_INVALID`,
  `CKR_BUFFER_TOO_SMALL`, `CKR_OBJECT_HANDLE_INVALID`.

### 4.6 `SC_SetAttributeValue`
- **기능**: 속성 변경. 키면 `NCMP_CMD_OBJECT_SET_ATTR`로 토큰에 반영.
- **원형 및 인자**:
  ```c
  CK_RV SC_SetAttributeValue(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_OBJECT_HANDLE hObject,       // 대상
      CK_ATTRIBUTE_PTR pTemplate,     // 변경 속성
      CK_ULONG ulCount                // 속성 개수
  );
  ```
- **반환값**: `CKR_OK`; `CKR_ATTRIBUTE_READ_ONLY`, `CKR_ATTRIBUTE_VALUE_INVALID`,
  `CKR_OBJECT_HANDLE_INVALID`, `CKR_SESSION_READ_ONLY`.

### 4.7 `SC_FindObjectsInit`
- **기능**: 템플릿 조건으로 검색 시작.
- **원형 및 인자**:
  ```c
  CK_RV SC_FindObjectsInit(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_ATTRIBUTE_PTR pTemplate,     // 매칭 템플릿(NULL/0=전체)
      CK_ULONG ulCount                // 속성 개수
  );
  ```
- **반환값**: `CKR_OK`; `CKR_OPERATION_ACTIVE`, `CKR_ATTRIBUTE_TYPE_INVALID`.

### 4.8 `SC_FindObjects`
- **기능**: 검색 결과 핸들을 최대 개수만큼 반환.
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
- **반환값**: `CKR_OK`; `CKR_OPERATION_NOT_INITIALIZED`, `CKR_ARGUMENTS_BAD`.

### 4.9 `SC_FindObjectsFinal`
- **기능**: 검색 종료.
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

> 지원: `CKM_AES_GCM`(one-shot + 멀티파트), `CKM_AES_CTR`(one-shot). 그 외는
> `SC_EncryptInit`에서 `CKR_MECHANISM_INVALID`.

### 5.1 `SC_EncryptInit`
- **기능**: 암호화 초기화. GCM은 컨텍스트 생성, 키는 토큰 키테이블에서 `key_id`로 참조.
- **원형 및 인자**:
  ```c
  CK_RV SC_EncryptInit(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_MECHANISM_PTR pMechanism,    // CKM_AES_GCM / CKM_AES_CTR (+파라미터)
      CK_OBJECT_HANDLE hKey           // 대칭 키 핸들
  );
  ```
- **반환값**: `CKR_OK`; `CKR_MECHANISM_INVALID`, `CKR_MECHANISM_PARAM_INVALID`,
  `CKR_KEY_TYPE_INCONSISTENT`, `CKR_KEY_FUNCTION_NOT_PERMITTED`, `CKR_OPERATION_ACTIVE`.

### 5.2 `SC_Encrypt`
- **기능**: 단발 암호화(`pEncryptedData==NULL`이면 길이만).
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

### 5.3 `SC_EncryptUpdate`
- **기능**: 멀티파트 암호화 청크(AES-GCM).
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

### 5.4 `SC_EncryptFinal`
- **기능**: 멀티파트 암호화 종료 + 잔여/GCM 태그 산출.
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

> 지원 범위는 5장과 동일. 복호는 GCM 태그를 마지막까지 보류해 검증한다.

### 6.1 `SC_DecryptInit`
- **기능**: 복호화 초기화(§5.1 복호 방향).
- **원형 및 인자**:
  ```c
  CK_RV SC_DecryptInit(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_MECHANISM_PTR pMechanism,    // CKM_AES_GCM / CKM_AES_CTR
      CK_OBJECT_HANDLE hKey           // 대칭 키 핸들
  );
  ```
- **반환값**: `CKR_OK`; `CKR_MECHANISM_INVALID`, `CKR_KEY_FUNCTION_NOT_PERMITTED`,
  `CKR_OPERATION_ACTIVE`.

### 6.2 `SC_Decrypt`
- **기능**: 단발 복호화. GCM 태그 검증 실패 시 거부.
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
- **반환값**: `CKR_OK`; `CKR_ENCRYPTED_DATA_INVALID`/`_LEN_RANGE`,
  `CKR_BUFFER_TOO_SMALL`, `CKR_OPERATION_NOT_INITIALIZED`.

### 6.3 `SC_DecryptUpdate`
- **기능**: 멀티파트 복호화 청크(AES-GCM, 태그 길이 보류).
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

### 6.4 `SC_DecryptFinal`
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

### 7.1 `SC_DigestInit`
- **기능**: 다이제스트 초기화.
- **원형 및 인자**:
  ```c
  CK_RV SC_DigestInit(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_MECHANISM_PTR pMechanism     // CKM_SHA256/SHA512/SHA3_*
  );
  ```
- **반환값**: `CKR_OK`; `CKR_MECHANISM_INVALID`, `CKR_OPERATION_ACTIVE`.

### 7.2 `SC_Digest`
- **기능**: 단발 다이제스트.
- **원형 및 인자**:
  ```c
  CK_RV SC_Digest(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_BYTE_PTR pData,              // 입력
      CK_ULONG ulDataLen,             // 입력 길이
      CK_BYTE_PTR pDigest,            // [out] 해시(NULL=길이만)
      CK_ULONG_PTR pulDigestLen       // [in/out] 버퍼 길이 / 실제 길이
  );
  ```
- **반환값**: `CKR_OK`; `CKR_BUFFER_TOO_SMALL`, `CKR_OPERATION_NOT_INITIALIZED`.

### 7.3 `SC_DigestUpdate`
- **기능**: 멀티파트 다이제스트 청크 누적(`<= NCMP_MP_UPDATE_MAX_DATA`).
- **원형 및 인자**:
  ```c
  CK_RV SC_DigestUpdate(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_BYTE_PTR pPart,              // 데이터 청크
      CK_ULONG ulPartLen              // 청크 길이
  );
  ```
- **반환값**: `CKR_OK`; `CKR_OPERATION_NOT_INITIALIZED`, `CKR_DATA_LEN_RANGE`.

### 7.4 `SC_DigestKey`
- **기능**: 키 값을 다이제스트에 공급. secure-key 토큰은 키 값 비노출이라 미지원.
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

### 7.5 `SC_DigestFinal`
- **기능**: 멀티파트 다이제스트 종료 + 최종 해시.
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

> 지원: `CKM_ML_DSA`(strength 1/3/5) 단발 서명. 멀티파트(Update/Final)·Recover는 미지원.

### 8.1 `SC_SignInit`
- **기능**: 서명 초기화.
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

### 8.2 `SC_Sign`
- **기능**: 단발 서명 생성(ML-DSA).
- **원형 및 인자**:
  ```c
  CK_RV SC_Sign(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_BYTE_PTR pData,              // 서명 대상
      CK_ULONG ulDataLen,             // 데이터 길이
      CK_BYTE_PTR pSignature,         // [out] 서명(NULL=길이만)
      CK_ULONG_PTR pulSignatureLen    // [in/out] 버퍼 길이 / 실제 길이
  );
  ```
- **반환값**: `CKR_OK`; `CKR_BUFFER_TOO_SMALL`, `CKR_OPERATION_NOT_INITIALIZED`,
  `CKR_DATA_LEN_RANGE`.

### 8.3 `SC_SignUpdate`
- **기능**: 멀티파트 서명 청크. ML-DSA 단발 전용이라 미지원.
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

### 8.4 `SC_SignFinal`
- **기능**: 멀티파트 서명 종료. 미지원.
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

### 8.5 `SC_SignRecoverInit`
- **기능**: 복원형 서명 초기화(RSA 전용). 미지원.
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

### 8.6 `SC_SignRecover`
- **기능**: 복원형 서명 생성(RSA 전용). 미지원.
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

> 지원: `CKM_ML_DSA` 단발 검증. Update/Final·Recover는 미지원.

### 9.1 `SC_VerifyInit`
- **기능**: 검증 초기화.
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

### 9.2 `SC_Verify`
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

### 9.3 `SC_VerifyUpdate`
- **기능**: 멀티파트 검증 청크. 미지원.
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

### 9.4 `SC_VerifyFinal`
- **기능**: 멀티파트 검증 종료. 미지원.
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

### 9.5 `SC_VerifyRecoverInit`
- **기능**: 복원형 검증 초기화(RSA 전용). 미지원.
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

### 9.6 `SC_VerifyRecover`
- **기능**: 복원형 검증(RSA 전용). 미지원.
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

> 서명을 `Init`에 미리 제공하고 데이터로 검증. ML-DSA 단발형만 지원.

### 10.1 `SC_VerifySignatureInit`
- **기능**: 서명을 미리 지정하여 검증 초기화.
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

### 10.2 `SC_VerifySignature`
- **기능**: `Init`의 서명을 데이터로 단발 검증.
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

### 10.3 `SC_VerifySignatureUpdate`
- **기능**: 멀티파트 서명 검증 청크. 미지원.
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

### 10.4 `SC_VerifySignatureFinal`
- **기능**: 멀티파트 서명 검증 종료. 미지원.
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

> 두 하위 연산이 모두 지원될 때만 동작. digest+encrypt / decrypt+digest 가능,
> sign/verify 조합은 ML-DSA 멀티파트 미지원이라 사실상 불가.

### 11.1 `SC_DigestEncryptUpdate`
- **기능**: 청크를 다이제스트하며 동시에 암호화.
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
- **반환값**: `CKR_OK`(양쪽 init 시); `CKR_OPERATION_NOT_INITIALIZED`,
  `CKR_BUFFER_TOO_SMALL`.

### 11.2 `SC_DecryptDigestUpdate`
- **기능**: 청크를 복호화하며 동시에 다이제스트.
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

### 11.3 `SC_SignEncryptUpdate`
- **기능**: 청크를 서명하며 동시에 암호화. ML-DSA 멀티파트 미지원이라 사실상 미지원.
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

### 11.4 `SC_DecryptVerifyUpdate`
- **기능**: 청크를 복호화하며 동시에 검증. ML-DSA 멀티파트 미지원이라 사실상 미지원.
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

### 12.1 `SC_GenerateKey`
- **기능**: 대칭 키 생성. NCMP는 **AES 키**(`CKM_AES_KEY_GEN`)만 지원.
- **원형 및 인자**:
  ```c
  CK_RV SC_GenerateKey(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_MECHANISM_PTR pMechanism,    // CKM_AES_KEY_GEN
      CK_ATTRIBUTE_PTR pTemplate,     // 키 속성 템플릿
      CK_ULONG ulCount,               // 속성 개수
      CK_OBJECT_HANDLE_PTR phKey      // [out] 키 핸들
  );
  ```
- **반환값**: `CKR_OK`; `CKR_MECHANISM_INVALID`, `CKR_TEMPLATE_INCONSISTENT`,
  `CKR_ATTRIBUTE_VALUE_INVALID`, `CKR_USER_NOT_LOGGED_IN`.

### 12.2 `SC_GenerateKeyPair`
- **기능**: 비대칭 키쌍 생성. **ML-DSA / ML-KEM**만 지원(strength=`CKA_PARAMETER_SET`).
  PQC 키는 `CKA_VALUE`에 blob 통째로 저장.
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
- **반환값**: `CKR_OK`; `CKR_MECHANISM_INVALID`, `CKR_TEMPLATE_INCONSISTENT`,
  `CKR_ATTRIBUTE_VALUE_INVALID`, `CKR_USER_NOT_LOGGED_IN`.

### 12.3 `SC_DeriveKey`
- **기능**: 키 유도. **SHAKE-128/256 KDF**만 지원(`NCMP_CMD_SHAKE_DERIVE`).
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
- **반환값**: `CKR_OK`; `CKR_MECHANISM_INVALID`, `CKR_KEY_TYPE_INCONSISTENT`,
  `CKR_TEMPLATE_INCONSISTENT`.

### 12.4 `SC_WrapKey`
- **기능**: 키 래핑. 훅 없음 → 미지원.
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

### 12.5 `SC_UnwrapKey`
- **기능**: 키 언래핑. 훅 없음 → 미지원.
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

### 12.6 `SC_EncapsulateKey` (PKCS#11 3.2)
- **기능**: KEM 캡슐화. **ML-KEM**만 지원(`NCMP_CMD_MLKEM_*`).
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
- **반환값**: `CKR_OK`; `CKR_MECHANISM_INVALID`, `CKR_KEY_TYPE_INCONSISTENT`,
  `CKR_BUFFER_TOO_SMALL`, `CKR_TEMPLATE_INCONSISTENT`.

### 12.7 `SC_DecapsulateKey` (PKCS#11 3.2)
- **기능**: KEM 역캡슐화. **ML-KEM**만 지원.
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
- **반환값**: `CKR_OK`; `CKR_MECHANISM_INVALID`,
  `CKR_ENCAPSULATED_DATA_INVALID`/`_KEY_INVALID`, `CKR_TEMPLATE_INCONSISTENT`.

---

## 13. 난수 (Random)

### 13.1 `SC_GenerateRandom`
- **기능**: 토큰 RNG 난수 생성(`t_rng` → `NCMP_CMD_RNG`).
- **원형 및 인자**:
  ```c
  CK_RV SC_GenerateRandom(
      STDLL_TokData_t *tokdata,       // 토큰 인스턴스 데이터
      ST_SESSION_HANDLE *sSession,    // 세션
      CK_BYTE_PTR pRandomData,        // [out] 난수 버퍼
      CK_ULONG ulRandomLen            // 요청 바이트 수
  );
  ```
- **반환값**: `CKR_OK`; `CKR_ARGUMENTS_BAD`, `CKR_DEVICE_ERROR`.

### 13.2 `SC_SeedRandom`
- **기능**: RNG 시드 공급. 시드 훅 없음 → 미지원.
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

### 14.1 `SC_IBM_ReencryptSingle`
- **기능**: 복호+재암호를 토큰 내부에서 단일 호출로 수행. 전용 훅 없음 → 미지원.
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

## 부록 A. export 심볼 목록 (73개)

`libpkcs11_ncmp.so`가 실제로 export 하는 전 심볼(직접 링크 대상). 함수별 지원 여부는
각 절 및 [`cryptoki_app_api.md` 부록 A](cryptoki_app_api.md#부록-a-export-심볼--애플리케이션-c_-대응-73개)와 동일하다.

- **인프라(3)**: `ST_Initialize`, `SC_SetFunctionList`, `SC_Finalize`
- **슬롯/토큰(7)**: `SC_GetTokenInfo`, `SC_GetMechanismList`, `SC_GetMechanismInfo`,
  `SC_InitToken`, `SC_InitPIN`, `SC_SetPIN`, `SC_WaitForSlotEvent`
- **세션/로그인(11)**: `SC_OpenSession`, `SC_CloseSession`, `SC_CloseAllSessions`,
  `SC_GetSessionInfo`, `SC_Login`, `SC_Logout`, `SC_SessionCancel`,
  `SC_CancelFunction`, `SC_GetFunctionStatus`, `SC_GetOperationState`,
  `SC_SetOperationState`
- **오브젝트(9)**: `SC_CreateObject`, `SC_CopyObject`, `SC_DestroyObject`,
  `SC_GetObjectSize`, `SC_GetAttributeValue`, `SC_SetAttributeValue`,
  `SC_FindObjectsInit`, `SC_FindObjects`, `SC_FindObjectsFinal`
- **Encrypt(4)**: `SC_EncryptInit`, `SC_Encrypt`, `SC_EncryptUpdate`, `SC_EncryptFinal`
- **Decrypt(4)**: `SC_DecryptInit`, `SC_Decrypt`, `SC_DecryptUpdate`, `SC_DecryptFinal`
- **Digest(5)**: `SC_DigestInit`, `SC_Digest`, `SC_DigestUpdate`, `SC_DigestKey`,
  `SC_DigestFinal`
- **Sign(6)**: `SC_SignInit`, `SC_Sign`, `SC_SignUpdate`, `SC_SignFinal`,
  `SC_SignRecoverInit`, `SC_SignRecover`
- **Verify(6)**: `SC_VerifyInit`, `SC_Verify`, `SC_VerifyUpdate`, `SC_VerifyFinal`,
  `SC_VerifyRecoverInit`, `SC_VerifyRecover`
- **VerifySignature 3.2(4)**: `SC_VerifySignatureInit`, `SC_VerifySignature`,
  `SC_VerifySignatureUpdate`, `SC_VerifySignatureFinal`
- **이중기능(4)**: `SC_DigestEncryptUpdate`, `SC_DecryptDigestUpdate`,
  `SC_SignEncryptUpdate`, `SC_DecryptVerifyUpdate`
- **키 관리(7)**: `SC_GenerateKey`, `SC_GenerateKeyPair`, `SC_DeriveKey`,
  `SC_WrapKey`, `SC_UnwrapKey`, `SC_EncapsulateKey`, `SC_DecapsulateKey`
- **난수(2)**: `SC_GenerateRandom`, `SC_SeedRandom`
- **IBM 확장(1)**: `SC_IBM_ReencryptSingle`

> `SC_HandleEvent`는 `new_host.c`에 정의되어 있으나 `opencryptoki_tok.map`에서 export
> 되지 않으므로(내부 `function_list.ST_HandleEvent` 연결 전용) 직접 링크 대상이 아니다.

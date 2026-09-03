# Token NCMP — Command Interface (CI) 메시지 규격

- **작성일**: 2026-09-02
- **대상 독자**: FX3 펌웨어/엔진 설계자, `ncmpd`·STDLL 개발자
- **근거 소스**: `ncmp/include/ncmp/ncmp_cmd.h`(opcode·레이아웃),
  `ncmp/include/ncmp/ncmp_wire.h`(프레임 구조), `ncmp/mock/mcu_scheduler.c`(참조 구현)
- **관련 문서**: [`architecture.md`](architecture.md) ·
  [`session-state-management.md`](session-state-management.md) · [`INDEX.md`](INDEX.md)

> 이 문서는 호스트(`ncmpd`/STDLL)가 **NCMP 토큰으로 보내는 모든 명령**에 대해
> 요청(Request)·응답(Response) 메시지 구조를 정의한다. 인터페이스 전체를
> **Command Interface = `CI`** 로 명명하며, 모든 타입에 `CI_` 접두어를 붙인다.
> opcode 값은 `ncmp_cmd.h`의 `NCMP_CMD_*`와 동일하다(문서에서는 `CI_CMD_*`로 부른다).

---

## 1. 공통 프레임 (envelope)

모든 CI 메시지는 동일한 봉투(envelope)를 공유한다. 4바이트 정렬, **리틀엔디언**.

```c
/* 고정 헤더 (20바이트, frame_len 접두어 제외). */
typedef struct CI_Header {
    uint32_t session_id;   /* 이 명령이 속한 PKCS#11 세션 핸들 (전송 전용 명령은 0) */
    uint32_t sequence_id;  /* 세션별 단조 증가 요청 id — 응답을 요청과 매칭하는 키 */
    uint32_t command_id;   /* [15:0] opcode(CI_CMD_*), [31:16] flags(CI_FLAG_*) */
    uint32_t ack;          /* CKR_* 결과 코드. 요청에서는 CKR_OK(0), 응답에서 실제 상태 */
    uint32_t payload_len;  /* 헤더 이후 바이트 수 = sizeof(param_len) + Σ param_len[i] */
} CI_Header;

/* 완전한 온-와이어 프레임. */
typedef struct CI_Message {
    uint32_t  frame_len;      /* 이 필드 이후 전체 길이 = 20(헤더) + payload_len */
    CI_Header header;
    uint32_t  param_len[8];   /* param0..param7 각각의 바이트 길이 (미사용 슬롯은 0) */
    uint8_t   payload[];      /* param0..param7 을 순서대로 이어붙인 바이트열 */
} CI_Message;
```

**불변식(invariant)**
- `frame_len == 20 + payload_len`
- `payload_len == 32 + Σ param_len[i]` (0..7)
- 단일 파라미터 ≤ 32 KB, 결합 payload(길이배열+파라미터) ≤ 40 KB
- FX3 bulk-IN은 **단발 수신**: 응답 프레임 1개를 한 전송으로 읽는다.

```c
/* command_id 상위 16비트 플래그. */
enum {
    CI_FLAG_NONE      = 0x00000000u,
    CI_FLAG_FAIL_INJECT = 0x80000000u  /* 테스트 훅: 토큰이 강제로 실패 ack 반환 */
};
```

### 1.1 명령별 구조체 표기 규약

아래 각 명령의 `CI_*Req` / `CI_*Rsp` 구조체는 **payload 안의 파라미터 슬롯 매핑을
논리적으로** 나타낸다(패킹된 C 구조체가 아니다).

- 각 필드는 하나의 파라미터 슬롯(`param0`, `param1`, …)에 대응한다.
- **스칼라**(`uint32_t` 등)는 해당 슬롯에 리틀엔디언으로 담긴 4바이트다.
- **가변 블롭**은 `name[]`로 표기하며, 실제 길이는 프레임의 `param_len[]`가 운반한다.
- 파라미터가 없으면 구조체는 비어 있고(`{ /* 없음 */ }`) 결과는 `header.ack`로만 온다.
- 모든 응답은 `header.ack`에 `CKR_*` 상태를 싣는다(→ 6절).

---

## 2. 명령 목록 (CI_CMD_*)

각 `CI_CMD_*`는 `ncmp_cmd.h`의 **`enum ncmp_opcode` 값을 그대로 별칭(alias)** 하도록
정의된다. 두 열거형은 항상 lockstep으로 유지되며(같은 값·같은 순번), CI 문서와 와이어
헤더가 서로 어긋날 수 없다.

```c
typedef enum CI_Cmd {
    /* 기본 / 대칭 / 해시 */
    CI_CMD_NOP             = NCMP_CMD_NOP,             /* 0x0000 */
    CI_CMD_RNG             = NCMP_CMD_RNG,             /* 0x0001 */
    CI_CMD_DIGEST          = NCMP_CMD_DIGEST,          /* 0x0002 */
    CI_CMD_GETMECHLIST     = NCMP_CMD_GETMECHLIST,     /* 0x0003 (예약) */
    CI_CMD_DIGEST_INIT     = NCMP_CMD_DIGEST_INIT,     /* 0x0004 */
    CI_CMD_DIGEST_UPDATE   = NCMP_CMD_DIGEST_UPDATE,   /* 0x0005 */
    CI_CMD_DIGEST_FINAL    = NCMP_CMD_DIGEST_FINAL,    /* 0x0006 */
    CI_CMD_SHAKE_DERIVE    = NCMP_CMD_SHAKE_DERIVE,    /* 0x0009 */
    /* 대칭 (AEAD / 스트림) */
    CI_CMD_AES_GCM         = NCMP_CMD_AES_GCM,         /* 0x0012 */
    CI_CMD_AES_CTR         = NCMP_CMD_AES_CTR,         /* 0x0013 */
    /* 토큰 관리 / 로그인 / 조회 */
    CI_CMD_LOGIN           = NCMP_CMD_LOGIN,           /* 0x0030 */
    CI_CMD_LOGOUT          = NCMP_CMD_LOGOUT,          /* 0x0031 */
    CI_CMD_INIT_PIN        = NCMP_CMD_INIT_PIN,        /* 0x0032 */
    CI_CMD_SET_PIN         = NCMP_CMD_SET_PIN,         /* 0x0033 */
    CI_CMD_INIT_TOKEN      = NCMP_CMD_INIT_TOKEN,      /* 0x0034 */
    CI_CMD_GET_UTC_TIME    = NCMP_CMD_GET_UTC_TIME,    /* 0x0035 */
    CI_CMD_GET_TOKEN_PARAMS = NCMP_CMD_GET_TOKEN_PARAMS, /* 0x0036 */
    CI_CMD_SET_UTC_TIME    = NCMP_CMD_SET_UTC_TIME,    /* 0x0037 */
    /* 포스트양자 (PKCS#11 3.2) */
    CI_CMD_MLDSA_KEYGEN    = NCMP_CMD_MLDSA_KEYGEN,    /* 0x0050 */
    CI_CMD_MLDSA_SIGN      = NCMP_CMD_MLDSA_SIGN,      /* 0x0051 */
    CI_CMD_MLDSA_VERIFY    = NCMP_CMD_MLDSA_VERIFY,    /* 0x0052 */
    CI_CMD_MLKEM_KEYGEN    = NCMP_CMD_MLKEM_KEYGEN,    /* 0x0053 */
    CI_CMD_MLKEM_ENCAPS    = NCMP_CMD_MLKEM_ENCAPS,    /* 0x0054 */
    CI_CMD_MLKEM_DECAPS    = NCMP_CMD_MLKEM_DECAPS,    /* 0x0055 */
    /* 벤더 정의 (datapath / 디바이스 상태) */
    CI_CMD_VD_MEM_WRITE    = NCMP_CMD_VD_MEM_WRITE,    /* 0x0101 */
    CI_CMD_VD_MEM_READ     = NCMP_CMD_VD_MEM_READ,     /* 0x0102 */
    CI_CMD_VD_PING         = NCMP_CMD_VD_PING,         /* 0x0103 */
    CI_CMD_VD_SELFTEST     = NCMP_CMD_VD_SELFTEST,     /* 0x0104 */
    CI_CMD_VD_FW_INFO      = NCMP_CMD_VD_FW_INFO,      /* 0x0105 */
    CI_CMD_VD_MEM_FILL     = NCMP_CMD_VD_MEM_FILL,     /* 0x0106 */
    CI_CMD_VD_MEM_CRC      = NCMP_CMD_VD_MEM_CRC,      /* 0x0107 */
    CI_CMD_VD_TOKEN_INFO   = NCMP_CMD_VD_TOKEN_INFO    /* 0x0108 */
} CI_Cmd;
```

> **와이어 표면 = advertised mechanism 표면.** opcode/CI 목록은 이제 토큰이 실제로
> 제공하는 mechanism(AES-GCM/CTR · SHA-2/3 · SHAKE · ML-KEM · ML-DSA)과 **정확히
> 일치**한다. RSA/EC/DH/ECDH/HMAC/AES-CBC·ECB·OFB·CFB 등 비광고 mechanism은 opcode·CI
> 구조체·어댑터·mock·테스트까지 **완전히 제거**되었다(레거시 포워딩 경로 없음).
> 에코/loopback은 별도 opcode 없이 `CI_CMD_NOP`로 처리한다.

---

## 3. 기본 · 대칭 · 해시 명령

### 3.1 CI_CMD_NOP (0x0000) — 무동작 / 에코
```c
typedef struct CI_NopReq { uint8_t data[]; /* param0: 임의 바이트(그대로 반향) */ } CI_NopReq;
typedef struct CI_NopRsp { uint8_t data[]; /* param0: 요청 payload 그대로 */ } CI_NopRsp;
```

### 3.2 CI_CMD_RNG (0x0001) — 난수 생성
```c
typedef struct CI_RngReq {
    uint32_t count;   /* param0: 요청 난수 바이트 수 (≤ 32 KB) */
} CI_RngReq;
typedef struct CI_RngRsp {
    uint8_t  bytes[]; /* param0: count 바이트의 난수 */
} CI_RngRsp;
```

### 3.3 CI_CMD_DIGEST (0x0002) — 단발 해시
```c
typedef struct CI_DigestReq {
    uint32_t mech;    /* param0[0..4): 해시 mechanism (CKM_SHA256/512, CKM_SHA3_* 등) */
    uint8_t  data[];  /* param0[4..):  입력 메시지 (mech 뒤에 이어붙임) */
} CI_DigestReq;
typedef struct CI_DigestRsp {
    uint8_t  digest[]; /* param0: 해시 출력 (mech에 따라 28/32/48/64 바이트) */
} CI_DigestRsp;
```
> 주의: `mech`와 `data`는 **하나의 파라미터(param0)** 안에 [mech(4B)|data] 형태로 결합된다.

### 3.4 CI_CMD_GETMECHLIST (0x0003) — 지원 mechanism 조회 *(예약)*
```c
typedef struct CI_GetMechListReq { /* 없음 */ } CI_GetMechListReq;
typedef struct CI_GetMechListRsp {
    uint32_t mechs[]; /* param0: 지원 mechanism(CKM_*) 배열 (LE u32 나열) */
} CI_GetMechListRsp;
```
> 현재 미구현(예약). 하드웨어에서 mechanism 목록을 조회할 때 사용 예정.

### 3.5 CI_CMD_DIGEST_INIT (0x0004) — 멀티파트 해시 시작
```c
typedef struct CI_DigestInitReq {
    uint32_t mech;    /* param0: 해시 mechanism */
} CI_DigestInitReq;
typedef struct CI_DigestInitRsp {
    uint32_t ctx_id;  /* param0: 토큰이 할당한 해시 컨텍스트 id (후속 update/final에 사용) */
} CI_DigestInitRsp;
```

### 3.6 CI_CMD_DIGEST_UPDATE (0x0005) — 멀티파트 해시 갱신
```c
typedef struct CI_DigestUpdateReq {
    uint32_t ctx_id;  /* param0: DIGEST_INIT가 반환한 컨텍스트 id */
    uint8_t  data[];  /* param1: 이번에 흡수할 입력 조각 */
} CI_DigestUpdateReq;
typedef struct CI_DigestUpdateRsp { /* 없음 (ack만) */ } CI_DigestUpdateRsp;
```

### 3.7 CI_CMD_DIGEST_FINAL (0x0006) — 멀티파트 해시 종료
```c
typedef struct CI_DigestFinalReq {
    uint32_t ctx_id;  /* param0: 종료할 컨텍스트 id (반환 후 해제됨) */
} CI_DigestFinalReq;
typedef struct CI_DigestFinalRsp {
    uint8_t  digest[]; /* param0: 최종 해시 출력 */
} CI_DigestFinalRsp;
```

### 3.8 CI_CMD_SHAKE_DERIVE (0x0009) — SHAKE XOF 키 유도
```c
typedef struct CI_ShakeDeriveReq {
    uint32_t mech;    /* param0: CKM_SHAKE_128/256_KEY_DERIVATION */
    uint32_t out_len; /* param1: 유도할 출력 바이트 수 */
    uint8_t  base[];  /* param2: 기반 키 재료(base key의 CKA_VALUE) */
} CI_ShakeDeriveReq;
typedef struct CI_ShakeDeriveRsp {
    uint8_t  out[];   /* param0: out_len 바이트의 유도 결과 */
} CI_ShakeDeriveRsp;
```

---

## 4. 대칭키 암복호 명령

모든 AES 명령의 `flags`는 방향 비트를 담는다.
```c
enum { CI_AES_FLAG_ENCRYPT = 0x1 };  /* flags bit0: 1=암호화, 0=복호화 */
```

### 4.1 CI_CMD_AES_GCM (0x0012) — AEAD
```c
typedef struct CI_AesGcmReq {
    uint32_t flags;    /* param0: bit0=암/복호 */
    uint8_t  key[];    /* param1: AES 키 */
    uint8_t  iv[];     /* param2: nonce/IV (1..16 B) */
    uint8_t  aad[];    /* param3: 추가 인증 데이터 (비어 있을 수 있음) */
    uint32_t tag_len;  /* param4: 인증 태그 길이(바이트) */
    uint8_t  data[];   /* param5: 암호화=평문 / 복호화=ciphertext‖tag */
} CI_AesGcmReq;
typedef struct CI_AesGcmRsp {
    uint8_t  out[];    /* param0: 암호화=ciphertext‖tag / 복호화=평문 */
} CI_AesGcmRsp;
```
> 복호화에서 태그 불일치 시 `ack = CKR_ENCRYPTED_DATA_INVALID`, 출력 없음.

### 4.2 CI_CMD_AES_CTR (0x0013) — 스트림
AES-CTR은 유일하게 광고되는 AES 스트림 모드다(`param2`가 카운터 블록).
```c
typedef struct CI_AesCtrReq {
    uint32_t flags;   /* param0: bit0=암/복호 (스트림은 방향 대칭) */
    uint8_t  key[];   /* param1: AES 키 (16/24/32 B) */
    uint8_t  iv[];    /* param2: 카운터 블록 (16 B) */
    uint8_t  data[];  /* param3: 입력 (임의 길이) */
} CI_AesCtrReq;
typedef struct CI_AesCtrRsp { uint8_t out[]; /* param0: 출력 (입력과 동일 길이) */ } CI_AesCtrRsp;
```

---

## 5. 토큰 관리 / 로그인 / 조회 명령

```c
enum { CI_CKU_SO = 0, CI_CKU_USER = 1, CI_CKU_CONTEXT_SPECIFIC = 2 }; /* user_type */

/* param1의 로그인 수정 플래그 (NCMP_LOGIN_FLAG_* 와 동일 값). */
enum {
    CI_LOGIN_FLAG_NONE           = 0x00000000u,
    CI_LOGIN_FLAG_PROTECTED_AUTH = 0x00000001u, /* PIN을 토큰 패드에서 입력 */
    CI_LOGIN_FLAG_CONTEXT        = 0x00000002u  /* CKU_CONTEXT_SPECIFIC 재인증 */
};
```

### 5.1 CI_CMD_LOGIN (0x0030)
로그인은 SO/User 역할(`user_type`) **외에** 부가 조건을 `flags`로 함께 전달한다.
```c
typedef struct CI_LoginReq {
    uint32_t user_type;  /* param0: CI_CKU_SO(0) / CI_CKU_USER(1) / CI_CKU_CONTEXT_SPECIFIC(2) */
    uint32_t flags;      /* param1: CI_LOGIN_FLAG_* (protected-auth / context 재인증) */
    uint8_t  pin[];      /* param2: PIN 바이트 (protected-auth면 비어 있음) */
} CI_LoginReq;
typedef struct CI_LoginRsp { /* 없음. ack=OK / CKR_PIN_INCORRECT / CKR_USER_* */ } CI_LoginRsp;
```
- **protected-auth**(`CI_LOGIN_FLAG_PROTECTED_AUTH`): PIN을 토큰 자체 패드에서
  입력하므로 와이어 PIN은 비어 있고, 토큰이 직접 인증을 승인한다.
- **context-specific**(`user_type=2` 또는 `CI_LOGIN_FLAG_CONTEXT`): **현재
  로그인된 사용자**의 PIN을 재검증(PKCS#11 `CKA_ALWAYS_AUTHENTICATE`)하며 로그인
  상태는 바꾸지 않는다. 아무도 로그인하지 않았으면 `CKR_USER_NOT_LOGGED_IN`.
- 잘못된 `user_type`은 `CKR_USER_TYPE_INVALID`, 중복 로그인은
  `CKR_USER_ALREADY_LOGGED_IN`.

### 5.2 CI_CMD_LOGOUT (0x0031)
```c
typedef struct CI_LogoutReq { /* 없음 */ } CI_LogoutReq;
typedef struct CI_LogoutRsp { /* 없음. ack=CKR_OK */ } CI_LogoutRsp;
```

### 5.3 CI_CMD_INIT_PIN (0x0032) — SO가 사용자 PIN 설정
```c
typedef struct CI_InitPinReq {
    uint8_t  new_pin[];  /* param0: 설정할 사용자 PIN */
} CI_InitPinReq;
typedef struct CI_InitPinRsp { /* 없음. ack=OK / CKR_USER_NOT_LOGGED_IN / CKR_PIN_LEN_RANGE */ } CI_InitPinRsp;
```

### 5.4 CI_CMD_SET_PIN (0x0033) — PIN 변경
```c
typedef struct CI_SetPinReq {
    uint8_t  old_pin[];  /* param0: 현재 PIN */
    uint8_t  new_pin[];  /* param1: 새 PIN */
} CI_SetPinReq;
typedef struct CI_SetPinRsp { /* 없음. ack=OK / CKR_PIN_INCORRECT / CKR_PIN_LEN_RANGE */ } CI_SetPinRsp;
```

### 5.5 CI_CMD_INIT_TOKEN (0x0034) — 토큰 초기화
```c
typedef struct CI_InitTokenReq {
    uint8_t  so_pin[];   /* param0: SO PIN(검증) */
    uint8_t  label[32];  /* param1: 새 토큰 라벨 (32바이트, 공백 패딩) */
} CI_InitTokenReq;
typedef struct CI_InitTokenRsp { /* 없음. ack=OK / CKR_PIN_INCORRECT */ } CI_InitTokenRsp;
```
> **호스트(STDLL) 후속 처리.** `INIT_TOKEN` 성공 후 STDLL은 `VD_TOKEN_INFO`로
> **라벨을 다시 읽어와 요청 라벨과 정밀 검증**한다. 일치하면 토큰 정체성을
> `nv_token_data`에 캐시하고 `save_token_data()`로 영속화한 뒤, 사용한 **임시 SO
> PIN·라벨 버퍼를 즉시 0으로 소거(zeroization)** 한다. 라벨이 불일치하면
> `CKR_FUNCTION_FAILED`.

### 5.6 CI_CMD_GET_UTC_TIME (0x0035) — UTC 시각 조회
```c
typedef struct CI_GetUtcTimeReq { /* 없음 */ } CI_GetUtcTimeReq;
typedef struct CI_GetUtcTimeRsp {
    uint8_t  utc[16];    /* param0: CK_TOKEN_INFO.utcTime ("YYYYMMDDhhmmssxx") */
} CI_GetUtcTimeRsp;
```
> STDLL은 이 값을 `C_GetTokenInfo`의 `utcTime` 필드에 반영한다.

### 5.7 CI_CMD_GET_TOKEN_PARAMS (0x0036) — 라벨·시리얼·PIN 길이 조회
```c
typedef struct CI_GetTokenParamsReq { /* 없음 */ } CI_GetTokenParamsReq;
typedef struct CI_GetTokenParamsRsp {
    uint8_t  label[32];   /* param0: 토큰 라벨 (NUL/공백 패딩) */
    uint8_t  serial[16];  /* param1: 시리얼 번호 (NUL/공백 패딩) */
    uint32_t min_pin_len; /* param2: ulMinPinLen (LE u32) */
    uint32_t max_pin_len; /* param3: ulMaxPinLen (LE u32) */
} CI_GetTokenParamsRsp;
```
> STDLL은 `ulMinPinLen`/`ulMaxPinLen`을 `C_GetTokenInfo`에 반영한다.

### 5.8 CI_CMD_SET_UTC_TIME (0x0037) — UTC 시각 설정
```c
typedef struct CI_SetUtcTimeReq {
    uint8_t  utc[16];    /* param0: 설정할 CK_TOKEN_INFO.utcTime ("YYYYMMDDhhmmssxx") */
} CI_SetUtcTimeReq;
typedef struct CI_SetUtcTimeRsp { /* 없음. ack=OK / CKR_USER_NOT_LOGGED_IN / CKR_ARGUMENTS_BAD */ } CI_SetUtcTimeRsp;
```
> 토큰 클럭을 설정한다. **SO 로그인 상태에서만** 허용되며(그 외 `CKR_USER_NOT_LOGGED_IN`),
> `utc`는 정확히 16바이트여야 한다(`CKR_ARGUMENTS_BAD`). 이후 `CI_CMD_GET_UTC_TIME`은
> 설정한 값을 그대로 되돌려준다. PKCS#11에는 시각 설정용 표준 C_ 함수가 없어
> 이 CI는 `ncmp_admin` 어댑터를 통한 관리 전용 경로다.

---

## 7. 포스트양자 명령 (PKCS#11 3.2)

키는 불투명 블롭으로 전달되며, **개인 블롭은 공개 블롭을 접두어로 포함**한다.
`param_set`은 보안강도 선택자(CKP_ML_*), 각종 `*_len`은 블롭 크기(호스트가
`struct pqc_oid`에서 계산해 전달)이다.

```c
enum {  /* param_set (keyform) 값 = 보안강도 */
    CI_ML_DSA_44 = 1, CI_ML_DSA_65 = 2, CI_ML_DSA_87 = 3,   /* 강도 2 / 3 / 5 */
    CI_ML_KEM_512 = 1, CI_ML_KEM_768 = 2, CI_ML_KEM_1024 = 3 /* 강도 1 / 3 / 5 */
};
```

### 7.1 CI_CMD_MLDSA_KEYGEN (0x0050)
```c
typedef struct CI_MlDsaKeygenReq {
    uint32_t param_set;  /* param0: CKP_ML_DSA_* (강도) */
    uint32_t pub_len;    /* param1: 생성할 공개 블롭 길이 */
    uint32_t priv_len;   /* param2: 생성할 개인 블롭 길이 (> pub_len) */
} CI_MlDsaKeygenReq;
typedef struct CI_MlDsaKeygenRsp {
    uint8_t  pub[];      /* param0: 공개 키 블롭 (pub_len) */
    uint8_t  priv[];     /* param1: 개인 키 블롭 (priv_len, 앞 pub_len은 pub과 동일) */
} CI_MlDsaKeygenRsp;
```

### 7.2 CI_CMD_MLDSA_SIGN (0x0051)
```c
typedef struct CI_MlDsaSignReq {
    uint32_t param_set;  /* param0: 강도 */
    uint32_t pub_len;    /* param1: 개인 블롭 내 공개 접두어 길이(폴딩 기준) */
    uint32_t sig_len;    /* param2: 생성할 서명 길이 */
    uint8_t  priv[];     /* param3: 개인 키 블롭 */
    uint8_t  data[];     /* param4: 서명 대상 메시지 */
} CI_MlDsaSignReq;
typedef struct CI_MlDsaSignRsp {
    uint8_t  sig[];      /* param0: ML-DSA 서명 (sig_len) */
} CI_MlDsaSignRsp;
```

### 7.3 CI_CMD_MLDSA_VERIFY (0x0052)
```c
typedef struct CI_MlDsaVerifyReq {
    uint32_t param_set;  /* param0: 강도 */
    uint8_t  pub[];      /* param1: 공개 키 블롭 */
    uint8_t  data[];     /* param2: 원본 메시지 */
    uint8_t  sig[];      /* param3: 대조할 서명 */
} CI_MlDsaVerifyReq;
typedef struct CI_MlDsaVerifyRsp { /* 없음. ack=OK / CKR_SIGNATURE_INVALID */ } CI_MlDsaVerifyRsp;
```

### 7.4 CI_CMD_MLKEM_KEYGEN (0x0053)
```c
typedef struct CI_MlKemKeygenReq {
    uint32_t param_set;  /* param0: CKP_ML_KEM_* (강도) */
    uint32_t pub_len;    /* param1: 공개 블롭 길이(pk_len) */
    uint32_t priv_len;   /* param2: 개인 블롭 길이(sk_len, > pub_len) */
} CI_MlKemKeygenReq;
typedef struct CI_MlKemKeygenRsp {
    uint8_t  pub[];      /* param0: 공개 키 블롭 */
    uint8_t  priv[];     /* param1: 개인 키 블롭 (앞 pub_len은 pub과 동일) */
} CI_MlKemKeygenRsp;
```

### 7.5 CI_CMD_MLKEM_ENCAPS (0x0054) — 캡슐화
```c
typedef struct CI_MlKemEncapsReq {
    uint32_t param_set;  /* param0: 강도 */
    uint32_t ct_len;     /* param1: 생성할 암호문 길이 */
    uint32_t ss_len;     /* param2: 공유 비밀 길이 (ML-KEM은 32) */
    uint8_t  pub[];      /* param3: 상대 공개 키 블롭 */
} CI_MlKemEncapsReq;
typedef struct CI_MlKemEncapsRsp {
    uint8_t  ct[];       /* param0: 암호문(캡슐) (ct_len) */
    uint8_t  ss[];       /* param1: 공유 비밀 (ss_len) */
} CI_MlKemEncapsRsp;
```

### 7.6 CI_CMD_MLKEM_DECAPS (0x0055) — 역캡슐화
```c
typedef struct CI_MlKemDecapsReq {
    uint32_t param_set;  /* param0: 강도 */
    uint32_t pub_len;    /* param1: 개인 블롭 내 공개 접두어 길이 */
    uint32_t ss_len;     /* param2: 공유 비밀 길이 */
    uint8_t  priv[];     /* param3: 자신의 개인 키 블롭 */
    uint8_t  ct[];       /* param4: 캡슐화된 암호문 */
} CI_MlKemDecapsReq;
typedef struct CI_MlKemDecapsRsp {
    uint8_t  ss[];       /* param0: 복원된 공유 비밀 (encaps 결과와 동일) */
} CI_MlKemDecapsRsp;
```

---

## 8. 벤더 정의 명령 (datapath / 디바이스 상태)

벤더 스크래치 RAM 크기는 `NCMP_VD_MEM_SIZE`(4 KB)이다.

> **에코/loopback**은 전용 opcode 없이 `CI_CMD_NOP`(0x0000)로 처리한다(요청 payload를
> 그대로 반향). 과거의 `CI_CMD_VD_LOOPBACK`(0x0100)은 제거되었다.

### 8.1 CI_CMD_VD_MEM_WRITE (0x0101)
```c
typedef struct CI_VdMemWriteReq {
    uint32_t addr;    /* param0: 스크래치 RAM 오프셋 */
    uint8_t  bytes[]; /* param1: 기록할 데이터 (addr+len ≤ 4 KB) */
} CI_VdMemWriteReq;
typedef struct CI_VdMemWriteRsp { /* 없음. ack=OK / CKR_DEVICE_MEMORY */ } CI_VdMemWriteRsp;
```

### 8.2 CI_CMD_VD_MEM_READ (0x0102)
```c
typedef struct CI_VdMemReadReq {
    uint32_t addr;    /* param0: 읽기 시작 오프셋 */
    uint32_t len;     /* param1: 읽을 바이트 수 */
} CI_VdMemReadReq;
typedef struct CI_VdMemReadRsp { uint8_t bytes[]; /* param0: 읽은 데이터 (len) */ } CI_VdMemReadRsp;
```

### 8.3 CI_CMD_VD_PING (0x0103)
```c
typedef struct CI_VdPingReq { /* 없음 */ } CI_VdPingReq;
typedef struct CI_VdPingRsp { uint32_t epoch; /* param0: 토큰 epoch 카운터 */ } CI_VdPingRsp;
```

### 8.4 CI_CMD_VD_SELFTEST (0x0104)
```c
typedef struct CI_VdSelftestReq { /* 없음 */ } CI_VdSelftestReq;
typedef struct CI_VdSelftestRsp {
    uint32_t status;  /* param0: 0 = 모든 서브시스템 정상 (epoch 증가) */
} CI_VdSelftestRsp;
```

### 8.5 CI_CMD_VD_FW_INFO (0x0105)
```c
typedef struct CI_VdFwInfoReq { /* 없음 */ } CI_VdFwInfoReq;
typedef struct CI_VdFwInfoRsp {  /* param0 = 아래 4개 LE u32 (16바이트) */
    uint32_t major;   /* 주 버전 */
    uint32_t minor;   /* 부 버전 */
    uint32_t patch;   /* 패치 */
    uint32_t build;   /* 빌드 태그 (예: 0x0FC3) */
} CI_VdFwInfoRsp;
```

### 8.6 CI_CMD_VD_MEM_FILL (0x0106)
```c
typedef struct CI_VdMemFillReq {
    uint32_t addr;    /* param0: 시작 오프셋 */
    uint32_t len;     /* param1: 채울 길이 */
    uint8_t  value;   /* param2: 채울 바이트 값 (1바이트) */
} CI_VdMemFillReq;
typedef struct CI_VdMemFillRsp { /* 없음. ack=OK / CKR_DEVICE_MEMORY */ } CI_VdMemFillRsp;
```

### 8.7 CI_CMD_VD_MEM_CRC (0x0107)
```c
typedef struct CI_VdMemCrcReq {
    uint32_t addr;    /* param0: 시작 오프셋 */
    uint32_t len;     /* param1: 길이 */
} CI_VdMemCrcReq;
typedef struct CI_VdMemCrcRsp { uint32_t crc32; /* param0: CRC-32 (0xEDB88320 다항식) */ } CI_VdMemCrcRsp;
```

### 8.8 CI_CMD_VD_TOKEN_INFO (0x0108) — 토큰 정체성 조회
```c
/* param0 = 고정 104바이트 정체성 블롭 (문자 필드는 NUL 패딩). */
typedef struct CI_TokenIdentity {
    char     label[32];        /* 오프셋 0  : 토큰 라벨 */
    char     serial[16];       /* 오프셋 32 : 시리얼 번호 */
    char     manufacturer[32]; /* 오프셋 48 : 제조사 */
    char     model[16];        /* 오프셋 80 : 모델 */
    uint8_t  hw_major;         /* 오프셋 96 : 하드웨어 주 버전 */
    uint8_t  hw_minor;         /* 오프셋 97 : 하드웨어 부 버전 */
    uint8_t  fw_major;         /* 오프셋 98 : 펌웨어 주 버전 */
    uint8_t  fw_minor;         /* 오프셋 99 : 펌웨어 부 버전 */
    uint32_t flags;            /* 오프셋 100: 벤더 상태 플래그 (LE u32) */
} CI_TokenIdentity;            /* 총 104바이트 */

typedef struct CI_VdTokenInfoReq { /* 없음 */ } CI_VdTokenInfoReq;
typedef struct CI_VdTokenInfoRsp { CI_TokenIdentity identity; /* param0 */ } CI_VdTokenInfoRsp;
```

---

## 9. 응답 상태 코드 (header.ack)

응답의 `header.ack`에는 PKCS#11 `CKR_*` 값이 그대로 실린다. 자주 쓰이는 코드:

| ack (CKR_*) | 값 | 의미 |
|-------------|-----|------|
| CKR_OK | 0x00000000 | 성공 |
| CKR_FUNCTION_FAILED | 0x00000006 | 일반 실패 / 파라미터 파싱 오류 |
| CKR_ARGUMENTS_BAD | 0x00000007 | 인자 부적합 |
| CKR_DEVICE_MEMORY | 0x00000031 | 스크래치/컨테이너 메모리 부족 |
| CKR_ENCRYPTED_DATA_INVALID | 0x00000040 | AEAD 태그 검증 실패 등 |
| CKR_MECHANISM_INVALID | 0x00000070 | 지원하지 않는/부적합 mechanism·파라미터 |
| CKR_PIN_INCORRECT | 0x000000A0 | PIN 불일치 |
| CKR_PIN_LEN_RANGE | 0x000000A2 | PIN 길이 범위 오류 |
| CKR_SIGNATURE_INVALID | 0x000000C0 | 서명/MAC 검증 실패 |
| CKR_USER_ALREADY_LOGGED_IN | 0x00000100 | 이미 로그인됨 |
| CKR_USER_NOT_LOGGED_IN | 0x00000101 | 로그인 필요 |
| CKR_USER_TYPE_INVALID | 0x00000103 | 사용자 유형 부적합 |

> 전송 계층 오류(USB/타임아웃 등)는 토큰의 ack가 아니라 호스트에서 `NCMP_ERR_*`로
> 처리되어 STDLL 경계에서 `CKR_*`로 매핑된다(→ `ncmp_errno.h`, `ncmp_ckr.h`).

---

## 10. 호스트 어댑터 대응 (참고)

| CI 명령 그룹 | 호스트 어댑터 | 파일 |
|--------------|---------------|------|
| RNG·DIGEST·AES(GCM·CTR)·SHAKE·PQC(ML-DSA·ML-KEM) | `ncmp_crypto_*` | `ncmp/stdll/ncmp_crypto.c` |
| LOGIN·PIN·TOKEN_INFO·GET/SET_UTC_TIME·GET_TOKEN_PARAMS | `ncmp_admin_*` | `ncmp/stdll/ncmp_admin.c` |
| 전송 프리미티브(단일/다중 param) | `ncmp_client_command[_mp]` | `ncmp/stdll/ncmp_client.c` |
| 프레임 인코딩/디코딩 | `ncmp_wire_encode/decode`, `ncmp_msg_*` | `ncmp/common/ncmp_wire.c` |
| 참조 구현(디바이스 측) | opcode 실행 | `ncmp/mock/mcu_scheduler.c` |

> mock 토큰은 결정론적 스텁으로 위 레이아웃을 그대로 구현한다. 실제 FX3 펌웨어는
> 동일한 CI 프레임/파라미터 규약을 따르되 진짜 암호 연산을 수행한다.

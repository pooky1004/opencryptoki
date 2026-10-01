# Token NCMP — CI(Command Interface) 명령어 규격

- 작성일 : 2026-09-02
- 대상 독자 : FX3 펌웨어/엔진 설계자, `ncmpd`·STDLL 개발자
- 근거 소스 : `ncmp/include/ncmp/ncmp_cmd.h`(opcode·레이아웃), `ncmp/include/ncmp/ncmp_wire.h`(프레임 구조), `ncmp/mock/mcu_scheduler.c`(참조 구현)
- 관련 문서 : [`architecture.md`](architecture.md) · [`session-state-management.md`](session-state-management.md) · [`middleware_api.md`](middleware_api.md) · [`INDEX.md`](INDEX.md)

---

## 1. 개요

### 1.1. 요약

CI는 호스트(`ncmpd`/STDLL)가 NCMP 토큰으로 보내는 모든 명령에 대한 논리적 인터페이스 규약으로, 토큰으로부터 보안 서비스를 제공받기 위하여 명령을 보내고 명령에 대한 응답을 받는 구조로 구성되어 있다. 인터페이스 전체를 **Command Interface = `CI`** 로 명명하며, 모든 타입에 `CI_` 접두어를 붙인다.

호스트와 토큰은 메시지(프레임) 송수신으로 명령 및 데이터를 전달하므로 포인터 등의 주소를 통한 파라미터 전송이 불가능하다. 따라서 모든 인자를 최대 8개의 파라미터 슬롯(`param0`~`param7`)에 담아 전달하는 메시지 전송 방식에 적합하도록 CI를 설계하였다.

opcode 값은 `ncmp_cmd.h`의 `NCMP_CMD_*`와 동일하며, 본 문서에서는 `CI_CMD_*`로 부른다.

### 1.2. 용어 및 약어

- 용어

| 용어 | 내용 |
|------|------|
| 호스트 | CI 명령을 생성·전송하는 측. 데몬(`ncmpd`)과 PKCS#11 STDLL로 구성 |
| 토큰 | CI 명령을 수신하여 실행하는 NCMP 보안 토큰(FX3 펌웨어 또는 mock) |
| 프레임(envelope) | 헤더와 파라미터 길이 배열, payload로 구성된 CI 메시지 한 개 |
| 파라미터 슬롯 | payload 내 `param0`~`param7` 각각의 위치. 길이는 `param_len[]`이 운반 |
| 블롭(blob) | 길이가 가변인 불투명 바이트열(키, 컨텍스트 등) |
| 컨텍스트 | 멀티파트 연산(INIT/UPDATE/FINAL)의 중간 상태 |
| 장치 컨테이너 | 인코딩된 프레임 1개가 담기는 장치 전송 단위 |

- 약어

| 약어 | 내용 |
|------|------|
| CI | Command Interface |
| NCMP | 토큰 통신 프로토콜 및 미들웨어 명칭 |
| STDLL | PKCS#11 슬롯 토큰 DLL(토큰별 PKCS#11 구현 라이브러리) |
| SHM | Shared Memory |
| LE | Little Endian |
| AEAD | Authenticated Encryption with Associated Data |
| GCM | Galois/Counter Mode |
| CTR | Counter |
| AAD | Additional Authenticated Data |
| IV | Initial Vector |
| XOF | eXtendable-Output Function |
| SHAKE | Secure Hash Algorithm KECCAK(XOF) |
| ML-DSA | Module-Lattice-based Digital Signature Algorithm |
| ML-KEM | Module-Lattice-based Key Encapsulation Mechanism |
| PQC | Post-Quantum Cryptography |
| SO | Security Officer |
| RV | Return Value |
| CRC | Cyclic Redundancy Check |
| HSM | Hardware Security Module |

---

## 2. CI 명령어 구조

### 2.1. CI 명령 블록 구조

모든 CI 메시지는 동일한 봉투(envelope)를 공유한다. 모든 필드는 4바이트 정렬, **리틀엔디언**이다.

- CI 명령 구조(호스트 ⇒ 토큰)

| 필드크기(word) | 명령블록 [31 … 16] | 명령블록 [15 … 0] |
|---|---|---|
| 1 | frame_len (32비트) | ← |
| 1 | session_id (32비트) | ← |
| 1 | sequence_id (32비트) | ← |
| 1 | flags (CI_FLAG_*) | opcode (CI_CMD_*) |
| 1 | ack = CKR_OK(0) (32비트) | ← |
| 1 | payload_len (32비트) | ← |
| 8 | param_len[0] ~ param_len[7] | ← |
| n | 명령인자 : param0 ~ param7 (가변) | ← |

[표 1] CI 명령 블록 구조 (← 는 좌측 필드가 32비트 전체를 차지함을 뜻함)

- frame_len(32비트) : 이 필드 이후 전체 길이. `20(헤더) + payload_len`
- session_id(32비트) : 이 명령이 속한 PKCS#11 세션 핸들. 전송 전용 명령은 0
- sequence_id(32비트) : 세션별 단조 증가 요청 id. 응답을 요청과 매칭하는 키
- command_id(32비트) : 하위 16비트는 opcode(`CI_CMD_*`), 상위 16비트는 플래그(`CI_FLAG_*`)
- ack(32비트) : `CKR_*` 결과 코드. 요청에서는 항상 `CKR_OK(0)`
- payload_len(32비트) : 헤더 이후 바이트 수. `sizeof(param_len) + Σ param_len[i]`
- param_len[8] : `param0`~`param7` 각각의 바이트 길이. 미사용 슬롯은 0
- 명령인자 : `param0`~`param7`을 순서대로 이어붙인 바이트열. 크기 가변적임

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

### 2.2. CI 명령어 응답 구조

- CI 응답 구조(토큰 ⇒ 호스트)

| 필드크기(word) | 응답블록 [31 … 16] | 응답블록 [15 … 0] |
|---|---|---|
| 1 | frame_len (32비트) | ← |
| 1 | session_id (32비트) | ← |
| 1 | sequence_id (32비트) | ← |
| 1 | flags (CI_FLAG_*) | opcode (CI_CMD_*) |
| 1 | RV : ack = CKR_* (32비트) | ← |
| 1 | payload_len (32비트) | ← |
| 8 | param_len[0] ~ param_len[7] | ← |
| n | 출력인자 : param0 ~ param7 (가변) | ← |

[표 2] CI 응답 구조

- session_id / sequence_id / command_id : 요청과 동일한 값을 반향하여 요청·응답을 매칭한다.
- RV(ack, 32비트) : 명령에 대한 결과 코드. PKCS#11 `CKR_*` 값을 그대로 사용한다(→ 5절).
- 출력인자 : 명령에 따라 출력되는 인자. 명령어에 따라 다양한 종류의 인자가 가능하며 크기는 가변적임.

- 프레임 불변식(invariant)
  - `frame_len == 20 + payload_len`
  - `payload_len == 32 + Σ param_len[i]` (i = 0..7)
  - 단일 파라미터 및 결합 payload(길이배열+파라미터) 각각 ≤ 65512 바이트 (= `NCMP_DEV_CONTAINER_SIZE - NCMP_WIRE_FRAME_OVERHEAD`). 인코딩된 프레임은 장치 컨테이너 1개에 정확히 들어간다.
  - FX3 bulk-IN은 **단발 수신**이다. 응답 프레임 1개를 한 전송으로 읽는다.

### 2.3. 명령 CMD 구성

command_id 필드는 다음과 같이 구성된다.

| 필드크기(word) | [31 … 16] | [15 … 0] |
|---|---|---|
| 1 | 플래그(CI_FLAG_*) | 명령코드(opcode, CI_CMD_*) |

[표 3] 명령 헤더(command_id)의 구성

```c
/* command_id 상위 16비트 플래그. */
enum {
    CI_FLAG_NONE        = 0x00000000u,
    CI_FLAG_FAIL_INJECT = 0x80000000u  /* 테스트 훅: 토큰이 강제로 실패 ack 반환 */
};
```

### 2.4. 파라미터 표기 규약

7절 각 명령의 `CI_*Req` / `CI_*Rsp` 구조체는 **payload 안의 파라미터 슬롯 매핑을 논리적으로** 나타낸 것이며, 패킹된 C 구조체가 아니다.

- 각 필드는 하나의 파라미터 슬롯(`param0`, `param1`, …)에 대응한다.
- 스칼라(`uint32_t` 등) : 해당 슬롯에 리틀엔디언으로 담긴 4바이트
- 가변 블롭 : `name[]`로 표기하며, 실제 길이는 프레임의 `param_len[]`이 운반한다.
- 파라미터가 없으면 구조체는 비어 있고(`{ /* 없음 */ }`) 결과는 `header.ack`로만 전달된다.
- 모든 응답은 `header.ack`에 `CKR_*` 상태를 싣는다(→ 5절).

### 2.5. 사용자 구성

토큰에서는 보안 관리자(SO), 일반 사용자(USER), 문맥 특정 사용자(CONTEXT_SPECIFIC)라는 세 가지 로그인 유형을 정의한다.

```c
enum { CI_CKU_SO = 0, CI_CKU_USER = 1, CI_CKU_CONTEXT_SPECIFIC = 2 }; /* user_type */
```

- 보안 관리자(SO : Security Officer) : 토큰의 관리자로서 사용자 PIN을 설정(`CI_CMD_INIT_PIN`)하고 토큰 클럭을 설정(`CI_CMD_SET_UTC_TIME`)할 수 있는 권한을 지닌다. 토큰 초기화(`CI_CMD_INIT_TOKEN`)는 SO PIN 검증을 거쳐 수행된다.
- 일반 사용자(USER) : PIN 인증 후 토큰의 보안 서비스 기능을 사용하는 사용자이다. 로그인 후 PIN 변경(`CI_CMD_SET_PIN`)이 가능하다.
- 문맥 특정 사용자(CONTEXT_SPECIFIC) : 별도의 계정이 아니라 **현재 로그인된 사용자**의 PIN을 재검증하는 유형이다(PKCS#11 `CKA_ALWAYS_AUTHENTICATE`). 로그인 상태는 바뀌지 않는다.

### 2.6. CI 명령어 종류 및 코드

각 `CI_CMD_*`는 `ncmp_cmd.h`의 `enum ncmp_opcode` 값을 그대로 별칭(alias)하도록 정의된다. 두 열거형은 항상 lockstep으로 유지되며(같은 값·같은 순번), CI 문서와 와이어 헤더가 서로 어긋날 수 없다.

| 명령 구분 | 세부 구분 | 명령어 이름 | 코드 | 기능 |
|---|---|---|---|---|
| 기본/해시 | 기본 | CI_CMD_NOP | 0x0000 | 무동작 / 에코(loopback) |
| | 난수발생 | CI_CMD_RNG | 0x0001 | 난수 생성 |
| | 해시 | CI_CMD_DIGEST | 0x0002 | 전체 블록 해시(단발) |
| | 조회 | CI_CMD_GETMECHLIST | 0x0003 | 지원 mechanism 조회 *(예약)* |
| | 해시 | CI_CMD_DIGEST_INIT | 0x0004 | 멀티파트 해시 시작 |
| | | CI_CMD_DIGEST_UPDATE | 0x0005 | 부분 블록 해시 |
| | | CI_CMD_DIGEST_FINAL | 0x0006 | 멀티파트 해시 종료 |
| | 키 유도 | CI_CMD_SHAKE_DERIVE | 0x0009 | SHAKE XOF 키 유도 |
| 대칭키 암복호 | AEAD | CI_CMD_AES_GCM | 0x0012 | AES-GCM 전체 블록 암/복호(단발) |
| | 스트림 | CI_CMD_AES_CTR | 0x0013 | AES-CTR 암/복호 |
| | AEAD(멀티파트) | CI_CMD_AES_GCM_INIT | 0x0014 | AES-GCM 초기화 |
| | | CI_CMD_AES_GCM_UPDATE | 0x0015 | AES-GCM 부분 블록 암/복호 |
| | | CI_CMD_AES_GCM_FINAL | 0x0016 | AES-GCM 종료(태그 생성/검증) |
| | 컨텍스트 | CI_CMD_CTX_FREE | 0x0017 | 멀티파트 컨텍스트 해제(중단) |
| 토큰 관리 | 로그인 | CI_CMD_LOGIN | 0x0030 | 로그인 |
| | | CI_CMD_LOGOUT | 0x0031 | 로그아웃 |
| | PIN | CI_CMD_INIT_PIN | 0x0032 | 사용자 PIN 초기화(SO) |
| | | CI_CMD_SET_PIN | 0x0033 | PIN 변경 |
| | 토큰 | CI_CMD_INIT_TOKEN | 0x0034 | 토큰 초기화 |
| | 조회/설정 | CI_CMD_GET_UTC_TIME | 0x0035 | UTC 시각 조회 |
| | | CI_CMD_GET_TOKEN_PARAMS | 0x0036 | 라벨·시리얼·PIN 길이 조회 |
| | | CI_CMD_SET_UTC_TIME | 0x0037 | UTC 시각 설정(SO) |
| 객체 관리 | 키 객체 | CI_CMD_OBJECT_ADD | 0x0038 | 키 객체 등록/임포트 |
| | | CI_CMD_OBJECT_SET_ATTR | 0x0039 | 키 속성 변경 검증 |
| 세션 관리 | 세션 | CI_CMD_OPEN_SESSION | 0x003A | 세션 열기 ((pid,sid)→HSM SID) |
| | | CI_CMD_CLOSE_SESSION | 0x003B | 세션 닫기 (HSM SID 해제) |
| 포스트양자 | ML-DSA | CI_CMD_MLDSA_KEYGEN | 0x0050 | ML-DSA 키 쌍 생성 |
| | | CI_CMD_MLDSA_SIGN | 0x0051 | ML-DSA 서명 |
| | | CI_CMD_MLDSA_VERIFY | 0x0052 | ML-DSA 검증 |
| | ML-KEM | CI_CMD_MLKEM_KEYGEN | 0x0053 | ML-KEM 키 쌍 생성 |
| | | CI_CMD_MLKEM_ENCAPS | 0x0054 | ML-KEM 캡슐화 |
| | | CI_CMD_MLKEM_DECAPS | 0x0055 | ML-KEM 역캡슐화 |
| 벤더 정의 | 메모리 | CI_CMD_VD_MEM_WRITE | 0x0101 | 스크래치 RAM 쓰기 |
| | | CI_CMD_VD_MEM_READ | 0x0102 | 스크래치 RAM 읽기 |
| | 진단 | CI_CMD_VD_PING | 0x0103 | 토큰 epoch 조회 |
| | | CI_CMD_VD_SELFTEST | 0x0104 | 자가 시험 |
| | 정보 | CI_CMD_VD_FW_INFO | 0x0105 | 펌웨어 버전 조회 |
| | 메모리 | CI_CMD_VD_MEM_FILL | 0x0106 | 스크래치 RAM 채우기 |
| | | CI_CMD_VD_MEM_CRC | 0x0107 | 스크래치 RAM CRC-32 계산 |
| | 정보 | CI_CMD_VD_TOKEN_INFO | 0x0108 | 토큰 정체성 조회 |

[표 4] CI 명령어 종류 및 코드

- 와이어 표면 = advertised mechanism 표면 : opcode/CI 목록은 토큰이 실제로 제공하는 mechanism(AES-GCM/CTR · SHA-2/3 · SHAKE · ML-KEM · ML-DSA)과 **정확히 일치**한다. RSA/EC/DH/ECDH/HMAC/AES-CBC·ECB·OFB·CFB 등 비광고 mechanism은 opcode·CI 구조체·어댑터·mock·테스트까지 완전히 제거되었다(레거시 포워딩 경로 없음).
- 에코/loopback은 별도 opcode 없이 `CI_CMD_NOP`로 처리한다. 과거의 `CI_CMD_VD_LOOPBACK`(0x0100)은 제거되었다.

---

## 3. 명령 처리 순서

### 3.1. 단발 명령과 멀티파트 명령

CI 명령은 한 번의 요청·응답으로 끝나는 단발(one-shot) 명령과, 연산별 컨텍스트를 유지하며 여러 번의 요청으로 수행되는 멀티파트 명령으로 나뉜다.

1. 초기화(INIT) : 멀티파트 연산을 시작하고, 토큰이 컨텍스트를 할당하여 응답 `param0`으로 돌려준다.
2. 갱신(UPDATE) : 요청 `param0`에 컨텍스트를, `param1+`에 이번 입력 조각을 실어 보낸다. 필요한 만큼 반복한다.
3. 종료(FINAL) : 컨텍스트를 전달하여 최종 결과(다이제스트/태그)를 받거나 태그를 검증받는다. 반환 후 컨텍스트는 해제된다.
4. 중단(CTX_FREE) : FINAL 없이 연산을 중단하면 STDLL 컨텍스트 해제 훅이 `CI_CMD_CTX_FREE`를 보내 컨텍스트를 회수한다.

[표] 수행 단계별 CI 명령어

| 수행 단계 | 관련 명령 | 비고 |
|---|---|---|
| 단발 | - CI_CMD_RNG<br>- CI_CMD_DIGEST<br>- CI_CMD_SHAKE_DERIVE<br>- CI_CMD_AES_GCM<br>- CI_CMD_AES_CTR<br>- CI_CMD_MLDSA_* / CI_CMD_MLKEM_*<br>- 토큰 관리 / 객체 관리 / 벤더 정의 명령 | 호출 간 토큰 상태 없음 |
| ①→②…②→③ | - CI_CMD_DIGEST_INIT / _UPDATE / _FINAL<br>- CI_CMD_AES_GCM_INIT / _UPDATE / _FINAL | 컨텍스트 유지 |
| ①→②…→④ | - CI_CMD_CTX_FREE | 중단 시 |

### 3.2. 멀티파트 컨텍스트 모델 (컴파일 옵션)

컨텍스트 보관 위치는 **데몬 빌드 시** `NCMP_HOST_MANAGED_CTX` 매크로(CMake 옵션, 기본 OFF)로 선택한다.

- 기본(매크로 OFF) : 물리 토큰이 컨텍스트를 소유한다. INIT이 컨텍스트 id를 반환하고 UPDATE/FINAL이 그 id를 전달하며 토큰이 상태를 보관한다.
- `NCMP_HOST_MANAGED_CTX`(매크로 ON) : 토큰이 무상태가 된다(HSM 저장 공간 부족 대응). 토큰은 INIT과 매 UPDATE에서 컨텍스트 blob 전체를 반환하고 UPDATE/FINAL에서 blob을 다시 받는다. 데몬 `comm_thread`가 blob을 호스트 측에 보관하고 작은 id로 중계하므로 STDLL은 변경되지 않는다.

규약 : `param0`은 INIT 응답과 UPDATE/FINAL 요청에서 컨텍스트 슬롯(STDLL=id, 토큰=blob)이며, 연산 데이터는 `param1+`에 온다. 브리지는 `ncmp/daemon/comm_thread.c`의 `ctx_xform_request`/`ctx_xform_response`가 담당하고 `ctx_phase_of()`로 대상 opcode를 분류한다. STDLL은 UPDATE 청크에 `NCMP_HOST_CTX_BLOB_MAX`만큼 여유를 두어 id→blob 치환 시 프레임이 넘치지 않게 한다.

### 3.3. 메커니즘별 컨텍스트와 key-id

컨텍스트 blob은 메커니즘별로 타입이 구분된다(`ncmp/include/ncmp/ncmp_ctx.h`). 공통 8바이트 헤더 `{type(u32)|len(u32)}` 뒤에 메커니즘별 구조가 온다.

| type | 구조체 | 필드 | 직렬화 크기 |
|---|---|---|---|
| NCMP_CTX_TYPE_DIGEST(1) | ncmp_ctx_digest_t | mech, acc | 16 바이트 |
| NCMP_CTX_TYPE_GCM(2) | ncmp_ctx_gcm_t | key_id, acc, offset, enc, taglen, ivlen, iv[16] | 39 바이트 |

[표 5] 컨텍스트 타입

- 민감정보 보호 : 키는 컨텍스트에 절대 담기지 않는다. 키는 토큰 키 테이블에 상주(HSM-resident)하고 GCM 컨텍스트는 `key_id`만 참조한다. 따라서 미들웨어(comm_thread)가 저장·중계하는 컨텍스트에는 키 바이트가 없다.
- 키 바이트는 임포트 키 특성상 `AES_GCM_INIT` 요청에서 토큰으로 전달되는 순간에만 통과하며(전송 중), 토큰은 이를 키 테이블에 등록하고 `key_id`가 담긴 컨텍스트를 돌려준다.
- FINAL/CTX_FREE는 컨텍스트와 함께 해당 키도 해제한다. 토큰과 데몬은 헤더의 `type`으로 명령/메커니즘별 컨텍스트 구조체를 선택한다.
- 단발 연산(AES-GCM one-shot, AES-CTR — 카운터를 매 명령에 실어 보냄)은 호출 간 토큰 상태가 없어 영향을 받지 않는다.
- `CI_CMD_CTX_FREE`(0x0017, `[ctx|kind]`)는 `NCMP_HOST_MANAGED_CTX`에서는 comm_thread가 호스트 슬롯을, 기본 빌드에서는 토큰이 자신의 테이블 항목을 해제한다. 멱등이며 teardown에서 best-effort로 동작한다.

---

## 4. CI 메커니즘

토큰 CI 규격에서 제공되는 메커니즘에 대한 내용을 기술한다.

### 4.1. CI 메커니즘 개요

| 메커니즘 | 설명 | 관련 명령 |
|---|---|---|
| CKM_SHA256 / CKM_SHA512 / CKM_SHA3_* 등 | - SHA-2/SHA-3 해시<br>- 출력 길이 28/32/48/64 바이트 | CI_CMD_DIGEST, CI_CMD_DIGEST_INIT |
| CKM_SHAKE_128_KEY_DERIVATION<br>CKM_SHAKE_256_KEY_DERIVATION | - SHAKE XOF로 기반 키 재료를 임의 길이로 확장 | CI_CMD_SHAKE_DERIVE |
| AES-GCM | - AEAD. 암호화 시 태그 부가, 복호화 시 태그 검증<br>- 단발/멀티파트 모두 지원 | CI_CMD_AES_GCM, CI_CMD_AES_GCM_INIT/UPDATE/FINAL |
| AES-CTR | - 유일하게 광고되는 AES 스트림 모드<br>- 출력 길이 = 입력 길이 | CI_CMD_AES_CTR |
| ML-DSA | - PKCS#11 3.2 포스트양자 서명 | CI_CMD_MLDSA_* |
| ML-KEM | - PKCS#11 3.2 포스트양자 키 캡슐화 | CI_CMD_MLKEM_* |

### 4.2. 포스트양자 파라미터 세트

키는 불투명 블롭으로 전달되며, **개인 블롭은 공개 블롭을 접두어로 포함**한다. `param_set`은 보안강도 선택자(CKP_ML_*)이고, 각종 `*_len`은 블롭 크기(호스트가 `struct pqc_oid`에서 계산해 전달)이다.

| 파라미터 세트 | 설정 값 | 보안강도 |
|---|---|---|
| CI_ML_DSA_44 | 1 | 2 |
| CI_ML_DSA_65 | 2 | 3 |
| CI_ML_DSA_87 | 3 | 5 |
| CI_ML_KEM_512 | 1 | 1 |
| CI_ML_KEM_768 | 2 | 3 |
| CI_ML_KEM_1024 | 3 | 5 |

```c
enum {  /* param_set (keyform) 값 = 보안강도 */
    CI_ML_DSA_44 = 1, CI_ML_DSA_65 = 2, CI_ML_DSA_87 = 3,   /* 강도 2 / 3 / 5 */
    CI_ML_KEM_512 = 1, CI_ML_KEM_768 = 2, CI_ML_KEM_1024 = 3 /* 강도 1 / 3 / 5 */
};
```

---

## 5. 반환값

CI 명령에 따른 응답 헤더의 리턴 값(RV : `header.ack`)에 관한 내용을 기술한다. 응답의 `header.ack`에는 PKCS#11 `CKR_*` 값이 그대로 실린다.

### 5.1. 반환값 목록

[표] 반환 값 목록

| 표현(Description) | 값 |
|---|---|
| CKR_OK | 0x00000000 |
| CKR_FUNCTION_FAILED | 0x00000006 |
| CKR_ARGUMENTS_BAD | 0x00000007 |
| CKR_ATTRIBUTE_VALUE_INVALID | 0x00000013 |
| CKR_DEVICE_MEMORY | 0x00000031 |
| CKR_ENCRYPTED_DATA_INVALID | 0x00000040 |
| CKR_MECHANISM_INVALID | 0x00000070 |
| CKR_PIN_INCORRECT | 0x000000A0 |
| CKR_PIN_LEN_RANGE | 0x000000A2 |
| CKR_SIGNATURE_INVALID | 0x000000C0 |
| CKR_TEMPLATE_INCOMPLETE | 0x000000D0 |
| CKR_USER_ALREADY_LOGGED_IN | 0x00000100 |
| CKR_USER_NOT_LOGGED_IN | 0x00000101 |
| CKR_USER_TYPE_INVALID | 0x00000103 |

### 5.2. 리턴 값 정의

- 주요 반환 값의 정의

아래 표에 언급되지 않은 반환값에 대한 설명은 PKCS#11 표준 문서를 참조한다.

[표] 반환 값의 정의

| 항목 | 설명 |
|---|---|
| CKR_OK | 명령이 정상적으로 수행되었음을 나타낸다. |
| CKR_FUNCTION_FAILED | 일반 실패 또는 파라미터 파싱 오류가 발생하였음을 나타낸다. |
| CKR_ARGUMENTS_BAD | 명령어에 입력되는 인자가 적합하지 않은 경우 호스트에 전달되는 응답이다. 예를 들어, `CI_CMD_SET_UTC_TIME`의 `utc`가 16바이트가 아닌 경우이다. |
| CKR_ATTRIBUTE_VALUE_INVALID | `CI_CMD_OBJECT_SET_ATTR`로 전달된 키 객체의 변경 속성 값이 유효하지 않은 경우 응답된다. |
| CKR_DEVICE_MEMORY | 토큰의 스크래치/컨테이너 메모리가 부족한 경우 응답된다. 벤더 메모리 명령에서 `addr+len`이 스크래치 RAM 범위를 벗어난 경우에도 응답된다. |
| CKR_ENCRYPTED_DATA_INVALID | AEAD(AES-GCM) 복호화 시 인증 태그 검증에 실패한 경우 응답되며, 이때 출력은 없다. |
| CKR_MECHANISM_INVALID | 지원하지 않거나 부적합한 mechanism·파라미터가 지정된 경우 응답된다. |
| CKR_PIN_INCORRECT | 지정된 PIN 값이 토큰에 저장된 PIN과 일치하지 않는 경우 발생하는 오류이며, 사용자 인증은 실패한다. |
| CKR_PIN_LEN_RANGE | 지정된 PIN의 길이가 허용 범위를 벗어난 경우 응답된다. PIN을 설정하는 명령에 적용된다. |
| CKR_SIGNATURE_INVALID | 서명 또는 MAC 값을 검증하였을 때 서명 값에 오류가 있음을 알려준다. |
| CKR_TEMPLATE_INCOMPLETE | `CI_CMD_OBJECT_ADD`로 전달된 키 객체의 속성이 등록에 부족한 경우 응답된다. |
| CKR_USER_ALREADY_LOGGED_IN | `CI_CMD_LOGIN`에서만 응답될 수 있는 값으로, 이미 로그인되어 있어 다시 로그인할 수 없음을 알려준다. |
| CKR_USER_NOT_LOGGED_IN | 요청한 동작에 필요한 사용자가 로그인되어 있지 않음을 알려준다. 예를 들어, SO 로그인 없이 `CI_CMD_SET_UTC_TIME`을 요청하거나, 아무도 로그인하지 않은 상태에서 문맥 특정 재인증을 요청한 경우이다. |
| CKR_USER_TYPE_INVALID | 로그인 유형 값이 유효하지 않음을 알려준다. 유효한 값은 `CI_CKU_SO(0)`, `CI_CKU_USER(1)`, `CI_CKU_CONTEXT_SPECIFIC(2)`이다. |

- 전송 계층 오류(USB/타임아웃 등)는 토큰의 ack가 아니라 호스트에서 `NCMP_ERR_*`로 처리되어 STDLL 경계에서 `CKR_*`로 매핑된다(→ `ncmp_errno.h`, `ncmp_ckr.h`, [`middleware_api.md`](middleware_api.md)).

---

## 6. CI 명령 규격

토큰 CI 명령어의 상세 규격을 기술한다. 모든 명령의 리턴 값(RV)은 PKCS#11(Cryptoki)에서 정의된 리턴 값을 사용하였다.

이 절에서는 각 명령의 요청(명령 블록)과 응답(응답 블록)을 파라미터 슬롯 단위로 표현하였으며, 명령 종류별로 구분지어 기술하였다. 각 명령의 "관련 호스트 API"는 해당 명령을 전송하는 STDLL 어댑터 함수이다([`middleware_api.md`](middleware_api.md) 참조).

### 6.1. 기본 · 해시 기능 블록

#### 6.1.1. CI_CMD_NOP (0x0000)

- 기능
  무동작 명령. 요청 payload를 그대로 반향(에코/loopback)한다.
- 명령 블록
  ```c
  typedef struct CI_NopReq {
      uint8_t data[];   /* param0: 임의 바이트(그대로 반향) */
  } CI_NopReq;
  ```
- 응답 블록
  ```c
  typedef struct CI_NopRsp {
      uint8_t data[];   /* param0: 요청 payload 그대로 */
  } CI_NopRsp;
  ```

| 구분 | 파라미터 | 필드 | 크기 | 설명 |
|---|---|---|---|---|
| 요청 | param0 | data | 가변 | 임의 바이트 |
| 응답 | param0 | data | 가변 | 요청 payload 그대로 |

#### 6.1.2. CI_CMD_RNG (0x0001)

- 기능
  난수를 생성한다.
- 관련 호스트 API : `ncmp_crypto_rng`
- 명령 블록
  ```c
  typedef struct CI_RngReq {
      uint32_t count;   /* param0: 요청 난수 바이트 수 (≤ 65512 B) */
  } CI_RngReq;
  ```
- 응답 블록
  ```c
  typedef struct CI_RngRsp {
      uint8_t  bytes[]; /* param0: count 바이트의 난수 */
  } CI_RngRsp;
  ```

| 구분 | 파라미터 | 필드 | 크기 | 설명 |
|---|---|---|---|---|
| 요청 | param0 | count | 4 | 요청 난수 바이트 수(≤ 65512) |
| 응답 | param0 | bytes | count | 난수 |

#### 6.1.3. CI_CMD_DIGEST (0x0002)

- 기능
  단발(one-shot) 해시를 수행한다.
- 관련 호스트 API : `ncmp_crypto_digest`
- 관련 메커니즘 : CKM_SHA256, CKM_SHA512, CKM_SHA3_* 등
- 명령 블록
  ```c
  typedef struct CI_DigestReq {
      uint32_t mech;    /* param0[0..4): 해시 mechanism (CKM_SHA256/512, CKM_SHA3_* 등) */
      uint8_t  data[];  /* param0[4..):  입력 메시지 (mech 뒤에 이어붙임) */
  } CI_DigestReq;
  ```
- 응답 블록
  ```c
  typedef struct CI_DigestRsp {
      uint8_t  digest[]; /* param0: 해시 출력 (mech에 따라 28/32/48/64 바이트) */
  } CI_DigestRsp;
  ```

| 구분 | 파라미터 | 필드 | 크기 | 설명 |
|---|---|---|---|---|
| 요청 | param0[0..4) | mech | 4 | 해시 mechanism |
| 요청 | param0[4..) | data | 가변 | 입력 메시지 |
| 응답 | param0 | digest | 28/32/48/64 | 해시 출력 |

- 주의사항
  - `mech`와 `data`는 **하나의 파라미터(param0)** 안에 `[mech(4B)|data]` 형태로 결합된다.

#### 6.1.4. CI_CMD_GETMECHLIST (0x0003) *(예약)*

- 기능
  토큰이 지원하는 mechanism 목록을 조회한다.
- 명령 블록
  ```c
  typedef struct CI_GetMechListReq { /* 없음 */ } CI_GetMechListReq;
  ```
- 응답 블록
  ```c
  typedef struct CI_GetMechListRsp {
      uint32_t mechs[]; /* param0: 지원 mechanism(CKM_*) 배열 (LE u32 나열) */
  } CI_GetMechListRsp;
  ```
- 주의사항
  - 현재 미구현(예약)이다. 하드웨어에서 mechanism 목록을 조회할 때 사용할 예정이다.

#### 6.1.5. CI_CMD_DIGEST_INIT (0x0004)

- 기능
  멀티파트 해시를 시작하고 컨텍스트를 할당한다.
- 관련 호스트 API : `ncmp_crypto_digest_init`
- 명령 블록
  ```c
  typedef struct CI_DigestInitReq {
      uint32_t mech;    /* param0: 해시 mechanism */
  } CI_DigestInitReq;
  ```
- 응답 블록
  ```c
  typedef struct CI_DigestInitRsp {
      uint32_t ctx_id;  /* param0: 토큰이 할당한 해시 컨텍스트 id (후속 update/final에 사용) */
  } CI_DigestInitRsp;
  ```

| 구분 | 파라미터 | 필드 | 크기 | 설명 |
|---|---|---|---|---|
| 요청 | param0 | mech | 4 | 해시 mechanism |
| 응답 | param0 | ctx_id | 4 (호스트 관리 빌드: blob) | 컨텍스트 |

#### 6.1.6. CI_CMD_DIGEST_UPDATE (0x0005)

- 기능
  멀티파트 해시 컨텍스트에 입력 조각을 흡수한다.
- 관련 호스트 API : `ncmp_crypto_digest_update`
- 명령 블록
  ```c
  typedef struct CI_DigestUpdateReq {
      uint32_t ctx_id;  /* param0: DIGEST_INIT가 반환한 컨텍스트 id */
      uint8_t  data[];  /* param1: 이번에 흡수할 입력 조각 */
  } CI_DigestUpdateReq;
  ```
- 응답 블록
  ```c
  typedef struct CI_DigestUpdateRsp { /* 없음 (ack만) */ } CI_DigestUpdateRsp;
  ```

| 구분 | 파라미터 | 필드 | 크기 | 설명 |
|---|---|---|---|---|
| 요청 | param0 | ctx_id | 4 (호스트 관리 빌드: blob) | 컨텍스트 |
| 요청 | param1 | data | 가변 | 입력 조각 |
| 응답 | — | — | — | ack만 |

#### 6.1.7. CI_CMD_DIGEST_FINAL (0x0006)

- 기능
  멀티파트 해시를 종료하고 최종 해시를 돌려준다.
- 관련 호스트 API : `ncmp_crypto_digest_final`
- 명령 블록
  ```c
  typedef struct CI_DigestFinalReq {
      uint32_t ctx_id;  /* param0: 종료할 컨텍스트 id (반환 후 해제됨) */
  } CI_DigestFinalReq;
  ```
- 응답 블록
  ```c
  typedef struct CI_DigestFinalRsp {
      uint8_t  digest[]; /* param0: 최종 해시 출력 */
  } CI_DigestFinalRsp;
  ```
- 주의사항
  - 응답 후 컨텍스트는 토큰에서 해제된다.

#### 6.1.8. CI_CMD_SHAKE_DERIVE (0x0009)

- 기능
  SHAKE XOF로 기반 키 재료를 지정 길이만큼 유도한다.
- 관련 호스트 API : `ncmp_crypto_shake_derive`
- 관련 메커니즘 : CKM_SHAKE_128_KEY_DERIVATION, CKM_SHAKE_256_KEY_DERIVATION
- 명령 블록
  ```c
  typedef struct CI_ShakeDeriveReq {
      uint32_t mech;    /* param0: CKM_SHAKE_128/256_KEY_DERIVATION */
      uint32_t out_len; /* param1: 유도할 출력 바이트 수 */
      uint8_t  base[];  /* param2: 기반 키 재료(base key의 CKA_VALUE) */
  } CI_ShakeDeriveReq;
  ```
- 응답 블록
  ```c
  typedef struct CI_ShakeDeriveRsp {
      uint8_t  out[];   /* param0: out_len 바이트의 유도 결과 */
  } CI_ShakeDeriveRsp;
  ```

| 구분 | 파라미터 | 필드 | 크기 | 설명 |
|---|---|---|---|---|
| 요청 | param0 | mech | 4 | SHAKE 메커니즘 |
| 요청 | param1 | out_len | 4 | 출력 바이트 수 |
| 요청 | param2 | base | 가변 | 기반 키 재료 |
| 응답 | param0 | out | out_len | 유도 결과 |

### 6.2. 대칭키 암복호 기능 블록

모든 AES 명령의 `flags`는 방향 비트를 담는다.

```c
enum { CI_AES_FLAG_ENCRYPT = 0x1 };  /* flags bit0: 1=암호화, 0=복호화 */
```

#### 6.2.1. CI_CMD_AES_GCM (0x0012)

- 기능
  AES-GCM(AEAD) 단발 암/복호를 수행한다.
- 관련 호스트 API : `ncmp_crypto_aes_gcm`
- 반환 값
  - CKR_OK
  - CKR_ENCRYPTED_DATA_INVALID (복호화 태그 불일치)
  - CKR_MECHANISM_INVALID
- 명령 블록
  ```c
  typedef struct CI_AesGcmReq {
      uint32_t flags;    /* param0: bit0=암/복호 */
      uint8_t  key[];    /* param1: AES 키 */
      uint8_t  iv[];     /* param2: nonce/IV (1..16 B) */
      uint8_t  aad[];    /* param3: 추가 인증 데이터 (비어 있을 수 있음) */
      uint32_t tag_len;  /* param4: 인증 태그 길이(바이트) */
      uint8_t  data[];   /* param5: 암호화=평문 / 복호화=ciphertext‖tag */
  } CI_AesGcmReq;
  ```
- 응답 블록
  ```c
  typedef struct CI_AesGcmRsp {
      uint8_t  out[];    /* param0: 암호화=ciphertext‖tag / 복호화=평문 */
  } CI_AesGcmRsp;
  ```

| 구분 | 파라미터 | 필드 | 크기 | 설명 |
|---|---|---|---|---|
| 요청 | param0 | flags | 4 | bit0 = 암/복호 |
| 요청 | param1 | key | 가변 | AES 키 |
| 요청 | param2 | iv | 1~16 | nonce/IV |
| 요청 | param3 | aad | 가변(0 가능) | 추가 인증 데이터 |
| 요청 | param4 | tag_len | 4 | 태그 길이 |
| 요청 | param5 | data | 가변 | 평문 / ciphertext‖tag |
| 응답 | param0 | out | 가변 | ciphertext‖tag / 평문 |

- 주의사항
  - 복호화에서 태그 불일치 시 `ack = CKR_ENCRYPTED_DATA_INVALID`이며 출력은 없다.

#### 6.2.2. CI_CMD_AES_CTR (0x0013)

- 기능
  AES-CTR 스트림 암/복호를 수행한다. AES-CTR은 유일하게 광고되는 AES 스트림 모드다.
- 관련 호스트 API : `ncmp_crypto_aes_stream`
- 명령 블록
  ```c
  typedef struct CI_AesCtrReq {
      uint32_t flags;   /* param0: bit0=암/복호 (스트림은 방향 대칭) */
      uint8_t  key[];   /* param1: AES 키 (16/24/32 B) */
      uint8_t  iv[];    /* param2: 카운터 블록 (16 B) */
      uint8_t  data[];  /* param3: 입력 (임의 길이) */
  } CI_AesCtrReq;
  ```
- 응답 블록
  ```c
  typedef struct CI_AesCtrRsp {
      uint8_t out[];    /* param0: 출력 (입력과 동일 길이) */
  } CI_AesCtrRsp;
  ```

| 구분 | 파라미터 | 필드 | 크기 | 설명 |
|---|---|---|---|---|
| 요청 | param0 | flags | 4 | bit0 = 암/복호 |
| 요청 | param1 | key | 16/24/32 | AES 키 |
| 요청 | param2 | iv | 16 | 카운터 블록 |
| 요청 | param3 | data | 가변 | 입력 |
| 응답 | param0 | out | 입력과 동일 | 출력 |

- 주의사항
  - 카운터를 매 명령에 실어 보내므로 호출 간 토큰 상태가 없다.

#### 6.2.3. CI_CMD_AES_GCM_INIT / UPDATE / FINAL (0x0014 – 0x0016)

- 기능
  멀티파트 AES-GCM을 수행하는 상태형(컨텍스트) 연산이다. 컨텍스트 배치는 3.2절의 두 모델을 따른다.
- 관련 호스트 API : `ncmp_crypto_aes_gcm_init` / `_update` / `_final`
- 명령 블록(INIT)
  ```c
  /* INIT: [flags|key|iv|aad|taglen] -> 응답 param0 = 컨텍스트(슬롯). */
  typedef struct CI_AesGcmInitReq {
      uint32_t flags;   /* param0: bit0=암/복호 */
      uint8_t  key[];   /* param1 */
      uint8_t  iv[];    /* param2 */
      uint8_t  aad[];   /* param3 (가능) */
      uint32_t taglen;  /* param4: 태그 바이트 수 */
  } CI_AesGcmInitReq;
  ```
- 명령/응답 블록(UPDATE, FINAL)
  ```c
  /* UPDATE: [ctx|data] -> [ctx'|out]. STDLL 관점: [ctx_id|data] -> [out]. */
  /* FINAL(암호화): [ctx] -> [tag]. FINAL(복호화): [ctx|expected_tag] -> ack. */
  ```

| 명령 | 요청 | 응답 |
|---|---|---|
| INIT (0x0014) | param0 flags, param1 key, param2 iv, param3 aad, param4 taglen | param0 컨텍스트 |
| UPDATE (0x0015) | param0 컨텍스트, param1 data | (param0 컨텍스트'), out |
| FINAL (0x0016) 암호화 | param0 컨텍스트 | param0 tag |
| FINAL (0x0016) 복호화 | param0 컨텍스트, param1 expected_tag | ack만 |

- 주의사항
  - `param0`은 UPDATE/FINAL 요청과 INIT 응답에서 컨텍스트 슬롯(STDLL=id, 토큰=blob)이며, 연산 데이터는 `param1+`에 온다.
  - `NCMP_HOST_MANAGED_CTX` 빌드에서는 comm_thread가 id↔blob을 교환한다(3.2절 참조).
  - 복호화 태그 불일치 시 `ack = CKR_ENCRYPTED_DATA_INVALID`.
  - 키는 INIT 요청 전송 중에만 통과하며, 토큰은 키 테이블에 등록한 뒤 `key_id`만 컨텍스트에 담는다(3.3절).

#### 6.2.4. CI_CMD_CTX_FREE (0x0017)

- 기능
  멀티파트 연산을 FINAL 없이 중단할 때 컨텍스트를 회수한다.
- 관련 호스트 API : `ncmp_crypto_ctx_free`
- 명령 블록 : `[ctx|kind]` (param0 = 컨텍스트, param1 = 컨텍스트 종류)
- 응답 블록 : 없음(ack만)
- 주의사항
  - 멱등이며 teardown에서 best-effort로 동작한다(3.3절).

### 6.3. 토큰 관리 / 로그인 / 조회 기능 블록

```c
enum { CI_CKU_SO = 0, CI_CKU_USER = 1, CI_CKU_CONTEXT_SPECIFIC = 2 }; /* user_type */

/* param1의 로그인 수정 플래그 (NCMP_LOGIN_FLAG_* 와 동일 값). */
enum {
    CI_LOGIN_FLAG_NONE           = 0x00000000u,
    CI_LOGIN_FLAG_PROTECTED_AUTH = 0x00000001u, /* PIN을 토큰 패드에서 입력 */
    CI_LOGIN_FLAG_CONTEXT        = 0x00000002u  /* CKU_CONTEXT_SPECIFIC 재인증 */
};
```

#### 6.3.1. CI_CMD_LOGIN (0x0030)

- 기능
  로그인(PIN 검증)을 수행한다. SO/User 역할(`user_type`) **외에** 부가 조건을 `flags`로 함께 전달한다.
- 관련 호스트 API : `ncmp_admin_login`
- 반환 값
  - CKR_OK
  - CKR_PIN_INCORRECT
  - CKR_USER_TYPE_INVALID
  - CKR_USER_ALREADY_LOGGED_IN
  - CKR_USER_NOT_LOGGED_IN
- 명령 블록
  ```c
  typedef struct CI_LoginReq {
      uint32_t user_type;  /* param0: CI_CKU_SO(0) / CI_CKU_USER(1) / CI_CKU_CONTEXT_SPECIFIC(2) */
      uint32_t flags;      /* param1: CI_LOGIN_FLAG_* (protected-auth / context 재인증) */
      uint8_t  pin[];      /* param2: PIN 바이트 (protected-auth면 비어 있음) */
  } CI_LoginReq;
  ```
- 응답 블록
  ```c
  typedef struct CI_LoginRsp { /* 없음. ack=OK / CKR_PIN_INCORRECT / CKR_USER_* */ } CI_LoginRsp;
  ```

| 구분 | 파라미터 | 필드 | 크기 | 설명 |
|---|---|---|---|---|
| 요청 | param0 | user_type | 4 | 로그인 유형 |
| 요청 | param1 | flags | 4 | CI_LOGIN_FLAG_* |
| 요청 | param2 | pin | 가변(0 가능) | PIN |
| 응답 | — | — | — | ack만 |

- 주의사항
  - protected-auth(`CI_LOGIN_FLAG_PROTECTED_AUTH`) : PIN을 토큰 자체 패드에서 입력하므로 와이어 PIN은 비어 있고, 토큰이 직접 인증을 승인한다.
  - context-specific(`user_type=2` 또는 `CI_LOGIN_FLAG_CONTEXT`) : **현재 로그인된 사용자**의 PIN을 재검증(PKCS#11 `CKA_ALWAYS_AUTHENTICATE`)하며 로그인 상태는 바꾸지 않는다. 아무도 로그인하지 않았으면 `CKR_USER_NOT_LOGGED_IN`.
  - 잘못된 `user_type`은 `CKR_USER_TYPE_INVALID`, 중복 로그인은 `CKR_USER_ALREADY_LOGGED_IN`.

#### 6.3.2. CI_CMD_LOGOUT (0x0031)

- 기능
  로그아웃한다.
- 관련 호스트 API : `ncmp_admin_logout`
- 명령 블록
  ```c
  typedef struct CI_LogoutReq { /* 없음 */ } CI_LogoutReq;
  ```
- 응답 블록
  ```c
  typedef struct CI_LogoutRsp { /* 없음. ack=CKR_OK */ } CI_LogoutRsp;
  ```

#### 6.3.3. CI_CMD_INIT_PIN (0x0032)

- 기능
  SO가 사용자 PIN을 설정한다.
- 관련 호스트 API : `ncmp_admin_init_pin`
- 반환 값
  - CKR_OK
  - CKR_USER_NOT_LOGGED_IN
  - CKR_PIN_LEN_RANGE
- 명령 블록
  ```c
  typedef struct CI_InitPinReq {
      uint8_t  new_pin[];  /* param0: 설정할 사용자 PIN */
  } CI_InitPinReq;
  ```
- 응답 블록
  ```c
  typedef struct CI_InitPinRsp { /* 없음 */ } CI_InitPinRsp;
  ```

#### 6.3.4. CI_CMD_SET_PIN (0x0033)

- 기능
  현재 사용자의 PIN을 변경한다.
- 관련 호스트 API : `ncmp_admin_set_pin`
- 반환 값
  - CKR_OK
  - CKR_PIN_INCORRECT
  - CKR_PIN_LEN_RANGE
- 명령 블록
  ```c
  typedef struct CI_SetPinReq {
      uint8_t  old_pin[];  /* param0: 현재 PIN */
      uint8_t  new_pin[];  /* param1: 새 PIN */
  } CI_SetPinReq;
  ```
- 응답 블록
  ```c
  typedef struct CI_SetPinRsp { /* 없음 */ } CI_SetPinRsp;
  ```

#### 6.3.5. CI_CMD_INIT_TOKEN (0x0034)

- 기능
  SO PIN을 검증하고 토큰을 초기화하며 새 라벨을 설정한다.
- 관련 호스트 API : `ncmp_admin_init_token`
- 반환 값
  - CKR_OK
  - CKR_PIN_INCORRECT
- 명령 블록
  ```c
  typedef struct CI_InitTokenReq {
      uint8_t  so_pin[];   /* param0: SO PIN(검증) */
      uint8_t  label[32];  /* param1: 새 토큰 라벨 (32바이트, 공백 패딩) */
  } CI_InitTokenReq;
  ```
- 응답 블록
  ```c
  typedef struct CI_InitTokenRsp { /* 없음 */ } CI_InitTokenRsp;
  ```
- 주의사항(호스트 STDLL 후속 처리)
  - `INIT_TOKEN` 성공 후 STDLL은 `CI_CMD_VD_TOKEN_INFO`로 **라벨을 다시 읽어와 요청 라벨과 정밀 검증**한다.
  - 일치하면 토큰 정체성을 `nv_token_data`에 캐시하고 `save_token_data()`로 영속화한 뒤, 사용한 **임시 SO PIN·라벨 버퍼를 즉시 0으로 소거(zeroization)** 한다.
  - 라벨이 불일치하면 `CKR_FUNCTION_FAILED`.

#### 6.3.6. CI_CMD_GET_UTC_TIME (0x0035)

- 기능
  토큰의 UTC 시각을 조회한다.
- 관련 호스트 API : `ncmp_admin_get_utc_time`
- 명령 블록
  ```c
  typedef struct CI_GetUtcTimeReq { /* 없음 */ } CI_GetUtcTimeReq;
  ```
- 응답 블록
  ```c
  typedef struct CI_GetUtcTimeRsp {
      uint8_t  utc[16];    /* param0: CK_TOKEN_INFO.utcTime ("YYYYMMDDhhmmssxx") */
  } CI_GetUtcTimeRsp;
  ```
- 주의사항
  - STDLL은 이 값을 `C_GetTokenInfo`의 `utcTime` 필드에 반영한다.

#### 6.3.7. CI_CMD_GET_TOKEN_PARAMS (0x0036)

- 기능
  토큰 라벨·시리얼·PIN 길이 범위를 조회한다.
- 관련 호스트 API : `ncmp_admin_get_token_params`
- 명령 블록
  ```c
  typedef struct CI_GetTokenParamsReq { /* 없음 */ } CI_GetTokenParamsReq;
  ```
- 응답 블록
  ```c
  typedef struct CI_GetTokenParamsRsp {
      uint8_t  label[32];   /* param0: 토큰 라벨 (NUL/공백 패딩) */
      uint8_t  serial[16];  /* param1: 시리얼 번호 (NUL/공백 패딩) */
      uint32_t min_pin_len; /* param2: ulMinPinLen (LE u32) */
      uint32_t max_pin_len; /* param3: ulMaxPinLen (LE u32) */
  } CI_GetTokenParamsRsp;
  ```

| 구분 | 파라미터 | 필드 | 크기 | 설명 |
|---|---|---|---|---|
| 응답 | param0 | label | 32 | 토큰 라벨 |
| 응답 | param1 | serial | 16 | 시리얼 번호 |
| 응답 | param2 | min_pin_len | 4 | ulMinPinLen |
| 응답 | param3 | max_pin_len | 4 | ulMaxPinLen |

- 주의사항
  - STDLL은 `ulMinPinLen`/`ulMaxPinLen`을 `C_GetTokenInfo`에 반영한다.

#### 6.3.8. CI_CMD_SET_UTC_TIME (0x0037)

- 기능
  토큰 클럭(UTC 시각)을 설정한다.
- 관련 호스트 API : `ncmp_admin_set_utc_time`
- 반환 값
  - CKR_OK
  - CKR_USER_NOT_LOGGED_IN
  - CKR_ARGUMENTS_BAD
- 명령 블록
  ```c
  typedef struct CI_SetUtcTimeReq {
      uint8_t  utc[16];    /* param0: 설정할 CK_TOKEN_INFO.utcTime ("YYYYMMDDhhmmssxx") */
  } CI_SetUtcTimeReq;
  ```
- 응답 블록
  ```c
  typedef struct CI_SetUtcTimeRsp { /* 없음 */ } CI_SetUtcTimeRsp;
  ```
- 주의사항
  - **SO 로그인 상태에서만** 허용된다(그 외 `CKR_USER_NOT_LOGGED_IN`).
  - `utc`는 정확히 16바이트여야 한다(그 외 `CKR_ARGUMENTS_BAD`).
  - 이후 `CI_CMD_GET_UTC_TIME`은 설정한 값을 그대로 되돌려준다.
  - PKCS#11에는 시각 설정용 표준 C_ 함수가 없어, 이 CI는 `ncmp_admin` 어댑터를 통한 관리 전용 경로다.

#### 6.3.9. CI_CMD_OPEN_SESSION (0x003A)

- 기능
  요청 프로세스의 `(pid, sid)` 쌍을 슬롯 내에서 유일한 **8비트 HSM SID(1~255)** 로
  매핑하여 세션을 연다. 토큰이 슬롯별 세션 테이블을 소유·관리하며, HSM SID는 중첩되지
  않는다. 같은 `(pid, sid)` 재요청은 **멱등**(동일 HSM SID 반환).
- 반환 값
  - CKR_OK
  - CKR_SESSION_COUNT (슬롯 세션 테이블이 255개로 가득 참)
  - CKR_ARGUMENTS_BAD
- 명령 블록
  ```c
  typedef struct CI_OpenSessionReq {
      uint32_t pid;    /* param0: 요청 프로세스 ID */
      uint32_t sid;    /* param1: 호출자(STDLL/앱) 세션 ID */
      uint32_t flags;  /* param2: 세션 flags(CKF_RW_SESSION 등), 선택 */
  } CI_OpenSessionReq;
  ```
- 응답 블록
  ```c
  typedef struct CI_OpenSessionRsp {
      uint32_t hsm_sid; /* param0: 발급된 HSM SID(1..255) */
  } CI_OpenSessionRsp;
  ```
- 주의사항
  - 발급된 `hsm_sid`는 이후 그 세션의 모든 명령에서 와이어 헤더 `session_id`로 사용한다.
  - `(pid 32비트 + sid 32비트) → hsm_sid 8비트` 매핑 규칙·충돌 회피는
    [`session-id-mapping.md`](session-id-mapping.md) 참조.
  - mock 구현은 테이블 인덱스+1을 HSM SID로 사용해 슬롯 내 유일성을 보장한다.

#### 6.3.10. CI_CMD_CLOSE_SESSION (0x003B)

- 기능
  HSM SID로 식별되는 세션 매핑을 해제한다.
- 반환 값
  - CKR_OK
  - CKR_SESSION_HANDLE_INVALID (존재하지 않는/이미 닫힌 HSM SID)
  - CKR_ARGUMENTS_BAD
- 명령 블록
  ```c
  typedef struct CI_CloseSessionReq {
      uint32_t hsm_sid; /* param0: 닫을 HSM SID(1..255) */
  } CI_CloseSessionReq;
  ```
- 응답 블록
  ```c
  typedef struct CI_CloseSessionRsp { /* 없음 */ } CI_CloseSessionRsp;
  ```
- 주의사항
  - 닫은 HSM SID 슬롯은 재사용 가능해진다(이후 OPEN_SESSION이 재할당 가능).
  - 표준 PKCS#11 `C_OpenSession`/`C_CloseSession`을 이 CI로 포워딩하려면 opencryptoki
    `token_specific`에 세션 훅이 필요한데 현재 SPI에는 없다(구조적 제약).
    → [`app-stdll-path-design.md`](app-stdll-path-design.md) 참조.

### 6.4. 객체 관리 기능 블록

보안키 토큰으로서 키 객체를 토큰에 등록하고 속성 변경을 검증한다.

#### 6.4.1. CI_CMD_OBJECT_ADD (0x0038)

- 기능
  `C_CreateObject`로 임포트된 **키 객체**를 토큰에 등록한다(`t_object_add`).
- 관련 호스트 API : `ncmp_object_add`
- 반환 값
  - CKR_OK
  - CKR_TEMPLATE_INCOMPLETE
  - CKR_ARGUMENTS_BAD
- 명령 블록
  ```c
  typedef struct CI_ObjectAddReq {
      uint32_t obj_class;  /* param0: CKO_* */
      uint32_t key_type;   /* param1: CKK_* */
      uint8_t  value[];    /* param2: 키 데이터 (CKA_VALUE) */
  } CI_ObjectAddReq;
  ```
- 응답 블록
  ```c
  typedef struct CI_ObjectAddRsp { /* 없음 */ } CI_ObjectAddRsp;
  ```
- 주의사항
  - 비키 객체(데이터·인증서) 및 키 데이터가 없는 객체는 전달하지 않고 공통 계층이 로컬 처리한다.
  - 객체 저장·핸들·열거·삭제는 공통 계층 전용이다.

#### 6.4.2. CI_CMD_OBJECT_SET_ATTR (0x0039)

- 기능
  `C_SetAttributeValue`/`C_CopyObject`로 키 객체의 속성이 바뀌면 변경분을 토큰에 전달해 검증한다(`t_set_attribute_values`).
- 관련 호스트 API : `ncmp_object_set_attrs`
- 반환 값
  - CKR_OK
  - CKR_ATTRIBUTE_VALUE_INVALID
- 명령 블록
  ```c
  typedef struct CI_ObjectSetAttrReq {
      uint32_t obj_class;  /* param0: CKO_* */
      uint32_t key_type;   /* param1: CKK_* */
      uint8_t  attrs[];    /* param2: count(u32) 다음 count개의 {type(u32)|len(u32)|value[len]} */
  } CI_ObjectSetAttrReq;
  ```
- 응답 블록
  ```c
  typedef struct CI_ObjectSetAttrRsp { /* 없음 */ } CI_ObjectSetAttrRsp;
  ```
- 주의사항
  - STDLL은 전달 후 직렬화 버퍼를 소거한다.

### 6.5. 포스트양자 기능 블록 (PKCS#11 3.2)

키는 불투명 블롭으로 전달되며, **개인 블롭은 공개 블롭을 접두어로 포함**한다. 파라미터 세트 값은 4.2절을 따른다.

#### 6.5.1. CI_CMD_MLDSA_KEYGEN (0x0050)

- 기능
  ML-DSA 키 쌍을 생성한다.
- 관련 호스트 API : `ncmp_crypto_mldsa_keygen`
- 명령 블록
  ```c
  typedef struct CI_MlDsaKeygenReq {
      uint32_t param_set;  /* param0: CKP_ML_DSA_* (강도) */
      uint32_t pub_len;    /* param1: 생성할 공개 블롭 길이 */
      uint32_t priv_len;   /* param2: 생성할 개인 블롭 길이 (> pub_len) */
  } CI_MlDsaKeygenReq;
  ```
- 응답 블록
  ```c
  typedef struct CI_MlDsaKeygenRsp {
      uint8_t  pub[];      /* param0: 공개 키 블롭 (pub_len) */
      uint8_t  priv[];     /* param1: 개인 키 블롭 (priv_len, 앞 pub_len은 pub과 동일) */
  } CI_MlDsaKeygenRsp;
  ```

#### 6.5.2. CI_CMD_MLDSA_SIGN (0x0051)

- 기능
  ML-DSA 서명을 생성한다.
- 관련 호스트 API : `ncmp_crypto_mldsa_sign`
- 명령 블록
  ```c
  typedef struct CI_MlDsaSignReq {
      uint32_t param_set;  /* param0: 강도 */
      uint32_t pub_len;    /* param1: 개인 블롭 내 공개 접두어 길이(폴딩 기준) */
      uint32_t sig_len;    /* param2: 생성할 서명 길이 */
      uint8_t  priv[];     /* param3: 개인 키 블롭 */
      uint8_t  data[];     /* param4: 서명 대상 메시지 */
  } CI_MlDsaSignReq;
  ```
- 응답 블록
  ```c
  typedef struct CI_MlDsaSignRsp {
      uint8_t  sig[];      /* param0: ML-DSA 서명 (sig_len) */
  } CI_MlDsaSignRsp;
  ```

#### 6.5.3. CI_CMD_MLDSA_VERIFY (0x0052)

- 기능
  ML-DSA 서명을 검증한다.
- 관련 호스트 API : `ncmp_crypto_mldsa_verify`
- 반환 값
  - CKR_OK
  - CKR_SIGNATURE_INVALID
- 명령 블록
  ```c
  typedef struct CI_MlDsaVerifyReq {
      uint32_t param_set;  /* param0: 강도 */
      uint8_t  pub[];      /* param1: 공개 키 블롭 */
      uint8_t  data[];     /* param2: 원본 메시지 */
      uint8_t  sig[];      /* param3: 대조할 서명 */
  } CI_MlDsaVerifyReq;
  ```
- 응답 블록
  ```c
  typedef struct CI_MlDsaVerifyRsp { /* 없음 */ } CI_MlDsaVerifyRsp;
  ```

#### 6.5.4. CI_CMD_MLKEM_KEYGEN (0x0053)

- 기능
  ML-KEM 키 쌍을 생성한다.
- 관련 호스트 API : `ncmp_crypto_mlkem_keygen`
- 명령 블록
  ```c
  typedef struct CI_MlKemKeygenReq {
      uint32_t param_set;  /* param0: CKP_ML_KEM_* (강도) */
      uint32_t pub_len;    /* param1: 공개 블롭 길이(pk_len) */
      uint32_t priv_len;   /* param2: 개인 블롭 길이(sk_len, > pub_len) */
  } CI_MlKemKeygenReq;
  ```
- 응답 블록
  ```c
  typedef struct CI_MlKemKeygenRsp {
      uint8_t  pub[];      /* param0: 공개 키 블롭 */
      uint8_t  priv[];     /* param1: 개인 키 블롭 (앞 pub_len은 pub과 동일) */
  } CI_MlKemKeygenRsp;
  ```

#### 6.5.5. CI_CMD_MLKEM_ENCAPS (0x0054)

- 기능
  ML-KEM 캡슐화를 수행한다.
- 관련 호스트 API : `ncmp_crypto_mlkem_encaps`
- 명령 블록
  ```c
  typedef struct CI_MlKemEncapsReq {
      uint32_t param_set;  /* param0: 강도 */
      uint32_t ct_len;     /* param1: 생성할 암호문 길이 */
      uint32_t ss_len;     /* param2: 공유 비밀 길이 (ML-KEM은 32) */
      uint8_t  pub[];      /* param3: 상대 공개 키 블롭 */
  } CI_MlKemEncapsReq;
  ```
- 응답 블록
  ```c
  typedef struct CI_MlKemEncapsRsp {
      uint8_t  ct[];       /* param0: 암호문(캡슐) (ct_len) */
      uint8_t  ss[];       /* param1: 공유 비밀 (ss_len) */
  } CI_MlKemEncapsRsp;
  ```

#### 6.5.6. CI_CMD_MLKEM_DECAPS (0x0055)

- 기능
  ML-KEM 역캡슐화를 수행하여 공유 비밀을 복원한다.
- 관련 호스트 API : `ncmp_crypto_mlkem_decaps`
- 명령 블록
  ```c
  typedef struct CI_MlKemDecapsReq {
      uint32_t param_set;  /* param0: 강도 */
      uint32_t pub_len;    /* param1: 개인 블롭 내 공개 접두어 길이 */
      uint32_t ss_len;     /* param2: 공유 비밀 길이 */
      uint8_t  priv[];     /* param3: 자신의 개인 키 블롭 */
      uint8_t  ct[];       /* param4: 캡슐화된 암호문 */
  } CI_MlKemDecapsReq;
  ```
- 응답 블록
  ```c
  typedef struct CI_MlKemDecapsRsp {
      uint8_t  ss[];       /* param0: 복원된 공유 비밀 (encaps 결과와 동일) */
  } CI_MlKemDecapsRsp;
  ```

### 6.6. 벤더 정의 기능 블록 (datapath / 디바이스 상태)

벤더 스크래치 RAM 크기는 `NCMP_VD_MEM_SIZE`(4 KB)이다. 에코/loopback은 전용 opcode 없이 `CI_CMD_NOP`(0x0000)로 처리한다.

#### 6.6.1. CI_CMD_VD_MEM_WRITE (0x0101)

- 기능
  스크래치 RAM에 데이터를 기록한다.
- 반환 값 : CKR_OK, CKR_DEVICE_MEMORY
- 명령 블록
  ```c
  typedef struct CI_VdMemWriteReq {
      uint32_t addr;    /* param0: 스크래치 RAM 오프셋 */
      uint8_t  bytes[]; /* param1: 기록할 데이터 (addr+len ≤ 4 KB) */
  } CI_VdMemWriteReq;
  ```
- 응답 블록
  ```c
  typedef struct CI_VdMemWriteRsp { /* 없음 */ } CI_VdMemWriteRsp;
  ```

#### 6.6.2. CI_CMD_VD_MEM_READ (0x0102)

- 기능
  스크래치 RAM에서 데이터를 읽는다.
- 명령 블록
  ```c
  typedef struct CI_VdMemReadReq {
      uint32_t addr;    /* param0: 읽기 시작 오프셋 */
      uint32_t len;     /* param1: 읽을 바이트 수 */
  } CI_VdMemReadReq;
  ```
- 응답 블록
  ```c
  typedef struct CI_VdMemReadRsp {
      uint8_t bytes[];  /* param0: 읽은 데이터 (len) */
  } CI_VdMemReadRsp;
  ```

#### 6.6.3. CI_CMD_VD_PING (0x0103)

- 기능
  토큰 epoch 카운터를 조회한다.
- 명령 블록
  ```c
  typedef struct CI_VdPingReq { /* 없음 */ } CI_VdPingReq;
  ```
- 응답 블록
  ```c
  typedef struct CI_VdPingRsp {
      uint32_t epoch;   /* param0: 토큰 epoch 카운터 */
  } CI_VdPingRsp;
  ```

#### 6.6.4. CI_CMD_VD_SELFTEST (0x0104)

- 기능
  토큰 서브시스템 자가 시험을 수행한다.
- 명령 블록
  ```c
  typedef struct CI_VdSelftestReq { /* 없음 */ } CI_VdSelftestReq;
  ```
- 응답 블록
  ```c
  typedef struct CI_VdSelftestRsp {
      uint32_t status;  /* param0: 0 = 모든 서브시스템 정상 (epoch 증가) */
  } CI_VdSelftestRsp;
  ```

#### 6.6.5. CI_CMD_VD_FW_INFO (0x0105)

- 기능
  펌웨어 버전 정보를 조회한다.
- 명령 블록
  ```c
  typedef struct CI_VdFwInfoReq { /* 없음 */ } CI_VdFwInfoReq;
  ```
- 응답 블록
  ```c
  typedef struct CI_VdFwInfoRsp {  /* param0 = 아래 4개 LE u32 (16바이트) */
      uint32_t major;   /* 주 버전 */
      uint32_t minor;   /* 부 버전 */
      uint32_t patch;   /* 패치 */
      uint32_t build;   /* 빌드 태그 (예: 0x0FC3) */
  } CI_VdFwInfoRsp;
  ```

#### 6.6.6. CI_CMD_VD_MEM_FILL (0x0106)

- 기능
  스크래치 RAM의 지정 영역을 한 바이트 값으로 채운다.
- 반환 값 : CKR_OK, CKR_DEVICE_MEMORY
- 명령 블록
  ```c
  typedef struct CI_VdMemFillReq {
      uint32_t addr;    /* param0: 시작 오프셋 */
      uint32_t len;     /* param1: 채울 길이 */
      uint8_t  value;   /* param2: 채울 바이트 값 (1바이트) */
  } CI_VdMemFillReq;
  ```
- 응답 블록
  ```c
  typedef struct CI_VdMemFillRsp { /* 없음 */ } CI_VdMemFillRsp;
  ```

#### 6.6.7. CI_CMD_VD_MEM_CRC (0x0107)

- 기능
  스크래치 RAM 지정 영역의 CRC-32를 계산한다.
- 명령 블록
  ```c
  typedef struct CI_VdMemCrcReq {
      uint32_t addr;    /* param0: 시작 오프셋 */
      uint32_t len;     /* param1: 길이 */
  } CI_VdMemCrcReq;
  ```
- 응답 블록
  ```c
  typedef struct CI_VdMemCrcRsp {
      uint32_t crc32;   /* param0: CRC-32 (0xEDB88320 다항식) */
  } CI_VdMemCrcRsp;
  ```

#### 6.6.8. CI_CMD_VD_TOKEN_INFO (0x0108)

- 기능
  토큰 정체성(라벨/시리얼/제조사/모델/HW·FW 버전/상태 플래그)을 조회한다.
- 관련 호스트 API : `ncmp_admin_token_info`
- 명령 블록
  ```c
  typedef struct CI_VdTokenInfoReq { /* 없음 */ } CI_VdTokenInfoReq;
  ```
- 응답 블록
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

  typedef struct CI_VdTokenInfoRsp { CI_TokenIdentity identity; /* param0 */ } CI_VdTokenInfoRsp;
  ```

| 오프셋 | 필드 | 크기(byte) | 설명 |
|---|---|---|---|
| 0 | label | 32 | 토큰 라벨 |
| 32 | serial | 16 | 시리얼 번호 |
| 48 | manufacturer | 32 | 제조사 |
| 80 | model | 16 | 모델 |
| 96 | hw_major | 1 | 하드웨어 주 버전 |
| 97 | hw_minor | 1 | 하드웨어 부 버전 |
| 98 | fw_major | 1 | 펌웨어 주 버전 |
| 99 | fw_minor | 1 | 펌웨어 부 버전 |
| 100 | flags | 4 | 벤더 상태 플래그 |

[표 6] 토큰 정체성 블롭 구조 (총 104바이트)

---

## 7. 호스트 어댑터 대응 (참고)

| CI 명령 그룹 | 호스트 어댑터 | 파일 |
|---|---|---|
| RNG·DIGEST·AES(GCM·CTR)·SHAKE·PQC(ML-DSA·ML-KEM) | `ncmp_crypto_*` | `ncmp/stdll/ncmp_crypto.c` |
| LOGIN·PIN·TOKEN_INFO·GET/SET_UTC_TIME·GET_TOKEN_PARAMS | `ncmp_admin_*` | `ncmp/stdll/ncmp_admin.c` |
| OBJECT_ADD·OBJECT_SET_ATTR | `ncmp_object_*` | `ncmp/stdll/ncmp_object.c` |
| 전송 프리미티브(단일/다중 param) | `ncmp_client_command[_mp]` | `ncmp/stdll/ncmp_client.c` |
| 프레임 인코딩/디코딩 | `ncmp_wire_encode/decode`, `ncmp_msg_*` | `ncmp/common/ncmp_wire.c` |
| 참조 구현(디바이스 측) | opcode 실행 | `ncmp/mock/mcu_scheduler.c` |

[표 7] CI 명령 그룹별 호스트 어댑터

- mock 토큰은 결정론적 스텁으로 위 레이아웃을 그대로 구현한다. 실제 FX3 펌웨어는 동일한 CI 프레임/파라미터 규약을 따르되 진짜 암호 연산을 수행한다.

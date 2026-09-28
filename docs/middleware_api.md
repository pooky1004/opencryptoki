# NCMP 미들웨어 API — `ncmp/stdll/*.c` 함수 레퍼런스

`ncmp/stdll/`의 모든 `*.c` 파일에 정의된 함수 각각의 **기능 / 원형 및 인자 /
반환값**을 정리한다. STDLL 미들웨어는 두 계층으로 나뉜다.

- **전송 계층**(`ncmp_client.c`, `ncmp_session.c`, `ncmp_ckr.c`): 반환형은 `int`
  이며 `NCMP_OK`(0) 또는 음수 `NCMP_ERR_*`를 돌려준다(토큰의 상태는 out 인자로 전달).
- **마샬링 어댑터**(`ncmp_admin.c`, `ncmp_crypto.c`, `ncmp_object.c`): 반환형은
  `unsigned long`(PKCS#11 `CK_RV` 규약)이며 값은 아래 세 갈래다.

> **어댑터 공통 반환값 규약** (개별 함수의 "반환값"은 이 규약 위에 함수 고유 값만
> 추가로 명시한다)
> 1. **어댑터 자체 검증 실패**: `NCMP_CKR_ARGUMENTS_BAD` 등 함수가 직접 반환.
> 2. **라운드트립 성공 + 토큰이 거부**: 토큰의 `ack`(그대로 `CKR_*`)를 반환.
> 3. **전송 실패**: `ncmp_err_to_ckr()`로 매핑된 `CKR_*`
>    (`CKR_TOKEN_NOT_PRESENT`/`CKR_DEVICE_ERROR`/`CKR_FUNCTION_CANCELED`/
>    `CKR_DEVICE_MEMORY`/`CKR_ARGUMENTS_BAD`/`CKR_GENERAL_ERROR`).

관련: [`command-interface.md`](command-interface.md)(각 opcode의 request/response),
[`stdll-call-flow.md`](stdll-call-flow.md)(호출 흐름), [`architecture.md`](architecture.md).

---

## 1. `ncmp_ckr.c` — 내부 오류 → PKCS#11 반환값 매핑

### 1.1 `ncmp_err_to_ckr`
- **기능**: 내부 전송 오류 코드(`NCMP_ERR_*`, 음수)를 PKCS#11 `CK_RV`(`CKR_*`)로
  변환한다. STDLL 경계에서 전송 실패를 표준 반환값으로 바꾸는 단일 지점이다(토큰의
  `ack`는 이미 `CKR_*`이므로 이 함수를 거치지 않는다).
- **원형 및 인자**:
  ```c
  unsigned long ncmp_err_to_ckr(
      int ncmp_rc   // NCMP_OK 또는 NCMP_ERR_* 코드
  );
  ```
- **반환값**: `NCMP_CKR_OK`, `NCMP_CKR_TOKEN_NOT_PRESENT`,
  `NCMP_CKR_FUNCTION_CANCELED`, `NCMP_CKR_SESSION_COUNT`,
  `NCMP_CKR_ARGUMENTS_BAD`, `NCMP_CKR_DEVICE_MEMORY`, `NCMP_CKR_DEVICE_ERROR`,
  `NCMP_CKR_GENERAL_ERROR`.

---

## 2. `ncmp_client.c` — 데몬 IPC/SHM 전송

### 2.1 `ncmp_client_init`
- **기능**: ncmpd에 연결(IPC HELLO/ATTACH)하고 공유메모리를 부착하여 클라이언트
  핸들을 초기화한다.
- **원형 및 인자**:
  ```c
  int ncmp_client_init(
      ncmp_client_t *c,       // 초기화할 클라이언트 핸들
      const char *sock_path   // IPC 소켓 경로, NULL이면 기본값(NCMP_IPC_SOCK_PATH)
  );
  ```
- **반환값**: `NCMP_OK`, `NCMP_ERR_INVAL`(c==NULL), `NCMP_ERR_NODAEMON`(데몬 부재),
  `NCMP_ERR_VERSION`(IPC/SHM 버전 불일치), 그 외 SHM 부착 오류(`NCMP_ERR_*`).

### 2.2 `ncmp_client_exec`
- **기능**: 인코딩된 요청 메시지를 대상 슬롯 링에 적재(FREE→CLAIMED→POSTED)하고
  응답(DONE)을 대기한다. 모든 상위 명령의 공통 하단 경로.
- **원형 및 인자**:
  ```c
  int ncmp_client_exec(
      ncmp_client_t *c,        // 초기화된 클라이언트 핸들
      uint32_t slot_id,        // 대상 슬롯
      const NCMP_Message *req, // 전송할 요청 메시지
      NCMP_Message *rsp,       // 응답 수신(rsp->header.ack=토큰 CKR_*)
      uint64_t spin_budget     // 타임아웃까지의 스핀 예산(0=무한)
  );
  ```
- **반환값**: `NCMP_OK`, `NCMP_ERR_INVAL`(인자/슬롯 범위), `NCMP_ERR_NODAEMON`
  (슬롯이 온라인 마스크에 없음), 적재 오류(`NCMP_ERR_FULL`/`NCMP_ERR_NOSPACE`/
  `NCMP_ERR_STATE`), `NCMP_ERR_TIMEOUT`(응답 미수신).

### 2.3 `ncmp_client_command`
- **기능**: 단일 파라미터(param0)를 opcode에 실어 한 번 왕복하고, 응답 param0와
  토큰 ack를 돌려주는 전송 프리미티브. 시퀀스 id는 내부에서 원자 증가로 부여.
- **원형 및 인자**:
  ```c
  int ncmp_client_command(
      ncmp_client_t *c,     // 초기화된 클라이언트 핸들
      uint32_t slot_id,     // 대상 슬롯
      uint32_t opcode,      // 오퍼레이션 opcode(하위16b) + 플래그(상위16b)
      const uint8_t *in,    // 요청 바이트(in_len==0이면 NULL 허용)
      uint32_t in_len,      // 요청 길이(<= NCMP_MAX_PARAM_SIZE)
      uint8_t *out,         // 응답 param0 수신 버퍼
      uint32_t out_cap,     // out 용량
      uint32_t *out_len,    // 응답 param0 길이 수신(NULL 허용)
      uint32_t *out_ack     // 토큰 CKR_* 수신(NULL 허용)
  );
  ```
- **반환값**: `NCMP_OK`, `NCMP_ERR_INVAL`(인자 불일치), `NCMP_ERR_PARAM_SIZE`
  (in_len 초과), 그 외 `ncmp_client_exec`의 오류.

### 2.4 `ncmp_client_command_mp`
- **기능**: 다중 파라미터를 하나의 요청으로 팩하여 왕복하고, 디코드된 응답 메시지를
  돌려주는 전송 프리미티브(다중 출력은 `ncmp_msg_param()`으로 추출).
- **원형 및 인자**:
  ```c
  int ncmp_client_command_mp(
      ncmp_client_t *c,          // 초기화된 클라이언트 핸들
      uint32_t slot_id,          // 대상 슬롯
      uint32_t opcode,           // 오퍼레이션 opcode + 플래그
      const uint8_t *const in[], // n_in개 입력 파라미터 포인터 배열
      const uint32_t in_len[],   // n_in개 입력 파라미터 길이 배열
      int n_in,                  // 입력 파라미터 수(1..NCMP_MAX_PARAM_COUNT)
      uint8_t *out_payload,      // 응답 파라미터 바이트 수신 버퍼
      uint32_t out_cap,          // out_payload 용량
      NCMP_Message *out_msg      // 디코드된 응답 메시지 수신
  );
  ```
- **반환값**: `NCMP_OK`, `NCMP_ERR_INVAL`(인자/n_in 범위), `NCMP_ERR_NOSPACE`
  (스크래치 할당 실패), 팩 오류(`NCMP_ERR_PARAM_SIZE`/`NCMP_ERR_PAYLOAD`), 그 외
  `ncmp_client_exec`의 오류.

### 2.5 `ncmp_client_fini`
- **기능**: 공유메모리 부착 해제 및 제어 소켓 닫기(부분 초기화 상태도 안전).
- **원형 및 인자**:
  ```c
  int ncmp_client_fini(
      ncmp_client_t *c   // 클라이언트 핸들(부분 초기화 허용)
  );
  ```
- **반환값**: `NCMP_OK`, `NCMP_ERR_INVAL`(c==NULL).

---

## 3. `ncmp_session.c` — 슬롯 세션 카운터

### 3.1 `ncmp_session_open`
- **기능**: 슬롯의 `sess_lock`(강건·프로세스공유 뮤텍스) 하에서 세션 1개를 예약한다.
  `PKCS11_MAX_SESSION_PER_SLOT` 상한을 프로세스 간 원자적으로 검사한다.
- **원형 및 인자**:
  ```c
  int ncmp_session_open(
      NCMP_Slot *slot   // 대상 슬롯(SHM)
  );
  ```
- **반환값**: `NCMP_OK`, `NCMP_ERR_INVAL`(slot==NULL), `NCMP_ERR_FULL`(슬롯당 상한
  도달; STDLL이 `CKR_SESSION_COUNT_EXCEEDED`로 매핑), `NCMP_ERR_MUTEX`(복구 불가
  잠금 실패). (`NCMP_MUTEX_RECOVERED`는 내부에서 처리)

### 3.2 `ncmp_session_close`
- **기능**: 슬롯의 `sess_lock` 하에서 세션 1개를 해제한다(0 미만으로 내려가지 않음).
- **원형 및 인자**:
  ```c
  int ncmp_session_close(
      NCMP_Slot *slot   // 대상 슬롯(SHM)
  );
  ```
- **반환값**: `NCMP_OK`, `NCMP_ERR_INVAL`(slot==NULL), `NCMP_ERR_MUTEX`.

---

## 4. `ncmp_admin.c` — 토큰 관리(정체성·로그인·PIN·시각) 어댑터

### 4.1 `admin_cmd` (static, 내부)
- **기능**: 단일 파라미터 관리 명령을 전송하고 토큰 상태를 표면화하는 내부 헬퍼.
- **원형 및 인자**:
  ```c
  static unsigned long admin_cmd(
      ncmp_client_t *c, uint32_t slot, uint32_t opcode,
      const uint8_t *in, uint32_t in_len,
      uint8_t *out, uint32_t out_cap, uint32_t *out_len
  );
  ```
- **반환값**: `NCMP_CKR_OK` / 토큰 ack / 전송오류 매핑(공통 규약).

### 4.2 `admin_cmd_mp` (static, 내부)
- **기능**: 다중 파라미터 관리 명령을 전송하고 토큰 상태를 표면화하는 내부 헬퍼.
- **원형 및 인자**:
  ```c
  static unsigned long admin_cmd_mp(
      ncmp_client_t *c, uint32_t slot, uint32_t opcode,
      const uint8_t *const parts[], const uint32_t lens[], int n
  );
  ```
- **반환값**: `NCMP_CKR_OK` / 토큰 ack / 전송오류 매핑(공통 규약).

### 4.3 `ncmp_admin_token_info`
- **기능**: 토큰 정체성(라벨/시리얼/제조사/모델/HW·FW 버전)을 조회한다
  (`NCMP_CMD_VD_TOKEN_INFO` → 블롭 디코드).
- **원형 및 인자**:
  ```c
  unsigned long ncmp_admin_token_info(
      ncmp_client_t *c,        // 초기화된 클라이언트 핸들
      uint32_t slot,           // 물리 슬롯 인덱스
      NCMP_TokenIdentity *out  // 성공 시 디코드된 정체성
  );
  ```
- **반환값**: `NCMP_CKR_OK`, `NCMP_CKR_ARGUMENTS_BAD`(out==NULL),
  `NCMP_CKR_FUNCTION_FAILED`(블롭 언팩 실패), 토큰 ack, 전송오류 매핑.

### 4.4 `ncmp_admin_get_utc_time`
- **기능**: 토큰의 현재 UTC 시각(`CK_TOKEN_INFO.utcTime`, 16바이트)을 조회한다.
- **원형 및 인자**:
  ```c
  unsigned long ncmp_admin_get_utc_time(
      ncmp_client_t *c,   // 초기화된 클라이언트 핸들
      uint32_t slot,      // 물리 슬롯 인덱스
      uint8_t *out        // NCMP_TOKEN_UTC_LEN(16)바이트 수신("YYYYMMDDhhmmssxx")
  );
  ```
- **반환값**: `NCMP_CKR_OK`, `NCMP_CKR_ARGUMENTS_BAD`(out==NULL),
  `NCMP_CKR_FUNCTION_FAILED`(응답 길이 불일치), 토큰 ack, 전송오류 매핑.

### 4.5 `ncmp_admin_set_utc_time`
- **기능**: 토큰의 UTC 시각을 설정한다(SO 전용, 16바이트).
- **원형 및 인자**:
  ```c
  unsigned long ncmp_admin_set_utc_time(
      ncmp_client_t *c,    // 초기화된 클라이언트 핸들
      uint32_t slot,       // 물리 슬롯 인덱스
      const uint8_t *utc   // NCMP_TOKEN_UTC_LEN(16)바이트 시각
  );
  ```
- **반환값**: `NCMP_CKR_OK`, `NCMP_CKR_ARGUMENTS_BAD`(utc==NULL), 토큰 ack
  (`CKR_USER_NOT_LOGGED_IN`/`CKR_ARGUMENTS_BAD`), 전송오류 매핑.

### 4.6 `ncmp_admin_get_token_params`
- **기능**: 토큰 라벨·시리얼·PIN 길이 범위(min/max)를 조회한다
  (`NCMP_CMD_GET_TOKEN_PARAMS`, 응답 4파라미터 디코드). 각 out 인자는 NULL로 생략 가능.
- **원형 및 인자**:
  ```c
  unsigned long ncmp_admin_get_token_params(
      ncmp_client_t *c,     // 초기화된 클라이언트 핸들
      uint32_t slot,        // 물리 슬롯 인덱스
      uint8_t *label,       // NCMP_TI_LABEL_LEN(32)바이트 수신(NULL이면 생략)
      uint8_t *serial,      // NCMP_TI_SERIAL_LEN(16)바이트 수신(NULL이면 생략)
      uint32_t *min_pin,    // ulMinPinLen 수신(NULL이면 생략)
      uint32_t *max_pin     // ulMaxPinLen 수신(NULL이면 생략)
  );
  ```
- **반환값**: `NCMP_CKR_OK`, `NCMP_CKR_FUNCTION_FAILED`(응답 파라미터 형식/길이
  불일치), 토큰 ack, 전송오류 매핑.

### 4.7 `ncmp_admin_login`
- **기능**: 로그인(PIN 검증)을 토큰에 전달한다. 역할(user_type) 외에 플래그
  (보호 인증 경로·문맥 특정 재인증)를 함께 실어보낸다(param0=user_type, param1=flags,
  param2=pin).
- **원형 및 인자**:
  ```c
  unsigned long ncmp_admin_login(
      ncmp_client_t *c,     // 초기화된 클라이언트 핸들
      uint32_t slot,        // 물리 슬롯 인덱스
      uint32_t user_type,   // NCMP_CKU_SO / USER / CONTEXT_SPECIFIC
      uint32_t flags,       // NCMP_LOGIN_FLAG_*(protected-auth / context)
      const uint8_t *pin,   // PIN 바이트(pin_len==0이면 NULL 허용)
      uint32_t pin_len      // PIN 길이
  );
  ```
- **반환값**: `NCMP_CKR_OK`, `NCMP_CKR_PIN_LEN_RANGE`(pin_len>NCMP_MAX_PARAM_SIZE),
  토큰 ack(`CKR_PIN_INCORRECT`/`CKR_USER_TYPE_INVALID`/
  `CKR_USER_ALREADY_LOGGED_IN`/`CKR_USER_NOT_LOGGED_IN` 등), 전송오류 매핑.

### 4.8 `ncmp_admin_logout`
- **기능**: 로그아웃을 토큰에 전달한다.
- **원형 및 인자**:
  ```c
  unsigned long ncmp_admin_logout(
      ncmp_client_t *c,   // 초기화된 클라이언트 핸들
      uint32_t slot       // 물리 슬롯 인덱스
  );
  ```
- **반환값**: `NCMP_CKR_OK` / 토큰 ack / 전송오류 매핑.

### 4.9 `ncmp_admin_init_pin`
- **기능**: SO가 (신규) 사용자 PIN을 설정한다(`NCMP_CMD_INIT_PIN`).
- **원형 및 인자**:
  ```c
  unsigned long ncmp_admin_init_pin(
      ncmp_client_t *c,     // 초기화된 클라이언트 핸들
      uint32_t slot,        // 물리 슬롯 인덱스
      const uint8_t *pin,   // 신규 사용자 PIN
      uint32_t pin_len      // PIN 길이
  );
  ```
- **반환값**: `NCMP_CKR_OK`, `NCMP_CKR_PIN_LEN_RANGE`(pin_len 초과), 토큰 ack,
  전송오류 매핑.

### 4.10 `ncmp_admin_set_pin`
- **기능**: 현재 사용자의 PIN을 변경한다(old→new, `NCMP_CMD_SET_PIN`).
- **원형 및 인자**:
  ```c
  unsigned long ncmp_admin_set_pin(
      ncmp_client_t *c,        // 초기화된 클라이언트 핸들
      uint32_t slot,           // 물리 슬롯 인덱스
      const uint8_t *old_pin,  // 기존 PIN
      uint32_t old_len,        // 기존 PIN 길이
      const uint8_t *new_pin,  // 신규 PIN
      uint32_t new_len         // 신규 PIN 길이
  );
  ```
- **반환값**: `NCMP_CKR_OK`, `NCMP_CKR_PIN_LEN_RANGE`(old_len/new_len 초과), 토큰
  ack(`CKR_PIN_INCORRECT` 등), 전송오류 매핑.

### 4.11 `ncmp_admin_init_token`
- **기능**: 토큰을 초기화한다(SO PIN 검증 + 라벨 설정). 라벨은 고정폭
  (`NCMP_TI_LABEL_LEN`)으로 공백 우측 패딩되어 전송된다.
- **원형 및 인자**:
  ```c
  unsigned long ncmp_admin_init_token(
      ncmp_client_t *c,       // 초기화된 클라이언트 핸들
      uint32_t slot,          // 물리 슬롯 인덱스
      const uint8_t *so_pin,  // SO PIN 바이트
      uint32_t so_len,        // SO PIN 길이
      const char *label       // 토큰 라벨(고정폭으로 패딩되어 전송)
  );
  ```
- **반환값**: `NCMP_CKR_OK`, `NCMP_CKR_PIN_LEN_RANGE`(so_len 초과), 토큰 ack
  (`CKR_PIN_INCORRECT` 등), 전송오류 매핑.

---

## 5. `ncmp_crypto.c` — 암호 연산 마샬링 어댑터

### 5.1 `crypto_cmd` (static, 내부)
- **기능**: 단일 파라미터 암호 명령을 전송하고 토큰 상태를 표면화하는 내부 헬퍼.
- **원형 및 인자**:
  ```c
  static unsigned long crypto_cmd(
      ncmp_client_t *c, uint32_t slot, uint32_t opcode,
      const uint8_t *in, uint32_t in_len,
      uint8_t *out, uint32_t out_cap, uint32_t *out_len
  );
  ```
- **반환값**: `NCMP_CKR_OK` / 토큰 ack / 전송오류 매핑.

### 5.2 `crypto_cmd_mp` (static, 내부)
- **기능**: 다중 파라미터 암호 명령을 전송하고 디코드된 응답을 `rsp`로 돌려주는 내부
  헬퍼(다중 출력 지원).
- **원형 및 인자**:
  ```c
  static unsigned long crypto_cmd_mp(
      ncmp_client_t *c, uint32_t slot, uint32_t opcode,
      const uint8_t *const parts[], const uint32_t lens[], int n,
      uint8_t *out, uint32_t out_cap, NCMP_Message *rsp
  );
  ```
- **반환값**: `NCMP_CKR_OK` / 토큰 ack / 전송오류 매핑.

### 5.3 `ncmp_crypto_rng`
- **기능**: 난수 `out_len`바이트를 요청한다.
- **원형 및 인자**:
  ```c
  unsigned long ncmp_crypto_rng(
      ncmp_client_t *c,   // 초기화된 클라이언트 핸들
      uint32_t slot,      // 물리 슬롯 인덱스
      uint8_t *out,       // 난수 수신 버퍼
      uint32_t out_len    // 요청 바이트 수(<= NCMP_MAX_PARAM_SIZE)
  );
  ```
- **반환값**: `NCMP_CKR_OK`, `NCMP_CKR_ARGUMENTS_BAD`(out==NULL/0/초과),
  `NCMP_CKR_FUNCTION_FAILED`(응답 길이 부족), 토큰 ack, 전송오류 매핑.

### 5.4 `ncmp_crypto_digest`
- **기능**: `mech` 하의 단발(one-shot) 다이제스트. 요청 param0=`[mech|data]`.
- **원형 및 인자**:
  ```c
  unsigned long ncmp_crypto_digest(
      ncmp_client_t *c,     // 초기화된 클라이언트 핸들
      uint32_t slot,        // 물리 슬롯 인덱스
      uint32_t mech,        // NCMP_MECH_SHA* 값
      const uint8_t *data,  // 입력 데이터
      uint32_t data_len,    // 입력 길이(4+data_len <= NCMP_MAX_PARAM_SIZE)
      uint8_t *out,         // 다이제스트 수신 버퍼
      uint32_t out_cap,     // out 용량
      uint32_t *out_len     // 다이제스트 길이 수신(NULL 허용)
  );
  ```
- **반환값**: `NCMP_CKR_OK`, `NCMP_CKR_ARGUMENTS_BAD`(길이 초과),
  `NCMP_CKR_DEVICE_MEMORY`(요청 버퍼 할당 실패), 토큰 ack
  (`CKR_MECHANISM_INVALID` 등), 전송오류 매핑.

### 5.5 `ncmp_crypto_digest_init`
- **기능**: 다중 파트 다이제스트 컨텍스트를 연다. 컨텍스트 id를 돌려준다.
- **원형 및 인자**:
  ```c
  unsigned long ncmp_crypto_digest_init(
      ncmp_client_t *c,    // 초기화된 클라이언트 핸들
      uint32_t slot,       // 물리 슬롯 인덱스
      uint32_t mech,       // NCMP_MECH_SHA* 값
      uint32_t *ctx_id     // 성공 시 컨텍스트 id 수신
  );
  ```
- **반환값**: `NCMP_CKR_OK`, `NCMP_CKR_ARGUMENTS_BAD`(ctx_id==NULL),
  `NCMP_CKR_FUNCTION_FAILED`(응답 id 길이 불일치), 토큰 ack, 전송오류 매핑.

### 5.6 `ncmp_crypto_digest_update`
- **기능**: 다중 파트 다이제스트 컨텍스트에 한 청크를 투입한다. 요청 `[ctx_id|data]`.
- **원형 및 인자**:
  ```c
  unsigned long ncmp_crypto_digest_update(
      ncmp_client_t *c,     // 초기화된 클라이언트 핸들
      uint32_t slot,        // 물리 슬롯 인덱스
      uint32_t ctx_id,      // 컨텍스트 id
      const uint8_t *data,  // 데이터 청크(<=32KB급)
      uint32_t data_len     // 청크 길이
  );
  ```
- **반환값**: `NCMP_CKR_OK` / 토큰 ack / 전송오류 매핑.

### 5.7 `ncmp_crypto_digest_final`
- **기능**: 다중 파트 다이제스트를 종료하고 결과를 받는다(토큰이 컨텍스트 해제).
- **원형 및 인자**:
  ```c
  unsigned long ncmp_crypto_digest_final(
      ncmp_client_t *c,    // 초기화된 클라이언트 핸들
      uint32_t slot,       // 물리 슬롯 인덱스
      uint32_t ctx_id,     // 컨텍스트 id
      uint8_t *out,        // 다이제스트 수신 버퍼
      uint32_t out_cap,    // out 용량
      uint32_t *out_len    // 다이제스트 길이 수신(NULL 허용)
  );
  ```
- **반환값**: `NCMP_CKR_OK` / 토큰 ack / 전송오류 매핑.

### 5.8 `ncmp_crypto_aes_stream`
- **기능**: AES 스트림 모드(opcode=`NCMP_CMD_AES_CTR`) 암복호. 출력 길이=입력 길이.
  요청 `[flags|key|iv|data]`.
- **원형 및 인자**:
  ```c
  unsigned long ncmp_crypto_aes_stream(
      ncmp_client_t *c,     // 초기화된 클라이언트 핸들
      uint32_t slot,        // 물리 슬롯 인덱스
      uint32_t opcode,      // NCMP_CMD_AES_CTR
      int encrypt,          // 비0=암호화(스트림은 방향 대칭)
      const uint8_t *key,   // AES 키
      uint32_t key_len,     // 키 길이
      const uint8_t *iv,    // 카운터/IV
      uint32_t iv_len,      // IV 길이
      const uint8_t *in,    // 입력
      uint32_t in_len,      // 입력 길이
      uint8_t *out,         // 출력 수신 버퍼
      uint32_t out_cap,     // out 용량
      uint32_t *out_len     // 출력 길이 수신(NULL 허용)
  );
  ```
- **반환값**: `NCMP_CKR_OK` / 토큰 ack(`CKR_MECHANISM_INVALID` 등) / 전송오류 매핑.

### 5.9 `ncmp_crypto_aes_gcm`
- **기능**: AES-GCM 단발(one-shot). 암호화는 태그를 부가(out=in_len+tag_len),
  복호화는 태그를 소비·검증(out=in_len-tag_len). 요청
  `[flags|key|iv|aad|taglen|data]`.
- **원형 및 인자**:
  ```c
  unsigned long ncmp_crypto_aes_gcm(
      ncmp_client_t *c,     // 초기화된 클라이언트 핸들
      uint32_t slot,        // 물리 슬롯 인덱스
      int encrypt,          // 비0=암호화
      const uint8_t *key,   // AES 키
      uint32_t key_len,     // 키 길이
      const uint8_t *iv,    // IV
      uint32_t iv_len,      // IV 길이
      const uint8_t *aad,   // 추가 인증 데이터(없으면 NULL/0)
      uint32_t aad_len,     // AAD 길이
      uint32_t tag_len,     // 태그 바이트 수
      const uint8_t *in,    // 입력(평문/암호문)
      uint32_t in_len,      // 입력 길이
      uint8_t *out,         // 출력 수신 버퍼
      uint32_t out_cap,     // out 용량
      uint32_t *out_len     // 출력 길이 수신(NULL 허용)
  );
  ```
- **반환값**: `NCMP_CKR_OK` / 토큰 ack(`CKR_ENCRYPTED_DATA_INVALID`(태그 불일치)/
  `CKR_MECHANISM_INVALID` 등) / 전송오류 매핑.

### 5.10 `ncmp_crypto_aes_gcm_init`
- **기능**: 다중 파트 AES-GCM 시작. 키/IV/AAD/태그길이를 전달하고 컨텍스트 id를
  받는다(키는 토큰이 등록, 컨텍스트는 key_id만 참조 — [`command-interface.md`](command-interface.md) §11.1).
- **원형 및 인자**:
  ```c
  unsigned long ncmp_crypto_aes_gcm_init(
      ncmp_client_t *c,     // 초기화된 클라이언트 핸들
      uint32_t slot,        // 물리 슬롯 인덱스
      int encrypt,          // 비0=암호화
      const uint8_t *key,   // AES 키(INIT 전송 중에만 통과)
      uint32_t key_len,     // 키 길이
      const uint8_t *iv,    // IV
      uint32_t iv_len,      // IV 길이
      const uint8_t *aad,   // AAD(없으면 NULL/0)
      uint32_t aad_len,     // AAD 길이
      uint32_t tag_len,     // 태그 바이트 수
      uint32_t *ctx_id      // 성공 시 컨텍스트 id 수신
  );
  ```
- **반환값**: `NCMP_CKR_OK`, `NCMP_CKR_ARGUMENTS_BAD`(ctx_id==NULL),
  `NCMP_CKR_FUNCTION_FAILED`(응답 id 길이 불일치), 토큰 ack, 전송오류 매핑.

### 5.11 `ncmp_crypto_aes_gcm_update`
- **기능**: 다중 파트 AES-GCM에 한 청크를 투입하고 암/평문 출력을 받는다.
  요청 `[ctx_id|data]`.
- **원형 및 인자**:
  ```c
  unsigned long ncmp_crypto_aes_gcm_update(
      ncmp_client_t *c,   // 초기화된 클라이언트 핸들
      uint32_t slot,      // 물리 슬롯 인덱스
      uint32_t ctx_id,    // 컨텍스트 id
      const uint8_t *in,  // 입력 청크
      uint32_t in_len,    // 청크 길이
      uint8_t *out,       // 출력 수신 버퍼
      uint32_t out_cap,   // out 용량
      uint32_t *out_len   // 출력 길이 수신(NULL 허용)
  );
  ```
- **반환값**: `NCMP_CKR_OK` / 토큰 ack / 전송오류 매핑.

### 5.12 `ncmp_crypto_aes_gcm_final`
- **기능**: 다중 파트 AES-GCM 종료. 암호화는 태그를 받고(`tag_out`), 복호화는
  기대 태그(`tag_in`)를 전달해 토큰이 검증한다.
- **원형 및 인자**:
  ```c
  unsigned long ncmp_crypto_aes_gcm_final(
      ncmp_client_t *c,        // 초기화된 클라이언트 핸들
      uint32_t slot,           // 물리 슬롯 인덱스
      uint32_t ctx_id,         // 컨텍스트 id
      int encrypt,             // 비0=암호화(태그 생성), 0=복호화(태그 검증)
      const uint8_t *tag_in,   // (복호화) 기대 태그
      uint32_t tag_in_len,     // (복호화) 기대 태그 길이
      uint8_t *tag_out,        // (암호화) 태그 수신 버퍼
      uint32_t tag_out_cap,    // (암호화) tag_out 용량
      uint32_t *tag_out_len    // (암호화) 태그 길이 수신(NULL 허용)
  );
  ```
- **반환값**: `NCMP_CKR_OK` / 토큰 ack(복호화 시 `CKR_ENCRYPTED_DATA_INVALID`) /
  전송오류 매핑.

### 5.13 `ncmp_crypto_ctx_free`
- **기능**: 다중 파트 컨텍스트를 해제한다(중단/teardown). 멱등. 요청 `[ctx_id|kind]`.
- **원형 및 인자**:
  ```c
  unsigned long ncmp_crypto_ctx_free(
      ncmp_client_t *c,   // 초기화된 클라이언트 핸들
      uint32_t slot,      // 물리 슬롯 인덱스
      uint32_t ctx_id,    // 컨텍스트 id
      uint32_t kind       // NCMP_CTX_KIND_DIGEST / NCMP_CTX_KIND_GCM
  );
  ```
- **반환값**: `NCMP_CKR_OK` / 토큰 ack / 전송오류 매핑.

### 5.14 `ncmp_crypto_shake_derive`
- **기능**: SHAKE XOF로 `base` 키 재료를 `out_len`바이트로 확장한다.
  요청 `[mech|outlen|base]`.
- **원형 및 인자**:
  ```c
  unsigned long ncmp_crypto_shake_derive(
      ncmp_client_t *c,     // 초기화된 클라이언트 핸들
      uint32_t slot,        // 물리 슬롯 인덱스
      uint32_t mech,        // SHAKE 메커니즘
      const uint8_t *base,  // 기반 키 재료
      uint32_t base_len,    // 기반 길이
      uint8_t *out,         // 유도 출력 수신 버퍼
      uint32_t out_len      // 요청 출력 길이(<= NCMP_MAX_PARAM_SIZE)
  );
  ```
- **반환값**: `NCMP_CKR_OK`, `NCMP_CKR_ARGUMENTS_BAD`(out==NULL/0/초과),
  `NCMP_CKR_FUNCTION_FAILED`(응답 길이 불일치), 토큰 ack, 전송오류 매핑.

### 5.15 `pqc_keygen` (static, 내부)
- **기능**: ML-DSA/ML-KEM 공용 키쌍 생성 헬퍼. `[set|len_a|len_b] → [blob_a|blob_b]`.
- **원형 및 인자**:
  ```c
  static unsigned long pqc_keygen(
      ncmp_client_t *c, uint32_t slot, uint32_t opcode,
      uint32_t paramset, uint32_t a_len, uint32_t b_len,
      uint8_t *a, uint8_t *b
  );
  ```
- **반환값**: `NCMP_CKR_OK`, `NCMP_CKR_ARGUMENTS_BAD`(인자/합계 초과),
  `NCMP_CKR_DEVICE_MEMORY`(스크래치 할당 실패), `NCMP_CKR_FUNCTION_FAILED`(응답
  파라미터 길이 불일치), 토큰 ack, 전송오류 매핑.

### 5.16 `ncmp_crypto_mldsa_keygen`
- **기능**: ML-DSA 키쌍 생성(`pqc_keygen` 위임). `[set|pub_len|priv_len] → [pub|priv]`.
- **원형 및 인자**:
  ```c
  unsigned long ncmp_crypto_mldsa_keygen(
      ncmp_client_t *c,    // 초기화된 클라이언트 핸들
      uint32_t slot,       // 물리 슬롯 인덱스
      uint32_t paramset,   // CKP_ML_DSA_* 강도
      uint32_t pub_len,    // 공개 블롭 크기
      uint32_t priv_len,   // 개인 블롭 크기
      uint8_t *pub,        // 공개 블롭 수신
      uint8_t *priv        // 개인 블롭 수신
  );
  ```
- **반환값**: `pqc_keygen`과 동일(`NCMP_CKR_OK`/`NCMP_CKR_ARGUMENTS_BAD`/
  `NCMP_CKR_DEVICE_MEMORY`/`NCMP_CKR_FUNCTION_FAILED`/토큰 ack/전송오류 매핑).

### 5.17 `ncmp_crypto_mlkem_keygen`
- **기능**: ML-KEM 키쌍 생성(`pqc_keygen` 위임). `[set|pub_len|priv_len] → [pub|priv]`.
- **원형 및 인자**:
  ```c
  unsigned long ncmp_crypto_mlkem_keygen(
      ncmp_client_t *c,    // 초기화된 클라이언트 핸들
      uint32_t slot,       // 물리 슬롯 인덱스
      uint32_t paramset,   // CKP_ML_KEM_* 강도
      uint32_t pub_len,    // 공개 블롭 크기
      uint32_t priv_len,   // 개인 블롭 크기
      uint8_t *pub,        // 공개 블롭 수신
      uint8_t *priv        // 개인 블롭 수신
  );
  ```
- **반환값**: `pqc_keygen`과 동일.

### 5.18 `ncmp_crypto_mldsa_sign`
- **기능**: ML-DSA 서명. `[set|pub_len|sig_len|priv|data] → [sig]`.
- **원형 및 인자**:
  ```c
  unsigned long ncmp_crypto_mldsa_sign(
      ncmp_client_t *c,      // 초기화된 클라이언트 핸들
      uint32_t slot,         // 물리 슬롯 인덱스
      uint32_t paramset,     // CKP_ML_DSA_* 강도
      uint32_t pub_len,      // 공개 블롭 크기(개인 블롭 접두어)
      uint32_t sig_len,      // 서명 버퍼 크기(<= NCMP_MAX_PARAM_SIZE)
      const uint8_t *priv,   // 개인 키 블롭
      uint32_t priv_len,     // 개인 블롭 길이
      const uint8_t *data,   // 서명 대상 데이터
      uint32_t data_len,     // 데이터 길이
      uint8_t *sig,          // 서명 수신 버퍼
      uint32_t *out_sig_len  // 서명 길이 수신(NULL 허용)
  );
  ```
- **반환값**: `NCMP_CKR_OK`, `NCMP_CKR_ARGUMENTS_BAD`(sig==NULL/0/초과),
  `NCMP_CKR_FUNCTION_FAILED`(응답 없음/길이 0), 토큰 ack, 전송오류 매핑.

### 5.19 `ncmp_crypto_mldsa_verify`
- **기능**: ML-DSA 검증. `[set|pub|data|sig] → ack`.
- **원형 및 인자**:
  ```c
  unsigned long ncmp_crypto_mldsa_verify(
      ncmp_client_t *c,     // 초기화된 클라이언트 핸들
      uint32_t slot,        // 물리 슬롯 인덱스
      uint32_t paramset,    // CKP_ML_DSA_* 강도
      const uint8_t *pub,   // 공개 키 블롭
      uint32_t pub_len,     // 공개 블롭 길이
      const uint8_t *data,  // 원문 데이터
      uint32_t data_len,    // 데이터 길이
      const uint8_t *sig,   // 검증할 서명
      uint32_t sig_len      // 서명 길이
  );
  ```
- **반환값**: `NCMP_CKR_OK` / 토큰 ack(`CKR_SIGNATURE_INVALID`) / 전송오류 매핑.

### 5.20 `ncmp_crypto_mlkem_encaps`
- **기능**: ML-KEM 캡슐화. `[set|ct_len|ss_len|pub] → [ct|ss]`.
- **원형 및 인자**:
  ```c
  unsigned long ncmp_crypto_mlkem_encaps(
      ncmp_client_t *c,     // 초기화된 클라이언트 핸들
      uint32_t slot,        // 물리 슬롯 인덱스
      uint32_t paramset,    // CKP_ML_KEM_* 강도
      const uint8_t *pub,   // 공개 키 블롭
      uint32_t pub_len,     // 공개 블롭 길이
      uint32_t ct_len,      // 암호문(캡슐) 크기
      uint32_t ss_len,      // 공유 비밀 크기
      uint8_t *ct,          // 암호문 수신
      uint8_t *ss           // 공유 비밀 수신
  );
  ```
- **반환값**: `NCMP_CKR_OK`, `NCMP_CKR_ARGUMENTS_BAD`(인자/합계 초과),
  `NCMP_CKR_DEVICE_MEMORY`(스크래치 할당 실패), `NCMP_CKR_FUNCTION_FAILED`(응답
  파라미터 길이 불일치), 토큰 ack, 전송오류 매핑.

### 5.21 `ncmp_crypto_mlkem_decaps`
- **기능**: ML-KEM 복호캡슐화. `[set|pub_len|ss_len|priv|ct] → [ss]`.
- **원형 및 인자**:
  ```c
  unsigned long ncmp_crypto_mlkem_decaps(
      ncmp_client_t *c,     // 초기화된 클라이언트 핸들
      uint32_t slot,        // 물리 슬롯 인덱스
      uint32_t paramset,    // CKP_ML_KEM_* 강도
      uint32_t pub_len,     // 공개 블롭 크기(개인 블롭 접두어)
      const uint8_t *priv,  // 개인 키 블롭
      uint32_t priv_len,    // 개인 블롭 길이
      const uint8_t *ct,    // 암호문(캡슐)
      uint32_t ct_len,      // 암호문 길이
      uint32_t ss_len,      // 공유 비밀 크기(<= NCMP_MAX_PARAM_SIZE)
      uint8_t *ss           // 공유 비밀 수신
  );
  ```
- **반환값**: `NCMP_CKR_OK`, `NCMP_CKR_ARGUMENTS_BAD`(ss==NULL/0/초과),
  `NCMP_CKR_FUNCTION_FAILED`(응답 길이 불일치), 토큰 ack, 전송오류 매핑.

---

## 6. `ncmp_object.c` — 객체 관리 마샬링 어댑터

### 6.1 `object_cmd` (static, 내부)
- **기능**: 3파라미터 객체 명령 `[class|key_type|blob]`을 전송하고 토큰 상태를
  표면화하는 내부 헬퍼.
- **원형 및 인자**:
  ```c
  static unsigned long object_cmd(
      ncmp_client_t *c, uint32_t slot, uint32_t opcode,
      uint32_t p0, uint32_t p1, const uint8_t *blob, uint32_t blob_len
  );
  ```
- **반환값**: `NCMP_CKR_DATA_LEN_RANGE`(blob_len>NCMP_MAX_PARAM_SIZE) / 토큰 ack /
  전송오류 매핑.

### 6.2 `ncmp_object_add`
- **기능**: 키 객체를 토큰에 등록/임포트한다(`C_CreateObject` 경로).
  `NCMP_CMD_OBJECT_ADD [class|key_type|value]`.
- **원형 및 인자**:
  ```c
  unsigned long ncmp_object_add(
      ncmp_client_t *c,      // 초기화된 클라이언트 핸들
      uint32_t slot,         // 물리 슬롯 인덱스
      uint32_t obj_class,    // PKCS#11 객체 클래스(CKO_*)
      uint32_t key_type,     // PKCS#11 키 타입(CKK_*)
      const uint8_t *value,  // 키 데이터(CKA_VALUE)
      uint32_t value_len     // 키 데이터 길이(<= NCMP_MAX_PARAM_SIZE)
  );
  ```
- **반환값**: `NCMP_CKR_OK`, `NCMP_CKR_DATA_LEN_RANGE`(value_len 초과), 토큰 ack
  (`CKR_TEMPLATE_INCOMPLETE`/`CKR_ARGUMENTS_BAD`), 전송오류 매핑.

### 6.3 `ncmp_object_set_attrs`
- **기능**: 키 객체의 변경 속성을 토큰에 전달해 검증한다
  (`C_SetAttributeValue`/`C_CopyObject` 경로).
  `NCMP_CMD_OBJECT_SET_ATTR [class|key_type|attrs]`
  (attrs = `count` 다음 `count`개의 `{type|len|value}`).
- **원형 및 인자**:
  ```c
  unsigned long ncmp_object_set_attrs(
      ncmp_client_t *c,      // 초기화된 클라이언트 핸들
      uint32_t slot,         // 물리 슬롯 인덱스
      uint32_t obj_class,    // PKCS#11 객체 클래스(CKO_*)
      uint32_t key_type,     // PKCS#11 키 타입(CKK_*)
      const uint8_t *attrs,  // 직렬화된 변경 속성 목록
      uint32_t attrs_len     // 목록 길이(<= NCMP_MAX_PARAM_SIZE)
  );
  ```
- **반환값**: `NCMP_CKR_OK`, `NCMP_CKR_DATA_LEN_RANGE`(attrs_len 초과), 토큰 ack
  (`CKR_ATTRIBUTE_VALUE_INVALID`), 전송오류 매핑.

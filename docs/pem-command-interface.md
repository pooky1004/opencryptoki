# PEM 토큰 — CI(Command Interface) 명령어 규격

- 작성일 : 2026-10-07
- 대상 독자 : PEM 펌웨어/엔진 설계자, PEM PKCS#11 provider·호스트 SDK 개발자
- 근거 소스 : `ci/cifx_protocol.h`(opcode·프레임), `ci/cifx_protocol.c`(인코딩),
  `ci/ci_commands.c`(명령별 레이아웃), `ci/ci_usb_lib.c`(USB 전송),
  `ci/ci_pem_lib.c`(인자 인코딩) — 분석 대상 `/home/pooky/ji/host`
- 관련 문서 : [`pem-usb-transport.md`](pem-usb-transport.md) ·
  [`pem-webtestapp-plan.md`](pem-webtestapp-plan.md) ·
  [`command-interface.md`](command-interface.md)(NCMP CI, 비교용)

---

## 1. 개요

### 1.1. 요약

CI는 호스트가 PEM 토큰(USB `04b4:5054`)으로 보내는 모든 명령에 대한 논리적 인터페이스
규약으로, 토큰으로부터 보안 서비스를 제공받기 위하여 명령을 보내고 응답을 받는 구조로
구성된다. 본 규격은 PEM 펌웨어의 **CI v4** 와이어 포맷을 정의한다.

메시지(프레임) 송수신으로 명령·데이터를 전달하므로 포인터 전송이 불가능하며, 모든
인자를 **16바이트 공통 헤더 뒤에 이어붙인 인자 영역(args)** 에 담아 전달한다.

> NCMP 토큰 CI([`command-interface.md`](command-interface.md))와 **와이어 포맷이 다르다.**
> NCMP는 20바이트 헤더 + `param_len[8]` 슬롯 배열 + 정수 4바이트인 반면, PEM은
> **16바이트 헤더 + 위치 기반 인자(positional args) + 인자 정수 8바이트**다.

### 1.2. 용어 및 약어

| 용어 | 내용 |
|------|------|
| 호스트 | CI 명령을 생성·전송하는 측(PEM PKCS#11 provider / SDK) |
| 토큰 | CI 명령을 수신·실행하는 PEM 보안 토큰(FPGA 펌웨어) |
| 프레임(message) | 16바이트 헤더 + 인자(args)로 구성된 CI 메시지 한 개 |
| 인자(args) | 헤더 뒤에 명령별로 **위치 순서대로** 이어붙인 바이트열 |
| 전송(transfer) | 메시지를 4바이트 경계로 올림 패딩한 실제 USB 전송 단위 |
| 블롭(blob) | 길이가 가변인 불투명 바이트열(키, 메시지, digest 등) |
| 컨텍스트 | 멀티파트 연산(INIT/UPDATE/FINAL)의 중간 상태(key_id로 식별) |
| 저장 키 ID | 토큰 키 테이블의 공개 키 번호(1–26) |

| 약어 | 내용 |
|------|------|
| CI | Command Interface |
| CI v4 | PEM 토큰의 4세대 CI 와이어 포맷 |
| PEM | 대상 토큰/보드 명칭 (USB 04b4:5054) |
| LE | Little Endian |
| ZLP | Zero-Length Packet |
| AEAD / GCM / CTR / AAD / IV | 대칭키 암복호 관련 용어 |
| SHA3 | Secure Hash Algorithm 3 |
| ML-DSA / ML-KEM / PQC | 포스트양자 서명 / 키캡슐화 / 포스트양자 암호 |
| ACK / RV | 응답 상태 코드 / Return Value |

---

## 2. CI 명령어 구조

### 2.1. CI 명령 블록 구조 (호스트 ⇒ 토큰)

모든 CI 메시지는 **16바이트 공통 헤더**로 시작한다. **헤더 필드는 4바이트 정수,
리틀엔디언**이다(`cifx_build_ci_v4_message`, `cifx_protocol.c`).

| 오프셋 | 크기 | 필드 | 설명 |
|:---:|:---:|------|------|
| 0 | 4 | TOTAL_BYTES | 헤더+인자의 총 바이트 수(패딩 전 메시지 길이) |
| 4 | 4 | SESSION_ID | 세션 핸들(hSession). OPEN 요청은 0 |
| 8 | 4 | COMMAND | 명령 코드(CI_CMD_*) |
| 12 | 4 | ACK | **요청 = `0x0000FFFF`**(`REQ_ACK`) |
| 16 | n | args | 명령별 인자(위치 순서, §2.4) |

[표 1] CI 명령 블록 구조

```c
/* CI v4 공통 헤더 (16바이트, 전부 LE u32). args가 뒤에 이어진다. */
typedef struct CI_Header {
    uint32_t total_bytes;  /* 헤더(16) + 인자 바이트 수 */
    uint32_t session_id;   /* 세션 핸들(hSession). OPEN 요청은 0 */
    uint32_t command;      /* 명령 코드 (CI_CMD_*) */
    uint32_t ack;          /* 요청=0x0000FFFF(REQ_ACK), 응답=상태코드(0=성공) */
} CI_Header;
```

- TOTAL_BYTES : 패딩 전 메시지 전체 길이(헤더 16 + 인자). 요청 최대 65504, 응답 최대 65520.
- SESSION_ID : SESSION(OPEN)으로 받은 hSession. 세션 불필요 명령/OPEN 요청은 0.
- COMMAND : §2.7 명령 코드.
- ACK : **요청에서는 항상 `0x0000FFFF`** 로 "요청"임을 표시한다.

### 2.2. CI 응답 구조 (토큰 ⇒ 호스트)

응답도 동일한 16바이트 헤더를 쓰며, **ACK 필드에 상태 코드**가 실린다.

| 오프셋 | 크기 | 필드 | 설명 |
|:---:|:---:|------|------|
| 0 | 4 | TOTAL_BYTES | 헤더+출력인자 총 바이트 수 |
| 4 | 4 | SESSION_ID | 요청과 동일(반향) |
| 8 | 4 | COMMAND | 요청과 동일(반향) |
| 12 | 4 | ACK (RV) | **상태 코드(0=성공, ≠0=오류)** |
| 16 | n | args | 명령별 출력 인자 |

[표 2] CI 응답 구조

- ACK(RV) : 0이면 성공, 0이 아니면 오류(명령 거부·검증 실패 등). GCM 복호화/ML-DSA
  검증 등은 이 ACK로 인증·검증 결과를 판단한다(→ §5).
- 전송 길이가 정확히 `max_packet`의 배수인 **요청**은 OUT 뒤에 **ZLP** 를 덧붙인다
  (§2.5). 응답에는 IN ZLP가 없다.

### 2.3. 엔디안 및 정수 폭 (중요)

**헤더와 인자 모두 little-endian으로 동일하다. 엔디안 차이는 없다.** 실제로 다른 것은
**정수 폭**이다.

| 영역 | 폭 | 인코딩 | 근거 |
|------|:---:|:---:|------|
| 헤더 필드 | 4 B (u32) | LE | `cifx_put_le32`/`cifx_get_le32` |
| 인자 정수 | **8 B (u64)** | LE | `put64`/`get64`(`p[i]=n>>(8*i)`), 주석 "u64 LE" |
| Python 레퍼런스 | — | LE | `struct.pack("<IIII", …)`(헤더), `"<Q"`(인자) (`tools/ci_console/wire.py`) |

호스트 코드 전체에 big-endian 사용은 없다. 키·IV·counter·digest·signature 등은
**정수가 아닌 raw 바이트 배열**이므로 엔디안이 적용되지 않는다.

### 2.4. 인자(args) 인코딩 규약

NCMP의 `param_len[8]` 슬롯 배열과 달리, PEM은 **헤더 뒤에 명령별 인자를 위치 순서대로
이어붙인다**(positional). `ci_commands.c` 상단 규약:

- **인자 정수는 8바이트(u64) LE.**
- **가변 바이트 배열**은 앞에 명시적 `*_len`(8B 정수)이 오고, 배열 뒤에 `PAD8`(0–7바이트
  0 패딩)로 **8바이트 경계**에 맞춘다. 빈 배열도 길이 필드(예: `aad_len=0`)는 전송한다.
- **고정 길이 배열**(키·digest·signature·public/secret key 등)은 **길이 필드 없이**
  규격 크기로 전송한다.
- 인자가 없으면 헤더(16B)만 전송하고 결과는 ACK로만 전달된다.

본 문서 §6의 `CI_*Req`/`CI_*Rsp`는 **인자 영역의 논리적 레이아웃**을 나타낸 것이며
패킹된 C 구조체가 아니다(가변 배열은 `name[]`, 정수는 `uint64_t`).

### 2.5. USB 전송

- USB : VID `0x04B4` / PID `0x5054`, 인터페이스 0, bulk **OUT `0x01` / IN `0x81`**.
- 접근 : **usbfs 직접(ioctl USBDEVFS_BULK)**. 교환 절차는 **OUT → (요청이 max_packet
  배수이면 ZLP) → IN**. 메시지는 4바이트 경계로 올림 패딩하여 전송한다.
- 상세·NCMP(FX3 Slave-FIFO) 비교는 [`pem-usb-transport.md`](pem-usb-transport.md) 참조.

### 2.6. CI 명령어 종류 및 코드

| 명령 구분 | 명령어 이름 | 코드 | 기능 |
|---|---|---|---|
| 시스템 | CI_CMD_CAPABILITIES | 0x0001 | API 버전·슬롯·지원 비트맵 조회 |
| | CI_CMD_ECHO | 0x0002 | 에코(loopback) |
| 세션 | CI_CMD_SESSION | 0x0023 | 세션 열기/닫기 |
| 키 | CI_CMD_KEYTABLE_INFO | 0x0024 | 키 테이블 공개 메타데이터 조회 |
| 진단 | CI_CMD_PERF_QUERY | 0x00F0 | 성능 카운터 조회 |
| PQC · ML-DSA | CI_CMD_MLDSA_KEYGEN | 0x0050 | ML-DSA 키 쌍 생성 |
| | CI_CMD_MLDSA_SIGN | 0x0051 | ML-DSA 서명(키 전달) |
| | CI_CMD_MLDSA_VERIFY | 0x0052 | ML-DSA 검증 |
| | CI_CMD_MLDSA_SIGN_KEY_ID | 0x005A | ML-DSA 서명(저장 키) |
| | CI_CMD_MLDSA_VERIFY_KEY_ID | 0x005B | ML-DSA 검증(저장 키) |
| PQC · ML-KEM | CI_CMD_MLKEM_KEYGEN | 0x0053 | ML-KEM 키 쌍 생성 |
| | CI_CMD_MLKEM_ENCAPS | 0x0054 | ML-KEM 캡슐화(키 전달) |
| | CI_CMD_MLKEM_DECAPS | 0x0055 | ML-KEM 역캡슐화(키 전달) |
| | CI_CMD_MLKEM_ENCAPS_KEY_ID | 0x005C | ML-KEM 캡슐화(저장 키) |
| | CI_CMD_MLKEM_DECAPS_KEY_ID | 0x005D | ML-KEM 역캡슐화(저장 키) |
| 대칭키 | CI_CMD_AES_ONESHOT | 0x0116 | AES 단발(키 전달) |
| | CI_CMD_AES_MASTER_KEY | 0x0117 | AES 단발(마스터 키 버전) |
| | CI_CMD_AES_KEY_ID | 0x0118 | AES 단발(저장 키 ID) |
| | CI_CMD_AES_CONTEXT | 0x0120 | AES 단발/멀티파트 통합 |
| | CI_CMD_AES_CTR_INIT | 0x0130 | AES-CTR 멀티파트 시작 |
| | CI_CMD_AES_CTR_UPDATE | 0x0131 | AES-CTR 부분 처리 |
| | CI_CMD_AES_CTR_FINAL | 0x0132 | AES-CTR 종료 |
| | CI_CMD_AES_GCM_INIT | 0x0133 | AES-GCM 멀티파트 시작 |
| | CI_CMD_AES_GCM_UPDATE | 0x0134 | AES-GCM 부분 처리 |
| | CI_CMD_AES_GCM_FINAL | 0x0135 | AES-GCM 종료(태그) |
| SHA3 | CI_CMD_SHA3_256/384/512 | 0x0310/0x0311/0x0312 | SHA3 단발 |
| | CI_CMD_SHA3_256_INIT/UPDATE/FINAL | 0x0340/0x0341/0x0342 | SHA3-256 멀티파트 |
| | CI_CMD_SHA3_384_INIT/UPDATE/FINAL | 0x0343/0x0344/0x0345 | SHA3-384 멀티파트 |
| | CI_CMD_SHA3_512_INIT/UPDATE/FINAL | 0x0346/0x0347/0x0348 | SHA3-512 멀티파트 |

[표 3] CI 명령어 종류 및 코드 (근거: `cifx_protocol.h`)

- API 버전 : 현행 7(`CIFX_CI_API_VERSION`), legacy 6.
- 저수준 패킷 opcode(`CIFX_OPCODE_PING 0x01` 등)는 별도의 ping/echo 프레이밍용이며,
  위 CI v4 명령 코드와 구분된다.

---

## 3. 명령 처리 순서

### 3.1. 단발 명령과 멀티파트 명령

| 수행 단계 | 관련 명령 | 비고 |
|---|---|---|
| 단발 | CAPABILITIES, ECHO, KEYTABLE_INFO, PERF_QUERY, AES_ONESHOT/MASTER_KEY/KEY_ID, SHA3 단발, MLDSA_*/MLKEM_* | 호출 간 토큰 상태 없음 |
| INIT→UPDATE…→FINAL | SHA3_*_INIT/UPDATE/FINAL, AES_CTR_INIT/UPDATE/FINAL, AES_GCM_INIT/UPDATE/FINAL | 컨텍스트 유지 |
| 통합 | AES_CONTEXT(action=0 ONESHOT / 1 INIT / 2 UPDATE / 3 FINAL / 4 ABORT) | 한 명령으로 모드 전환 |

### 3.2. 멀티파트 컨텍스트 모델 (key_id 기반)

- INIT : 키·IV(또는 저장 `key_id`)로 연산을 시작한다. 이후 UPDATE/FINAL은 **같은
  `key_id`** 로 토큰 측 컨텍스트를 자동 재사용한다(`key_id=0`이면 INIT에 전달한 입력 키).
- UPDATE : 입력 조각을 처리하고 결과(암호문/평문)를 돌려준다. `data_len≥1`.
- FINAL : GCM 암호화는 **태그**를 반환하고, GCM 복호화는 **expected tag** 를 받아
  검증한다(ACK로 결과). CTR FINAL은 추가 인자 없음.
- `AES_CONTEXT`(0x0120)는 action 필드로 ONESHOT/INIT/UPDATE/FINAL/ABORT를 한 opcode에서
  처리하며, GCM AAD UPDATE는 `flags=1`로 표시한다.

---

## 4. CI 메커니즘

| 메커니즘 | 설명 | 관련 명령 |
|---|---|---|
| SHA3-256/384/512 | 출력 32/48/64바이트 해시(단발·멀티파트) | SHA3_* |
| AES-GCM | AEAD(암호화 시 태그 부가, 복호화 시 태그 검증) | AES_ONESHOT/KEY_ID/CONTEXT, AES_GCM_* |
| AES-CTR | 스트림 암/복호(출력=입력 길이) | AES_ONESHOT/KEY_ID/CONTEXT, AES_CTR_* |
| ML-DSA | 포스트양자 서명 | MLDSA_*(+_KEY_ID) |
| ML-KEM | 포스트양자 키 캡슐화 | MLKEM_*(+_KEY_ID) |

### 4.1. PQC 파라미터·고정 크기 (길이 필드 없음)

**ML-DSA** (`profile` = 44 / 65 / 87)

| profile | public_key | secret_key | signature |
|:---:|:---:|:---:|:---:|
| 44 | 1312 | 2560 | 2420 |
| 65 | 1952 | 4032 | 3309 |
| 87 | 2592 | 4896 | 4627 |

**ML-KEM** (`profile` = 512 / 768 / 1024, `shared_secret`는 항상 32B)

| profile | public_key | secret_key | ciphertext |
|:---:|:---:|:---:|:---:|
| 512 | 800 | 1632 | 768 |
| 768 | 1184 | 2400 | 1088 |
| 1024 | 1568 | 3168 | 1568 |

### 4.2. 저장 키 ID

| 용도 | key_id |
|------|--------|
| AES-CTR | 홀수 1–19 |
| AES-GCM | 짝수 2–20 |
| ML-DSA (44/65/87) | 21 / 22 / 23 |
| ML-KEM (512/768/1024) | 24 / 25 / 26 |

---

## 5. 반환값

응답 헤더 `ACK`(RV)에 상태 코드가 실린다. **요청은 항상 `ACK=0x0000FFFF`, 응답은
0=성공 / ≠0=오류**이다. 호스트 PKCS#11 provider는 이를 `CKR_*`로 매핑한다.

### 5.1. 호스트 라이브러리 상태 코드 (`enum cifx_status`)

| 표현 | 값 | 의미 |
|---|---|---|
| CIFX_OK | 0 | 성공 |
| CIFX_ERR_ARGUMENT | -1 | 인자 오류 |
| CIFX_ERR_CAPACITY | -2 | 버퍼 용량 부족 |
| CIFX_ERR_FORMAT | -3 | 프레임 형식 오류 |
| CIFX_ERR_RANGE | -4 | 길이·범위 초과 |
| CIFX_ERR_UNSUPPORTED | -5 | 미지원 |

- 위 코드는 **호스트 측 인코딩/파싱** 결과다. 토큰의 명령 결과는 응답 헤더 ACK로
  전달되며, GCM 복호화 태그 불일치·ML-DSA 검증 실패 등은 ACK≠0으로 나타난다.
- USB 전송 계층 오류는 `CI_USB_ERR_*`(`ci_usb_lib.h`)로 구분된다
  (TIMEOUT/IO/SHORT/NOT_FOUND/MULTIPLE 등).

---

## 6. CI 명령 규격

각 명령의 요청/응답 인자 영역을 **위치 순서**로 기술한다. 정수는 8바이트 LE,
가변 배열은 `*_len`(8B)+배열+`PAD8`(8B 정렬), 고정 배열은 길이 필드 없음. 모든 메시지는
공통 16B 헤더(§2.1)로 시작한다.

### 6.1. 시스템 · 세션

#### 6.1.1. CI_CMD_CAPABILITIES (0x0001)
- 기능 : API 버전·슬롯 수·지원 명령 비트맵 조회.
- 요청 : 추가 인자 없음(헤더 16B).
- 응답 : `api_version`(8B) · `slots`(8B, 물리 슬롯 수) · `mask`(8B, 지원 명령 비트맵).

#### 6.1.2. CI_CMD_ECHO (0x0002)
- 기능 : 입력을 그대로 반향(loopback).
- 요청/응답 : `data_len`(8B) · `data`(data_len B) · `PAD8`.

#### 6.1.3. CI_CMD_SESSION (0x0023)
- 기능 : 세션 열기/닫기.
- 요청 : `action`(8B · 1=OPEN / 2=CLOSE). OPEN은 헤더 `SESSION_ID=0`, CLOSE는 닫을
  `SESSION_ID`를 헤더에 지정.
- 응답 : OPEN → 할당된 `hSession`(8B) ; CLOSE → 인자 없음(ACK만).

#### 6.1.4. CI_CMD_KEYTABLE_INFO (0x0024)
- 기능 : 키 테이블 공개 메타데이터 조회(키·IV·비밀값 미포함).
- 요청 : 추가 인자 없음.
- 응답 : `records_len`(8B, 현재 960) · `records`(30 × 32B). 각 record =
  ID/family/profile/iv_len/key_len/key_offset/flags/reserved (각 4B 정수).

#### 6.1.5. CI_CMD_PERF_QUERY (0x00F0)
- 기능 : 성능 카운터 조회(진단).
- 요청 : `target_hSession`(8B) · `sequence`(8B · 0xFFFFFFFF=최신).
- 응답 : PERF v2 고정 304B(8B 정수 38개) — version/slot/hSession/sequence/ordinal/
  event_valid(각 8B) · events 13×8B · counters 19×8B.

### 6.2. 대칭키 암복호

공통 열거 : `mode` 0=CTR / 1=GCM, `direction` 0=암호화 / 1=복호화.

#### 6.2.1. CI_CMD_AES_ONESHOT (0x0116) — 키 직접 전달
- 요청 : `mode`(8B) · `direction`(8B) · `key`(고정 32B, AES-256)
  - CTR : `iv`(고정 16B)
  - GCM : `iv_len`(8B)·`iv`(12 또는 16B)·PAD8, `aad_len`(8B)·`aad`·PAD8(빈 AAD도 len=0)
  - 공통 : `data_len`(8B)·`data`·PAD8
  - GCM 복호화 : 끝에 `tag`(고정 16B)
- 응답 : `data_len`(8B)·`data`·PAD8 ; GCM 암호화면 `tag`(16B) 추가.

#### 6.2.2. CI_CMD_AES_MASTER_KEY (0x0117) — 마스터 키 버전
- 요청 : `mode` · `direction` · `master_key_version`(8B) + AES_ONESHOT과 동일한
  IV/AAD/data/tag 구성.
- 응답 : AES_ONESHOT과 동일.

#### 6.2.3. CI_CMD_AES_KEY_ID (0x0118) — 저장 키/IV 사용
- 요청 : `mode` · `direction` · `key_id`(8B · CTR=홀수 1–19 / GCM=짝수 2–20).
  **KEY·IV 미전송.** GCM이면 `aad_len`·`aad`·PAD8, 공통 `data_len`·`data`·PAD8,
  GCM 복호화면 `tag`(16B).
- 응답 : AES_ONESHOT과 동일.

#### 6.2.4. CI_CMD_AES_CONTEXT (0x0120) — 단발/멀티파트 통합
- 요청 : `action`(8B · 0=ONESHOT/1=INIT/2=UPDATE/3=FINAL/4=ABORT) · `direction`(8B) ·
  `mode`(8B) · `key_id`(8B · 0=입력 key/IV) · `flags`(8B · 0=일반/1=GCM AAD UPDATE)
  - action 0 또는 1 : `key`(32B); CTR `iv`(16B) / GCM `iv_len`·`iv`·PAD8
  - action 0 & GCM : `aad_len`·`aad`·PAD8
  - action 0 또는 2 : `data_len`·`data`·PAD8
  - action 0 또는 3 & GCM 복호화 : `tag`(16B)
- 응답 : ONESHOT → data(+GCM 암호화 tag 16B) ; UPDATE → data(AAD UPDATE는 없음) ;
  FINAL → GCM 암호화 tag 16B / 그 외 없음 ; INIT/ABORT → 없음.

#### 6.2.5. CI_CMD_AES_CTR_INIT / UPDATE / FINAL (0x0130 – 0x0132)
- INIT(0x0130) : `key_id`(8B · 0=입력) · `direction`(8B) · `key`(32B) · `iv`(16B).
  (`key_id>0`이면 key·iv 자리에 0을 보내고 저장 키 사용) → 응답 인자 없음.
- UPDATE(0x0131) : `key_id`(8B) · `data_len`(8B)·`data`·PAD8(`data_len≥1`)
  → 응답 `data_len`·`data`·PAD8.
- FINAL(0x0132) : `key_id`(8B) → 응답 인자 없음.

#### 6.2.6. CI_CMD_AES_GCM_INIT / UPDATE / FINAL (0x0133 – 0x0135)
- INIT(0x0133) : `key_id`(8B · 0=입력) · `direction`(8B) · `key`(32B) ·
  `iv_len`·`iv`·PAD8 · `aad_len`·`aad`·PAD8(없으면 len=0). (`key_id>0`이면 key·iv에 0)
  → 응답 인자 없음.
- UPDATE(0x0134) : `key_id`(8B) · `data_len`(8B)·`data`·PAD8(`data_len≥1`)
  → 응답 `data_len`·`data`·PAD8.
- FINAL(0x0135) : `key_id`(8B) · [GCM 복호화만] `tag`(16B)
  → 응답 : 암호화면 `tag`(16B), 복호화면 인자 없음(ACK로 인증 결과).

### 6.3. SHA3

#### 6.3.1. CI_CMD_SHA3_256/384/512 (0x0310 / 0x0311 / 0x0312) — 단발
- 요청 : `data_len`(8B)·`data`·PAD8.
- 응답 : `digest`(고정 32 / 48 / 64B, 길이 필드 없음).

#### 6.3.2. SHA3 멀티파트 INIT/UPDATE/FINAL
- INIT (256:0x0340 / 384:0x0343 / 512:0x0346) : 요청·응답 인자 없음.
- UPDATE (0x0341 / 0x0344 / 0x0347) : `data_len`(8B)·`data`·PAD8(`data_len≥1`) → 응답 없음.
- FINAL (0x0342 / 0x0345 / 0x0348) : 요청 없음 → 응답 `digest`(32 / 48 / 64B).

### 6.4. PQC — ML-DSA

고정 크기는 §4.1 표 참조(길이 필드 없음).

#### 6.4.1. CI_CMD_MLDSA_KEYGEN (0x0050)
- 요청 : `profile`(8B · 44/65/87) → 응답 : `public_key` · `secret_key`.

#### 6.4.2. CI_CMD_MLDSA_SIGN (0x0051)
- 요청 : `profile` · `message_len`(8B)·`message`·PAD8 · `secret_key`
  → 응답 : `signature` · PAD8.

#### 6.4.3. CI_CMD_MLDSA_VERIFY (0x0052)
- 요청 : `profile` · `message_len`·`message`·PAD8 · `signature`·PAD8 · `public_key`
  → 응답 : 인자 없음(ACK로 검증 결과).

#### 6.4.4. CI_CMD_MLDSA_SIGN_KEY_ID (0x005A) / VERIFY_KEY_ID (0x005B)
- SIGN : `profile` · `key_id`(8B · 21/22/23) · `message_len`·`message`·PAD8
  → 응답 `signature`·PAD8.
- VERIFY : `profile` · `key_id` · `message_len`·`message`·PAD8 · `signature`·PAD8
  → 응답 없음. (저장 키 사용, secret/public key 미전송)

### 6.5. PQC — ML-KEM

고정 크기는 §4.1 표 참조. `shared_secret`은 항상 32B.

#### 6.5.1. CI_CMD_MLKEM_KEYGEN (0x0053)
- 요청 : `profile`(8B · 512/768/1024) → 응답 : `public_key` · `secret_key`.

#### 6.5.2. CI_CMD_MLKEM_ENCAPS (0x0054)
- 요청 : `profile` · `public_key` → 응답 : `ciphertext` · `shared_secret`(32B).

#### 6.5.3. CI_CMD_MLKEM_DECAPS (0x0055)
- 요청 : `profile` · `ciphertext` · `secret_key` → 응답 : `shared_secret`(32B).

#### 6.5.4. CI_CMD_MLKEM_ENCAPS_KEY_ID (0x005C) / DECAPS_KEY_ID (0x005D)
- ENCAPS : `profile` · `key_id`(8B · 24/25/26) → 응답 `ciphertext` · `shared_secret`.
- DECAPS : `profile` · `key_id` · `ciphertext` → 응답 `shared_secret`(32B).

---

## 부록: NCMP CI와의 주요 차이

| 항목 | PEM CI v4 | NCMP CI ([`command-interface.md`](command-interface.md)) |
|------|------|------|
| 헤더 | 16B (total/session/command/ack) | 20B (session/sequence/command/ack/payload_len) + frame_len |
| 파라미터 | 위치 기반 args(연속) | `param_len[8]` + param0~7 슬롯 |
| 정수 폭 | 헤더 4B / 인자 **8B** | 전부 4B |
| 요청 표식 | ACK=`0x0000FFFF` | ack=`CKR_OK(0)` |
| 배열 정렬 | 8바이트(PAD8) | 4바이트 |
| USB | usbfs 직접, OUT→ZLP→IN | libusb, FX3 Slave-FIFO(NOP 트리거) |
| 키 모델 | 저장 키 ID(1–26)/마스터키/입력키 | 보안키 토큰(인라인 키) |

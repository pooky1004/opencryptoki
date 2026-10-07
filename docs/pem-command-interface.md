# PEM 모듈 — USB Command Interface (CI) 분석

작성일: 2026-10-07 · 분석 대상: `/home/pooky/ji/host` (PEM CI 호스트 SDK)

PEM 토큰(USB `04b4:5054`)으로 데이터를 보내는 **Command Interface(CI v4)** 의
메시지 헤더/메시지 구조를 명령별로 정리한다. opencryptoki 포크의 PEM 모듈
(`ncmp-pem-module` 브랜치) 구현 시 참조한다.

분석 소스:
- 와이어 프로토콜: `ci/cifx_protocol.h` · `ci/cifx_protocol.c`
- USB 전송: `ci/ci_usb_lib.c` · `ci/ci_usb_lib.h`
- 명령 인코딩/고수준 API: `ci/ci_pem_lib.c` · `ci/ci_pem_lib.h`
- 명령 메타데이터(요청/응답 레이아웃): `ci/ci_commands.c`

---

## 1. USB 전송 계층

| 항목 | 값 | 출처 |
|------|-----|------|
| VID | **0x04B4** (Cypress) | `ci_usb_lib.c:58` |
| PID | **0x5054** ("PT") | `ci_usb_lib.c:59` |
| 인터페이스 | 0 | `usbfs_destroy` (iface 0) |
| Bulk OUT 엔드포인트 | **0x01** | `ci_usb_lib.c:265` |
| Bulk IN 엔드포인트 | **0x81** | `ci_usb_lib.c:278` |
| 기본 타임아웃 | 10000 ms (최대 60000) | `ci_usb_lib.c:60,303` |

### 교환(exchange) 흐름 — `usbfs_exchange()`
1. **OUT(0x01)** 로 요청 전송(전체 프레임 1회).
2. 요청 길이가 **max_packet의 배수**이면 **명시적 Zero-Length Packet(ZLP)** 을
   OUT으로 한 번 더 보내 경계를 알림(AUTO DMA short-packet 요구). `ci_usb_lib.c:270`
3. **IN(0x81)** 으로 기대 길이만큼 응답 수신. 펌웨어는 IN ZLP를 붙이지 않으며,
   16바이트짜리 짧은 CI 오류 프레임도 허용한다. `ci_usb_lib.c:276`

요청/응답은 **1:1 단발(single-shot)** 이며, 전송 버퍼는 **4바이트 정렬**로 패딩한다
(아래 §2 전송 정렬).

---

## 2. 메시지 프레이밍 (CI v4)

### 2.0 엔디안 (중요)

**헤더와 메시지(인자) 모두 little-endian(LE)으로 동일하다. 엔디안 차이는 없다.**
둘 사이에 실제로 다른 것은 **엔디안이 아니라 정수 폭**이다 —
**헤더 필드 = 4바이트(u32), 인자 정수 = 8바이트(u64).**

코드 교차 검증(세 곳 모두 LE):

| 영역 | 폭 | 인코딩 | 근거 |
|------|:---:|:---:|------|
| 헤더 필드 | 4 B (u32) | **LE** | `cifx_put_le32` / `cifx_get_le32` (`cifx_protocol.c`) |
| 인자 정수 | 8 B (u64) | **LE** | `put64`/`get64`: `p[i]=n>>(8*i)` (`ci_pem_lib.c`), 주석 "data_len:u64 LE" |
| Python 레퍼런스 | — | **LE** | `struct.pack("<IIII", …)`(헤더), `struct.pack("<Q", …)`(인자) (`tools/ci_console/wire.py`) |

호스트 코드 전체에 big-endian(`>`, `be32/be64`, `htonl`, `bswap`) 사용은 없다.
키·IV·counter·digest·signature 등은 **정수가 아닌 raw 바이트 배열**이므로 엔디안이
적용되지 않고 바이트 순서 그대로 전송된다.

### 2.1 공통 헤더 (16바이트, little-endian · 4바이트 필드)

모든 메시지는 16바이트 헤더로 시작한다(`cifx_build_ci_v4_message`,
`cifx_protocol.c`). **헤더 필드는 4바이트 정수**다.

| 오프셋 | 크기 | 필드 | 의미 |
|:---:|:---:|------|------|
| 0 | 4 | `TOTAL_BYTES` | 헤더+인자의 총 바이트 수(패딩 전 메시지 길이) |
| 4 | 4 | `SESSION_ID` | 세션 핸들(hSession). OPEN 요청은 0 |
| 8 | 4 | `COMMAND` | 명령 코드(§3) |
| 12 | 4 | `ACK` | **요청=`0x0000FFFF`**(`REQ_ACK`), **응답=상태코드**(0=성공) |
| 16 | … | `args` | 명령별 인자(§3) |

- **요청 판별**: `ACK == 0x0000FFFF` 이면 요청, 그 외 값은 응답의 상태코드.
  `ci_pem_lib.c:7` `#define REQ_ACK 0xffff`
- 응답 `ACK`가 0이 아니면 오류(명령 거부/검증 실패 등). GCM 복호화는 이 ACK로
  태그 인증 결과를 확인한다.

### 2.2 인자(args) 인코딩 규칙

`ci_commands.c` 상단 주석 + `ci_pem_lib.c`(`get64`/`put_le64`) 기준:

- **인자 정수는 8바이트(u64) little-endian.** (헤더 4B와 구분 — 혼동 주의)
- **바이트 배열은 8바이트 정렬**: 가변 배열 앞에는 명시적 `*_len`(8B 정수)이 오고,
  배열 뒤에 `PAD8`(0–7바이트 0 패딩)로 8바이트 경계에 맞춘다.
- **고정 길이 배열**(키·digest·signature 등)은 길이 필드 없이 규격 크기로 전송.
- 빈 가변 배열도 길이 필드(예: `aad_len=0`의 8바이트)는 전송한다.

### 2.3 전송 정렬(transfer)

메시지(`TOTAL_BYTES`)를 그대로 보내되, USB 전송 버퍼는 **4바이트 배수**로 올림
패딩한다(`cifx_ci_v4_transfer_size`: `(message_bytes + 3) & ~3`). 추가된 lane은
와이어 의미가 없고 수신측이 검증하지 않는다(GPIF 워드 전송용).

### 2.4 크기 한도

| 항목 | 값 | 출처 |
|------|-----|------|
| 헤더 | 16 B | `CIFX_CI_V4_HEADER_BYTES` |
| 요청 최대 | 65504 B | `CIFX_CI_V4_REQUEST_MAX_BYTES` |
| 응답 최대 | 65520 B | `CIFX_CI_V4_RESPONSE_MAX_BYTES` |

---

## 3. 명령별 Command Interface

명령 코드는 `cifx_protocol.h`, 요청/응답 인자 레이아웃은 `ci_commands.c` 기준.
모든 인자 정수는 **8바이트 LE**, 배열은 **8바이트 정렬(PAD8)**, 고정 배열은 길이
필드 없음. 모든 요청은 공통 16B 헤더(§2.1)로 시작하며 아래 "요청 인자"는 그 뒤에
붙는 부분이다.

### 3.1 시스템 / 세션

#### CAPABILITIES — `0x0001`
- 요청: 추가 인자 없음(헤더 16B만).
- 응답: `api_version`(8B) · `slots`(8B, 물리 슬롯 수) · `mask`(8B, 지원 명령 비트맵).
- 참고: API 버전 7(현행)/6(legacy). `CIFX_CI_API_VERSION`.

#### ECHO — `0x0002`
- 요청/응답 동일: `data_len`(8B) · `data`(data_len B) · `PAD8`.

#### SESSION — `0x0023`
- 요청: `action`(8B · 1=OPEN / 2=CLOSE). OPEN은 헤더 `SESSION_ID=0`, CLOSE는 닫을
  `SESSION_ID`를 헤더에 지정.
- 응답: OPEN → 할당된 `hSession`(8B); CLOSE → 인자 없음(ACK만 확인).

#### KEYTABLE_INFO — `0x0024`
- 요청: 추가 인자 없음.
- 응답: `records_len`(8B, 현재 960) · `records`(30개 × 32B 공개 메타데이터).
  각 record = ID/family/profile/iv_len/key_len/key_offset/flags/reserved(각 4B 정수).
  **키·IV·비밀키 값은 포함하지 않음.**

#### PERF_QUERY — `0x00F0` (진단)
- 요청: `target_hSession`(8B) · `sequence`(8B · 0xFFFFFFFF=최신).
- 응답: PERF v2 고정 304B(8B 정수 38개) — version/slot/hSession/sequence/ordinal/
  event_valid(각 8B) · events 13×8B · counters 19×8B.

### 3.2 AES

공통 열거: `mode` 0=CTR/1=GCM, `direction` 0=암호화/1=복호화.

#### AES_ONESHOT — `0x0116` (키 직접 전달)
- 요청: `mode`(8B) · `direction`(8B) · `key`(고정 32B, AES-256)
  - CTR: `iv`(고정 16B)
  - GCM: `iv_len`(8B)·`iv`(12 또는 16B)·PAD8, `aad_len`(8B)·`aad`·PAD8(빈 AAD도 len=0 전송)
  - 공통: `data_len`(8B)·`data`·PAD8
  - GCM 복호화: 끝에 `tag`(고정 16B)
- 응답: `data_len`(8B)·`data`(암호문 또는 평문)·PAD8; GCM 암호화면 `tag`(16B) 추가.

#### AES_MASTER_KEY — `0x0117` (마스터 키 버전 사용)
- 요청: `mode`·`direction`·`master_key_version`(8B, 저장 키 ID와 별도) + AES_ONESHOT과
  동일한 IV/AAD/data/tag 구성.
- 응답: AES_ONESHOT과 동일.

#### AES_KEY_ID — `0x0118` (저장 키/IV 사용)
- 요청: `mode`·`direction`·`key_id`(8B · CTR=홀수 1–19 / GCM=짝수 2–20). **KEY·IV 미전송**
  (선택된 저장 키·IV 사용). GCM이면 `aad_len`·`aad`·PAD8, 공통 `data_len`·`data`·PAD8,
  GCM 복호화면 `tag`(16B).
- 응답: AES_ONESHOT과 동일.

#### AES_CONTEXT — `0x0120` (단발/멀티파트 통합)
- 요청: `action`(8B · 0=ONESHOT/1=INIT/2=UPDATE/3=FINAL/4=ABORT) · `direction`(8B) ·
  `mode`(8B) · `key_id`(8B · 0=입력 key/IV) · `flags`(8B · 0=일반/1=GCM AAD UPDATE)
  - action 0 또는 1: `key`(32B); CTR `iv`(16B) / GCM `iv_len`·`iv`·PAD8
  - action 0 & GCM: `aad_len`·`aad`·PAD8
  - action 0 또는 2: `data_len`·`data`·PAD8
  - action 0 또는 3 & GCM 복호화: `tag`(16B)
- 응답: ONESHOT → data(+GCM 암호화 tag 16B); UPDATE → data(AAD UPDATE는 인자 없음);
  FINAL → GCM 암호화 tag 16B / 그 외 없음; INIT/ABORT → 없음.

#### AES-CTR 멀티파트
- **AES_CTR_INIT `0x0130`**: `key_id`(8B · 0=입력) · `direction`(8B) · `key`(32B) · `iv`(16B).
  (API7 `key_id>0`이면 key·iv 자리에 0을 보내고 저장 키 사용) → 응답 인자 없음.
- **AES_CTR_UPDATE `0x0131`**: `key_id`(8B) · `data_len`(8B)·`data`·PAD8 (`data_len≥1`)
  → 응답 `data_len`·`data`·PAD8.
- **AES_CTR_FINAL `0x0132`**: `key_id`(8B) → 응답 인자 없음.

#### AES-GCM 멀티파트
- **AES_GCM_INIT `0x0133`**: `key_id`(8B · 0=입력) · `direction`(8B) · `key`(32B) ·
  `iv_len`·`iv`·PAD8 · `aad_len`·`aad`·PAD8 (없으면 len=0). API7 `key_id>0`이면 key·iv에 0.
  → 응답 인자 없음.
- **AES_GCM_UPDATE `0x0134`**: `key_id`(8B) · `data_len`·`data`·PAD8 (`data_len≥1`)
  → 응답 `data_len`·`data`·PAD8.
- **AES_GCM_FINAL `0x0135`**: `key_id`(8B) · [GCM 복호화만] `tag`(16B)
  → 응답: 암호화면 `tag`(16B), 복호화면 인자 없음(ACK로 인증 결과 확인).

### 3.3 SHA3

#### 단발(one-shot)
- **SHA3_256 `0x0310`** / **SHA3_384 `0x0311`** / **SHA3_512 `0x0312`**
  - 요청: `data_len`(8B)·`data`·PAD8
  - 응답: `digest`(고정 32 / 48 / 64B, 길이 필드 없음)

#### 멀티파트(INIT/UPDATE/FINAL)
- **INIT** `0x0340`(256)/`0x0343`(384)/`0x0346`(512): 요청·응답 인자 없음.
- **UPDATE** `0x0341`/`0x0344`/`0x0347`: `data_len`(8B)·`data`·PAD8 (`data_len≥1`) → 응답 없음.
- **FINAL** `0x0342`/`0x0345`/`0x0348`: 요청 인자 없음 → 응답 `digest`(32/48/64B).

### 3.4 PQC — ML-DSA

프로파일별 고정 크기(길이 필드 없음):

| profile | public_key | secret_key | signature |
|:---:|:---:|:---:|:---:|
| 44 | 1312 | 2560 | 2420 |
| 65 | 1952 | 4032 | 3309 |
| 87 | 2592 | 4896 | 4627 |

- **MLDSA_KEYGEN `0x0050`**: 요청 `profile`(8B) → 응답 `public_key` · `secret_key`.
- **MLDSA_SIGN `0x0051`**: 요청 `profile` · `message_len`·`message`·PAD8 · `secret_key`
  → 응답 `signature` · PAD8.
- **MLDSA_VERIFY `0x0052`**: 요청 `profile` · `message_len`·`message`·PAD8 · `signature`·PAD8
  · `public_key` → 응답 인자 없음(ACK로 검증 결과).
- **MLDSA_SIGN_KEY_ID `0x005A`**: 요청 `profile` · `key_id`(8B · 21/22/23) ·
  `message_len`·`message`·PAD8 → 응답 `signature`·PAD8. (저장 키 사용, secret_key 미전송)
- **MLDSA_VERIFY_KEY_ID `0x005B`**: 요청 `profile` · `key_id`(21/22/23) ·
  `message_len`·`message`·PAD8 · `signature`·PAD8 → 응답 없음.

### 3.5 PQC — ML-KEM

프로파일별 고정 크기(길이 필드 없음), `shared_secret`은 항상 32B:

| profile | public_key | secret_key | ciphertext |
|:---:|:---:|:---:|:---:|
| 512 | 800 | 1632 | 768 |
| 768 | 1184 | 2400 | 1088 |
| 1024 | 1568 | 3168 | 1568 |

- **MLKEM_KEYGEN `0x0053`**: 요청 `profile`(8B) → 응답 `public_key` · `secret_key`.
- **MLKEM_ENCAPS `0x0054`**: 요청 `profile` · `public_key` → 응답 `ciphertext` · `shared_secret`(32B).
- **MLKEM_DECAPS `0x0055`**: 요청 `profile` · `ciphertext` · `secret_key` → 응답 `shared_secret`(32B).
- **MLKEM_ENCAPS_KEY_ID `0x005C`**: 요청 `profile` · `key_id`(8B · 24/25/26) → 응답 `ciphertext` · `shared_secret`.
- **MLKEM_DECAPS_KEY_ID `0x005D`**: 요청 `profile` · `key_id`(24/25/26) · `ciphertext` → 응답 `shared_secret`.

---

## 4. 상태 / ACK 코드

- **응답 ACK**: 0=성공, 0이 아니면 오류(명령 거부·검증 실패 등). GCM 복호화/ML-DSA
  검증은 이 ACK로 인증·검증 결과를 판단한다.
- **라이브러리 상태코드**(`enum cifx_status`, `cifx_protocol.h`): `CIFX_OK(0)`,
  `CIFX_ERR_ARGUMENT(-1)`, `CIFX_ERR_CAPACITY(-2)`, `CIFX_ERR_FORMAT(-3)`,
  `CIFX_ERR_RANGE(-4)`, `CIFX_ERR_UNSUPPORTED(-5)` — 호스트 측 인코딩/파싱 오류.

---

## 5. 세션 · 키 ID 참고

- **세션**: SESSION(OPEN)으로 `hSession` 할당 → 이후 모든 요청 헤더 `SESSION_ID`에 사용 →
  SESSION(CLOSE)로 반납. 상세 매핑은 `docs/KEY_HANDLE_ID.md`, `share/pem_memory_map.json`.
- **저장 키 ID 요약**(명령 테이블 기준):
  - AES: CTR=홀수 1–19, GCM=짝수 2–20 (`AES_KEY_ID`)
  - ML-DSA: 21/22/23 (44/65/87), ML-KEM: 24/25/26 (512/768/1024)

---

## 6. 명령 요약표

| 코드 | 이름 | 분류 |
|:---:|------|------|
| 0x0001 | CAPABILITIES | system |
| 0x0002 | ECHO | system |
| 0x0023 | SESSION | session |
| 0x0024 | KEYTABLE_INFO | keys |
| 0x00F0 | PERF_QUERY | diagnostic |
| 0x0050/0x0051/0x0052 | MLDSA_KEYGEN/SIGN/VERIFY | ML-DSA |
| 0x005A/0x005B | MLDSA_SIGN/VERIFY_KEY_ID | ML-DSA |
| 0x0053/0x0054/0x0055 | MLKEM_KEYGEN/ENCAPS/DECAPS | ML-KEM |
| 0x005C/0x005D | MLKEM_ENCAPS/DECAPS_KEY_ID | ML-KEM |
| 0x0116 | AES_ONESHOT | AES |
| 0x0117 | AES_MASTER_KEY | AES |
| 0x0118 | AES_KEY_ID | AES |
| 0x0120 | AES_CONTEXT | AES |
| 0x0130/0x0131/0x0132 | AES_CTR_INIT/UPDATE/FINAL | AES |
| 0x0133/0x0134/0x0135 | AES_GCM_INIT/UPDATE/FINAL | AES |
| 0x0310/0x0311/0x0312 | SHA3_256/384/512 (one-shot) | SHA3 |
| 0x0340–0x0348 | SHA3_256/384/512 INIT/UPDATE/FINAL | SHA3 |

> 참고: 이 토큰의 CI v4는 opencryptoki NCMP 토큰(`04b4:00f1`)의 와이어 포맷과 **다르다**
> (NCMP는 20B 헤더 + param_len[8] 배열, 정수 4B). PEM은 16B 헤더 + 8B 정수 인자 모델이다.
> PEM 모듈은 이 CI v4 규약에 맞춘 별도 transport/adapter가 필요하다.

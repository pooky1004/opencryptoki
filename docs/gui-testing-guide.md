# NCMP GUI 시험 가이드

모의 HSM GUI와 테스트 App GUI로 NCMP 토큰을 **어떻게 실행·설정하고, 각 메뉴가 무슨
용도이며, 어떤 시험을 할 때 무엇을 실행/설정해야 하는지**를 단계별로 설명한다.

- 도구 개요·아키텍처: [`gui-tools-status.md`](gui-tools-status.md)
- 빌드/설치 요약: [`../ncmp/gui/README.md`](../ncmp/gui/README.md)
- 명령(CI) 규격: [`command-interface.md`](command-interface.md)

---

## 0. 구성 요소와 관계

```
┌──────────────┐  control(JSON, 7000)   ┌──────────────────────────────┐
│ Mock HSM GUI │◀──────────────────────▶│ mock_server (C)              │
│ (mock_gui.py)│                        │  slot0 → 127.0.0.1:7010      │
└──────────────┘                        │  slot1 → 127.0.0.1:7011 …    │
┌──────────────┐  data(wire frame)      │  (또는 hsm_bridge = 실 FX3)  │
│ Test App GUI │◀──────────────────────▶│                              │
│ (app_gui.py) │   127.0.0.1:(7010+slot)└──────────────────────────────┘
└──────────────┘
```

- **mock_server**: 에뮬레이트 토큰(최대 4슬롯). **control 포트**(기본 7000)로 상태를
  조회/설정하고, 슬롯별 **data 포트**(기본 base=7010, `base+slot`)로 명령(wire 프레임)을
  주고받는다.
- **hsm_bridge**: 같은 프로토콜이지만 백엔드가 실 USB 토큰. App GUI가 `target=real`로 붙는다.
- **Mock HSM GUI**: control 포트로 mock_server를 관리·감시(정체성/통계/디버그/링크).
- **Test App GUI**: data 포트로 토큰에 명령을 보내 시험(암복호·해시·PQC·파일비교·시나리오).

> **핵심 규약**: App GUI는 **`데이터 포트 = 서버 base 포트 + slot`** 으로 접속한다.
> 예) 서버 `--data-port 7010`, 슬롯 1 시험 → App에서 **port=7010, slot=1** (실접속 7011).
> 슬롯당 **동시 데이터 연결은 1개**만 허용된다(두 번째 App 연결은 거부).

---

## 1. 사전 준비 (최초 1회)

### 1.1 서버 빌드 (C)
CMake:
```bash
cd ncmp && cmake -S . -B build && cmake --build build -j
# → build/gui/mock_server, build/gui/hsm_bridge
```
CMake 없이(gcc)면 [`../ncmp/gui/README.md`](../ncmp/gui/README.md) 참고.

### 1.2 Python 의존성
```bash
cd ncmp/gui/py
python3 -m pip install -r requirements.txt      # PySide6 (+ cryptography)
```

### 1.3 창 표시(xcb) 준비
- 정식: `sudo apt install libxcb-cursor0`
- 비-root/헤드리스 우회는 README의 "창 표시 요구사항" 절 참고
  (`Qt/lib` 복사 방식 또는 `LD_LIBRARY_PATH`, 그리고 `QT_QPA_PLATFORM=offscreen` 폴백).
- 원격 접속이면 `ssh -X`(또는 `-Y`)로 `DISPLAY`가 설정돼 있어야 창이 뜬다.

---

## 2. 표준 실행 순서

```bash
# ① 서버 (예: 슬롯 2개)
./build/gui/mock_server --slots 2 --data-port 7010 --ctrl-port 7000

# ② 모의 HSM GUI (서버를 관리·감시)
cd ncmp/gui/py && python3 mock_gui.py

# ③ 테스트 App GUI (토큰에 명령 전송)
cd ncmp/gui/py && python3 app_gui.py
```
- ②의 **Start** 버튼으로 GUI가 서버를 직접 띄울 수도 있다(별도 ①을 안 띄워도 됨).
- 실 하드웨어면 ① 대신 `./build/gui/hsm_bridge --data-port 7010 --ctrl-port 7000`,
  App GUI에서 **target=real**.

**두 가지 구동 방식**:
- **프레임 링크 모드**(기본, 위 ①~③): App이 토큰에 **wire 프레임을 직접** 보냄. 전체
  CI(벤더·세션·fail-bit 포함) 시험 가능.
- **실 PKCS#11 스택 모드**: App이 **libopencryptoki(C_*)** → STDLL → ncmpd(소켓 전송) →
  mock_server 로 **실제 스택**을 구동. App GUI의 **"PKCS#11 (real stack)" 탭** 사용(§4.7).
  ncmpd를 `-DENABLE_SOCKET_TOKEN=ON`으로 빌드·기동해야 하며, 레시피는
  [`app-stdll-path-design.md`](app-stdll-path-design.md).

---

## 3. 모의 HSM GUI (`mock_gui.py`) 상세

용도: **mock_server를 실행/부착하고, 슬롯별로 정체성·통계·디버그·링크를 관리**.

### 3.1 상단 "Server" 바
| 항목 | 용도 |
|------|------|
| **bin** | `mock_server` 실행 파일 경로(자동 탐색; `…` 버튼으로 지정). |
| **slots** | Start 시 띄울 슬롯 수(1~4). |
| **ctrl** | control 포트(기본 7000). |
| **data** | data base 포트(기본 7010; 슬롯 s는 7010+s). |
| **Start** | 위 설정으로 서버 프로세스를 **직접 실행**하고 Attach. |
| **Attach** | 이미 떠 있는 서버의 control 포트에 **연결만** 함. |
| **Stop** | (Start로 띄운) 서버를 종료하고 연결 해제. |

> 외부 터미널에서 이미 서버를 띄웠다면 **Attach**만 누르면 된다(ctrl 포트를 맞춘 뒤).

### 3.2 좌측 슬롯 목록 / 우측 슬롯 탭
슬롯을 고르면 우측에 해당 슬롯 패널이 나온다. 상단에 슬롯 번호와 data 포트를 표시.

### 3.3 "Host link" 박스 (슬롯별)
| 버튼/표시 | 용도 |
|------|------|
| **link / connected** 표시 | 링크 up/down 상태, App 연결 여부. 0.6초마다 갱신. |
| **Link Up** | 슬롯의 데이터 링크 수신을 허용. |
| **Link Down** | 링크를 내리고 **현재 App 연결을 강제 절단**(장애 주입 시험용). |
| **Reset** | 통계·디버그 링·장치 상태(키/컨텍스트)를 초기화(정체성·PIN은 유지). |

### 3.4 "Identity" 탭 — 토큰 정보 입력/조회/수정
필드: **Label / Serial / Manufacturer / Model / HW version(major.minor) /
FW version(major.minor) / Flags(u32) / UTC(16자) / Login state(읽기전용)**.
- **Reload**: 서버에서 현재 값을 다시 읽어옴.
- **Apply**: 편집한 값을 서버(해당 슬롯)에 적용.
> 변경한 정체성은 App GUI의 **HSM State → Token Info / Token Params**로 확인된다.
> (실 hsm_bridge에서는 정체성 편집 미지원 — 토큰이 소유.)

### 3.5 "Statistics" 탭 — 슬롯 통계(라이브)
| 항목 | 의미 |
|------|------|
| requests / responses | 수신한 요청 / 반환한 응답 프레임 수. |
| bytes_in / bytes_out | 요청/응답 누적 바이트. |
| errors | 파싱·실행·인코딩 실패 수. |
| connects | 데이터 링크 연결 횟수. |
| in_flight / max_in_flight | 현재 처리 중 / 역대 최대 동시 처리 수. |
| last_opcode | 최근 요청 opcode(이름+코드). |

### 3.6 "Debug" 탭 — 현재/처리된 메시지 추적
최근 메시지(최대 128건)를 표로 표시: **time · opcode · session · seq · ack · req(바이트)
· rsp(바이트)**. 실패 ack는 빨간색. 어떤 명령이 오갔는지·실패했는지 실시간 관찰용.

---

## 4. 테스트 App GUI (`app_gui.py`) 상세

용도: **슬롯을 골라 토큰에 명령을 보내 기능을 시험**하고 결과를 SW 기준과 비교·집계.

### 4.1 상단 "Link" 바
| 항목 | 용도 |
|------|------|
| **host** | 서버 주소(기본 127.0.0.1). |
| **port** | 서버 **base** 데이터 포트(기본 7010). |
| **slot** | 시험할 슬롯(실접속 포트 = port + slot). |
| **target** | `mock` 또는 `real (bridge)`. SW 비교 기준을 좌우(§4.4). |
| **Connect / Disconnect** | 데이터 링크 연결/해제. 오른쪽 점: 초록=연결, 빨강=미연결. |

> **연결이 거부되면**: 해당 슬롯이 Link Down 상태이거나, 다른 App이 이미 그 슬롯에
> 연결돼 있는 경우다(슬롯당 1연결).

### 4.2 "HSM State" 탭 — 상태 조회/설정
- **Queries**: `Ping`(epoch), `Selftest`(status=0), `FW Info`(버전),
  `Token Info`(정체성 블롭), `Token Params`(label/serial/min·maxPIN), `Get UTC`(시각).
  → 결과는 아래 콘솔에 출력.
- **Admin / login**:
  - **Login**: 역할(USER/SO) + PIN 입력 후 로그인(mock 기본 PIN: user `1234`, SO `12345678`).
  - **Logout**.
  - **Set PIN**: old→new PIN 변경.
  - **Init Token**: SO PIN + 라벨로 토큰 초기화.
- **Session (CI 0x003A/0x003B)**: `pid`+`sid`로 **Open** → 토큰이 발급한 **HSM SID(1~255)**
  표시, 그 HSM SID로 **Close**. (PID+SID→HSM SID 매핑은
  [`session-id-mapping.md`](session-id-mapping.md).)

### 4.3 "Crypto / Hash" 탭 — 암복호/해시 시험 (+ SW 비교)
| 그룹 | 설정 | 동작/확인 |
|------|------|-----------|
| **RNG** | bytes 수 | 난수 생성. mock이면 결정론 복제본과 일치 표시. |
| **Digest** | mech(SHA-256/512, SHA3-*) + 입력 텍스트 | 해시 계산 후 **SW 기준과 EQUAL/DIFFERENT** 표시. |
| **AES-CTR** | key(hex)/iv(hex)/data | 암호화→복호화 **왕복**, ct가 복제본과 일치·복호 OK 확인. |
| **AES-GCM** | key/iv/aad(hex)/data | one-shot 암복호 왕복(ct∥tag), **tag 검증** 확인. |
> key/iv는 **16진수**로 입력한다(AES-CTR 예시 key=32바이트=64hex, iv=16바이트=32hex).

### 4.4 "PQC" 탭 — 포스트양자 시험
- **ML-DSA**: Parameter set(44/65/87) + 메시지 → **keygen→sign→verify**, 그리고
  **위조 메시지 거부**(SIGNATURE_INVALID)까지 한 번에. 단계별 크기/ack/`RESULT: PASS`.
- **ML-KEM**: Parameter set(512/768/1024) → **keygen→encapsulate→decapsulate**,
  **공유비밀 일치(YES)** 확인.
> mock은 크기만 맞으면 결정론적으로 왕복하는 에뮬레이션이라 실제 ML-DSA/ML-KEM 값과는
> 다르다(정합성이 아니라 **경로/왕복** 검증). 실 토큰이면 진짜 값.

### 4.5 "File Compare" 탭 — 1MB+ 파일 SW 비교
| 항목 | 용도 |
|------|------|
| **File / Browse…** | 시험할 파일 선택. |
| **Make 1MB test file** | 약 1.25MB 테스트 파일 생성. |
| **Operation** | `Digest (streaming, multipart)` 또는 `AES-CTR (chunked)`. |
| **Digest mech** | digest 모드에서 사용할 해시. |
| **Run & Compare** | 파일을 청크로 토큰에 흘려 처리하고 SW 기준과 비교(진행바). |
| 결과 | `IDENTICAL ✓/DIFFERENT ✗`, 크기, 시간, **MB/s**, (AES-CTR) 청크 불일치/왕복 실패 수. |

- **Digest 모드**: 파일 전체를 멀티파트로 스트리밍. mock=복제본, **real=`hashlib` 실측**과
  비교 → 실 토큰이면 **암호 정합성**까지 검증.
- **AES-CTR 모드**: 청크별 one-shot 암호화(청크마다 키스트림 리셋). **mock 데이터패스**
  검증용(연속 CTR이 아니므로 real 기준 비교는 부적합 — 안내 문구 표시).

### 4.6 "Scenarios" 탭 — 내장 시나리오 일괄 시험
드롭다운에서 고르고 **Run scenario** → step별 PASS/FAIL 표.
| 시나리오 | 내용 |
|----------|------|
| Smoke | ping·selftest·RNG·SHA-256(복제본 일치). |
| Admin lifecycle | login(정상)·login(거부)·logout·token params. |
| Crypto round-trips | AES-CTR 왕복·멀티파트 digest 시작. |
| PQC round-trips | ML-DSA sign/verify(+위조), ML-KEM 공유비밀 일치. |
> **주의(순서)**: Admin 시나리오는 **로그아웃 상태에서** 실행해야 1단계 login이
> 성공한다. 직전에 HSM State에서 로그인해 두면 "이미 로그인"으로 1단계가 실패(FAIL)
> 표시될 수 있다 — 먼저 Logout 후 실행.

### 4.7 "PKCS#11 (real stack)" 탭 — 실 스택 구동
프레임 링크와 **독립**으로, App이 **libopencryptoki(C_*)** 를 통해 실제 STDLL→ncmpd→
USB/소켓 스택을 구동한다(표준 `C_*`로 표현 가능한 연산만).
| 항목 | 용도 |
|------|------|
| module (.so) | `libopencryptoki.so` 경로(기본 `$PKCS11_MODULE`). **Browse…** 로 파일 선택 가능. |
| slot / PIN | PKCS#11 슬롯·사용자 PIN. |
| Load+Open / Login / Logout / Close | 모듈 로드+세션 열기 / 로그인 / 로그아웃 / 닫기. |
| GenerateRandom · Digest · AES-GCM round-trip · Token Info | `C_*` 연산 버튼. |
> **전제**: `pip install PyKCS11` + 빌드된 opencryptoki + 기동된 ncmpd. 설정·레시피는
> [`app-stdll-path-design.md`](app-stdll-path-design.md). 벤더 datapath·세션 CI·fail-bit는
> 이 탭에 없다(프레임 링크 모드에서 시험).
> **아직 빌드 전이면**: 모듈 미설정/세션 없음 상태에서 버튼을 누르면 탭이
> **프레임 링크 모드(상단 Link 바, target=mock)로 시험하라**고 안내한다 — 지금 mock을
> 시험할 때는 이 탭 대신 상단 Link 바로 Connect 후 다른 탭을 쓰면 된다.

### 4.8 "Statistics" 탭 — 세션 통계
App이 보낸 명령을 **opcode별**로 집계: count / ok / fail / bytes_in / bytes_out /
avg_ms. **Refresh**로 갱신, **Clear**로 초기화.

---

## 5. 시험별 "무엇을 실행/설정" 요리책

### 5.1 토큰 정보(정체성) 조회·변경 시험
1. `mock_server`(또는 Mock GUI Start) → Mock GUI **Attach**.
2. Mock GUI **Identity** 탭에서 Label/Serial 등 수정 → **Apply**.
3. App GUI **Connect**(같은 슬롯) → **HSM State → Token Info / Token Params**로 변경 확인.

### 5.1b 세션 매핑(OpenSession/CloseSession) 시험
1. App **Connect**.
2. **HSM State → Session**: pid(자동)·sid 입력 → **Open** → HSM SID(1~255) 확인.
3. 같은 pid·sid로 다시 Open → 같은 HSM SID(멱등). sid를 바꿔 Open → 다른 HSM SID.
4. 표시된 HSM SID로 **Close** → CKR_OK, 재Close → CKR_SESSION_HANDLE_INVALID.

### 5.2 로그인 / PIN 시험
1. App **Connect**.
2. **HSM State → Login**(USER, `1234`) → ack=CKR_OK 확인.
3. **Set PIN**(old `1234` → new `5678`) → 다시 Login으로 확인. **Logout**.
4. 실패 확인: 틀린 PIN으로 Login → PIN_INCORRECT류 ack.

### 5.3 해시 정합성 시험
1. App **Connect**, target=mock.
2. **Crypto/Hash → Digest**: mech 선택 + 입력 → **EQUAL** 확인(복제본 대비).
3. (실 토큰) target=real로 두면 `hashlib` 실측과 비교.

### 5.4 대칭 암복호 왕복 시험
1. **Crypto/Hash → AES-CTR**: key/iv(hex)·data 입력 → **Encrypt+Decrypt** →
   ct 복제본 일치 + 복호 OK 확인.
2. **AES-GCM**도 동일하게 → tag 검증 OK 확인.

### 5.5 PQC 서명/키합의 시험
1. **PQC → ML-DSA**: set 선택 + 메시지 → **Run ML-DSA round-trip** → `RESULT: PASS`.
2. **PQC → ML-KEM**: set 선택 → **Run ML-KEM round-trip** → shared secret match YES.

### 5.6 대용량 파일 데이터패스/정합성 시험
1. **File Compare → Make 1MB test file**(또는 Browse).
2. Operation=Digest, mech 선택 → **Run & Compare** → **IDENTICAL ✓** + MB/s 확인.
3. AES-CTR(mock) 데이터패스도 동일 절차로 불일치=0 확인.

### 5.7 링크 단절/복구(장애) 시험
1. App **Connect** 후 명령 하나 전송(정상 확인).
2. Mock GUI 해당 슬롯 **Link Down** → App에서 다음 명령 전송 시 링크 절단(오류) 관찰.
3. Mock GUI **Link Up** → App **Connect** 재시도 → 정상 복구.
4. Mock GUI **Statistics/Debug**에서 errors 증가·이벤트 확인.

### 5.8 다중 슬롯 / 다중 프로세스(파이프라인) 시험
1. 서버를 `--slots 2`(이상)로 실행.
2. App 인스턴스 A: slot 0 Connect / App 인스턴스 B: slot 1 Connect(다른 슬롯이므로 동시 가능).
3. 각자 File Compare나 시나리오를 돌리며 Mock GUI의 슬롯별 통계/`max_in_flight` 관찰.
> 같은 슬롯에 두 App을 붙이면 두 번째는 거부된다(슬롯당 1연결).

### 5.9 통계/디버그 관찰
- Mock GUI: 슬롯별 **Statistics**(서버 관점)·**Debug**(메시지 흐름).
- App GUI: **Statistics**(내가 보낸 명령의 opcode별 지연/성공률).

### 5.10 실 HSM(브리지)로 전환
1. `mock_server` 대신 `./build/gui/hsm_bridge --data-port 7010 --ctrl-port 7000`.
2. App GUI **target=real**, host/port/slot 설정 → **Connect**.
3. 상태·암호·파일(Digest는 `hashlib`와 정합성 비교) 시험.
> libusb + FX3 하드웨어가 없으면 브리지는 기동되지만 데이터 명령은 device 오류를 돌려준다.

---

## 6. 트러블슈팅

| 증상 | 원인 / 해결 |
|------|-------------|
| `Could not load the Qt platform plugin "xcb"` | `libxcb-cursor0` 필요 → §1.3 / README. 임시로 `QT_QPA_PLATFORM=offscreen`. |
| App **Connect 실패** | 서버 미기동, 포트 불일치(`port+slot` 확인), 또는 해당 슬롯 Link Down. |
| 두 번째 App 연결이 안 됨 | 슬롯당 데이터 연결 1개 — 다른 슬롯을 쓰거나 기존 연결 해제. |
| Admin 시나리오 1단계 FAIL | 직전 로그인 상태 — 먼저 **Logout** 후 실행(§4.6 주의). |
| AES-CTR 파일비교가 real에서 불일치 | 청크별 CTR 리셋이라 real 연속 CTR과 다름 — real은 **Digest 모드** 사용. |
| `bind: Address already in use` | 이전 서버가 포트 점유 — 종료 후 재실행하거나 다른 포트 사용. |
| Mock GUI 값이 안 갱신 | Attach 여부/ctrl 포트 확인. 폴링 주기 0.6초. |

---

## 7. 부록

### 7.1 포트 규약
- control(JSON): 기본 **7000**.
- data(wire frame): 기본 base **7010**, 슬롯 s → **7010+s**.
- App 접속 포트 = **base + slot**.

### 7.2 지원 메커니즘(광고 표면)
AES-GCM/CTR · SHA-256/512 · SHA3-224/256/384/512 · SHAKE-128/256(KDF) ·
ML-KEM(512/768/1024) · ML-DSA(44/65/87) · RNG · AES 키생성. 그 외(RSA/EC/DH/HMAC/
AES-블록 등)는 미지원.

### 7.3 mock vs real (SW 비교의 의미)
- **mock**: 결정론적 에뮬레이션(진짜 암호 아님). SW 기준=에뮬레이터 알고리즘 복제 →
  **프레이밍/청킹/마샬링(데이터패스)** 정합성 검증.
- **real(hsm_bridge)**: 실제 암호. Digest는 `hashlib` 실측과 비교해 **암호 정합성** 검증.

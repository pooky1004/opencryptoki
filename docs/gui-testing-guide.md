# NCMP GUI 시험 가이드

모의 HSM GUI와 테스트 App GUI로 NCMP 토큰을 **어떻게 실행·설정하고, 각 메뉴가 무슨
용도이며, 어떤 시험을 할 때 무엇을 실행/설정해야 하는지**를 단계별로 설명한다.

- 도구 개요·아키텍처: [`gui-tools-status.md`](gui-tools-status.md)
- 빌드/설치 요약: [`../ncmp/gui/README.md`](../ncmp/gui/README.md)
- 이중 모드(STDLL/독립): [`dual-mode-provider.md`](dual-mode-provider.md)
- CI 규격: [`command-interface.md`](command-interface.md) · 세션 매핑:
  [`session-id-mapping.md`](session-id-mapping.md)

---

## 0. 두 가지 시험 경로

NCMP는 두 방식으로 시험한다. 목적에 따라 하나를 고른다.

### 경로 A — 프레임 링크 (기본, 가장 간단)
App GUI가 토큰 서버에 **wire 프레임을 직접** 보낸다. ncmpd·STDLL 없이 전체 CI(벤더
datapath·세션 CI·fail-bit 포함)를 자유롭게 시험. **하드웨어·빌드 최소**.
```
 Mock HSM GUI ─ control(JSON,7000) ─▶ mock_server (C)  ◀─ data(wire frame) ─ Test App GUI
                                       slot s → 127.0.0.1:(7010+s)            (Link 바)
                                       (또는 hsm_bridge = 실 FX3)
```

### 경로 B — 실 PKCS#11 스택 (모드 2)
App GUI가 **`libpkcs11_ncmp.so`를 직접 dlopen+dlsym** 하여 표준 `C_*`를 호출한다. 호출은
STDLL 파사드 → **ncmpd** → (comm thread) → 대상으로 흐른다. 대상은 ncmpd의
**`--transport real|mock|socket`**(기본 real)이 결정한다.
```
 Test App GUI(PKCS#11 탭) ─ dlopen/dlsym C_* ─▶ libpkcs11_ncmp.so(파사드)
        │                                              │ ncmp_client → IPC+SHM
        ▼                                              ▼
   (C_Initialize)                                    ncmpd ──comm thread──▶ 대상
                                                      --transport real   → 실 FX3(USB)
                                                      --transport mock   → 내장 에뮬레이터
                                                      --transport socket → mock_server
 Mock HSM GUI ─ control ─▶ mock_server  ◀── (socket) ──┘  (socket일 때 같은 mock 모니터)
```
> **경로 B에서 Mock HSM GUI의 역할**: ncmpd를 `--transport socket`으로 띄우면 comm
> thread가 **Mock GUI가 관리하는 mock_server**와 연동되어, GUI의 슬롯 패널로 실시간
> 트래픽을 모니터할 수 있다. `--transport mock`(내장 에뮬레이터)은 외부 모니터 대상이
> 아니다. `--transport real`은 실 HSM이라 mock 모니터가 없다.

### 핵심 규약
- **경로 A 접속 포트 = 서버 base 포트 + slot** (예: base 7010, slot 1 → 7011).
- **슬롯당 동시 데이터 연결 1개** (두 번째 연결은 거부).
- **ncmpd는 한 번만** 띄운다. Mock GUI의 *ncmpd 그룹* 또는 App GUI의 *PKCS#11 탭
  autostart* 중 한 곳에서 시작(둘 다 같은 `NCMP_SOCK_PATH`를 쓰면 됨). 모니터까지
  원하면 **Mock GUI에서 `mock(socket)`으로 띄우는 것**을 권장.

---

## 1. 사전 준비 (최초 1회)

### 1.1 바이너리 빌드 (C)
CMake(권장) — mock_server·hsm_bridge·ncmpd(전 백엔드)를 한 번에:
```bash
cd ncmp && cmake -S . -B build && cmake --build build -j
# → build/gui/mock_server, build/gui/hsm_bridge, build/daemon/ncmpd
```
풀빌드 없이 경로 B만 빠르게(모드 2 전용 provider + ncmpd):
```bash
sh ncmp/gui/build_standalone_p11.sh     # → ncmp/gui/build-standalone/{libpkcs11_ncmp_p11.so, ncmpd}
```
gcc 수동 빌드는 [`../ncmp/gui/README.md`](../ncmp/gui/README.md) 참고.

### 1.2 Python 의존성
```bash
cd ncmp/gui/py && python3 -m pip install -r requirements.txt   # PySide6 (+ cryptography)
```
(경로 B의 App PKCS#11 탭은 **ctypes만** 쓰므로 PyKCS11 불필요.)

### 1.3 창 표시(xcb)
- 정식: `sudo apt install libxcb-cursor0`
- 비-root/헤드리스 우회(`Qt/lib` 복사 또는 `LD_LIBRARY_PATH`, `QT_QPA_PLATFORM=offscreen`):
  README "창 표시 요구사항" 절. 원격이면 `ssh -X`/`-Y`로 `DISPLAY` 필요.

---

## 2. 실행 순서

### 2.A 경로 A (프레임 링크)
```bash
# ① 토큰 서버 (슬롯 2개)
./build/gui/mock_server --slots 2 --data-port 7010 --ctrl-port 7000
#   실 하드웨어면 대신: ./build/gui/hsm_bridge --data-port 7010 --ctrl-port 7000
# ② 모의 HSM GUI (관리/모니터)
cd ncmp/gui/py && python3 mock_gui.py
# ③ 테스트 App GUI (Link 바 target=mock 또는 real(bridge) → Connect)
cd ncmp/gui/py && python3 app_gui.py
```
- ②의 **Start** 버튼으로 mock_server를 GUI가 직접 띄울 수도 있다(①생략 가능).

### 2.B 경로 B (실 PKCS#11 스택 / 모드 2)
```bash
export NCMP_SOCK_PATH=/tmp/ncmpd.sock          # ncmpd IPC 소켓(클라이언트와 공유)
# ① mock_server (comm thread가 붙을 mock) — socket 대상일 때
./build/gui/mock_server --slots 2 --data-port 7010 --ctrl-port 7000
# ② Mock GUI에서 mock_server Attach 후, ncmpd 그룹 transport=mock(socket)으로 Start ncmpd
#    (또는 수동: NCMP_SOCKET_PORT_BASE=7010 NCMP_SOCKET_SLOTS=2 ./build/daemon/ncmpd --transport socket)
# ③ App GUI "PKCS#11 (real stack)" 탭 → module=libpkcs11_ncmp.so → Load+Open → C_* 시험
cd ncmp/gui/py && NCMP_PKCS11_MODULE=$PWD/../build-standalone/libpkcs11_ncmp_p11.so python3 app_gui.py
```
- 실 하드웨어면 ①②를 생략하고 ncmpd를 **기본(`--transport real`)** 으로 띄운다.
- ncmpd를 App 탭에서 autostart 시킬 수도 있다(§4.8의 ncmpd 진단/실행).

---

## 3. 모의 HSM GUI (`mock_gui.py`)

용도: **mock_server를 실행/부착해 슬롯별 정체성·통계·디버그·링크를 관리**하고, 선택적으로
**ncmpd를 띄워 comm thread를 이 mock(또는 real)과 연동**.

### 3.1 "Server" 바 — mock_server 제어
| 항목 | 용도 |
|------|------|
| **bin / …** | `mock_server` 경로(자동 탐색; `…`로 지정). |
| **slots** | Start 시 띄울 슬롯 수(1~4). |
| **ctrl** | control 포트(기본 7000). |
| **data** | data base 포트(기본 7010; 슬롯 s는 7010+s). |
| **Start / Attach / Stop** | 직접 실행+Attach / 외부 서버에 연결만 / 종료. |

### 3.2 "ncmpd (comm thread target)" 그룹 — 실 타깃/이 mock 연동
Mock GUI에서 ncmpd를 띄우고 **comm thread가 보낼 대상**을 고른다(경로 B).
| 항목 | 용도 |
|------|------|
| **bin / …** | ncmpd 바이너리(자동 탐색, `NCMP_DAEMON` 우선, 파일 선택). |
| **transport** | **mock (socket → this mock)**: `--transport socket`으로 위 mock_server에 붙임(= comm thread가 이 mock과 연동, 슬롯 패널로 모니터). **real target**: `--transport real`(실 HSM; 슬롯 패널 해당 없음). |
| **sock** | ncmpd IPC 소켓(`NCMP_SOCK_PATH`); App/STDLL이 이 경로로 ncmpd 접속. |
| **Start/Stop ncmpd · 상태** | 실행/중지, RUNNING(transport)·소켓 UP 표시. |
> **mock 대상은 먼저 Server에서 mock_server를 Start/Attach** 해야 한다(ncmpd가 그 data
> 포트에 socket으로 붙음). 포트/슬롯은 Server의 data/slots를 따른다.

### 3.3 슬롯 패널 (좌측 목록에서 슬롯 선택)
- 상단: 슬롯 번호 + data 포트.
- **Host link**: `link/connected` 표시(0.6s 갱신), **Link Up** / **Link Down**(현재 App
  연결 강제 절단 — 장애 주입) / **Reset**(통계·디버그·장치 상태 초기화, 정체성·PIN 유지).
- **Identity** 탭: Label/Serial/Manufacturer/Model/HW·FW/Flags(u32)/UTC(16)/Login state.
  **Reload**(서버값 재조회) / **Apply**(해당 슬롯에 적용). 변경은 App의
  *HSM State → Token Info/Params*로 확인. (hsm_bridge/real은 정체성 편집 미지원.)
- **Statistics** 탭: requests/responses, bytes_in/out, errors, connects,
  in_flight/max_in_flight, last_opcode (라이브).
- **Debug** 탭: 최근 128건(time·opcode·session·seq·ack·req·rsp), 실패 ack 빨간색.

---

## 4. 테스트 App GUI (`app_gui.py`)

용도: **토큰에 명령을 보내 기능 시험**하고 결과를 SW 기준과 비교·집계. 상단 **Link 바**는
경로 A(프레임 링크)용, **"PKCS#11 (real stack)" 탭**은 경로 B(모드 2)용 — 서로 독립.

### 4.1 "Link" 바 (경로 A)
| 항목 | 용도 |
|------|------|
| **host / port / slot** | 서버 주소 / **base** 데이터 포트 / 슬롯. 실접속 = port+slot. |
| **target** | `mock`(mock_server) 또는 `real (bridge)`(hsm_bridge). SW 비교 기준을 좌우(§7.3). |
| **Connect / Disconnect** | 데이터 링크 연결/해제(점: 초록=연결). |
> 연결 거부 시: 슬롯 Link Down이거나 그 슬롯에 이미 다른 App이 연결됨(슬롯당 1개).

아래 §4.2~4.6 탭은 **경로 A(Link 바로 Connect)** 에서 동작한다.

### 4.2 "HSM State" — 상태 조회/설정/세션
- **Queries**: Ping(epoch)·Selftest(0)·FW Info·Token Info(정체성)·Token Params
  (label/serial/min·maxPIN)·Get UTC.
- **Admin/login**: Login(USER/SO, mock 기본 PIN user `1234`·SO `12345678`)·Logout·
  Set PIN·Init Token.
- **Session (CI 0x003A/0x003B)**: pid+sid로 **Open** → HSM SID(1~255) 표시, 그 SID로
  **Close** (매핑: [`session-id-mapping.md`](session-id-mapping.md)).

### 4.3 "Crypto / Hash" (+ SW 비교)
| 그룹 | 설정 | 확인 |
|------|------|------|
| RNG | bytes | 난수; mock이면 복제본 일치 표시. |
| Digest | mech(SHA-256/512·SHA3-*) + 입력 | **EQUAL/DIFFERENT**(SW 기준 대비). |
| AES-CTR | key/iv(hex)·data | 암→복 **왕복**, ct 복제본 일치·복호 OK. |
| AES-GCM | key/iv/aad(hex)·data | one-shot 왕복(ct∥tag), **tag 검증**. |
> key/iv는 16진수(AES-CTR 예: key 64hex=32B, iv 32hex=16B).

### 4.4 "PQC"
- **ML-DSA**(44/65/87) + 메시지 → keygen→sign→verify(+**위조 거부**) → `RESULT: PASS`.
- **ML-KEM**(512/768/1024) → keygen→encaps→decaps → **공유비밀 일치(YES)**.
> mock은 크기만 맞는 결정론 왕복(경로/왕복 검증). 실 토큰이면 진짜 값.

### 4.5 "File Compare" — 1MB+ 파일 SW 비교
- **File/Browse… · Make 1MB test file**, **Operation**(Digest 스트리밍 / AES-CTR chunked),
  **Digest mech**, **Run & Compare**(진행바) → `IDENTICAL ✓/✗`·크기·시간·**MB/s**.
- Digest: 전체 멀티파트 스트리밍. mock=복제본, **real=`hashlib`**(암호 정합성).
- AES-CTR: 청크별 one-shot(키스트림 청크마다 리셋) — **mock 데이터패스** 검증용.

### 4.6 "Scenarios" — 내장 일괄 시험
Smoke / Admin lifecycle / Crypto round-trips / PQC round-trips → step별 PASS/FAIL.
> Admin은 **로그아웃 상태에서** 실행(직전 로그인 시 1단계 "이미 로그인"으로 FAIL).

### 4.7 "Statistics" — 세션 통계
App이 보낸 명령을 opcode별 count/ok/fail/bytes/avg_ms로 집계. Refresh/Clear.

### 4.8 "PKCS#11 (real stack)" — 경로 B (모드 2, dlopen+dlsym)
App이 **`libpkcs11_ncmp.so`를 직접 dlopen**, **dlsym**으로 `C_*`를 찾아 호출(ctypes만).
Link 바와 **독립**. 표준 `C_*`로 표현 가능한 연산만 제공.
| 항목 | 용도 |
|------|------|
| **module (.so)** | `libpkcs11_ncmp.so` 경로(자동 탐색, `NCMP_PKCS11_MODULE` 우선, **Browse…**). |
| **slot / PIN** | PKCS#11 슬롯·PIN. |
| **ncmpd transport** | 이 탭에서 ncmpd를 **autostart**할 때 대상(**mock** 또는 **real**). 이미 떠 있는 ncmpd엔 무영향. |
| **Resolve (dlsym)** | dlopen 후 `C_GetFunctionList`/`C_GetInterfaceList`/`C_GetInterface` 발견 여부. |
| **Load+Open** | dlopen→`C_Initialize`→`C_GetSlotList`→`C_OpenSession`. |
| **Login/Logout/Close** | `C_Login`/`C_Logout`/`C_CloseSession`+`C_Finalize`. |
| **GenerateRandom·Digest·AES-GCM·Token Info** | 해당 `C_*` 호출. |

**ncmpd 진단/자동실행**: Load+Open의 `C_Initialize`가 ncmpd에 접속 못 하면 —
- ncmpd가 **살아있으면** 경고 팝업(버전/SHM 불일치 등),
- **미실행이면** "실행할까요?" 팝업 → 예 시 ncmpd를 (위 ncmpd transport로) 띄우고 **자동
  재시도**.

> **전제**: 빌드된 `libpkcs11_ncmp.so` + 기동된 ncmpd(`NCMP_SOCK_PATH` 공유). 벤더
> datapath·세션 CI·fail-bit·원시 opcode는 이 탭에 **없다**(경로 A에서 시험).
> 빌드 전이면 버튼이 **경로 A로 시험하라**고 안내한다.

---

## 5. 시험별 요리책 (무엇을 실행/설정)

### 5.1 토큰 정보(정체성) 조회·변경 (경로 A)
Mock GUI **Start**(또는 Attach) → **Identity**에서 Label/Serial 수정 → **Apply** →
App **Connect**(같은 슬롯) → **HSM State → Token Info/Params**로 확인.

### 5.2 세션 매핑 OpenSession/CloseSession (경로 A)
App **Connect** → **HSM State → Session**: pid(자동)·sid → **Open**(HSM SID 1~255) →
같은 pid·sid 재Open=동일 SID(멱등), sid 변경=다른 SID → **Close**(재Close=INVALID).

### 5.3 로그인/PIN (경로 A)
App **Connect** → **Login**(USER,1234)=CKR_OK → **Set PIN**(1234→5678) → 재Login 확인 →
**Logout**. 틀린 PIN → PIN_INCORRECT류.

### 5.4 해시/대칭 암복호 (경로 A)
**Crypto/Hash → Digest**(EQUAL) · **AES-CTR/AES-GCM** 왕복(복제본 일치·복호 OK·tag 검증).

### 5.5 PQC (경로 A)
**PQC → Run ML-DSA/ML-KEM round-trip** → PASS / shared secret match YES.

### 5.6 대용량 파일 데이터패스/정합성 (경로 A)
**File Compare → Make 1MB test file** → Operation=Digest → **Run & Compare** →
`IDENTICAL ✓`·MB/s. AES-CTR(mock)도 불일치=0 확인.

### 5.7 링크 단절/복구(장애) (경로 A)
App **Connect**+명령 1회 → Mock GUI 슬롯 **Link Down**(App 다음 명령 오류) →
**Link Up** → App 재Connect 복구. Mock GUI **Statistics/Debug**에서 errors·이벤트 확인.

### 5.8 다중 슬롯/파이프라인 (경로 A)
서버 `--slots 2+` → App 2개(각각 slot 0 / slot 1 Connect) → File Compare/시나리오 동시
실행 → Mock GUI 슬롯별 통계·`max_in_flight` 관찰. (같은 슬롯 2연결은 거부.)

### 5.9 실 PKCS#11 스택 end-to-end (경로 B, 모니터 포함) — 권장 순서
1. Mock GUI **Server**: mock_server **Start**(slots 2, data 7010, ctrl 7000).
2. Mock GUI **ncmpd 그룹**: sock=`/tmp/ncmpd.sock`, transport=**mock(socket→this mock)** →
   **Start ncmpd**(상태 RUNNING(mock)·소켓 UP).
3. App GUI **PKCS#11 탭**: module=`libpkcs11_ncmp.so`(또는 `libpkcs11_ncmp_p11.so`),
   `NCMP_SOCK_PATH` 동일하게 → **Resolve(dlsym)**(3개 FOUND) → **Load+Open** → **Login** →
   **GenerateRandom/Digest/AES-GCM**.
4. Mock GUI 슬롯 **Statistics/Debug**에서 그 요청들이 흐르는지 확인(= comm thread가 이
   mock과 연동).
> 실 하드웨어면 2를 생략하고 ncmpd transport=**real**(App 탭 autostart도 가능).

### 5.10 실 HSM(브리지) 프레임 링크 (경로 A, 실 FX3)
`hsm_bridge --data-port 7010 --ctrl-port 7000` → App **target=real(bridge)** → Connect →
상태·암호·파일(Digest는 `hashlib` 정합성). HW/libusb 없으면 데이터 명령은 device 오류.

---

## 6. 트러블슈팅

| 증상 | 원인 / 해결 |
|------|-------------|
| `Could not load the Qt platform plugin "xcb"` | `libxcb-cursor0` 필요(§1.3). 임시로 `QT_QPA_PLATFORM=offscreen`. |
| App Link **Connect 실패** | 서버 미기동, 포트 불일치(port+slot), 슬롯 Link Down. |
| 두 번째 App 연결 거부 | 슬롯당 1연결 — 다른 슬롯 사용/기존 해제. |
| PKCS#11 탭 Load+Open 실패 팝업 | ncmpd 진단: 살아있으면 버전/SHM 확인, 미실행이면 "실행" 선택. `NCMP_SOCK_PATH` 일치 확인. |
| PKCS#11 탭 "경로 A로 시험하라" 안내 | 모듈 미지정/ncmpd 미구동 — §5.9 순서로 준비하거나 경로 A 사용. |
| Admin 시나리오 1단계 FAIL | 직전 로그인 — 먼저 **Logout**. |
| AES-CTR 파일비교 real 불일치 | 청크 CTR 리셋이라 연속 CTR과 다름 — real은 **Digest 모드**. |
| `bind: Address already in use` | 포트 점유 — 종료 후 재실행/다른 포트. |
| Mock GUI 값 안 갱신 | Attach 여부/ctrl 포트 확인(폴링 0.6s). |

---

## 7. 부록

### 7.1 포트/소켓 규약
- control(JSON) 기본 **7000**, data 기본 base **7010**(슬롯 s → 7010+s), App 접속 = base+slot.
- ncmpd IPC 소켓 = `NCMP_SOCK_PATH`(기본 `/run/ncmpd/ncmpd.sock`; 비-root는 `/tmp/...` 권장).
- ncmpd 소켓 전송(=socket 대상) 설정: `NCMP_SOCKET_HOST`/`NCMP_SOCKET_PORT_BASE`/
  `NCMP_SOCKET_SLOTS`.

### 7.2 지원 메커니즘
AES-GCM/CTR · SHA-256/512 · SHA3-224/256/384/512 · SHAKE-128/256(KDF) ·
ML-KEM(512/768/1024) · ML-DSA(44/65/87) · RNG · AES 키생성. 그 외(RSA/EC/DH/HMAC/
AES-블록 등) 미지원.

### 7.3 mock vs real (SW 비교의 의미)
- **mock**: 결정론 에뮬레이션(진짜 암호 아님). SW 기준=에뮬레이터 알고리즘 복제 →
  **데이터패스(프레이밍/청킹/마샬링)** 정합성 검증.
- **real**: 실제 암호. Digest는 `hashlib` 실측과 비교해 **암호 정합성** 검증.

### 7.4 ncmpd transport (경로 B 대상)
`--transport real`(기본, 실 FX3/libusb) · `mock`(내장 에뮬레이터, 외부 모니터 불가) ·
`socket`(mock_server, Mock GUI로 모니터 가능). `$NCMP_TRANSPORT`로도 지정.

# NCMP GUI 도구 — 모의 HSM GUI + 테스트 App GUI

opencryptoki(pkcsslotd)나 SHM 없이, **C mock을 소켓 서버로 확장**하고 그 위에
두 개의 **PySide6 데스크톱 GUI**를 올린 개발/시험 도구다.

> **메뉴별 용도·시험 절차(무엇을 언제 실행/설정하는지) 상세 가이드**:
> [`../../docs/gui-testing-guide.md`](../../docs/gui-testing-guide.md).

```
┌─────────────┐   control(JSON)   ┌──────────────────────────┐
│  Mock GUI   │◀─────────────────▶│  mock_server (C)         │
│ (PySide6)   │                   │  - slot 0..3 = mock_dev  │
└─────────────┘                   │  - mcu_scheduler.c 재사용 │
┌─────────────┐   data(wire frame)│  - data port = base+slot │
│  App GUI    │◀─────────────────▶│  - ctrl port             │
│ (PySide6)   │                   └──────────────────────────┘
└─────────────┘
```

- **mock_server** (`server/mock_server.c`): 기존 FX3 에뮬레이터(`mcu_scheduler.c`
  /`container.c`)를 **그대로 재사용**하여 wire 프레임을 TCP 소켓으로 주고받는다.
  슬롯 하나 = 에뮬레이트 토큰 하나(최대 4). 각 슬롯은 `data port = base+slot`에서
  호스트 링크를 받고, 공용 `control port`(JSON)로 GUI가 상태를 조회/설정한다.
- **hsm_bridge** (`server/hsm_bridge.c`): **동일한 링크/컨트롤 프로토콜**을 쓰되 백엔드가
  실 USB 토큰(`ncmp_transport_*` = `daemon/usb_transport.c`, libusb)이다. App GUI가
  mock과 **똑같이** `host:port`로 붙어 실 하드웨어를 구동한다. 토큰이 정체성을 소유하므로
  identity 조회/설정은 미지원(정체성은 `VD_TOKEN_INFO` 데이터 명령으로 조회).
- **frame_server** (`server/frame_server.{c,h}`): 위 두 서버가 공유하는 소켓/스레드/통계/
  디버그/컨트롤 골격. 백엔드(vtable)만 mock ↔ USB로 바뀐다.
- **Mock GUI** (`py/mock_gui.py`): 서버를 실행/부착하고, 슬롯별 **identity 입력·조회·
  수정**, **통계**, **디버그(최근 메시지)**, **링크 up/down·reset**을 제공. 한 창에서
  여러 mock을 동시에 관리.
- **App GUI** (`py/app_gui.py`): 슬롯을 선택해 mock(또는 실 타깃 브리지)에 링크로
  붙어 **CI 전송**, **HSM 상태 조회/설정**, **암복호/해시 시험**, **테스트 시나리오**,
  **1MB+ 파일 암복호/해시 후 SW 결과 비교**, **통계**를 수행.
- **ncmp_gui** (`py/ncmp_gui/`): wire 코덱·소켓 링크·CI 빌더·SW 기준 암호(에뮬레이터
  알고리즘 정확 복제 + 실 암호). GUI 없이 스크립트로도 사용 가능.

## 빌드

### mock_server (C)
CMake 통합(권장):
```bash
cd ncmp && cmake -S . -B build && cmake --build build -j
# → build/gui/mock_server
```
CMake 없이 직접:
```bash
# mock_server
gcc -std=gnu11 -O2 -I ncmp/include -I ncmp/mock -I ncmp/gui/server \
    ncmp/gui/server/mock_server.c ncmp/gui/server/frame_server.c \
    ncmp/mock/container.c ncmp/mock/fx3_dma.c ncmp/mock/mcu_scheduler.c \
    ncmp/common/ncmp_wire.c -lpthread -o mock_server

# hsm_bridge (usb_transport.c는 libusb 헤더가 있으면 자동 링크, 없으면 스텁)
gcc -std=gnu11 -O2 -I ncmp/include -I ncmp/gui/server \
    ncmp/gui/server/hsm_bridge.c ncmp/gui/server/frame_server.c \
    ncmp/daemon/usb_transport.c ncmp/common/ncmp_wire.c \
    -lpthread $(pkg-config --libs libusb-1.0 2>/dev/null) -o hsm_bridge
```
> CMake로는 `build/gui/mock_server`, `build/gui/hsm_bridge`가 생성된다(libusb가 있으면
> 브리지가 자동 링크, 없으면 "no device" 스텁으로 빌드).

### GUI 의존성 (Python)
```bash
cd ncmp/gui/py
python3 -m pip install -r requirements.txt   # PySide6 (+ cryptography)
```

## 실행

```bash
# 1) 서버 (슬롯 2개, 데이터 base 7010, 컨트롤 7000)
./build/gui/mock_server --slots 2 --data-port 7010 --ctrl-port 7000

# 2) 모의 HSM GUI (서버를 직접 Start 하거나 Attach)
cd ncmp/gui/py && python3 mock_gui.py

# 3) 테스트 App GUI (host 127.0.0.1, base port 7010, slot 0/1 …)
cd ncmp/gui/py && python3 app_gui.py

# 실 하드웨어를 붙일 때: mock_server 대신 브리지를 띄우고 App GUI target=real
./build/gui/hsm_bridge --data-port 7010 --ctrl-port 7000
#   → App GUI에서 host=127.0.0.1, base port=7010, slot 선택 후 Connect
```
> Mock GUI의 **Start** 버튼으로 서버를 직접 띄울 수 있다(바이너리 경로 지정). App GUI는
> `데이터 포트 = base + slot`으로 접속한다.

### 창 표시 요구사항 (Qt xcb 플랫폼)

PySide6 6.5+의 xcb 플랫폼은 시스템 라이브러리 **`libxcb-cursor0`** 를 요구한다. 없으면
`Could not load the Qt platform plugin "xcb"` 로 실패한다. 정식 설치:
```bash
sudo apt install libxcb-cursor0
```

**root 권한이 없을 때(비-root 우회)** — `.deb`를 받아 사용자 영역에 푼다:
```bash
mkdir -p ~/.local/xcbcursor && cd ~/.local/xcbcursor
apt-get download libxcb-cursor0                 # root 불필요
dpkg-deb -x libxcb-cursor0_*.deb .
```
그 다음 둘 중 하나로 라이브러리를 로드시킨다.

- **(a) PySide6 Qt/lib에 복사 — 권장(환경변수 불필요, 영구)**: xcb 플러그인의
  RUNPATH가 PySide6 번들 `Qt/lib`를 가리키므로, 거기에 `.so`를 넣으면 이후 아무 설정
  없이 `python3 mock_gui.py`가 창을 띄운다.
  ```bash
  QTLIB=$(python3 -c "import PySide6,os;print(os.path.join(os.path.dirname(PySide6.__file__),'Qt','lib'))")
  cp ~/.local/xcbcursor/usr/lib/x86_64-linux-gnu/libxcb-cursor.so.0.0.0 "$QTLIB/"
  ln -sf libxcb-cursor.so.0.0.0 "$QTLIB/libxcb-cursor.so.0"
  ```
  > 주의: 이 복사본은 그 `--user` PySide6 안에 있으므로 **PySide6 재설치/업그레이드 시
  > 사라진다**(그때 다시 복사하거나 apt로 설치).

- **(b) `LD_LIBRARY_PATH`로 로드 — 셸마다 설정**:
  ```bash
  export LD_LIBRARY_PATH="$HOME/.local/xcbcursor/usr/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH"
  # (영구 적용은 ~/.bashrc 에 위 줄 추가)
  ```

이후 창 실행:
```bash
cd ncmp/gui/py && python3 mock_gui.py            # (또는 app_gui.py)
```
> SSH 사용 시 X 포워딩(`ssh -X`/`-Y`)으로 `DISPLAY`가 설정돼 있어야 한다. 디스플레이가
> 전혀 없으면 `QT_QPA_PLATFORM=offscreen` 으로 창 없이 구동/스크린샷만 가능하다
> (예: `QT_QPA_PLATFORM=offscreen python3 app_gui.py`).

## 헤드리스 검증 (GUI 없이)

서버 + 파이썬 코어의 종단 간 동작은 `py/smoke_test.py`로 검증한다(디스플레이 불필요):
```bash
./mock_server --slots 2 &
cd ncmp/gui/py && python3 smoke_test.py     # 15개 체크: RNG/digest/AES-CTR/링크/통계 …
```

## 요구사항 대응표

| 요구사항 | 구현 |
|----------|------|
| mock을 GUI로 구동 | `mock_gui.py`가 `mock_server`를 Start/Attach |
| 토큰 정보 입력/조회/수정 | Mock GUI **Identity** 탭 (label/serial/manufacturer/model/HW·FW/flags/UTC) |
| 한 GUI에서 여러 mock 동시 실행 | `--slots N`, 슬롯별 패널/포트 |
| App→mock CI 처리 후 결과 반환 | data 링크(wire 프레임) + `mcu_scheduler` 실행 경로 |
| 통계 정보 | Mock GUI **Statistics**, App GUI **Statistics**(opcode별 count/ok/fail/bytes/avg_ms) |
| 현재/처리 중 메시지 디버그 서브화면 | Mock GUI **Debug** 탭(최근 메시지 링, opcode/session/seq/ack/크기) |
| 호스트 링크 연결/해제 | Mock GUI **Link Up/Down/Reset**, App GUI **Connect/Disconnect** |
| 슬롯 선택 | App GUI slot 스핀박스 → `base+slot` 포트 |
| mock/real 타깃 연결 | ✅ mock=`mock_server`, real=`hsm_bridge`(동일 링크 프로토콜). App GUI target 선택 |
| HSM 상태 조회/설정 | App GUI **HSM State**(ping/selftest/fw/token-info/params/utc, login/PIN/init-token) |
| 다양한 암복호/해시 시험 | App GUI **Crypto/Hash**(RNG, digest, AES-CTR, AES-GCM) |
| PQC 시험 | App GUI **PQC**(ML-DSA keygen→sign→verify(+위조), ML-KEM keygen→encaps→decaps 공유비밀 일치) |
| 테스트 시나리오 | App GUI **Scenarios**(내장 4종: smoke/admin/crypto/PQC, step별 pass/fail) |
| 1MB+ 파일 SW 비교 | App GUI **File Compare**(스트리밍 digest / chunked AES-CTR, token vs SW, MB/s) |

## 한계 / 후속 과제

- **파일 비교의 기준(SW ref)**: mock 타깃은 에뮬레이터가 실제 AES/SHA가 아니므로
  **SW 기준 = 에뮬레이터 알고리즘의 정확 복제**(`swcrypto.mock_*`)로 비교한다. 이는
  암호 정합성이 아니라 **데이터패스(프레이밍/청킹/마샬링)**의 종단 간 정합성을 검증한다.
  **실 HSM** 타깃일 때는 digest가 `hashlib` 실측과 비교되어 암호 정합성까지 검증된다
  (연속 CTR은 64KB 프레임·one-shot 제약상 청크 비교가 제한적).
- **실 타깃(real HSM) 링크**: `hsm_bridge`가 `ncmp_transport`(libusb)를 소켓 프론트로
  노출하므로 App GUI가 mock과 동일하게 붙는다. 실제 응답은 **libusb + FX3 토큰**이 있어야
  나오며, 없으면 브리지는 기동은 하되 데이터 명령에 device 오류를 돌려준다(정상). VID/PID/EP는
  `daemon/usb_transport.c`의 값이 실 펌웨어와 일치해야 한다.
- **PQC 파라미터셋 크기**: ML-DSA/ML-KEM의 pub/priv/sig/ct/ss 크기는 실제 규격에
  근접한 값을 사용하되(`ci.MLDSA_SETS`/`ci.MLKEM_SETS`), mock은 크기만 일치하면
  결정적으로 왕복하므로 실 토큰과 blob 내용은 다르다(암호 정합성 아님).

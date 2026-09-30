# NCMP GUI 도구 — 모의 HSM GUI + 테스트 App GUI

opencryptoki(pkcsslotd)나 SHM 없이, **C mock을 소켓 서버로 확장**하고 그 위에
두 개의 **PySide6 데스크톱 GUI**를 올린 개발/시험 도구다.

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
gcc -std=gnu11 -O2 -I ncmp/include -I ncmp/mock \
    ncmp/gui/server/mock_server.c \
    ncmp/mock/container.c ncmp/mock/fx3_dma.c ncmp/mock/mcu_scheduler.c \
    ncmp/common/ncmp_wire.c -lpthread -o mock_server
```

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
```
> Mock GUI의 **Start** 버튼으로 서버를 직접 띄울 수 있다(바이너리 경로 지정). App GUI는
> `데이터 포트 = base + slot`으로 접속한다.

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
| mock/real 타깃 연결 | App GUI target=mock / real(bridge). 실 HSM은 프레임 브리지 필요(아래 참고) |
| HSM 상태 조회/설정 | App GUI **HSM State**(ping/selftest/fw/token-info/params/utc, login/PIN/init-token) |
| 다양한 암복호/해시 시험 | App GUI **Crypto/Hash**(RNG, digest, AES-CTR, AES-GCM) |
| 테스트 시나리오 | App GUI **Scenarios**(내장 3종, step별 pass/fail) |
| 1MB+ 파일 SW 비교 | App GUI **File Compare**(스트리밍 digest / chunked AES-CTR, token vs SW, MB/s) |

## 한계 / 후속 과제

- **파일 비교의 기준(SW ref)**: mock 타깃은 에뮬레이터가 실제 AES/SHA가 아니므로
  **SW 기준 = 에뮬레이터 알고리즘의 정확 복제**(`swcrypto.mock_*`)로 비교한다. 이는
  암호 정합성이 아니라 **데이터패스(프레이밍/청킹/마샬링)**의 종단 간 정합성을 검증한다.
  **실 HSM** 타깃일 때는 digest가 `hashlib` 실측과 비교되어 암호 정합성까지 검증된다
  (연속 CTR은 64KB 프레임·one-shot 제약상 청크 비교가 제한적).
- **실 타깃(real HSM) 링크**: App GUI는 "host:port에서 NCMP 프레임을 주고받는 링크"로
  추상화되어 있다. 실 USB HSM은 `ncmp_transport`(libusb)를 소켓 프론트로 노출하는
  **브리지**가 있으면 그대로 붙는다(후속 작업).
- **PQC(ML-DSA/ML-KEM) 시험 탭**: 현재 Crypto 탭은 RNG/digest/AES 중심. PQC 왕복
  (keygen→sign/verify, encaps/decaps) UI는 후속으로 추가 예정(와이어 파라미터 레이아웃은
  `docs/command-interface.md` 참고).

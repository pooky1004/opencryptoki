# NCMP GUI 도구 — 진행상황 요약

- **작성일**: 2026-09-30
- **범위**: 모의 HSM GUI + 테스트 App GUI (opencryptoki/pkcsslotd·SHM 없이 동작)
- **소스**: [`../ncmp/gui/`](../ncmp/gui/) · 사용법: [`../ncmp/gui/README.md`](../ncmp/gui/README.md)
- **종합 현황**: [`SUMMARY.md`](SUMMARY.md) / [`STATUS.md`](STATUS.md)

## 1. 설계 결정 (사용자 확정)

- **GUI 스택**: Python + Qt(PySide6) 데스크톱.
- **mock 노출**: 기존 C 에뮬레이터(`mcu_scheduler.c`/`container.c`)를 **소켓 서버로
  확장**해 재사용. 슬롯 = 에뮬레이트 토큰, wire 프레임을 TCP로 주고받음.

```
Mock GUI ─ control(JSON) ─▶ mock_server(C) ◀─ data(wire frame) ─ App GUI
                              slot0..3 = mock_device_t (mcu_scheduler 재사용)
                            hsm_bridge(C)  ◀─ data(wire frame) ─ App GUI(target=real)
                              slot0..3 = ncmp_transport_* (libusb, 실 FX3)
  * 두 서버는 frame_server(소켓/통계/디버그/컨트롤)를 공유, 백엔드만 mock↔USB
```

## 2. 지금까지 한 일 (Done)

### 2.1 소켓 서버 — 공통 골격 + 두 백엔드 (`ncmp/gui/server/`)
- `frame_server.{c,h}`: 소켓/스레드/슬롯별 **통계**(requests/responses/bytes/errors/
  connects/in_flight/max_in_flight/last_opcode) + **디버그 링**(최근 128건) + **control
  프로토콜**(`list`/`get`/`set`/`stats`/`debug`/`link`/`reset`)을 담당. 백엔드는 vtable
  (`exec`/`get_identity`/`set_identity`/`reset`/`label`)로 주입. 의존성 없음.
- `mock_server.c`: **mock 백엔드** — `mock_mover_ingest`+`mock_mcu_step`(정통 에뮬레이션),
  identity 조회/설정/reset 가능(에뮬 편의).
- `hsm_bridge.c`: **USB 백엔드** — `ncmp_transport_send`+`ncmp_transport_recv`로 실 FX3에
  프레임 포워딩. identity 조회/설정은 미지원(토큰이 소유). `usb_transport.c`가 libusb 유무를
  `__has_include`로 감지 → **libusb 없이도 빌드**(데이터 명령은 device 오류 반환).
- CMake: `ncmp/gui/server/CMakeLists.txt`(`ENABLE_GUI_SERVER`) — `ncmp_frame_server`
  라이브러리 + `mock_server` + `hsm_bridge`(libusb 있으면 자동 링크). 상위
  `ncmp/CMakeLists.txt`에 `add_subdirectory(gui/server)`.

### 2.2 Python 공용 코어 — `ncmp/gui/py/ncmp_gui/`
- `wire.py`: wire 프레임 LE 인코드/디코드(프레임 프리픽스+헤더+param_len[8]+params).
- `ci.py`: opcode·메커니즘·CKR 상수 + CI 요청 빌더(RNG/digest/AES/admin/vendor …).
- `link.py`: `DataLink`(프레임 링크, 스레드 안전) + `ControlClient`(JSON RPC).
- `swcrypto.py`: **에뮬레이터 알고리즘 바이트 정확 복제**(`mock_*`: RNG/digest fold·
  finalize/AES 스트림) + **실 암호**(`real_*`: hashlib/cryptography).

### 2.3 모의 HSM GUI — `ncmp/gui/py/mock_gui.py`
- 서버 **Start/Attach/Stop**, 슬롯 목록.
- 슬롯 패널: **Identity**(label/serial/manufacturer/model/HW·FW/flags/UTC 조회·수정),
  **Statistics**(라이브), **Debug**(최근 메시지 표, 실패 ack 강조),
  **Link**(Up/Down/Reset). 0.6s 주기 폴링.

### 2.4 테스트 App GUI — `ncmp/gui/py/app_gui.py`
- 연결 바: host/base port/slot/target(mock·real) + Connect/Disconnect(`포트=base+slot`).
- 탭: **HSM State**(ping/selftest/fw/token-info/params/utc, login/PIN/init-token),
  **Crypto/Hash**(RNG·digest·AES-CTR·AES-GCM + SW 비교),
  **PQC**(ML-DSA keygen→sign→verify(+위조 거부), ML-KEM keygen→encaps→decaps 공유비밀 일치),
  **File Compare**(스트리밍 digest / chunked AES-CTR, token↔SW, MB/s, 진행바; 워커 스레드),
  **Scenarios**(내장 4종: smoke/admin/crypto/PQC, step별 pass/fail 표),
  **Statistics**(opcode별 count/ok/fail/bytes/avg_ms).
- opcode별 세션 통계 자동 집계.

### 2.5 검증 / 부속
- `smoke_test.py`: 헤드리스 E2E(디스플레이 불필요).
- README(요구사항 대응표·빌드·실행), requirements.txt, .gitignore.

## 3. 검증 결과

| 항목 | 결과 |
|------|------|
| C 서버 gcc 빌드(mock_server + hsm_bridge) | **성공**(경고 0) |
| 헤드리스 스모크(`smoke_test.py`, frame_server 리팩터 후) | **15/15 PASS** (RNG·digest one-shot/multipart·AES-CTR 왕복이 SW 복제본과 바이트 일치, fail-bit·통계·디버그·링크 down) |
| hsm_bridge(HW 없음) | 기동·control(list/stats) OK, identity=미지원, 데이터=device 오류로 링크 드롭(정상) |
| App GUI CI 경로 개별 확인 | AES-GCM 왕복(ct‖tag)·token-info(104B)·token-params·login good/bad/logout **정상** |
| 전체 `py_compile` | **OK**(코어 4 + smoke + GUI 2) |
| **GUI 실행(PySide6 6.11.2)** | Mock/App GUI **헤드리스(offscreen) 구동 검증**: attach·identity 수정·통계·디버그·링크, 연결·HSM상태·암호/해시·PQC·시나리오(4종)·1MB+ 파일비교·통계 핸들러 실동작 확인. 실제 렌더 스크린샷 캡처. |

## 4. 요구사항 대응

| 요구사항 | 상태 |
|----------|------|
| mock을 GUI로 구동 | ✅ Mock GUI Start/Attach |
| 토큰 정보 입력/조회/수정 | ✅ Identity 탭 |
| 한 GUI에서 여러 mock 동시 | ✅ `--slots N`, 슬롯 패널 |
| App→mock CI 처리·결과 반환 | ✅ data 링크 + 에뮬레이션 실행 |
| 통계 정보 | ✅ Mock/App 양쪽 |
| 현재/처리 중 메시지 디버그 서브화면 | ✅ Debug 탭(메시지 링) |
| 호스트 링크 연결/해제 | ✅ Link Up/Down/Reset, Connect/Disconnect |
| 슬롯 선택 | ✅ slot→(base+slot) 포트 |
| mock/real 타깃 연결 | ✅ mock=`mock_server`, real=`hsm_bridge`(동일 프로토콜) |
| HSM 상태 조회/설정 | ✅ HSM State 탭 |
| 암복호/해시 시험 | ✅ Crypto/Hash 탭 |
| PQC(ML-DSA/ML-KEM) 시험 | ✅ PQC 탭 (강도 3종씩 왕복, 위조 거부 확인) |
| 테스트 시나리오 | ✅ 내장 4종(smoke/admin/crypto/PQC) |
| 1MB+ 파일 SW 비교 | ✅ File Compare 탭 |

## 5. 남은 과제 (TODO)

- [x] **GUI 실행 검증**: PySide6 6.11.2 설치 후 두 GUI를 offscreen으로 구동, 실제 핸들러
  (attach/identity/통계/디버그/링크, 연결/HSM상태/암호/PQC/시나리오/파일비교/통계)가 실행
  중인 `mock_server`에 대해 정상 동작함을 확인하고 스크린샷 캡처.
- [ ] **온스크린(xcb) 실행**: 실제 창 표시는 시스템 패키지 `libxcb-cursor0`(apt) 필요.
  offscreen/eglfs/vnc/wayland 플랫폼은 그대로 동작. 설치 후 `python3 mock_gui.py` /
  `app_gui.py`로 창 확인.
- [x] **실 HSM(real target) 브리지**: `hsm_bridge`(`ncmp_transport` libusb 백엔드) 추가
  완료. 실제 응답은 libusb + FX3 하드웨어 연결 시 검증 필요(VID/PID/EP 확정 포함).
- [x] **PQC 시험 탭**: ML-DSA(keygen/sign/verify)·ML-KEM(keygen/encaps/decaps) 왕복 UI
  완료(서버 대조 6종 왕복 + 위조 거부 검증).
- [ ] **파일 비교 확장**: 실 타깃용 연속 CTR/GCM(멀티파트) 비교, 대용량 처리량 벤치.
- [ ] **시나리오 외부 파일(JSON) 로딩**, 결과 저장/리포트.
- [ ] CMake 실제 빌드 확인(이 환경엔 cmake 미설치, gcc로만 검증).

## 6. 파일 목록

```
ncmp/gui/
  server/frame_server.{c,h}     공통 소켓/통계/디버그/컨트롤 골격 + 백엔드 vtable
  server/mock_server.c          mock 백엔드(에뮬레이터)
  server/hsm_bridge.c           USB 백엔드(실 FX3, libusb)
  server/CMakeLists.txt
  py/ncmp_gui/{wire,ci,link,swcrypto,__init__}.py   공용 코어
  py/mock_gui.py                모의 HSM GUI
  py/app_gui.py                 테스트 App GUI
  py/smoke_test.py              헤드리스 E2E
  py/requirements.txt
  README.md, .gitignore
ncmp/CMakeLists.txt             (add_subdirectory(gui/server))
```

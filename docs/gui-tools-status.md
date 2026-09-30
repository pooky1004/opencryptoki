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
```

## 2. 지금까지 한 일 (Done)

### 2.1 C mock 소켓 서버 — `ncmp/gui/server/mock_server.c`
- 슬롯별 **data 포트**(base+slot)로 호스트 링크(wire 프레임) 수신 →
  `mock_mover_ingest` + `mock_mcu_step`(정통 에뮬레이션 경로) 실행 → 응답 프레임 반환.
- 공용 **control 포트**(newline JSON): `list`/`get`/`set`(identity)/`stats`/`debug`/
  `link`(up·down)/`reset`.
- 슬롯당 통계(requests/responses/bytes/errors/connects/in_flight/max_in_flight/
  last_opcode)와 **디버그 링**(최근 128건: opcode/session/seq/ack/크기/타임스탬프).
- 링크 강제 down 시 현재 데이터 연결을 끊음. 의존성 없음(POSIX 소켓 + pthreads).
- CMake 연결: `ncmp/gui/server/CMakeLists.txt`(`ENABLE_GUI_SERVER`, 기본 ON),
  상위 `ncmp/CMakeLists.txt`에 `add_subdirectory(gui/server)`.

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
| C 서버 gcc 빌드 | **성공** |
| 헤드리스 스모크(`smoke_test.py`) | **15/15 PASS** (RNG·digest one-shot/multipart·AES-CTR 왕복이 SW 복제본과 바이트 일치, fail-bit·통계·디버그·링크 down) |
| App GUI CI 경로 개별 확인 | AES-GCM 왕복(ct‖tag)·token-info(104B)·token-params·login good/bad/logout **정상** |
| 전체 `py_compile` | **OK**(코어 4 + smoke + GUI 2) |

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
| mock/real 타깃 연결 | ⚠️ mock 완비, real은 프레임 브리지 필요(후속) |
| HSM 상태 조회/설정 | ✅ HSM State 탭 |
| 암복호/해시 시험 | ✅ Crypto/Hash 탭 |
| PQC(ML-DSA/ML-KEM) 시험 | ✅ PQC 탭 (강도 3종씩 왕복, 위조 거부 확인) |
| 테스트 시나리오 | ✅ 내장 4종(smoke/admin/crypto/PQC) |
| 1MB+ 파일 SW 비교 | ✅ File Compare 탭 |

## 5. 남은 과제 (TODO)

- [ ] **사용자 환경 GUI 실행 검증**: 이 개발 환경엔 `pip`가 없어 PySide6 설치 불가 →
  GUI는 `py_compile` + 서버 상대 로직 확인까지만. 사용자 측 `pip install -r
  requirements.txt` 후 실제 창 구동 확인 필요.
- [ ] **실 HSM(real target) 브리지**: `ncmp_transport`(libusb)를 소켓 프론트로 노출하는
  브리지를 추가하면 App GUI가 그대로 실 타깃에 연결.
- [x] **PQC 시험 탭**: ML-DSA(keygen/sign/verify)·ML-KEM(keygen/encaps/decaps) 왕복 UI
  완료(서버 대조 6종 왕복 + 위조 거부 검증).
- [ ] **파일 비교 확장**: 실 타깃용 연속 CTR/GCM(멀티파트) 비교, 대용량 처리량 벤치.
- [ ] **시나리오 외부 파일(JSON) 로딩**, 결과 저장/리포트.
- [ ] CMake 실제 빌드 확인(이 환경엔 cmake 미설치, gcc로만 검증).

## 6. 파일 목록

```
ncmp/gui/
  server/mock_server.c          C 소켓 서버 (~600줄)
  server/CMakeLists.txt
  py/ncmp_gui/{wire,ci,link,swcrypto,__init__}.py   공용 코어
  py/mock_gui.py                모의 HSM GUI
  py/app_gui.py                 테스트 App GUI
  py/smoke_test.py              헤드리스 E2E
  py/requirements.txt
  README.md, .gitignore
ncmp/CMakeLists.txt             (add_subdirectory(gui/server))
```

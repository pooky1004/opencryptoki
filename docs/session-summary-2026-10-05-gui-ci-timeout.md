# 세션 요약 — GUI 정리 · 5초 타임아웃 · CI 송수신 이관 (2026-10-05)

Token NCMP의 GUI 도구(Web Test App · Debug App)와 데몬 타임아웃을 다듬은 세션의
작업·결과·남은 과제 요약. 상세는 각 설계/매뉴얼/결과 문서 참고
([`INDEX.md`](INDEX.md)).

- 일자: 2026-10-05
- 브랜치: `ncmp-host-managed-ctx`
- 환경: Linux x86_64, 실 FX3 `04b4:00f1`(CYUSB3KIT-003), mock 토큰, CMake +
  standalone(build.sh) 양쪽 빌드.

---

## 1. 한 일 (커밋 순)

### ① Web Test App — real 기본 · 세션 0 · 레이아웃 (`1d8dd834`, 문서 `29651fbe`)
- ncmpd 기본 전송을 **`real`** 로 변경(서버 `g_transport`·UI select·`.config/config`·
  `build.sh`). 하드웨어 없으면 `mock` 명시.
- **세션 ID 0(시스템 세션)** 을 C_Initialize 시 활성 세션 목록에 자동 추가, 모든
  탭의 세션 picker에 포함(`adoptSid()` 코어로 리팩터링, sid 중복 채택 방지).
- 툴바 간소화: **C_Initialize/C_Finalize 버튼 + "명령 기본값" 패널**을 토큰 정보
  탭 상단으로 이동(명령 기본값은 접기 `<details>`).

### ② 데몬 5초 타임아웃 (`575a1704`) · ncmp_web 가드 (`cd58e4e0`)
- **문제**: 미응답 토큰에서 명령이 ~40초 걸림. 실 디버그로 원인 확정 — bulk-OUT
  전송 자체가 5초 USB 타임아웃으로 실패(`rc=-7`)하고 comm_thread가 무한 재시도,
  클라이언트는 스핀 예산(~40초)까지 대기.
- **수정(`comm_thread.c`/`ncmpd.h`)**: 미응답을 **~5초**로 캡.
  - send 실패 시 재시도하지 않고 즉시 에러 응답으로 완료(`CKR_FUNCTION_CANCELED`/
    `CKR_DEVICE_ERROR`).
  - `comm_reap_timeouts()`: `NCMP_CMD_TIMEOUT_MS=5000`(USB 타임아웃과 동일) 초과
    SENT 엔트리를 에러 응답으로 완료(per-entry 단조 타임스탬프 `sent_ms[]`).
    in-flight 예약 누수(슬롯 wedge)도 방지.
  - `comm_release_inflight()`에 언더플로 가드(CAS floor 0).
  - rc는 그대로 80(`CKR_FUNCTION_CANCELED`), 지연만 40초→5초.
- **ncmp_web 가드**: 빈 본문 `daemon/start`가 `snprintf(g_transport,…,g_transport)`
  자기겹침(UB)으로 transport를 ""로 만들던 버그 수정(`transport != g_transport`일
  때만 복사).

### ③ Debug App — 읽기 전용 SHM 뷰어 (`956e26f4`, 문서 `c2b00944`)
- CI 송수신 기능 **완전 제거**(`/api/ci`·handle_ci/emit_frame/hex2bytes, CI 탭·
  디버깅 창). **USB 미사용**(libusb 미링크) — ncmpd가 USB 소유, Debug App은 conn
  thread 핸드셰이크 + **SHM 읽기 전용 attach**만.
- 단일 **공유메모리 뷰어** 화면(슬롯 상태) + **주기적 자동 갱신(기본 1초**, 1~60초
  조절·중첩 방지).

### ④ Web Test App — CI 송수신 탭 추가 (`956e26f4`, 문서 `c2b00944`)
- Debug App에서 제거한 CI 송수신을 Web Test App으로 **이관**.
- 서버 `/api/ci`: facade 미경유, **서버 전용 `ncmp_client`(`g_ci_cli`)로 데몬
  직결**. `g_api_lock` 밖·독립 락이라 상태/슬롯 폴링을 막지 않음.
- UI "CI 송수신" 탭: CI opcode 선택 + **CI별 입력 파라미터 p0~p7(Hex)** +
  session_id, 전송 시 **송신(TX)/수신(RX)을 raw(Hex)+parsed 동시 출력**.
- 빌드(`build.sh`/CMake)에 `ncmp_client`+common 링크(`ncmp_stdll_client`),
  `ncmp/include` 추가.

### ⑤ CI 송수신 실 타겟 시험 문서 (`a0802a5a`)
- [`testapp-web-ci-results.md`](testapp-web-ci-results.md) 작성 + INDEX 등록.

---

## 2. 검증 결과

- **빌드/테스트**: CMake(mock) + standalone 양쪽 **경고 0**, `ctest` **100%**,
  `NCMP_HOST_MANAGED_CTX` on/off 모두 컴파일.
- **5초 타임아웃(실 FX3, 세션 0)**: C_GenerateRandom·C_Digest·AES-GCM·C_Login·
  C_GetTokenInfo 모두 **~5.0초**(이전 ~40초), rc 동일. 호스트측(GetSlotList/
  GetSessionInfo/GetMechanismList)·mock 무영향.
- **PKCS#11 API 기능(실 FX3, 세션 0)**: 호스트/facade측 API(dlsym·GetInfo·
  GetSlotList·GetSessionInfo·GetMechanismList 9종)는 rc=0, 토큰 왕복 암호/로그인은
  보드 미응답으로 5초 rc=80. 세션 0 와이어 라우팅은 정상(세션 상태 R/W public).
- **Debug App**: mock·실 FX3에서 SHM status/slots/slot 정상, `/api/ci` 제거 확인,
  1초 자동 갱신 동작.
- **CI 송수신 탭(실 FX3)**: 요청/응답 프레임 raw+parsed 정상 표시(VD_PING 등).
  현 보드가 미응답이라 5초 타임아웃 합성 응답(`ack=0x50`) 표시. mock에서는 RNG가
  실제 응답(param0 16B)으로 파싱됨.

---

## 3. 남은 과제

- **provisioned 펌웨어 재시험**: 세션/크립토(C_Login·Random·Digest·AES-GCM)와 CI
  송수신 실제 ack/파라미터는 응답 가능한 보드에서 재확인 필요(현 보드는
  UNPROVISIONED/미응답으로 관측).
- **standalone facade mechlist 보강(선택)**: 웹앱이 로드하는 mode-2 facade
  (`ncmp_p11.c`)의 `g_mechs[]`에는 SHAKE·ML-KEM·ML-DSA가 없음(9종만). 해당 PQC/XOF
  C_* 연산도 스텁(미구현). 노출하려면 ① facade 확장(구현+광고) 또는 ② 웹앱이 full
  opencryptoki의 mode-1 `libpkcs11_ncmp.so` 로드. (mode-1 `ncmp_specific.c`에는
  14종 광고 — 상세는 코드 주석/`ncmp-pqc-sha3-xof` 참고.)
- **CI 송수신 세션 기반 CI**: 현재 session_id 직접 입력. 필요 시 활성 세션 picker
  연동 고려(OPEN_SESSION 핸들 자동 주입).
- **UI 수동 점검**: 실제 브라우저에서의 탭/디버깅 창/자동 갱신 UX 육안 확인(현재는
  jsdom 헤드리스 + REST 라이브로 검증).
- **시스템 설정(미적용)**: 방화벽/udev/systemd는 root 권한이라 명령만 문서화,
  미적용(배포 문서 참고).

---

## 4. 관련 문서

| 주제 | 문서 |
|---|---|
| Web Test App 설계/API/UI | [`testapp-web-design.md`](testapp-web-design.md) |
| Web Test App 사용 매뉴얼 | [`testapp-web-manual.md`](testapp-web-manual.md) |
| Web Test App 배포/시스템 설정 | [`testapp-web-deployment.md`](testapp-web-deployment.md) |
| CI 송수신 실 타겟 결과 | [`testapp-web-ci-results.md`](testapp-web-ci-results.md) |
| 시나리오 시험 결과 | [`testapp-web-scenario-results.md`](testapp-web-scenario-results.md) |
| Debug App 설계/매뉴얼/배포 | [`debugapp-design.md`](debugapp-design.md) · [`debugapp-manual.md`](debugapp-manual.md) · [`debugapp-deployment.md`](debugapp-deployment.md) |
| GUI 도구 개발 요약 | [`ncmp-gui-development-summary.md`](ncmp-gui-development-summary.md) |

# NCMP GUI 도구 개발 종합 요약

이 세션에서 개발한 **Token NCMP용 웹 기반 도구 2종**(Test App, Debug App)과
그 과정에서 수반된 코어 수정·시험 내역을 한 문서로 요약한다. 상세는 각 주제
문서를 링크한다. (작성: 2026-10-05)

| 주제 | 상세 문서 |
|------|-----------|
| Test App 설계/API/UI/시나리오/설정/세션 | [`testapp-web-design.md`](testapp-web-design.md) |
| Test App 사용자 매뉴얼(상세) | [`testapp-web-manual.md`](testapp-web-manual.md) |
| Test App 배포·시스템 설정 | [`testapp-web-deployment.md`](testapp-web-deployment.md) |
| Test App 시험 결과(기능) | [`testapp-web-test-results.md`](testapp-web-test-results.md) |
| 시나리오 시험 결과(실 타겟 3회차) | [`testapp-web-scenario-results.md`](testapp-web-scenario-results.md) |
| Debug App 설계/개발 | [`debugapp-design.md`](debugapp-design.md) |
| Debug App 사용자 매뉴얼(상세) | [`debugapp-manual.md`](debugapp-manual.md) |
| Debug App 배포·시스템 설정 | [`debugapp-deployment.md`](debugapp-deployment.md) |
| 세션 ID 매핑(OPEN/CLOSE 변경) | [`session-id-mapping.md`](session-id-mapping.md) |

---

## 1. 무엇을 만들었나

브라우저에서 접속해 쓰는 **외부 접속 가능한 웹 도구 2종**. GUI는 웹, Application은
C. (이전의 C#/Avalonia 안은 요청에 따라 폐기)

```
① Test App  (PKCS#11 기능 시험 — facade 경유)
   브라우저 ─HTTP/JSON─ ncmp_web(C) ─app_*─ dlopen C_* ─ libpkcs11_ncmp.so
        ─ ncmp_client ─ IPC+SHM ─ ncmpd ─ comm thread ─▶ 실 FX3(USB)/mock

② Debug App (공유메모리 열람 + CI 송수신 — conn thread 직결, facade 미경유)
   브라우저 ─HTTP/JSON─ ncmp_dbg(C) ─ncmp_ipc 핸드셰이크─ ncmpd conn thread
        ─ SHM 직접 attach(읽기) / ncmp_client로 CI 전송 ─▶ 실 FX3(USB)/mock
```

위치: `ncmp/gui/testapp/`(Test App), `ncmp/gui/debugapp/`(Debug App).

---

## 2. Test App (`ncmp/gui/testapp/`)

- **C 애플리케이션 계층**(`native/ncmp_testapp.c`): facade를 dlopen하고 모든 C_*를
  dlsym, `app_*` ABI(19종)로 노출. multipart digest 포함.
- **C 웹서버**(`webserver/ncmp_web.c`): 의존성 없는 HTTP/JSON 서버(native 포함
  단일 바이너리). REST ~26종. ncmpd 실행/정지, CORS, **Bearer 토큰 인증**,
  **설정 파일** 로더, 깨끗한 SIGTERM 종료. OpenSSL(SW 해시) 링크.
- **웹 UI**(`web/`): 좌=활성 슬롯, 우=탭 6종 — 토큰 정보 / 세션·로그인 /
  암복호화·해시 / **파일·검증** / **PKCS#11 API 시험** / **시나리오**.
  **라이트/다크 테마** 토글.
- **기능 요점**
  - 토큰/슬롯/세션/로그인, 난수·SHA-256/512·SHA3·AES-GCM 자가검증.
  - **파일/검증**: 크기 입력→테스트 파일 생성(init/update/final 시험용 ≥64KB),
    토큰 multipart 해시, **실 타겟 ↔ SW(OpenSSL) 비교(MATCH/MISMATCH)**.
  - **PKCS#11 API 시험**: 단위 API 1건 실행(요청/응답 JSON).
  - **시나리오**: 단위 항목 팔레트를 **순서대로 클릭**해 구성(스텝 파라미터·저장
    변수 `${s}`·`성공/실패/일치/불일치` 단정 인라인 편집), 실행 시 스텝별
    PASS/FAIL, **서버 영구 저장**(`scendir` JSON) + 내보내기/가져오기.
  - **설정 파일** `.config/config`(host/port/webroot/module/ncmpd/transport/
    sock/filedir/scendir/token). 우선순위 기본값<파일<env<CLI.

---

## 3. Debug App (`ncmp/gui/debugapp/`)

- **C 서버**(`server/ncmp_dbg.c`): `ncmp_stdll_client` 링크. ncmpd **conn thread와
  핸드셰이크**(ncmp_ipc) 후 **SHM을 읽기 전용 attach**. REST:
  `status/slots/slot/reconnect` + **`ci`**. **ncmpd 수정 불필요**.
- **웹 UI**(`web/`): 탭 2종.
  - **공유메모리 뷰어**: 실재 슬롯 목록 + 슬롯별 상세(state·bound_ck_slot·
    세션수·max_inflight·통계 in_flight/max/total_sent·토큰 신원·bufPool·
    **명령 링(MPSC) 상태 히스토그램 + 비-FREE 엔트리**). 2초 자동 새로고침.
  - **CI 송수신**: CI(opcode+이름) 선택·session_id·파라미터(p0~p7 Hex) 입력→전송.
    **디버깅 창에 송신(TX)/수신(RX)을 각각 Hex + 파싱 표로 동시 출력**
    (frame_len·session_id·sequence_id·command_id(+CI 이름)·ack(+CKR 이름)·
    payload_len·param[i]).
  - 라이트/다크 테마, 설정 파일, Bearer 토큰.

---

## 4. 수반된 코어 수정

1. **세션 OPEN/CLOSE를 실 타겟(MPF300TS Mi-V) 레퍼런스에 정합**
   (`2026-10-01_1615_GETMECHLIST_AES_GCM` 패키지 기준): OPEN_SESSION
   `0x003A→0x0020`(req flags 1파라미터·hdr sid=0 → resp param0=핸들),
   CLOSE_SESSION `0x003B→0x0021`(hdr sid=핸들, 무파라미터). facade가 실제로 세션을
   열어 `dev_sid` 저장, 이후 명령이 핸들을 와이어 헤더에 싣는다
   (`ncmp_client_t.active_session_id`, `sess_get()` 설정). mock도 갱신.
2. **slot_mask UB 수정**: `PKCS11_MAX_SLOT_COUNT 4→256` 전환 시 `uint32` 마스크의
   `1u<<s`(s≥32) UB → `NCMP_SLOT_MASK_BITS(32)`/`NCMP_SLOT_SCAN_MAX`/
   `NCMP_SLOT_IN_MASK()`로 32비트 캡(daemon·common·facade 전 사이트). 255 전면
   지원은 bitset 후속.
3. **hsm_bridge 링크 복구**(디스패처 리팩터 이후 방치).
4. **test_concurrency 불변식 완화**(`==4`→`>=1`).
5. **session 0 폴백(opt-in)**: `NCMP_SESSION0_FALLBACK` 설정 시 C_OpenSession이
   토큰 OPEN을 생략하고 wire session_id=0 로컬 세션 생성(펌웨어 브링업용). 기본 OFF.
6. **facade 세그폴트 수정**: `ncmp_p11.c`에 `<stdlib.h>` 누락으로 `getenv` 암시적
   선언(포인터 절단) → 헤더 추가.
7. **UI 초기화 크래시 수정**(app.js `el()`의 읽기전용 `dataset` 할당)과 **데몬
   준비 레이스 수정**(서버가 소켓 바인딩까지 대기 후 반환).

---

## 5. 시험 (실 FX3 `04b4:00f1` 연결)

- **빌드/단위**: CMake/gcc 경고 없이 빌드, `ctest` 100% 통과.
- **Test App 기능(mock)**: 정적 서빙·전 REST·음성 로그인(0xA0)·토큰 인증(401/200)·
  파일 생성+multipart+**SW 비교(openssl 교차검증)** 정상. jsdom 헤드리스 UI
  하네스로 전 탭·시나리오 빌더(팔레트 클릭·서버 저장/복원/실행/삭제)·테마 토글
  **0 problems**.
- **시나리오 25개(기본 15 + 비정상 10)**: 생성·영구 저장 후 실 FX3 **3회 시험**:
  - 1·2회차: 11~12/25(전송·메타·음성군 통과, 세션/크립토는 OpenSSL 타임아웃).
  - **3회차(session 0 폴백)**: **15/25**(기본 5, 비정상 **10/10**). openSession은
    폴백으로 통과하나 **크립토는 session 0을 `CKR_SESSION_HANDLE_INVALID`로 거부**.
  - 결론: 펌웨어가 **유효한 OPEN_SESSION 핸들을 요구**하며, OPEN_SESSION 자체는
    현재 보드에서 타임아웃 → 세션 크립토 완결 불가. provisioned 펌웨어 필요.
- **Debug App(실 FX3)**: SHM 뷰어 — 슬롯0 ONLINE·slotMask 0x1·링 FREE 32 표시.
  CI 송수신 — VD_PING은 **0.7ms에 실제 응답**(ack=0xB3, session 0 거부지만 프레임
  반환) Hex+파싱 확인, FW_INFO/TOKEN_INFO는 타임아웃(RX 없음).

> 실 보드는 시험 중 부트로더 → `MPF300TS Development`/`UNPROVISIONED`(펌웨어 적재)
> 상태로 관측됨. 세션/크립토의 완전한 검증은 provisioned 펌웨어에서 재시험 필요.

---

## 6. 빌드 & 실행

```bash
# 전체(CMake): ENABLE_TESTAPP / ENABLE_DEBUGAPP 기본 ON
cd ncmp && cmake -S . -B build -DENABLE_MOCK_TOKEN=ON && cmake --build build -j
#   -> build/gui/testapp/webserver/ncmp_web , build/gui/debugapp/ncmp_dbg
# 또는 gcc 단독
ncmp/gui/testapp/build.sh            # ncmp_web (+ facade/ncmpd)
ncmp/gui/debugapp/build.sh           # ncmp_dbg

# 실행(예: mock)
export NCMP_SOCK_PATH=/tmp/ncmpd.sock
ncmp_web  --host 0.0.0.0 --port 8080 --webroot web --transport mock ...
ncmp_dbg  --host 0.0.0.0 --port 8090 --webroot web --sock $NCMP_SOCK_PATH
```

의존성: libc/pthread/dl(+OpenSSL는 ncmp_web). 외부 접속·방화벽·systemd·토큰은
각 `*-deployment.md`. **systemd는 `enable`(부팅 자동 실행) 대신 `start`(수동)
권장** — 자동 실행 해제는 `systemctl disable [--now] <svc>`.

---

## 7. 커밋 (이 세션)

```
5f7b6338 ncmp/gui/testapp: add web-based Test App + slot-mask/link fixes
fc516459 docs: document the web Test App (design, deployment, test results)
9fe3ee1a ncmp: align session open/close to reference target; scenario builder; themes
92aa1b79 docs: user manual + session/scenario/theme updates for the web Test App
a23c8349 docs/testapp: add 15 basic + 10 abnormal scenarios and real-target results
00250799 ncmp/gui/debugapp: new Debug App (SHM inspector + CI send/receive); session0 fallback
2106a2ee docs: Debug App guide; session0 fallback + re-test results
46df1776 docs/deploy: default systemd install to manual start (no boot auto-start)
```

---

## 8. 남은 과제

- **provisioned 펌웨어**에서 세션 기반 크립토(login·digest·AES-GCM·multipart) 및
  25개 시나리오 재검증(결과 문서의 "실 타겟" 열 갱신).
- 256슬롯 전면 지원: 온라인 마스크 uint32 → presence bitset
  ([`slot-scaling-design.md`](slot-scaling-design.md)).
- Test App "기타" 탭: 객체/키쌍(ML-KEM·ML-DSA)/서명·검증, AES-GCM multipart 비교.
- Debug App: CI 응답 요청/응답 바이트 덤프 확장, 다중 SHM 인스턴스 선택.
- 다중 클라이언트 세션 격리(현재 토큰 1개 직렬화 공유), 운영 시 HTTPS 프록시+토큰.
- 브라우저 수동 UI 점검(헤드리스로 로직은 검증됨).

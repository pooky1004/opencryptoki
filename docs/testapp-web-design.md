# Web Test App 설계·개발 내역

Token NCMP를 **웹 브라우저(외부 호스트 접속 가능)**로 조작·검증하는 Test App.
이전 C# 안을 폐기하고, GUI를 웹으로, Application 계층은 그대로 C로 두어
브라우저 ─HTTP/JSON─ C 웹서버로 연결한다.

관련: [`testapp-web-deployment.md`](testapp-web-deployment.md)(설정/배포),
[`testapp-web-test-results.md`](testapp-web-test-results.md)(시험 결과),
[`dual-mode-provider.md`](dual-mode-provider.md)(facade),
[`slot-scaling-design.md`](slot-scaling-design.md).

위치: `ncmp/gui/testapp/` — `web/`(정적 UI), `webserver/`(C HTTP 서버),
`native/`(C 애플리케이션 ABI, 공용).

## 1. 구조

```
브라우저(어느 호스트든)
   │  HTTP/JSON (REST)                         ← 여기부터가 Test App
   ▼
ncmp_web (C, webserver/ncmp_web.c)  ── 정적 web/ 서빙 + /api/* 라우팅
   │  app_* 직접 호출 (native/ncmp_testapp.c를 그대로 컴파일 포함)
   ▼
libncmp_testapp 로직 ── dlopen + dlsym C_*  (RTLD_NOW|RTLD_LOCAL)
   ▼
libpkcs11_ncmp.so (facade, ncmp_p11.c)
   │  ncmp_client
   ▼
IPC(UNIX socket) + SHM  ──▶ ncmpd ──comm thread──▶ 실 FX3(USB) / mock / socket
```

- `ncmp_web`는 **단일 실행 파일**: `native/ncmp_testapp.c`(app_* ABI)를 그대로
  컴파일해 넣는다(SW 해시용 OpenSSL `libcrypto`만 추가 링크).
- 접속 정보(포트 등)는 **설정 파일** `.config/config`에 둘 수 있다(§6). 우선순위
  **기본값 < 파일 < env < CLI**.
- facade STDLL은 **런타임 dlopen**이라 빌드 의존이 없다.
- 데몬(`ncmpd`)은 facade 경로가 아니라 `ncmp_web`가 자식 프로세스로 실행/감시하며
  같은 `NCMP_SOCK_PATH`를 공유한다.
- **세션**: C_OpenSession이 토큰에 OPEN_SESSION(0x0020, flags)을 보내 핸들을 받고
  (facade가 `dev_sid`로 저장), 이후 그 세션의 모든 명령은 핸들을 와이어 헤더
  `session_id`로 싣는다(실 타겟 레퍼런스와 동일). C_CloseSession은 0x0021.
  자세히: [`session-id-mapping.md`](session-id-mapping.md).
- PKCS#11 상태는 프로세스-전역(한 facade)이라, 서버는 모든 API 호출을 하나의
  뮤텍스로 **직렬화**한다(브라우저 탭이 여럿이어도 토큰은 하나).

## 2. C 웹서버 (`webserver/ncmp_web.c`)

의존성 없는 HTTP/1.1 서버(연결당 스레드). 역할:
- 정적 파일 서빙(`web/`, 경로 `..` 차단, MIME 추론).
- `/api/*` JSON REST 라우팅 → `app_*` 호출 → `{"rc","ok","error",...}` 응답.
- ncmpd 실행/정지(fork+exec/kill)와 상태(waitpid WNOHANG).
- CORS 허용 헤더, `OPTIONS` 프리플라이트.
- `NCMP_WEB_TOKEN` 설정 시 모든 API에 `Authorization: Bearer <token>` 요구
  (정적 파일은 무인증).
- `SIGINT/SIGTERM`은 `sigaction`(SA_RESTART 미사용)으로 받아 `accept()`를 EINTR로
  깨워 깨끗이 종료.

### REST API

| 메서드·경로 | 바디 | app_* / 설명 | 응답 핵심 필드 |
|---|---|---|---|
| `GET /api/status` | — | 서버/데몬 상태 + 설정 | `daemonRunning,transport,sockPath,defaultModule,configPath,host,port,filedir,authRequired` |
| `POST /api/daemon/start` | `{transport}` | ncmpd fork+exec | `pid` |
| `POST /api/daemon/stop` | — | ncmpd 종료 | — |
| `POST /api/load` | `{module?}` | app_load(dlopen+dlsym) | — |
| `POST /api/initialize` | — | C_Initialize | — |
| `POST /api/finalize` | — | C_Finalize | — |
| `GET /api/dlsym` | — | 70개 C_* 심볼 존재 | `report{}` |
| `GET /api/library` | — | C_GetInfo | `info{}` |
| `GET /api/slots` | — | C_GetSlotList | `slots[]` |
| `POST /api/token` | `{slot}` | C_GetTokenInfo | `token{}` |
| `POST /api/mechanisms` | `{slot}` | C_GetMechanismList | `mechanisms[]` |
| `POST /api/session/open` | `{slot,rw}` | C_OpenSession | `session` |
| `POST /api/session/close` | `{session}` | C_CloseSession | — |
| `POST /api/session/info` | `{session}` | C_GetSessionInfo | `session{}` |
| `POST /api/login` | `{session,userType,pin}` | C_Login | — |
| `POST /api/logout` | `{session}` | C_Logout | — |
| `POST /api/random` | `{session,length}` | C_GenerateRandom | `hex,length` |
| `POST /api/digest` | `{session,mech,input}` | C_DigestInit+Digest | `hex,length` |
| `POST /api/gcm-selftest` | `{session}` | GenerateKey+Encrypt/Decrypt 왕복 | `detail` |
| `POST /api/genfile` | `{size,name?,seed?}` | 테스트 파일 생성(PRNG 패턴) | `name,size,sha256`(SW 참조) |
| `GET /api/files` | — | 생성된 파일 목록 | `files[],dir` |
| `POST /api/digest-file` | `{session,mech,name}` | 파일 **multipart**(init/update/final) 해시 | `hex,length,bytes` |
| `POST /api/digest-compare` | `{session,mech,name}` | 토큰 multipart ↔ **SW(OpenSSL)** 비교 | `tokenHex,swHex,match,bytes` |
| `GET /api/scenarios` | — | 서버 저장 시나리오 목록 | `scenarios[],dir` |
| `POST /api/scenario/get` | `{name}` | 저장 시나리오 1건 | `scenario{name,steps}` |
| `POST /api/scenario/save` | `{name,steps[]}` | 시나리오 영구 저장(JSON 파일) | `name` |
| `POST /api/scenario/delete` | `{name}` | 저장 시나리오 삭제 | — |

`rc`: 0=CKR_OK, >0=CKR_* 코드, <0=앱 오류(APP_ERR_*). `ok`는 `rc==0`.
`digest-compare`의 판정은 `rc`(토큰 호출 성공 여부)와 별개로 **`match`** 필드가
담는다(토큰 해시 == SW 해시). `genfile`/`files`는 토큰에 접근하지 않아 API 락
밖에서 처리한다. 파일은 `--filedir`(기본 `/tmp/ncmp_web_files`) 안에서만 다루며
이름은 basename으로 제한(경로 탈출 차단), 1회 처리 상한은 64 MiB.

SW 레퍼런스는 OpenSSL `libcrypto`(EVP)로 계산한다. 지원: SHA-256/512,
SHA3-224/256/384/512.

## 3. 웹 UI (`web/`, 바닐라 HTML/CSS/JS)

프레임워크 없음. `index.html` + `style.css`(다크 테마) + `app.js`.

- **테마**: 헤더의 ☀️/🌙 버튼으로 **라이트/다크** 전환(선택을 localStorage에 저장,
  첫 방문은 OS 설정을 따름). 색은 CSS 변수(`:root` 다크, `:root[data-theme=light]`
  라이트)로 정의. 상세 사용법은 [`testapp-web-manual.md`](testapp-web-manual.md).
- **상단 툴바**: ncmpd 전송 선택·시작/정지·상태 램프, facade 경로·로드·
  C_Initialize/Finalize·슬롯 새로고침·dlsym 점검, 서버 토큰 입력칸.
- **좌측**: 활성 슬롯 리스트(C_GetSlotList). 선택 시 우측 패널이 그 토큰으로 전환.
- **우측 탭**:
  1. **토큰 정보** — C_GetTokenInfo + 메커니즘 목록.
  2. **세션/로그인** — R/W 세션 열기·닫기, 세션 정보, 로그인/로그아웃.
  3. **암복호화/해시** — C_GenerateRandom, C_Digest(SHA-256/512·SHA3),
     AES-GCM 자가검증.
  4. **파일/검증** — ① 크기를 입력해 테스트 파일 생성(바이트/KB/MB; init/update/
     final 시험은 ≥64KB 필요), ② 그 파일을 토큰 **multipart** 해시, ③ **실 타겟
     ↔ SW(OpenSSL) 비교**로 토큰이 정확히 동작하는지 MATCH/MISMATCH 판정.
  5. **PKCS#11 API 시험** — **단위 API 항목**을 골라 파라미터를 채워 1건 실행
     (요청/응답 JSON 표시). 각 항목이 시나리오의 단위 스텝이 된다.
  6. **시나리오** — 단위 스텝을 조합해 시나리오를 만들고 실행(스텝별 PASS/FAIL).
- **하단**: 로그.

### 단위 항목 ↔ 시나리오 엔진 (요구사항 매핑)

- **PKCS#11 API 시험 항목**: `app.js`의 `OPS` 카탈로그(각 op = method·path·
  파라미터 스키마·저장가능 필드). API 탭에서 1건 실행 = "단위 시험".
- **시나리오로 시험**: 내장 시나리오(“Mock 전체 왕복”, “초기화 & 슬롯 조회”,
  “세션/로그인 수명주기”, “음성: 잘못된 PIN 로그인 실패”, “대용량 해시 검증
  (실타겟, ≥64KB)”)를 불러와 실행. 각 스텝은 `성공`/`실패`/`일치`/`불일치` 기대
  단정(assertion)을 가지며 결과 표에 PASS/FAIL과 상세(rc/match/bytes/반환필드)를
  표시. `일치/불일치`는 `digest-compare`의 `match`를 판정한다.
- **단위 조합으로 시나리오 작성**: 시나리오 탭의 **단위 항목 팔레트**(범주별로
  모든 op 표시, 대부분 PKCS#11 함수; 비-PKCS#11 보조 항목은 "도구"로 표기)를
  **순서대로 클릭**하면 스텝이 차례로 추가된다. 각 스텝은 그 자리에서 파라미터
  (텍스트/선택) · `저장변수` · `성공/실패/일치/불일치 기대`를 수정하고 위로이동·
  삭제할 수 있다. "PKCS#11 API 시험" 탭의 “▶ 시나리오에 스텝 추가”로도 추가 가능.
  **변수**: openSession은 기본 `저장변수 s`로 핸들을 담고, 세션 파라미터는 기본
  `${s}`로 채워져 클릭만으로 동작하는 체인이 만들어진다(실행 시 치환).
- **영구 저장**: 저장 시나리오는 **서버**에 JSON 파일로 보관된다(`scendir`,
  `/api/scenario/*`). localStorage가 아니라 서버이므로 브라우저/캐시와 무관하게
  영구적이고 여러 접속자가 공유한다. 이름으로 저장/불러오기/삭제, JSON
  내보내기/가져오기 지원. 내장 시나리오 5종은 `★`, 서버 저장분은 `💾`로 표시.

## 4. 수반된 코어 수정

이전 턴의 수정이 그대로 유효하다:
- **slot_mask UB 수정**(`ncmp_limits.h`의 32비트 캡 매크로 + daemon·common·facade
  전 사이트) → 슬롯 열거 정상화. 255 전면 지원은 bitset 후속(§slot-scaling).
- **hsm_bridge 링크 복구**, **test_concurrency 불변식 완화**.

C# 자산(`csharp/`, app.manifest)과 `testapp-csharp-design.md`는 **삭제**했다.
네이티브 ABI는 그대로 재사용하며, 대용량·검증 기능을 위해
`app_digest_multipart`(C_DigestInit→Update 청크 반복→Final; 기본 32KB 청크로
≥64KB 데이터를 한 프레임 한계 없이 처리)를 추가했다(`app_library_info`/
`app_session_info`도 포함). SW 레퍼런스·파일 I/O는 네이티브가 아니라 웹서버
(`ncmp_web.c`, OpenSSL 링크)가 담당한다.

## 5. 빌드 & 검증

```bash
ncmp/gui/testapp/build.sh            # facade/ncmpd + ncmp_web
ncmp/gui/testapp/build.sh --run      # 빌드 후 0.0.0.0:8080(mock) 실행
```

이 환경(gcc, libusb, 실 FX3 04b4:00f1)에서 **백엔드 전체를 실제 기동·검증**했다.
curl 기반 종합 시험 결과는 [`testapp-web-test-results.md`]
(testapp-web-test-results.md). 요지: 정적 서빙·전 API·음성 로그인(rc=0xA0)·
베어러 토큰 게이트(401/200)·mock 및 실 FX3 모두 정상. (실 FX3는 부트로더
디스크립터라 토큰 아이덴티티는 공백; USB 경로·슬롯 온라인은 정상.)

웹 UI(JS)는 정적 파일 서빙·엔드포인트 응답으로 간접 검증되며, 브라우저 상호작용
자체는 수동 확인 대상(헤드리스 브라우저 미사용).

## 6. 설정 파일 (`.config/config`)

접속 포트 등 Application 설정을 파일로 저장한다. `webserver/ncmp_web.c`의
`load_config()`가 `key = value` 형식을 파싱한다.

- 탐색: `--config PATH` → `$NCMP_WEB_CONFIG` → `./.config/config`.
- 키: `host port webroot module ncmpd transport sock filedir scendir token`.
- 우선순위: **내장 기본값 < 설정 파일 < 환경변수 < CLI 인자**.
- 동봉 샘플: `ncmp/gui/testapp/.config/config`(기본 포트 8080 등). `GET
  /api/status`가 로드된 `configPath`/`port`/`authRequired`를 반환하고 UI 헤더에
  표시한다.

배포(방화벽/udev/systemd/토큰/리버스 프록시)는
[`testapp-web-deployment.md`](testapp-web-deployment.md) 참고.

## 7. 남은 과제

- 브라우저에서의 수동 UI 점검(슬롯 선택·탭·시나리오 빌더 UX).
- “PKCS#11 API 시험” 카탈로그 확장: 객체 관리(C_CreateObject/FindObjects),
  키쌍 생성(ML-KEM/ML-DSA), 서명/검증 — 네이티브 `app_*`와 `/api/*`·`OPS` 추가.
- 다중 사용자 동시 접속 시 세션 격리(현재는 토큰 1개를 직렬화 공유).
- 256슬롯 전면 지원(마스크→bitset), 실 FX3 펌웨어 적재 후 크립토 왕복 재검증.
- 운영 사용 시 HTTPS 리버스 프록시/토큰 필수(§deployment).

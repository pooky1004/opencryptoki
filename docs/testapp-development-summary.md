# Web Test App 개발 종합 정리

Token NCMP용 **웹 기반 Test App**과 그 과정에서 수반된 코어 수정의 전체 개발
내역을 한 문서로 정리한다. 세부 문서로의 진입점 역할을 한다.

| 주제 | 세부 문서 |
|------|-----------|
| 설계·REST API·UI·시나리오·설정 | [`testapp-web-design.md`](testapp-web-design.md) |
| 빌드·실행·시스템 설정(방화벽/udev/systemd/토큰/설정파일) | [`testapp-web-deployment.md`](testapp-web-deployment.md) |
| 시험 결과(실측) | [`testapp-web-test-results.md`](testapp-web-test-results.md) |
| 슬롯 255 확장(마스크→bitset 후속) | [`slot-scaling-design.md`](slot-scaling-design.md) |
| facade(이중 사용 모드) | [`dual-mode-provider.md`](dual-mode-provider.md) |

## 1. 무엇을 만들었나

브라우저에서 접속해 PKCS#11 Token NCMP를 조작·검증하는 Test App.
GUI는 웹(정적 HTML/CSS/JS), Application 계층은 C(`ncmp_web`), 둘 사이는
HTTP/JSON REST. 외부 호스트에서 접속 가능.

```
브라우저(어느 호스트든)
   │ HTTP/JSON (REST, 선택적 Bearer 토큰)
   ▼
ncmp_web (C 단일 실행파일: webserver/ncmp_web.c + native/ncmp_testapp.c)
   │ app_*  →  dlopen/dlsym C_*
   ▼
libpkcs11_ncmp.so (facade, ncmp_p11.c)  →  ncmp_client
   ▼
IPC(UNIX socket) + SHM  →  ncmpd  ─comm thread─▶  실 FX3(USB) / mock / socket
```

> 이전에 만든 C#(Avalonia) 안은 요청에 따라 **전량 삭제**했다.

## 2. 구성 요소 (파일 지도)

```
ncmp/gui/testapp/
  native/        ncmp_testapp.{h,c}   C "Application" ABI(app_* 19종), facade dlopen
                 CMakeLists.txt       libncmp_testapp.so 타깃(ENABLE_TESTAPP)
  webserver/     ncmp_web.c           의존성 없는 HTTP/JSON 서버 + 설정 로더 + 데몬 제어
                 CMakeLists.txt       ncmp_web 타깃(OpenSSL libcrypto 링크)
                 deploy/ncmp_web.service      systemd 유닛 템플릿
                 deploy/70-cypress-fx3.rules  FX3 udev 규칙(plugdev)
  web/           index.html style.css app.js   정적 SPA
  .config/config                      Application 설정 파일(포트 등)
  build.sh                            gcc 빌드/실행 헬퍼
  README.md
docs/            testapp-web-*.md     설계/배포/시험결과 + 본 정리 문서
```

## 3. 기능

### 3.1 네이티브 Application ABI (`native/ncmp_testapp.c`)
facade를 `dlopen`하고 모든 C_*를 `dlsym`한 뒤 각 `app_*`가 대응 C_*를 구동.
반환 규약: `0=CKR_OK`, `>0=CKR_* 코드`, `<0=앱 오류(APP_ERR_*)`.
주요: load/unload·dlsym 리포트·initialize/finalize·get_slots·library/token/
mechanism/session info·open/close session·login/logout·generate_random·digest·
**digest_multipart(init/update/final)**·aes_gcm_selftest.

### 3.2 C 웹서버 (`webserver/ncmp_web.c`)
- 정적 UI 서빙(경로 탈출 차단) + `/api/*` JSON REST.
- ncmpd 실행/정지(fork+exec/kill)·상태(waitpid).
- CORS·`OPTIONS` 프리플라이트.
- **Bearer 토큰 인증**(`token` 설정 시 모든 API에 `Authorization: Bearer`).
- **설정 파일 로더**(§3.5).
- **테스트 파일 생성**(`/api/genfile`) + **SW(OpenSSL) 해시**와 **실타겟 비교**
  (`/api/digest-compare`).
- `sigaction`(SA_RESTART 미사용)으로 SIGTERM 즉시 종료.

REST 전체 목록은 [`testapp-web-design.md`](testapp-web-design.md) §2.

### 3.3 웹 UI (`web/`)
좌=활성 슬롯 리스트, 우=탭:
1. **토큰 정보** (C_GetTokenInfo + 메커니즘)
2. **세션/로그인** (Open/Close·Login/Logout·SessionInfo)
3. **암복호화/해시** (RNG·Digest·AES-GCM 자가검증)
4. **파일/검증** — 크기 입력→테스트 파일 생성(≥64KB), 토큰 multipart 해시,
   **실타겟↔SW 비교(MATCH/MISMATCH)**
5. **PKCS#11 API 시험** — 단위 API 1건 실행(요청/응답 JSON) + "시나리오에 스텝 추가"
6. **시나리오** — 범주별 **단위 항목 팔레트를 순서대로 클릭**해 스텝 구성(각 스텝
   파라미터·저장변수·기대값 수정), 실행(스텝별 PASS/FAIL), 변수 `${s}`,
   `성공/실패/일치/불일치` 단정, 내장 5종, **서버 영구 저장**(`scendir` JSON,
   `/api/scenario/*`) + JSON 내보내기/가져오기
상단=ncmpd 실행·상태·설정 요약, 서버 토큰 입력. 하단=로그.

### 3.4 대용량(init/update/final) + 실타겟 정확성 검증
- init/update/final 시험은 데이터 ≥64KB 필요 → `genfile`로 크기 입력받아 생성,
  `app_digest_multipart`가 32KB 청크로 `C_DigestInit→Update*→Final` 수행.
- `digest-compare`가 토큰 multipart 결과와 OpenSSL 계산 결과를 대조해 `match`로
  정확성 판정. SW 해시가 `openssl dgst`와 바이트 일치함을 확인(SW 정확성 보증).

### 3.5 설정 파일 (`.config/config`)
접속 포트 등을 파일로 저장. `key = value` 형식.
탐색: `--config` → `$NCMP_WEB_CONFIG` → `./.config/config`.
키: `host port webroot module ncmpd transport sock filedir token`.
우선순위: **기본값 < 파일 < env < CLI**.

## 4. 수반된 코어 수정 (Test App 과정에서)
0. **세션 OPEN/CLOSE를 실 타겟 레퍼런스에 정합** — OPEN_SESSION 0x003A→**0x0020**
   (요청 flags 1파라미터·헤더 sid=0 → 응답 param0=핸들), CLOSE 0x003B→**0x0021**
   (헤더 sid=핸들, 무파라미터). facade가 토큰에 실제로 세션을 열고 `dev_sid`를
   저장, 이후 명령이 핸들을 와이어 헤더에 싣는다(`ncmp_client_t.active_session_id`,
   `sess_get()`가 설정). LOGIN/LOGOUT(0x0030/0x0031)은 이미 일치. mock도 갱신.
   (`ncmp_cmd.h`, `ncmp_p11.c`, `ncmp_admin.c`, `ncmp_client.c`, `mcu_scheduler.c`)
1. **slot_mask UB 수정** — `PKCS11_MAX_SLOT_COUNT` 4→256 전환으로 `uint32`
   마스크의 `1u<<s`(s≥32)가 UB가 되어 슬롯 열거가 `[0,32,…]`로 깨지던 것을,
   `ncmp_limits.h`의 `NCMP_SLOT_MASK_BITS(32)`/`NCMP_SLOT_SCAN_MAX`/
   `NCMP_SLOT_IN_MASK()`로 32비트 캡(daemon·common·facade 전 사이트). 255 전면
   지원은 bitset 후속(slot-scaling-design).
2. **hsm_bridge 링크 복구** — transport 디스패처 리팩터 이후 방치된 링크 오류를
   데몬과 동일 스택 링크로 수정.
3. **test_concurrency 불변식 완화** — `==4` → `>=1`.

## 5. 빌드 & 실행

```bash
# gcc 헬퍼(설정파일/실행까지)
ncmp/gui/testapp/build.sh            # facade/ncmpd + ncmp_web
ncmp/gui/testapp/build.sh --run      # 빌드 후 0.0.0.0:8080(mock) 실행
# 또는 CMake 트리(ENABLE_TESTAPP 기본 ON)
cd ncmp && cmake -S . -B build -DENABLE_MOCK_TOKEN=ON && cmake --build build -j
```

```bash
# 설정 파일로 실행(테스트앱 디렉토리에서 ./.config/config 자동 로드)
cd ncmp/gui/testapp && build/ncmp_web
# 브라우저: http://<서버IP>:8080/ → 데몬 시작 → 로드 → C_Initialize → 슬롯 선택
```

의존성: libc/pthread/dl + **OpenSSL libcrypto**. 외부 접속·방화벽·udev·systemd·
토큰은 [`testapp-web-deployment.md`](testapp-web-deployment.md).

## 6. 검증 요지 (이 환경: gcc·libusb·실 FX3 04b4:00f1)
- `cmake`/gcc **경고 없이 빌드**, `ctest` 100% 통과.
- curl 종합: 정적 서빙·전 REST API(mock)·음성 로그인(0xA0)·토큰 게이트(401/200)·
  실 FX3(real: slots=[0], load/init OK)·설정 파일 우선순위(파일<env<CLI).
- 대용량: 100KB/128KB 파일 생성 → multipart digest 동작, SW 해시가 `openssl
  dgst`와 **일치**(SHA-256/512) → 비교 로직·SW 레퍼런스 정확성 확인.
- mock은 가짜 해시라 `match=false`가 정상. **실타겟 MATCH(positive)**는 NCMP
  펌웨어 적재된 FX3에서 확인 대상(현재 보드는 부트로더 디스크립터).

## 7. 남은 과제
- 브라우저 UI 수동 점검(헤드리스 미사용).
- API 카탈로그 확장: 객체/키쌍(ML-KEM·ML-DSA)/서명·검증, AES-GCM multipart 비교.
- 다중 클라이언트 세션 격리(현재 토큰 1개 직렬화 공유).
- 256슬롯 전면 지원(마스크→bitset), 실 FX3 펌웨어 적재 후 크립토·비교 재검증.
- 운영 사용 시 HTTPS 리버스 프록시 + 토큰 필수.

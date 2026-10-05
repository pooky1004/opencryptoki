# Web Test App 시험 결과

`ncmp_web`(웹 Test App 백엔드)에 대한 실측 시험 결과. 설계는
[`testapp-web-design.md`](testapp-web-design.md), 설정은
[`testapp-web-deployment.md`](testapp-web-deployment.md).

- 일자: 2026-10-05
- 환경: Linux x86_64, gcc, libusb-1.0, 실 FX3 `04b4:00f1`(CYUSB3KIT-003) 연결.
- 빌드: `ncmp_web`(`webserver/ncmp_web.c` + `native/ncmp_testapp.c`), 경고 없이
  컴파일. `cmake --build`로 `ncmp_web` 타깃 포함 전체 빌드 성공, `ctest` 통과.
- 방법: 서버를 `127.0.0.1`에 기동 후 `curl`로 각 REST 엔드포인트 호출. 데몬은
  서버의 `/api/daemon/start`가 `ncmpd`를 띄움.

## 1. 요약

| 구분 | 결과 |
|------|------|
| 정적 UI 서빙(`/`, `/app.js`) | **PASS** (HTTP 200, 7408B / 25334B) |
| REST API 전 항목(mock) | **PASS** |
| 음성 케이스(잘못된 PIN 로그인) | **PASS** (rc=0xA0 CKR_PIN_INCORRECT, ok=false) |
| 베어러 토큰 인증 게이트 | **PASS** (무/오류 토큰 401, 정상 토큰 200, 정적은 무인증 200) |
| 실 FX3(`--transport real`) | **PASS** (probe 감지, slots=[0], load/init OK) |
| 깨끗한 종료(SIGTERM) | **PASS** |

## 2. 단위 API 시험 (mock 전송)

서버 기동 → `daemon/start(mock)` → 아래 순서로 호출.

| # | 엔드포인트 | 입력 | 결과 | 비고 |
|---|-----------|------|------|------|
| 1 | `POST /api/daemon/start` | `{transport:mock}` | ok, `pid` 반환 | — |
| 2 | `GET /api/status` | — | ok, `daemonRunning:true` | — |
| 3 | `POST /api/load` | 기본 모듈 | ok | facade dlopen+dlsym |
| 4 | `POST /api/initialize` | — | ok | C_Initialize |
| 5 | `GET /api/library` | — | ok | Cryptoki 3.2 · DYST · NCMP standalone provider v1.0 |
| 6 | `GET /api/dlsym` | — | ok | **70/70** C_* 심볼 확인 |
| 7 | `GET /api/slots` | — | ok | `slots:[0]` (마스크 버그 수정 반영) |
| 8 | `POST /api/mechanisms` | `{slot:0}` | ok | AES-GCM/CTR, SHA-256/512, SHA3-224/256/384/512, AES_KEY_GEN |
| 9 | `POST /api/session/open` | `{slot:0,rw:1}` | ok | `session:1` |
| 10 | `POST /api/session/info` | `{session:1}` | ok | `slot 0, state 2, flags 0x6` |
| 11 | `POST /api/login` | `{session:1,userType:1,pin:"1234"}` | ok | User 로그인 |
| 12 | `POST /api/random` | `{session:1,length:16}` | ok | 16B hex 반환 |
| 13 | `POST /api/digest` | `{session:1,mech:592,input:"abc"}` | ok | SHA-256 32B: `0bccbcc4…bfd87452` |
| 14 | `POST /api/gcm-selftest` | `{session:1}` | ok | `ct=37B, decrypt OK` |
| 15 | `POST /api/login`(음성) | `pin:"9999"` | **의도된 실패** | `rc=160(0xA0) ok:false` |
| 16 | `POST /api/logout` | `{session:1}` | ok | — |
| 17 | `POST /api/session/close` | `{session:1}` | ok | — |
| 18 | `POST /api/finalize` | — | ok | C_Finalize |

> SHA-256, 난수 값은 mock 토큰의 결정적(deterministic) 출력이다. AES-GCM
> 자가검증은 키 생성→암호화→복호화 왕복이 원문과 일치함을 확인한다.

## 3. 시나리오 시험

웹 UI의 "시나리오" 탭 내장 시나리오는 위 단위 항목을 조합한 것으로, 동일한
REST 호출 시퀀스로 검증된다.

| 시나리오 | 스텝(요약) | 기대/결과 |
|----------|-----------|-----------|
| **Mock 전체 왕복** | daemonStart→load→initialize→slots→openSession(`$s`)→login(`${s}`)→random→digest→gcm→logout→closeSession→finalize | 전 스텝 PASS |
| **초기화 & 슬롯 조회** | load→initialize→slots→tokenInfo→mechanisms | 전 스텝 PASS |
| **세션/로그인 수명주기** | openSession(`$s`)→sessionInfo→login→logout→closeSession | 전 스텝 PASS |
| **음성: 잘못된 PIN** | openSession(`$s`)→login(pin 9999, **실패 기대**)→closeSession | login 스텝이 "실패 기대"로 PASS |

변수(`${s}`) 치환: `openSession`의 `session` 출력이 저장변수 `s`로 담겨 이후
스텝의 `session` 파라미터로 전달됨을 §2의 9·11·16·17 연쇄로 확인.

## 4. 인증 게이트 시험

`NCMP_WEB_TOKEN=s3cret`로 기동:

| 요청 | 헤더 | 결과 |
|------|------|------|
| `GET /` (정적) | 없음 | HTTP 200 (무인증 허용) |
| `GET /api/status` | 없음 | HTTP **401** |
| `GET /api/status` | `Bearer nope` | HTTP **401** |
| `GET /api/status` | `Bearer s3cret` | HTTP 200, ok |

## 5. 실 FX3 시험 (`--transport real`)

| 항목 | 결과 |
|------|------|
| ncmpd 로그 | `transport = real`, `running (online slots mask=0x1)` |
| `POST /api/load` | ok |
| `POST /api/initialize` | ok |
| `GET /api/slots` | `slots:[0]` |
| `POST /api/token` | ok, 단 label/manufacturer/serial **공백** |

보드가 FX3 부트로더 디스크립터(`04b4:00f1`)로 올라와 NCMP 펌웨어가 없어 토큰
아이덴티티 질의에 응답하지 않는다(5초 read 타임아웃 후 online). USB 경로·슬롯
온라인·웹 전 구간은 정상 동작한다. 크립토 왕복은 펌웨어 적재 후 재검증 필요.

## 6. 테스트 파일 생성 + multipart(init/update/final) + 실타겟↔SW 비교

mock 전송, 세션 1개로 수행.

| # | 엔드포인트 | 입력 | 결과 |
|---|-----------|------|------|
| 1 | `POST /api/genfile` | `{size:100000,name:"big.bin"}` | ok, size=100000, SW SHA-256=`9adf3fe4…` |
| 2 | `GET /api/files` | — | ok, `big.bin (100000B)` |
| 3 | `POST /api/digest-file` | `{mech:592,name:"big.bin"}` | ok, 32B, **bytes=100000**(32KB 청크×4의 multipart) |
| 4 | `POST /api/digest-compare`(SHA-256) | `big.bin` | token=`7e06d952…`, sw=`9adf3fe4…`, **match=false** |
| 5 | `POST /api/genfile` | `{size:131072,name:"verify.bin"}`(128KB) | ok |
| 6 | `POST /api/digest-compare`(SHA-512) | `verify.bin` | bytes=131072, **match=false** |

**SW 레퍼런스 정확성 교차검증** (핵심): 웹서버가 계산한 SW 해시가 독립 도구
`openssl dgst`와 **바이트 단위로 일치**함을 확인 → SW 쪽이 올바른 SHA다.

| 메커니즘 | web SW(앞부분) | `openssl dgst`(앞부분) | 일치 |
|---------|----------------|------------------------|------|
| SHA-256 (big.bin) | `9adf3fe4093c9ebf…` | `9adf3fe4093c9ebf…` | ✔ |
| SHA-512 (verify.bin) | `aac76ba0003de8ba…` | `aac76ba0003de8ba…` | ✔ |

해석: **SW 계산이 정확**하므로, 정상 동작하는 실 타겟이라면 토큰 multipart 결과가
SW와 **일치(match=true)**해야 한다. 현재 연결된 FX3는 NCMP 펌웨어가 없어
(부트로더 디스크립터) 실제 해시를 내지 못하고, mock 토큰은 결정적 가짜 해시라
`match=false`가 나오는 것이 정상이다. 즉 비교 로직·SW 레퍼런스·multipart 경로는
검증되었고, 정확성 판정(MATCH)은 **펌웨어가 적재된 실 타겟**에서 positive로
확인하면 된다.

> `digest-compare`의 `rc`는 토큰 호출 성공 여부(여기선 0)이고, 정확성 판정은
> `match` 필드다. 시나리오 스텝의 `일치/불일치 기대` 단정이 이 `match`를 본다.

## 7. 미검증/제약

- 웹 UI의 브라우저 상호작용(슬롯 클릭, 탭 전환, 시나리오 빌더 드래그/편집)은
  수동 확인 대상(헤드리스 브라우저 미사용). 정적 서빙과 REST 응답으로 간접 검증.
- 다중 클라이언트 동시성: 토큰 1개를 서버가 직렬화 공유(세션 격리 없음).
- 실 FX3 크립토(암복호/해시/서명)는 NCMP 펌웨어 적재 후 재시험 대상.
- **실타겟 MATCH(positive) 판정**: 펌웨어가 올라간 실 타겟에서 `digest-compare`가
  `match=true`가 되는지 확인 필요(현 환경은 부트로더라 미확인). 비교 로직·SW
  레퍼런스·multipart는 §6에서 검증됨.

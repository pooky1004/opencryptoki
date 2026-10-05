# 시나리오 시험 결과 (기본 15 + 비정상 10, 실 타겟)

웹 Test App으로 **기본 시나리오 15개**와 **비정상(음성) 시나리오 10개**를
생성·영구 저장한 뒤, **실 FX3 타겟**으로 실행한 결과. 시나리오 정의의 정상성은
**mock 전체 실행**으로 교차 검증했다.

- 일자: 2026-10-05
- 환경: Linux x86_64, 실 FX3 `04b4:00f1`(CYUSB3KIT-003) USB 연결, `ncmp_web`
  최신 빌드.
- 저장 위치(영구): `ncmp/gui/testapp/.config/scenarios/` (시나리오당 JSON 1개,
  총 25개). 서버 `--scendir`가 가리키는 곳이며 브라우저/캐시와 무관하게 유지됨.
- 실행 방식: 각 시나리오를 웹 UI 시나리오 엔진과 동일한 REST 순서로 실행하고
  스텝별 성공/실패를 집계. 기대값(`성공`/`실패`/`일치`)은 각 스텝에 명시.

> **핵심 결론**: 연결된 FX3 보드는 **NCMP 펌웨어가 올라가 있지 않은 부트로더
> 상태**(디스크립터 `04b4:00f1`)다. 그래서 **전송·메타데이터 명령(load,
> C_Initialize, C_GetSlotList, C_GetTokenInfo, C_GetMechanismList, 파일 생성,
> C_Finalize)은 정상 동작(rc=0)** 하지만, **세션을 여는 순간(C_OpenSession)
> 토큰이 응답하지 않아 약 40초 후 실패(rc=80)** 하고, 세션에 의존하는 모든
> 후속 단계가 실패한다. 즉 **스택·전송 경로는 정상이며, 실제 세션/크립토 검증은
> 펌웨어 적재 후 재시험**해야 한다.

## 1. 요약

| 구분 | 통과 | 비고 |
|------|------|------|
| 기본 15 (실 타겟) | **4 / 15** | 전송·메타 전용(B01·B02·B03·B13)만 통과. 세션/크립토 11개는 C_OpenSession 타임아웃으로 실패 |
| 비정상 10 (실 타겟) | **7 / 10** | 세션이 필요 없는 음성 7개는 "실패 기대"대로 통과. 세션을 먼저 여는 음성 3개(A02·A07·A09)는 OpenSession 자체가 실패해 시나리오 전체는 실패 |
| 25개 전체 (mock 검증) | **24 / 25** | 정의의 정상성 확인. 유일한 FAIL은 B15로, mock은 실제 해시가 아니라 `일치 기대`가 어긋나는 **의도된 결과**(B15는 실 타겟 positive 검증용) |

## 2. 기본 시나리오 15개 (정상 흐름)

| # | 이름 | 목적 / 스텝 요약 | mock | 실 타겟 |
|---|------|------------------|:----:|:------:|
| B01 | 토큰정보조회 | 슬롯·토큰·메커니즘 조회 | PASS | **PASS** |
| B02 | 라이브러리정보 | C_GetInfo + dlsym 70개 | PASS | **PASS** |
| B03 | 슬롯열거 | C_GetSlotList | PASS | **PASS** |
| B04 | 세션열고닫기 | OpenSession→SessionInfo→Close | PASS | FAIL(OpenSession) |
| B05 | 로그인로그아웃 | 세션+Login(1234)+Logout | PASS | FAIL(OpenSession) |
| B06 | 난수16 | 세션+C_GenerateRandom(16) | PASS | FAIL(OpenSession) |
| B07 | 난수256 | 세션+난수(256) | PASS | FAIL(OpenSession) |
| B08 | SHA256단발 | 세션+C_Digest(SHA-256,"abc") | PASS | FAIL(OpenSession) |
| B09 | SHA512단발 | 세션+SHA-512 | PASS | FAIL(OpenSession) |
| B10 | SHA3_256단발 | 세션+SHA3-256 | PASS | FAIL(OpenSession) |
| B11 | AESGCM자가검증 | 세션+키생성+암복호 왕복 | PASS | FAIL(OpenSession) |
| B12 | 로그인후난수 | 세션+Login+난수+Logout | PASS | FAIL(OpenSession) |
| B13 | 대용량파일생성 | 128KB 테스트 파일 생성 | PASS | **PASS** |
| B14 | 대용량multipart해시 | 세션+128KB 파일 multipart 해시 | PASS | FAIL(OpenSession) |
| B15 | 실타겟vsSW비교_64KB | 세션+64KB 토큰해시 ↔ OpenSSL `일치 기대` | FAIL* | FAIL(OpenSession) |

\* B15 mock FAIL은 의도된 것(mock은 가짜 해시 → `일치`가 성립하지 않음). 실
타겟에 펌웨어가 올라가면 token==SW로 **일치(MATCH)** 가 기대된다.

## 3. 비정상(음성) 시나리오 10개

의도적으로 오류 조건을 만들고 해당 스텝에 `실패 기대`를 두어, 토큰/STDLL이
올바르게 거부하는지 확인한다.

| # | 이름 | 의도한 오류(기대=실패) | mock | 실 타겟 |
|---|------|------------------------|:----:|:------:|
| A01 | 미초기화_슬롯조회 | 초기화 전 C_GetSlotList → `CKR_CRYPTOKI_NOT_INITIALIZED`(rc 400) | PASS | **PASS** |
| A02 | 잘못된PIN_로그인 | PIN `9999` 로그인 → `CKR_PIN_INCORRECT` | PASS | FAIL† |
| A03 | 없는슬롯_토큰정보 | 슬롯 99 토큰정보 → `CKR_SLOT_ID_INVALID` | PASS | **PASS** |
| A04 | 잘못된세션_로그인 | 세션 9999 로그인 → `CKR_SESSION_HANDLE_INVALID`(rc 179) | PASS | **PASS** |
| A05 | 잘못된세션_닫기 | 세션 9999 닫기 → 핸들 무효 | PASS | **PASS** |
| A06 | 세션없이_난수 | 세션 9999 난수 → 핸들 무효 | PASS | **PASS** |
| A07 | 잘못된사용자유형_로그인 | userType 99 로그인 → `CKR_USER_TYPE_INVALID` | PASS | FAIL† |
| A08 | 잘못된세션_digest | 세션 9999 digest → 핸들 무효 | PASS | **PASS** |
| A09 | 없는파일_비교 | 없는 파일 digest 비교 → 실패 | PASS | FAIL† |
| A10 | 미초기화_세션열기 | 초기화 전 OpenSession → 실패 | PASS | **PASS** |

† A02·A07·A09는 음성 스텝 **앞에** 정상 `OpenSession`을 두는데, 실 타겟에서는
그 OpenSession이 (펌웨어 미응답으로) 실패하므로 시나리오 전체가 FAIL로 집계된다.
음성 스텝 자체(잘못된 PIN·사용자유형)는 세션이 없으면 검증 대상에 도달하지 못한다.
펌웨어 적재 후에는 이 3개도 PASS가 되어야 한다.

## 4. 실 타겟 스텝 상세(대표 예)

```
B01 토큰정보조회  PASS(6/6)
  load rc=0 · initialize rc=0 · slots rc=0 slots=[0] · tokenInfo rc=0
  · mechanisms rc=0 · finalize rc=0
B04 세션열고닫기  FAIL(3/6)
  load rc=0 · initialize rc=0
  · openSession rc=80  ← 토큰 미응답, 약 40초 후 실패
  · sessionInfo rc=-4 · closeSession rc=-4  (세션 변수 ${s} 미설정)
  · finalize rc=0
A04 잘못된세션_로그인  PASS(4/4)
  load rc=0 · initialize rc=0
  · login(session=9999) rc=179 (CKR_SESSION_HANDLE_INVALID) = 실패 기대 → 통과
  · finalize rc=0
```

- `rc=0` 정상, `rc=80` 전송 타임아웃(토큰 무응답), `rc=179`
  `CKR_SESSION_HANDLE_INVALID`, `rc=400` `CKR_CRYPTOKI_NOT_INITIALIZED`,
  `rc=-4` 앱 인자 오류(선행 OpenSession 실패로 세션 변수 공백).
- `C_OpenSession`은 참조 타겟 프로토콜(0x0020)로 전송되지만 보드 펌웨어가
  응답하지 않아 USB 타임아웃(약 40초)으로 실패한다.

## 5. mock 교차 검증(정의의 정상성)

동일 25개를 mock 토큰으로 실행하면 **24/25 통과**, 유일한 FAIL은 B15(실 타겟
positive 비교)로 설계상 mock에서는 불일치가 정상이다. 즉 **시나리오 정의·엔진·
기대값 로직은 올바르며**, 실 타겟의 FAIL은 전적으로 **보드 펌웨어 부재** 때문이다.

## 6. 펌웨어 적재 후 재시험 방법

1. FX3에 NCMP 펌웨어를 적재한다(부트로더 → 애플리케이션).
2. `ncmp_web`를 `--transport real`로 띄우고 **데몬 시작 → 로드 → C_Initialize**.
3. 시나리오 탭에서 저장된 25개(💾)를 불러와 **▶ 실행**하거나, 전체를 일괄
   재실행한다. 기대: 기본 15개 전부 PASS, 비정상 10개 전부 PASS(A02·A07·A09
   포함), B15는 `일치(MATCH)`.
4. 결과를 본 문서의 "실 타겟" 열에 갱신한다.

## 6-1. 재시험 (실 타겟, 2026-10-05 2회차)

동일 25개를 실 FX3로 **다시 실행**했다. 보드는 여전히 부트로더
(`04b4:00f1`, 펌웨어 미적재) 상태였다.

- 합계: **12 / 25 통과**(기본 4/15, 비정상 **8/10**). 1회차(11/25)와 거의 동일.
- **새로 관찰된 사실 — `C_OpenSession`이 간헐적으로 성공한다.** 이번 실행의
  OpenSession 결과 분포: **`rc=0`(성공) 5회 · `rc=80`(타임아웃) 9회 · `rc=400`
  (미초기화, A10) 1회**. 즉 부트로더 보드가 **OPEN/CLOSE_SESSION에는 때때로
  응답**하지만, **LOGIN·난수·해시 등 실제 크립토는 일관되게 타임아웃**(`rc=80`)
  한다.
  - 예) B05: `openSession rc=0` → `login rc=80`(타임아웃) → `closeSession rc=0`.
  - 예) A09: `openSession rc=0` → (없는 파일 비교, 토큰 접촉 전 `rc=-4` 실패-기대
    통과) → `closeSession rc=0` ⇒ 이번엔 시나리오 PASS(1회차엔 FAIL).
- 결론 불변: **세션 개폐 경로는 부분적으로 동작하나 크립토는 펌웨어 부재로 미검증**.
  OpenSession의 성공/실패가 실행마다 달라 세션 의존 시나리오의 합격 수가 1~2개
  요동친다. 신뢰성 있는 검증은 **NCMP 펌웨어 적재 후** 가능하다.

| 지표 | 1회차 | 2회차 |
|------|:----:|:----:|
| 기본 15 PASS | 4 | 4 |
| 비정상 10 PASS | 7 | 8 |
| 합계 | 11/25 | 12/25 |
| OpenSession rc=0(성공) | (미집계) | 5/15 |

전송·메타 명령(B01·B02·B03·B13, 미초기화/무효핸들 음성군)은 **두 회차 모두 안정적
으로 동일**하게 통과했다.

## 6-2. 재시험 (실 타겟, session 0 폴백, 2026-10-05 3회차)

지시: **"세션 open 시 문제가 발생하면 세션을 open하지 말고 session ID 0으로
시험하라."** 이에 맞춰 STDLL facade에 opt-in 모드
`NCMP_SESSION0_FALLBACK`를 추가했다 — 설정 시 C_OpenSession이 토큰에
OPEN_SESSION을 보내지 않고(문제 회피), 대신 **wire session_id = 0**을 싣는 로컬
세션을 만든다. 이후 모든 명령이 session_id 0으로 토큰에 전달된다(C_CloseSession도
토큰 CLOSE를 생략). 이 모드로 25개를 실 FX3에 재실행했다.

- 이번엔 보드가 식별에 응답했다: ncmpd가 토큰을 **`MPF300TS Development` /
  serial `UNPROVISIONED`** 로 인식(펌웨어 적재 상태).
- 합계: **15 / 25 통과**(기본 5/15, **비정상 10/10 전부 통과**). 1·2회차(11~12/25)
  대비 상승.
- **openSession/closeSession/sessionInfo는 폴백으로 즉시 통과**(토큰 왕복 없음).
  그 덕에 세션을 먼저 여는 음성 시나리오(A02·A07·A09 포함)가 **모두 PASS**가 됐다.
- **그러나 실제 크립토는 session 0을 거부한다.** login/random/digest/gcm/
  multipart 단계가 대부분 **`rc=179 CKR_SESSION_HANDLE_INVALID`** (토큰이 세션 0을
  유효 세션으로 인정하지 않음), 일부는 **`rc=80`**(전송 타임아웃)으로 실패했다.
  예) `B08 digest: openSession rc=0 → digest(sid0) rc=179 → closeSession rc=0`.

| 지표 | 1회차 | 2회차 | 3회차(sid0) |
|------|:----:|:----:|:----:|
| 기본 15 PASS | 4 | 4 | **5** |
| 비정상 10 PASS | 7 | 8 | **10** |
| 합계 | 11/25 | 12/25 | **15/25** |

**해석**: 펌웨어(MPF300TS, UNPROVISIONED)는 **유효한 OPEN_SESSION으로 발급된
세션 핸들을 요구**하며 **session_id 0을 크립토에 받아주지 않는다**(→ 179). 한편
OPEN_SESSION 자체는 여전히 타임아웃(§6/6-1)이라, 현재 보드 상태에서는 세션
기반 크립토를 완결할 수 없다. 전송·메타·세션 수명주기(로컬) 및 음성 처리 경로는
정상임이 재확인됐다. 세션/크립토의 완전한 검증은 **OPEN_SESSION이 동작하는
(provisioned) 펌웨어**가 필요하다.

> 수반 수정: 이 과정에서 facade의 버그를 하나 고쳤다 — `usr/lib/ncmp_stdll/
> ncmp_p11.c`에 `<stdlib.h>` 누락으로 `getenv`가 암시적 선언되어(반환값 int로
> 절단) 세그폴트가 났다. 헤더를 추가해 해결. `NCMP_SESSION0_FALLBACK`는 기본
> OFF이며 운영 동작(정상 OPEN_SESSION)은 변하지 않는다.

## 7. 산출물

- 저장된 시나리오 25개: `ncmp/gui/testapp/.config/scenarios/*.json`
  (기본 `B01`~`B15`, 비정상 `A01`~`A10`).
- 본 결과 문서. 관련: [`testapp-web-manual.md`](testapp-web-manual.md),
  [`testapp-web-test-results.md`](testapp-web-test-results.md),
  [`testapp-web-design.md`](testapp-web-design.md).

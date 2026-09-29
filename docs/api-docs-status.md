# API 문서화 작업 요약 — 진행/남은 과제

- **작성일**: 2026-09-29
- **범위**: `libpkcs11_ncmp.so`(STDLL)와 `ncmp/stdll` 미들웨어의 **API 레퍼런스 문서화**
- **관련 색인**: [`INDEX.md`](INDEX.md) · 종합 현황: [`SUMMARY.md`](SUMMARY.md) /
  [`STATUS.md`](STATUS.md)

> 이 문서는 최근 세션의 **문서화 작업**만 요약한다. 프로젝트 전체 현황은
> `SUMMARY.md`/`STATUS.md`를 본다.

---

## 1. 지금까지 한 일 (Done)

### 1.1 미들웨어 API 레퍼런스 — `ncmp/stdll/*.c`
- **문서**: [`middleware_api.md`](middleware_api.md) (+ `.docx`)
- **내용**: 전송 계층(`ncmp_client.c`/`ncmp_session.c`/`ncmp_ckr.c`) + 마샬링 어댑터
  (`ncmp_admin.c`/`ncmp_crypto.c`/`ncmp_object.c`)의 **함수 43개** 각각을
  기능 / 원형 및 인자 / 반환값으로 정리. 어댑터 공통 반환값 규약(자체 검증 /
  토큰 ack / 전송오류 `ncmp_err_to_ckr()` 매핑) 포함.
- **커밋**: `e8973f47`(md), `496ef885`(docx)

### 1.2 애플리케이션 API 레퍼런스 (opencryptoki 경유) — `SC_*`/`C_*`
- **문서**: [`cryptoki_app_api.md`](cryptoki_app_api.md) (+ `.docx`)
- **내용**: `opencryptoki_tok.map`가 export 하는 **73개 심볼**(72 `SC_*` +
  `ST_Initialize`)을 근거로, opencryptoki 앱이 호출하는 표준 `C_*` 관점에서
  기능 / 원형 및 인자 / 반환값 정리. §0에 구조체·`#define` 선정의(CK_MECHANISM /
  CK_ATTRIBUTE / CK_*_INFO / 세션 flags / 사용자 역할 / NCMP 한계상수). 부록 A:
  심볼 → `C_*` → NCMP 지원여부 73행 대응표.
- **커밋**: `ebb6f5a2`

### 1.3 직접(비-opencryptoki) 사용 API 레퍼런스 — `SC_*` 직접 호출
- **문서**: [`pure_app_api.md`](pure_app_api.md) (+ `.docx`)
- **내용**: pkcsslotd/슬롯매니저 SHM 없이 `.so`를 직접 로드해 export 심볼을 호출하는
  관점. **전제 명시**: 이 `.so`는 독립 PKCS#11 프로바이더가 아니라 STDLL(토큰 SPI)이며
  `C_GetFunctionList`/`C_*`를 export 하지 않음 → 앱이 api 계층 역할(TokData 할당·
  초기화, `API_Slot_t`/`SLOT_INFO` 구성, `ST_Initialize`, 세션핸들→`ST_SESSION_T`
  래핑)을 대신해야 함. **토큰 전송은 여전히 ncmpd(UNIX 소켓 + POSIX SHM) 필수**이고
  slotd의 SHM만 회피됨을 정정. §0 구조체/상수 + 직접 초기화 시퀀스 + 함수별 3항목 +
  부록(카테고리별 전 심볼).
- **커밋**: `8b518d1a`

### 1.4 아키텍처 Q&A 문서 — ncmpd vs pkcsslotd
- **문서**: [`ncmpd-vs-pkcsslotd.md`](ncmpd-vs-pkcsslotd.md)
- **내용**: "USB 명령 pipeline을 pkcsslotd로 할 수 있나?"에 대한 근거 기반 답변.
  slotd=컨트롤 플레인(슬롯/프로세스/이벤트, 명령 경로에 없음) vs ncmpd comm_thread=
  데이터 플레인(단일 USB 소유·in-flight pipeline). 파일:라인 근거 인덱스 포함.
- **커밋**: `10b5af99`

### 1.5 부수 작업
- `docs/INDEX.md`에 위 신규 문서 항목 3건 추가.
- 모든 docx는 `pandoc -f gfm -t docx --toc`로 생성 후 zip/OpenXML 유효성 확인.

---

## 2. 문서화에서 확정한 핵심 사실

- **export API 표면 = 73 심볼** (`opencryptoki_tok.map`의 `global:`; `local: *;`로
  나머지 은닉). 실체는 `new_host.c`의 `SC_*` + `ST_Initialize`.
- **`SC_HandleEvent`는 정의만 되고 export 안 됨** → API 표면 아님(내부
  `function_list.ST_HandleEvent` 연결 전용).
- **`.so`는 표준 `C_*`/`C_GetFunctionList`를 export 하지 않는다** → 비-opencryptoki
  앱이 표준 PKCS#11 모듈로 직접 적재 불가. 직접 사용은 api 계층 재구현을 수반.
- **지원 메커니즘**(`tok_struct.h` 훅 기준): AES-GCM/CTR, SHA-256/512, SHA3-*,
  SHAKE KDF, ML-DSA/ML-KEM, RNG, AES 키생성. 미지원: RSA/EC/DH/HMAC, wrap/unwrap,
  recover, 연산상태 저장, seed-random, 멀티파트 서명/검증 → `CKR_MECHANISM_INVALID`
  / `CKR_FUNCTION_NOT_SUPPORTED`.

---

## 3. 남은 과제 (TODO)

### 3.1 문서 관련
- [ ] **하드웨어 확정 후 반영**: 실 FX3 VID/PID/EP·타이밍이 정해지면
  `CK_TOKEN_INFO` 필드(제조사/모델/버전)·`SC_GetTokenInfo` 서술을 실측값으로 갱신.
- [ ] **직접 사용 최소 예제 코드**: `pure_app_api.md`의 초기화 시퀀스를 실제 컴파일되는
  샘플(`STDLL_TokData_t` 준비 → `ST_Initialize` → `SC_*`)로 보강 여부 검토(현재는
  개요 수준). *opencryptoki 프레임워크 없이 tokdata를 채우는 난이도가 높아 지원
  범위/권장 여부 결정 필요.*
- [ ] **영문 요약 필요 시** 각 API 문서의 영문판/영문 초록 추가 여부 결정(현재 한국어).
- [ ] docx 산출물의 저장소 포함 정책 확인(현재 md+docx 동반 커밋 중).

### 3.2 코드/검증 (문서 밖, 종합 현황과 공유)
- [ ] 실 하드웨어 브링업(VID/PID/EP 확정, `pkcsconf` 런타임 검증, 실 암호 정합성) —
  `SUMMARY.md`의 "미완(하드웨어 필요)"와 동일.
- [ ] end-to-end `C_EncryptUpdate` 등 멀티파트 경로는 full opencryptoki 빌드에서 실행
  검증 필요(standalone 스위트로는 `ncmp_specific.c` 미적재).

---

## 4. 산출물 위치

| 문서 | 파일 |
|------|------|
| 미들웨어 API | `docs/middleware_api.md` (+ `.docx`) |
| 앱 API (opencryptoki 경유) | `docs/cryptoki_app_api.md` (+ `.docx`) |
| 앱 API (직접 사용) | `docs/pure_app_api.md` (+ `.docx`) |
| ncmpd vs pkcsslotd | `docs/ncmpd-vs-pkcsslotd.md` |
| 색인 | `docs/INDEX.md` |

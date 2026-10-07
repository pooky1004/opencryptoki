# PEM × Web Test App 연동 개발 계획서

작성일: 2026-10-07 · 브랜치: `ncmp-pem-module`

목표: **Web Test App에서 PKCS#11 API를 호출 → PEM PKCS#11 provider → PEM CI v4 →
USB(`04b4:5054`) 로 메시지를 보내고 결과를 받는다.** CI 상세는
[`pem-command-interface.md`](pem-command-interface.md) 참조.

---

## 0. 범위

- **대상**: 기존 Web Test App(`ncmp/gui/testapp`)에 **PEM 백엔드**를 추가.
- **포함**: 백엔드(토큰) 선택, PEM PKCS#11 provider 로드·구동, PEM에 맞는 UI/엔드포인트,
  USB 권한, 관측성(CI 패킷 로그), 실 타겟 시험.
- **제외(1차)**: PEM용 멀티프로세스 데몬화(현재 PEM은 단일 프로세스 USB 직결), pkcsslotd 통합.

---

## 1. 현황 분석

### 1.1 Web Test App 현재 구조 (NCMP)
```
브라우저 ──HTTP/JSON──▶ ncmp_web ──dlopen/dlsym──▶ libpkcs11_ncmp_p11.so(facade)
                           │                             │ ncmp_client
                           └─ ncmpd 관리(spawn/reclaim)   ▼
                                                      ncmpd(UNIX socket + SHM) ─▶ USB 04b4:00f1
```
- ncmp_web은 `--module`로 지정한 **임의 PKCS#11 .so를 dlopen**하여 `/api/*`로 구동
  (load/initialize/slots/token/session/login/random/digest/encrypt…). 범용 하네스다.
- NCMP 전용: **ncmpd 데몬 관리**(데몬 시작/정지, 좀비 회수), **SHM 세션맵/통계**,
  Debug App(SHM 뷰어), (pid,app_sid)→hsm_sid 매핑.

### 1.2 PEM 측 기존 자산 (`/home/pooky/ji/host`)
- **`pkcs11/ci_pem_pkcs11.c` → `build/libci_pem_pkcs11.so`**: 완전한 PKCS#11 provider.
  `C_GetFunctionList` + 전체 C_ 세트(Initialize/Slot/Token/Session/Login/Create·Destroy·
  Find Object/Encrypt·Decrypt(+Update/Final)/Digest(+Update/Final)/Sign·Verify/
  GenerateKey·KeyPair/GenerateRandom…) 구현.
- **연결 모델**: `CI_USB_Open()`(기본 옵션 VID 0x04b4/PID 0x5054)로 **usbfs 직결**,
  `CI_PEM_Session`/CI v4로 통신. **데몬·SHM 없음, 단일 프로세스.** `CI_PEM_PKCS11_Attach()`로
  외부에서 연 디바이스 차용(borrow)도 가능.
- 광고 메커니즘: **AES-GCM(키 32B), SHA3-256/384/512** (`C_GetMechanismList`/`Info`).
  PQC(ML-DSA/ML-KEM) 및 AES-CTR·키ID 연산은 CI/라이브러리에는 있으나 mech 광고 범위는
  구현 확인 필요.
- CI 라이브러리: `ci/`(cifx_protocol, ci_usb_lib, ci_pem_lib, ci_commands), 빌드 `Makefile`.

### 1.3 NCMP vs PEM 비교 (설계에 영향)

| 항목 | NCMP (기존) | PEM (신규) |
|------|------|------|
| USB ID | 04b4:00f1 | **04b4:5054** |
| 와이어 | 20B 헤더+param_len[8], 정수 4B | **16B 헤더, 인자 정수 8B LE** (CI v4) |
| 중개 | ncmpd 데몬 + SHM(멀티프로세스) | **없음(단일 프로세스 USB 직결)** |
| PKCS#11 | libpkcs11_ncmp_p11.so | **libci_pem_pkcs11.so (기존)** |
| 세션 | (pid,app_sid)↔hsm_sid SHM 매핑 | provider 내부 hSession |
| 키 모델 | 보안키 토큰(인라인 키) | 저장 키 ID(1–26)+마스터키+입력키 |
| 관측성 | Debug App(SHM TX/RX) | SHM 없음 → CI 패킷 로그 필요 |

---

## 2. 목표 아키텍처

```
브라우저 ──HTTP/JSON──▶ ncmp_web ──dlopen/dlsym──▶ libci_pem_pkcs11.so
   (백엔드=PEM 선택)        │ (데몬 관리/ SHM 비활성)      │ CI v4 (16B hdr, 8B args, LE)
                           └─ USB 권한 확인               ▼
                                                     usbfs bulk OUT 0x01 / IN 0x81 ─▶ FX3 PEM 04b4:5054
```

**핵심 설계 결정**: Web Test App은 이미 "임의 PKCS#11 .so를 dlopen하는 범용 하네스"이므로,
**기존 `libci_pem_pkcs11.so`를 모듈로 로드**하는 것을 1차 방안으로 한다(신규 코드 최소화).
ncmp_web에 **백엔드 모드**(① NCMP=데몬, ② PEM=USB 직결 모듈)를 도입해 모드별로
lifecycle·UI를 분기한다.

> 대안(2차): opencryptoki 트리 안에 PEM facade를 NCMP facade 패턴으로 재구현.
> 장점은 저장소 일관성, 단점은 중복 구현. **1차는 기존 provider 재사용을 권장.**

---

## 3. 설계 상세

### 3.1 백엔드 모드 추상화 (ncmp_web)
- `--backend ncmp|pem`(기본 ncmp) + `/api/status`에 `backend` 노출, UI에서 선택.
- **PEM 모드 lifecycle**:
  - `데몬 시작/정지` **비활성**(PEM은 데몬 없음). 대신 `모듈 로드 → C_Initialize`가
    곧 USB 오픈. 단일 프로세스이므로 ncmp_web이 USB를 **점유**한다.
  - `/api/sessmap`·SHM 의존 기능 **비표시**.
  - 기본 `--module`을 `libci_pem_pkcs11.so` 경로로 설정.

### 3.2 ncmp_web 변경
- `g_backend` 상태 + 모드별 라우팅 게이팅(데몬 라우트는 PEM에서 no-op/안내).
- USB 권한 사전 점검 엔드포인트(`/api/usbcheck`): `04b4:5054` 접근 가능 여부(usbfs) 확인,
  실패 시 udev 설정 안내(`tools/setup_usb_permissions.py` 참고).
- 기존 crypto 엔드포인트(`/api/random|digest|encrypt|digest-file|encrypt-file`)는
  **PKCS#11 표준 호출**이라 provider만 바뀌면 재사용 가능(아래 3.3 검증).

### 3.3 native(app_ 헬퍼) 호환성
- ncmp_testapp.c는 표준 C_ 함수를 dlsym → **PEM provider와 그대로 호환** 목표.
- 점검/대응 항목:
  - PEM `C_GetMechanismList` 결과(AES-GCM/SHA3)에 맞춰 UI 메커니즘 선택지 구성.
  - **키 모델**: PEM provider의 `C_CreateObject(CKA_VALUE)`+`C_EncryptInit(GCM)` 매핑 확인
    (사용자 키 GCM). 저장 키 ID(1–26) 사용 경로는 별도 UI 옵션으로 노출 검토.
  - **SHA3 전용**(SHA-2 미지원) → digest 기본 mech를 SHA3로.
  - AES-CTR·PQC 지원 여부를 mech/함수로 확인 후 페이지 활성/비활성.
  - 단발·멀티파트 digest/GCM: PEM provider의 Update/Final 구현으로 ≥64KB 시험 가능.

### 3.4 UI
- 상단에 **백엔드 선택**(NCMP / PEM). PEM 선택 시:
  - 데몬 그룹·Debug(SHM) 메뉴 숨김/비활성, 모듈 경로 기본값 PEM.
  - 세션 관리·토큰 정보·메커니즘·난수·AES-GCM·SHA3·(가능 시)PQC 페이지는 공용 재사용.
  - PEM 전용 정보 카드: **키 테이블**(KEYTABLE_INFO, 공개 메타데이터 30×32B),
    CAPABILITIES(api_version/slots/mask) 조회.

### 3.5 관측성 (SHM 대체)
- PEM은 SHM이 없으므로 Debug App 대신 **CI 패킷 로그**:
  - provider/ci 라이브러리에 TX/RX 프레임 훅이 있으면 활용, 없으면
    `tools/show_ci_packets.py` 방식(요청/응답 16진수+파싱)을 ncmp_web 측에서 기록하는
    `/api/pem/lastci` 추가 검토(마지막 CI TX/RX raw+parsed, >512B는 파일 스필 재사용).

### 3.6 빌드 통합
- 1차: `/home/pooky/ji/host`에서 `make`로 산출된 `libci_pem_pkcs11.so`를 **경로 지정 로드**.
- 중기: PEM `ci/`+provider 소스를 opencryptoki 트리(예: `ncmp/pem/` 또는 별도)로 반입하고
  `build.sh`에 PEM provider 타깃 추가(라이선스·의존성 확인).

---

## 4. PKCS#11 ↔ PEM CI 매핑 (요약)

| PKCS#11 | PEM CI 명령 | 비고 |
|---------|------------|------|
| C_OpenSession / CloseSession | SESSION(0x0023) action 1/2 | hSession=헤더 SESSION_ID |
| C_GetTokenInfo / MechanismList | CAPABILITIES(0x0001) / 내부 | 토큰/메커니즘 표시 |
| (키 테이블 조회) | KEYTABLE_INFO(0x0024) | 공개 메타데이터 |
| C_GenerateRandom | (provider 내부) | provider 구현 확인 |
| C_Digest(Init/Update/Final) | SHA3 one-shot / INIT·UPDATE·FINAL(0x0310~0x0348) | SHA3-256/384/512 |
| C_Encrypt/Decrypt(GCM/CTR) | AES_ONESHOT(0x0116) / AES_KEY_ID(0x0118) / AES_CONTEXT(0x0120) | 사용자 키/저장 키 |
| C_Encrypt/DecryptUpdate/Final | AES_GCM/CTR INIT·UPDATE·FINAL(0x0130~0x0135) | 멀티파트 |
| C_Sign/Verify (ML-DSA) | MLDSA_*(0x0050~, key_id 0x005A/B) | 지원 시 |
| C_Derive/Encaps (ML-KEM) | MLKEM_*(0x0053~, key_id 0x005C/D) | 지원 시 |

> 정확한 매핑은 `ci_pem_pkcs11.c`의 각 C_ 구현을 근거로 확정한다.

---

## 5. 작업 분해(WBS) & 마일스톤

- **M1 — 연결 PoC (1)**: `libci_pem_pkcs11.so`를 ncmp_web `--module`로 로드 →
  load/initialize/slots/token/mechanisms/open/close/random/digest 동작 확인(USB 권한 포함).
- **M2 — 백엔드 모드화 (2)**: ncmp_web `--backend pem`, 데몬 UI 게이팅, 기본 모듈 설정,
  `/api/usbcheck`.
- **M3 — 암호 기능 (3)**: AES-GCM(사용자/저장키), SHA3 단발·멀티파트, (가능 시)CTR/PQC
  엔드포인트·UI 연결, ≥64KB 멀티파트.
- **M4 — PEM 전용 UI (4)**: 키 테이블/CAPABILITIES 카드, SHA3 기본값, 페이지 활성 규칙.
- **M5 — 관측성 (5)**: CI 패킷 로그(`/api/pem/lastci`) + 뷰.
- **M6 — 시험·문서 (6)**: 실 타겟 전수 시험 + 결과/매뉴얼 문서.

각 M은 이전 성과 위에 쌓이며 M1→M6 순서. (괄호 숫자는 상대 작업량 가늠)

---

## 6. 테스트 계획 (실 타겟 04b4:5054)

- **연결/수명주기**: USB 권한, load/initialize/slots/token/mechanisms/session/login.
- **암호 정확성**: python `hashlib`(SHA3), `cryptography`(AES-GCM)로 **바이트 교차검증**.
  - SHA3-256/384/512 단발·멀티파트(≥64KB), AES-GCM 128~256/AAD/태그변조 음성.
  - 저장 키 ID 경로(가능 시) 별도 케이스.
- **경계/오류**: 큰 입력(요청≤65504B), 오류 ACK 처리, 세션 격리.
- 자동화: 기존 Web Test App 테스트 하네스(curl+python) 패턴 재사용.

---

## 7. 리스크 / 고려사항

- **USB 권한**: ncmp_web이 usbfs로 `04b4:5054` 직접 오픈 → udev 규칙 필요
  (`tools/setup_usb_permissions.py`). 실패 시 명확한 안내.
- **단일 프로세스 점유**: PEM은 데몬이 없어 **한 번에 한 ncmp_web만** USB 보유.
  동시 접근 필요 시 데몬화는 별도 과제(범위 외).
- **기능 커버리지**: PEM provider의 mech/함수 실제 구현 범위(PQC/CTR/키ID) 확인 후
  UI 활성 결정.
- **키 모델 차이**: 저장 키 ID(1–26)·마스터키 vs PKCS#11 키객체 — 노출 방식 설계 필요.
- **와이어 차이**: CI v4(16B 헤더, 8B 인자, LE)는 NCMP와 호환 안 됨 → 반드시 PEM
  provider 경유(ncmpd 재사용 불가). 엔디안은 헤더·인자 모두 LE, 정수 폭만 4B/8B 상이.
- **라이선스/소스 반입**: `/home/pooky/ji/host` 코드를 트리에 포함할지 경로 로드할지 결정.

---

## 8. 산출물

- ncmp_web 백엔드 모드(PEM) + USB 권한 점검 + (선택)CI 패킷 로그.
- PEM 대응 UI(공용 페이지 재사용 + 키테이블/CAPABILITIES).
- 실 타겟 시험 결과 문서 + 사용자 매뉴얼 보강.
- (중기) PEM provider/ci 소스의 트리 반입 및 빌드 타깃.

# PEM CI Test Console — 단위 기능 ↔ PKCS#11 API ↔ PEM CI 매핑

- 작성일 : 2026-10-07
- 분석 대상 : `/home/pooky/ji/host/tools/ci_console` (Web UI) · `pkcs11/ci_pem_pkcs11.c`
  (PEM PKCS#11 provider) · `ci/ci_commands.c`(CI 레이아웃)
- 관련 문서 : [`pem-command-interface.md`](pem-command-interface.md) ·
  [`pem-usb-transport.md`](pem-usb-transport.md) · [`pem-webtestapp-plan.md`](pem-webtestapp-plan.md)

PEM CI Test Console의 **단위 기능(버튼/입력/설명)** 을 분해하고, 각 기능을 **PKCS#11
API로 수행**하려면 어떤 호출이 필요한지, 그리고 그것이 **최종 PEM CI 명령에 어떻게
매핑**되는지 정리한다.

> 중요한 전제: 콘솔 자체는 내부적으로 **SDK(`sdk.py`)가 CI 프레임을 직접** 만들어
> 보낸다. 본 문서는 "**Web Test App에서 PKCS#11 API를 통해** PEM CI로 보낸다"는 목표
> 관점에서, 각 기능의 **표준 PKCS#11 호출 경로**와 그 **CI 매핑**을 정리한 것이다.
> 현재 PEM PKCS#11 provider(`libci_pem_pkcs11.so`)가 실제로 지원하는 범위는
> **AES-GCM + SHA3** 뿐이며(아래 §5), 나머지는 provider 확장 또는 직접-CI 경로가 필요하다.

---

## 1. Web UI 구성 (페이지)

| 페이지 | 역할 |
|------|------|
| CI 테스트 | 명령 실행(operation 선택 + 동적 입력), 키 테이블 조회, CI 목록 |
| TX / RX 로그 | 실제 송수신 프레임(raw+parsed) 조회 |
| 성능 측정 | 단건 반복·GCM lifecycle·성능 모니터(0x00F0) |
| 메모리 공간 | Shared RAM 사용 추정·주소 영역 |
| PKCS#11 테스트 | provider 로드 후 표준 C_* 스모크(GCM/SHA3 KAT 등) |

### 1.1 "명령 실행" 공통 요소
- **operation ▼**: 수행할 단위 기능(아래 §3 목록).
- **hSession ▼**: 대상 세션(= PKCS#11 세션 핸들). `OpenSession` 버튼으로 생성.
- **동적 입력**(operation에 따라 표시/숨김, `visibility()`):
  `key-id`(+입력키/저장키 버튼), `aes-params`(direction·key·iv), `gcm-params`(aad),
  `gcm-tag`(tag), `sha-bits`(256/384/512), `pqc-profile`, `pqc-pk/sk/signature/ciphertext`,
  `data`(UTF-8/HEX·32 KiB 생성), `perf`(target/sequence/clock), `advanced`(command·arguments).
- **버튼**: `실행(run)`, `OpenSession(quick-open)`, `결과를 입력에 적용(use-output)`.

---

## 2. 공통 선행 기능 — 세션

### 2.1 OpenSession
- UI : `OpenSession` 버튼 / hSession 선택기 채움.
- PKCS#11 : `C_OpenSession(slot, CKF_SERIAL_SESSION[|CKF_RW_SESSION], …, &hSession)`
  (필요 시 `C_Initialize`/`C_GetSlotList` 선행).
- PEM CI : **SESSION(0x0023)** action=1(OPEN), 헤더 SESSION_ID=0 → 응답 `hSession`.

### 2.2 CloseSession
- UI : operation=`close_session` + 실행.
- PKCS#11 : `C_CloseSession(hSession)`.
- PEM CI : **SESSION(0x0023)** action=2(CLOSE), 헤더 SESSION_ID=닫을 hSession.

> 로그인: PEM CI에는 LOGIN 명령이 없다(ci_commands.c 미포함). provider의 `C_Login`은
> 토큰 통신 없는 수용(no-op) 수준이며, 본 콘솔 기능들은 로그인을 요구하지 않는다.

---

## 3. 단위 기능별 매핑

각 항목 = **① UI(입력/설명) · ② 필요한 PKCS#11 API · ③ PEM CI 매핑**.

### 3.1 시스템 · 진단

#### CAPABILITIES
- ① operation=`capabilities`, 입력 없음. 보드 기능(api_version/slots/mask) 조회.
- ② 표준 대응: `C_GetMechanismList`/`C_GetTokenInfo`(근사). 정확한 등가 API는 없음(벤더 정보).
- ③ **CAPABILITIES(0x0001)** → api_version·slots·mask.

#### KEY_TABLE_INFO (키 테이블)
- ① operation=`key_table_info` 또는 `키 메타데이터 조회` 버튼. 표에 ID/알고리즘/프로파일/
  key·iv 길이/주소 표시(값은 비노출).
- ② 표준 대응: `C_FindObjectsInit`/`C_FindObjects`/`C_GetAttributeValue`(공개 속성 열거)로 근사.
- ③ **KEYTABLE_INFO(0x0024)** → 30×32B 공개 메타데이터.

#### ECHO
- ① operation=`echo`, `data`(UTF-8/HEX). 진단용 반향.
- ② 표준 PKCS#11 등가 없음(벤더/진단).
- ③ **ECHO(0x0002)** → `data_len·data·PAD8` 반향.

#### PERF_QUERY (성능 모니터)
- ① operation=`perf_query` / `선택한 세션 조회` 버튼. 입력 `target hSession`·`sequence`·`clock MHz`.
- ② 표준 PKCS#11 등가 없음(벤더 진단).
- ③ **PERF_QUERY(0x00F0)** → PERF v2 304B. (성능 모니터 빌드 전용)

#### Advanced · CI arguments (raw_command)
- ① operation=`raw_command`, `command ▼`·`arguments HEX`·`expected_args_len`. 공통 헤더 뒤
  바이트열을 직접 구성.
- ② PKCS#11 경로 아님(원시 CI 직접 전송).
- ③ **임의 CI_CMD_***(선택한 command) → 지정 args 그대로.

### 3.2 대칭키 — AES (direction·key·iv·aad·tag·data·key_id)

공통 UI: `방향(0=Enc/1=Dec)`, `Key 32B HEX`, `IV(GCM 12/16B·CTR 16B)`, `Key ID`
(0=입력키 / >0=저장키), GCM은 `AAD`·`Tag`(복호화), `Data`(UTF-8/HEX, 32 KiB 생성).

#### AES-GCM oneshot
- ② PKCS#11:
  - 입력키: `C_CreateObject({CKO_SECRET_KEY, CKK_AES, CKA_VALUE=key})` →
    `C_EncryptInit(CKM_AES_GCM, CK_GCM_PARAMS{iv, aad, tagBits})` → `C_Encrypt`/`C_Decrypt`.
  - 저장키: 키 객체 대신 `key_id` 참조(provider 확장 필요; §5).
- ③ PEM CI: 입력키 → **AES_ONESHOT(0x0116)**(mode=1 GCM), 저장키 → **AES_KEY_ID(0x0118)**.
  암호화 응답 `data‖tag`, 복호화 입력 `data‖tag`.

#### AES-GCM INIT / UPDATE / FINAL
- ② PKCS#11: `C_EncryptInit(CKM_AES_GCM,…)` → `C_EncryptUpdate`×N → `C_EncryptFinal`
  (복호화는 `C_Decrypt*`). FINAL에서 태그 생성/검증.
- ③ PEM CI: **AES_GCM_INIT(0x0133) / UPDATE(0x0134) / FINAL(0x0135)** (또는 통합
  **AES_CONTEXT(0x0120)** action 1/2/3). UPDATE/FINAL은 INIT의 `key_id` 재사용.

#### AES-CTR oneshot / INIT / UPDATE / FINAL
- ② PKCS#11: `C_EncryptInit(CKM_AES_CTR, CK_AES_CTR_PARAMS{cb=counter})` →
  `C_Encrypt`(oneshot) 또는 `C_EncryptUpdate/Final`(멀티파트).
  **현 PEM provider는 CKM_AES_CTR 미지원**(EncryptInit이 GCM만 허용) → 확장 필요(§5).
- ③ PEM CI: oneshot → **AES_ONESHOT(0x0116)**(mode=0 CTR) / **AES_KEY_ID(0x0118)**,
  멀티파트 → **AES_CTR_INIT(0x0130)/UPDATE(0x0131)/FINAL(0x0132)**.

### 3.3 해시 — SHA3 (bits 256/384/512·data)

#### SHA3 oneshot
- ② PKCS#11: `C_DigestInit(CKM_SHA3_256|384|512)` → `C_Digest(data)`.
- ③ PEM CI: **SHA3_256/384/512(0x0310/0x0311/0x0312)** → `digest`(32/48/64B).

#### SHA3 INIT / UPDATE / FINAL
- ② PKCS#11: `C_DigestInit` → `C_DigestUpdate`×N → `C_DigestFinal`.
- ③ PEM CI: **SHA3_*_INIT(0x0340/43/46) / UPDATE(0x0341/44/47) / FINAL(0x0342/45/48)**.

### 3.4 PQC — ML-DSA (profile 44/65/87 · pk/sk/message/signature · key_id)

#### ML-DSA KEYGEN
- ② PKCS#11: `C_GenerateKeyPair(CKM_ML_DSA_KEY_PAIR_GEN, pub템플릿, priv템플릿, &hPub,&hPriv)`
  → `C_GetAttributeValue(CKA_VALUE)`로 blob 추출. (**provider 미구현**; §5)
- ③ PEM CI: **MLDSA_KEYGEN(0x0050)** → `public_key`·`secret_key`.

#### ML-DSA SIGN
- ② PKCS#11: `C_SignInit(CKM_ML_DSA, hPriv)` → `C_Sign(message)`
  (또는 `CKA_VALUE=secret_key`로 키 객체 생성 후).
- ③ PEM CI: 키전달 → **MLDSA_SIGN(0x0051)**, 저장키 → **MLDSA_SIGN_KEY_ID(0x005A)**
  (key_id 21/22/23).

#### ML-DSA VERIFY
- ② PKCS#11: `C_VerifyInit(CKM_ML_DSA, hPub)` → `C_Verify(message, signature)`.
- ③ PEM CI: **MLDSA_VERIFY(0x0052)** / **_KEY_ID(0x005B)** → ACK로 결과.

### 3.5 PQC — ML-KEM (profile 512/768/1024 · pk/sk/ciphertext · key_id)

#### ML-KEM KEYGEN
- ② PKCS#11: `C_GenerateKeyPair(CKM_ML_KEM_KEY_PAIR_GEN, …)`. (**provider 미구현**; §5)
- ③ PEM CI: **MLKEM_KEYGEN(0x0053)** → `public_key`·`secret_key`.

#### ML-KEM ENCAPS
- ② PKCS#11 3.2: `C_EncapsulateKey(CKM_ML_KEM, hPub, …, &ciphertext, &hSharedSecret)`
  (3.0 대체: `C_WrapKey`/`C_DeriveKey` 조합).
- ③ PEM CI: **MLKEM_ENCAPS(0x0054)** / **_KEY_ID(0x005C)** → `ciphertext`·`shared_secret(32B)`.

#### ML-KEM DECAPS
- ② PKCS#11 3.2: `C_DecapsulateKey(CKM_ML_KEM, hPriv, ciphertext, …, &hSharedSecret)`
  (3.0 대체: `C_DeriveKey`).
- ③ PEM CI: **MLKEM_DECAPS(0x0055)** / **_KEY_ID(0x005D)** → `shared_secret(32B)`.

### 3.6 PKCS#11 테스트 페이지 (provider 스모크)
- ① `현재 연결에서 표준 API 테스트 실행` 버튼 → GCM·SHA3 KAT, 길이 조회, 작은 버퍼,
  잘못된 태그 검사.
- ② PKCS#11: `C_GetFunctionList` → `C_Initialize`/`OpenSession` →
  `C_DigestInit/Digest`, `C_CreateObject`+`C_EncryptInit/Encrypt`+`C_DecryptInit/Decrypt`.
- ③ PEM CI: SHA3_*·AES_ONESHOT(GCM) 등. **이 페이지가 "Web→PKCS#11→PEM CI" 경로의
  실제 예시**다(현재 provider 지원 범위 내).

---

## 4. 매핑 요약표

| 콘솔 기능 | 필요한 PKCS#11 API(표준) | PEM CI 명령 | 현 provider |
|------|------|------|:---:|
| OpenSession | C_OpenSession | SESSION(0x0023) OPEN | ✅ |
| CloseSession | C_CloseSession | SESSION(0x0023) CLOSE | ✅ |
| CAPABILITIES | (C_GetTokenInfo/MechList 근사) | CAPABILITIES(0x0001) | △ |
| KEY_TABLE_INFO | C_FindObjects* (근사) | KEYTABLE_INFO(0x0024) | △ |
| ECHO | (없음·벤더) | ECHO(0x0002) | ✗ |
| PERF_QUERY | (없음·벤더) | PERF_QUERY(0x00F0) | ✗ |
| AES-GCM oneshot | C_CreateObject + C_EncryptInit(GCM)/C_Encrypt | AES_ONESHOT/KEY_ID | ✅ |
| AES-GCM INIT/UPDATE/FINAL | C_EncryptInit/Update/Final(GCM) | AES_GCM_INIT/UPDATE/FINAL | ✅ |
| AES-CTR (전부) | C_EncryptInit(CKM_AES_CTR)/… | AES_ONESHOT/CTR_INIT/UPDATE/FINAL | ✗(확장) |
| SHA3 oneshot | C_DigestInit/C_Digest | SHA3_256/384/512 | ✅ |
| SHA3 INIT/UPDATE/FINAL | C_DigestInit/Update/Final | SHA3_*_INIT/UPDATE/FINAL | ✅ |
| ML-DSA KEYGEN | C_GenerateKeyPair | MLDSA_KEYGEN(0x0050) | ✗(확장) |
| ML-DSA SIGN/VERIFY | C_Sign(Init)/C_Verify(Init) | MLDSA_SIGN/VERIFY(+_KEY_ID) | ✗(확장) |
| ML-KEM KEYGEN | C_GenerateKeyPair | MLKEM_KEYGEN(0x0053) | ✗(확장) |
| ML-KEM ENCAPS/DECAPS | C_Encapsulate/DecapsulateKey(3.2) | MLKEM_ENCAPS/DECAPS(+_KEY_ID) | ✗(확장) |
| raw_command | (없음·직접 CI) | 임의 CI_CMD_* | ✗ |

범례: ✅ 현 provider가 표준 PKCS#11로 지원 / △ 근사·부분 / ✗ 미지원(직접-CI 또는 확장 필요).

---

## 5. 구현 권고 (Web Test App 관점)

- **바로 가능(Web→PKCS#11→CI)**: 세션 open/close, **AES-GCM(단발·멀티파트)**,
  **SHA3(단발·멀티파트)**. 현 `libci_pem_pkcs11.so`로 그대로 매핑된다(계획서 §M1~M3).
- **provider 확장 필요**:
  - **AES-CTR**: `C_EncryptInit`에 `CKM_AES_CTR` 허용 + CI `AES_*`(CTR) 연결.
  - **ML-DSA/ML-KEM**: `C_GenerateKeyPair`/`C_Sign`/`C_Verify`/`C_Encapsulate`/
    `C_Decapsulate`(PKCS#11 3.2) 구현 → CI `MLDSA_*`/`MLKEM_*`.
  - **저장 키 ID 모드**: 키 객체(`C_CreateObject`)에 `key_id`를 바인딩하는 벤더 속성
    또는 별도 UI 옵션 → CI `*_KEY_ID`.
- **PKCS#11 경로 없음(벤더/진단 전용)**: ECHO, CAPABILITIES, KEY_TABLE_INFO,
  PERF_QUERY, raw_command — Web Test App에서 필요하면 **직접-CI 엔드포인트**(기존 NCMP
  `/api/ci`에 상응)로 노출한다.
- 관측성(TX/RX 로그)은 PKCS#11 경로와 별개로 CI 패킷 로그(`CI_USB_SetTrace`)로 제공.

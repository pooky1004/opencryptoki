# PEM 모듈 — Web Test App 기능 시험 결과

작성일: 2026-10-07 · 대상: 실 PEM 보드(`04b4:5054`, usbfs) + `ncmpd --transport pem`
+ 표준 facade(`libpkcs11_ncmp_p11.so`) + `ncmp_web`

PEM 모듈을 ncmpd의 **번역 백엔드**(`ncmp_pem_ops`, `daemon/pem_transport.c`)로
붙인 뒤, Web Test App의 **PEM CI 콘솔**에서 PKCS#11 API 조합으로 각 단위 기능을
실 보드까지 구동해 검증한 결과를 정리한다. 전체 구조는
[`pem-webui-pkcs11-ci-mapping.md`](pem-webui-pkcs11-ci-mapping.md),
CI v4 명령은 [`pem-command-interface.md`](pem-command-interface.md),
USB 전송은 [`pem-usb-transport.md`](pem-usb-transport.md) 참고.

## 구동 방식

```bash
# 1) PEM 백엔드로 ncmpd 기동 (SHM/소켓은 NCMP와 공유, 슬롯 0 = PEM)
export NCMP_SOCK_PATH=/tmp/ncmpd.sock
ncmp/gui/build-standalone/ncmpd --transport pem &      # 온라인 슬롯 mask=0x1
# 2) 웹 서버 (facade 로드 → C_Initialize → PEM 슬롯 세션)
cd ncmp/gui/testapp && ./build/ncmp_web &              # http://host:8080
```

- `/api/slots` 가 `slotTypes{slot:1}` 로 PEM 슬롯을 표시 → UI 가 오른쪽 창을
  **PEM CI 콘솔**로 전환(`app.js` `selectSlot`).
- facade/comm_thread/SHM/세션 코드는 **무수정**. ncmpd 백엔드 send() 가 NCMP 와이어
  프레임을 디코드해 PEM CI v4 로 번역하고, recv() 가 NCMP 응답으로 재인코딩한다.

## 이번 증분에서 추가한 기능

| 기능 | 경로 | PEM CI |
|------|------|--------|
| AES-GCM 멀티파트(스트리밍, ≥64KB) | facade `C_Encrypt/DecryptInit+Update×N+Final` → NCMP `AES_GCM_{INIT,UPDATE,FINAL}`(0x14/15/16) → **ncmpd PEM 백엔드 번역** | `AES_GCM_INIT/UPDATE/FINAL`(0x0133/0x0134/0x0135) |
| AES 저장 키 ID(단발) | PEM 콘솔 → 범용 CI 터널(`PEM_RAW_CMD` 0x01F0) | `AES_KEY_ID`(0x0118) |

### 백엔드 번역 규칙 (`daemon/pem_transport.c`)

- **GCM_INIT(0x14→0x0133)** : `[flags|key|iv|aad|taglen]` → `key_id=0`(입력 키/IV) ·
  `direction`(flags 의 ENCRYPT 비트) · `key`(32B) · `iv_len·iv·PAD8` ·
  `aad_len·aad·PAD8`. 응답 인자는 없으므로 facade 규약에 맞춰 **ctx_id=0(4B)** 합성.
- **GCM_UPDATE(0x15→0x0134)** : `[ctx|data]` → `key_id=0` · `data_len·data·PAD8`;
  응답 `data_len·data·PAD8` 에서 출력 추출.
- **GCM_FINAL(0x16→0x0135)** : 암호화는 param1 없음 → `key_id=0` 전송, 응답
  `tag`(16B). 복호화는 param1(16B tag) 존재 → `key_id=0 · tag(16B)` 전송, 응답은
  ACK(태그 검증 결과).
- facade 는 토큰 per-call 한도(3968B) 로 UPDATE 를 자동 분할하므로 번역기는 청크당
  1프레임을 그대로 중계한다.
- 저장 키 ID 는 facade AES 경로에 key_id 인자가 없어 **PEM 콘솔의 CI 터널**로만 노출:
  `mode·direction·key_id · [GCM aad_len·aad·PAD8] · data_len·data·PAD8 · [GCM 복호화 tag16]`.
  KEY·IV 는 전송하지 않고 토큰의 저장 키(테이블)를 사용한다.

### 수정 중 발견·해결한 버그

- **GCM_FINAL 암호화가 `CKR_ARGUMENTS_BAD(0x07)`** : 번역기가 복호/암호를
  `ncmp_msg_param(1)` 성공 여부로 구분했는데, 이 함수는 **빈 파라미터(len 0)에도
  OK** 를 반환해 암호화(1-파라미터)가 복호화로 오판되고 `tag len != 16` 검사에서
  실패했다. → 판정을 `param1 이 존재하고 len>0` 으로 교정.

## 시험 결과 (실 PEM 보드)

### A) AES-GCM 멀티파트 (스트리밍)

입력은 `/api/genfile format=hex`(64B/줄), 처리는 `/api/encrypt-file`
(`app_aes_gcm_multipart` → `C_EncryptInit`+청크 `C_EncryptUpdate`+`C_EncryptFinal`).
암호문 출력 파일은 `ct||tag`, 복호화는 이를 그대로 입력.

| 입력 | update 수 | 왕복(암→복) | python AES-256-GCM 바이트 일치 |
|------|:---:|:---:|:---:|
| 128KB (chunk 16384) | enc 8 / dec 9 | ✅ PASS | ✅ PASS (131088B = 131072 ct + 16 tag) |
| 200000B (chunk 8192) | enc 25 / dec 25 | ✅ PASS | ✅ PASS |

- **변조 거부** : 암호문 1바이트 변조 후 복호화 → `C_DecryptFinal` 태그 검증 실패로
  **거부**(rc 13). ✅ PASS
- 교차검증은 python `cryptography` 의 `AESGCM().encrypt(iv, pt, aad)` 결과와
  보드 출력(`ct||tag`)이 **바이트 단위 완전 일치**.

### B) AES 저장 키 ID (단발, 왕복)

저장 키 테이블(CTR=홀수 1–19 / GCM=짝수 2–20)의 사전 프로비저닝된 키로 암/복호.
키 바이트는 호스트가 모르므로 **암호화→복호화 왕복**으로 검증.

| 메커니즘 | key_id | 결과 |
|---------|:---:|:---:|
| AES-256 CTR | 1 | ✅ PASS (ct 32B → 복호 왕복) |
| AES-256 GCM | 2 | ✅ PASS (ct 32B + tag 16B → 복호 왕복) |

### C) 회귀 (기존 단발 경로 불변)

| 메커니즘 | 결과 |
|---------|:---:|
| AES-256 GCM 단발 (python 바이트 일치) | ✅ PASS |
| AES-256 CTR 단발 (python 바이트 일치) | ✅ PASS |

## PEM CI 콘솔 UI 추가

`web/index.html` · `web/app.js`:
- `#pemOp` 에 **AES-256 GCM 멀티파트(파일) · 암호화/복호화** 항목 추가.
- 저장 키 ID 입력(`#pemKeyId`, 0=입력 키) — 값>0 이면 GCM/CTR 단발을
  `AES_KEY_ID` 터널 경로로 전환.
- 멀티파트 파일 그룹(`data-pf="mpfile"`) : 입력 파일 선택 · 크기 지정 Hex 파일 생성
  (`/api/genfile`) · update 당 청크 · 출력 파일명. 결과는 입력/출력 바이트 수,
  update 횟수, 출력 SHA-256, 출력 파일 열기 버튼 표시.
- PEM 슬롯 선택 시 파일 목록 자동 갱신(`pemMpRefresh`).

## 현재 PEM 콘솔 지원 범위 (누적)

SESSION(세션 관리) · CAPABILITIES · ECHO · KEY_TABLE_INFO · PERF_QUERY ·
SHA3-256/384/512 단발 · AES-256 GCM/CTR 단발 · **AES 저장 키 ID** ·
**AES-GCM 멀티파트(파일, ≥64KB)** · ML-DSA/ML-KEM(KEYGEN/SIGN·VERIFY/ENCAPS·DECAPS).

# Web Test App — AES-GCM / AES-CTR 실 타겟 시험 결과

작성일: 2026-10-06 · 대상: 실 FX3(`04b4:00f1`) + `ncmpd --transport real`

Web Test App의 **AES-GCM / AES-CTR** 페이지(PKCS#11 경로)를 실 토큰으로 검증한
결과를 정리한다. 명령 경로·UI 설계는 [`testapp-web-manual.md`](testapp-web-manual.md),
토큰 식별/로그인은 [`session-id-mapping.md`](session-id-mapping.md) 참고.

## 시험 대상 경로 (PKCS#11, mode-2 facade)

버튼 → 백엔드 `/api/encrypt` → 네이티브 헬퍼가 **PKCS#11 C_ 함수**로 수행한다
(raw CI 직접 전송이 아님):

```
C_CreateObject(CKO_SECRET_KEY, CKK_AES, CKA_VALUE=key)   # 사용자 키를 로컬 키객체로
  → C_EncryptInit / C_DecryptInit (CKM_AES_GCM 또는 CKM_AES_CTR, 기구 파라미터)
  → C_Encrypt / C_Decrypt                                 # 키는 어댑터가 와이어에 인라인
  → C_DestroyObject
```

- AES-GCM 암호화 출력 = `ciphertext || tag`, 복호화 입력 = `ciphertext || tag`.
- AES-CTR은 16바이트 counter 블록을 사용하며 암·복호화가 동일 연산.
- 세션: `C_OpenSession`(실 OPEN_SESSION) 후 `C_Login`(User PIN `12345678`).

## 검증 방법

python `cryptography`(AESGCM, AES-CTR = NIST 표준 구현)로 **권위값을 계산**해
토큰 출력과 **바이트 단위 전수 대조**했다. 추가로 AES-CTR은 OpenSSL CLI로도
교차검증했고, AES-GCM은 McGrew/Viega(NIST) Test Case 3을 python 재계산으로 확인했다.

## 결과 요약 — 108/108 PASS

| 범주 | 조건 | 건수 | 결과 |
|------|------|----:|:----:|
| AES-GCM KAT 대조 | 키 128/192/256 × AAD(0·20B) × 데이터 0/1/16/60/500/3968B, tag 16B | 72 | ✅ |
| AES-GCM tag 12B 왕복 | 키 128/256, 데이터 64B | 4 | ✅ |
| AES-GCM 인증 음성시험 | 태그 1비트 변조 / 잘못된 AAD → 복호화 거부 | 2 | ✅ |
| AES-CTR KAT 대조 | 키 128/192/256 × 데이터 1/16/60/500/3968B | 30 | ✅ |
| **합계** | | **108** | **✅ 0 실패** |

### 세부

- **AES-GCM 정확성**: 암호화 결과 `ct‖tag`가 python cryptography와 **정확히 일치**
  (키 128/192/256, AAD 유무, 데이터 0~3968B 전 조합). 복호화 평문도 원문과 일치.
- **태그 길이**: 16B는 KAT 대조, 12B는 왕복(출력 길이=평문+12, 복호화 원문 복원) 확인.
- **인증(무결성)**: 태그 1비트 변조 또는 AAD 불일치 시 복호화가 **올바르게 실패**
  (평문 미반환). 토큰이 태그를 실제로 검증함을 확인.
- **AES-CTR 정확성**: 암호화 결과가 python/OpenSSL CTR과 **정확히 일치**
  (키 128/192/256, 데이터 1~3968B). 복호화 원문 복원.
- **경계값**: 데이터 0바이트(GCM), 1바이트, 블록경계(16B), 청크 상한(3968B)에서 정상.

## 알려진 사항

- **PQC(ML-DSA/ML-KEM)**: 이 웹앱이 로드하는 mode-2 facade는 PQC/Sign/Verify를
  미구현(스텁)하므로 PQC 페이지는 비활성 안내 상태로 둔다. PQC 전체 기능은
  opencryptoki full 빌드의 mode-1 STDLL(`ncmp_specific.c`)에서 제공된다.
- **데이터 상한**: 토큰 청크 한도(3968B)에 맞춰 입력을 제한한다.

## 재현 절차

```bash
# 1) 빌드
bash ncmp/gui/build_standalone_p11.sh
bash ncmp/gui/testapp/build.sh --server

# 2) 실 타겟으로 Web Test App 기동 (FX3 연결, 04b4:00f1)
./start-test-web.sh          # 브라우저 127.0.0.1:8080

# 3) UI에서: 데몬 시작 → 로드 → C_Initialize → 슬롯 선택 → 새 세션
#    → 로그인(User, 12345678) → AES-GCM / AES / SHA3 페이지에서 암·복호화 실행
```

프로그램적 전수 대조는 `/api/encrypt`에 `{session, algo:"gcm"|"ctr", encrypt,
key, iv, aad, tagBytes, data}`(hex)를 POST하고 응답 `{hex, length}`를 python
cryptography 권위값과 비교하면 된다.

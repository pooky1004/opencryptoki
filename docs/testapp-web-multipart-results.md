# Web Test App — 대용량 멀티파트(Init/Update/Final) 시험 결과

작성일: 2026-10-07 · 대상: 실 FX3(`04b4:00f1`) + `ncmpd --transport real`

여러 단계(Init → Update×N → Final)를 거치는 **대용량(≥64KB)** 연산을 PKCS#11
경로로 실 토큰에서 검증한 결과를 정리한다. 테스트 데이터 파일 메커니즘과 UI는
[`testapp-web-manual.md`](testapp-web-manual.md) §5.3 참고.

## 시험 데이터 파일 메커니즘

멀티파트 입력은 세 가지로 제공한다:
- **직접 입력**(단발 카드), **크기 지정 → Hex 시험파일 생성**(`/api/genfile format=hex`,
  64바이트/줄), **기존 파일 선택**(`/api/files`).
- `.hex`/`.txt` 파일은 서버가 Hex 디코드(주석 `#`·공백 무시)해 **데이터 바이트**로
  복원한 뒤 처리한다. 생성/결과 파일은 `/files/<이름>` 으로 열람한다.
- 토큰 per-call 데이터 한도(**3968B**)보다 큰 update 청크는 서버/facade가 내부적으로
  3968B 이하로 분할해 전송한다.

## 멀티파트 digest (SHA3, C_DigestInit/Update×N/Final)

- 경로: `/api/digest-file` → `app_digest_multipart` → C_DigestInit + 청크 C_DigestUpdate
  + C_DigestFinal. update 청크는 ≤3968B로 클램프. update 실패 시 C_DigestFinal로
  컨텍스트를 정리(세션 wedge 방지).
- 실 토큰은 **SHA3만** 지원(SHA‑2 미지원).

결과 — **9/9 PASS** (python `hashlib` 교차검증, 바이트 일치):

| 데이터 | SHA3-256 | SHA3-384 | SHA3-512 |
|-------|:---:|:---:|:---:|
| 64KB (17 updates) | ✅ | ✅ | ✅ |
| 128KB (34 updates) | ✅ | ✅ | ✅ |
| 512KB (133 updates) | ✅ | ✅ | ✅ |

- 오버사이즈 청크(예: 99999) 요청은 서버에서 3968으로 클램프되어 정상 동작.
- 단발/멀티파트/단발 순서 교차 실행 정상(아래 facade 수정 참조).

## 멀티파트 AES-GCM (스트리밍, C_EncryptUpdate/Final · C_DecryptUpdate/Final)

mode-2 facade에 AES-GCM 스트리밍 멀티파트를 신규 구현했다:
- 첫 Update에서 토큰 GCM 컨텍스트를 **지연 생성**(단발 C_Encrypt 경로는 불변).
- 토큰 per-call 한도(3968B)로 **내부 서브청킹**.
- **암호화**: Update→암호문, Final→태그. 출력 = 암호문‖태그.
- **복호화**: 마지막 `tag_len` 바이트를 **hold-back** 해 암호문만 Update로 복호화,
  Final에서 held 태그로 검증. 출력 = 평문.
- 경로: `/api/encrypt-file` → `app_aes_gcm_multipart`. 결과는 Hex 파일(64B/줄)로 저장.

결과 — **75/75 PASS** (python `cryptography` AESGCM 교차검증):

| 항목 | 범위 | 결과 |
|------|------|:---:|
| 암호문‖태그 == python one-shot | 키 128/192/256 × AAD(0·13B) × 70KB·200KB × 청크 3968/20000/65536 | ✅ |
| 복호화 == 원문 | 동일 조합 | ✅ |
| 태그 1비트 변조 → 복호화 거부 | AES-256 | ✅ |
| 태그 길이 12B 왕복 | AES-128 | ✅ |

- 예: 128KB(AES‑192+AAD) 암호화 7 updates, 복호화 11 updates(청크 12345) — 왕복·정확성 모두 일치.
- one-shot AES-GCM/AES-CTR·digest 회귀 없음.

## 관련 facade 수정

- **단발 `C_Digest` 수정**: 기존엔 `C_DigestInit`(컨텍스트 할당·active) 후 별도
  one-shot `DIGEST(0x02)` 를 호출해 토큰의 활성 digest 연산과 충돌(`CKR_OPERATION_ACTIVE
  0x90`)했다. 이제 Init된 컨텍스트에 **UPDATE+FINAL**(3968B 청킹)로 처리한다.
- **`C_EncryptUpdate/Final`·`C_DecryptUpdate/Final`**: 스텁 → AES-GCM 스트리밍 구현.

## 재현 절차

```bash
bash ncmp/gui/build_standalone_p11.sh
bash ncmp/gui/testapp/build.sh --server
./start-test-web.sh    # 127.0.0.1:8080

# UI: 데몬 시작 → 로드 → C_Initialize → 슬롯 선택 → 새 세션 → 로그인(User,12345678)
#  - AES/SHA3 → 멀티파트 digest: 데이터 크기 입력 → Hex 시험파일 생성 → 실행
#  - AES-GCM → 멀티파트 AES-GCM: 키/IV/AAD/태그/청크 + 입력 파일 → 실행 → 출력 파일 열기
```

프로그램 검증은 `/api/digest-file`·`/api/encrypt-file` 응답을 python
`hashlib`/`cryptography` 권위값과 바이트 비교하면 된다.

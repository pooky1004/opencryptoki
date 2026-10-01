# App → 실 STDLL 경로 설계 (GUI App이 PKCS#11 스택을 실제로 구동)

테스트 App GUI가 **wire 프레임을 소켓으로 직접** 보내는 현재 방식 대신,
`libpkcs11_ncmp.so`(STDLL) → `token_specific`(`ncmp_specific.c`) → `ncmpd` →
USB(실 토큰)/소켓(mock) 의 **실제 생산 경로**를 구동하도록 바꾸는 설계. 그리고 이 경로
에서 **구조적으로 구현 불가능한 명령**을 정리한다(사용자 요청 §마지막).

- 관련: [`pure_app_api.md`](pure_app_api.md)(STDLL 단독 로드 불가 근거),
  [`cryptoki_app_api.md`](cryptoki_app_api.md), [`stdll-call-flow.md`](stdll-call-flow.md),
  [`ncmpd-vs-pkcsslotd.md`](ncmpd-vs-pkcsslotd.md)

## 1. 목표 경로

```
 GUI App
   │  (PKCS#11 C_* 호출)
   ▼
 libopencryptoki (api 계층)                     ← C_* → ST_* 디스패치
   │  dlopen
   ▼
 libpkcs11_ncmp.so (STDLL: usr/lib/common/new_host.c)
   │  SC_*  →  공통 mgr(mech_aes 등)  →  token_specific.t_* 훅
   ▼
 ncmp_specific.c (token_specific 구현: proxy)
   │  ncmp_client_command_mp(NCMP_CMD_AES_GCM, [flags,key,iv,aad,taglen,data])
   ▼
 ncmpd (UNIX socket + SHM robust 큐)
   ├── USB ──▶ FX3 ──▶ real target(Token, HSM)
   └── 소켓 ──▶ mock
```

> **중요(구조적 사실)**: App은 `libpkcs11_ncmp.so`를 **직접 dlopen 할 수 없다**. 이 `.so`는
> `C_GetFunctionList`/표준 `C_*`를 export 하지 않는 **STDLL(토큰 SPI)** 이기 때문이다
> ([`pure_app_api.md`](pure_app_api.md)). 따라서 App은 **libopencryptoki**(표준 `C_*`)를
> 로드하고, libopencryptoki가 설정에 따라 `libpkcs11_ncmp.so`를 dlopen 한다. 위 그림의
> "App → libpkcs11_ncmp.so 링크"는 실제로는 "App → libopencryptoki → STDLL"이다.

## 2. 실제 구동에 필요한 것 (런타임)

1. **opencryptoki 빌드**: `./configure --enable-ncmptok && make` → `libpkcs11_ncmp.so`
   (+ libopencryptoki, pkcsslotd).
2. **pkcsslotd 기동** + `opencryptoki.conf`에 ncmp 슬롯 정의(슬롯↔STDLL).
3. **ncmpd 기동**: 전송 백엔드 선택
   - 실 토큰: `usb_transport.c`(libusb) — VID/PID/EP 확정 필요.
   - mock: 아래 §4의 선택지(인프로세스 mock 또는 소켓 mock_server).
4. **App의 PKCS#11 바인딩**: Python이면 `PyKCS11`/`python-pkcs11` 또는 ctypes로
   `libopencryptoki.so` 로드 → `C_Initialize`/`C_OpenSession`/`C_Encrypt`… 호출.

> **이 개발 환경 제약**: cmake/libusb/full opencryptoki 런타임이 없어 이 경로는
> **빌드·실행 검증 불가**. 설계·배선 수준까지만 가능. (현재 소켓 프레임 App은 이 환경에서
> 완전히 동작·검증됨 — §5에서 둘을 공존시키는 안을 권장.)

## 3. App GUI 변경 설계

- **target=real (PKCS#11 모드)**: DataLink(프레임) 대신 `Pkcs11Link` 어댑터 신설 —
  libopencryptoki를 통해 `C_*`로 연산 수행. 슬롯 선택 = PKCS#11 `slotID`.
  지원 연산만 노출(암복호/해시/서명/키생성 등 §6의 "가능" 집합).
- **target=mock**: ncmpd를 mock 전송으로 띄우거나(§4), 또는 **현행 프레임 링크 유지**
  (아래 §5 권장안).
- 공통: 세션 통계·시나리오·파일비교는 `C_*` 호출 지연으로 재측정.

## 4. mock을 "소켓으로" 붙이는 방법

현재 ncmpd는 빌드시 **인프로세스 mock_transport** 또는 **usb_transport** 중 하나만 링크한다
(`ENABLE_MOCK_TOKEN`). 그림의 "ncmpd ──소켓──▶ mock"을 실현하려면:

- **옵션 A (신규 소켓 전송)**: `ncmp_transport_*`를 **TCP 소켓**으로 구현한 백엔드
  (`socket_transport.c`)를 추가해, ncmpd가 우리 `mock_server`(이미 wire 프레임 서버)에
  접속. → GUI 도구의 mock_server를 그대로 재사용, 실 STDLL 경로로 end-to-end 테스트.
- **옵션 B (인프로세스)**: `ENABLE_MOCK_TOKEN`으로 ncmpd에 mock을 링크(소켓 아님). 그림의
  "소켓" 요건은 못 맞추지만 가장 단순.
- 권장: **옵션 A** — 기존 mock_server/`frame_server` 자산을 실 STDLL 경로에서 재사용.

## 5. 권장: 두 모드 공존 (현행 유지 + 신규)

현행 **프레임 링크 App**(mock_server/hsm_bridge 직접)과 **PKCS#11 모드 App**을 **둘 다**
둔다.

| 모드 | 경로 | 커버리지 | 이 환경 |
|------|------|----------|---------|
| 프레임 링크(현행) | App → 소켓 → mock_server/bridge | **전체 CI**(벤더·세션·fail-bit 포함) | 동작·검증 O |
| PKCS#11 모드(신규) | App → libopencryptoki → STDLL → ncmpd → USB/소켓 | **C_*로 표현 가능한 연산만** | 빌드 필요, 검증 X |

- 프레임 링크는 **데이터패스/벤더/세션 CI**를 자유롭게 시험(지금처럼).
- PKCS#11 모드는 **표준 스택 정합성**(공통 mgr·mech_aes·token_specific)을 시험.

## 6. 구조적으로 구현 불가능한(또는 C_*로 도달 불가한) 명령

표준 `C_* → SC_* → token_specific` 경로에서는 아래가 **불가/제약**이다. (프레임 링크
모드에서는 전부 가능 — 그래서 §5 공존을 권장.)

| CI / 기능 | PKCS#11 경로에서의 상태 | 이유 |
|-----------|------------------------|------|
| `OPEN_SESSION`/`CLOSE_SESSION`(0x003A/B) | **불가** | opencryptoki `token_specific`에 세션 열림/닫힘 훅이 **없음**. 세션 관리는 공통 계층(new_host) 로컬 처리 → 토큰으로 포워딩되지 않음. SPI 확장(커스텀 훅/ new_host 패치) 필요. |
| `VD_MEM_READ/WRITE/FILL/CRC`, `VD_PING`, `VD_SELFTEST`, `VD_FW_INFO` | **불가** | 대응하는 표준 `C_*`가 없음(벤더 datapath/진단). 앱에서 호출할 PKCS#11 함수 자체가 없음. |
| `VD_TOKEN_INFO`(0x0108) | 간접만 | 앱이 직접 못 부름. 내부적으로 `t_get_token_info`/부팅 스캔이 사용 → `C_GetTokenInfo`로 일부 필드만 노출. |
| `GET_UTC_TIME`/`SET_UTC_TIME` | get만 간접 | set용 표준 `C_`가 없음(관리 전용). get은 `C_GetTokenInfo.utcTime`로 일부. |
| `NOP`/echo | **불가** | 대응 `C_` 없음(전송 keepalive/loopback 용도). |
| `C_SeedRandom` | **불가** | `t_seed_random` 훅 미배선 → 토큰 시드 미지원(`CKR_RANDOM_SEED_NOT_SUPPORTED`). `C_GenerateRandom`(RNG)은 가능. |
| 멀티파트 서명/검증(ML-DSA) | **불가** | ML-DSA는 단발 전용(멀티파트 훅 없음). digest/AES-GCM 멀티파트는 가능. |
| `C_WrapKey`/`C_UnwrapKey` | **불가** | wrap/unwrap 훅 미배선 → `CKR_FUNCTION_NOT_SUPPORTED`/`CKR_MECHANISM_INVALID`. |
| `C_GetOperationState`/`SetOperationState` | **불가** | 타입드 컨텍스트가 저장 불가 → `CKR_STATE_UNSAVEABLE`. |
| RSA/EC/DH/ECDH/HMAC/AES-블록 | **불가** | 비광고 mechanism — opcode·훅·어댑터·mock까지 제거됨. |
| fail-bit 등 테스트 훅, 원시 opcode 전송 | **불가** | `C_*` 표면에 그런 제어가 없음(프레임 링크 전용 기능). |

> 요약: **표준 암복호/해시/서명·검증/키생성/키합의/난수생성** 등 *광고 mechanism의 연산*은
> PKCS#11 경로로 가능하고, **벤더 datapath·세션 CI·진단·관리·테스트 훅**은 표준 `C_*`에
> 대응이 없어 구조적으로 불가하다. 이들은 프레임 링크 모드(또는 전용 관리 인터페이스)로만
> 시험할 수 있다.

## 7. 권장 단계

1. (선택) ncmpd에 **소켓 전송 백엔드**(옵션 A) 추가 → mock_server 재사용.
2. App GUI에 **PKCS#11 모드**(libopencryptoki 로드) 추가, 현행 프레임 링크와 **공존**.
3. §6의 불가 명령은 UI에서 **프레임 링크 모드에서만** 노출(혹은 비활성/주석).
4. opencryptoki 빌드 환경(cmake/libusb/`--enable-ncmptok`)에서 end-to-end 검증.

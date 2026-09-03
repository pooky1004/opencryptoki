# Token NCMP — 진행 요약 (Executive Summary)

- **작성일**: 2026-09-01
- **저장소**: `/home/pooky/workspace/opencryptoki` (fork `pooky1004/opencryptoki`, `master`)
- **상세 로그**: [`STATUS.md`](STATUS.md) · **아키텍처**: [`architecture.md`](architecture.md) · **색인**: [`INDEX.md`](INDEX.md)

> USB(Cypress EZ-USB FX3, CYUSB3KIT-003) 토큰을 다중 프로세스·스레드가 공유하도록
> 다중화하는 `ncmpd` 데몬 + PKCS#11 STDLL `libpkcs11_ncmp.so`를 opencryptoki
> 포크에 추가하는 프로젝트. **`ncmpd`는 `pkcsslotd`의 대체·훅이 아니라 독립 파이프/
> 프록시 멀티플렉서**.

---

## 1. 한눈에 보는 현황

| 지표 | 값 |
|------|-----|
| 진행 단계 | STEP ①~⑨ + 토큰관리 + PQC/SHA3/XOF + **비광고 mechanism 정리(advertised-only)** 완성 |
| standalone 테스트 | **43/43 통과** (인프라/전송 14 + 클라이언트 6 + 크립토 5 + 토큰관리 14 + PQC/SHA3/XOF 4), ThreadSanitizer 0 races |
| opencryptoki STDLL | `libpkcs11_ncmp.so.0.0.0` (strict `-pedantic -Werror -std=c99`); `secure_key_token=TRUE` |
| `token_specific` 훅 | **29종** 배선 (라이프사이클/데이터스토어 5 + login/PIN 5 + RNG 1 + SHA 4 + AES-GCM/CTR/keygen 4 + XOF 1 + PQC 6 + 리포팅 3) |
| 와이어 opcode | 23종 + 벤더 8종 (mem·crc/ping/selftest/fw/token-info; loopback은 NOP로 통합) |
| **advertised mechanism** | AES-GCM/CTR · SHA-256/512 · SHA3-224/256/384/512 · SHAKE-128/256 KDF · ML-KEM(+keygen) · ML-DSA(+keygen) |
| 소스 규모 | `ncmp/` 서브트리 + opencryptoki 통합(`usr/lib/ncmp_stdll/`) |
| **미완(하드웨어 필요)** | 실 FX3 브링업 (VID/PID/EP 확정, `pkcsconf` 런타임 검증, 실 암호 정합성) |

---

## 2. 지금까지 한 일 (Done)

### 2.1 인프라 & 데몬 (STEP ①~④)
- **와이어 프로토콜**: 4바이트 정렬, frame_len + `NCMP_Header`(20B) + `param_len[8]` +
  payload. `_Static_assert`로 헤더 20B 고정. **단발 수신**(최대 버퍼로 프레임 1개 한 번에 읽고 파싱).
- **공유 메모리(SHM)**: `shm_open`/`mmap`, magic/version 검증. **원시 포인터 금지** —
  전부 오프셋/인덱스(`ncmp_shm_ptr`). 슬롯당 per-entry 요청/응답 버퍼 풀.
- **동시성**: MPSC CAS 큐(`FREE→CLAIMED→POSTED→SENT→DONE→FREE`, 타임아웃 `ABANDONED`),
  robust 프로세스공유 뮤텍스(`EOWNERDEAD` 복구), 세션 상한 `sess_lock`.
- **comm_thread 파이프라인**: dispatch(`in_flight<max_inflight`까지 연속 송신) +
  drain(`sequence_id` 매칭). **in-flight 통계 3종**(`in_flight_cnt`,
  `stats_max_in_flight`, `stats_total_sent_cmds`) 실측. stop 플래그 `__atomic_*` 원자화.
- **IPC**: UNIX 소켓 HELLO/ATTACH 핸드셰이크(제어) + SHM(대량 데이터). conn_thread 서버.
- **STDLL 클라이언트**: connect+attach, enqueue/wait 재사용, `NCMP_ERR_*`→`CKR_*` 매핑.
- **libusb 실전송**: `__has_include(<libusb.h>)` 가드(실구현/스텁 자동), 디바이스 열거·
  claim·bulk R/W·단발 프레임 수신. **VID/PID/EP는 상수 + 펌웨어 확정 시 조정 TODO**.
- **daemon 라이프사이클**: 시그널→SHM→probe→슬롯별 comm_thread + conn_thread→정상 종료.
  mock/real `ncmpd` 모두 기동·SIGTERM 종료 실측.

### 2.2 opencryptoki 통합 (STEP ⑤)
- `usr/lib/ncmp_stdll/` (tok_struct.h·ncmp_specific.c·ncmp_stdll.mk).
- autotools: `configure.ac --enable-ncmptok`(**기본 off**), `usr/lib/lib.mk`,
  `Makefile.am` install/uninstall 훅, `opencryptoki.conf` 예시 슬롯(주석).
- `autoreconf`→`./configure --enable-ncmptok`→`make` → `.so` 빌드·심볼 검증 완료.

### 2.3 PKCS#11 연산 포워딩 (STEP ⑥~⑨ + 확장)
opcode 체계(`[15:0]` opcode / `[31:16]` flags) + 전송 API `ncmp_client_command`(단일
param) / `ncmp_client_command_mp`(다중 param). **아키텍처 패턴 8종 확립**: 무상태-단일버퍼,
무상태-다중버퍼, 상태형-컨텍스트 핸들, 비대칭-다중키, AEAD-태그, sign/verify 왕복,
키페어-템플릿 조작, 키합의-원시배열.

> **주의(정리됨).** 초기에는 RSA/EC/DH/HMAC/AES-CBC·ECB·OFB·CFB 등 폭넓은 연산을
> 포워딩했으나, 지금은 **토큰이 실제로 광고하는 mechanism만** 남기고 나머지는 opcode·
> CI 구조체·어댑터·mock·테스트까지 전부 제거했다(→ §2.7). 현재 포워딩되는 연산:

| 카테고리 | 연산 |
|----------|------|
| 난수 | RNG |
| 해시 | SHA-256/512, SHA3-224/256/384/512 (one-shot + 멀티파트 update/final) |
| 대칭 암복호 | AES — GCM(AEAD) · CTR(스트림) |
| XOF/키유도 | SHAKE-128/256 key derivation |
| PQC 서명/검증 | ML-DSA (강도 1/3/5) |
| PQC 키합의 | ML-KEM (강도 1/3/5, encaps/decaps) |
| 키 생성 | AES 키 · ML-DSA/ML-KEM 키페어 |

> **mock 토큰**은 결정론적 스텁(진짜 암호 아님)이지만, 왕복(encrypt∘decrypt=원문,
> sign→verify, 변조→오류)·크기·키/입력 민감성을 검증해 **포워딩 정확성**을 보장.
> 실제 암호값 정합성은 하드웨어 몫.

### 2.4 토큰 정체성·슬롯 바인딩·login (2026-09-02)
- **부팅 스캔**: `ncmpd`가 기동 시 각 online 슬롯에 `NCMP_CMD_VD_TOKEN_INFO`
  단발 왕복으로 토큰 정체성(label/serial/manufacturer/model/hw·fw 버전/flags)을
  조회해 SHM(`NCMP_TokenIdentity`, 슬롯별)에 캐시(`daemon/main.c`
  `ncmpd_probe_identity`). comm_thread 기동 전에 전송을 독점 사용.
- **CK슬롯↔물리토큰 바인딩**(`common/ncmp_slotmap.c`): `t_init`에서
  `ncmp_slot_bind()`가 원하는 **serial→label** 순으로 online·미할당 토큰을
  매칭, 없으면 **첫 미할당 online 토큰**을 할당. 바인딩은 **CK 슬롯 ID 기준**으로
  SHM `global_lock` 하에 저장돼, 같은 CK 슬롯의 여러 프로세스가 동일 물리 토큰으로
  수렴하고 데몬 수명 동안 유지(final에서 해제하지 않음). 원하는 label/serial은
  env `NCMP_TOK_LABEL[<n>]`/`NCMP_TOK_SERIAL[<n>]`(CK 슬롯별 접미사 우선).
- **login/PIN**(`stdll/ncmp_admin.c`): `t_login/t_logout/t_init_pin/t_set_pin/
  t_init_token`을 물리 토큰으로 포워딩(opcode `NCMP_CMD_LOGIN`..`INIT_TOKEN`).
  mock 토큰이 PIN 저장·검증(기본 user `1234`, SO `12345678`) 및 로그인 상태 관리.
- **get_token_info**: 캐시된 정체성으로 manufacturerID/model/serialNumber/hw·fw
  버전을 채움.
- **테스트**(`tests/test_admin.c`, 11종): 정체성 조회, serial/label 매칭, 첫
  미할당 폴백, 매칭 실패 폴백, 멱등 바인딩, 언바인드, login(오PIN/이미로그인/SO),
  set_pin·init_pin·init_token(오SO PIN 거부·재라벨 확인).

### 2.5 Mechanism 재정의: PQC / SHA3 / XOF (2026-09-02)
NCMP 토큰의 advertised mechanism list를 아래 집합으로 **재정의**하고 신규 기능·
테스트를 추가:
- **대칭키**: AES-GCM, AES-CTR (기존 포워딩 유지).
- **HASH/XOF**: SHA-256, SHA-512, SHA3-224/256/384/512(기존 DIGEST 경로 재사용,
  `ncmp_digest_size`에 SHA3 추가) + SHAKE-128/256 **key derivation**(신규 opcode
  `NCMP_CMD_SHAKE_DERIVE`, `t_shake_key_derive` 배선).
- **PQC(PKCS#11 3.2)**:
  - **ML-KEM** 보안강도 1/3/5(CKP_ML_KEM_512/768/1024, `CKA_PARAMETER_SET`로
    선택): 키페어 생성 + encapsulate/decapsulate로 **공유비밀** 유도.
  - **ML-DSA** 보안강도 1/3/5(CKP_ML_DSA_44/65/87): 키페어 생성 + **전자서명/검증**.
- **프록시 표현**: PQC 키는 통짜 블롭으로 `CKA_VALUE`에 저장, private 블롭은 public
  블롭을 접두어로 포함해 mock의 sign↔verify·encaps↔decaps가 일치. 크기는 공통
  계층이 넘겨준 `struct pqc_oid`에서 STDLL이 계산해 와이어로 전달(ML-KEM 공유비밀은
  32B 고정). KEM은 공통 계층 패턴대로 `object_mgr_create_skel/final`로 CKO_SECRET_KEY
  오브젝트를 생성.
- 신규 opcode: `SHAKE_DERIVE`(0x0009), `MLDSA_KEYGEN/SIGN/VERIFY`(0x0050~0x0052),
  `MLKEM_KEYGEN/ENCAPS/DECAPS`(0x0053~0x0055). mock 결정론 구현
  (`mcu_scheduler.c`), 어댑터(`ncmp_crypto.c`), 테스트(`test_pqc.c`, 4종).

### 2.6 자체 PKCS#11 프로바이더 계층 — 제거됨 (2026-09-02)
초기에는 `ncmp/pkcs11/`(p11_*.c)로 애플리케이션이 `libpkcs11_ncmp.so`를 직접
dlopen 해 `C_GetFunctionList`로 쓰는 **완전 자립형 프로바이더**를 병행 제공했으나,
opencryptoki 표준 STDLL(new_host 기반) 경로로 **일원화**하면서 해당 계층·전용
테스트(`test_pkcs11_api.c`)·빌드 배선을 모두 제거했다. 애플리케이션은 표준 3층
경로(API → new_host → `token_specific`=`ncmp/stdll/ncmp_specific.c`)만 사용한다.
벤더 와이어 opcode(0x0100+)는 토큰 datapath 기능이라 유지(`ncmp_cmd.h` +
`mock/mcu_scheduler.c`).

### 2.7 Mechanism 정리(advertised-only) · CI 동기화 · InitToken/Login 강화
- **비광고 mechanism 전면 제거**: advertised 집합(AES-GCM/CTR · SHA-2/3 · SHAKE ·
  ML-KEM · ML-DSA) **외의 모든 mechanism**(RSA sign/verify/PSS/OAEP/keygen, EC/ECDSA
  sign/verify/keygen, DH/ECDH, HMAC, AES-CBC/ECB/OFB/CFB, DES/3DES·generic-secret
  keygen)을 opcode(`ncmp_cmd.h`)·CI 구조체(`command-interface.md`)·크립토 어댑터
  (`ncmp_crypto.c`)·mock(`mcu_scheduler.c`)·테스트에서 삭제. `token_specific` 표에서도
  해당 훅 제거.
- **secure_key_token = TRUE**: 물리 토큰이 모든 PIN·키 비밀을 소유하는 프록시
  모델을 반영. STDLL은 임시 비밀 버퍼를 사용 직후 zeroize.
- **CI ↔ opcode 동기화**: `command-interface.md`의 `typedef enum CI_Cmd`를
  `enum ncmp_opcode`의 **별칭**으로 재정의(`CI_CMD_NOP = NCMP_CMD_NOP /* 0x0000 */`
  형식)해 두 열거형을 lockstep 유지. `VD_LOOPBACK`(0x0100) 제거 — 에코는 `NOP`로 통합.
- **신규 조회 CI**: `GET_UTC_TIME`(0x0035, `CK_TOKEN_INFO.utcTime` 16B),
  `GET_TOKEN_PARAMS`(0x0036, label·serial·ulMinPinLen·ulMaxPinLen). STDLL
  `get_token_info`가 이 값을 반영. 어댑터 `ncmp_admin_get_utc_time` /
  `ncmp_admin_get_token_params`.
- **Login flags 강화**: `LOGIN` 요청이 역할(SO/User/CONTEXT_SPECIFIC) 외에 flags를
  운반 — protected-auth(토큰 패드 입력), context-specific 재인증
  (`CKA_ALWAYS_AUTHENTICATE`). 어댑터/`token_specific_login`/mock 모두 반영.
- **C_InitToken 개편**: set(PIN+label) → `VD_TOKEN_INFO`로 label read-back·정밀
  검증 → 정체성을 `nv_token_data`에 캐시 → `save_token_data()` 영속화 → 임시 SO
  PIN·label 버퍼 zeroize. 데이터스토어 훅
  `t_init_token_data`/`t_load_token_data`/`t_save_token_data` 배선.
- 테스트: 삭제된 mechanism 테스트 제거, 신규 `test_admin_token_params`·
  `test_admin_login_flags`·`test_admin_set_utc_time` 추가 → **43/43 통과**.

---

## 3. 남은 과제 (TODO)

### 3.1 하드웨어 필요 — STEP ⑩ (실질적 유일 잔여 작업)
- [ ] `usb_transport.c`의 **VID/PID/엔드포인트를 실 FX3 펌웨어 값으로 확정**.
- [ ] `ncmpd` 기동 후 `pkcsconf -t`로 **슬롯 인식·토큰 정보 런타임 검증**.
- [ ] 실제 SHA/AES-GCM·CTR/SHAKE/ML-DSA·ML-KEM **암호 정합성**(mock 결정론 스텁 →
      진짜 값) 확인.
- [ ] 다중 FX3 보드 시 opencryptoki 슬롯↔물리 슬롯 매핑(`ncmptok.conf`; 현재 최저
      online 슬롯 자동 선택).

### 3.2 순수 반복(새 패턴 없음, 필요 시)
- [ ] SHA/ML-DSA 멀티파트 확장, 다이제스트-then-sign(`CKM_HASH_ML_DSA*`) 등
      **광고된 mechanism 범위 내** 추가 경로.
- [ ] 기본 빌드(`--enable-ncmptok` 미지정) 전체 `make` 회귀 1회(조건부 배선이라
      구조적 무영향이나 확인 권장).

### 3.3 도구/환경
- [ ] `libusb-1.0-0-dev` 정식 설치(현재는 헤더만 임시 확보해 실분기 컴파일 검증).
- [ ] CMake 설치(현재 gcc 수동 빌드로 검증) + CI에서 mock 빌드/ctest 자동화.

---

## 4. 빌드 & 테스트

```bash
# (A) opencryptoki STDLL — 실제 토큰 빌드
cd /home/pooky/workspace/opencryptoki
autoreconf --force --install
./configure --enable-ncmptok
make opencryptoki/stdll/libpkcs11_ncmp.la     # -> libpkcs11_ncmp.so

# (B) ncmp 서브트리 standalone 테스트 (하드웨어/데몬 불필요, mock 루프백)
cd /home/pooky/workspace/opencryptoki
gcc -std=c11 -O2 -Wall -Wextra -D_GNU_SOURCE \
    -Iusr/include -Incmp/include -Incmp/tests -Incmp/mock -Incmp/daemon \
    ncmp/tests/*.c ncmp/common/*.c \
    ncmp/stdll/ncmp_session.c ncmp/stdll/ncmp_client.c ncmp/stdll/ncmp_ckr.c \
    ncmp/stdll/ncmp_crypto.c ncmp/stdll/ncmp_admin.c \
    ncmp/daemon/comm_thread.c ncmp/daemon/conn_thread.c \
    ncmp/mock/mock_transport.c ncmp/mock/fx3_dma.c ncmp/mock/container.c \
    ncmp/mock/mcu_scheduler.c -lpthread -lrt -o /tmp/ncmp_tests
/tmp/ncmp_tests                                # -> SUITE PASSED (43/43)

# ThreadSanitizer (ASLR off + 새로 빌드한 바이너리 필수):
#   위 명령에 -fsanitize=thread 추가 후:  setarch $(uname -m) -R /tmp/ncmp_tests

# CMake 설치 시: cd ncmp && cmake -S . -B build -DENABLE_MOCK_TOKEN=ON && ctest --test-dir build
```

---

## 5. 다음 착수 추천
하드웨어(FX3 보드) 준비 시 **STEP ⑩**로 진행: `usb_transport.c` VID/PID/EP 확정 →
`ncmpd` 기동 → `pkcsconf -t` 슬롯 확인 → 대표 연산(RNG·SHA·AES) 실 정합성 검증 →
나머지 연산 순차 확인. 소프트웨어 계층은 이미 전 연산 포워딩이 완비되어, 하드웨어
브링업 후 곧바로 end-to-end 동작이 가능한 상태.

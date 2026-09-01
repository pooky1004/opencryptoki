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
| 진행 단계 | STEP ①~⑨ + 연산 확장 완성 |
| standalone 테스트 | **32/32 통과** (전송 계층), ThreadSanitizer 0 races |
| opencryptoki STDLL | `libpkcs11_ncmp.so.0.0.0` **실제 빌드 성공** (strict `-pedantic -Werror -std=c99`) |
| `token_specific` 훅 | **36종** 배선 (crypto 30 + 라이프사이클/리포팅 6) |
| 와이어 opcode | 20종 + 벤더 8종 (loopback/mem read·write·fill·crc/ping/selftest/fw) |
| 소스 규모 | `ncmp/` 서브트리 53파일 + opencryptoki 통합 4파일 |
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

| 카테고리 | 연산 |
|----------|------|
| 난수 | RNG |
| 해시 | SHA-1/224/256/384/512 (one-shot + 멀티파트 update/final) |
| MAC | HMAC (sign/verify) |
| 대칭 암복호 | AES — CBC · ECB · GCM(AEAD) · CTR · OFB · CFB |
| 비대칭 암복호 | RSA-OAEP (encrypt/decrypt) |
| 서명/검증 | RSA-PKCS · RSA-PSS · ECDSA |
| 키 생성 | AES · DES · 3DES · generic-secret · RSA keypair · EC keypair |
| 키 합의 | DH · ECDH |

> **mock 토큰**은 결정론적 스텁(진짜 암호 아님)이지만, 왕복(encrypt∘decrypt=원문,
> sign→verify, 변조→오류)·크기·키/입력 민감성을 검증해 **포워딩 정확성**을 보장.
> 실제 암호값 정합성은 하드웨어 몫.

### 2.4 자체 PKCS#11 프로바이더 계층 — 제거됨 (2026-09-02)
초기에는 `ncmp/pkcs11/`(p11_*.c)로 애플리케이션이 `libpkcs11_ncmp.so`를 직접
dlopen 해 `C_GetFunctionList`로 쓰는 **완전 자립형 프로바이더**를 병행 제공했으나,
opencryptoki 표준 STDLL(new_host 기반) 경로로 **일원화**하면서 해당 계층·전용
테스트(`test_pkcs11_api.c`)·빌드 배선을 모두 제거했다. 애플리케이션은 표준 3층
경로(API → new_host → `token_specific`=`ncmp/stdll/ncmp_specific.c`)만 사용한다.
벤더 와이어 opcode(0x0100+)는 토큰 datapath 기능이라 유지(`ncmp_cmd.h` +
`mock/mcu_scheduler.c`).

---

## 3. 남은 과제 (TODO)

### 3.1 하드웨어 필요 — STEP ⑩ (실질적 유일 잔여 작업)
- [ ] `usb_transport.c`의 **VID/PID/엔드포인트를 실 FX3 펌웨어 값으로 확정**.
- [ ] `ncmpd` 기동 후 `pkcsconf -t`로 **슬롯 인식·토큰 정보 런타임 검증**.
- [ ] 실제 SHA/AES/RSA/EC 등 **암호 정합성**(mock 결정론 스텁 → 진짜 값) 확인.
- [ ] 다중 FX3 보드 시 opencryptoki 슬롯↔물리 슬롯 매핑(`ncmptok.conf`; 현재 최저
      online 슬롯 자동 선택).

### 3.2 순수 반복(새 패턴 없음, 필요 시)
- [ ] HMAC 멀티파트(update/final), DH/EC 키페어 생성, 다이제스트-then-sign,
      추가 mech(SHAKE, MD 등).
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
    ncmp/daemon/comm_thread.c ncmp/daemon/conn_thread.c \
    ncmp/mock/mock_transport.c ncmp/mock/fx3_dma.c ncmp/mock/container.c \
    ncmp/mock/mcu_scheduler.c -lpthread -lrt -o /tmp/ncmp_tests
/tmp/ncmp_tests                                # -> SUITE PASSED (32/32)

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

# Token NCMP 진행 상태 (Status)

- **최종 업데이트**: 2026-08-31
- **저장소**: `/home/pooky/workspace/opencryptoki` (fork `pooky1004/opencryptoki`, `master`)
- **현재 단계**: 스캐폴드 + **STEP ①~⑨ 완료 = 소프트웨어 프레임워크 기능 완성**.
  ① SHM + mock 루프백 / ② comm_thread 파이프라인 + in-flight 통계 /
  ③ STDLL 클라이언트 왕복(실 소켓 IPC + CKR 매핑 + ACK 에러) /
  ④ libusb 실전송 + `daemon/main.c` 라이프사이클 /
  ⑤ opencryptoki 통합(`--enable-ncmptok` → `libpkcs11_ncmp.so` 빌드) /
  ⑥ 포워딩 프레임워크(opcode + `ncmp_client_command`) + 첫 연산 RNG /
  ⑦ SHA one-shot digest 포워딩 /
  ⑧ 다중버퍼(AES-CBC) + 8-param 헬퍼 /
  **⑨ 상태형(멀티파트 digest 토큰-측 컨텍스트 핸들) + 비대칭(RSA 서명, 다중 키
  컴포넌트 추출) + 슬롯 매핑(`__builtin_ctz(slot_mask)`)**.
  → **4대 전송 패턴 모두 확립**: 무상태-단일버퍼(RNG)·무상태-다중버퍼(AES/digest)·
  상태형-컨텍스트(멀티파트)·비대칭-다중키(RSA). 나머지 연산은 이 패턴들의 반복.
  **+ 연산 확장**: AES 전 모드(CBC/ECB/GCM/CTR/OFB/CFB), RSA(sign/verify/OAEP/
  **PSS**), EC(sign/verify), HMAC(sign/verify), 키 생성 전종류, **DH/ECDH 키 합의**
  → PKCS#11 전 연산 카테고리 커버.
  다음은 **STEP ⑩(실 FX3 하드웨어 브링업: VID/PID/EP 확정 + `pkcsconf` 런타임 검증)** —
  하드웨어 필요. 현 시점 standalone **32/32 통과 + TSan 클린**, opencryptoki STDLL
  `.so`에 **36개 `token_specific_*` 훅**(crypto 30종) 링크 검증 완료.

---

## 1. 지금까지 한 일 (Done)

### 1.1 환경/빌드 방침 결정
- 포크는 autotools(`configure.ac`, `--enable-*tok`) 기반, 토큰은
  `token_spec_t token_specific` SPI로 등록되는 STDLL 구조임을 확인.
- NCMP 서브시스템(데몬·목·테스트)의 독립성이 크고 사양이 CMake
  (`-DENABLE_MOCK_TOKEN`)를 명시하므로, **자체 완결형 `ncmp/` CMake 서브트리**로
  스캐폴딩. 실제 opencryptoki 로더 연동(autotools `--enable-ncmptok`)은
  후속 과제로 문서화.

### 1.2 문서 (3종)
- `CLAUDE.md` (109줄, 목표 100–140) — 규칙·한계값·빌드/테스트 명령·와이어 요약.
- `docs/architecture.md` — 시스템 개요, FX3 데이터패스, 와이어 프로토콜, SHM
  (오프셋 기반), 동시성 모델, in-flight 통계, 데이터 흐름, 통합 경로.
- `docs/INDEX.md` — 온디맨드 문서/소스 색인.
- `ncmp/README.md` — 서브트리 빌드/레이아웃 안내.

### 1.3 공개 헤더 (`ncmp/include/ncmp/`, 7종) — 저수준 가이드라인을 코드로 인코딩
- `ncmp_limits.h` — 4 slots / 8 sessions / 32 total, 파라미터 32KB·페이로드
  40KB, FX3 버퍼(Rx 64KB/Tx 128KB)·컨테이너(64KB×4)·기본 in-flight 상한.
- `ncmp_wire.h` — `NCMP_Header`, param_len[8], 4바이트 정렬, 불변식, 단발 수신.
- `ncmp_queue.h` — MPSC 링, CAS 상태머신, `ncmp_qentry_cas()`.
- `ncmp_shm.h` — `NCMP_ShmHeader`/`NCMP_Slot`/`NCMP_SlotStats`, `ncmp_shm_ptr()`.
- `ncmp_mutex.h` — robust 프로세스 공유 뮤텍스 래퍼 계약.
- `ncmp_ipc.h` — 데몬↔STDLL 소켓 핸드셰이크(HELLO/ATTACH).
- `ncmp_errno.h` — 내부 `NCMP_ERR_*` 코드.

### 1.4 모듈 스캐폴드 (4 모듈 + common)
- **Module A `ncmp/daemon/`**: `main.c`(시그널·라이프사이클), `conn_thread.c`,
  `comm_thread.c`(in-flight 통계 로직 포함), `usb_transport.c`(단발 수신 골격).
- **Module B `ncmp/stdll/`**: `ncmp_specific.c`(토큰 SPI seam),
  `ncmp_client.c`(claim/post/wait), `ncmp_session.c`, `tok_struct.h`.
- **Module C `ncmp/mock/`**: `mock_main.c`, `fx3_dma.c`, `container.c`(mover),
  `mcu_scheduler.c`(round-robin).
- **Module D `ncmp/tests/`**: 와이어/큐/세션/뮤텍스/통계/동시성/ACK 테스트 +
  `ncmp_test.h` 러너.
- **common**: `ncmp_mutex.c`, `ncmp_queue.c`, `ncmp_wire.c`, `ncmp_shm.c`.
- **빌드**: 최상위 `CMakeLists.txt`(+`ENABLE_MOCK_TOKEN`, `_GNU_SOURCE`), 모듈별
  `CMakeLists.txt`, `cmake/FindLibUSB.cmake`.

### 1.5 실동작 구현 완료(스텁 아님)
- robust mutex 래퍼(`ncmp_mutex_init/lock/unlock`, EOWNERDEAD→consistent 복구).
- CAS 큐 `ncmp_queue_claim/post` + inline CAS/state-load.
- 와이어 검증 + **직렬화 `ncmp_wire_encode` / 역직렬화 `ncmp_wire_decode_header`
  · `ncmp_wire_decode`** (little-endian, 불변식 검사, `_Static_assert`로 헤더
  20바이트 고정 보장). — STEP ①
- 세션 상한 `ncmp_session_open/close`(sess_lock 임계구역).
- **SHM `ncmp_shm_create/attach/detach/destroy`** (shm_open·ftruncate·mmap,
  magic/version 검증, global_lock·slot별 sess_lock·ring FREE 초기화). — STEP ①
- **transport 추상화(`ncmp_transport.h`) + mock 루프백(`mock_transport.c`)**:
  open→mover, recv→MCU. `usb_transport.c`도 동일 심볼로 정렬(실전송은 TODO). — STEP ①
- mover ingest(길이 프리픽스 파싱 + 컨테이너 배정), **MCU echo 응답 생성**
  (요청 identity/payload 유지, `ack=CKR_OK`). — STEP ①
- **SHM per-entry 요청/응답 버퍼 풀 배치**(`ncmp_shm.c`): 슬롯당 풀 +
  entry별 `req_off`/`rsp_off` 지정, `ncmp_shm_slot()` 헬퍼. — STEP ②
- **producer 헬퍼**(`common/ncmp_slot.c`): `ncmp_slot_enqueue`(claim→SHM 버퍼에
  encode→post), `ncmp_slot_wait`(DONE 폴링→decode→FREE, 타임아웃 ABANDONED). — STEP ②
- **comm_thread 파이프라인**(`daemon/comm_thread.c`): dispatch(POSTED→SENT,
  `in_flight<max_inflight`까지 연속 송신) + drain(응답 수신→`sequence_id` 매칭→
  SENT→DONE), in-flight 3종 통계 실측, 종료 시 스레드 자가 리포트. `g_running`
  의존 제거(ctx.stop) → 단독 유닛 테스트 가능. stop 플래그는 `__atomic_*`
  래퍼(`ncmpd_request_stop`/`ncmpd_should_stop`)로 접근(TSan 클린). — STEP ②
- **IPC 소켓**(`common/ncmp_ipc.c`): `ncmp_ipc_connect`(HELLO 송신→ATTACH 수신)
  + `ncmp_ipc_listen`(bind/listen, 경로 인자화), full read/write 헬퍼. — STEP ③
- **conn_thread 서버**(`daemon/conn_thread.c`): poll 기반 accept 루프(정상 종료),
  HELLO 검증→online 슬롯 비트마스크 계산→ATTACH 응답. — STEP ③
- **STDLL 클라이언트**(`stdll/ncmp_client.c`): `ncmp_client_init`(connect+attach)
  / `ncmp_client_exec`(슬롯 검증→`ncmp_slot_enqueue`/`wait` 재사용) /
  `ncmp_client_fini`. — STEP ③
- **CKR 매핑**(`stdll/ncmp_ckr.c` + `ncmp_ckr.h`): `NCMP_ERR_*`→`CKR_*` 단일
  변환 지점(예: NODAEMON→TOKEN_NOT_PRESENT, TIMEOUT→FUNCTION_CANCELED). — STEP ③
- **mock ACK 오류 주입**(`mcu_scheduler.c`): 요청 `command_id`의
  `NCMP_MOCK_CMD_FAIL_BIT` 시 `ack=CKR_FUNCTION_FAILED` 반환. — STEP ③
- **libusb 실전송**(`daemon/usb_transport.c`): `__has_include(<libusb.h>)` 가드로
  실 구현/스텁 자동 선택. `ncmp_transport_probe`(VID/PID 열거→슬롯 매핑),
  `_open`(nth FX3 device open+claim), `_send`(bulk exact 루프)/`_recv`(**단발
  수신**: 최대 버퍼로 프레임 1개 한 번에 read), `_close`. VID/PID/EP는 상수 + 펌웨어 확정 시 조정 주석. — STEP ④
- **transport 열거 추상화**: `ncmp_transport_probe()`를 mock/real 양쪽에 구현
  (mock=1 슬롯, real=매칭 USB 수, cap 4). — STEP ④
- **daemon 라이프사이클**(`daemon/main.c`): 시그널 설치→SHM create→probe→슬롯별
  transport open + comm_thread 기동→conn_thread 기동→`g_running` 대기→
  정상 종료(stop/join/close/destroy). `NCMP_SOCK_PATH` env로 소켓 경로 override. — STEP ④
- **opencryptoki 통합**(`usr/lib/ncmp_stdll/`): `tok_struct.h`(C99 지정 초기화
  `token_specific` — 라이프사이클 훅만 채우고 crypto는 NULL, EP11/ICSF 프록시
  패턴), `ncmp_specific.c`(`token_specific_init`=ncmpd 연결→`private_data`,
  `_final`, `_get_token_info`, `_get_mechanism_list/info`, 토큰 identity 전역),
  `ncmp_stdll.mk`(공통 소스 + ncmp client 소스 + `-I ncmp/include`, libusb 불필요).
  autotools: `configure.ac --enable-ncmptok`(기본 off), `usr/lib/lib.mk`,
  `Makefile.am` install/uninstall 훅, `opencryptoki.conf` 예시 슬롯(주석). — STEP ⑤
- **PKCS#11 연산 포워딩 프레임워크**: command_id opcode 체계(`ncmp_cmd.h`:
  `[15:0]` opcode / `[31:16]` flags), 전송 계층 순수 바이트 API
  `ncmp_client_command`(opcode + in/out 바이트, atomic seq, 유한 타임아웃).
  mock MCU가 opcode 디스пат치(RNG 처리 + 미지 opcode는 echo로 하위호환). — STEP ⑥
- **첫 crypto 연산 RNG 포워딩**: opencryptoki `token_specific_rng`가
  `NCMP_CMD_RNG`로 32KB 청크 포워딩→토큰 응답을 CK_BYTE 버퍼로. `.t_rng` 연결.
  mock은 결정론적 패턴(`NCMP_MOCK_RNG_BYTE`) 반환으로 테스트 검증 가능. — STEP ⑥
- **SHA one-shot digest 포워딩**: `NCMP_CMD_DIGEST`(param0=`[mech LE u32|data]`),
  `ncmp_digest_size()`로 mech→출력 크기 매핑을 adapter/mock 공유. opencryptoki
  `token_specific_sha_init`(dig_mgr 계약대로 ctx 컨텍스트 sentinel 할당 +
  `context_free_func`) + `token_specific_sha`(마샬링→포워딩). `.t_sha_init/.t_sha`
  연결, mech_list에 SHA-1/224/256/384/512 광고. mock은 입력 민감 결정론적
  digest 반환(실 해시는 하드웨어). — STEP ⑦
- **다중 파라미터(다중버퍼) 인프라**: 와이어 헬퍼 `ncmp_msg_pack`(parts→payload
  concat + param_len 설정, 32KB/40KB 한계 검사)·`ncmp_msg_param`(누적 오프셋으로
  추출) + 8-param 전송 API `ncmp_client_command_mp`. — STEP ⑧
- **AES-CBC 포워딩**: `NCMP_CMD_AES_CBC` params `[flags|key|iv|data]→[out]`.
  opencryptoki `token_specific_aes_cbc`가 OBJECT에서 키 추출
  (`template_attribute_get_non_empty(CKA_VALUE)`)→다중버퍼 포워딩, `.t_aes_cbc`
  연결. mock은 가역 keystream XOR(방향 무관, encrypt∘decrypt=원문)로 왕복 검증
  가능(실 AES는 하드웨어). opcode 충돌 방지 위해 echo 테스트는 `NCMP_CMD_NOP`
  사용으로 정정. — STEP ⑧
- **슬롯 매핑**: `token_specific_init`이 데몬 `slot_mask`의 최저 online 슬롯을
  `__builtin_ctz`로 선택(mask 0이면 `CKR_TOKEN_NOT_PRESENT`). 다중 보드는
  `ncmptok.conf`로 지정 예정(TODO). — STEP ⑨
- **멀티파트 digest(상태형 토큰-측 컨텍스트)**: opcode INIT/UPDATE/FINAL. mock이
  슬롯별 컨텍스트 테이블(id) 유지, one-shot과 fold/finalize 공유 → `멀티파트==원샷`
  보장. opencryptoki `token_specific_sha_update/_final`이 lazy INIT로 컨텍스트 id를
  `ctx->context`에 보관, UPDATE 32KB 청크, FINAL 후 컨텍스트 해제. — STEP ⑨
- **RSA 서명(비대칭 다중 키 컴포넌트)**: opcode `NCMP_CMD_RSA_SIGN`
  params `[modulus|priv_exp|data]→[sig]`. opencryptoki `token_specific_rsa_sign`이
  OBJECT에서 `CKA_MODULUS`+`CKA_PRIVATE_EXPONENT` 추출→포워딩, 서명 길이=모듈러스
  길이. mock은 입력·키 민감 결정론적 서명(실 RSA는 하드웨어). — STEP ⑨
- **연산 확장(기존 패턴 반복)**: — 연산 확장
  - **AES-ECB**(`t_aes_ecb`, `[flags|key|data]`, IV 없는 AES-CBC 변형).
  - **EC(ECDSA) 서명**(`t_ec_sign`, `[ec_params|priv|data]→[sig]`, 서명 길이
    =2×필드길이, `CKA_EC_PARAMS`+`CKA_VALUE` 추출).
  - **AES-GCM(AEAD, 신규 패턴)**: opcode `NCMP_CMD_AES_GCM`
    `[flags|key|iv|aad|taglen|data]→[out]`. 공통 계층이 GCM 파라미터를
    `ctx->mech`에 복제·키 핸들을 `ctx->key`에 보관하므로, `token_specific_aes_gcm`이
    `object_mgr_find_in_map1`로 키 추출 + 파라미터 읽어 포워딩(암호화=ct‖tag,
    복호화=tag 검증 후 평문). mock은 가역 keystream XOR + 결정론적 tag(변조 시
    `CKR_ENCRYPTED_DATA_INVALID`). `t_aes_gcm_init`은 프록시라 무상태(검증만).
  - **RSA/EC 서명 검증(sign/verify 왕복)**: opcode `NCMP_CMD_RSA_VERIFY`
    `[mod|pub_exp|data|sig]`, `NCMP_CMD_EC_VERIFY` `[ec_params|point|data|sig]`.
    `token_specific_rsa_verify`/`_ec_verify`가 **공개 키**(RSA=modulus+pub_exp,
    EC=ec_params+ec_point) 추출→포워딩, ACK로 `CKR_OK`/`CKR_SIGNATURE_INVALID`.
    mock은 서명을 재계산(공유 컴포넌트 modulus/ec_params + data fold, `mock_sig_expand`
    공유)→비교. sign도 동일 공유 컴포넌트만 fold하도록 재설계하여 **sign→verify
    왕복 일치 + 변조 시 SIGNATURE_INVALID** 검증. (private 값은 포워딩되나 mock
    출력엔 미반영 — mock 한계.)
  - **AES 키 생성**: `token_specific_aes_key_gen`이 `NCMP_CMD_RNG`로 keysize 바이트
    생성→키 재료(`is_opaque=FALSE`). 키 생성 = 토큰 RNG 포워딩 패턴.
  - **RSA/EC 키페어 생성(템플릿 조작 패턴)**: opcode `NCMP_CMD_RSA_KEYGEN`
    `[modbits|pub_exp]→[n|d|p|q|dp|dq|qinv]`(7 컴포넌트), `NCMP_CMD_EC_KEYGEN`
    `[ec_params]→[ec_point|priv]`. 어댑터가 `template_attribute_get_ulong`
    (`CKA_MODULUS_BITS`)로 키 크기 추출→토큰 생성 요청→응답 컴포넌트를
    `build_attribute`+`template_update_attribute`로 공개/개인 템플릿에 채움
    (`ncmp_tmpl_add` 헬퍼, build_attribute 단일 블록 할당 확인 후 실패 시 free).
    mock은 크기 규격에 맞는 결정론적 컴포넌트 생성(실 키페어는 하드웨어). — 연산 확장
  - **AES 스트림 모드(CTR/OFB/CFB)**: opcode `NCMP_CMD_AES_CTR/OFB/CFB`
    `[flags|key|iv|data]→[out]`(블록 정합 불필요, 출력=입력 길이). 어댑터 공유
    헬퍼 `ncmp_aes_stream`(OFB/CFB는 `out_len` 인자 없음 — 출력=입력 길이).
    mock은 세 모드 모두 동일 가역 keystream XOR(공유 `mock_aes_stream`).
    CTR counter_width·CFB cfb_len은 mock 미반영(실 HW 처리). — 연산 확장
  - **HMAC(대칭 MAC)**: opcode `NCMP_CMD_HMAC_SIGN` `[mech|key|data]→[mac]`,
    `NCMP_CMD_HMAC_VERIFY` `[mech|key|data|mac]→(ack)`. 어댑터가 `sess->sign_ctx`
    /`verify_ctx`에서 키 핸들+mech 추출→키 해석→포워딩. `ncmp_hmac_size(mech)`로
    출력 크기(HMAC-SHA*). sign/verify가 같은 키 fold→왕복 일치·변조 시
    `CKR_SIGNATURE_INVALID`. — 연산 확장
  - **RSA-OAEP(비대칭 암복호)**: opcode `NCMP_CMD_RSA_OAEP_ENC`
    `[mod|pub_exp|data]→[ct]`(모듈러스 길이), `_DEC` `[mod|priv_exp|ct]→[plain]`.
    어댑터가 `ctx->key` 해석→공개/개인 키 컴포넌트 포워딩(OAEP label hash는 mock
    무시). mock은 `[len|data|pad]`를 모듈러스 유도 keystream XOR로 인코딩→복호 시
    복원(암호화∘복호=원문). — 연산 확장
  - **대칭 키 생성 전종류**: 공유 헬퍼 `ncmp_gen_random`(RNG 포워딩) +
    `ncmp_symkey_gen`으로 `token_specific_aes_key_gen`/`des_key_gen`(DES 8·3DES 24
    바이트) 통일. `token_specific_generic_secret_key_gen`은 `CKA_VALUE_LEN` 읽어
    랜덤 생성→`ncmp_tmpl_add`로 `CKA_VALUE` 템플릿 삽입(전방 선언으로 순서 해결). — 연산 확장
  - **RSA-PSS 서명/검증**: `SIGN_VERIFY_CONTEXT*`에서 `ctx->key` 해석→공개/개인 키
    컴포넌트 추출→**RSA_SIGN/VERIFY opcode 재사용**(마샬링 동일, mock은 PSS/PKCS
    구분 없이 결정론적). modlen을 object_put 전 캡처(use-after-release 회피). — 연산 확장
  - **DH/ECDH 키 합의**: opcode `NCMP_CMD_DH_DERIVE` `[prime|priv|peer_pub]→[secret]`,
    `NCMP_CMD_ECDH_DERIVE` `[ec_params|priv|peer_point]→[secret]`. 원시 바이트 배열
    입력(오브젝트 해석 불필요). 어댑터가 그대로 포워딩→`*secret_len`을 응답 길이로.
    mock은 세 입력을 fold→결정론적 shared secret(DH=prime 길이, ECDH=필드 길이
    =(point-1)/2). 실 modexp/스칼라곱은 하드웨어. — 연산 확장

### 1.6 검증
- cmake 미설치 → gcc 직접 컴파일. 전 모듈 `-Wall -Wextra -Wshadow` 클린.
- 테스트 스위트 실행: **32/32 PASS (`SUITE PASSED, 0 failures`)**.
  - 통과: 와이어 3, 큐 CAS 3, 세션 상한 1, SHM 왕복·교차매핑 2, mock 루프백
    echo 1, in-flight 통계 1, 멀티스레드 동시성 1, **STDLL 클라이언트 왕복 1,
    ACK 오류 전파 1**.
- **-O2(FORTIFY) 무경고 빌드 + 30회 연속 통과 + ThreadSanitizer 클린**(stop
  플래그 원자화로 경합 0; ASLR off 환경에서 검증).
- end-to-end 검증: `test_shm_create_attach`, `test_shm_cross_mapping_visibility`,
  `test_mock_loopback_echo`(session/sequence/command 유지 + payload echo + ack==0).
- **STEP ② 실측 검증**:
  - `test_inflight_stats_tracking`: N=8을 소비자 기동 전 일괄 enqueue →
    `stats_total_sent_cmds==8`, `stats_max_in_flight==4`(=컨테이너 수=max_inflight,
    결정론적), 종료 시 `in_flight_cnt==0`.
  - `test_concurrent_enqueue_single_slot`: 4 producer × 4 req 동시 enqueue →
    (session,sequence) 상관 정확, 누수 0(전 엔트리 FREE), `total_sent==16`.
- **STEP ③ 검증**:
  - `test_client_roundtrip`: 인프로세스 데몬(SHM+comm+conn) 기동 → 클라이언트가
    실 소켓으로 `ncmp_client_init` 핸드셰이크 → `slot_mask` 확인(slot0 online,
    slot1 offline) → `ncmp_client_exec` 성공(echo, ack==CKR_OK) → offline 슬롯
    거부(→CKR_TOKEN_NOT_PRESENT).
  - `test_ack_error_propagation`: fail-bit 주입 → 전송은 성공(NCMP_OK)하되
    `rsp.ack==CKR_FUNCTION_FAILED` 그대로 surface, identity 유지.
- **STEP ④ 검증**(하드웨어 없이 가능한 범위):
  - **mock ncmpd**: 빌드→실행 `running (mask=0x1)`→SIGTERM→comm 통계 리포트→
    `stopped` 정상 종료.
  - **real ncmpd**: libusb dev 헤더 확보(apt-get download, root 불필요)로 실
    libusb 분기 컴파일(0 경고, `libusb_init/open/claim/bulk_transfer` 심볼 참조
    확인) + `libusb-1.0.so.0` 링크. 실행 시 probe가 FX3 미발견→`mask=0x0`,
    블로킹 없이 정상 기동·종료.
  - `usb_transport.c` 스텁 분기(헤더 부재)도 무경고 컴파일.
- **STEP ⑤ 검증**(실제 opencryptoki 빌드):
  - `ncmp_specific.c`가 실 opencryptoki 헤더(`token_spec_t`/`STDLL_TokData_t`/
    `MECH_LIST_ELEMENT`/`ock_generic_*`)에 대해 무경고 컴파일.
  - `autoreconf` 클린 재생성 → `./configure --enable-ncmptok` → `NCMP token: yes`.
  - `make opencryptoki/stdll/libpkcs11_ncmp.la` **성공** → `libpkcs11_ncmp.so.0.0.0`
    (4.1MB) 생성. `SC_*` PKCS#11 진입점(@OPENCRYPTOKI_TOK_3.27) export,
    `token_specific`/`token_specific_init` 정의, ncmp client 심볼
    (`ncmp_client_init`/`ncmp_ipc_connect`/`ncmp_shm_attach`/…) 링크.
  - `ldd`: crypto+lber만 의존, **libusb 미의존**(STDLL은 소켓/SHM로 ncmpd 연결).
- **STEP ⑥ 검증**:
  - standalone `test_client_rng_forward`: `ncmp_client_command(NCMP_CMD_RNG)`로
    64B 요청→응답 바이트를 `NCMP_MOCK_RNG_BYTE` 패턴과 byte-for-byte 대조,
    ack==CKR_OK. 기존 echo 테스트 전부 유지(미지 opcode=echo). **16/16 통과**.
  - opencryptoki STDLL 재빌드 성공 → `token_specific_rng`/`ncmp_client_command`
    링크. 실 빌드 strict 플래그(`-pedantic -Werror=strict-prototypes
    -Werror=implicit-function-declaration -std=c99`)로도 ncmp 소스 무경고.
  - TSan 클린(atomic seq 경합 0) + 20회 연속 통과.
- **STEP ⑦ 검증**:
  - standalone `test_client_digest_forward`: SHA-256 digest 왕복 → `out_len==32`,
    ack==OK, **결정론(동일입력=동일출력)·입력민감(다른입력=다른출력)** 검증,
    미지원 mech→`CKR_MECHANISM_INVALID`(0x70). **17/17 통과** + TSan 클린 + 20회.
  - opencryptoki STDLL 재빌드 성공 → `token_specific_sha`/`_sha_init` 링크
    (strict `-pedantic -Werror` 통과).
- **STEP ⑧ 검증**:
  - standalone `test_client_aes_cbc_forward`: key16/iv16/data32 다중버퍼 →
    encrypt→ciphertext(≠원문)→decrypt→**원문 복원(round-trip)**, 블록 비배수
    입력→`CKR_MECHANISM_INVALID`. **18/18 통과** + TSan 클린(fresh 빌드) + 20회.
  - opencryptoki STDLL 재빌드 성공 → `token_specific_aes_cbc`/`ncmp_client_command_mp`
    /`ncmp_msg_pack` 링크(strict `-pedantic -Werror` 통과).
- **STEP ⑨ 검증**:
  - `test_client_digest_multipart`: INIT→UPDATE×2→FINAL, **멀티파트("hel"+"lo")==
    원샷("hello")** byte 일치, FINAL 후 재-FINAL→`CKR_FUNCTION_FAILED`(컨텍스트 해제).
  - `test_client_rsa_sign_forward`: 다중 키 컴포넌트(mod256/exp256/data32) →
    서명 길이==모듈러스, 결정론·입력민감·**키민감** 검증.
  - **20/20 통과** + TSan 클린 + 20회 연속. opencryptoki STDLL에
    `token_specific_sha_update`/`_sha_final`/`_rsa_sign` 링크(9개 훅 배선).

---

## 2. 남은 과제 (TODO)

### 2.1 Common / 전송
- [x] `ncmp_wire_encode` / `ncmp_wire_decode_header` / `ncmp_wire_decode`
      little-endian 직렬화 완성. — STEP ①
- [x] `ncmp_shm_create`/`attach`/`detach`/`destroy` 실제 구현. — STEP ①
- [x] SHM 내 per-entry 요청/응답 스크래치 풀 배치 + ring `req_off`/`rsp_off`
      연결 + `ncmp_shm_slot()` 헬퍼. — STEP ②
- [ ] `ncmp_queue_claim` 스캔 시작점 atomic 힌트 커서(경합 완화).

### 2.2 Module A — ncmpd
- [x] `main` 라이프사이클: 시그널 설치→SHM 생성→probe→comm_thread(≤4)→
      conn_thread→`g_running` 종료 후 join, 스레드별 통계 자가 출력. — STEP ④
- [x] `conn_thread`: poll 기반 accept 루프, HELLO/ATTACH 핸드셰이크, online
      슬롯 비트마스크 응답, 정상 종료. — STEP ③
- [x] `comm_thread`: dispatch/drain 파이프라인, in-flight 예약/해제, `sequence_id`
      매칭, ABANDONED 응답 폐기, 종료 시 통계 자가 리포트. — STEP ②
- [x] `usb_transport`: libusb open/claim/endpoint, bulk R/W, 단발 프레임 수신 실제
      read 2회, `ncmp_transport_probe` 열거. — STEP ④
      (실제 FX3 하드웨어 브링업/VID·PID·EP 확정은 하드웨어 확보 후.)

### 2.3 Module B — libpkcs11_ncmp.so
- [x] `ncmp_client_init/exec/fini`: IPC 연결·SHM attach, `ncmp_slot_enqueue`/
      `wait` 재사용, 타임아웃(ABANDONED), 응답 디코드. — STEP ③
- [x] `NCMP_ERR_*` → `CKR_*` 매핑(`ncmp_ckr.c`). — STEP ③
- [x] `token_spec_t token_specific` 정의(`usr/lib/ncmp_stdll/tok_struct.h`,
      지정 초기화) + 라이프사이클/리포팅 훅(`ncmp_specific.c`). — STEP ⑤
- [ ] 실제 PKCS#11 `C_*` 암호 연산을 와이어 프로토콜로 포워딩(현재는 crypto
      포인터 NULL → `CKR_MECHANISM_INVALID`). — STEP ⑥

### 2.4 Module C — mock
- [ ] `fx3_dma` Rx/Tx 링 push/pop(16KB 단위·버퍼 수·백프레셔).
- [x] `mcu_scheduler`: 요청 파싱→echo 실행→유효 `ack`/`payload_len` 응답 생성. — STEP ①
- [x] `mock_transport`: open/send/recv 루프백(`ncmp_transport.h` 구현). — STEP ①
- [ ] `mock_main`: 다중 슬롯 device·스레드 구동으로 실제 데몬과 연결.
- [ ] echo 대신 슬롯별 실제 명령 시맨틱(선택) + 컨테이너 동시 점유/백프레셔 경로.

### 2.5 Module D — tests (자리표시 → 실측)
- [ ] `test_mutex_robust`: fork로 소유자 사망 후 `NCMP_MUTEX_RECOVERED` 검증.
- [x] `test_inflight_stats`: 소비자 기동 전 일괄 enqueue → `stats_total_sent_cmds`
      / `stats_max_in_flight`(=max_inflight) 결정론적 실측. — STEP ②
- [x] `test_concurrency`: 4×4 다중 생산자 동시 enqueue, 상관 정확·누수 0,
      30회 반복 + TSan 클린. — STEP ②
- [x] `test_client_roundtrip`: 실 소켓 IPC 핸드셰이크 + exec 왕복 + offline 슬롯
      거부(CKR 매핑). — STEP ③
- [x] `test_ack_error_propagation`: 목 fail-bit 주입 → `rsp.ack` CKR 오류
      surface 확인. — STEP ③

### 2.6 opencryptoki 통합
- [x] `configure.ac`에 `--enable-ncmptok` 토글(기본 off) + `AM_CONDITIONAL` +
      summary echo. — STEP ⑤
- [x] `usr/lib/ncmp_stdll` 디렉터리(tok_struct.h/ncmp_specific.c/ncmp_stdll.mk)
      + `usr/lib/lib.mk` 배선 → `libpkcs11_ncmp.so` 빌드·export. — STEP ⑤
- [x] `Makefile.am` install/uninstall 훅, `opencryptoki.conf` 예시 슬롯(주석). — STEP ⑤
- [ ] 실 환경에서 `pkcsslotd`+`pkcsconf`로 슬롯 인식/초기화 런타임 검증
      (ncmpd 기동 상태 필요).
- [ ] 기본 빌드(--enable-ncmptok 미지정) 무영향 재확인(조건부 배선이라 안전하나
      전체 `make` 1회 회귀 확인 권장).
- [ ] PKCS#11 2.x/3.0/3.2 커버리지 확인.

### 2.6b STEP ⑥ — PKCS#11 연산 포워딩
- [x] command_id opcode 체계(`ncmp_cmd.h`) + 전송 API `ncmp_client_command`. — STEP ⑥
- [x] 첫 연산 RNG 포워딩(`token_specific_rng` + mock 처리 + 테스트). — STEP ⑥
- [x] SHA one-shot digest 포워딩(`t_sha_init`+`t_sha`, mech→size 공유). — STEP ⑦
- [x] 다중버퍼 인프라(`ncmp_msg_pack/param` + `ncmp_client_command_mp`) +
      AES-CBC(`t_aes_cbc`, OBJECT 키 추출, 왕복 검증). — STEP ⑧
- [x] 멀티파트 digest(update/final) + 토큰-측 컨텍스트 핸들. — STEP ⑨
- [x] RSA 서명(비대칭 다중 키 컴포넌트 마샬링) + 슬롯 매핑. — STEP ⑨
- [x] AES 전 모드(ECB/GCM/CTR/OFB/CFB), EC 서명, RSA/EC **검증**,
      **RSA/EC 키페어 생성(템플릿 조작)**, **HMAC(sign/verify)**,
      **RSA-OAEP(enc/dec)**, **키 생성 전종류(AES/DES/3DES/generic-secret)**,
      **RSA-PSS(sign/verify)**, **DH/ECDH 키 합의** 확장. — 연산 확장
- [ ] 나머지 순수 반복: HMAC 멀티파트(update/final), 다이제스트-then-sign
      (RSA/ECDSA with hash), DH/EC 키페어 생성 등. — 후속(패턴 동일)
- [ ] opencryptoki 슬롯 번호 ↔ NCMP 물리 슬롯 매핑(현재 slot 0 고정).
- [ ] 세션/오브젝트 핸들의 토큰-호스트 정합(상태형 연산 대비).

### 2.7 도구/환경
- [ ] 개발환경에 CMake 설치(현재 미설치 → gcc 수동 빌드로 검증 중).
- [ ] `libusb-1.0-0-dev` 정식 설치(현재는 apt-get download로 헤더만 확보해 실
      분기 컴파일 검증). real 빌드 시 필요.
- [ ] CI에서 mock 빌드 + ctest 자동화.

---

## 3. 검증 재현 명령

```bash
# CMake 설치 시(권장)
cd ncmp && cmake -S . -B build -DENABLE_MOCK_TOKEN=ON
cmake --build build -j && ctest --test-dir build --output-on-failure

# CMake 없이(현재 사용한 방식)
cd ncmp && gcc -std=c11 -Wall -Wextra -Wshadow -D_GNU_SOURCE -Iinclude -Itests \
  tests/test_*.c common/ncmp_*.c stdll/ncmp_session.c -lpthread -o /tmp/ncmp_tests \
  && /tmp/ncmp_tests
```

---

## 4. 다음 추천 착수 순서
1. [x] `ncmp_shm_create/attach` + mock 루프백 → 하드웨어 없이 end-to-end 골격. ✅ 완료
2. [x] `comm_thread` 디스패치 루프 + SHM per-entry 버퍼 풀 + in-flight 통계 실측
   (`test_inflight_stats`/`test_concurrency` 실측화). ✅ 완료
3. [x] STDLL `ncmp_client_exec` 왕복: IPC 핸드셰이크 + SHM attach +
   `ncmp_slot_enqueue`/`wait` 재사용, `NCMP_ERR_*`→`CKR_*` 매핑, ACK 오류 전파. ✅ 완료
4. [x] libusb 실전송(`usb_transport.c`, 단발 프레임 수신) + `daemon/main.c`
   라이프사이클 + `ncmp_transport_probe`. mock/real ncmpd 기동·종료 확인. ✅ 완료
5. [x] opencryptoki 통합: `usr/lib/ncmp_stdll/` + autotools `--enable-ncmptok`
   → `libpkcs11_ncmp.so` 실제 빌드·심볼 검증. ✅ 완료
6. [x] PKCS#11 연산 포워딩 프레임워크(opcode + `ncmp_client_command`) + 첫 연산
   RNG(`token_specific_rng`) end-to-end. ✅ 완료
7. [x] SHA one-shot digest 포워딩(다중 파라미터 마샬링 패턴). ✅ 완료
8. [x] 다중버퍼 인프라(`ncmp_client_command_mp`) + AES-CBC(key+iv+data, OBJECT
   키 추출, encrypt∘decrypt 왕복 검증). ✅ 완료
9. [x] 멀티파트 digest(토큰-측 컨텍스트) + RSA 서명(비대칭 다중 키) + 슬롯 매핑.
   ✅ 완료 → **4대 전송 패턴 확립, 소프트웨어 프레임워크 기능 완성**.
10. [ ] **(다음, 하드웨어 필요) 실 FX3 브링업**: `usb_transport.c`의 VID/PID/EP를
   실제 펌웨어 값으로 확정, `ncmpd` 기동 후 `pkcsconf -t`로 슬롯 인식/토큰 정보
   런타임 검증, 실 암호 연산 정합성(진짜 SHA/AES/RSA) 확인. 그 다음 EC/추가 모드
   등 나머지 연산을 기존 패턴대로 확장.

---

## 5. 자체 PKCS#11 프로바이더 계층 (신규, `ncmp/pkcs11/`)

STDLL(new_host 기반) 경로와 별개로, 애플리케이션이 `libpkcs11_ncmp.so`를 직접
로드해 `C_GetFunctionList`로 함수테이블을 얻어 쓰는 **완전 자립형 프로바이더**를
추가. C_* 심볼이 opencryptoki `new_host.c`와 충돌하므로 **독립 빌드 타깃**으로 분리.

### 5.1 구성 파일
- `p11_provider.h` — 내부 상태 타입(세션/객체/opctx/슬롯), 헬퍼 선언.
- `p11_state.c` — 전역 상태·per-process 락·객체/속성 스토어·전송 헬퍼
  (`p11_forward`/`p11_forward_mp`, 왕복 중 락 해제)·에러 매핑.
- `p11_slotmap.c` — CK 슬롯 ↔ 물리 슬롯 매핑(`ncmptok.conf`/`NCMP_SLOT_BASE`).
- `p11_api_general.c` — Initialize/Finalize/GetInfo(+세션 카운터 해제).
- `p11_api_slot.c` — slot·token 관리, mechanism 목록(28종)/정보, InitToken(zeroize).
- `p11_api_session.c` — 세션 관리 + 로그인(슬롯 단위), 상태(CKS_*) 계산.
- `p11_api_object.c` — 객체/find, 가시성(슬롯 단위, private=로그인 필요), 민감속성.
- `p11_api_crypt.c` — enc/dec(AES ECB/CBC/CBC_PAD/CTR/GCM, RSA-OAEP; 2-call 버퍼
  프로토콜, 멀티파트 버퍼링), digest(1shot+멀티파트), sign/verify(RSA/PSS/ECDSA/
  HMAC), dual-function, message-based(단발형 구현·streaming은 미지원 배선).
- `p11_api_key.c` — GenerateKey/KeyPair(RSA·EC)/Wrap/Unwrap/Derive(DH·ECDH)/RNG/
  parallel + 3.2 async·encapsulate 등 미지원 배선.
- `p11_functionlist.c` — `CK_FUNCTION_LIST` 2.40/3.0/3.2 3종 테이블 +
  `C_GetFunctionList`/`GetInterfaceList`/`GetInterface`(이름/버전 매칭).
- `p11_vendor.c` / `ncmp_vendor.h` — `CK_NCMP_VENDOR_FUNCTION_LIST`(콜백 13종).

### 5.2 벤더 opcode/콜백 + 목 지원
- 와이어 opcode 0x0100+: `VD_LOOPBACK/MEM_WRITE/MEM_READ/MEM_FILL/MEM_CRC/PING/
  SELFTEST/FW_INFO`. `mock_device_t`에 4KB vendor 스크래치 RAM + epoch 추가,
  `mcu_scheduler.c`에 실행부 구현.
- 콜백: loopback·mem R/W·fill·crc(토큰 왕복), ping·selftest·fw_info(헬스/식별),
  get_inflight·get_slotmap·set/get_loglevel·host_echo(호스트 인트로스펙션).

### 5.3 동시성/멀티프로세스
- 프로세스 전역 상태는 정적 초기화된 per-process 뮤텍스로 보호. **토큰 왕복 직전
  키 소재를 지역 버퍼로 스냅샷 후 락 해제** → 스레드가 lock-free 전송으로 실제
  동시 실행. 프로세스 간 세션 상한은 SHM robust 카운터(`ncmp_session_open/close`)로
  강제(Finalize에서도 해제). `.so` 다중 로드는 init 상태로 정합.

### 5.4 테스트 (`ncmp/tests/test_pkcs11_api.c`)
- 버전 매핑(2.40/3.0/3.2 테이블·기본 3.2)·벤더 인터페이스 스모크.
- **복합 시나리오 S1~S5**: (1) 멀티스레드 동시성·세션격리, (2) 토큰키 영속+백업/
  복원(파워사이클=Finalize/Initialize, 비추출 개인키·민감속성), (3) RSA-OAEP
  래핑/언래핑+CBC_PAD Update/Final 파이프라인, (4) 예외/권한(ENCRYPT 불가→
  `CKR_KEY_FUNCTION_NOT_PERMITTED`, 잘못된 IV→`CKR_MECHANISM_PARAM_INVALID`,
  세션종료 후 무효화)·복구, (5) 슬롯 스캔+`InitToken` Zeroization.
- **멀티슬롯/멀티세션 M1~M10**: 세션상한(8/슬롯), 슬롯별 RNG, 라운드로빈 AES,
  슬롯 간 객체격리, 동시 키생성, 세션 간 객체공유, 동시 멀티파트 다이제스트,
  로그인 격리, 동시 sign/verify, 시스템 세션상한(32)+CloseAllSessions.
- 결과: **49/49 통과, ThreadSanitizer 0 races**(`setarch -R` + 재빌드).

### 5.5 슬롯정보 정합
`opencryptoki.conf`의 슬롯번호(예 slot 5)와 ncmpd 물리 슬롯(0..3) 불일치를
`ncmptok.conf`(`<ck_slot> <phys> [label]`) 또는 `NCMP_SLOT_BASE`로 매핑. 온라인
물리 슬롯만 `C_GetSlotList`에 노출. 예시 conf 및 opencryptoki.conf 주석 정합화.

### 5.6 빌드 배선
- CMake: `ncmp/pkcs11/CMakeLists.txt`(shared `pkcs11_ncmp`), `ncmp/stdll`는
  재사용 전송 static lib(`ncmp_stdll_client`)로 전환, 상위 CMake에 PIC +
  `add_subdirectory(pkcs11)`, tests에 프로바이더/테스트 추가.
- 자립형 프로바이더는 opencryptoki `usr/include`(PKCS#11 헤더)만 의존.

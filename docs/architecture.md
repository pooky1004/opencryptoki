# Token NCMP 아키텍처

opencryptoki 사설 포크에 추가되는 신규 PKCS#11 토큰 **Token NCMP**의 상세
설계 문서입니다. 요약/규칙은 루트 `CLAUDE.md`, 문서 색인은 `docs/INDEX.md`를
참고하세요. 모든 식별자·코드·주석은 영어, 설명 서술은 한국어로 작성합니다.

---

## 1. 시스템 개요

Token NCMP는 Cypress EZ-USB FX3(CYUSB3KIT-003) 보드를 USB로 연결한 물리
토큰이며 `libusb`로 접근합니다. 여러 프로세스의 여러 스레드가 **단일 USB
링크**를 동시에 공유해야 하므로, 이를 다중화하는 독립 데몬 `ncmpd`를 둡니다.

> `ncmpd`는 `pkcsslotd`의 대체물이나 훅이 **아닙니다**. 별도의 파이프/프록시
> 멀티플렉서로서, `pkcsslotd`와 무관하게 동작합니다.

```
 App proc 1                 App proc 2
 ┌───────────────┐          ┌───────────────┐
 │ thread…thread │          │ thread…thread │
 │ libpkcs11_ncmp│          │ libpkcs11_ncmp│   (Module B, STDLL)
 └──────┬────────┘          └──────┬────────┘
        │ UNIX socket (control)    │
        │ + POSIX SHM (bulk)       │
        ▼                          ▼
 ┌──────────────────────────────────────────┐
 │  ncmpd  (Module A, system daemon)         │
 │   conn_thread ×1   comm_thread ×N(≤4)     │
 │   SHM: slots[4] + rings + stats           │
 └───────────────┬──────────────────────────┘
                 │ libusb bulk IN/OUT
                 ▼
   Token NCMP (FX3)  ── 또는 ──  mock_token_ncmp (Module C)
```

기동 순서: **`ncmpd` 먼저 실행 → 그 다음 STDLL 로드**. 데몬이 없으면 STDLL은
`NCMP_ERR_NODAEMON`을 받고 `CKR_TOKEN_NOT_PRESENT`로 매핑합니다.

---

## 2. 디렉터리 구조와 모듈 역할

| 경로 | 역할 |
|------|------|
| `ncmp/include/ncmp/` | 모든 타깃이 공유하는 공개 헤더(한계값, 와이어, 큐, SHM, 뮤텍스, IPC, 에러) |
| `ncmp/common/` | 공유 구현: robust mutex 래퍼, CAS 큐, 와이어 인코딩, SHM 생성/부착 |
| `ncmp/daemon/` | **Module A** `ncmpd`: `conn_thread`, per-slot `comm_thread`, `usb_transport` |
| `ncmp/stdll/` | **Module B** `libpkcs11_ncmp.so`: 토큰 SPI, 클라이언트 전송, 세션 관리 |
| `ncmp/mock/` | **Module C** `mock_token_ncmp`: FX3 DMA·컨테이너·MCU 에뮬레이터 |
| `ncmp/tests/` | **Module D** C 테스트 스위트(ctest) |
| `ncmp/cmake/` | `FindLibUSB.cmake` 등 빌드 보조 |

---

## 3. 자원 한계 (STRICT)

`ncmp/include/ncmp/ncmp_limits.h`에 단일 정의합니다.

- 슬롯/토큰 최대 `PKCS11_MAX_SLOT_COUNT = 4`
- 슬롯당 세션 최대 `PKCS11_MAX_SESSION_PER_SLOT = 8`
- 시스템 총 세션 `PKCS11_MAX_TOTAL_SESSIONS = 32` (4 × 8)
- 파라미터 개별 ≤ 32 KB, 결합 페이로드(길이 배열 + 파라미터) ≤ 40 KB
- 슬롯 in-flight 상한 기본값 = 장치 SRAM 컨테이너 수(4)

---

## 4. 하드웨어 / FX3 데이터패스

- **Rx DMA (Device→Host)**: 16 KB × 4 = 64 KB
- **Tx DMA (Host→Device)**: 16 KB × 8 = 128 KB
- **내부 컨테이너**: 64 KB × 4 (SRAM)
- **Mover**: 인입 페이로드의 선행 4바이트(길이)를 읽어 비어있는 컨테이너에
  기록. 4개가 모두 차면 하나가 비워질 때까지 정지.
- **MCU 스케줄러**: 컨테이너를 **Round-Robin**으로 처리, 응답을 Rx DMA로 반환.

호스트의 slot in-flight 상한을 컨테이너 수(4)로 잡으면, Mover가 감당 못 할
양을 절대 밀어내지 않습니다. `mock_token_ncmp`가 이 데이터패스를 그대로
모사하여 하드웨어 없이 개발/테스트가 가능합니다.

---

## 5. 와이어 패킷 프로토콜 (4바이트 정렬, little-endian)

```
+-------------------------------------------------------------+
| frame_len (4B)  : 이 필드를 제외한 전체 길이                 |
+-------------------------------------------------------------+
| NCMP_Header (20B):                                          |
|   session_id, sequence_id, command_id, ack, payload_len     |
+-------------------------------------------------------------+
| param_len[8] (32B)  : 파라미터별 길이 배열                   |
| payload             : param 1..8 연접 (len 0 = 생략)         |
+-------------------------------------------------------------+
```

- `ack`는 요청·응답 양방향에서 `CKR_*` 상태를 전달합니다.
- 불변식: `frame_len == 20 + payload_len`,
  `payload_len == 32 + Σ param_len[i]`.
- **2단계 수신**(`usb_transport_recv`): ① 고정 헤더를 읽고 ② `payload_len`을
  파싱한 뒤 정확히 그만큼 재수신하여 조립. USB 패킷 경계와 무관하게 프레이밍을
  보장합니다.
- 헤더/구조체 정의는 `ncmp/include/ncmp/ncmp_wire.h`.

---

## 6. 공유 메모리(SHM) 설계 — 주소 독립성

프로세스마다 매핑 주소가 다르므로 **SHM 안에는 원시 포인터를 저장하지 않습니다**.
모든 내부 참조는 배열 인덱스 또는 SHM 베이스로부터의 바이트 오프셋이며,
`ncmp_shm_ptr(base, off)`로 지역 주소로 변환합니다.

레이아웃(`ncmp_shm.h`): `NCMP_ShmHeader`(magic/version/global_lock) → `NCMP_Slot
slots[4]`. 각 `NCMP_Slot`은 `state`, `max_inflight`, `sess_lock`,
`cur_sessions`, `NCMP_SlotStats`, MPSC 링 `ring[NCMP_QUEUE_DEPTH]`, 그리고
슬롯별 스크래치 버퍼 풀 오프셋(`buf_pool_off/len`)을 가집니다.

---

## 7. 동시성 모델

### 7.1 MPSC 명령 큐 (슬롯 락 없음)
여러 애플리케이션 스레드가 **슬롯 단위 블로킹 락 없이** 같은 슬롯 링에 명령을
넣습니다. 유일한 소비자는 해당 슬롯의 `comm_thread`입니다. 엔트리 상태 전이는
반드시 CAS(`__atomic_compare_exchange_n`, 래퍼 `ncmp_qentry_cas`)로만:

```
FREE → CLAIMED → POSTED → SENT → DONE → FREE      (정상)
                          SENT → ABANDONED → FREE  (타임아웃)
```

- 생산자: `ncmp_queue_claim`(FREE→CLAIMED) → 요청 기록 → `ncmp_queue_post`
  (CLAIMED→POSTED).
- 소비자: POSTED→SENT 후 USB 송신, 응답 수신 시 SENT→DONE, 대기 클라이언트는
  자신의 엔트리가 DONE이 되는지 폴링(“waiting queue”는 DONE 관점의 뷰).
- 타임아웃 시 SENT→ABANDONED로 전환하고 늦게 온 응답은 폐기합니다.

### 7.2 Robust 프로세스 공유 뮤텍스
모든 SHM 뮤텍스는 `PTHREAD_PROCESS_SHARED` + `PTHREAD_MUTEX_ROBUST`. **직접
`pthread_mutex_lock/unlock` 호출 금지.** `ncmp_mutex_lock/unlock`만 사용하며,
소유자 사망 시 `EOWNERDEAD`를 감지해 `pthread_mutex_consistent()`로 복구 후
`NCMP_MUTEX_RECOVERED`를 반환합니다.

### 7.3 세션 카운터 보호
`cur_sessions`는 오직 `sess_lock` 임계구역 안에서만 증감합니다(원시 atomic으로
대체 금지). 상한 도달 시 `CKR_SESSION_COUNT_EXCEEDED`. 구현은
`ncmp/stdll/ncmp_session.c`.

### 7.4 비동기 시그널 안전성
시그널 핸들러는 `volatile sig_atomic_t g_running` 플래그만 조작합니다.
`printf/malloc`·뮤텍스 획득 금지. in-flight/성능 요약은 각 스레드가 자신의
처리 루프를 빠져나오며 개별 출력합니다.

---

## 8. In-flight 추적 & 통계 (슬롯별, SHM)

`comm_thread`가 USB 송신 **직전**에 갱신합니다:

- `in_flight_cnt` — 토큰 내부에서 처리 중인 명령 수. 송신 전
  `in_flight_cnt < slot->max_inflight` 확인, 디스패치 시 +1, 응답 수신 시 −1.
- `stats_max_in_flight` — `in_flight_cnt`의 역대 최대치.
- `stats_total_sent_cmds` — 토큰으로 전송한 누적 명령 수.

`comm_thread`는 단일 소비자이므로 통계 필드는 평문 갱신이 안전하며,
`in_flight_cnt`는 클라이언트도 읽으므로 원자적으로 증감합니다.

---

## 9. 데이터 흐름 (요청 1건)

1. STDLL: `ncmp_wire_validate_params`(≤32KB/≤40KB) → 요청 인코딩.
2. `ncmp_queue_claim` → 엔트리의 `req_off` 버퍼에 프레임 기록 →
   `ncmp_queue_post`.
3. `comm_thread`: POSTED 발견 → SENT 전이 → in-flight 예약(통계 갱신) →
   `usb_transport_send`.
4. `usb_transport_recv` 2단계 수신 → `sequence_id`로 엔트리 매칭 → in-flight
   해제 → `rsp_off`에 응답+`ack` 기록 → DONE 전이.
5. STDLL: 엔트리 DONE 관측 → 응답 디코드 → `ack`(CKR_*) 반환 → DONE→FREE.

---

## 10. 빌드 & 테스트

```bash
cd ncmp && cmake -S . -B build -DENABLE_MOCK_TOKEN=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

- `ENABLE_MOCK_TOKEN=ON`이면 Module C를 빌드하고 데몬 전송을 목 루프백으로
  전환(`NCMP_USE_MOCK_TRANSPORT`). OFF면 libusb-1.0을 요구합니다.
- 테스트 커버리지(Module D): 와이어 경계값, CAS 큐 전이, 세션 상한,
  robust mutex 크래시 복구, in-flight 통계, 멀티스레드 동시성, 2단계 수신,
  ACK 오류 전파.

---

## 11. opencryptoki 통합 (후속)

현재 `ncmp/` 서브트리는 자체 CMake로 독립 빌드됩니다. 실제 opencryptoki
로더(API 계층)에 연결하려면:

1. STDLL이 `token_spec_t token_specific`를 export (다른 토큰의
   `tok_struct.h` 패턴 참조; 골격은 `ncmp/stdll/ncmp_specific.c`,
   `ncmp/stdll/tok_struct.h`).
2. autotools에 `--enable-ncmptok` 토글과 `usr/lib/ncmp_stdll` 디렉터리를 추가
   (`configure.ac`의 `--enable-swtok` 패턴 참조).
3. 토큰 등록 및 `pkcsconf`/슬롯 설정 반영.

---

## 12. 에러 코드 규약

전송 계층 내부 오류는 음수 `NCMP_ERR_*`(`ncmp_errno.h`)를 사용하고, STDLL이
PKCS#11 경계에서 `CKR_*`로 매핑합니다. 토큰의 `ack` 필드는 항상 `CKR_*`를
전달합니다(내부 코드가 아님).

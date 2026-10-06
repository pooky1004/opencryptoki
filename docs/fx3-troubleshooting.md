# FX3 실 타겟 연동 문제 분석 및 조치 (Token NCMP)

작성일: 2026-10-06 · 대상: Cypress EZ-USB FX3 (CYUSB3KIT-003) + `ncmpd` 실 타겟 경로

이 문서는 `--transport real`(libusb) 경로로 실제 FX3 보드와 연동하는 과정에서
발생한 문제들, 각 문제의 **증상 → 근본 원인 → 조치 → 검증**을 상세히 정리한다.
배경 설계는 [`architecture.md`](architecture.md), 세션 ID 매핑은
[`session-id-mapping.md`](session-id-mapping.md), 와이어 프로토콜은
`ncmp/include/ncmp/ncmp_wire.h`를 참고한다.

> 결론 요약: "수신부(RX)가 항상 비어 있다"는 최종 증상은 USB 전송 자체의 문제가
> 아니라 **OPEN_SESSION 파라미터 레이아웃 불일치**(토큰이 `ack=0x7`로 거절)가
> 주원인이었다. 그 이전 단계에서 USB Slave-FIFO 버스 턴어라운드 처리 누락과
> 부팅 probe 잡음도 함께 해결했다. 모든 조치 후 실 FX3에서
> OpenSession→Login→GenerateRandom→Logout 전 구간이 정상 동작함을 확인했다.

---

## 0. 환경

| 항목 | 값 |
|------|-----|
| 보드 | Cypress EZ-USB FX3 (CYUSB3KIT-003), Slave-FIFO sync(GPIF) 펌웨어 |
| USB ID | VID `0x04B4`, PID `0x00F1`(CI 앱 펌웨어) / `0x00F3`(부트로더) |
| 엔드포인트 | 인터페이스 0, bulk OUT `0x01`, bulk IN `0x81` |
| 전송 | `libusb-1.0` `libusb_bulk_transfer`, 타임아웃 5000 ms |
| 데몬 | `ncmpd --transport real`, 제어 소켓 `NCMP_SOCK_PATH`(=`/tmp/ncmpd.sock`) |
| 레퍼런스 | `/home/pooky/bang/2026-10-01_1615_GETMECHLIST_AES_GCM`<br>(동작하는 Python 구현 `host/web_ui/fx3_ci.py`, `server.py`, `capabilities.py`) |

구현 위치: `ncmp/daemon/usb_transport.c`(USB 물리 전송),
`ncmp/daemon/comm_thread.c`(세션 변환/디스패치),
`ncmp/daemon/main.c`(부팅/슬롯 기동), `usr/lib/ncmp_stdll/ncmp_p11.c`(STDLL facade).

---

## 1. 문제 #1 — FX3 Slave-FIFO 버스 턴어라운드 누락 (RX 공백 / 타임아웃)

### 증상
- 실 타겟에 명령을 보내면 OUT(송신)은 `rc=0`로 성공하지만 IN(수신)은 항상
  0바이트로, 5초 뒤 `ack=0x50`(타임아웃) 처리됨. Debug App의 comm↔HSM 뷰에서
  **수신부가 영구 공백**.
- 동일 보드가 레퍼런스 Python(`start-test-web.sh`, 브라우저 `127.0.0.1:8080`)에서는
  정상적으로 요청/응답을 주고받음.

### 근본 원인
FX3의 Slave-FIFO sync(GPIF) 경로에는 알려진 버스 턴어라운드 특성이 있다.
디바이스→호스트(P-to-U) 방향 응답은, **그 다음 호스트→디바이스(U-to-P) 전송이
버스 방향을 되돌릴 때 비로소 커밋**된다. 즉, 요청만 보내고 바로 IN을 읽으면
응답이 아직 FIFO로 밀려나오지 않아 0바이트가 돌아온다. 또한 GPIF 버스가 32비트라
프레임은 **4바이트 정렬**이 필요하다. 초기 `usb_transport.c`에는 이 처리가 없었다.

레퍼런스 `host/web_ui/fx3_ci.py`가 `exchange()`에서
`_write_frame()` 후 `_send_trigger()`(NOP OUT)를 보내고 IN을 flush-read 하는
구조로 이 문제를 우회하고 있었다.

### 조치 (`ncmp/daemon/usb_transport.c` 재작성)
레퍼런스 동작을 그대로 반영했다.
- **NOP 트리거**: 매 요청 OUT 뒤에 56바이트 NOP 프레임(`command_id=0`,
  파라미터 없음)을 OUT으로 보내 버스를 되돌려 응답을 커밋시킨다
  (`fx3_build_nop`, `fx3_send_trigger`). 상수 `FX3_NOP_FRAME_LEN = 56`
  (`4 + 20 + 32`, 이미 4바이트 정렬).
- **4바이트 정렬 패딩**: 송신 프레임을 4바이트 경계로 패딩(`txpad` 버퍼),
  프레임 파싱 시 물리 길이 `physical = (total + 3) & ~3`로 계산.
- **인터프레임 가드**: OUT 후 `FX3_GUARD_NS = 5 ms` 대기(`next_out_ns`로
  다음 OUT의 최소 시작 시각을 관리) — 응답 커밋/쿨다운 보장.
- **IN flush-read 루프**: 수신 시 `fx3_drain_in`으로 누적 버퍼(`rx`,
  `FX3_RX_CAP = 2 × NCMP_MAX_FRAME_SIZE`)에 모은 뒤 `fx3_extract`로 프레임을
  파싱. 빈 타임아웃이면 트리거를 재전송하며 `flush_limit = 3 + 5000/200`회까지
  재시도.
- **NOP 응답 폐기**: 수신 스트림에서 `command_id == 0`(NOP 트리거 응답)
  프레임은 버리고 첫 비-NOP 프레임을 반환(`fx3_extract`).

관련 상수/필드:
```c
#define FX3_GUARD_NS   5000000ull   /* 5 ms 인터프레임 가드 */
#define FX3_OUT_CHUNK_MS 50         /* OUT 중 IN 서비스 주기 */
#define FX3_RX_CAP   (2u * NCMP_MAX_FRAME_SIZE)
#define FX3_NOP_FRAME_LEN 56u
/* struct: uint8_t *rx; size_t rx_len; uint8_t *txpad;
          uint32_t trig_seq; uint64_t next_out_ns; */
```

### 검증
단독으로는 다음 문제(#3)에 가려 완전 검증이 안 됐으나, FX3 재연결 후
`VD_PING`이 `ack=0xB3`를 6.5 ms에 반환 → **RX 경로 자체는 정상 동작 확인**.

---

## 2. 문제 #2 — 디바이스 wedge (OUT `rc=-7`)

### 증상
어느 시점부터 우리 코드뿐 아니라 **레퍼런스 Python도** OUT에서
`rc=-7`(LIBUSB_ERROR_TIMEOUT)로 실패. 즉 코드 문제가 아니라 보드 상태 문제.

### 근본 원인
FX3가 이전 세션 잔여 상태로 FIFO/엔드포인트가 멈춘(wedged) 상태.

### 조치
- **USB 리셋 복구**: `usb_open()`에서 `libusb_claim_interface` 직후
  `libusb_reset_device()` 성공 시 인터페이스를 재-claim 하도록 추가
  (`usb_transport.c`).
- 운영상으로는 **보드 재연결(re-plug)** 로 복구. 재연결 후 `VD_PING ack=0xB3`로
  정상 복귀 확인.

---

## 3. 문제 #3 — OPEN_SESSION 파라미터 레이아웃 불일치 (★ RX 공백의 주원인)

### 증상
USB 경로가 살아난 뒤에도 `C_OpenSession`이 `ack=0x7`
(`CKR_ARGUMENTS_BAD`)로 거절됨 → 세션이 안 열려 이후 어떤 명령도 성공하지
못하고, 결과적으로 **수신부가 계속 비어 보임**.

### 근본 원인
세션 ID 매핑 설계([`session-id-mapping.md`](session-id-mapping.md))에서 STDLL이
OPEN을 `[pid, app_sid, flags]` **3-파라미터**로 올려보내고, `ncmpd`가 이를
그대로 토큰에 전달했다. 그러나 실제 펌웨어는 OPEN_SESSION을 **단일
`param0 = flags`, 헤더 `session_id = 0`** 형태로만 받는다.

레퍼런스로 확정:
- `host/web_ui/server.py:115` — `build_message(0, seq, CI_CMD_OPEN_SESSION, (struct.pack("<I", 4),))`
- `host/web_ui/capabilities.py:44` — 요청 `param0=flags` → 응답 `param0=session_id`

즉 `(pid, app_sid)` 조합은 **ncmpd 내부 매핑용**이지 토큰 와이어로 내려가면
안 되는 값이었다.

### 조치
토큰으로 나가는 프레임만 단일 `[flags]`로 재조립하되, `(pid, app_sid)`는
응답 매핑을 위해 **원본 요청 버퍼에 보존**한다.

- `ncmp/daemon/comm_thread.c` `sess_xform_request()` OPEN 분기:
  ```c
  if (op == NCMP_CMD_OPEN_SESSION) {
      /* 호스트 요청 = [pid, app_sid, flags]; 토큰은 단일 [flags]만 기대.
       * app_sid는 원본 요청 버퍼에 남아 sess_apply_response()가
       * (pid, app_sid)->hsm_sid 매핑 키로 사용한다. */
      const uint8_t *pf; uint32_t lf, flags = 0;
      if (ncmp_msg_param(&m, 2, &pf, &lf) == NCMP_OK && lf >= 4)
          flags = ncmp_rd_u32le(pf);
      ncmp_wr_u32le(pay, flags);
      m.param_len[0] = 4;
      for (int i = 1; i < NCMP_MAX_PARAM_COUNT; ++i) m.param_len[i] = 0;
      m.header.session_id = 0;
      *out_sent_sid = 0;
      if (ncmp_wire_encode(&m, txbuf, txcap, out_len) != NCMP_OK) return 0;
      return 1;
  }
  ```
- `sess_apply_response()`: OPEN 응답이 OK면 `map[(pid, app_sid)] = hsm_sid`
  (응답 `param0`)로 저장. 이후 모든 명령은 헤더의 `app_sid`를
  `ncmp_sess_map_lookup`으로 `hsm_sid`로 치환해 토큰에 전달. CLOSE는
  `hsm_sid` 기준으로 매핑 제거.
- `ncmp/mock/mcu_scheduler.c` OPEN_SESSION 핸들러: `param0`에서 flags를 읽도록
  복원(ncmpd가 단일 `[flags]`를 보내므로 mock도 동일 규약으로 통일).

### 검증
실 FX3(`04b4:00f1`)에서 standalone p11 facade로 전 구간 성공:
```
C_GetFunctionList rv=0x0
C_Initialize      rv=0x0
C_GetSlotList     rv=0x0  n=1  slot[0]=0
C_OpenSession     rv=0x0  handle=1      ← 이전 0x7 해소
C_Login(User)     rv=0x0                ← PIN 12345678
C_GenerateRandom  rv=0x0  bytes=ea654a38aa01f67e42daa87ae46585b0  ← 실 토큰 RNG
C_Logout          rv=0x0
C_CloseSession    rv=0x0
C_Finalize        rv=0x0
```
USB 교환 로그(`NCMP_USB_DEBUG=1`), 전부 `rc=0`:

| 단계 | OUT | IN | 해석 |
|------|-----|-----|------|
| OPEN_SESSION | 60 B | 60 B | `4+20+32+4`(flags) / 응답 `param0=hsm_sid` |
| Login | 72 B | 56 B | PIN 포함 요청 / ack 응답 |
| GenerateRandom | 60 B | 72 B | 길이 요청 / 16 B 랜덤 응답 |
| Logout/Close | 56 B | 56 B | ack 응답 |

Login/Random/Logout가 `app_sid→hsm_sid` 치환으로 성공했다는 사실 자체가
**ncmpd 세션맵이 정상적으로 채워졌음**을 입증한다(미매핑이면 거절됨).

---

## 4. 문제 #4 — 부팅 시 TOKEN_INFO probe 잡음

### 증상
Debug App의 comm↔HSM 송신부가 **항상 TOKEN_INFO** 로 고정되고 수신부는 비어
보임(토큰이 아직 응답 못 하는 상태에서 부팅 probe가 TX만 남김).

### 근본 원인
`ncmpd`가 부팅 시 세션 없이 `NCMP_CMD_VD_TOKEN_INFO`로 토큰 신원을 조회하던
probe가, 응답 불가 상태에서는 TX만 남기고 RX 공백을 유발.

### 조치
`ncmp/daemon/main.c`의 부팅 probe 호출을 주석 처리하고 함수를 `#if 0`으로 비활성화.
토큰 신원은 이후 세션 내 조회로 대체. CK-슬롯 바인딩은 신원 확인 전까지
first-free 폴백. (Debug App 매뉴얼
[`debugapp-manual.md`](debugapp-manual.md) §4.5에 반영.)

---

## 5. 부수 조치 (관찰성/안정성)

- **단일 인스턴스 락**: `ncmpd`는 시스템 전체에 하나만 떠야 하므로
  `ncmpd_single_instance_lock()`(`/tmp/ncmpd.lock`, `flock`, `NCMP_LOCK_PATH`로
  override) 추가. 중복 기동 시 거절.
- **실 백엔드 직렬화**: FX3 Slave-FIFO는 요청/응답 1건씩만 처리 가능하므로
  `main.c`에서 실 백엔드일 때 `slot->max_inflight = 1`로 직렬화(mock/socket은
  파이프라인 기본 유지).
- **5초 타임아웃**: `comm_thread`의 미회수 명령 타임아웃을 5초로 설정
  (`comm_reap_timeouts`), 타임아웃 시 `SENT → ABANDONED`.
- **comm↔HSM 마지막 메시지 캡처**: SHM `NCMP_LastMsg`에 슬롯별 마지막 TX/RX
  프레임을 기록(`ncmp_slot_lastmsg_tx/rx`). 송신은 실패해도 기록, 수신은 응답
  수신 시 기록. Debug App이 raw(Hex)+parsed로 표시(파라미터당 1024 B 표시 상한).
- **디버그 로깅**: `NCMP_USB_DEBUG=1`이면 `usb_transport.c`가 OUT/IN 바이트 수,
  `rc`, `rx_pending`, 재시도 횟수를 stderr로 출력.

---

## 6. 우리 구현 ↔ 레퍼런스 대응표

| 항목 | 레퍼런스 `fx3_ci.py` 외 | 우리 구현 |
|------|------------------------|-----------|
| 요청 후 트리거 | `_send_trigger()` NOP OUT | `fx3_send_trigger()` 56 B NOP |
| 4바이트 정렬 | `_write_frame` 패딩 | `txpad` 패딩 + `(total+3)&~3` |
| IN 읽기 | flush-read 재시도 | `fx3_drain_in` + `flush_limit` 루프 |
| NOP 응답 | 폐기 | `command_id==0` 폐기 |
| OPEN_SESSION | `build_message(0,seq,OPEN,(flags,))` | `sess_xform_request` 단일 `[flags]`, 헤더 sid=0 |
| 세션 동시성 | 1건씩 | `max_inflight = 1` |

---

## 7. 재현/점검 절차

```bash
# 1) 빌드 (mock 포함 유닛테스트)
cd ncmp && cmake -S . -B build -DENABLE_MOCK_TOKEN=ON && cmake --build build -j
ctest --test-dir build --output-on-failure        # test_session_map 포함

# 2) standalone p11 facade 빌드
bash ncmp/gui/build_standalone_p11.sh

# 3) 실 타겟으로 데몬 기동 (FX3 연결 상태, 04b4:00f1)
NCMP_USB_DEBUG=1 NCMP_SOCK_PATH=/tmp/ncmpd.sock \
  ncmp/gui/build-standalone/ncmpd --transport real

# 4) OpenSession→Login→Random 확인 (별도 하네스 또는 Web Test App)
#    기대: 모든 rv=0x0, GenerateRandom이 실제 랜덤 16B 반환
```

점검 포인트:
- USB 로그가 OUT/IN 모두 `rc=0`, IN `transferred > 0`인지.
- `C_OpenSession`이 `0x7`이 아니라 `0x0`인지(파라미터 레이아웃).
- Debug App comm↔HSM 뷰에 TX/RX가 모두 표시되는지.
- 보드 wedge(OUT `rc=-7`) 시 재연결 또는 `libusb_reset_device` 복구.

---

## 8. 변경 파일 요약

| 파일 | 변경 |
|------|------|
| `ncmp/daemon/usb_transport.c` | FX3 버스 턴어라운드(NOP 트리거/4B 패딩/IN flush/가드), `libusb_reset_device` 복구, 디버그 로깅 |
| `ncmp/daemon/comm_thread.c` | OPEN 단일 `[flags]` 재조립, `(pid,app_sid)→hsm_sid` 매핑, 5초 타임아웃, 마지막 메시지 캡처 |
| `ncmp/daemon/main.c` | 부팅 probe 비활성화, 단일 인스턴스 락, 실 백엔드 `max_inflight=1` |
| `ncmp/mock/mcu_scheduler.c` | OPEN `param0=flags` 규약 통일 |
| `ncmp/common/ncmp_slot.c` · `ncmp/include/ncmp/ncmp_shm.h` | `NCMP_SessMap`, `NCMP_LastMsg`, SHM 버전 상향 |
| `usr/lib/ncmp_stdll/ncmp_p11.c` | `app_sid` 생성, OPEN 시 `[pid,app_sid,flags]` 전송 |

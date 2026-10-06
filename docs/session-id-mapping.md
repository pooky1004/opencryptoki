# 세션 ID 매핑

> **갱신(2026-10-06): `(pid, app_sid) → hsm_sid` 매핑을 ncmpd에 구현했다.**
> 2026-10-05의 "단순 핸들" 노트를 대체한다(원래 (pid+sid)→HSM SID 설계를 재채택,
> app_sid는 OPEN의 param1에 실음).
>
> - **OPEN_SESSION = 0x0020**: App(STDLL) 요청 — 와이어 헤더 `session_id = 0`,
>   파라미터 `[pid, app_sid, flags]`. app_sid는 **앱이 고르는 세션 식별자**(facade
>   의 `g_next_app_sid` 단조 증가). ncmpd는 enqueue한 **pid를 큐 엔트리에 기록**하고,
>   토큰으로 보낼 때 **param1(sid)=0**으로 바꿔 보낸다(토큰이 새 세션 할당). 토큰
>   응답 — **param0 = hsm_sid**. ncmpd는 슬롯 SHM의 `sess_map[(pid, app_sid)] =
>   hsm_sid`(`NCMP_SessMap`)에 저장한다.
> - **이후 모든 명령**: 와이어 헤더 `session_id = app_sid`로 도착하면 ncmpd가
>   `(pid, app_sid) → hsm_sid`로 **헤더 session_id를 치환**해 토큰에 보낸다(그리고
>   보낸 hsm_sid로 응답을 상관). LOGIN=0x0030 등 모든 opcode 동일.
> - **CLOSE_SESSION = 0x0021**: 헤더 `session_id = app_sid` → hsm_sid로 치환,
>   성공 시 매핑 제거.
>
> 구현: `ncmp_cmd.h`(opcode/레이아웃), `ncmp_shm.h`(`NCMP_SessMap`+슬롯 테이블,
> SHM v3), `ncmp_queue.h`(`NCMP_QEntry.pid`), `ncmp/common/ncmp_slot.c`
> (`ncmp_sess_map_*` + enqueue pid), `ncmp/stdll/ncmp_client.c`(pid 기록),
> `ncmp/daemon/comm_thread.c`(`sess_xform_request`/`sess_apply_response` 변환),
> `ncmp/stdll/ncmp_admin.c`(`ncmp_admin_open_session`=[pid,app_sid,flags]),
> `usr/lib/ncmp_stdll/ncmp_p11.c`(app_sid 생성·`dev_sid`), `ncmp/mock/mcu_scheduler.c`
> (OPEN flags=param2, hsm_sid 반환). 테스트 `ncmp/tests/test_session_map.c`.
> GUI 표시: `ncmp_web`의 `POST /api/sessmap`(SHM `sess_map` 조회) + 세션 관리 탭의
> "토큰 세션 맵" 표. 아래 원문은 상세 설계 기록이다.

---

## (과거 설계) (PID + SID) → HSM SID

OpenSession/CloseSession CI와, 요청 프로세스의 `(pid, sid)` 쌍을 토큰 측 8비트
세션 id(**HSM SID**, 1~255)로 매핑하는 규칙을 정의한다.

- 관련: [`command-interface.md`](command-interface.md) §6.3.9/6.3.10,
  [`architecture.md`](architecture.md), [`session-state-management.md`](session-state-management.md)

## 1. 목적

호스트는 명령을 와이어 헤더의 `session_id`로 구분한다. 토큰은 자원이 제한되어 세션을
**8비트(1~255)** 로 식별하려 한다. 그런데 호스트의 세션 식별자는 넓다:

```
호스트 측 식별:  pid (32비트)  +  sid (32비트)      ← 다중 프로세스·다중 세션
토큰 측 식별:    HSM SID (8비트, 1~255)             ← 슬롯 내 유일, 중첩 금지
```

OpenSession 명령이 들어오면 토큰이 `(pid, sid)` → `HSM SID` 매핑을 **생성·저장·관리**
하고, HSM SID를 반환한다. 이후 그 세션의 모든 명령은 이 HSM SID를 `session_id`로 쓴다.

## 2. 범위·소유 결정

| 항목 | 결정 |
|------|------|
| HSM SID 범위 | **슬롯별** 1~255 (슬롯마다 독립 테이블) |
| 소유 주체 | **토큰**(mock/펌웨어)이 슬롯별 세션 테이블 소유·발급 |
| 유일성 | 슬롯 내에서 HSM SID 중첩 없음(collision-free) |
| 재요청 | 같은 `(pid, sid)`는 **멱등** — 기존 HSM SID 반환 |
| 최대 세션 | 슬롯당 255(테이블 포화 시 `CKR_SESSION_COUNT`) |

> 슬롯별 범위이므로 서로 다른 슬롯은 같은 HSM SID 값을 독립적으로 가질 수 있다. 전역
> 유일이 필요하면 `(slot, hsm_sid)` 조합으로 식별한다.

## 3. 매핑 규칙

### 3.1 할당 (OPEN_SESSION)
1. 슬롯 세션 테이블에서 `(pid, sid)`가 이미 있으면 그 **HSM SID를 그대로 반환**(멱등).
2. 없으면 **가장 낮은 빈 인덱스**를 찾아 `(pid, sid, flags)`를 저장하고
   **HSM SID = 인덱스 + 1** (1~255)을 반환.
3. 빈 자리가 없으면 `CKR_SESSION_COUNT`.

인덱스+1을 쓰므로 HSM SID는 0이 되지 않고, 살아있는 세션끼리 절대 겹치지 않는다.

### 3.2 해제 (CLOSE_SESSION)
- `HSM SID`로 테이블 항목을 찾아 지운다(인덱스 = `hsm_sid - 1`). 해당 자리는 이후
  재사용 가능. 없는/이미 닫힌 SID는 `CKR_SESSION_HANDLE_INVALID`.

### 3.3 와이어 레이아웃
```
OPEN_SESSION  (0x003A):  req [pid(u32) | sid(u32) | flags(u32)]
                         rsp [hsm_sid(u32, 1..255)]           ack: CKR_OK / CKR_SESSION_COUNT
CLOSE_SESSION (0x003B):  req [hsm_sid(u32)]
                         rsp (없음)                           ack: CKR_OK / CKR_SESSION_HANDLE_INVALID
```

## 4. 구현 (현재)

- **토큰(mock)**: `mock_device_t.sessions[NCMP_MOCK_SESSION_MAX=255]`
  (`ncmp/mock/mock_token_ncmp.h`). 핸들러는 `ncmp/mock/mcu_scheduler.c`의
  `NCMP_CMD_OPEN_SESSION`/`CLOSE_SESSION` 케이스. Reset 시 세션 테이블도 초기화.
- **CI opcode**: `ncmp/include/ncmp/ncmp_cmd.h` (`NCMP_CMD_OPEN_SESSION`=0x003A,
  `NCMP_CMD_CLOSE_SESSION`=0x003B).
- **클라이언트(테스트)**: `ncmp/gui/py/ncmp_gui/ci.py`의 `open_session(pid,sid,flags)` /
  `close_session(hsm_sid)`; 검증은 `ncmp/gui/py/smoke_test.py`(고유성·멱등·해제·상한 255).

### 4.1 검증 결과
- 서로 다른 `(pid,sid)` → 서로 다른 HSM SID(1~255) ✓
- 같은 `(pid,sid)` 재요청 → 동일 HSM SID(멱등) ✓
- close → OK, 재close → `CKR_SESSION_HANDLE_INVALID` ✓
- 255개 초과 → `CKR_SESSION_COUNT` ✓

## 5. STDLL/데몬 통합 (후속)

현재 opencryptoki STDLL은 세션 카운트를 로컬(`ncmp/stdll/ncmp_session.c`,
`NCMP_Slot.cur_sessions`)로만 관리하고 **세션 open/close를 토큰에 포워딩하지 않는다**.
이 CI를 실 경로에 물리려면:

1. `token_specific`에 세션 열림/닫힘 훅이 필요하나 **opencryptoki SPI에는 해당 훅이
   없다**(구조적 제약, [`app-stdll-path-design.md`](app-stdll-path-design.md) 참조).
   대안: `t_init`/`new_host`의 세션 생성 지점에서 커스텀 훅을 추가하거나, STDLL이
   `C_OpenSession` 경로에서 직접 CI를 호출하도록 패치.
2. 포워딩 시 STDLL은 응답 HSM SID를 세션 핸들↔HSM SID 매핑으로 보관하고, 이후 암호
   명령의 `header.session_id`에 HSM SID를 싣는다.
3. `pid`는 STDLL이 `getpid()`로, `sid`는 공통 계층의 세션 핸들로 전달한다.

> 데몬(ncmpd)이 매핑을 대신 소유하는 모델도 가능하나(중앙 집중), 본 설계는 **토큰
> 소유**로 확정했다(§2). 데몬은 프레임을 중계만 한다.

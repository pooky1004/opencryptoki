# Debug App 설계·개발 내역

ncmpd의 **공유 메모리(SHM)를 슬롯별로 열람**하는 웹 기반 Debug App. PKCS#11
facade를 거치지 않고 **ncmpd의 connection thread와 직접 핸드셰이크**한 뒤 SHM을
읽는다. 외부 호스트에서 브라우저로 접속해 사용한다.

관련: [`debugapp-manual.md`](debugapp-manual.md)(사용법),
[`debugapp-deployment.md`](debugapp-deployment.md)(설정/배포),
[`ncmpd-vs-pkcsslotd.md`](ncmpd-vs-pkcsslotd.md),
SHM 레이아웃 `ncmp/include/ncmp/ncmp_shm.h`.

위치: `ncmp/gui/debugapp/` — `server/ncmp_dbg.c`(C 서버), `web/`(정적 UI),
`.config/config`, `deploy/`, `build.sh`.

## 1. 구조

```
브라우저(어느 호스트든)
   │ HTTP/JSON (REST, 선택적 Bearer 토큰)
   ▼
ncmp_dbg (C, server/ncmp_dbg.c)                         ← Debug App
   │ ① ncmp_ipc_connect(sock)  → HELLO 핸드셰이크 (ncmpd conn_thread)
   │     → 온라인 슬롯 mask 수신, 데몬 생존 확인
   │ ② ncmp_shm_attach()       → "/ncmpd_shm" 읽기 매핑
   │ ③ NCMP_ShmHeader / NCMP_Slot[] 직접 read (무잠금 스냅샷)
   ▼
ncmpd (conn_thread + SHM 소유)  ──comm thread──▶ 실 FX3(USB)/mock/socket
```

- **Debug App GUI ⇄ ncmpd(conn thread)**: 요청마다 `ncmp_ipc_connect`로 conn
  thread와 핸드셰이크해 생존/슬롯 mask를 확인하고, SHM은 한 번 attach해 재사용한다.
- SHM 구조체를 **직접 읽는다**(쓰기 없음, 잠금 없음). robust 뮤텍스
  (`global_lock`/`sess_lock`)는 **잡지 않는다** — 디버그 리더가 소유권을 가지면
  `EOWNERDEAD` 등으로 데몬에 간섭할 수 있어, 휘발성 카운터는 스냅샷으로만 읽는다.
  링 엔트리 상태는 원자적 load(`ncmp_qentry_state`)로 읽는다.
- **ncmpd 수정 불필요**: conn thread의 기존 HELLO→ATTACH 핸드셰이크와 공개 SHM
  레이아웃만으로 충분하다. (요구사항의 "필요시 수정"에 해당 없음)

## 2. C 서버 (`server/ncmp_dbg.c`)

의존성 없는 HTTP/1.1 서버(연결당 스레드), `ncmp_common`만 링크. 기능:
- 정적 UI 서빙(경로 탈출 차단) + `/api/*` JSON.
- SHM 핸드셰이크/attach(`shm_ensure`), 재연결(`/api/reconnect`).
- Bearer 토큰 인증(`NCMP_DBG_TOKEN`), 설정 파일 로더(§deployment), CORS,
  `sigaction`로 SIGTERM 즉시 종료.

### REST API

| 메서드·경로 | 바디 | 설명 | 응답 핵심 |
|---|---|---|---|
| `GET /api/status` | — | 연결/ SHM 헤더 | `connected,shmName,magic,version,slotCount,totalSize,slotMask,sockPath,authRequired` |
| `GET /api/slots` | — | 실재(ABSENT 아님) 슬롯 요약 | `slots[],slotCount,shown` |
| `POST /api/slot` | `{slot}` | 슬롯 1개 전체 SHM 덤프 | `state,boundCkSlot,curSessions,maxInflight,stats,token,bufPool,queue,busy[]` |
| `POST /api/reconnect` | — | SHM detach 후 재attach | `connected` |
| `POST /api/ci` | `{slot,command,session,p0..p7}` | **CI 1건을 실 타겟에 송신하고 수신** | `ok,rc,elapsedMs,request{...},response{...}` |

### CI 송수신 (`/api/ci`)

`Debug App GUI ⇄ ncmpd(conn thread) → comm thread → 실 target`. conn thread
핸드셰이크로 얻은 command path(`ncmp_client`)로 지정한 **CI opcode**와 파라미터
(hex)를 실 토큰에 보내고 응답을 받는다.

- 요청 조립: `NCMP_Message`(header.command_id=opcode, session_id, param_len[],
  payload=hex 디코드) → `ncmp_client_exec`로 슬롯 링에 enqueue → comm thread가
  USB로 전송 → 응답을 `ncmp_wire_decode`로 복원.
- **송신/수신 프레임을 각각 Hex와 파싱 형식으로 동시 반환**한다:
  `ncmp_wire_encode`로 raw 바이트(hex), 그리고 헤더(session_id·sequence_id·
  command_id·ack·payload_len)와 param_len/param hex를 파싱 필드로. 응답의 `ack`은
  `CKR_*`로 프런트에서 이름 매핑.
- 긴 교환(무응답 CI는 comm thread USB 타임아웃까지 대기)은 SHM-읽기 엔드포인트를
  막지 않도록 g_lock을 짧게만 잡고 exec는 잠금 밖에서 수행한다.

### 슬롯 덤프에 포함되는 SHM 필드(`NCMP_Slot`)

- `state`(ABSENT/ONLINE/FAULTED), `slot_id`, `bound_ck_slot`(CK슬롯 바인딩),
  `cur_sessions`, `max_inflight`.
- `stats`: `in_flight_cnt`(현재 토큰 내부 명령 수), `stats_max_in_flight`(피크),
  `stats_total_sent_cmds`(누적 전송) — comm thread가 USB 송수신 전후로 갱신.
- `token`(`NCMP_TokenIdentity`): valid·label·serial·manufacturer·model·HW/FW·flags
  — 데몬이 부팅 시 `NCMP_CMD_VD_TOKEN_INFO`로 채운다.
- `bufPool`: 슬롯 스크래치 풀 오프셋/길이.
- `queue`: MPSC 명령 링(depth 32)의 상태 히스토그램(FREE/CLAIMED/POSTED/SENT/
  DONE/ABANDONED) + 비-FREE 엔트리 목록(idx·state·ownerSess·seq·reqLen·rspLen).

> `slot_count`는 `PKCS11_MAX_SLOT_COUNT`(최대 256)로 대부분 ABSENT다. `/api/slots`
> 는 **실재 슬롯만** 출력하고(버퍼 가드로 안전) 전체 수(`slotCount`)와 표시 수
> (`shown`)를 함께 준다.

## 3. 웹 UI (`web/`)

바닐라 HTML/CSS/JS. 라이트/다크 테마(토글, localStorage 저장). **탭 2개**:
**공유메모리 뷰어**와 **CI 송수신**. 구성:
- 헤더: 테마 토글, 서버 토큰, 자동 새로고침(2초) 토글, 재연결, 연결 램프.
- 상태 바: SHM 이름·magic·version·slotCount·totalSize·slotMask·sock.
- 좌측: 실재 슬롯 목록(상태 뱃지·토큰 라벨·in-flight·누적 전송). 클릭 선택.
- (공유메모리 뷰어) 좌: 실재 슬롯 목록 / 우: 선택 슬롯 상세(상태·통계·토큰 신원
  카드, 명령 링 히스토그램 + 비-FREE 엔트리 표).
- (CI 송수신) 상단 바: 슬롯·CI 선택(opcode+이름)·session_id·전송·창 지우기, CI별
  파라미터 힌트. 파라미터: p0~p7 hex 입력. **디버깅 창**: 교환마다 TX/RX를 각각
  **Hex(바이트 정렬) + 파싱 표**(frame_len·session_id·sequence_id·command_id(+CI
  이름)·ack(+CKR 이름)·payload_len·param[i])로 동시 출력, 최신이 위로 누적.
- 하단: 로그.

## 4. 빌드 & 검증

```bash
ncmp/gui/debugapp/build.sh            # gcc 단독 빌드 -> build/ncmp_dbg
# 또는 CMake(ENABLE_DEBUGAPP 기본 ON)
cd ncmp && cmake -S . -B build -DENABLE_MOCK_TOKEN=ON && cmake --build build -j
```

이 환경(gcc, libusb, 실 FX3 04b4:00f1)에서 **경고 없이 빌드·`ctest` 통과**, 그리고
**mock·실 타겟 모두 end-to-end 검증**:
- mock: 슬롯 0 ONLINE, 토큰 `NCMPTOKEN0`/`DYST`/`NCMP`, 통계 0, 링 FREE 32 정상
  표시.
- 실 FX3(`--transport real`): 슬롯 0 ONLINE·`slotMask 0x1`·링 FREE 32 표시 —
  SHM 상태를 있는 그대로 반영함을 확인.
- **CI 송수신(mock)**: VD_PING·GETMECHLIST·RNG(p0=16B) 등에서 TX/RX 프레임이
  Hex + 파싱으로 정확히 표시(예 RNG RX param0=16바이트).
- **CI 송수신(실 FX3)**: VD_PING은 **0.7ms에 실제 응답 수신**(ack=0xB3
  CKR_SESSION_HANDLE_INVALID — session 0이라 거부하나 펌웨어가 프레임 반환),
  VD_FW_INFO/VD_TOKEN_INFO는 ~42s 타임아웃(RX 없음). 실 타겟 송수신·hex/파싱
  표시가 정상 동작함을 확인. 상세는 [`debugapp-manual.md`](debugapp-manual.md).

## 5. 남은 과제
- 명령 링 엔트리의 요청/응답 바이트 덤프(현재는 길이·세션·seq만). 필요 시
  `req_off`/`rsp_off`로 버퍼를 읽어 16진수 표시.
- 다중 ncmpd/SHM 인스턴스 선택(현재 well-known `/ncmpd_shm` 고정).
- 펌웨어 적재된 실 토큰에서 세션/큐가 실제로 채워지는 모습 재확인.

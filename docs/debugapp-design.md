# Debug App 설계·개발 내역

ncmpd의 **공유 메모리(SHM)를 슬롯별로 열람**하는 웹 기반 Debug App. PKCS#11
facade를 거치지 않고 **ncmpd의 connection thread와 직접 핸드셰이크**한 뒤 SHM을
읽는다. 외부 호스트에서 브라우저로 접속해 사용한다.

> **USB 권한 불필요.** Debug App은 USB(FX3)를 직접 열지 않는다(libusb 미링크).
> ncmpd가 USB를 소유하며, Debug App은 소켓 핸드셰이크 + SHM **읽기**만 한다.
> 토큰에 명령을 보내는 CI 송수신 기능은 **Web Test App**으로 이관되었다 — 이
> 앱은 순수 **읽기 전용 SHM 뷰어**다.

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

> Debug App은 **읽기 전용 SHM 인스펙터**다. 토큰에 명령을 보내는 경로는 없다
> (이전의 `POST /api/ci` CI 송수신 기능은 제거됨 — 실 타겟 명령 송신은 Web Test
> App을 사용). conn thread 핸드셰이크(`ncmp_client_init`)로 SHM을 **read-only**로
> attach해 슬롯 메타데이터만 조회한다.

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

바닐라 HTML/CSS/JS. 라이트/다크 테마(토글, localStorage 저장). **단일 화면**:
**공유메모리 뷰어**(슬롯 상태 전용). 구성:
- 헤더: 테마 토글, 서버 토큰, **자동 새로고침 토글 + 주기(초, 기본 1초)**, 재연결,
  연결 램프.
- 상태 바: SHM 이름·magic·version·slotCount·totalSize·slotMask·sock.
- 좌측: 실재 슬롯 목록(상태 뱃지·토큰 라벨·in-flight·누적 전송). 클릭 선택.
- 우측: 선택 슬롯 상세(상태·통계·토큰 신원 카드, 명령 링 히스토그램 + 비-FREE
  엔트리 표).
- 하단: 로그.
- **주기적 자동 갱신**: 기본 1초마다 `/api/status`+`/api/slots`+`/api/slot`을 다시
  읽어 화면을 갱신한다(이전 갱신이 진행 중이면 건너뛰어 중첩 방지). 주기는 헤더의
  "주기(초)"로 조절(1~60), 토글로 끄면 수동.

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
- 자동 새로고침(기본 1초): status/slots/slot가 주기적으로 갱신되고, CI 송수신
  엔드포인트(`/api/ci`)는 제거되어 `{"error":"no such api"}`를 반환함을 확인.
  상세는 [`debugapp-manual.md`](debugapp-manual.md).

## 5. 남은 과제
- 명령 링 엔트리의 요청/응답 바이트 덤프(현재는 길이·세션·seq만). 필요 시
  `req_off`/`rsp_off`로 버퍼를 읽어 16진수 표시.
- 다중 ncmpd/SHM 인스턴스 선택(현재 well-known `/ncmpd_shm` 고정).
- 펌웨어 적재된 실 토큰에서 세션/큐가 실제로 채워지는 모습 재확인.

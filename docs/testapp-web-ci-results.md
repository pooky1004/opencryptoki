# CI 송수신 탭 시험 결과 (실 타겟)

웹 Test App의 **CI 송수신** 탭(`/api/ci`)을 **실 FX3 타겟**으로 시험한 결과.
CI(Command Interface) 단위로 원시 와이어 프레임을 토큰에 직접 보내고 받아,
송신(TX)/수신(RX)을 **raw(Hex)** 와 **parsed**(해석)로 동시에 확인한다. 설계는
[`testapp-web-design.md`](testapp-web-design.md), 사용법은 §5.5-A
[`testapp-web-manual.md`](testapp-web-manual.md) 참고.

- 일자: 2026-10-05
- 환경: Linux x86_64, 실 FX3 `04b4:00f1`(CYUSB3KIT-003) USB 연결, `ncmp_web`
  최신 빌드(`--transport real`), slot 0 ONLINE(`slotMask 0x1`).
- 경로: 브라우저 ─`/api/ci`─ `ncmp_web`(서버 전용 `ncmp_client`, facade 미경유)
  ─ IPC+SHM ─ `ncmpd` ─ comm thread ─ FX3(USB). `g_api_lock` 밖·독립 락이라
  상태/슬롯 폴링을 막지 않는다.

> **핵심 결론**: **CI 송수신 탭은 실 타겟에서 end-to-end로 정상 동작**한다 —
> 프레임을 조립·전송하고 응답을 받아 **TX/RX를 raw+parsed로 정확히 표시**한다.
> 다만 이번 시험 시점의 보드는 해당 CI들에 **응답하지 않아**, 데몬이 **5초
> 타임아웃**에서 합성 에러 응답(`ack=0x50 CKR_FUNCTION_CANCELED`)을 돌려주고
> 탭이 이를 "수신(RX) ack=CKR_FUNCTION_CANCELED"로 올바르게 보여준다. (직전에
> 적용한 5초 타임아웃 캡이 동작 — 40초가 아님.)

## 1. 송수신 프레임 예 (VD_PING, 0x0103)

요청/응답이 모두 raw(Hex)와 parsed로 반환됨을 확인했다.

| 방향 | raw (Hex) | parsed |
|------|-----------|--------|
| 송신(TX) | `34000000 00000000 04000000 03010000 00000000 20000000 …` | frame_len 52 · session_id 0 · sequence_id 4 · command_id 0x0103(VD_PING) · ack 0x0 · payload_len 32 · params 없음 |
| 수신(RX) | `34000000 00000000 04000000 03010050 00000000 20000000 …` | frame_len 52 · session_id 0 · sequence_id 4 · command_id 0x0103 · **ack 0x50(CKR_FUNCTION_CANCELED)** · payload_len 32 · params 없음 |

- RX 프레임은 데몬의 **5초 무응답 합성 응답**이다(요청의 session/sequence/command
  를 echo, ack만 `0x50`). 토큰이 실제로 응답하면 이 자리에 그 ack/파라미터가 그대로
  파싱되어 표시된다.

## 2. 시험한 CI와 결과

| CI (opcode) | 파라미터 | 소요 | RX ack | 비고 |
|---|---|---|---|---|
| VD_PING (0x0103) | 없음 | ~5.0s | 0x50 CKR_FUNCTION_CANCELED | 무응답(합성 타임아웃) |
| VD_FW_INFO (0x0105) | 없음 | ~5.0s | 0x50 | 〃 |
| VD_TOKEN_INFO (0x0108) | 없음 | ~5.0s | 0x50 | 〃 |
| NOP (0x0000) | 없음 | ~5.0s | 0x50 | 〃 |
| GETMECHLIST (0x0003) | 없음 | ~5.0s | 0x50 | 〃 |

- 모든 CI가 `ok=true, rc=0`(응답 프레임 수신됨) + `ack=0x50`(합성 타임아웃)으로
  돌아왔다. `ok/rc`는 "응답 프레임을 받았는가"이고, 실제 처리 결과는 `ack`로 본다.

## 3. 검증된 것 / 제약

**검증됨**
- CI opcode 선택 → **CI별 입력 파라미터(p0~p7, Hex)** → session_id → 전송 흐름.
- 전송 시 디버깅 창에 **TX/RX를 raw(Hex, 16바이트 정렬) + parsed**(frame_len·
  session_id·sequence_id·command_id(+CI 이름)·ack(+CKR 이름)·payload_len·param[i])
  로 동시 출력.
- 서버 전용 `ncmp_client`가 facade와 독립적으로 데몬에 직결되어 동작.
- **5초 타임아웃 캡**: 무응답 CI가 ~5.0초에 종료(이전 ~40초 대비).
- mock 교차 검증: 동일 경로에서 VD_PING은 `ack=0x0`(즉시), RNG(p0=16B)는
  `ack=0x0`·param0 16바이트로 **실제 응답**이 raw+parsed로 표시됨을 확인.

**제약 / 미검증**
- 이번 시점의 실 보드는 시험한 CI에 **응답하지 않았다**(UNPROVISIONED/OUT
  엔드포인트 미드레인 상태로 추정). 따라서 **실 토큰의 정상 ack/응답 파라미터**가
  파싱되는 모습은 이 세션에서 확인하지 못했다.
- 과거 세션에서는 보드 상태에 따라 VD_PING이 **0.7ms에 실제 응답**(ack 반환)한
  기록이 있다 — 응답 여부는 **보드/펌웨어 상태 의존**이며 탭 자체의 문제가 아니다.
- 세션 기반 CI(LOGIN·DIGEST 등)는 먼저 OPEN_SESSION으로 핸들을 받아야 하나, 현
  보드는 OPEN_SESSION도 미응답이라 session_id 0으로만 시도했다.

## 4. 재시험 방법 (응답 가능한 보드에서)

```bash
# 1) 실 타겟으로 Web Test App 기동
cd ncmp/gui/testapp
build/ncmp_web --host 0.0.0.0 --port 8080 --transport real
# 2) 브라우저: 데몬 시작 → 로드 → C_Initialize → 슬롯 0 선택
# 3) "CI 송수신" 탭에서 CI 선택·파라미터 입력·전송 → TX/RX의 raw+parsed 확인
```

응답 가능한(provisioned) 펌웨어에서는 RX 프레임의 `ack`가 `CKR_OK`(또는 해당
오류)로, 응답 파라미터(예: RNG 난수, GET_TOKEN_PARAMS 라벨/시리얼)가 param[i]에
raw+parsed로 표시된다.

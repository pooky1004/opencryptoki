# 슬롯 확장 설계: 최대 255 슬롯 (시스템 2 + 사용자 나머지)

슬롯 최대 개수를 현재 **4**에서 **255**로 늘리고, 슬롯을 **시스템 슬롯 2개 + 사용자
슬롯 나머지(최대 253)** 로 구분하기 위한 설계·영향분석·마이그레이션. 결정은 "255 슬롯
전면 지원". 본 문서는 **설계**이며 일부는 **구조적 제약/HW 필요**로 표시한다(§6).

- 관련: [`architecture.md`](architecture.md), [`../CLAUDE.md`](../CLAUDE.md)(현재 한계 상수),
  [`ncmpd-vs-pkcsslotd.md`](ncmpd-vs-pkcsslotd.md)

> **주의**: 현재 `CLAUDE.md`·`ncmp_limits.h`는 `PKCS11_MAX_SLOT_COUNT=4`를 **STRICT**로
> 못박고 있다. 본 설계는 이 상수를 **의도적으로 상향**하는 변경이므로, 적용 시 두 곳을
> 함께 갱신하고 관련 불변식을 재검토해야 한다.

## 1. 목표

| 항목 | 현재 | 목표 |
|------|------|------|
| 최대 슬롯 | 4 | **255** (id 0~254) |
| 슬롯 분류 | 없음 | **시스템 2** + **사용자 253** |
| 슬롯 presence 표현 | `uint32_t slot_mask`(≤32) | 255 수용 표현 |
| 슬롯당 세션 | 8 | 255 (→ [`session-id-mapping.md`](session-id-mapping.md)) |

## 2. 가장 큰 제약: `uint32_t slot_mask`

슬롯 존재 여부가 **32비트 비트마스크**로 표현되어 전 구간에 박혀 있다:

| 위치 | 코드 |
|------|------|
| 전송 probe | `int ncmp_transport_probe(uint32_t *out_slot_mask)` (`ncmp_transport.h`) |
| IPC HELLO | `uint32_t slot_mask` (`ncmp_ipc.h`) |
| 클라이언트 | `c->slot_mask` (`ncmp_client.h`), `(slot_mask & (1u<<slot))` 체크 |
| 데몬/mock | `*out_slot_mask |= (1u << s)` (`usb_transport.c`, `mock_transport.c`) |

→ **32개 초과 불가**. 255로 가려면 presence 표현을 바꿔야 한다.

### 2.1 제안: 비트셋 + 개수
- `slot_mask`(스칼라) → **`uint8_t slot_present[32]`**(256비트 비트셋) 또는
  `uint32_t slot_count + uint8_t online[256]`.
- probe/HELLO/클라이언트 API를 비트셋 전달로 교체(`ncmp_slot_is_online(set, id)` 헬퍼).
- 와이어 HELLO 응답 길이가 4B→32B로 증가(IPC 구조체 버전업 `NCMP_ERR_VERSION` 관리).

## 3. SHM 레이아웃

현재 SHM 헤더는 슬롯 배열을 **인라인**으로 품는다:
```c
NCMP_Slot slots[PKCS11_MAX_SLOT_COUNT];   // ncmp_shm.h
```
`NCMP_Slot`은 슬롯당 큐·엔트리 버퍼 풀(각 엔트리 = `NCMP_MAX_FRAME_SIZE` 64KB)을 포함해
수십~수백 KB다. 이를 **255배** 인라인하면 SHM이 수십 MB~수백 MB로 폭증한다.

### 3.1 제안: 동적·오프셋 기반 슬롯 배열
- SHM 헤더에는 `slots_off`(이미 존재) + `slot_capacity`만 두고, **활성 슬롯 수만큼** 슬롯
  구조를 할당(오프셋 주소지정은 이미 `ncmp_shm_slot()`로 추상화됨).
- 엔트리 버퍼 풀(64KB×N)은 **온라인 슬롯에만** 매핑. 오프라인 슬롯은 메타만.
- 슬롯당 in-flight 상한(4 컨테이너)은 유지 — 슬롯 수와 무관.

## 4. 데몬 스레드 모델

현재 "슬롯당 comm_thread 1개". 255 슬롯에 255 스레드는 비현실적(메모리·스케줄링).

### 4.1 제안
- **활성(온라인) 슬롯에만** comm_thread를 생성(존재하지 않는 슬롯은 스레드 없음).
- 또는 **스레드 풀**(워커 N개가 다수 슬롯 큐를 멀티플렉싱). 단일 USB 링크가 병목이면
  comm_thread는 사실상 **물리 링크 수**에 비례하면 충분(슬롯 수가 아니라).
- 실 FX3가 단일 USB면 동시 "물리 토큰"은 소수 → 논리 슬롯 255개라도 실제 데이터 플레인
  스레드는 소수.

## 5. 데이터 포트 / GUI

- mock 서버: `data port = base + slot`. 255 슬롯이면 `base .. base+254`(예 7010~7264).
  포트 범위 충돌 주의, `--slots`가 255까지 허용되도록 상향.
- `mock_device_t`(에뮬 장치)도 `[255]` 배열은 큼 — 활성 수만 할당하도록 변경 권장.
- GUI(Mock/App): 슬롯 선택 위젯 범위 0~254, 슬롯 목록 스크롤.

## 6. 시스템/사용자 슬롯 구분

| 분류 | id | 용도(예) |
|------|----|----------|
| 시스템 슬롯 | 0, 1 | 토큰 관리·감사·키 관리 등 특권/인프라 용도(정책상 제한) |
| 사용자 슬롯 | 2 ~ 254 | 일반 애플리케이션 세션 |

- `ncmp_limits.h`에 `NCMP_SYSTEM_SLOT_COUNT=2`, `NCMP_USER_SLOT_BASE=2` 추가.
- 바인딩(`ncmp_slotmap.c`)·설정(`ncmptok.conf`)에서 분류별 정책(접근 제어, 기본 토큰
  선택)을 분기.
- opencryptoki `opencryptoki.conf`의 슬롯 정의와 동기화 필요.

## 7. 변경 대상 요약

| 파일 | 변경 |
|------|------|
| `ncmp/include/ncmp/ncmp_limits.h` | `PKCS11_MAX_SLOT_COUNT 4→255`, 시스템/사용자 상수 추가, 세션 255 |
| `ncmp_transport.h`/`usb_transport.c`/`mock_transport.c` | probe의 mask→비트셋 |
| `ncmp_ipc.h`/`ncmp_ipc.c`/`conn_thread.c` | HELLO의 slot_mask→비트셋(+버전업) |
| `ncmp_client.h`/`ncmp_client.c` | online 판정 비트셋화 |
| `ncmp_shm.h` | 인라인 `slots[4]`→동적·활성분 할당 |
| `daemon/main.c`/`comm_thread.c` | 활성 슬롯만 스레드/스레드풀 |
| `ncmp/gui/server/*`, GUI | 슬롯 범위·포트 범위 확대 |
| `CLAUDE.md` | STRICT 한계값 갱신 |

## 8. 구조적 제약 / 이 환경에서 불가

- **255 comm_thread 동시 구동**: 비현실적 → 활성 슬롯/스레드풀 모델이 **필수**(단순
  상수 상향만으로는 불가).
- **인라인 SHM 배열의 단순 확대**: 메모리 폭증으로 사실상 불가 → 동적 할당 리팩터 필수.
- **실제 255 물리 토큰 동시 연결**: 단일 USB 링크 구조에서는 물리적으로 불가. 255는
  **논리 슬롯 id 공간**이며, 실 동시 토큰 수는 하드웨어(허브/다중 FX3)에 종속 → HW 필요.
- **빌드/런타임 검증**: 이 개발 환경엔 cmake/libusb/full opencryptoki 런타임이 없어
  데몬·STDLL 경로의 255 슬롯 실동작은 검증 불가(설계·단위 수준까지).

## 9. 권장 단계

1. `slot_mask`→비트셋 추상화(헬퍼 도입) + IPC 버전업.
2. SHM 슬롯 배열 동적화(활성분 할당).
3. 데몬 스레드 모델을 활성 슬롯/풀로 전환.
4. 한계 상수 상향(4→255) + 시스템/사용자 분류 + 설정 동기화.
5. mock 서버·GUI 슬롯/포트 범위 확대.
6. 세션 255는 이미 토큰 측 구현됨([`session-id-mapping.md`](session-id-mapping.md)); 슬롯
   확대와 독립적으로 동작.

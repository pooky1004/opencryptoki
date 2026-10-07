# PEM USB 전송 방식 분석 및 기존(NCMP FX3) 방식 비교

작성일: 2026-10-07 · 분석 대상: PEM `/home/pooky/ji/host/ci/ci_usb_lib.c`,
기존 NCMP `ncmp/daemon/usb_transport.c`

PEM 보드(USB `04b4:5054`)의 USB 포트로 데이터를 보내는 방식을 코드 기준으로 상세
분석하고, 기존 NCMP 보드(`04b4:00f1`, FX3 Slave-FIFO) 방식과 비교한다.

> 요지: **두 방식의 근본 차이는 펌웨어 데이터패스다.** PEM은 **표준 USB bulk
> (Cypress AUTO DMA) 전송**으로 단순히 OUT→IN 하면 되지만, NCMP는 **FX3 Slave-FIFO
> sync(GPIF)** 특성 때문에 매 요청 뒤에 **버스 방향을 되돌리는 NOP 트리거**와
> 인터프레임 가드·flush가 필요하다. 또 PEM은 **usbfs를 직접(ioctl)** 쓰고 NCMP는
> **libusb**를 쓴다.

---

## 1. 공통점 (물리 계층)

| 항목 | 값 |
|------|-----|
| 제조사 | Cypress (VID `0x04B4`) |
| PID | PEM `0x5054` / NCMP `0x00F1` |
| 인터페이스 | 0 (both) |
| Bulk OUT 엔드포인트 | `0x01` (both) |
| Bulk IN 엔드포인트 | `0x81` (both) |
| 전송 단위 | 요청/응답 1:1, 전송 버퍼 4바이트 정렬 |

엔드포인트 번호·인터페이스·4바이트 정렬은 동일하다. **차이는 "어떻게 보내고 받는가"**
(호스트 API + 핸드셰이크 절차)에 있다.

---

## 2. PEM USB 전송 방식 (상세)

소스: `ci/ci_usb_lib.c`, API: `ci/ci_usb_lib.h`.

### 2.1 디바이스 접근 — **usbfs 직접(ioctl)** (기본 백엔드)
- 기본 빌드는 libusb 없이 **커널 usbfs를 직접** 연다(컴파일 플래그로 libusb 선택 가능,
  §2.4).
- **디바이스 탐색**(`find_device`): `/sys/bus/usb/devices/*`를 순회하며 `idVendor`/
  `idProduct`가 `04b4:5054`인 노드를 찾고, `busnum`/`devnum`으로
  `/dev/bus/usb/BBB/DDD` 경로를 만든다. VID/PID가 **2개 이상이면 `ERR_MULTIPLE`**.
  (옵션 `device_path`로 정확한 경로 지정 가능)
- **디스크립터 파싱**(`descriptor_packet`): sysfs `descriptors`를 읽어 인터페이스 0 /
  alt 0 의 **bulk 엔드포인트**를 찾는다 — OUT `0x01`의 **wMaxPacketSize**를 얻고
  IN `0x81` 존재를 확인한다. 둘 중 하나라도 없으면 `ERR_UNSUPPORTED`.
- **오픈/클레임**(`CI_USB_Open`): `/dev/bus/usb/BBB/DDD`를 `O_RDWR`로 열고
  `ioctl(USBDEVFS_CLAIMINTERFACE, 0)`으로 인터페이스 0을 claim. 백엔드 구조체에
  `fd`, `timeout_ms`, `max_packet` 보관.

### 2.2 전송 절차 — `usbfs_exchange()` (OUT → [ZLP] → IN)
표준 벌크 전송이며 **핸드셰이크성 추가 전송이 없다.**

1. **OUT(`0x01`)**: `ioctl(USBDEVFS_BULK)`로 요청 프레임을 **한 번에** 전송
   (`bulk_until`가 데드라인까지 1회 전송). 보낸 길이가 요청 길이와 다르면 `ERR_SHORT`.
2. **ZLP(조건부)**: 요청 길이가 **`max_packet`의 배수**이면 **길이 0 OUT 패킷(ZLP)**
   을 한 번 더 보낸다. → Cypress **AUTO DMA가 "짧은 패킷"으로 전송 종료를 인식**하게
   하기 위함(정확히 최대패킷 배수인 전송에만 필요).
3. **IN(`0x81`)**: 기대 응답 길이만큼 `ioctl(USBDEVFS_BULK)`로 **한 번** 읽는다.
   펌웨어는 IN ZLP를 붙이지 않으며, **16바이트짜리 짧은 CI 오류 프레임**도 허용.
   실제 수신 길이를 그대로 반환.
- **타이밍**: `CI_USB_Timing`에 out/in 시작·종료 ns 기록(성능 측정용).
- **타임아웃**: 기본 10 s(최대 60 s). `bulk_until`가 남은 시간으로 각 전송의 타임아웃 계산.

### 2.3 특징 요약
- **버스 턴어라운드/트리거 없음**: OUT 후 바로 IN을 읽어도 응답이 커밋되어 있다
  (표준 bulk + AUTO DMA).
- **인터프레임 가드/쿨다운 없음**: 전송 간 강제 지연 없음(타임아웃만 존재).
- **flush/재시도 루프 없음**: IN은 기대 길이 1회 읽기.
- **특수 복구 없음**: 타임아웃 시 "연결 상태 불확실" 오류만 반환(디바이스 reset 없음).
- **백엔드 추상화**: `CI_USB_Backend` 콜백으로 대체 transport/테스트 더블 주입 가능
  (`CI_USB_CreateBackend`).

### 2.4 USB 백엔드 선택 — usbfs ioctl ↔ libusb-1.0 (컴파일 플래그)

`ci_usb_lib.c`는 **동일한 전송 절차(OUT → [ZLP] → IN)** 를 두 가지 하위 백엔드로
구현하며, **컴파일 타임 매크로 `CI_USB_USE_LIBUSB`** 로 하나를 고른다. 선택은
`CI_USB_Open()` 내부에서만 갈리고, 프레임 검증·타이밍·트레이스·에러 매핑 등 상위
로직(`CI_USB_Exchange` 등)은 두 백엔드가 공유한다.

| 항목 | 기본 (usbfs ioctl) | `-DCI_USB_USE_LIBUSB` (libusb-1.0) |
|------|--------------------|-------------------------------------|
| 매크로 | 미정의 | `CI_USB_USE_LIBUSB` 정의 |
| 디바이스 탐색 | `/sys/bus/usb/devices` 순회 + sysfs `descriptors` | `libusb_get_device_list` + 활성 config 디스크립터 |
| `device_path` 매칭 | sysfs `busnum`/`devnum` → `/dev/bus/usb/BBB/DDD` | `libusb_get_bus_number`/`_device_address` → 동일 경로 문자열 |
| OUT max packet | sysfs 디스크립터의 EP `0x01` wMaxPacketSize | 활성 config EP `0x01` wMaxPacketSize |
| 오픈/클레임 | `open(O_RDWR)` + `ioctl(USBDEVFS_CLAIMINTERFACE,0)` | `libusb_open` + `set_auto_detach_kernel_driver` + `claim_interface(0)` |
| 벌크 전송 | `ioctl(USBDEVFS_BULK)` (`bulk_until`) | `libusb_bulk_transfer` (`ci_libusb_bulk`) |
| ZLP 규칙 | 요청이 max packet 배수면 길이 0 OUT | 동일 |
| 외부 의존성 | 없음(커널 usbfs) | libusb-1.0 |

- **ZLP·IN 규칙 동일**: 요청이 max-packet 배수일 때 OUT ZLP 1회, IN은 기대 길이 1회
  읽기(펌웨어 IN ZLP 없음). 두 백엔드 출력은 실 보드에서 **바이트 단위로 동일**함을
  확인(SHA3/AES-GCM·CTR 단발·멀티파트·저장 키 ID 교차검증).
- **빌드 선택**:
  - CMake : `cmake -S ncmp -B build -DENABLE_PEM_LIBUSB=ON` (OFF=usbfs 기본).
    ON이면 libusb가 **필수**가 되고 `ci_usb_lib.c`를 컴파일하는 모든 타깃
    (ncmpd, hsm_bridge)이 libusb를 링크한다.
  - 스탠드얼론 스크립트 : `CI_USB_USE_LIBUSB=1 bash ncmp/gui/build_standalone_p11.sh`
    (미설정=usbfs 기본). ncmpd는 실 FX3 경로 때문에 어느 쪽이든 libusb를 링크하므로
    컴파일 플래그만 바뀐다.
- 타임아웃 의미는 미세하게 다르다: usbfs는 OUT+ZLP+IN **전체 데드라인**, libusb는
  **전송 단위** 타임아웃(기본 10 s). 운용상 차이는 없다.

### 2.5 컨테이너 파이프라인 — OUT/IN 분리와 3-deep in-flight

PEM 보드는 요청 컨테이너가 **3개**다. 이를 활용해 ncmpd의 comm_thread가 **최대 3개를
동시에 in-flight** 로 둔다: POSTED 요청을 **누적 송신이 3이 되거나 보낼 것이 없을 때까지
OUT(dispatch)** 하고, 그다음 **IN 응답을 수집(drain)** 한다. 이는 comm_thread의 기존
파이프라인 정책(`slot->max_inflight`)이며, PEM 슬롯은 `max_inflight =
NCMP_PEM_CONTAINER_COUNT(3)` 로 설정된다(`daemon/main.c`).

이를 위해 CI_USB 와 PEM 백엔드의 교환을 **OUT 전용/IN 전용으로 분리**한다:
- `CI_USB_Send`(OUT+조건부 ZLP) / `CI_USB_Recv`(IN) 를 추가(usbfs·libusb 공통).
  기존 `CI_USB_Exchange` = Send+Recv.
- `daemon/pem_transport.c`:
  - `pem_be_send()` 는 NCMP 요청을 CI v4 로 **번역해 OUT만** 보내고, 응답을 어떻게
    NCMP 로 shaping할지(`pem_rsp_kind_t` + req 헤더 + 기대 크기)를 **대기 FIFO**
    (`NCMP_PEM_CONTAINER_COUNT` 깊이)에 넣는다. 번역 단계 오류는 OUT 없이 ack-only 로
    FIFO에 적재(`PEM_RK_LOCAL`).
  - `pem_be_recv()` 는 FIFO 선두를 꺼내 **IN 1프레임을 읽고** `pem_shape()` 로 NCMP
    응답을 만든다(local 항목은 IN 없이 ack-only 반환).
- **응답 상관**: PEM CI v4 응답 헤더에는 sequence_id 가 없으므로, 백엔드는 보드가
  **제출(FIFO) 순서대로 응답**함을 이용해 FIFO 선두와 대응시키고, NCMP 응답에 그 요청의
  session/sequence_id 를 실어 comm_thread 의 `(session_id, sequence_id)` 상관을 만족시킨다.
  실 보드에서 **서로 다른 세션의 동시 one-shot 3건**(AES-GCM)을 실행해 각 스레드가
  자기 입력의 python AES-256-GCM 결과와 바이트 일치함을 확인(= 순서/상관 정확).
- **상태형 멀티파트 주의**: 토큰의 SHA3/AES-GCM 멀티파트 컨텍스트는 토큰 측에서
  공유될 수 있어, **서로 다른 응용이 멀티파트를 동시에 교차** 진행하면 컨텍스트가 섞일
  수 있다(토큰 특성; in-flight 수와 무관하게 프레임 교차로 발생 가능). 단일 응용의
  멀티파트 스트림은 facade 가 단계마다 응답을 기다리므로 자연히 depth 1 로 직렬화되어
  영향이 없다.

---

## 3. 기존 NCMP USB 전송 방식 (상세)

소스: `ncmp/daemon/usb_transport.c` (상세 배경: `docs/fx3-troubleshooting.md`).

### 3.1 디바이스 접근 — **libusb-1.0**
- `libusb_open_device_with_vid_pid`/목록 열거로 `04b4:00f1`을 열고
  `libusb_claim_interface(0)`.
- 오픈 시 **`libusb_reset_device()` 후 재-claim**으로 wedged 상태 복구.

### 3.2 전송 절차 — FX3 Slave-FIFO sync(GPIF) 대응
FX3 Slave-FIFO 경로는 **device→host(P-to-U) 응답이, 그 다음 host→device(U-to-P)
전송이 버스 방향을 되돌릴 때 비로소 커밋**되는 특성이 있다. 그래서:

1. **4바이트 패딩**: GPIF 버스가 32비트라 프레임을 4바이트 경계로 패딩
   (`physical=(total+3)&~3`).
2. **OUT**: 요청 프레임을 chunked로 전송(`fx3_out_write`, OUT 중 IN 서비스).
3. **인터프레임 가드**: OUT 후 **`FX3_GUARD_NS`(5 ms)** 대기(`next_out_ns`로 다음 OUT
   최소 시작 시각 관리).
4. **NOP 트리거**: 매 요청 뒤 **56바이트 NOP 프레임(`command_id=0`)을 OUT으로 전송**
   하여 버스를 되돌려 **직전 응답을 커밋**시킨다(`fx3_send_trigger`).
5. **IN flush-read 루프**: 누적 버퍼(`rx`, `2×NCMP_MAX_FRAME_SIZE`)에 모은 뒤
   프레임을 파싱(`fx3_extract`). **단발(single-shot)**: 한 IN 전송이 max-size 버퍼를
   채우면 그것을 파싱. 빈 타임아웃이면 **트리거 재전송**하며 `flush_limit`회까지 재시도.
6. **NOP 응답 폐기**: 수신 스트림에서 `command_id==0`(트리거 응답)은 버리고 첫 비-NOP
   프레임 반환.

### 3.3 중개 구조
- NCMP는 **ncmpd 데몬**이 USB를 단독 소유하고, 다수 프로세스/스레드를 **SHM + 로버스트
  뮤텍스**로 멀티플렉싱한다(slot별 comm_thread). 즉 USB 전송은 데몬 내부에서만 일어난다.

---

## 4. 비교표

| 구분 | PEM (`04b4:5054`) | NCMP (`04b4:00f1`) |
|------|------|------|
| 호스트 USB API | **usbfs 직접(ioctl USBDEVFS_BULK)** | **libusb-1.0** |
| 디바이스 탐색 | /sys 스캔 + 디스크립터 파싱(EP·max_packet) | libusb VID/PID 열거 |
| 펌웨어 데이터패스 | **표준 bulk + Cypress AUTO DMA** | **FX3 Slave-FIFO sync (GPIF)** |
| 전송 핸드셰이크 | OUT → (ZLP) → IN | OUT → 가드 → **NOP 트리거** → **flush IN** |
| 버스 턴어라운드 처리 | **불필요** | **필수(NOP 트리거로 응답 커밋)** |
| ZLP | **조건부 OUT ZLP**(요청이 max_packet 배수일 때) | 사용 안 함(대신 NOP 트리거) |
| 인터프레임 가드 | 없음 | **5 ms 가드 + 쿨다운** |
| IN 수신 | 기대 길이 1회 읽기(IN ZLP 없음) | **flush-read 루프 + 단발 max-frame**, NOP 응답 폐기 |
| 프레임 정렬 | 4바이트(전송) · 인자 8바이트 | 4바이트(전송/파라미터) |
| 오류 복구 | 타임아웃 보고(특수 복구 없음) | **libusb_reset_device 재초기화** |
| 동시 접근 | **단일 프로세스(인터페이스 claim)** | **ncmpd 데몬 + SHM 멀티플렉싱** |
| 와이어 | CI v4(16B 헤더, 인자 8B) | NCMP(20B 헤더, param_len[8], 4B) |

---

## 5. 왜 다른가 (근본 원인)

- **FX3 Slave-FIFO(GPIF)** 는 FPGA↔FX3 간 외부 FIFO 인터페이스로, 방향 전환 시점이
  명시적 버스 턴어라운드에 묶여 있다. 그래서 호스트가 **응답을 받으려면 다음 OUT으로
  버스를 되돌려야** 하고, 이를 위해 **NOP 트리거**와 가드·flush가 필요하다. 이것이
  NCMP 전송부 복잡도의 원인이다(초기 "RX 공백" 문제의 근원).
- **PEM 펌웨어**는 **표준 USB bulk(AUTO DMA)** 로 동작한다. 호스트는 평범하게 OUT 후
  IN을 읽으면 되고, 유일한 특수 처리는 **정확히 max_packet 배수인 요청에 ZLP** 를
  덧붙여 전송 종료를 알리는 것뿐이다(USB bulk의 일반적 short-packet 규칙).
- 접근 API도 달라, PEM은 의존성 최소화를 위해 **usbfs를 직접** 다루고, NCMP는
  **libusb**로 추상화한다.

---

## 6. Web Test App 통합 관점 시사점

- **NCMP 전송 코드(usb_transport.c)를 PEM에 재사용할 수 없다**: 핸드셰이크·API가 다르다.
  PEM은 **기존 CI USB 라이브러리(`ci_usb_lib.c`) / provider(`libci_pem_pkcs11.so`)를
  그대로 경유**해야 한다(계획서 `pem-webtestapp-plan.md` 참고).
- **데몬 불필요**: PEM은 usbfs 직결·단일 프로세스. ncmp_web이 provider를 dlopen하면
  그 프로세스가 USB를 **직접 claim**한다(동시 접근은 1개 프로세스로 제한).
- **USB 권한**: usbfs 직접 접근이므로 `/dev/bus/usb/*`에 대한 권한(udev 규칙)이 필요하다
  (`tools/setup_usb_permissions.py`). libusb도 동일 권한이 필요하나, PEM은 provider가
  오픈 주체이므로 ncmp_web 프로세스 권한을 확인해야 한다.
- **관측성**: NCMP의 SHM 기반 TX/RX 뷰(Debug App)는 PEM에 없다. PEM은 CI 패킷 로그
  (`tools/show_ci_packets.py` 방식, 또는 `CI_USB_SetTrace` 콜백)로 대체 가능.
- **ZLP/정렬**: PEM 전송은 라이브러리가 ZLP·4바이트 정렬을 처리하므로 상위(PKCS#11)
  계층에서는 신경 쓸 필요가 없다.

---

## 부록: 소스 근거

| 내용 | 파일·위치 |
|------|-----------|
| PEM usbfs 오픈/claim | `ci/ci_usb_lib.c` `CI_USB_Open` (≈295) |
| PEM 디바이스 탐색/디스크립터 | `ci/ci_usb_lib.c` `find_device`/`descriptor_packet` (≈178–239) |
| PEM OUT→ZLP→IN 교환 | `ci/ci_usb_lib.c` `usbfs_exchange` (≈256–283) |
| PEM 기본 옵션(VID/PID/타임아웃) | `ci/ci_usb_lib.c` (≈58–60) |
| PEM 백엔드/트레이스 API | `ci/ci_usb_lib.h` |
| NCMP FX3 전송(트리거/가드/flush/reset) | `ncmp/daemon/usb_transport.c`, `docs/fx3-troubleshooting.md` |

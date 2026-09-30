# 문서 색인 — Token NCMP

토큰 사용량 최적화를 위해 필요한 문서만 골라 읽으세요.

| 문서 | 언제 읽나 |
|------|-----------|
| [`../CLAUDE.md`](../CLAUDE.md) | 항상. 규칙·한계값·빌드/테스트 명령 요약. |
| [`SUMMARY.md`](SUMMARY.md) | **먼저 읽기**. 한 일·남은 과제·현황 지표·빌드/테스트 명령 요약본. |
| [`STATUS.md`](STATUS.md) | 단계별 상세 진행 로그(무엇을 어떻게 구현·검증했는지). |
| [`architecture.md`](architecture.md) | 설계 세부가 필요할 때. 시스템 개요, 와이어 프로토콜, SHM, 동시성, in-flight 통계, 데이터 흐름, opencryptoki 통합. |
| [`stdll-call-flow.md`](stdll-call-flow.md) | 표준 opencryptoki 경로 추적. `C_Initialize`→`C_OpenSession`→`C_EncryptInit`→`C_Encrypt`가 API층→new_host(SC_*)→token_specific→ncmpd로 내려가는 호출 흐름을 파일:라인 단위로. |
| [`session-state-management.md`](session-state-management.md) | NCMP 토큰의 세션 기반 동작 모델과 관리 항목. 다중 앱·스레드 동시 접근, 세션별 연산 중간 상태(load→process→save), **비휘발성(NVM) vs 휘발성(RAM)** 저장 항목 구분과 항목별 상세 설명. |
| [`cryptoki_app_api.md`](cryptoki_app_api.md) | **애플리케이션 API 레퍼런스**. opencryptoki 앱이 `libpkcs11_ncmp.so`로 호출하는 공개 API(`opencryptoki_tok.map` export 73개 = `SC_*`/`ST_Initialize`)별 기능·원형/인자·반환값. 각 함수의 애플리케이션 `C_*` 대응과 NCMP 지원/미지원(메커니즘 범위) 명시 + 심볼↔`C_*` 대응표. |
| [`pure_app_api.md`](pure_app_api.md) | **직접(비-opencryptoki) 사용 API 레퍼런스**. pkcsslotd/슬롯매니저 SHM 없이 `libpkcs11_ncmp.so`를 직접 로드해 export 심볼(`SC_*`/`ST_Initialize`)을 호출하는 관점. **전제**: 이 `.so`는 독립 PKCS#11 프로바이더가 아닌 STDLL(토큰 SPI)이며 `C_GetFunctionList`/`C_*`를 export 하지 않음 → 앱이 api 계층 역할(TokData 할당·초기화, 세션핸들 관리)을 대신해야 하고, 토큰 전송은 여전히 ncmpd(소켓+POSIX SHM) 필요. §0 구조체/상수 + 초기화 시퀀스 + 함수별 기능·원형/인자·반환값. |
| [`middleware_api.md`](middleware_api.md) | **미들웨어 API 레퍼런스**. `ncmp/stdll/*.c`의 모든 함수(전송 계층 + 마샬링 어댑터 43개)별 기능·원형/인자·반환값. 어댑터 공통 반환값 규약(자체 검증/토큰 ack/전송오류 매핑) 포함. |
| [`ncmpd-vs-pkcsslotd.md`](ncmpd-vs-pkcsslotd.md) | "USB 명령 pipeline을 pkcsslotd로 할 수 있나?"에 대한 근거 기반 분석. slotd=컨트롤 플레인(슬롯 관리·프로세스 등록·이벤트/GC, 명령 경로에 없음) vs ncmpd comm_thread=데이터 플레인(단일 USB 소유·in-flight pipeline). 왜 slotd로는 안 되는지와 pipeline 튜닝 지점. |
| [`command-interface.md`](command-interface.md) | **Command Interface(CI)** 규격. 토큰으로 가는 모든 명령별 request/response 구조체(`CI_*Req`/`CI_*Rsp`)와 필드 설명, 공통 프레임(`CI_Header`/`CI_Message`), ack(CKR_*) 표. `CI_Cmd`는 `enum ncmp_opcode`의 **별칭(alias)** 으로 정의(lockstep). advertised mechanism만 남긴 정리된 opcode 집합 + 신규 조회 CI(`GET_UTC_TIME`/`GET_TOKEN_PARAMS`) + 로그인 flags 포함. |
| [`gui-tools-status.md`](gui-tools-status.md) | **GUI 도구 진행상황**. 모의 HSM GUI + 테스트 App GUI(+ 실 HSM 브리지)의 설계 결정·한 일·검증 결과·요구사항 대응·남은 과제 요약. 아키텍처(frame_server 공통 골격 + mock/USB 백엔드)와 파일 목록 포함. |
| [`../ncmp/gui/README.md`](../ncmp/gui/README.md) | **GUI 도구 사용법**. `mock_server`/`hsm_bridge`(C 소켓 서버) + PySide6 두 GUI의 빌드·실행 방법, 데이터/컨트롤 프로토콜, 요구사항 대응표, 헤드리스 검증(`smoke_test.py`), 한계/후속. |
| [`gui-testing-guide.md`](gui-testing-guide.md) | **GUI 시험 가이드(상세)**. 무엇을 실행·설정하고 각 메뉴/탭이 어떤 용도인지, 어떤 시험을 할 때 무엇을 실행/설정하는지 단계별 설명. Mock GUI(Server 바·Identity·Statistics·Debug·Link)·App GUI(Link·HSM State·Crypto·PQC·File Compare·Scenarios·Statistics) 메뉴 레퍼런스 + 시험별 요리책 + 트러블슈팅. |

## 핵심 소스 진입점

| 관심사 | 파일 |
|--------|------|
| 자원 한계 상수 | `ncmp/include/ncmp/ncmp_limits.h` |
| 와이어 프로토콜 | `ncmp/include/ncmp/ncmp_wire.h` |
| MPSC CAS 큐 | `ncmp/include/ncmp/ncmp_queue.h` |
| SHM 레이아웃(오프셋 기반) | `ncmp/include/ncmp/ncmp_shm.h` |
| Robust mutex 래퍼 | `ncmp/include/ncmp/ncmp_mutex.h`, `ncmp/common/ncmp_mutex.c` |
| 데몬 comm/통계 | `ncmp/daemon/comm_thread.c` |
| 단발 USB 수신(최대 버퍼) | `ncmp/daemon/usb_transport.c` |
| STDLL 세션 상한 | `ncmp/stdll/ncmp_session.c` |
| STDLL 크립토/관리 훅(token_specific) | `usr/lib/ncmp_stdll/ncmp_specific.c`, `tok_struct.h` |
| 크립토 마샬링 어댑터(순수 버퍼) | `ncmp/stdll/ncmp_crypto.c`, `ncmp/include/ncmp/ncmp_crypto.h` |
| 토큰관리 어댑터(정체성/login/PIN) | `ncmp/stdll/ncmp_admin.c`, `ncmp/include/ncmp/ncmp_admin.h` |
| CK슬롯↔물리토큰 바인딩(라벨/시리얼) | `ncmp/common/ncmp_slotmap.c`, `ncmp/include/ncmp/ncmp_slotmap.h` |
| 토큰 정체성 캐시(SHM)·부팅 스캔 | `ncmp/include/ncmp/ncmp_shm.h`(`NCMP_TokenIdentity`), `ncmp/daemon/main.c` |
| 슬롯 매핑 설정 | `usr/lib/ncmp_stdll/ncmptok.conf`, env `NCMP_TOK_LABEL`/`NCMP_TOK_SERIAL` |
| 벤더 와이어 opcode(0x0100+) | `ncmp/include/ncmp/ncmp_cmd.h`, `ncmp/mock/mcu_scheduler.c` |
| 목 데이터패스 | `ncmp/mock/` |
| 테스트 스위트 | `ncmp/tests/` (크립토: `test_crypto.c`, 관리/바인딩: `test_admin.c`, PQC/SHA3/XOF: `test_pqc.c`) |

## 작업 마무리 규약
작업을 끝낼 때마다 진행 상황과 남은 과제를 `.md` 상태 파일로 요약할 것을
사용자에게 권합니다 (예: "지금까지 한 일과 남은 과제를 .md 파일로 요약해줘").

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
| [`command-interface.md`](command-interface.md) | **Command Interface(CI)** 규격. 토큰으로 가는 모든 명령별 request/response 구조체(`CI_*Req`/`CI_*Rsp`)와 필드 설명, 공통 프레임(`CI_Header`/`CI_Message`), ack(CKR_*) 표. `CI_Cmd`는 `enum ncmp_opcode`의 **별칭(alias)** 으로 정의(lockstep). advertised mechanism만 남긴 정리된 opcode 집합 + 신규 조회 CI(`GET_UTC_TIME`/`GET_TOKEN_PARAMS`) + 로그인 flags 포함. |

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

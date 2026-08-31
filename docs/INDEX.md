# 문서 색인 — Token NCMP

토큰 사용량 최적화를 위해 필요한 문서만 골라 읽으세요.

| 문서 | 언제 읽나 |
|------|-----------|
| [`../CLAUDE.md`](../CLAUDE.md) | 항상. 규칙·한계값·빌드/테스트 명령 요약. |
| [`architecture.md`](architecture.md) | 설계 세부가 필요할 때. 시스템 개요, 와이어 프로토콜, SHM, 동시성, in-flight 통계, 데이터 흐름, opencryptoki 통합. |

## 핵심 소스 진입점

| 관심사 | 파일 |
|--------|------|
| 자원 한계 상수 | `ncmp/include/ncmp/ncmp_limits.h` |
| 와이어 프로토콜 | `ncmp/include/ncmp/ncmp_wire.h` |
| MPSC CAS 큐 | `ncmp/include/ncmp/ncmp_queue.h` |
| SHM 레이아웃(오프셋 기반) | `ncmp/include/ncmp/ncmp_shm.h` |
| Robust mutex 래퍼 | `ncmp/include/ncmp/ncmp_mutex.h`, `ncmp/common/ncmp_mutex.c` |
| 데몬 comm/통계 | `ncmp/daemon/comm_thread.c` |
| 2단계 USB 수신 | `ncmp/daemon/usb_transport.c` |
| STDLL 세션 상한 | `ncmp/stdll/ncmp_session.c` |
| 목 데이터패스 | `ncmp/mock/` |
| 테스트 스위트 | `ncmp/tests/` |

## 작업 마무리 규약
작업을 끝낼 때마다 진행 상황과 남은 과제를 `.md` 상태 파일로 요약할 것을
사용자에게 권합니다 (예: "지금까지 한 일과 남은 과제를 .md 파일로 요약해줘").

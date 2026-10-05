# Debug App 배포·시스템 설정 가이드

외부(원격) 호스트에서 브라우저로 ncmpd 공유 메모리를 열람하는 Debug App
(`ncmp_dbg`)의 빌드·실행·시스템 설정. 사용법은
[`debugapp-manual.md`](debugapp-manual.md), 설계는
[`debugapp-design.md`](debugapp-design.md).

> **보안 요약**: ncmpd 내부 상태(슬롯·세션·명령 링)를 네트워크로 노출하며 전송
> 암호화가 없다. 운영에선 ① `NCMP_DBG_TOKEN`(베어러 토큰), ② 신뢰 인터페이스
> bind 또는 SSH 터널, ③ 필요 시 HTTPS 리버스 프록시를 쓸 것. 읽기 전용이지만
> 민감 메타데이터가 보이므로 공용 노출 금지.

## 1. 빌드

```bash
ncmp/gui/debugapp/build.sh            # -> ncmp/gui/debugapp/build/ncmp_dbg
# 또는 CMake(ENABLE_DEBUGAPP 기본 ON)
cd ncmp && cmake -S . -B build -DENABLE_MOCK_TOKEN=ON && cmake --build build -j
#   -> ncmp/build/gui/debugapp/ncmp_dbg
```

의존성: libc, pthread, librt (POSIX SHM). PKCS#11/facade 의존 없음.

## 2. 실행

ncmpd가 **먼저 실행 중**이어야 하고, Debug App은 그 **제어 소켓 경로를 공유**해야
한다(`NCMP_SOCK_PATH` 또는 `--sock`).

```bash
export NCMP_SOCK_PATH=/tmp/ncmpd.sock     # ncmpd가 사용하는 것과 동일하게
ncmp/gui/debugapp/build/ncmp_dbg \
    --host 0.0.0.0 --port 8090 \
    --webroot ncmp/gui/debugapp/web
# 브라우저: http://<서버IP>:8090/
```

| 인자 | env | 설정키 | 기본값 | 설명 |
|------|-----|--------|--------|------|
| `--host` | `NCMP_DBG_HOST` | host | `0.0.0.0` | bind 주소(로컬 전용은 127.0.0.1) |
| `--port` | `NCMP_DBG_PORT` | port | `8090` | TCP 포트 |
| `--webroot` | `NCMP_DBG_ROOT` | webroot | `web` | 정적 UI 디렉토리 |
| `--sock` | `NCMP_SOCK_PATH` | sock | (기본 경로) | ncmpd 제어 소켓(데몬과 일치) |
| — | `NCMP_DBG_TOKEN` | token | (없음) | 설정 시 모든 API에 베어러 토큰 요구 |
| `--config` | `NCMP_DBG_CONFIG` | — | `./.config/config` | 설정 파일 경로 |

우선순위: **내장 기본값 < 설정 파일 < 환경변수 < CLI 인자**. 설정 파일 샘플은
`ncmp/gui/debugapp/.config/config`.

> **Test App과 같은 ncmpd(소켓)를 가리켜야 한다 — 이제 기본값이 일치한다.**
> Debug App은 지정한 소켓의 ncmpd에만 붙는다. Test App(`ncmp_web`)과 Debug App
> (`ncmp_dbg`) **모두 기본 소켓이 `/tmp/ncmpd.sock`** 이라, 둘 다 `--sock` 없이
> 실행하면 **자동으로 같은 ncmpd에 연결**된다(예전 pid별 경로 불일치 문제 해소).
> 다른 경로의 ncmpd(예: systemd `/run/ncmpd/ncmpd.sock`)를 쓸 때만 양쪽에 같은
> `--sock`/`NCMP_SOCK_PATH`를 지정한다. 아래 "실 FX3 + 두 앱 동시 사용" 참고.

## 2.1 실 FX3 + 두 앱(Test App·Debug App) 동시 사용 — 중요

ncmpd는 **시스템 전체에 하나만** 떠야 한다(단일 USB 장치·SHM 소유자). 이제 ncmpd가
기동 시 **전역 배타 락**(`/tmp/ncmpd.lock`, flock; `NCMP_LOCK_PATH`로 변경 가능)을
잡아 **두 번째 기동을 거부**하므로 중복이 원천 차단된다(과거: 둘 이상 뜨면
`slot 0 transport open failed`→`mask=0x0`로 Test App 슬롯이 빈 목록). 따라서 **하나의
ncmpd를 두 앱이 같은 소켓으로 공유**한다 — 두 앱 모두 기본 소켓이 `/tmp/ncmpd.sock`
이라 보통 추가 설정이 필요 없다.

권장 방법 — **기본 소켓 `/tmp/ncmpd.sock` 공유(인자 불필요)**:
```bash
# (A) Test App 실행 → "데몬 시작"이 /tmp/ncmpd.sock에 ncmpd 1개를 띄운다
ncmp_web  --transport real ...        # --sock 생략 → /tmp/ncmpd.sock
# (B) Debug App을 그대로 실행 → 같은 /tmp/ncmpd.sock에 자동 연결
ncmp_dbg  --host 0.0.0.0 --port 8090 --webroot <...>/web   # --sock 생략
```
- 두 앱의 **기본 소켓이 같아** 추가 인자 없이 같은 ncmpd에 붙는다.
- `ncmp_web`의 "데몬 시작"은 **그 소켓에 ncmpd가 이미 있으면 재사용**한다(두 번째
  ncmpd로 FX3를 다투지 않음).
- 다른 경로를 쓰려면 **양쪽에 같은 `--sock`**(또는 `NCMP_SOCK_PATH`)을 지정한다.
- 서로 다른 소켓으로 `ncmp_web`를 두 개 띄우면 ncmpd가 둘 생겨 충돌하므로 **금지**.

## 3. 시스템 설정 (필요 시)

> 특권 변경(방화벽·systemd 설치)은 root 권한이 필요하다. 아래 명령을 그대로
> 실행하면 된다(이 저장소/세션에서는 적용하지 않음).

### 3.1 방화벽 포트 열기
```bash
sudo ufw allow 8090/tcp                                  # ufw
sudo firewall-cmd --permanent --add-port=8090/tcp && sudo firewall-cmd --reload  # firewalld
```
특정 대역만 허용 권장: `sudo ufw allow from 192.168.0.0/24 to any port 8090 proto tcp`.

### 3.2 서비스 등록 (systemd)
`ncmp/gui/debugapp/deploy/ncmp_dbg.service`의 경로·`NCMP_DBG_TOKEN`·
`NCMP_SOCK_PATH`·`User`를 환경에 맞게 고친 뒤:
```bash
sudo cp ncmp/gui/debugapp/deploy/ncmp_dbg.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start ncmp_dbg           # 지금만 실행, 부팅 자동 실행 없음(권장)
# sudo systemctl enable --now ncmp_dbg  # 부팅 자동 실행까지 원할 때만
journalctl -u ncmp_dbg -f
```
`WorkingDirectory`가 설정돼 있어 `./.config/config`가 그 디렉토리에서 로드된다.

> **부팅 자동 실행을 원치 않으면 `enable` 대신 `start`만** 쓴다. 이미 `enable`한
> 것을 해제: `sudo systemctl disable ncmp_dbg`(현재 실행 유지) 또는
> `sudo systemctl disable --now ncmp_dbg`(지금 중지까지). `systemctl is-enabled
> ncmp_dbg`가 `disabled`면 완료.

### 3.3 베어러 토큰 + (권장) HTTPS 리버스 프록시
```bash
export NCMP_DBG_TOKEN="$(head -c 24 /dev/urandom | base64)"
# UI 상단 "서버 토큰" 칸에 동일 값 입력
```
TLS가 필요하면 `--host 127.0.0.1`로 bind하고 nginx/caddy로 앞단 HTTPS를 둔다.

### 3.4 SSH 터널(설정 변경 없이 원격 접속)
```bash
ssh -L 8090:127.0.0.1:8090 user@server     # 서버는 --host 127.0.0.1로 실행
# 브라우저: http://localhost:8090/
```

## 4. 빠른 점검
```bash
curl -s http://<서버IP>:8090/api/status                     # {"connected":true,...}
curl -s -H "Authorization: Bearer $NCMP_DBG_TOKEN" http://<서버IP>:8090/api/status
```

## 5. 트러블슈팅

| 증상 | 원인 / 해결 |
|------|-------------|
| `connected:false` | ncmpd 미기동 또는 `NCMP_SOCK_PATH` 불일치 → 데몬 실행·경로 일치 후 **재연결**. |
| API 401 | `NCMP_DBG_TOKEN` 설정됨 → UI "서버 토큰"에 동일 값 입력. |
| 슬롯 목록 비어 있음 | 온라인 슬롯이 없음(토큰 미연결) 또는 데몬이 아직 probe 중. |
| 토큰 신원 공백(valid=0) | 보드에 NCMP 펌웨어 미적재(부트로더) → 전송·슬롯은 정상, 식별만 미응답. |
| SHM 매핑 실패 | ncmpd와 **같은 사용자**로 실행(POSIX SHM 권한). |

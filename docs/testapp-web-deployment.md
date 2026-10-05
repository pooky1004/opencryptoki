# Web Test App 배포·시스템 설정 가이드

외부(원격) 호스트에서 브라우저로 접속해 Token NCMP를 시험하기 위한 웹 Test App
(`ncmp_web`)의 빌드·실행·시스템 설정 방법. 설계·API는
[`testapp-web-design.md`](testapp-web-design.md), 시험 결과는
[`testapp-web-test-results.md`](testapp-web-test-results.md) 참고.

> **보안 요약**: `ncmp_web`는 모듈 로드·PKCS#11·데몬 실행을 네트워크로 노출하며
> **전송 암호화가 없다**. 운영에 준하는 사용은 ① `NCMP_WEB_TOKEN`(베어러 토큰)
> 설정, ② 신뢰 네트워크/인터페이스로 bind 제한 또는 SSH 터널, ③ 필요 시 HTTPS
> 리버스 프록시를 조합하라. 공용 인터넷에 그대로 노출하지 말 것.

## 1. 빌드

```bash
# 전체(표준 facade/ncmpd + ncmp_web)
ncmp/gui/testapp/build.sh
#   -> ncmp/gui/testapp/build/ncmp_web
# 또는 CMake 트리로(ENABLE_TESTAPP 기본 ON)
cd ncmp && cmake -S . -B build -DENABLE_MOCK_TOKEN=ON && cmake --build build -j
#   -> ncmp/build/gui/testapp/webserver/ncmp_web
```

의존성: libc, pthread, libdl, **OpenSSL libcrypto**(실타겟↔SW 비교용 SW 해시).
facade STDLL은 **런타임 dlopen**이라 빌드 의존이 아니다. 데비안/우분투에서는
`sudo apt install libssl-dev`로 헤더를 설치한다.

## 2. 실행

```bash
REPO=/home/pooky/workspace/opencryptoki
ncmp/gui/testapp/build/ncmp_web \
    --host 0.0.0.0 --port 8080 \
    --webroot   $REPO/ncmp/gui/testapp/web \
    --module    $REPO/ncmp/gui/build-standalone/libpkcs11_ncmp_p11.so \
    --ncmpd     $REPO/ncmp/gui/build-standalone/ncmpd \
    --transport real        # 기본값 real (하드웨어 없으면 mock)
# 브라우저: http://<서버IP>:8080/
```

> **ncmpd는 시스템 전체에 하나만 — 강제됨.** ncmpd는 단일 USB 장치와 공유
> 메모리의 소유자라, 기동 시 **전역 배타 락**(`/tmp/ncmpd.lock`, flock; 환경변수
> `NCMP_LOCK_PATH`로 변경 가능)을 잡는다. 이미 다른 ncmpd가 떠 있으면 두 번째는
> **즉시 거부**(`another ncmpd is already running …`)되고 종료한다(락은 프로세스
> 종료 시 커널이 자동 해제 — 남은 락 파일은 무해). 따라서 `--transport real`
> ncmp_web을 여러 개 띄워도 **FX3를 다투는 두 번째 ncmpd는 생기지 않는다**. 여러
> 클라이언트(ncmp_web·Debug App·facade)는 같은 소켓(기본 `/tmp/ncmpd.sock`)을
> 공유한다 — ncmp_web의 "데몬 시작"은 그 소켓에 ncmpd가 이미 있으면 **재사용**한다.
> Debug App과 함께 쓰는 법은 debugapp-deployment.md §2.1 참고.

### 설정 파일 (`.config/config`)

포트 등 접속 정보를 매번 인자로 넘기지 않도록 **설정 파일**에 저장할 수 있다.
우선순위는 **내장 기본값 < 설정 파일 < 환경변수 < CLI 인자**.

- 탐색 순서: `--config PATH` → `$NCMP_WEB_CONFIG` → `./.config/config`(작업
  디렉토리 기준). 즉 `ncmp/gui/testapp/`에서 실행하면 동봉된 `.config/config`를
  자동으로 읽는다.
- 형식: `key = value`, `#`/`;` 주석, 값에 따옴표 선택. 키:
  `host port webroot module ncmpd transport sock filedir scendir token`.

```ini
# ncmp/gui/testapp/.config/config (발췌)
host = 0.0.0.0
port = 8080
token =                     # 비우면 인증 끔. 운영 시 강한 비밀값 설정
module = ../build-standalone/libpkcs11_ncmp_p11.so
ncmpd  = ../build-standalone/ncmpd
transport = real
filedir = /tmp/ncmp_web_files
```

```bash
# 설정 파일만으로 실행(테스트앱 디렉토리에서)
cd ncmp/gui/testapp && ../../gui/testapp/build/ncmp_web     # ./.config/config 자동 로드
# 또는 임의 위치의 파일 지정
build/ncmp_web --config /etc/ncmp_web.config
```

`GET /api/status`가 로드된 `configPath`·`port`·`authRequired`를 돌려주며, UI
헤더에 함께 표시된다.

인자(모두 env·설정 파일로도 지정 가능):

| 인자 | env | 기본값 | 설명 |
|------|-----|--------|------|
| `--host` | `NCMP_WEB_HOST` | `0.0.0.0` | bind 주소. 로컬 전용은 `127.0.0.1` |
| `--port` | `NCMP_WEB_PORT` | `8080` | TCP 포트 |
| `--webroot` | `NCMP_WEB_ROOT` | `web` | 정적 UI 디렉토리 |
| `--module` | `NCMP_PKCS11_MODULE` | (없음) | 기본 facade `.so` 경로(UI에서 비우면 사용) |
| `--ncmpd` | — | `ncmpd` | 데몬 실행 파일(“데몬 시작”이 exec) |
| `--transport` | — | `real` | 데몬 기본 전송(real/mock/socket). 기본 **real** |
| `--sock` | `NCMP_SOCK_PATH` | `/tmp/ncmpd.sock` | facade↔ncmpd↔Debug App 공유 소켓(기본 고정 경로라 Debug App이 `--sock` 없이 접속). 격리 실행은 명시 지정 |
| `--filedir` | `NCMP_WEB_FILEDIR` | `/tmp/ncmp_web_files` | 생성한 테스트 파일 보관 디렉토리 |
| `--scendir` | `NCMP_WEB_SCENDIR` | `.config/scenarios` | 저장 시나리오(JSON) 보관 디렉토리(영구 저장소 권장) |
| — | `NCMP_WEB_TOKEN` | (없음) | 설정 시 모든 API에 베어러 토큰 요구 |

데몬은 UI의 “데몬 시작/정지”로 `ncmp_web`가 자식 프로세스로 띄우고 같은
`NCMP_SOCK_PATH`를 넘긴다. 이미 외부에서 띄운 ncmpd가 있다면 `--sock`을 그
경로로 맞추고 UI에서 바로 facade를 로드하면 된다.

## 3. 시스템 설정 (필요 시)

> 이 저장소/세션에서는 **특권 변경(방화벽·udev·systemd 설치)을 적용하지
> 않았다**(root 권한 비보유, 되돌리기 어려운 시스템 변경은 사용자 승인 사항).
> 아래 명령을 그대로 실행하면 된다. 현재 호스트 관측치: ufw 설치됨(상태 미확인,
> 기본 비활성 추정), FX3 노드 `189,385`가 world-rw라 실HW 접근은 추가 설정 없이
> 동작, 사용자 `plugdev` 소속.

### 3.1 방화벽에서 포트 열기

```bash
# ufw (Debian/Ubuntu)
sudo ufw allow 8080/tcp
sudo ufw status

# firewalld (RHEL/Fedora)
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --reload

# nftables 직접
sudo nft add rule inet filter input tcp dport 8080 accept
```

방화벽이 비활성이면 `--host 0.0.0.0`만으로 외부 접속이 바로 된다(이 호스트가
그러함). **권장**: LAN 전체가 아니라 특정 대역만 허용하라, 예)
`sudo ufw allow from 192.168.0.0/24 to any port 8080 proto tcp`.

### 3.2 실 FX3 USB 권한 (udev)

`ncmp/gui/testapp/webserver/deploy/70-cypress-fx3.rules`를 설치하면 `plugdev`
그룹이 root 없이 FX3를 연다.

```bash
sudo cp ncmp/gui/testapp/webserver/deploy/70-cypress-fx3.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules && sudo udevadm trigger
sudo usermod -aG plugdev "$USER"   # 로그인 다시 필요
```

### 3.3 서비스 등록 (systemd)

`.../deploy/ncmp_web.service`의 경로/`NCMP_WEB_TOKEN`/`User`를 환경에 맞게 고친 뒤:

```bash
sudo cp ncmp/gui/testapp/webserver/deploy/ncmp_web.service /etc/systemd/system/
sudo systemctl daemon-reload

# (A) 필요할 때만 수동 실행 — 부팅 자동 실행 없음 (권장 기본값)
sudo systemctl start ncmp_web

# (B) 부팅 시 자동 실행까지 원할 때만
sudo systemctl enable --now ncmp_web

systemctl status ncmp_web
journalctl -u ncmp_web -f
```

> **주의**: `enable`은 부팅 시 자동 실행을 등록한다. **자동 실행을 원치 않으면
> `start`만** 쓴다. 이미 `enable`한 것을 **해제(자동 실행 끄기)**:
> ```bash
> sudo systemctl disable ncmp_web        # 부팅 자동 실행만 해제(현재 실행은 유지)
> sudo systemctl disable --now ncmp_web  # 해제 + 지금 바로 중지
> systemctl is-enabled ncmp_web          # -> disabled 이면 완료
> ```
> 이후에도 `sudo systemctl start ncmp_web`로 수동 실행은 가능하다. 디버그 앱
> (`ncmp_dbg`)도 동일하게 `enable` 대신 `start`를 쓰면 자동 실행되지 않는다.

### 3.4 (권장) 베어러 토큰 + HTTPS 리버스 프록시

```bash
export NCMP_WEB_TOKEN="$(head -c 24 /dev/urandom | base64)"   # 강한 비밀값
# UI 상단 "서버 토큰" 칸에 같은 값을 입력하면 모든 API 호출에 자동 첨부된다.
```

TLS가 필요하면 `ncmp_web`를 `127.0.0.1`에 bind하고 nginx/caddy로 앞단 HTTPS를
둔다(예: nginx `location / { proxy_pass http://127.0.0.1:8080; }`,
`proxy_set_header Authorization`로 토큰 주입 가능).

### 3.5 원격 접속만 필요하면 SSH 터널 (설정 변경 없음)

```bash
# 클라이언트에서: 서버의 8080을 로컬 8080으로
ssh -L 8080:127.0.0.1:8080 user@server
# 서버는 --host 127.0.0.1 로 실행. 브라우저: http://localhost:8080/
```

## 4. 빠른 점검

```bash
curl -s http://<서버IP>:8080/api/status            # {"ok":true,...}
curl -s -H "Authorization: Bearer $NCMP_WEB_TOKEN" \
     http://<서버IP>:8080/api/status               # 토큰 설정 시
```

## 5. 트러블슈팅

- **브라우저에서 접속 안 됨**: 방화벽(§3.1) 또는 `--host`가 `127.0.0.1`인지 확인.
- **API가 401**: `NCMP_WEB_TOKEN`이 설정됨 → UI "서버 토큰" 칸에 동일 값 입력.
- **C_Initialize가 rc≠0(예: 0xE0)**: ncmpd 미기동/소켓 경로 불일치. UI의 "데몬
  시작"으로 띄우거나 `--sock`을 외부 ncmpd와 일치시켜라. UNIX 소켓 경로는 108바이트
  미만이어야 한다(너무 긴 경로 금지).
- **두 번째 ncmpd가 안 뜸(`another ncmpd is already running`)**: 정상 동작이다 —
  전역 락(`/tmp/ncmpd.lock`)으로 **시스템 전체 1개**만 허용한다. 기존 ncmpd를
  재사용하거나(같은 소켓 공유), `pgrep -af ncmpd`로 확인 후 기존 것을 멈춘 뒤 다시
  띄운다. 격리 실행이 꼭 필요하면 `NCMP_LOCK_PATH`로 다른 락 경로를 준다.
- **ncmpd는 running인데 활성 슬롯이 빈 목록(실 FX3)**: 과거 중복 ncmpd로 FX3 claim이
  실패하던 증상(`slot 0 transport open failed` / `online slots mask=0x0`). 이제 전역
  락으로 중복 기동이 차단되므로, 남은(좀비) ncmpd가 있는지 `pgrep -af ncmpd`로
  확인하고 정리한 뒤 하나만 띄운다. §2의 "ncmpd는 … 하나만" 참고.
- **실 FX3가 안 보임**: udev 규칙(§3.2)·`plugdev` 소속 확인, `lsusb | grep 04b4:00f1`.

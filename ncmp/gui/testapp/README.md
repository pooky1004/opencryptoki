# Token NCMP — Web Test App (브라우저 GUI + C 웹서버)

PKCS#11 Token NCMP를 **웹 브라우저로 조작·검증**하는 Test App. 외부 호스트에서
접속할 수 있다. GUI는 웹(정적 HTML/CSS/JS), Application 계층은 C(`ncmp_web`,
`libncmp_testapp` 로직 포함).

```
브라우저 ─HTTP/JSON─▶ ncmp_web(C) ─app_*─▶ dlopen/dlsym C_* ─▶
    libpkcs11_ncmp.so(facade) ─▶ ncmp_client ─▶ IPC+SHM ─▶ ncmpd ─comm thread─▶ 실 FX3(USB)
```

- `native/` — C 애플리케이션 ABI(`ncmp_testapp.h/.c`, app_* 18종). facade를
  런타임 dlopen.
- `webserver/` — `ncmp_web.c`(의존성 없는 HTTP/JSON 서버) + `deploy/`(systemd
  유닛, FX3 udev 규칙).
- `web/` — 정적 UI: 좌=활성 슬롯, 우=탭(토큰 정보 · 세션/로그인 · 암복호화/해시 ·
  **파일/검증** · **PKCS#11 API 시험** · **시나리오**), 상단=ncmpd 실행·상태.
  "파일/검증"은 크기 입력→테스트 파일 생성(init/update/final 시험용 ≥64KB)과
  실 타겟 multipart 해시 ↔ SW(OpenSSL) 비교(MATCH/MISMATCH)를 제공.
- `build.sh` — gcc로 `ncmp_web`(+ facade/ncmpd) 빌드/실행.

의존성: libc/pthread/dl + **OpenSSL libcrypto**(SW 해시). 데비안/우분투:
`sudo apt install libssl-dev`.

## 빠른 시작

```bash
./build.sh                    # facade/ncmpd + ncmp_web 빌드
# 또는 CMake: cd ../../.. ; cd ncmp && cmake -S . -B build -DENABLE_MOCK_TOKEN=ON && cmake --build build -j
REPO=$(git rev-parse --show-toplevel)
build/ncmp_web --host 0.0.0.0 --port 8080 --webroot web \
    --module $REPO/ncmp/gui/build-standalone/libpkcs11_ncmp_p11.so \
    --ncmpd  $REPO/ncmp/gui/build-standalone/ncmpd --transport mock
# 브라우저: http://<서버IP>:8080/  → 데몬 시작 → 로드 → C_Initialize → 슬롯 선택
```

설계·API·시험결과·배포(방화벽/udev/systemd/토큰):
- [`docs/testapp-web-design.md`](../../../docs/testapp-web-design.md)
- [`docs/testapp-web-deployment.md`](../../../docs/testapp-web-deployment.md)
- [`docs/testapp-web-test-results.md`](../../../docs/testapp-web-test-results.md)

> 보안: API는 모듈 로드·PKCS#11·데몬 실행을 네트워크로 노출한다. `NCMP_WEB_TOKEN`
> (베어러 토큰) + bind 제한/SSH 터널/HTTPS 프록시를 사용하라. 공용 노출 금지.

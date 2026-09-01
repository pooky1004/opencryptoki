# STDLL 호출 흐름 — 표준 opencryptoki 경로

애플리케이션이 세션을 열고 암호화를 수행하는 전 구간을 코드 레벨로 추적한
문서다. 앱은 **opencryptoki 표준 3층 구조**(API 층 → STDLL(new_host) →
token_specific)를 타고 `libpkcs11_ncmp.so`에 도달한다.

## 1. 전체 그림

```
App ──링크──> libopencryptoki.so            (API 층: usr/lib/api/)
                    │  C_*  →  슬롯별 FcnList 의 ST_* 를 함수포인터로 호출
                    ▼
             libpkcs11_ncmp.so               (STDLL: usr/lib/common/new_host.c)
                    │  SC_*  →  공통 mgr(mech_aes 등)  →  token_specific.t_* 훅
                    ▼
             ncmp_specific.c                  (token_specific 구현: proxy)
                    │  ncmp_client_command_mp(NCMP_CMD_AES_ECB, [flags,key,data])
                    ▼
             ncmpd  (UNIX socket + SHM robust 큐)  ──USB / mock──>  FX3
```

핵심 성질:

- **함수 포인터 2단 디스패치.** 앱이 부르는 `C_Encrypt`(API 층)는 슬롯별
  `FcnList->ST_Encrypt`(= new_host 의 `SC_Encrypt`)를 간접 호출하고, 공통층은
  다시 `token_specific.t_aes_ecb` 훅으로 분기한다.
- **`pkcsslotd` 는 데이터 경로 밖.** 초기화 때 슬롯 구성(`opencryptoki.conf`)
  제공 + 전역 SHM 생성만 담당한다. 암·복호 왕복에는 관여하지 않는다.
- **상태 소유권은 STDLL 프로세스 로컬.** 세션·객체·로그인·키 원문은
  `STDLL_TokData_t`(세션표·객체 template) 안에 있고, 매 연산마다 키 원문을
  토큰으로 실어 보내는 **프록시 모델**이다. ncmpd/FX3 는 상태를 거의 안 가진다.

## 2. 0단계 — `C_Initialize`: STDLL 로드 지점

앱이 `C_Initialize` 를 부르면 API 층이 `pkcsslotd` 에 UNIX 소켓
(`usr/lib/api/socket_client.c`)으로 접속해 `opencryptoki.conf` 의 슬롯 구성
(슬롯 5 → `libpkcs11_ncmp.so`, `confname = ncmptok.conf`)을 받는다. 그다음
슬롯마다 `DL_Load_and_Init()`(`usr/lib/api/apiutil.c:723`)이 실행된다.

| 단계 | 위치 | 하는 일 |
|------|------|---------|
| dlopen | `apiutil.c:632` | `dlopen(sinfp->dll_location, ...)` 로 STDLL 로드 |
| 심볼 조회 | `apiutil.c:831` | `dlsym(..., "ST_Initialize")` — STDLL 의 유일 진입점 |
| 초기화 호출 | `apiutil.c:838` | `pSTinit(sltp, slotID, sinfp, trace)` |
| 성공 표시 | `apiutil.c:847` | `sltp->DLLoaded = TRUE` |

`ST_Initialize`(`usr/lib/common/new_host.c`)가 하는 핵심 두 가지:

1. `sltp->FcnList = &function_list` — 이때 `function_list.ST_OpenSession =
   SC_OpenSession`, `function_list.ST_EncryptInit = SC_EncryptInit`,
   `function_list.ST_Encrypt = SC_Encrypt` 등 **SC_\* 함수테이블**이 채워진다
   (`new_host.c:4551`, `4567`, `4568`).
2. `sltp->TokData` — 이 슬롯의 **프로세스 로컬 상태**(`STDLL_TokData_t`:
   세션표·객체·로그인·`private_data`)를 할당. `token_specific.t_init`(=
   `ncmp_token_specific_init`)이 여기서 ncmpd 클라이언트 연결과 물리 슬롯
   (`priv->ncmp_slot`)을 세팅한다.

## 3. 1단계 — `C_OpenSession`

`usr/lib/api/api_interface.c` 의 `C_OpenSession`:

1. `API_Initialized()` 확인
2. `sltp = &Anchor->SltList[slotID]`, `sltp->DLLoaded` 확인
3. `fcn->ST_OpenSession(sltp->TokData, ...)` → new_host 의
   `SC_OpenSession`(`new_host.c:1040`)

`SC_OpenSession` 은 공통 `session_mgr_new()` 로 **호스트 측 세션 객체**를 만들고
핸들을 반환한다. 표준 모델에서 세션은 원칙적으로 호스트 개념이라 토큰 왕복이
필수는 아니다. (NCMP 변형은 `token_specific` 의 open_session 훅에서
`ncmp_session_open` 으로 프로세스 간 세션 상한을 SHM robust 카운터로 예약할 수
있다.)

반환된 `hSession` 은 API 층이 `(slotID, STDLL 세션핸들)` 쌍으로 매핑하며, 이후
모든 호출은 `Valid_Session(hSession, &rSession)`(`api_interface.c:1540`)로 이
쌍을 복원한다.

## 4. 2단계 — `C_EncryptInit`

`C_EncryptInit`(`api_interface.c:1629`) → `Valid_Session` 으로 slotID 복원 →
`fcn->ST_EncryptInit` → `SC_EncryptInit`(`new_host.c:2232`):

- `session_mgr_find_reset_error` 로 세션 조회, PIN 만료·mech 유효성
  (`valid_mech`) 검사
- `encr_mgr_init(... &sess->encr_ctx ...)` — **mech 와 키 핸들을 세션의
  `encr_ctx` 에 저장**만 한다

AES-ECB/CBC 같은 블록 암호는 이 시점에 토큰으로 내려가지 않는다(호스트 측
컨텍스트 세팅만). GCM 은 `token_specific_aes_gcm_init`(`ncmp_specific.c:567`)이
파라미터 유효성만 확인하고 상태를 만들지 않는다(프록시 토큰이라 per-init 상태
불필요).

## 5. 3단계 — `C_Encrypt`: 실제 토큰 왕복

`C_Encrypt`(`api_interface.c:1524`) → `fcn->ST_Encrypt` →
`SC_Encrypt`(`new_host.c:2290`) 이후 공통 mgr → token_specific 훅으로 내려간다:

| # | 위치 | 하는 일 |
|---|------|---------|
| 1 | `new_host.c:2317` | `encr_ctx.active` 확인 후 `encr_mgr_encrypt(...)` |
| 2 | `mech_aes.c:30` | mech 분기 → `aes_ecb_encrypt` |
| 3 | `mech_aes.c:4010` | `ckm_aes_ecb_encrypt` |
| 4 | `mech_aes.c:4028` | `token_specific.t_aes_ecb == NULL` 확인 |
| 5 | `mech_aes.c:4033` | `token_specific.t_aes_ecb(...)` 호출 |
| 6 | `ncmp_specific.c:519` | `token_specific_aes_ecb` — 여기서 ncmpd 로 나감 |

`token_specific_aes_ecb`(`usr/lib/ncmp_stdll/ncmp_specific.c:519`) 요지:

```c
struct ncmp_private_data *priv = tokdata->private_data;   /* ST_Initialize 에서 세팅 */
template_attribute_get_non_empty(key->template, CKA_VALUE, &key_attr); /* 키 원문 추출 */
ncmp_wr_u32le(flags, encrypt ? NCMP_AES_FLAG_ENCRYPT : 0u);
parts[0] = flags;            /* [0] 모드 플래그 */
parts[1] = key_attr->pValue; /* [1] 키 원문   */
parts[2] = in_data;          /* [2] 평문      */
ncmp_client_command_mp(&priv->client, priv->ncmp_slot,
                       NCMP_CMD_AES_ECB, parts, lens, 3, out_data, ...);
if (rsp.header.ack != NCMP_CKR_OK) return (CK_RV)rsp.header.ack;  /* ack → CK_RV */
```

`ncmp_client_command_mp`(`ncmp/stdll/ncmp_client.c`)가 와이어 프레임을 만들어
UNIX 소켓으로 ncmpd 에 보내고, ncmpd 는 SHM robust 큐(CAS 상태전이) + 슬롯별
comm 스레드 → USB(또는 mock)로 전달한다. 응답의 `ack`(CKR_\*)를 되돌려 받아
`ncmp_specific.c:558` 에서 `CK_RV` 로 변환해 올려보낸다.

> 이 지점부터 **STDLL → ncmpd → USB** 전송 1홉의 세부(요청 인코딩, MPSC CAS 큐
> 전이, FX3 단발 프레임 수신, in-flight 예약/해제)는
> [`architecture.md` §9 데이터 흐름](architecture.md#9-데이터-흐름-요청-1건) 참고.

결과는 역순으로
`ckm_ → mech_aes → encr_mgr → SC_Encrypt → ST_Encrypt → C_Encrypt` 로 전파되어
앱에 리턴된다.

## 6. 관련 소스 진입점

| 관심사 | 파일:라인 |
|--------|-----------|
| API `C_Encrypt`/`C_EncryptInit`/`C_OpenSession` | `usr/lib/api/api_interface.c:1524`, `:1629` |
| STDLL 로드/`ST_Initialize` 호출 | `usr/lib/api/apiutil.c:632`, `:831`, `:838` |
| SC_* 함수테이블 등록 | `usr/lib/common/new_host.c:4551`, `:4567`, `:4568` |
| `SC_OpenSession`/`SC_EncryptInit`/`SC_Encrypt` | `usr/lib/common/new_host.c:1040`, `:2232`, `:2290` |
| 공통 AES → token_specific 훅 | `usr/lib/common/mech_aes.c:4010`, `:4028`, `:4033` |
| token_specific AES 프록시 | `usr/lib/ncmp_stdll/ncmp_specific.c:519` (ECB), `:567` (GCM) |
| ncmp 전송층 | `ncmp/stdll/ncmp_client.c` (`ncmp_client_command_mp`) |

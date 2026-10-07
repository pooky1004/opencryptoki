/*
 * Token NCMP - Web Test App frontend.
 *
 * Talks to the C web server (ncmp_web) over JSON. Three testing surfaces:
 *   - the per-slot tabs (token / session / crypto) for ad-hoc use,
 *   - "PKCS#11 API 시험": run a single unit API item with chosen params,
 *   - "시나리오": compose unit items into a scenario (with variables + pass/fail
 *     assertions), run it, and see per-step results; save/load/export.
 */
'use strict';

/* ------------------------------------------------------------------ */
/* Core: fetch wrapper + helpers                                      */
/* ------------------------------------------------------------------ */

const $ = (sel) => document.querySelector(sel);
const el = (tag, props = {}, ...kids) => {
  const e = Object.assign(document.createElement(tag), props);
  for (const k of kids) e.append(k);
  return e;
};

let SELECTED_SLOT = null;
let SLOT_TYPES = {};   // slot id -> hsm_type (0=NCMP,1=PEM)
let CUR_SESSION = null;          // local facade handle of the active session
let SESSIONS = [];               // [{handle, label, sid}] opened/adopted sessions

/* Command defaults panel (token-info tab): push PIN / user type / R/W / session
 * id into the per-tab command inputs. Applied on edit, on "적용", and at
 * C_Initialize. */
function applyDefaults() {
  const ut = $('#defUserType'), pin = $('#defPin'), soPin = $('#defSoPin');
  const rw = $('#defRw');
  if (!ut) return;
  if ($('#userType')) $('#userType').value = ut.value;
  // SO(0) uses SO PIN; User(1)/ContextSpecific(2) use the user PIN.
  if ($('#pin')) $('#pin').value = (ut.value === '0' ? soPin.value : pin.value);
  if ($('#rwSession')) $('#rwSession').checked = rw.checked;
}

function setSessionText() {
  const t = $('#sessionText'); if (!t) return;
  if (CUR_SESSION === null) { t.textContent = '세션 없음'; return; }
  const s = SESSIONS.find((x) => x.handle === CUR_SESSION);
  t.textContent = `현재 세션 ${s ? s.label : ('h' + CUR_SESSION)} · 활성 ${SESSIONS.length}개`;
}
// Fill every session picker (.sessionPicker) with the active sessions; all
// per-session commands use the selected one (CUR_SESSION).
function renderSessionPickers() {
  document.querySelectorAll('.sessionPicker').forEach((sel) => {
    sel.innerHTML = SESSIONS.length
      ? SESSIONS.map((s) => `<option value="${s.handle}">${s.label} · handle ${s.handle}</option>`).join('')
      : '<option value="">(열린 세션 없음)</option>';
    if (CUR_SESSION !== null) sel.value = String(CUR_SESSION);
    sel.onchange = () => {
      CUR_SESSION = sel.value === '' ? null : Number(sel.value);
      document.querySelectorAll('.sessionPicker').forEach((o) => { if (CUR_SESSION !== null) o.value = String(CUR_SESSION); });
      setSessionText();
      if (CUR_SESSION !== null) sessionInfo();
    };
  });
}
function addSession(handle, label, meta = {}) {
  SESSIONS.push({
    handle, label,
    type: meta.type || '-', sid: (meta.sid === undefined ? null : meta.sid),
    slot: (meta.slot === undefined ? null : meta.slot),
    openedAt: Date.now(),
    count: 0, lastCmd: '-', lastAt: null, lastOk: null, state: null,
  });
  CUR_SESSION = handle; renderSessionPickers(); setSessionText(); renderSessionsTab();
  refreshSessMap();
}
function removeSession(handle) {
  SESSIONS = SESSIONS.filter((s) => s.handle !== handle);
  CUR_SESSION = SESSIONS.length ? SESSIONS[SESSIONS.length - 1].handle : null;
  renderSessionPickers(); setSessionText(); renderSessionsTab();
  refreshSessMap();
}
/* Record the last command issued on a session (updates the 활성 세션 tab). */
function touchSession(handle, cmd, ok) {
  const s = SESSIONS.find((x) => x.handle === handle);
  if (!s) return;
  s.count++; s.lastCmd = cmd; s.lastAt = Date.now(); s.lastOk = ok;
  renderSessionsTab();
}
function fmtTime(ms) { return ms ? new Date(ms).toTimeString().slice(0, 8) : '-'; }
function fmtAgo(ms) {
  if (!ms) return '-';
  const s = Math.floor((Date.now() - ms) / 1000);
  if (s < 60) return s + '초';
  const m = Math.floor(s / 60); if (m < 60) return m + '분 ' + (s % 60) + '초';
  return Math.floor(m / 60) + '시간 ' + (m % 60) + '분';
}
const ROLE_NAME = { 1: 'User', 0: 'SO', 2: 'ContextSpecific' };
function renderSessionsTab() {
  const tb = document.querySelector('#sessTable tbody'); if (!tb) return;
  tb.innerHTML = '';
  const empty = $('#sessEmpty');
  if (empty) empty.style.display = SESSIONS.length ? 'none' : '';
  SESSIONS.forEach((s, i) => {
    const tr = el('tr', {});
    if (s.handle === CUR_SESSION) tr.className = 'cur';
    const td = (v, cls) => el('td', cls ? { className: cls, textContent: String(v) } : { textContent: String(v) });
    // No
    tr.append(td(i + 1));
    // 세션 ID: wire session_id when adopted, else the local handle (h<n>);
    // include the slot since session ids may differ per slot.
    const sidText = (s.sid !== null && s.sid !== undefined) ? String(s.sid) : ('h' + s.handle);
    const slotText = (s.slot === null || s.slot === undefined) ? '' : ` · slot ${s.slot}`;
    tr.append(td(sidText + slotText + (s.handle === CUR_SESSION ? ' ●' : '')));
    // 역할: logged-in role, else 종류(open/adopt)
    tr.append(td(s.role ? ROLE_NAME[s.role] || s.role : (s.type === '-' ? '-' : s.type)));
    // 관리
    const act = el('td', {});
    const bSel = el('button', { className: 'link', textContent: '선택' });
    bSel.onclick = () => { CUR_SESSION = s.handle; renderSessionPickers(); setSessionText(); renderSessionsTab(); };
    const bClose = el('button', { className: 'link', textContent: '닫기' });
    bClose.onclick = async () => { const d = await api('/api/session/close', 'POST', { session: s.handle }); log(`세션(handle ${s.handle}) 닫기: ${describe(d)}`); removeSession(s.handle); };
    act.append(bSel, ' ', bClose);
    tr.append(act);
    tb.append(tr);
  });
  const sum = $('#sessSummary');
  if (sum) sum.textContent = `활성 세션 ${SESSIONS.length}개` + (CUR_SESSION !== null ? ` · 현재 handle ${CUR_SESSION}` : '');
}
/* Show the session map for the selected slot. Two sources merged:
 *  - open   : ncmpd's live (pid, app_sid) -> hsm_sid map (C_OpenSession), read
 *             from SHM via /api/sessmap;
 *  - adopt  : local adopt sessions (NCMP_OpenSessionWithId) have no token OPEN,
 *             so the wire sid is used directly (hsm_sid == app_sid). */
async function refreshSessMap() {
  const tb = document.querySelector('#sessMapTable tbody'); if (!tb) return;
  tb.innerHTML = '';
  const rows = [];
  if (SELECTED_SLOT !== null) {
    const d = await api('/api/sessmap', 'POST', { slot: SELECTED_SLOT });
    if (d && d.ok && d.entries)
      for (const e of d.entries)
        rows.push({ kind: 'open', pid: e.pid, app: e.appSid, hsm: e.hsmSid });
  }
  /* Render numeric ids (pid, app_sid, hsm_sid) in hex (0x…). */
  const hex = (v) => {
    const n = Number(v);
    return Number.isFinite(n) ? '0x' + (n >>> 0).toString(16).toUpperCase() : String(v);
  };
  for (const r of rows) {
    tb.append(el('tr', {},
      el('td', { textContent: r.kind }),
      el('td', { textContent: hex(r.pid) }),
      el('td', { textContent: hex(r.app) }),
      el('td', { textContent: hex(r.hsm) })));
  }
  const empty = $('#sessMapEmpty');
  if (empty) empty.style.display = rows.length ? 'none' : '';
}
async function refreshSessionStates() {
  for (const s of SESSIONS) {
    const d = await api('/api/session/info', 'POST', { session: s.handle });
    s.state = d.ok ? `${d.session.state} (flags 0x${d.session.flags.toString(16)})` : `err rc=${d.rc}`;
  }
  renderSessionsTab();
}

function authToken() { return $('#authToken').value.trim(); }

/* ---- theme (light / dark) ---------------------------------------- */
function applyTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  try { localStorage.setItem('ncmp_theme', t); } catch { /* private mode */ }
  const btn = $('#themeToggle');
  if (btn) btn.textContent = (t === 'light') ? '🌙 다크' : '☀️ 라이트';
}
function initTheme() {
  let t = null;
  try { t = localStorage.getItem('ncmp_theme'); } catch { /* ignore */ }
  if (!t) t = (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) ? 'light' : 'dark';
  applyTheme(t);
}
function toggleTheme() {
  applyTheme(document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light');
}

async function api(path, method = 'GET', body = null) {
  const headers = {};
  if (body) headers['Content-Type'] = 'application/json';
  const t = authToken();
  if (t) headers['Authorization'] = 'Bearer ' + t;
  const res = await fetch(path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  let data;
  try { data = await res.json(); }
  catch { data = { rc: -99, ok: false, error: 'invalid JSON (HTTP ' + res.status + ')' }; }
  return data;
}

function log(msg) {
  const now = new Date().toTimeString().slice(0, 8);
  const node = $('#log');
  node.textContent += `[${now}] ${msg}\n`;
  node.scrollTop = node.scrollHeight;
}

function describe(d) {
  if (!d) return '(no response)';
  if (d.ok) return 'OK';
  return `rc=${d.rc} ${d.error || ''}`.trim();
}

/* ------------------------------------------------------------------ */
/* Status polling + daemon / facade lifecycle                         */
/* ------------------------------------------------------------------ */

/* Factory-default PINs differ by backend: the real token uses 12345678/87654321
 * (reference firmware), the mock uses 1234/12345678. Keep the "명령 기본값" PINs
 * in sync with the running transport unless the user set custom ones (i.e. the
 * current pair still matches one of the known factory pairs). */
const PIN_DEFAULTS = {
  real: { user: '12345678', so: '87654321' },
  mock: { user: '1234', so: '12345678' },
};
function syncPinDefaults(transport) {
  const want = PIN_DEFAULTS[transport];
  if (!want) return;
  const dp = $('#defPin'), ds = $('#defSoPin');
  if (!dp || !ds) return;
  const isFactory = Object.values(PIN_DEFAULTS)
    .some((p) => p.user === dp.value && p.so === ds.value);
  if (!isFactory) return;                 /* user customised - leave as is */
  if (dp.value === want.user && ds.value === want.so) return;
  dp.value = want.user;
  ds.value = want.so;
  applyDefaults();                        /* propagate to the login tab inputs */
  log(`PIN 기본값을 ${transport} 토큰 값으로 설정 (User ${want.user} / SO ${want.so})`);
}

async function refreshStatus() {
  try {
    const s = await api('/api/status');
    const on = s.daemonRunning;
    $('#daemonDot').className = 'dot ' + (on ? 'on' : 'off');
    $('#daemonText').textContent = on
      ? `ncmpd 실행 중 (${s.transport})`
      : 'ncmpd 정지됨';
    if (s.transport) syncPinDefaults(s.transport);
    if (s.configPath !== undefined)
      $('#cfgInfo').textContent =
        `· cfg: ${s.configPath || '(none)'} · :${s.port}${s.authRequired ? ' · 🔒' : ''}`;
    if (s.defaultModule && !$('#modulePath').value)
      $('#modulePath').placeholder = s.defaultModule + ' (서버 기본값)';
  } catch {
    $('#daemonDot').className = 'dot off';
    $('#daemonText').textContent = '서버 연결 안 됨';
  }
}

async function daemonStart() {
  const d = await api('/api/daemon/start', 'POST', { transport: $('#transport').value });
  log('데몬 시작: ' + describe(d) + (d.pid ? ` (pid ${d.pid})` : ''));
  // Wait until the daemon has actually bound its socket before the user loads
  // the facade. The real FX3 probe (token identity scan) can take several
  // seconds, so poll rather than assume it is ready immediately.
  $('#daemonText').textContent = 'ncmpd 준비 대기 중…';
  for (let i = 0; i < 40; i++) {
    const s = await api('/api/status');
    if (s.daemonRunning) { log('ncmpd 준비됨'); break; }
    await new Promise((r) => setTimeout(r, 250));
  }
  refreshStatus();
}
async function daemonStop() {
  await api('/api/daemon/stop', 'POST', {});
  log('데몬 정지 요청');
  refreshStatus();
}
async function loadModule() {
  const d = await api('/api/load', 'POST', { module: $('#modulePath').value.trim() });
  log('facade 로드: ' + describe(d));
}
async function initialize() {
  const d = await api('/api/initialize', 'POST', {});
  log('C_Initialize: ' + describe(d));
  if (d.ok) {
    applyDefaults();   // seed command inputs from the 명령 기본값 panel
    log('명령 기본값 적용: 사용자=' + $('#defUserType').value + ', R/W=' + $('#defRw').checked);
    const lib = await api('/api/library');
    if (lib.ok && lib.info)
      $('#libInfo').textContent =
        `Cryptoki ${lib.info.cryptokiVersion} · ${lib.info.manufacturer} · ${lib.info.libDescription} (v${lib.info.libVersion})`;
    await refreshSlots();
    // No session is opened automatically; use 세션 관리에서 "새 세션" 또는
    // "ID로 추가"(세션 ID 0 포함)로 직접 연다.
  }
}
async function finalize() {
  const d = await api('/api/finalize', 'POST', {});
  log('C_Finalize: ' + describe(d));
  $('#libInfo').textContent = '';
  $('#slotList').innerHTML = '';
  SELECTED_SLOT = null;
}
async function dlsymReport() {
  const d = await api('/api/dlsym');
  if (d.ok && d.report) {
    const found = Object.values(d.report).filter(Boolean).length;
    log(`dlsym 점검: ${found}/${Object.keys(d.report).length} 함수 확인`);
  } else log('dlsym 점검 실패: ' + describe(d));
}

/* ------------------------------------------------------------------ */
/* Slots + per-slot tabs                                              */
/* ------------------------------------------------------------------ */

async function refreshSlots() {
  const d = await api('/api/slots');
  const ul = $('#slotList');
  ul.innerHTML = '';
  if (!d.ok) { log('슬롯 조회 실패: ' + describe(d)); return; }
  log(`활성 슬롯 ${d.slots.length}개: [${d.slots.join(', ')}]`);
  SLOT_TYPES = d.slotTypes || {};
  for (const id of d.slots) {
    const pem = Number(SLOT_TYPES[id]) === 1;
    const li = el('li', { textContent: `Slot ${id}` + (pem ? ' \u00b7 PEM' : '') });
    li.onclick = () => selectSlot(id, li);
    ul.append(li);
  }
  if (d.slots.length) ul.firstChild.click();
}

function slotIsPem(id) { return Number(SLOT_TYPES[id]) === 1; }
function selectSlot(id, li) {
  SELECTED_SLOT = id;
  /* Sessions are facade-global; keep them across slot selection. */
  document.querySelectorAll('#slotList li').forEach((n) => n.classList.remove('sel'));
  li.classList.add('sel');
  // keep the API tester's slot field in sync
  const sf = document.querySelector('#apiParams [data-pk="slot"]');
  if (sf) sf.value = id;
  /* PEM slot -> reveal + switch to the PEM CI console; NCMP slot -> hide it. */
  const pem = slotIsPem(id);
  const nav = $('#navPemci');
  if (nav) nav.hidden = !pem;
  if (pem) { pemVisibility(); switchTab('pemci'); }
  else if (document.querySelector('.navitem[data-tab="pemci"].active')) switchTab('session');
}

async function tokenInfo() {
  if (SELECTED_SLOT === null) return log('먼저 슬롯을 선택하세요');
  const t = await api('/api/token', 'POST', { slot: SELECTED_SLOT });
  if (!t.ok) return log('C_GetTokenInfo 실패: ' + describe(t));
  const ti = t.token;
  $('#tokenInfo').textContent =
    `label        : ${ti.label}\nmanufacturer : ${ti.manufacturer}\nmodel        : ${ti.model}\n` +
    `serial       : ${ti.serial}\nflags        : 0x${ti.flags.toString(16)}\n` +
    `PIN len      : ${ti.minPin}..${ti.maxPin}\nmax sessions : ${ti.maxSession}\n` +
    `HW / FW ver  : ${ti.hwVersion} / ${ti.fwVersion}`;
  const m = await api('/api/mechanisms', 'POST', { slot: SELECTED_SLOT });
  const ul = $('#mechList'); ul.innerHTML = '';
  if (m.ok) for (const me of m.mechanisms)
    ul.append(el('li', { textContent: `${me.name}  (code ${me.code})` }));
  log(`슬롯 ${SELECTED_SLOT}: 토큰 정보 + ${m.ok ? m.mechanisms.length : 0} 메커니즘`);
}

async function openSession() {
  if (SELECTED_SLOT === null) return log('먼저 슬롯을 선택하세요');
  $('#sessionText').textContent = '세션 여는 중… (실 타겟 OPEN_SESSION은 수십 초 걸릴 수 있음)';
  log(`슬롯 ${SELECTED_SLOT}: C_OpenSession 요청…`);
  setSessionText();
  log(`슬롯 ${SELECTED_SLOT}: C_OpenSession 요청…`);
  const d = await api('/api/session/open', 'POST', { slot: SELECTED_SLOT, rw: $('#rwSession').checked ? 1 : 0 });
  if (!d.ok) return log('C_OpenSession 실패: ' + describe(d) +
    ' — ncmpd/FX3 연결과 데몬 상태를 먼저 확인하세요. (펌웨어가 OPEN_SESSION을 아예 미지원하는 경우에 한해 "ID로 추가"(adopt)로 우회 — 단 adopt는 토큰 통신이 없습니다.)');
  addSession(d.session, `열림(C_OpenSession)`, { type: 'open', slot: SELECTED_SLOT });
  await sessionInfo();
  log(`슬롯 ${SELECTED_SLOT}: 세션 ${d.session} 열림`);
}

async function closeSession() {
  if (CUR_SESSION === null) return log('닫을 세션이 없습니다');
  const h = CUR_SESSION;
  const d = await api('/api/session/close', 'POST', { session: h });
  log(`세션(handle ${h}) 닫기: ${describe(d)}`);
  removeSession(h);
  $('#sessionInfo').textContent = '';
}
async function sessionInfo() {
  if (CUR_SESSION === null) return;
  const d = await api('/api/session/info', 'POST', { session: CUR_SESSION });
  if (d.ok) $('#sessionInfo').textContent =
    `slot ${d.session.slot}, state ${d.session.state}, flags 0x${d.session.flags.toString(16)}, deviceError ${d.session.deviceError}`;
}
const NO_SESS = '먼저 세션을 여세요 — 세션/로그인 탭에서 "세션 열기" 또는 "ID로 세션 열기", 그리고 활성 세션을 선택하세요.';
async function login() {
  if (CUR_SESSION === null) { $('#sessionInfo').textContent = NO_SESS; return log('C_Login: ' + NO_SESS); }
  const h = CUR_SESSION;
  $('#sessionInfo').textContent = `C_Login 전송 중… (handle ${h}) — 실 타겟은 수십 초 걸릴 수 있습니다`;
  log(`C_Login 전송(handle ${h})…`);
  const role = Number($('#userType').value);
  const d = await api('/api/login', 'POST', { session: h, userType: role, pin: $('#pin').value });
  touchSession(h, 'C_Login', d.ok);
  log('C_Login: ' + describe(d));
  if (d.ok) {
    const s = SESSIONS.find((x) => x.handle === h); if (s) s.role = role;
    setSessionText(); sessionInfo(); renderSessionsTab();
  } else { $('#sessionInfo').textContent = 'C_Login 실패: ' + describe(d); }
}
async function logout() {
  if (CUR_SESSION === null) { $('#sessionInfo').textContent = NO_SESS; return log('C_Logout: ' + NO_SESS); }
  const h = CUR_SESSION;
  $('#sessionInfo').textContent = `C_Logout 전송 중… (handle ${h})`;
  const d = await api('/api/logout', 'POST', { session: h });
  touchSession(h, 'C_Logout', d.ok);
  log('C_Logout: ' + describe(d));
  if (d.ok) {
    const s = SESSIONS.find((x) => x.handle === h); if (s) s.role = null;
    setSessionText(); sessionInfo(); renderSessionsTab();
  } else { $('#sessionInfo').textContent = 'C_Logout 실패: ' + describe(d); }
}
async function genRandom() {
  if (CUR_SESSION === null) { $('#rngOut').textContent = NO_SESS; return log('C_GenerateRandom: ' + NO_SESS); }
  const h = CUR_SESSION;
  $('#rngOut').textContent = `C_GenerateRandom 전송 중… (handle ${h})`;
  const d = await api('/api/random', 'POST', { session: h, length: Number($('#randLen').value) });
  touchSession(h, 'C_GenerateRandom', d.ok);
  $('#rngOut').textContent = d.ok ? `C_GenerateRandom(${d.length}) =\n${hexWrap(d.hex)}` : '오류: ' + describe(d);
}
async function doDigest() {
  if (CUR_SESSION === null) { $('#hashOut').textContent = NO_SESS; return log('C_Digest: ' + NO_SESS); }
  const h = CUR_SESSION;
  $('#hashOut').textContent = `C_Digest 전송 중… (handle ${h})`;
  const d = await api('/api/digest', 'POST', { session: h, mech: Number($('#digestMech').value), input: $('#digestInput').value });
  touchSession(h, 'C_Digest', d.ok);
  $('#hashOut').textContent = d.ok ? `digest [${d.length}B] =\n${hexWrap(d.hex)}` : '오류: ' + describe(d);
}
async function gcmSelftest() {
  if (CUR_SESSION === null) { $('#gcmOut').textContent = NO_SESS; return log('AES-GCM: ' + NO_SESS); }
  const h = CUR_SESSION;
  $('#gcmOut').textContent = `AES-GCM 자가검증 전송 중… (handle ${h})`;
  const d = await api('/api/gcm-selftest', 'POST', { session: h });
  touchSession(h, 'AES-GCM selftest', d.ok);
  $('#gcmOut').textContent = (d.ok ? 'AES-GCM 자가검증 OK — ' : '실패 — ') + (d.detail || describe(d));
}
/* Validate/normalise a hex string (whitespace allowed); throws on bad input. */
function hexClean(s, label) {
  const v = (s || '').replace(/\s+/g, '');
  if (v.length % 2 || !/^[0-9a-fA-F]*$/.test(v)) throw new Error((label || 'Hex') + ' 형식을 확인하세요.');
  return v.toLowerCase();
}
/* AES-CTR encrypt/decrypt via PKCS#11 (/api/encrypt algo=ctr). */
async function doCtr() {
  if (CUR_SESSION === null) { $('#ctrOut').textContent = NO_SESS; return log('AES-CTR: ' + NO_SESS); }
  const h = CUR_SESSION;
  let key, counter, data;
  try {
    key = hexClean($('#ctrKey').value, 'AES 키');
    counter = hexClean($('#ctrCounter').value, 'Counter');
    data = hexClean($('#ctrData').value, '입력');
    if (![32, 48, 64].includes(key.length)) throw new Error('AES 키는 16/24/32바이트여야 합니다.');
    if (counter.length !== 32) throw new Error('Counter는 16바이트여야 합니다.');
  } catch (e) { $('#ctrOut').textContent = '오류: ' + e.message; return; }
  const enc = Number($('#ctrDir').value);
  $('#ctrOut').textContent = `AES-CTR ${enc ? '암호화' : '복호화'} 전송 중… (handle ${h})`;
  const d = await api('/api/encrypt', 'POST', { session: h, algo: 'ctr', encrypt: enc, key, iv: counter, data });
  touchSession(h, 'AES-CTR', d.ok);
  $('#ctrOut').textContent = d.ok
    ? `${enc ? '암호문' : '평문'} [${d.length}B] =\n${hexWrap(d.hex)}`
    : '오류: ' + describe(d);
  $('#ctrKey').value = '';
}
/* AES-GCM encrypt/decrypt via PKCS#11 (/api/encrypt algo=gcm). Encrypt output is
 * ciphertext||tag (split for display); decrypt input is ciphertext||tag. */
async function doGcm() {
  if (CUR_SESSION === null) { $('#gcmOut').textContent = NO_SESS; return log('AES-GCM: ' + NO_SESS); }
  const h = CUR_SESSION;
  const enc = Number($('#gcmDir').value);
  const tl = Number($('#gcmTagLen').value);
  let key, iv, aad, data, tag;
  try {
    key = hexClean($('#gcmKey').value, 'AES 키');
    iv = hexClean($('#gcmIv').value, 'IV');
    aad = hexClean($('#gcmAad').value, 'AAD');
    data = hexClean($('#gcmData').value, enc ? '평문' : '암호문');
    if (![32, 48, 64].includes(key.length)) throw new Error('AES 키는 16/24/32바이트여야 합니다.');
    if (iv.length < 2 || iv.length > 32) throw new Error('IV는 1–16바이트여야 합니다.');
    if (!enc) {
      tag = hexClean($('#gcmTag').value, '인증 태그');
      if (tag.length !== tl * 2) throw new Error('태그 길이가 선택값과 다릅니다.');
      data = data + tag;   /* decrypt input = ciphertext||tag */
    }
  } catch (e) { $('#gcmOut').textContent = '오류: ' + e.message; return; }
  $('#gcmOut').textContent = `AES-GCM ${enc ? '암호화' : '복호화'} 전송 중… (handle ${h})`;
  const d = await api('/api/encrypt', 'POST', { session: h, algo: 'gcm', encrypt: enc, key, iv, aad, tagBytes: tl, data });
  touchSession(h, 'AES-GCM', d.ok);
  if (!d.ok) { $('#gcmOut').textContent = '오류: ' + describe(d); $('#gcmKey').value = ''; return; }
  if (enc) {
    const ct = d.hex.slice(0, -tl * 2), tg = d.hex.slice(-tl * 2);
    $('#gcmOut').textContent = `암호화 완료\n암호문 [${ct.length / 2}B] =\n${hexWrap(ct)}\n\n인증 태그 [${tl}B] =\n${hexWrap(tg)}`;
  } else {
    $('#gcmOut').textContent = `인증 성공\n평문 [${d.length}B] =\n${hexWrap(d.hex)}`;
  }
  $('#gcmKey').value = '';
}
/* ---- Multipart digest over a large test-data file (Init/Update×N/Final) ---- */
async function mdRefreshFiles() {
  const sel = $('#mdFile'); if (!sel) return;
  const d = await api('/api/files');
  const cur = sel.value;
  sel.innerHTML = '';
  if (d.ok && d.files) {
    for (const f of d.files) sel.append(el('option', { value: f.name, textContent: `${f.name} (${f.size}B)` }));
    if ([...sel.options].some((o) => o.value === cur)) sel.value = cur;
  }
  if (!sel.options.length) sel.append(el('option', { value: '', textContent: '(시험 파일 없음 — 생성하세요)' }));
}
async function mdGen() {
  const size = Math.max(0, Math.floor(Number($('#mdGenSize').value)));
  $('#mdGenInfo').textContent = `${size}B Hex 시험파일 생성 중…`;
  const d = await api('/api/genfile', 'POST', { size, format: 'hex' });
  if (!d.ok) { $('#mdGenInfo').textContent = '생성 실패: ' + describe(d); return; }
  $('#mdGenInfo').textContent = `${d.name} · ${d.size}B · SHA-256 ${d.sha256.slice(0, 16)}…`;
  await mdRefreshFiles();
  $('#mdFile').value = d.name;
}
async function mdRun() {
  if (CUR_SESSION === null) { $('#mdOut').textContent = NO_SESS; return log('멀티파트 digest: ' + NO_SESS); }
  const name = $('#mdFile').value;
  if (!name) { $('#mdOut').textContent = '시험 파일을 생성하거나 선택하세요.'; return; }
  const h = CUR_SESSION;
  const mech = Number($('#mdMech').value);
  let chunk = Math.max(1, Math.floor(Number($('#mdChunk').value)));
  if (chunk > 3968) chunk = 3968;   /* token per-update digest data limit */
  $('#mdOut').textContent = `멀티파트 digest 실행 중… (handle ${h}, 파일 ${name}, 청크 ${chunk}B)`;
  const d = await api('/api/digest-file', 'POST', { session: h, mech, name, chunk });
  touchSession(h, '멀티파트 digest', d.ok);
  $('#mdOut').textContent = d.ok
    ? `digest [${d.length}B] (데이터 ${d.bytes}B · update ${d.updates}회 · 청크 ${d.chunk}B) =\n${hexWrap(d.hex)}`
    : '오류: ' + describe(d);
}
/* ---- Multipart AES-GCM over a large test-data file (Init/Update×N/Final) ---- */
async function gmpRefreshFiles() {
  const sel = $('#gmpFile'); if (!sel) return;
  const d = await api('/api/files');
  const cur = sel.value;
  sel.innerHTML = '';
  if (d.ok && d.files) {
    for (const f of d.files) sel.append(el('option', { value: f.name, textContent: `${f.name} (${f.size}B)` }));
    if ([...sel.options].some((o) => o.value === cur)) sel.value = cur;
  }
  if (!sel.options.length) sel.append(el('option', { value: '', textContent: '(시험 파일 없음 — 생성하세요)' }));
}
async function gmpGen() {
  const size = Math.max(0, Math.floor(Number($('#gmpGenSize').value)));
  $('#gmpGenInfo').textContent = `${size}B Hex 시험파일 생성 중…`;
  const d = await api('/api/genfile', 'POST', { size, format: 'hex' });
  if (!d.ok) { $('#gmpGenInfo').textContent = '생성 실패: ' + describe(d); return; }
  $('#gmpGenInfo').textContent = `${d.name} · ${d.size}B`;
  await gmpRefreshFiles(); $('#gmpFile').value = d.name;
}
async function gmpRun() {
  if (CUR_SESSION === null) { $('#gmpOut').textContent = NO_SESS; return log('멀티파트 GCM: ' + NO_SESS); }
  const name = $('#gmpFile').value;
  if (!name) { $('#gmpOut').textContent = '입력 시험 파일을 생성하거나 선택하세요.'; return; }
  const h = CUR_SESSION, enc = Number($('#gmpDir').value), tl = Number($('#gmpTagLen').value);
  let key, iv, aad;
  try {
    key = hexClean($('#gmpKey').value, 'AES 키'); iv = hexClean($('#gmpIv').value, 'IV'); aad = hexClean($('#gmpAad').value, 'AAD');
    if (![32, 48, 64].includes(key.length)) throw new Error('AES 키는 16/24/32바이트여야 합니다.');
    if (iv.length < 2 || iv.length > 32) throw new Error('IV는 1–16바이트여야 합니다.');
  } catch (e) { $('#gmpOut').textContent = '오류: ' + e.message; return; }
  const chunk = Math.max(1, Math.floor(Number($('#gmpChunk').value)));
  const outName = $('#gmpOutName').value.trim();
  $('#gmpOut').textContent = `멀티파트 GCM ${enc ? '암호화' : '복호화'} 실행 중… (handle ${h}, 파일 ${name})`;
  const d = await api('/api/encrypt-file', 'POST',
    { session: h, encrypt: enc, key, iv, aad, tagBytes: tl, name, chunk, outName });
  touchSession(h, '멀티파트 GCM', d.ok);
  $('#gmpKey').value = '';
  if (!d.ok) { $('#gmpOut').textContent = '오류: ' + describe(d); return; }
  const body = $('#gmpOut');
  body.textContent = `${enc ? '암호화' : '복호화'} 완료\n입력 ${d.inBytes}B → 출력 ${d.outBytes}B · update ${d.updates}회\n`
    + `출력 파일: ${d.outName}\nSHA-256(출력): ${d.sha256}\n`;
  const btn = el('button', { className: 'link', textContent: '출력 파일 열기' });
  btn.onclick = () => window.open('/files/' + encodeURIComponent(d.outName), '_blank', 'noopener');
  body.append(btn);
  await gmpRefreshFiles();
}
function gmpNewIv() { $('#gmpIv').value = Array.from(crypto.getRandomValues(new Uint8Array(12)), (b) => b.toString(16).padStart(2, '0')).join(''); }
/* ---- PEM CI 콘솔 (PEM 슬롯 선택 시) ---- */
const PEM_TUNNEL_CMD = 0x01F0;               // ncmpd PEM backend generic CI tunnel
const PEM_DIAG = { capabilities:0x0001, echo:0x0002, key_table:0x0024, perf_query:0x00F0 };
function pemU32le(n){ const b=[]; for(let i=0;i<4;i++){b.push((n>>>(8*i))&0xff);} return b.map(x=>x.toString(16).padStart(2,'0')).join(''); }
function pemU64le(n){ let h=''; let v=BigInt(n); for(let i=0;i<8;i++){h+=Number(v&0xffn).toString(16).padStart(2,'0'); v>>=8n;} return h; }
function pemPad8(hex){ const nb=hex.length/2, pad=((8-(nb%8))%8); return hex + '00'.repeat(pad); }
function pemVarHex(dataHex){ const nb=dataHex.length/2; return pemU64le(nb)+pemPad8(dataHex); }
function pemTextHex(t){ return Array.from(new TextEncoder().encode(t),b=>b.toString(16).padStart(2,'0')).join(''); }
function pemIsDiag(op){ return op in PEM_DIAG; }

function pemVisibility() {
  const op = $('#pemOp') ? $('#pemOp').value : 'capabilities';
  const sha = op.startsWith('sha3'), gcm = op.startsWith('gcm'), dec = op.endsWith('_dec');
  const show = {
    data: sha || gcm || op.startsWith('ctr') || op === 'echo' || op === 'perf_query',
    key: gcm || op.startsWith('ctr'), iv: gcm || op.startsWith('ctr'),
    aad: gcm, tag: gcm && dec,
  };
  document.querySelectorAll('#pemFields [data-pf]').forEach((e) => { e.style.display = show[e.dataset.pf] ? '' : 'none'; });
  const hint = $('#pemDataHint'), ivl = $('#pemIvLabel');
  if (hint) hint.textContent = op === 'echo' ? '(반향할 UTF-8 문자열)' : op === 'perf_query' ? '(대상 hSession 10진수)'
    : sha ? '(UTF-8 문자열)' : dec ? '(암호문 Hex)' : '(평문 Hex)';
  if (ivl) ivl.textContent = op.startsWith('ctr') ? 'Counter Hex (16바이트)' : 'IV Hex (12/16바이트)';
}

/* Run a PEM-native command through the ncmpd PEM CI tunnel (/api/ci). */
async function pemTunnel(pemCmd, argsHex, expBytes) {
  const d = await api('/api/ci', 'POST', {
    slot: SELECTED_SLOT, command: PEM_TUNNEL_CMD, session: 0,
    p0: pemU32le(pemCmd), p1: argsHex || '', p2: pemU32le(expBytes || 4096),
  });
  if (!d.ok) throw new Error(describe(d));
  const ackName = d.response ? (d.response.ackName || ('ack ' + d.response.ack)) : '';
  const ack = d.response ? d.response.ack : -1;
  const out = (d.response && d.response.params && d.response.params[0]) ? d.response.params[0].hex || '' : '';
  return { ack, ackName, out };
}

async function pemRun() {
  const op = $('#pemOp').value;
  $('#pemOut').textContent = '실행 중…';
  try {
    /* --- PEM-native diagnostic/info commands via the CI tunnel (session0) --- */
    if (pemIsDiag(op)) {
      if (SELECTED_SLOT === null) { $('#pemOut').textContent = '먼저 PEM 슬롯을 선택하세요.'; return; }
      let args = '', exp = 4096, r;
      if (op === 'capabilities') { exp = 40; r = await pemTunnel(PEM_DIAG.capabilities, '', exp);
        if (r.ack !== 0) { $('#pemOut').textContent = 'ack ' + r.ack; return; }
        const api_v = parseInt(r.out.slice(0,16).match(/../g).reverse().join(''),16);
        const slots = parseInt(r.out.slice(16,32).match(/../g).reverse().join(''),16);
        const mask  = r.out.slice(32,48);
        $('#pemOut').textContent = `CAPABILITIES\napi_version : ${api_v}\nslots       : ${slots}\nmask        : 0x${mask.match(/../g).reverse().join('')}`;
        return;
      }
      if (op === 'echo') { const dh = pemTextHex($('#pemData').value); args = pemVarHex(dh);
        exp = 16 + 8 + pemPad8(dh).length/2; r = await pemTunnel(PEM_DIAG.echo, args, exp);
        if (r.ack !== 0) { $('#pemOut').textContent = 'ack ' + r.ack; return; }
        const n = parseInt(r.out.slice(0,16).match(/../g).reverse().join(''),16);
        $('#pemOut').textContent = `ECHO [${n}B] =\n${hexWrap(r.out.slice(16, 16 + n*2))}`;
        return;
      }
      if (op === 'key_table') { exp = 984; r = await pemTunnel(PEM_DIAG.key_table, '', exp);
        if (r.ack !== 0) { $('#pemOut').textContent = 'ack ' + r.ack; return; }
        const n = parseInt(r.out.slice(0,16).match(/../g).reverse().join(''),16);
        $('#pemOut').textContent = `KEY_TABLE_INFO · records ${n}B (30 × 32B 공개 메타데이터)\n${hexWrap(r.out.slice(16, 16 + Math.min(n,320)*2))}${n>320?'\n…':''}`;
        return;
      }
      if (op === 'perf_query') { const tgt = Math.floor(Number($('#pemData').value)) || 0;
        args = pemU64le(tgt) + pemU64le(0xffffffff); exp = 320; r = await pemTunnel(PEM_DIAG.perf_query, args, exp);
        if (r.ack !== 0) { $('#pemOut').textContent = '성능 모니터 빌드에서만 지원 · ack ' + r.ack; return; }
        $('#pemOut').textContent = `PERF_QUERY [${r.out.length/2}B]\n${hexWrap(r.out.slice(0, 160))}…`;
        return;
      }
    }
    /* --- crypto unit functions via the PKCS#11 facade (needs a session) --- */
    if (CUR_SESSION === null) { $('#pemOut').textContent = NO_SESS; return log('PEM CI: ' + NO_SESS); }
    const h = CUR_SESSION;
    if (op.startsWith('sha3')) {
      const mech = op === 'sha3_384' ? 704 : op === 'sha3_512' ? 720 : 688;
      const d = await api('/api/digest', 'POST', { session: h, mech, input: $('#pemData').value });
      touchSession(h, 'PEM ' + op, d.ok);
      $('#pemOut').textContent = d.ok ? `digest [${d.length}B] =\n${hexWrap(d.hex)}` : '오류: ' + describe(d);
      return;
    }
    const gcm = op.startsWith('gcm'), enc = op.endsWith('_enc') ? 1 : 0;
    const key = hexClean($('#pemKey').value, 'AES 키');
    const iv = hexClean($('#pemIv').value, gcm ? 'IV' : 'Counter');
    let data = hexClean($('#pemData').value, enc ? '평문' : '암호문');
    if (key.length !== 64) throw new Error('PEM AES는 32바이트(AES-256) 키만 지원합니다.');
    const body = { session: h, algo: gcm ? 'gcm' : 'ctr', encrypt: enc, key, iv, data };
    if (gcm) {
      body.aad = hexClean($('#pemAad').value, 'AAD'); body.tagBytes = 16;
      if (!enc) { const tag = hexClean($('#pemTag').value, 'Tag'); if (tag.length !== 32) throw new Error('Tag는 16바이트여야 합니다.'); body.data = data + tag; }
    }
    const d = await api('/api/encrypt', 'POST', body);
    touchSession(h, 'PEM ' + op, d.ok);
    $('#pemKey').value = '';
    if (!d.ok) { $('#pemOut').textContent = '오류: ' + describe(d); return; }
    if (gcm && enc) {
      const ct = d.hex.slice(0, -32), tg = d.hex.slice(-32);
      $('#pemOut').textContent = `암호화 완료\n암호문 [${ct.length/2}B] =\n${hexWrap(ct)}\n\n태그 [16B] =\n${hexWrap(tg)}`;
    } else {
      $('#pemOut').textContent = `${enc ? '암호문' : '평문'} [${d.length}B] =\n${hexWrap(d.hex)}`;
    }
  } catch (e) { $('#pemOut').textContent = '오류: ' + e.message; }
}
function gcmDirToggle() {
  const dec = Number($('#gcmDir').value) === 0;
  $('#gcmDataLabel').firstChild.textContent = dec ? '암호문 Hex ' : '평문 Hex ';
  $('#gcmTagRow').hidden = !dec;
  $('#btnGcmNewIv').disabled = dec;
}
function newGcmIv() {
  const b = crypto.getRandomValues(new Uint8Array(12));
  $('#gcmIv').value = Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}
function clearGcm() {
  for (const id of ['gcmKey', 'gcmIv', 'gcmAad', 'gcmData', 'gcmTag']) $('#' + id).value = '';
  $('#gcmOut').textContent = '입력과 결과를 지웠습니다.';
}
/* "Ping" — verify the selected session is alive via C_GetSessionInfo. */
async function ping() {
  if (CUR_SESSION === null) { $('#sessionInfo').textContent = NO_SESS; return log('Ping: ' + NO_SESS); }
  const h = CUR_SESSION;
  $('#sessionInfo').textContent = `Ping(C_GetSessionInfo) 전송 중… (handle ${h})`;
  const d = await api('/api/session/info', 'POST', { session: h });
  touchSession(h, 'Ping(C_GetSessionInfo)', d.ok);
  $('#sessionInfo').textContent = d.ok
    ? `slot ${d.session.slot}, state ${d.session.state}, flags 0x${d.session.flags.toString(16)}, deviceError ${d.session.deviceError}`
    : 'Ping 실패: ' + describe(d);
}
function hexWrap(hex) {
  return (hex.match(/.{1,32}/g) || []).map((r) => r.match(/.{1,2}/g).join(' ')).join('\n');
}

/* ------------------------------------------------------------------ */
/* File generation + real-target vs software verification             */
/* ------------------------------------------------------------------ */

async function genFile() {
  const size = Math.max(0, Math.floor(Number($('#fileSize').value) * Number($('#fileUnit').value)));
  const name = $('#fileName').value.trim();
  const d = await api('/api/genfile', 'POST', name ? { size, name } : { size });
  if (d.ok) {
    $('#genFileInfo').textContent = `생성됨: ${d.name} (${d.size}B), SW SHA-256=${d.sha256.slice(0, 16)}…`;
    log(`파일 생성: ${d.name} ${d.size}B`);
    if (size < 65536) log('주의: init/update/final 시험에는 64KB(65536) 이상을 권장합니다.');
    await refreshFiles(d.name);
  } else log('파일 생성 실패: ' + describe(d));
}

async function refreshFiles(select) {
  const d = await api('/api/files');
  const sel = $('#verifyFile');
  sel.innerHTML = '';
  if (d.ok) for (const f of d.files)
    sel.append(el('option', { value: f.name, textContent: `${f.name} (${f.size}B)` }));
  if (select) sel.value = select;
}

async function digestFileOnToken() {
  if (CUR_SESSION === null) return log('먼저 세션을 여세요(세션 탭)');
  const name = $('#verifyFile').value;
  if (!name) return log('파일을 먼저 생성/선택하세요');
  const h = CUR_SESSION;
  const d = await api('/api/digest-file', 'POST', { session: h, mech: Number($('#verifyMech').value), name });
  touchSession(h, 'C_Digest(multipart)', d.ok);
  $('#compareVerdict').className = 'summary';
  $('#compareVerdict').textContent = '';
  $('#fileOut').textContent = d.ok
    ? `토큰 multipart 해시 (${name}, ${d.bytes}B)\n${d.hex}`
    : '오류: ' + describe(d);
}

async function compareFile() {
  if (CUR_SESSION === null) return log('먼저 세션을 여세요(세션 탭)');
  const name = $('#verifyFile').value;
  if (!name) return log('파일을 먼저 생성/선택하세요');
  const h = CUR_SESSION;
  const d = await api('/api/digest-compare', 'POST', { session: h, mech: Number($('#verifyMech').value), name });
  touchSession(h, 'digest-compare', d.ok && d.match !== undefined);
  const v = $('#compareVerdict');
  if (!d.ok && d.match === undefined) {
    v.className = 'summary fail';
    v.textContent = '비교 실패: ' + describe(d);
    $('#fileOut').textContent = '';
    return;
  }
  v.className = 'summary ' + (d.match ? 'pass' : 'fail');
  v.textContent = d.match
    ? `✔ MATCH — 실 타겟 결과가 SW 계산과 일치 (${d.bytes}B)`
    : `✘ MISMATCH — 실 타겟 결과가 SW와 다름 (${d.bytes}B) · mock 토큰은 정상적으로 불일치`;
  $('#fileOut').textContent =
    `bytes : ${d.bytes}\ntoken : ${d.tokenHex}\nSW    : ${d.swHex}\nmatch : ${d.match}`;
  log(`비교(${name}): match=${d.match}`);
}

/* ------------------------------------------------------------------ */
/* Unit API catalog (shared by the API tester and the scenario engine) */
/* ------------------------------------------------------------------ */

const DIGEST_OPTS = [
  ['592', 'SHA-256'], ['624', 'SHA-512'], ['693', 'SHA3-224'],
  ['688', 'SHA3-256'], ['704', 'SHA3-384'], ['720', 'SHA3-512'],
];
const USER_OPTS = [['1', 'User'], ['0', 'SO'], ['2', 'ContextSpecific']];
const TRANSPORT_OPTS = [['mock', 'mock'], ['real', 'real'], ['socket', 'socket']];

// Each op: how to call it + what params it needs + which response field it can save.
const OPS = {
  daemonStart: { label: '데몬 시작', method: 'POST', path: '/api/daemon/start',
    params: [{ k: 'transport', t: 'select', opts: TRANSPORT_OPTS, def: 'mock' }] },
  daemonStop: { label: '데몬 정지', method: 'POST', path: '/api/daemon/stop', params: [] },
  load: { label: 'facade 로드(dlopen)', method: 'POST', path: '/api/load',
    params: [{ k: 'module', t: 'text', def: '', opt: true, ph: '비우면 서버 기본값' }] },
  initialize: { label: 'C_Initialize', method: 'POST', path: '/api/initialize', params: [] },
  finalize: { label: 'C_Finalize', method: 'POST', path: '/api/finalize', params: [] },
  dlsym: { label: 'dlsym 점검', method: 'GET', path: '/api/dlsym', params: [] },
  library: { label: 'C_GetInfo(라이브러리)', method: 'GET', path: '/api/library', params: [] },
  slots: { label: 'C_GetSlotList', method: 'GET', path: '/api/slots', params: [] },
  tokenInfo: { label: 'C_GetTokenInfo', method: 'POST', path: '/api/token',
    params: [{ k: 'slot', t: 'number', def: 0 }] },
  mechanisms: { label: 'C_GetMechanismList', method: 'POST', path: '/api/mechanisms',
    params: [{ k: 'slot', t: 'number', def: 0 }] },
  openSession: { label: 'C_OpenSession', method: 'POST', path: '/api/session/open',
    params: [{ k: 'slot', t: 'number', def: 0 }, { k: 'rw', t: 'number', def: 1 }], save: 'session' },
  closeSession: { label: 'C_CloseSession', method: 'POST', path: '/api/session/close',
    params: [{ k: 'session', t: 'text', def: '' }] },
  sessionInfo: { label: 'C_GetSessionInfo', method: 'POST', path: '/api/session/info',
    params: [{ k: 'session', t: 'text', def: '' }] },
  login: { label: 'C_Login', method: 'POST', path: '/api/login',
    params: [{ k: 'session', t: 'text', def: '' }, { k: 'userType', t: 'select', opts: USER_OPTS, def: '1' }, { k: 'pin', t: 'text', def: '1234' }] },
  logout: { label: 'C_Logout', method: 'POST', path: '/api/logout',
    params: [{ k: 'session', t: 'text', def: '' }] },
  random: { label: 'C_GenerateRandom', method: 'POST', path: '/api/random',
    params: [{ k: 'session', t: 'text', def: '' }, { k: 'length', t: 'number', def: 16 }], save: 'hex' },
  digest: { label: 'C_Digest', method: 'POST', path: '/api/digest',
    params: [{ k: 'session', t: 'text', def: '' }, { k: 'mech', t: 'select', opts: DIGEST_OPTS, def: '592' }, { k: 'input', t: 'text', def: 'abc' }], save: 'hex' },
  gcmSelftest: { label: 'AES-GCM 자가검증', method: 'POST', path: '/api/gcm-selftest',
    params: [{ k: 'session', t: 'text', def: '' }] },
  genfile: { label: '테스트 파일 생성', method: 'POST', path: '/api/genfile',
    params: [{ k: 'size', t: 'number', def: 100000 }, { k: 'name', t: 'text', def: '', opt: true, ph: '(자동)' }], save: 'name' },
  digestFile: { label: '파일 multipart 해시(토큰)', method: 'POST', path: '/api/digest-file',
    params: [{ k: 'session', t: 'text', def: '' }, { k: 'mech', t: 'select', opts: DIGEST_OPTS, def: '592' }, { k: 'name', t: 'text', def: '' }], save: 'hex' },
  digestCompare: { label: '실타겟 vs SW 비교', method: 'POST', path: '/api/digest-compare',
    params: [{ k: 'session', t: 'text', def: '' }, { k: 'mech', t: 'select', opts: DIGEST_OPTS, def: '592' }, { k: 'name', t: 'text', def: '' }], save: 'match' },
};

const NUMBER_KEYS = new Set(['slot', 'rw', 'length', 'mech', 'userType', 'session']);

// Build a request body from a param map, substituting ${vars} and coercing types.
function buildBody(opId, values, vars) {
  const op = OPS[opId];
  if (op.method === 'GET' || op.params.length === 0) return null;
  const body = {};
  for (const p of op.params) {
    let v = values[p.k];
    if (v === undefined || v === null) v = p.def;
    v = subst(String(v), vars);
    if (p.opt && v === '') continue;
    if (NUMBER_KEYS.has(p.k) && v !== '' && !isNaN(Number(v))) body[p.k] = Number(v);
    else body[p.k] = v;
  }
  return body;
}

function subst(str, vars) {
  return str.replace(/\$\{([^}]+)\}/g, (_, name) => (vars && name in vars) ? vars[name] : '');
}

async function runOp(opId, values, vars) {
  const op = OPS[opId];
  const body = buildBody(opId, values, vars);
  return api(op.path, op.method, body);
}

/* PKCS#11 function name (or helper note) shown next to each unit item. */
const PK = {
  daemonStart: '도구', daemonStop: '도구', load: '도구(dlopen)', dlsym: '도구',
  initialize: 'C_Initialize', finalize: 'C_Finalize', library: 'C_GetInfo',
  slots: 'C_GetSlotList', tokenInfo: 'C_GetTokenInfo', mechanisms: 'C_GetMechanismList',
  openSession: 'C_OpenSession', sessionInfo: 'C_GetSessionInfo', login: 'C_Login',
  logout: 'C_Logout', closeSession: 'C_CloseSession', random: 'C_GenerateRandom',
  digest: 'C_DigestInit+Digest', gcmSelftest: 'C_GenerateKey+Encrypt/Decrypt',
  genfile: '도구', digestFile: 'C_Digest(multipart)', digestCompare: '도구+SW',
};

/* Unit-item palette, grouped. Shown in the scenario tab; click to append a step. */
const PALETTE = [
  ['수명주기', ['daemonStart', 'daemonStop', 'load', 'initialize', 'finalize', 'dlsym', 'library']],
  ['슬롯/토큰', ['slots', 'tokenInfo', 'mechanisms']],
  ['세션/로그인', ['openSession', 'sessionInfo', 'login', 'logout', 'closeSession']],
  ['암복호화/해시', ['random', 'digest', 'gcmSelftest']],
  ['파일/검증', ['genfile', 'digestFile', 'digestCompare']],
];

function defaultParams(opId) {
  const op = OPS[opId];
  const p = {};
  for (const q of op.params) {
    if (q.k === 'session') p[q.k] = '${s}';          // chain from an opened session
    else if (q.k === 'slot') p[q.k] = (SELECTED_SLOT !== null ? SELECTED_SLOT : 0);
    else p[q.k] = q.def ?? '';
  }
  return p;
}

function appendStep(opId) {
  const step = { op: opId, params: defaultParams(opId) };
  if (OPS[opId].save === 'session') step.saveAs = 's';   // openSession -> ${s}
  working.steps.push(step);
  renderSteps();
  log('스텝 추가: ' + opId + (PK[opId] ? ' (' + PK[opId] + ')' : ''));
}

function renderPalette() {
  const box = $('#palette');
  if (!box) return;
  box.innerHTML = '';
  for (const [group, ids] of PALETTE) {
    const row = el('div', { className: 'grp' }, el('span', { className: 'glabel', textContent: group }));
    for (const id of ids) {
      const b = el('button', { className: 'item', type: 'button' });
      b.append(OPS[id].label + ' ');
      b.append(el('span', { className: 'pk', textContent: PK[id] || '' }));
      b.title = `${id} — ${PK[id] || ''}`;
      b.onclick = () => appendStep(id);
      row.append(b);
    }
    box.append(row);
  }
}

/* ------------------------------------------------------------------ */
/* API tester tab                                                     */
/* ------------------------------------------------------------------ */

function fillApiOpSelect() {
  const sel = $('#apiOp');
  sel.innerHTML = '';
  for (const [id, op] of Object.entries(OPS))
    sel.append(el('option', { value: id, textContent: `${id} — ${op.label}` }));
  sel.onchange = renderApiParams;
  renderApiParams();
}

function renderApiParams() {
  const op = OPS[$('#apiOp').value];
  const box = $('#apiParams');
  box.innerHTML = '';
  for (const p of op.params) {
    box.append(el('span', { className: 'pk', textContent: p.k }));
    let input;
    if (p.t === 'select') {
      input = el('select');
      for (const [val, lab] of p.opts) input.append(el('option', { value: val, textContent: lab }));
      input.value = p.def;
    } else {
      input = el('input', { type: p.t === 'number' ? 'number' : 'text', value: p.def ?? '' });
      if (p.ph) input.placeholder = p.ph;
    }
    input.dataset.pk = p.k;
    if (p.k === 'slot' && SELECTED_SLOT !== null) input.value = SELECTED_SLOT;
    if (p.k === 'session' && CUR_SESSION !== null) input.value = CUR_SESSION;
    box.append(input);
  }
}

function currentApiValues() {
  const values = {};
  document.querySelectorAll('#apiParams [data-pk]').forEach((n) => { values[n.dataset.pk] = n.value; });
  return values;
}

async function apiRun() {
  const opId = $('#apiOp').value;
  const d = await runOp(opId, currentApiValues(), scenarioVars);
  $('#apiOut').textContent = JSON.stringify(d, null, 2);
  log(`API 시험 ${opId}: ${describe(d)}`);
}

/* ------------------------------------------------------------------ */
/* Scenario engine                                                    */
/* ------------------------------------------------------------------ */

let scenarioVars = {};                 // shared ${var} scope (also usable by API tester)
let working = { name: '새 시나리오', steps: [] };

const BUILTIN = {
  'Mock 전체 왕복': { builtin: true, steps: [
    { op: 'daemonStart', params: { transport: 'mock' } },
    { op: 'load', params: { module: '' } },
    { op: 'initialize', params: {} },
    { op: 'slots', params: {} },
    { op: 'openSession', params: { slot: 0, rw: 1 }, saveAs: 's' },
    { op: 'login', params: { session: '${s}', userType: '1', pin: '1234' } },
    { op: 'random', params: { session: '${s}', length: 16 } },
    { op: 'digest', params: { session: '${s}', mech: '592', input: 'abc' } },
    { op: 'gcmSelftest', params: { session: '${s}' } },
    { op: 'logout', params: { session: '${s}' } },
    { op: 'closeSession', params: { session: '${s}' } },
    { op: 'finalize', params: {} },
  ] },
  '초기화 & 슬롯 조회': { builtin: true, steps: [
    { op: 'load', params: { module: '' } },
    { op: 'initialize', params: {} },
    { op: 'slots', params: {} },
    { op: 'tokenInfo', params: { slot: 0 } },
    { op: 'mechanisms', params: { slot: 0 } },
  ] },
  '세션/로그인 수명주기': { builtin: true, steps: [
    { op: 'openSession', params: { slot: 0, rw: 1 }, saveAs: 's' },
    { op: 'sessionInfo', params: { session: '${s}' } },
    { op: 'login', params: { session: '${s}', userType: '1', pin: '1234' } },
    { op: 'logout', params: { session: '${s}' } },
    { op: 'closeSession', params: { session: '${s}' } },
  ] },
  '음성: 잘못된 PIN 로그인 실패': { builtin: true, steps: [
    { op: 'openSession', params: { slot: 0, rw: 1 }, saveAs: 's' },
    { op: 'login', params: { session: '${s}', userType: '1', pin: '9999' }, expect: 'fail' },
    { op: 'closeSession', params: { session: '${s}' } },
  ] },
  '대용량 해시 검증 (실타겟, ≥64KB)': { builtin: true, steps: [
    { op: 'load', params: { module: '' } },
    { op: 'initialize', params: {} },
    { op: 'openSession', params: { slot: 0, rw: 1 }, saveAs: 's' },
    { op: 'genfile', params: { size: 131072, name: 'verify.bin' } },
    // 실 타겟이면 토큰 multipart 결과가 SW(OpenSSL)와 일치해야 한다(일치 기대).
    // mock 토큰은 실제 해시가 아니므로 이 스텝은 FAIL로 표시된다(정상).
    { op: 'digestCompare', params: { session: '${s}', mech: '592', name: 'verify.bin' }, expect: 'match' },
    { op: 'closeSession', params: { session: '${s}' } },
    { op: 'finalize', params: {} },
  ] },
};

// Saved scenarios live on the SERVER (permanent, shared across browsers),
// fetched via /api/scenarios and /api/scenario/*.
async function fillScenarioSelect() {
  const sel = $('#scenarioSelect');
  sel.innerHTML = '';
  for (const name of Object.keys(BUILTIN))
    sel.append(el('option', { value: 'builtin:' + name, textContent: '★ ' + name }));
  try {
    const d = await api('/api/scenarios');
    if (d.ok) for (const name of d.scenarios)
      sel.append(el('option', { value: 'saved:' + name, textContent: '💾 ' + name }));
  } catch { /* server list optional */ }
}

async function loadScenario() {
  const v = $('#scenarioSelect').value;
  if (!v) return;
  const kind = v.slice(0, v.indexOf(':'));
  const name = v.slice(v.indexOf(':') + 1);
  let src;
  if (kind === 'builtin') {
    src = BUILTIN[name];
  } else {
    const d = await api('/api/scenario/get', 'POST', { name });
    if (!d.ok || !d.scenario) return log('불러오기 실패: ' + describe(d));
    src = d.scenario;
  }
  if (!src) return;
  working = { name, steps: JSON.parse(JSON.stringify(src.steps || [])) };
  $('#scenarioName').value = kind === 'builtin' ? name + ' (사본)' : name;
  renderSteps();
  log(`시나리오 불러오기: ${name} (${working.steps.length} 스텝)`);
}

function newScenario() {
  working = { name: '새 시나리오', steps: [] };
  $('#scenarioName').value = '';
  renderSteps();
}

function addStepFromApi() {
  const opId = $('#apiOp').value;
  working.steps.push({ op: opId, params: currentApiValues() });
  renderSteps();
  switchTab('scenario');
  log(`시나리오에 스텝 추가: ${opId}`);
}

function renderSteps() {
  const ol = $('#stepList');
  ol.innerHTML = '';
  working.steps.forEach((step, i) => {
    const op = OPS[step.op];
    const paramStr = Object.entries(step.params || {}).map(([k, v]) => `${k}=${v}`).join(', ');
    const head = el('div', { className: 'sh' },
      el('b', { textContent: step.op }),
      el('span', { className: 'meta', textContent: op ? op.label : '(알 수 없는 op)' }));

    // save-as control (only meaningful if the op returns a saveable field)
    const saveWrap = el('label', { className: 'meta' });
    saveWrap.append('저장변수 ');
    const saveInp = el('input', { type: 'text', value: step.saveAs || '', size: 4, placeholder: op && op.save ? op.save : '' });
    saveInp.oninput = () => { step.saveAs = saveInp.value.trim() || undefined; };
    saveWrap.append(saveInp);

    // expect control
    const expSel = el('select');
    expSel.append(el('option', { value: 'ok', textContent: '성공 기대' }));
    expSel.append(el('option', { value: 'fail', textContent: '실패 기대' }));
    expSel.append(el('option', { value: 'match', textContent: '일치 기대(비교)' }));
    expSel.append(el('option', { value: 'nomatch', textContent: '불일치 기대(비교)' }));
    expSel.value = step.expect || 'ok';
    expSel.onchange = () => { step.expect = expSel.value; };
    expSel.className = 'meta';

    const up = el('button', { textContent: '↑', title: '위로' });
    up.onclick = () => { if (i > 0) { [working.steps[i - 1], working.steps[i]] = [working.steps[i], working.steps[i - 1]]; renderSteps(); } };
    const del = el('button', { textContent: '✕', className: 'x', title: '삭제' });
    del.onclick = () => { working.steps.splice(i, 1); renderSteps(); };

    head.append(saveWrap, expSel, up, del);
    const li = el('li', {}, head);

    // Editable parameters for this step.
    if (op && op.params.length) {
      const pe = el('div', { className: 'pedit' });
      for (const q of op.params) {
        const lab = el('label', {}, q.k + ' ');
        let inp;
        if (q.t === 'select') {
          inp = el('select');
          for (const [val, txt] of q.opts) inp.append(el('option', { value: val, textContent: txt }));
          inp.value = step.params[q.k] ?? q.def;
        } else {
          inp = el('input', { type: 'text', value: step.params[q.k] ?? q.def ?? '' });
          if (q.ph) inp.placeholder = q.ph;
        }
        inp.oninput = inp.onchange = () => { step.params[q.k] = inp.value; };
        lab.append(inp);
        pe.append(lab);
      }
      li.append(pe);
    } else if (paramStr) {
      li.append(el('div', { className: 'meta', textContent: paramStr }));
    }
    ol.append(li);
  });
}

async function runScenario() {
  scenarioVars = {};
  const tbody = $('#resultTable tbody');
  tbody.innerHTML = '';
  let pass = 0, fail = 0;
  log(`시나리오 실행 시작: ${working.name} (${working.steps.length} 스텝)`);

  for (let i = 0; i < working.steps.length; i++) {
    const step = working.steps[i];
    let d, ok, detail;
    try {
      d = await runOp(step.op, step.params || {}, scenarioVars);
      const want = step.expect || 'ok';
      if (want === 'match') ok = !!(d && d.match === true);
      else if (want === 'nomatch') ok = !!(d && d.match === false);
      else if (want === 'fail') ok = !d.ok;
      else ok = !!d.ok;
      if (ok && step.saveAs && d[OPS[step.op].save] !== undefined)
        scenarioVars[step.saveAs] = d[OPS[step.op].save];
      detail = summarize(d, step);
    } catch (e) {
      d = null; ok = false; detail = 'exception: ' + e.message;
    }
    ok ? pass++ : fail++;
    const tr = el('tr', {},
      el('td', { textContent: String(i + 1) }),
      el('td', { textContent: `${step.op}${step.expect === 'fail' ? ' (실패기대)' : ''}` }),
      el('td', { className: ok ? 'pass' : 'fail', textContent: ok ? 'PASS' : 'FAIL' }),
      el('td', { className: 'detail', textContent: detail }));
    tbody.append(tr);
    if (!ok) log(`  스텝 ${i + 1} ${step.op}: FAIL — ${detail}`);
  }
  const sum = $('#resultSummary');
  sum.className = 'summary ' + (fail === 0 ? 'pass' : 'fail');
  sum.textContent = `결과: ${pass} PASS / ${fail} FAIL (총 ${pass + fail})`;
  log(`시나리오 실행 완료: ${pass} PASS / ${fail} FAIL`);
}

function summarize(d, step) {
  if (!d) return '(응답 없음)';
  const parts = [`rc=${d.rc}`];
  if (d.error) parts.push(d.error);
  const save = OPS[step.op].save;
  if (d.ok && save && d[save] !== undefined) parts.push(`${save}=${String(d[save]).slice(0, 48)}`);
  if (d.slots) parts.push(`slots=[${d.slots.join(',')}]`);
  if (d.session && typeof d.session === 'object') parts.push(`state=${d.session.state}`);
  if (d.bytes !== undefined) parts.push(`bytes=${d.bytes}`);
  if (d.match !== undefined) parts.push(`match=${d.match}`);
  if (d.detail) parts.push(d.detail);
  return parts.join(' · ');
}

async function saveScenario() {
  const name = $('#scenarioName').value.trim();
  if (!name) return log('시나리오 이름을 입력하세요');
  const d = await api('/api/scenario/save', 'POST', { name, steps: working.steps });
  if (!d.ok) return log('시나리오 저장 실패: ' + describe(d));
  working.name = name;
  await fillScenarioSelect();
  $('#scenarioSelect').value = 'saved:' + name;
  log(`시나리오 저장(서버): ${name}`);
}
async function deleteScenario() {
  const v = $('#scenarioSelect').value;
  if (!v.startsWith('saved:')) return log('내장 시나리오는 삭제할 수 없습니다');
  const name = v.slice('saved:'.length);
  await api('/api/scenario/delete', 'POST', { name });
  await fillScenarioSelect();
  log(`시나리오 삭제(서버): ${name}`);
}
function exportScenario() {
  const blob = new Blob([JSON.stringify({ name: $('#scenarioName').value || working.name, steps: working.steps }, null, 2)], { type: 'application/json' });
  const a = el('a', { href: URL.createObjectURL(blob), download: (($('#scenarioName').value || 'scenario') + '.json') });
  a.click(); URL.revokeObjectURL(a.href);
}
function importScenario(ev) {
  const f = ev.target.files[0];
  if (!f) return;
  const r = new FileReader();
  r.onload = () => {
    try {
      const o = JSON.parse(r.result);
      working = { name: o.name || f.name, steps: o.steps || [] };
      $('#scenarioName').value = working.name;
      renderSteps();
      log(`시나리오 가져오기: ${working.name} (${working.steps.length} 스텝)`);
    } catch (e) { log('가져오기 실패: ' + e.message); }
  };
  r.readAsText(f);
}

/* ------------------------------------------------------------------ */
/* Raw CI send / receive (CI 송수신 tab)                               */
/* ------------------------------------------------------------------ */
const CI_LIST = [
  [0x0000,'NOP(loopback)'],[0x0001,'RNG'],[0x0002,'DIGEST'],[0x0003,'GETMECHLIST'],
  [0x0004,'DIGEST_INIT'],[0x0005,'DIGEST_UPDATE'],[0x0006,'DIGEST_FINAL'],[0x0009,'SHAKE_DERIVE'],
  [0x0012,'AES_GCM'],[0x0013,'AES_CTR'],[0x0014,'AES_GCM_INIT'],[0x0015,'AES_GCM_UPDATE'],
  [0x0016,'AES_GCM_FINAL'],[0x0017,'CTX_FREE'],[0x0020,'OPEN_SESSION'],[0x0021,'CLOSE_SESSION'],
  [0x0030,'LOGIN'],[0x0031,'LOGOUT'],[0x0032,'INIT_PIN'],[0x0033,'SET_PIN'],[0x0034,'INIT_TOKEN'],
  [0x0035,'GET_UTC_TIME'],[0x0036,'GET_TOKEN_PARAMS'],[0x0037,'SET_UTC_TIME'],
  [0x0038,'OBJECT_ADD'],[0x0039,'OBJECT_SET_ATTR'],
  [0x0050,'MLDSA_KEYGEN'],[0x0051,'MLDSA_SIGN'],[0x0052,'MLDSA_VERIFY'],
  [0x0053,'MLKEM_KEYGEN'],[0x0054,'MLKEM_ENCAPS'],[0x0055,'MLKEM_DECAPS'],
  [0x0101,'VD_MEM_WRITE'],[0x0102,'VD_MEM_READ'],[0x0103,'VD_PING'],[0x0104,'VD_SELFTEST'],
  [0x0105,'VD_FW_INFO'],[0x0106,'VD_MEM_FILL'],[0x0107,'VD_MEM_CRC'],[0x0108,'VD_TOKEN_INFO'],
];
const CI_NAME = Object.fromEntries(CI_LIST.map(([c, n]) => [c, n]));
const CI_HINT = {
  0x0001: 'p0 = LE u32 길이 (예 10000000 = 16바이트)',
  0x0103: '파라미터 없음 (epoch/ping 반환)',
  0x0104: '파라미터 없음 (status 반환)', 0x0105: '파라미터 없음 (fw 버전)',
  0x0108: '파라미터 없음 (토큰 신원 블롭)', 0x0035: '파라미터 없음', 0x0036: '파라미터 없음',
  0x0020: 'p0 = LE u32 flags (헤더 session_id=0)',
  0x0030: 'p0=userType, p1=flags, p2=PIN (예 01000000 00000000 31323334)',
  0x0102: 'p0=addr(LE u32), p1=len(LE u32)',
};
const CKR = {0:'OK',6:'FUNCTION_FAILED',7:'ARGUMENTS_BAD',0x30:'DEVICE_ERROR',0x50:'FUNCTION_CANCELED',
  0x54:'FUNCTION_NOT_SUPPORTED',0x60:'KEY_HANDLE_INVALID',0xA0:'PIN_INCORRECT',0xA1:'PIN_INVALID',
  0xB0:'SESSION_CLOSED',0xB1:'SESSION_COUNT',0xB3:'SESSION_HANDLE_INVALID',0xB5:'SESSION_READ_ONLY',
  0x90:'OPERATION_NOT_INITIALIZED',0x100:'USER_ALREADY_LOGGED_IN',0x101:'USER_NOT_LOGGED_IN',
  0x103:'USER_TYPE_INVALID',0x190:'CRYPTOKI_NOT_INITIALIZED'};
const ckrName = (v) => CKR[v] ? `CKR_${CKR[v]}` : `CKR_0x${(v>>>0).toString(16).toUpperCase()}`;
const hx = (n, w) => '0x' + (n >>> 0).toString(16).toUpperCase().padStart(w || 0, '0');

function fillCiSelect() {
  const sel = $('#ciCmd'); if (!sel) return; sel.innerHTML = '';
  for (const [c, n] of CI_LIST) sel.append(el('option', { value: c, textContent: `${hx(c,4)}  ${n}` }));
  sel.onchange = () => { const c = Number(sel.value); $('#ciHint').textContent = CI_HINT[c] || ''; };
  sel.onchange();
}
function fillCiParamRows() {
  const box = $('#ciParamRows'); if (!box) return; box.innerHTML = '';
  for (let i = 0; i < 8; i++) {
    box.append(el('label', { textContent: 'p' + i }));
    box.append(el('input', { type: 'text', id: 'ciP' + i, placeholder: '(Hex, 비움=생략)' }));
  }
}
function ciFmtHex(hexStr) {   // group into bytes, 16 per line
  const b = (hexStr.match(/.{1,2}/g) || []);
  let out = '';
  for (let i = 0; i < b.length; i++) out += b[i] + ((i % 16 === 15) ? '\n' : ' ');
  return out.trim() || '(empty)';
}
function ciFrameTable(f) {
  const t = el('table', { className: 'pf' });
  const row = (k, v) => t.append(el('tr', {}, el('td', { className: 'k', textContent: k }), el('td', { textContent: v })));
  row('frame_len', `${f.frameLen} (${hx(f.frameLen)})`);
  row('session_id', `${f.sessionId} (${hx(f.sessionId)})`);
  row('sequence_id', `${f.sequenceId} (${hx(f.sequenceId)})`);
  row('command_id', `${hx(f.commandId,4)}  ${CI_NAME[f.commandId] || '?'}`);
  row('ack', `${hx(f.ack)}  ${ckrName(f.ack)}`);
  row('payload_len', `${f.payloadLen}`);
  for (const p of f.params) row(`param[${p.idx}]`, `len ${p.len} : ${p.hex || '(0)'}`);
  if (!f.params.length) row('params', '(없음)');
  return t;
}
function ciFrameBlock(label, f) {
  const d = el('div', { className: 'frame' });
  d.append(el('div', { className: 'lbl', textContent: label + ' — raw (Hex)' }));
  d.append(el('pre', { className: 'hex', textContent: ciFmtHex(f.hex) }));
  d.append(el('div', { className: 'lbl', textContent: label + ' — parsed' }));
  d.append(ciFrameTable(f));
  return d;
}
async function ciSend() {
  const slot = Number($('#ciSlot').value);
  const command = Number($('#ciCmd').value);
  const session = Number($('#ciSession').value);
  const body = { slot, command, session };
  for (let i = 0; i < 8; i++) { const v = $('#ciP' + i).value.trim(); if (v) body['p' + i] = v; }
  const name = CI_NAME[command] || hx(command, 4);
  log(`CI 전송: ${name} slot=${slot} sid=${session}`);
  const box = el('div', { className: 'xchg' });
  const head = el('div', { className: 'xh' });
  head.append(el('span', {}, el('span', { className: 'dir tx', textContent: '▶ TX ' }), `${hx(command,4)} ${name}`),
              el('span', { className: 'ts', textContent: new Date().toTimeString().slice(0,8) }));
  box.append(head);
  const dbg = $('#ciDebug'); dbg.insertBefore(box, dbg.firstChild);
  let d;
  try { d = await api('/api/ci', 'POST', body); }
  catch (e) { box.append(el('div', { className: 'dir err', textContent: '요청 실패: ' + e.message })); return; }
  // TX (left) and RX (right) side by side.
  const frames = el('div', { className: 'frames2' });
  box.append(frames);
  if (d.request) frames.append(ciFrameBlock('송신(TX)', d.request));
  if (!d.ok) {
    const why = d.error || (d.rc === -7 ? 'timeout (토큰 무응답)' : 'rc=' + d.rc);
    frames.append(el('div', { className: 'frame' },
      el('div', { className: 'lbl', textContent: '수신(RX)' }),
      el('div', { className: 'dir err', textContent: '✘ RX 없음: ' + why })));
    log(`  수신 실패: ${why}`);
  } else {
    head.append(el('span', { className: 'dir rx', textContent: `  ◀ RX ack=${ckrName(d.response.ack)} (${d.elapsedMs}ms)` }));
    frames.append(ciFrameBlock('수신(RX)', d.response));
    log(`  수신: ack=${ckrName(d.response.ack)} (${d.elapsedMs}ms)`);
  }
}

/* ------------------------------------------------------------------ */
/* Tabs + wiring                                                      */
/* ------------------------------------------------------------------ */

function switchTab(name) {
  document.querySelectorAll('.navitem').forEach((t) => t.classList.toggle('active', t.dataset.tab === name));
  document.querySelectorAll('.tabpane').forEach((p) => p.classList.toggle('active', p.dataset.pane === name));
  const it = document.querySelector('.navitem[data-tab="' + name + '"]');
  if (it) {
    const g = $('#crumbGroup'), c = $('#crumbItem');
    if (g) g.textContent = it.dataset.group || '';
    if (c) c.textContent = it.dataset.label || it.textContent.trim();
  }
}

function wire() {
  document.querySelectorAll('.navitem').forEach((t) => (t.onclick = () => switchTab(t.dataset.tab)));

  $('#btnDaemonStart').onclick = daemonStart;
  $('#btnDaemonStop').onclick = daemonStop;
  $('#btnLoad').onclick = loadModule;
  $('#btnInit').onclick = initialize;
  $('#btnFinal').onclick = finalize;
  $('#btnSlots').onclick = refreshSlots;
  $('#btnDlsym').onclick = dlsymReport;

  $('#btnTokenInfo').onclick = tokenInfo;
  $('#btnOpenSession').onclick = openSession;
  $('#btnCloseSession').onclick = closeSession;
  $('#btnLogin').onclick = login;
  $('#btnLogout').onclick = logout;
  $('#btnPing').onclick = ping;
  $('#btnRandom').onclick = genRandom;
  $('#btnDigest').onclick = doDigest;
  $('#btnCtr').onclick = doCtr;
  $('#btnMdGen').onclick = mdGen;
  $('#btnMdFiles').onclick = mdRefreshFiles;
  $('#btnMdRun').onclick = mdRun;
  $('#btnGcm').onclick = doGcm;
  $('#btnGcmSelf').onclick = gcmSelftest;
  $('#btnGcmClear').onclick = clearGcm;
  $('#btnGcmNewIv').onclick = newGcmIv;
  $('#gcmDir').onchange = gcmDirToggle;
  $('#btnGmpGen').onclick = gmpGen;
  $('#btnGmpFiles').onclick = gmpRefreshFiles;
  $('#btnGmpRun').onclick = gmpRun;
  $('#btnGmpNewIv').onclick = gmpNewIv;
  if ($('#pemRun')) $('#pemRun').onclick = pemRun;
  if ($('#pemOp')) $('#pemOp').onchange = pemVisibility;

  $('#btnGenFile').onclick = genFile;
  $('#btnRefreshFiles').onclick = () => refreshFiles();
  $('#btnDigestFile').onclick = digestFileOnToken;
  $('#btnCompare').onclick = compareFile;

  $('#btnApiRun').onclick = apiRun;
  $('#btnApiAddStep').onclick = addStepFromApi;

  fillCiSelect();
  fillCiParamRows();
  $('#ciSend').onclick = ciSend;
  $('#ciClear').onclick = () => { $('#ciDebug').innerHTML = ''; };

  $('#btnScenarioLoad').onclick = loadScenario;
  $('#btnScenarioNew').onclick = newScenario;
  $('#btnScenarioRun').onclick = runScenario;
  $('#btnScenarioSave').onclick = saveScenario;
  $('#btnScenarioDelete').onclick = deleteScenario;
  $('#btnScenarioExport').onclick = exportScenario;
  $('#scenarioImport').onchange = importScenario;

  $('#btnClearLog').onclick = () => { $('#log').textContent = ''; };
  $('#themeToggle').onclick = toggleTheme;

  initTheme();
  // Command-defaults panel: live-sync into the per-tab inputs.
  ['#defUserType', '#defPin', '#defSoPin', '#defRw'].forEach((sel) => {
    const e = $(sel); if (e) e.onchange = applyDefaults;
  });
  $('#btnApplyDefaults').onclick = () => { applyDefaults(); log('명령 기본값을 각 탭 입력칸에 적용'); };
  applyDefaults();
  // Show/hide (eye) toggles for password inputs (PIN, server token).
  document.querySelectorAll('.eye').forEach((b) => {
    b.onclick = () => {
      const t = document.getElementById(b.dataset.target);
      if (!t) return;
      const show = t.type === 'password';
      t.type = show ? 'text' : 'password';
      b.textContent = show ? '🙈' : '👁';
      b.title = show ? '숨기기' : '표시/숨김';
    };
  });
  renderSessionPickers();
  renderSessionsTab();
  $('#btnSessRefresh').onclick = renderSessionsTab;
  $('#btnSessRefreshAll').onclick = refreshSessionStates;
  // Sync breadcrumb/content with the default-active nav item.
  switchTab(document.querySelector('.navitem.active')?.dataset.tab || 'session');
  fillApiOpSelect();
  renderPalette();
  fillScenarioSelect();
  renderSteps();
  refreshFiles();
  mdRefreshFiles().catch(() => {});
  gmpRefreshFiles().catch(() => {});
  refreshStatus();
  setInterval(refreshStatus, 3000);
  log('웹 테스트 앱 준비 완료. 데몬 시작 → facade 로드 → C_Initialize 순으로 시작하세요.');
}

document.addEventListener('DOMContentLoaded', wire);

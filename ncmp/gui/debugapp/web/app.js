/* Token NCMP - Debug App frontend: browse ncmpd shared memory per slot. */
'use strict';
const $ = (s) => document.querySelector(s);
const el = (t, p = {}, ...k) => { const e = Object.assign(document.createElement(t), p); for (const c of k) e.append(c); return e; };

let SEL = null;         // selected slot id
let timer = null;

function authToken() { return $('#authToken').value.trim(); }
async function api(path, body = null) {
  const h = {};
  if (body) h['Content-Type'] = 'application/json';
  const t = authToken(); if (t) h['Authorization'] = 'Bearer ' + t;
  const r = await fetch(path, { method: body ? 'POST' : 'GET', headers: h, body: body ? JSON.stringify(body) : undefined });
  try { return await r.json(); } catch { return { error: 'HTTP ' + r.status }; }
}
function log(m) { const n = $('#log'); n.textContent += `[${new Date().toTimeString().slice(0,8)}] ${m}\n`; n.scrollTop = n.scrollHeight; }

/* theme */
function applyTheme(t){ document.documentElement.setAttribute('data-theme', t); try{localStorage.setItem('ncmp_dbg_theme',t);}catch{} $('#themeToggle').textContent = t==='light'?'🌙 다크':'☀️ 라이트'; }
function initTheme(){ let t=null; try{t=localStorage.getItem('ncmp_dbg_theme');}catch{} if(!t) t=(window.matchMedia&&window.matchMedia('(prefers-color-scheme: light)').matches)?'light':'dark'; applyTheme(t); }

async function refreshStatus() {
  const s = await api('/api/status');
  const on = !!s.connected;
  $('#connDot').className = 'dot ' + (on ? 'on' : 'off');
  $('#connText').textContent = on ? 'ncmpd SHM 연결됨' : 'ncmpd 연결 안 됨';
  $('#shmName').textContent = s.shmName || '-';
  $('#shmMagic').textContent = s.magic || '-';
  $('#shmVer').textContent = s.version ?? '-';
  $('#shmSlots').textContent = s.slotCount ?? '-';
  $('#shmSize').textContent = s.totalSize != null ? (s.totalSize + ' B') : '-';
  $('#shmMask').textContent = s.slotMask != null ? ('0x' + (s.slotMask >>> 0).toString(16)) : '-';
  $('#shmSock').textContent = s.sockPath || '-';
}

async function refreshSlots() {
  const d = await api('/api/slots');
  const ul = $('#slotList'); ul.innerHTML = '';
  if (!d.connected) { ul.append(el('li', { className: 'muted', textContent: '(ncmpd 미연결 — 데몬 실행 확인)' })); return; }
  if (!d.slots.length) ul.append(el('li', { className: 'muted', textContent: `(실재 슬롯 없음 — 전체 ${d.slotCount}개 중 활성 0)` }));
  for (const s of d.slots) {
    const li = el('li');
    if (s.slot === SEL) li.className = 'sel';
    const top = el('div', { className: 'row' },
      el('span', { className: 'sid', textContent: 'Slot ' + s.slot }),
      el('span', { className: 'badge ' + s.stateName, textContent: s.stateName }));
    top.style.justifyContent = 'space-between';
    const sub = el('div', { className: 'muted small' });
    sub.textContent = `${s.tokenValid ? (s.tokenLabel || '(라벨없음)') : '(미식별)'} · inflight ${s.inFlight} · sent ${s.totalSent}`;
    li.append(top, sub);
    li.onclick = () => { SEL = s.slot; refreshSlots(); refreshDetail(); };
    ul.append(li);
  }
  if (d.slots.length)
    ul.append(el('li', { className: 'muted small', textContent: `표시 ${d.shown} · 전체 슬롯 ${d.slotCount}` }));
}

function kv(rows) {
  const t = el('table', { className: 'kv' });
  for (const [k, v] of rows) t.append(el('tr', {}, el('td', { className: 'k', textContent: k }), el('td', { className: 'v', textContent: String(v) })));
  return t;
}

async function refreshDetail() {
  if (SEL === null) return;
  const d = await api('/api/slot', { slot: SEL });
  const body = $('#detailBody'); body.innerHTML = '';
  $('#detailTitle').textContent = `Slot ${SEL} 상세 (공유메모리)`;
  if (d.error || !d.connected) { body.append(el('div', { className: 'muted', textContent: d.error || 'ncmpd 미연결' })); return; }

  const grid = el('div', { className: 'grid' });
  const left = el('div', { className: 'card' });
  left.append(el('h3', { textContent: '슬롯 상태' }));
  left.append(kv([
    ['state', `${d.state} (${d.stateName})`],
    ['boundCkSlot', d.boundCkSlot === -1 ? '-1 (미바인딩)' : d.boundCkSlot],
    ['curSessions', d.curSessions],
    ['maxInflight', d.maxInflight],
    ['bufPool.off', d.bufPool.off],
    ['bufPool.len', d.bufPool.len],
  ]));
  left.append(el('h3', { textContent: '통계 (comm thread)' }));
  left.append(kv([
    ['in_flight_cnt', d.stats.inFlight],
    ['stats_max_in_flight', d.stats.maxInFlightSeen],
    ['stats_total_sent_cmds', d.stats.totalSent],
  ]));

  const right = el('div', { className: 'card' });
  right.append(el('h3', { textContent: '토큰 신원 (NCMP_TokenIdentity)' }));
  const t = d.token;
  right.append(kv([
    ['valid', t.valid],
    ['label', t.label], ['serial', t.serial],
    ['manufacturer', t.manufacturer], ['model', t.model],
    ['hwVersion', t.hw], ['fwVersion', t.fw], ['flags', '0x' + (t.flags >>> 0).toString(16)],
  ]));
  grid.append(left, right);
  body.append(grid);

  // queue
  body.append(el('h3', { textContent: `명령 링 (MPSC queue, depth ${d.queueDepth})` }));
  const hist = el('div', { className: 'qhist' });
  for (const [k, v] of Object.entries(d.queue))
    hist.append(el('span', { className: 'chip' }, k + ' ', el('b', { textContent: v })));
  body.append(hist);

  if (d.busy && d.busy.length) {
    const tb = el('table', { className: 'rows' });
    tb.append(el('tr', {}, ...['idx','state','ownerSess','seq','reqLen','rspLen'].map(h => el('th', { textContent: h }))));
    for (const e of d.busy)
      tb.append(el('tr', {}, ...[e.idx, e.state, e.ownerSess, e.seq, e.reqLen, e.rspLen].map(x => el('td', { textContent: String(x) }))));
    body.append(tb);
  } else {
    body.append(el('div', { className: 'muted small', textContent: '활성(비-FREE) 링 엔트리 없음' }));
  }
}

async function refreshAll() { await refreshStatus(); await refreshSlots(); await refreshDetail(); }

/* ================= CI send / receive tab ========================== */
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
// hints: typical parameters for a few CIs
const CI_HINT = {
  0x0001: 'p0 = LE u32 길이 (예 10000000 = 16바이트)',
  0x0103: '파라미터 없음 (epoch 반환)',
  0x0104: '파라미터 없음 (status 반환)', 0x0105: '파라미터 없음 (fw 버전)',
  0x0108: '파라미터 없음 (토큰 신원 블롭)', 0x0035: '파라미터 없음', 0x0036: '파라미터 없음',
  0x0020: 'p0 = LE u32 flags (헤더 session_id=0)',
  0x0030: 'p0=userType, p1=flags, p2=PIN (예 01000000 00000000 31323334)',
  0x0102: 'p0=addr(LE u32), p1=len(LE u32)',
};
const CKR = {0:'CKR_OK',6:'FUNCTION_FAILED',7:'ARGUMENTS_BAD',0x30:'DEVICE_ERROR',0x50:'DATA_LEN_RANGE',
  0x54:'FUNCTION_NOT_SUPPORTED',0x60:'KEY_HANDLE_INVALID',0xA0:'PIN_INCORRECT',0xA1:'PIN_INVALID',
  0xB0:'SESSION_CLOSED',0xB1:'SESSION_COUNT',0xB3:'SESSION_HANDLE_INVALID',0xB5:'SESSION_READ_ONLY',
  0x90:'OPERATION_NOT_INITIALIZED',0x100:'USER_ALREADY_LOGGED_IN',0x101:'USER_NOT_LOGGED_IN',
  0x103:'USER_TYPE_INVALID',0x190:'CRYPTOKI_NOT_INITIALIZED'};
const ckrName = (v) => CKR[v] ? `CKR_${CKR[v]}` : `CKR_0x${(v>>>0).toString(16).toUpperCase()}`;
const hx = (n, w) => '0x' + (n >>> 0).toString(16).toUpperCase().padStart(w || 0, '0');

function fillCiSelect() {
  const sel = $('#ciCmd'); sel.innerHTML = '';
  for (const [c, n] of CI_LIST) sel.append(el('option', { value: c, textContent: `${hx(c,4)}  ${n}` }));
  sel.onchange = () => { const c = Number(sel.value); $('#ciHint').textContent = CI_HINT[c] || ''; };
  sel.onchange();
}
function fillCiParamRows() {
  const box = $('#ciParamRows'); box.innerHTML = '';
  for (let i = 0; i < 8; i++) {
    box.append(el('label', { textContent: 'p' + i }));
    box.append(el('input', { type: 'text', id: 'ciP' + i, placeholder: '(Hex, 비움=생략)' }));
  }
}
function fmtHex(hexStr) {   // group into bytes, 16 per line
  const b = (hexStr.match(/.{1,2}/g) || []);
  let out = '';
  for (let i = 0; i < b.length; i++) out += b[i] + ((i % 16 === 15) ? '\n' : ' ');
  return out.trim() || '(empty)';
}
function frameTable(f, isResp) {
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
function frameBlock(label, f, isResp) {
  const d = el('div', { className: 'frame' });
  d.append(el('div', { className: 'lbl', textContent: label + ' — Hex' }));
  d.append(el('pre', { className: 'hex', textContent: fmtHex(f.hex) }));
  d.append(el('div', { className: 'lbl', textContent: label + ' — 파싱' }));
  d.append(frameTable(f, isResp));
  return d;
}
function ciAppend(node) { const dbg = $('#ciDebug'); dbg.insertBefore(node, dbg.firstChild); }

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
  ciAppend(box);
  let d;
  try { d = await api('/api/ci', body); }
  catch (e) { box.append(el('div', { className: 'dir err', textContent: '요청 실패: ' + e.message })); return; }
  if (d.request) box.append(frameBlock('송신(TX)', d.request, false));
  if (!d.ok) {
    const why = d.error || (d.rc === -7 ? 'timeout (토큰 무응답)' : 'rc=' + d.rc);
    box.append(el('div', { className: 'xh' }, el('span', { className: 'dir err', textContent: '✘ RX 없음: ' + why })));
    log(`  수신 실패: ${why}`);
  } else {
    head.append(el('span', { className: 'dir rx', textContent: `  ◀ RX ack=${ckrName(d.response.ack)} (${d.elapsedMs}ms)` }));
    box.append(frameBlock('수신(RX)', d.response, true));
    log(`  수신: ack=${ckrName(d.response.ack)} (${d.elapsedMs}ms)`);
  }
}

function switchTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
  document.querySelectorAll('.pane').forEach(p => p.classList.toggle('active', p.dataset.pane === name));
}

function setAuto(on) {
  if (timer) { clearInterval(timer); timer = null; }
  if (on) timer = setInterval(refreshAll, 2000);
}

function wire() {
  initTheme();
  $('#themeToggle').onclick = () => applyTheme(document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light');
  $('#btnClearLog').onclick = () => { $('#log').textContent = ''; };
  $('#autoRefresh').onchange = (e) => setAuto(e.target.checked);
  $('#btnReconnect').onclick = async () => { const d = await api('/api/reconnect'); log('재연결: ' + (d.connected ? 'OK' : '실패')); refreshAll(); };
  document.querySelectorAll('.tab').forEach(t => t.onclick = () => switchTab(t.dataset.tab));
  fillCiSelect();
  fillCiParamRows();
  $('#ciSend').onclick = ciSend;
  $('#ciClear').onclick = () => { $('#ciDebug').innerHTML = ''; };
  refreshAll();
  setAuto($('#autoRefresh').checked);
  log('Debug App 준비 완료. ncmpd가 실행 중이어야 SHM이 보입니다.');
}
document.addEventListener('DOMContentLoaded', wire);

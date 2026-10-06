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
  $('#connText').textContent = on ? 'ncmpd SHM 연결됨' : ('ncmpd 연결 안 됨' + (s.reason ? ' — ' + s.reason : ''));
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

  // last comm_thread <-> HSM exchange (raw + parsed)
  await renderLastMsg(body, SEL);
}

/* ---- comm<->HSM last message (TX/RX) rendering ---- */
const LM_CI = {0x0000:'NOP',0x0001:'RNG',0x0002:'DIGEST',0x0003:'GETMECHLIST',
  0x0004:'DIGEST_INIT',0x0005:'DIGEST_UPDATE',0x0006:'DIGEST_FINAL',0x0009:'SHAKE_DERIVE',
  0x0012:'AES_GCM',0x0013:'AES_CTR',0x0014:'AES_GCM_INIT',0x0015:'AES_GCM_UPDATE',
  0x0016:'AES_GCM_FINAL',0x0017:'CTX_FREE',0x0020:'OPEN_SESSION',0x0021:'CLOSE_SESSION',
  0x0030:'LOGIN',0x0031:'LOGOUT',0x0032:'INIT_PIN',0x0033:'SET_PIN',0x0034:'INIT_TOKEN',
  0x0035:'GET_UTC_TIME',0x0036:'GET_TOKEN_PARAMS',0x0037:'SET_UTC_TIME',0x0038:'OBJECT_ADD',
  0x0039:'OBJECT_SET_ATTR',0x0050:'MLDSA_KEYGEN',0x0051:'MLDSA_SIGN',0x0052:'MLDSA_VERIFY',
  0x0053:'MLKEM_KEYGEN',0x0054:'MLKEM_ENCAPS',0x0055:'MLKEM_DECAPS',0x0101:'VD_MEM_WRITE',
  0x0102:'VD_MEM_READ',0x0103:'VD_PING',0x0104:'VD_SELFTEST',0x0105:'VD_FW_INFO',
  0x0106:'VD_MEM_FILL',0x0107:'VD_MEM_CRC',0x0108:'VD_TOKEN_INFO'};
const LM_CKR = {0:'OK',5:'GENERAL_ERROR',6:'FUNCTION_FAILED',0x30:'DEVICE_ERROR',
  0x50:'FUNCTION_CANCELED',0x54:'FUNCTION_NOT_SUPPORTED',0xA0:'PIN_INCORRECT',
  0xB0:'SESSION_CLOSED',0xB3:'SESSION_HANDLE_INVALID'};
const lmHx = (n, w) => '0x' + (n >>> 0).toString(16).toUpperCase().padStart(w || 0, '0');
const lmCkr = (v) => LM_CKR[v] ? ('CKR_' + LM_CKR[v]) : ('CKR_0x' + (v >>> 0).toString(16).toUpperCase());
function lmFmtHex(h) {
  const b = (h.match(/.{1,2}/g) || []); let s = '';
  for (let i = 0; i < b.length; i++) s += b[i] + ((i % 16 === 15) ? '\n' : ' ');
  return s.trim() || '(empty)';
}
function lmBlock(label, f) {
  const d = el('div', { className: 'frame' });
  const trunc = f.cap < f.len;
  d.append(el('div', { className: 'lbl', textContent:
    `${label} — raw (Hex)` + (f.len ? (trunc ? ` · ${f.cap}/${f.len}B (truncated)` : ` · ${f.len}B`) : '') }));
  d.append(el('pre', { className: 'hex', textContent: f.len ? lmFmtHex(f.hex || '') : '(없음)' }));
  d.append(el('div', { className: 'lbl', textContent: label + ' — parsed' }));
  if (f.parsed) {
    const t = el('table', { className: 'pf' });
    const row = (k, v) => t.append(el('tr', {}, el('td', { className: 'k', textContent: k }), el('td', { textContent: v })));
    /* Row whose value cell holds arbitrary nodes (e.g. a file-open button). */
    const rowNode = (k, ...nodes) => t.append(el('tr', {}, el('td', { className: 'k', textContent: k }), el('td', {}, ...nodes)));
    row('frame_len', String(f.frameLen));
    row('session_id', `${f.sessionId} (${lmHx(f.sessionId)})`);
    row('sequence_id', String(f.sequenceId));
    row('command_id', `${lmHx(f.commandId, 4)}  ${LM_CI[f.commandId] || '?'}`);
    row('ack', `${lmHx(f.ack)}  ${lmCkr(f.ack)}`);
    row('payload_len', String(f.payloadLen));
    for (const p of (f.params || [])) {
      if (p.file) {
        /* Oversized parameter (>512B): the server spilled its Hex to a text file
         * served under /lmfile/. Show the name + a button that opens it in a new
         * window/tab. */
        const capNote = (p.captured != null && p.captured < p.len)
          ? ` · 캡처 ${p.captured}B (프레임 캡처 잘림)` : '';
        const name = el('span', { className: 'mono', textContent: p.file });
        const btn = el('button', { className: 'link', textContent: '열기' });
        btn.onclick = () => window.open('/lmfile/' + encodeURIComponent(p.file), '_blank', 'noopener');
        rowNode(`param[${p.idx}]`, document.createTextNode(`len ${p.len}B${capNote} · Hex 파일 `), name, document.createTextNode(' '), btn);
      } else {
        const note = p.truncated ? ` (표시 ${p.shown != null ? p.shown : (p.hex ? p.hex.length / 2 : 0)}B, 잘림)` : '';
        row(`param[${p.idx}]`, `len ${p.len}${note} : ${p.hex || '(0)'}`);
      }
    }
    if (!(f.params || []).length) row('params', '(없음)');
    d.append(t);
  } else {
    d.append(el('div', { className: 'muted small', textContent: f.len ? '파싱 불가(헤더 미만 캡처)' : '(없음)' }));
  }
  return d;
}
async function renderLastMsg(body, slot) {
  body.append(el('h3', { textContent: 'comm ↔ HSM 마지막 메시지 (TX/RX raw + parsed)' }));
  let d;
  try { d = await api('/api/lastmsg', { slot }); } catch { d = null; }
  if (!d || d.error || d.connected === false) {
    body.append(el('div', { className: 'muted small', textContent: '(없음)' }));
    return;
  }
  const wrap = el('div', { className: 'frames2' });
  wrap.append(lmBlock('송신(TX → HSM)', d.tx || { len: 0 }));
  wrap.append(lmBlock('수신(RX ← HSM)', d.rx || { len: 0 }));
  body.append(wrap);
  /* Help the common "왜 비어 있나" case: a slot can be ONLINE yet have never
   * exchanged a frame. The usual cause is that the session was opened via the
   * Test App's "ID로 추가"(adopt) path, which does NOT send OPEN_SESSION to the
   * token (it just reuses a wire session_id locally), so comm<->HSM has nothing
   * to show until a real command is sent. A real "새 세션"(C_OpenSession) or any
   * crypto/login call populates TX/RX here. */
  const txLen = (d.tx && d.tx.len) || 0;
  const rxLen = (d.rx && d.rx.len) || 0;
  if (!txLen && !rxLen) {
    body.append(el('div', { className: 'muted small', textContent:
      '송신/수신이 비어 있음: 이 슬롯은 아직 토큰과 프레임을 주고받지 않았습니다. ' +
      'Test App에서 "ID로 추가"(adopt)로 연 세션은 토큰에 OPEN_SESSION을 보내지 ' +
      '않으므로 여기에 표시되지 않습니다 — 실제 통신을 보려면 "새 세션"(C_OpenSession) ' +
      '또는 로그인·난수·암복호 등 명령을 보내세요.' }));
  }
}

async function refreshAll() { await refreshStatus(); await refreshSlots(); await refreshDetail(); }

/* Periodic auto-refresh of the SHM view. Interval comes from #refreshSec
 * (seconds, default 1). A refresh in flight is skipped so a slow poll never
 * stacks up. */
let refreshing = false;
async function tick() {
  if (refreshing) return;
  refreshing = true;
  try { await refreshAll(); } finally { refreshing = false; }
}
function refreshMs() {
  const s = Number($('#refreshSec').value);
  return (isFinite(s) && s >= 1 ? s : 1) * 1000;
}
function setAuto(on) {
  if (timer) { clearInterval(timer); timer = null; }
  if (on) timer = setInterval(tick, refreshMs());
}

function wire() {
  initTheme();
  $('#themeToggle').onclick = () => applyTheme(document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light');
  $('#btnClearLog').onclick = () => { $('#log').textContent = ''; };
  $('#autoRefresh').onchange = (e) => setAuto(e.target.checked);
  $('#refreshSec').onchange = () => { if ($('#autoRefresh').checked) setAuto(true); };
  $('#btnReconnect').onclick = async () => { const d = await api('/api/reconnect'); log('재연결: ' + (d.connected ? 'OK' : ('실패' + (d.reason ? ' — ' + d.reason : '')))); refreshAll(); };
  refreshAll();
  setAuto($('#autoRefresh').checked);
  log('Debug App 준비 완료. ncmpd가 실행 중이어야 SHM이 보입니다. 자동 새로고침 기본 1초.');
}
document.addEventListener('DOMContentLoaded', wire);

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
  $('#btnReconnect').onclick = async () => { const d = await api('/api/reconnect'); log('재연결: ' + (d.connected ? 'OK' : '실패')); refreshAll(); };
  refreshAll();
  setAuto($('#autoRefresh').checked);
  log('Debug App 준비 완료. ncmpd가 실행 중이어야 SHM이 보입니다. 자동 새로고침 기본 1초.');
}
document.addEventListener('DOMContentLoaded', wire);

'use strict';
/* Paper Panel · MCDRS 设计系统 · 单列无侧栏版
   三层架构：数据层 → 计算层 → 渲染层；refreshAll() 统一调度，渲染函数互不调用 */

/* ============================== 数据层 ============================== */
var state = {
  token: null,          // 仅存内存，不落 localStorage（每次进入均需密码）
  stats: null,
  tpsHist: [],
  lines: [],
  maxLines: 600,
  autoscroll: true,
  connected: false,
  streamAbort: null,
  levelFilter: 'ALL',
  searchQuery: ''
};

var QUICK_KEY = 'paper-panel-quick';
var DEFAULT_QUICK = ['tps', 'list', 'save-all', 'whitelist list'];

var quickCmds = [];
function loadQuick() {
  try {
    var raw = localStorage.getItem(QUICK_KEY);
    if (raw) { quickCmds = JSON.parse(raw); return; }
  } catch (_) {}
  quickCmds = DEFAULT_QUICK.slice();
}
function saveQuick() {
  try { localStorage.setItem(QUICK_KEY, JSON.stringify(quickCmds)); } catch (_) {}
}

function api(path, options) {
  options = options || {};
  var headers = { 'Content-Type': 'application/json' };
  if (state.token) headers['Authorization'] = 'Bearer ' + state.token;
  return fetch(path, {
    method: options.method || 'GET',
    headers: headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
    cache: 'no-store'
  }).then(function (res) {
    return res.json().catch(function () { return {}; }).then(function (data) {
      if (!res.ok) {
        var err = new Error(data.error || ('请求失败 ' + res.status));
        err.status = res.status;
        throw err;
      }
      return data;
    });
  });
}

function login(password) {
  return api('/api/nonce').then(function (n) {
    // 校验值 = SHA256(nonce + ":" + SHA256(password))，明文密码不离开浏览器
    var inner = sha256Hex(password);
    var digest = sha256Hex(n.nonce + ':' + inner);
    return api('/api/login', { method: 'POST', body: { nonce: n.nonce, digest: digest } });
  });
}

function logout() {
  return api('/api/logout', { method: 'POST', body: {} }).catch(function () {});
}

function connectStream() {
  if (state.streamAbort) { try { state.streamAbort.abort(); } catch (_) {} }
  var ctrl = new AbortController();
  state.streamAbort = ctrl;
  fetch('/api/stream', {
    headers: { 'Authorization': 'Bearer ' + state.token },
    cache: 'no-store',
    signal: ctrl.signal
  }).then(function (res) {
    if (!res.ok || !res.body) throw new Error('stream ' + res.status);
    setConn(true);
    var reader = res.body.getReader();
    var decoder = new TextDecoder();
    var buf = '';
    function pump() {
      return reader.read().then(function (r) {
        if (r.done) throw new Error('stream closed');
        buf += decoder.decode(r.value, { stream: true });
        var idx;
        while ((idx = buf.indexOf('\n\n')) >= 0) {
          handleSseBlock(buf.slice(0, idx));
          buf = buf.slice(idx + 2);
        }
        return pump();
      });
    }
    return pump();
  }).catch(function () {
    setConn(false);
    if (state.token) setTimeout(connectStream, 2500);
  });
}

function handleSseBlock(block) {
  var ev = 'message', data = '';
  block.split('\n').forEach(function (line) {
    if (line.indexOf('event:') === 0) ev = line.slice(6).trim();
    else if (line.indexOf('data:') === 0) data += line.slice(5).trim();
  });
  if (!data) return;
  var obj;
  try { obj = JSON.parse(data); } catch (_) { return; }
  if (ev === 'backlog') { obj.forEach(pushLine); refreshAll(); }
  else if (ev === 'log') { pushLine(obj); renderConsole(); renderCounts(); }
  else if (ev === 'stats') { onStats(obj); }
}

function pushLine(entry) {
  state.lines.push(entry);
  if (state.lines.length > state.maxLines) state.lines.splice(0, state.lines.length - state.maxLines);
}

function onStats(s) {
  state.stats = s;
  if (s && s.tpsHist && s.tpsHist.length) {
    state.tpsHist = s.tpsHist.slice(-40);
  } else if (s && s.tps) {
    state.tpsHist.push(s.tps[0]);
    if (state.tpsHist.length > 40) state.tpsHist.shift();
  }
  refreshAll();
}

/* ============================== 计算层 ============================== */
function el(id) { return document.getElementById(id); }

function fmtBytes(n) {
  if (!n && n !== 0) return '--';
  var u = ['B', 'KB', 'MB', 'GB', 'TB'];
  var i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return (Math.round(v * 10) / 10) + ' ' + u[i];
}

function tpsQuality(t) {
  if (t >= 19.5) return { label: '流畅', cls: 'good' };
  if (t >= 17) return { label: '波动', cls: 'warn' };
  return { label: '卡顿', cls: 'bad' };
}

function cpuQuality(c) {
  if (c < 60) return { label: '正常', cls: 'good' };
  if (c < 85) return { label: '偏高', cls: 'warn' };
  return { label: '高压', cls: 'bad' };
}

function sparkPoints(hist, w, h) {
  if (!hist.length) return '';
  var min = 17, max = 20.4;
  var n = hist.length;
  return hist.map(function (v, i) {
    var x = n <= 1 ? w : (i / (n - 1)) * w;
    var y = h - ((v - min) / (max - min)) * h;
    y = Math.max(2, Math.min(h - 2, y));
    return x.toFixed(1) + ',' + y.toFixed(1);
  }).join(' ');
}

function countLevels() {
  var c = { WARN: 0, ERROR: 0 };
  state.lines.forEach(function (e) { if (c[e.level] != null) c[e.level]++; });
  return c;
}

function lineVisible(entry) {
  if (state.levelFilter !== 'ALL' && entry.level !== state.levelFilter) return false;
  if (state.searchQuery && (entry.text || '').toLowerCase().indexOf(state.searchQuery) < 0) return false;
  return true;
}

function nowHMS() {
  var d = new Date();
  var p = function (n) { return String(n).padStart(2, '0'); };
  return p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
}

/* ============================== Toast ============================== */
function toast(msg) {
  var box = el('toasts');
  var t = document.createElement('div');
  t.className = 'toast';
  t.innerHTML = '<svg aria-hidden="true"><use href="#i-check"/></svg><span class="toast__msg"></span>';
  t.querySelector('.toast__msg').textContent = msg;
  box.appendChild(t);
  var kill = function () {
    t.classList.add('is-leaving');
    setTimeout(function () { t.remove(); }, 150);
  };
  t.addEventListener('click', kill);
  setTimeout(kill, 2600);
}

/* ============================== 渲染层 ============================== */
function renderLoginError(msg) {
  var box = el('login-error');
  if (!msg) { box.hidden = true; box.textContent = ''; return; }
  box.hidden = false;
  box.textContent = msg;
}

function renderStats() {
  var s = state.stats;
  if (!s) return;

  var t1 = s.tps && s.tps[0] != null ? s.tps[0] : 0;
  el('tps-value').textContent = t1.toFixed(1);
  el('tps-detail').textContent = (s.tps || []).map(function (v) { return v.toFixed(1); }).join(' / ');
  var q = tpsQuality(t1);
  var badge = el('tps-badge');
  badge.textContent = q.label;
  badge.className = 'tag ' + q.cls;

  el('players-value').textContent = s.players ? s.players.online : '--';
  el('players-max').textContent = '/ 上限 ' + (s.players ? s.players.max : '--');
  var pb = el('players-badge');
  pb.textContent = s.players && s.players.online > 0 ? s.players.online + ' 人在线' : '空闲';
  pb.className = 'tag ' + (s.players && s.players.online > 0 ? 'good' : '');

  el('cpu-value').textContent = s.cpu != null ? s.cpu.toFixed(0) : '--';
  var cq = cpuQuality(s.cpu || 0);
  var cb = el('cpu-badge');
  cb.textContent = cq.label;
  cb.className = 'tag ' + cq.cls;
  el('cpu-meter').style.setProperty('--w', Math.min(100, s.cpu || 0) + '%');

  // 页头状态行
  var online = t1 >= 17 && (s.cpu || 0) < 90;
  el('side-dot').className = 'srv__dot ' + (online ? 'is-online' : 'is-offline');
  el('side-status').textContent = online ? '服务器运行正常' : '状态异常 · TPS ' + t1.toFixed(1);
  if (s.mem) {
    var pct = s.mem.total ? (s.mem.used / s.mem.total) * 100 : 0;
    el('mem-value').textContent = fmtBytes(s.mem.used) + ' / ' + fmtBytes(s.mem.total) + '（' + pct.toFixed(0) + '%）';
    el('side-mem').textContent = '内存 ' + fmtBytes(s.mem.used) + ' · ' + pct.toFixed(0) + '%';
  }

  el('stats-time').textContent = nowHMS() + ' 刷新';
}

function renderTpsSpark() {
  el('tps-line').setAttribute('points', sparkPoints(state.tpsHist, 260, 44));
}

function renderPlayers() {
  var box = el('player-chips');
  box.textContent = '';
  var names = (state.stats && state.stats.players && state.stats.players.names) || [];
  if (!names.length) {
    var e = document.createElement('span');
    e.className = 'chips__empty';
    e.textContent = '当前没有在线玩家';
    box.appendChild(e);
    return;
  }
  names.slice(0, 10).forEach(function (n) {
    var chip = document.createElement('span');
    chip.className = 'chip';
    var nameSpan = document.createElement('span');
    nameSpan.textContent = n;
    nameSpan.title = '点击填充 whisper';
    var kick = document.createElement('span');
    kick.className = 'chip-x';
    kick.title = '踢出';
    kick.textContent = '×';
    chip.appendChild(nameSpan);
    chip.appendChild(kick);
    box.appendChild(chip);
  });
  if (names.length > 10) {
    var more = document.createElement('span');
    more.className = 'chips__empty';
    more.textContent = '…等 ' + names.length + ' 人';
    box.appendChild(more);
  }
}

function lineNode(entry) {
  var div = document.createElement('div');
  div.className = 'line line-' + (entry.level || 'OTHER') + (entry.cls ? ' ' + entry.cls : '');
  var t = document.createElement('span');
  t.className = 'lt';
  t.textContent = entry.t || '';
  var x = document.createElement('span');
  x.className = 'lx';
  x.textContent = entry.text;
  div.appendChild(t);
  div.appendChild(x);
  return div;
}

function renderConsole() {
  var out = el('console-out');
  out.textContent = '';
  var frag = document.createDocumentFragment();
  var visible = 0;
  state.lines.forEach(function (e) {
    if (!lineVisible(e)) return;
    visible++;
    frag.appendChild(lineNode(e));
  });
  if (!visible) {
    var none = document.createElement('div');
    none.className = 'no-match';
    none.textContent = state.lines.length ? '没有匹配的日志' : '等待服务器输出…';
    frag.appendChild(none);
  }
  out.appendChild(frag);
  if (state.autoscroll) out.scrollTop = out.scrollHeight;
}

function renderCounts() {
  var c = countLevels();
  el('cnt-warn').textContent = c.WARN ? String(c.WARN) : '';
  el('cnt-error').textContent = c.ERROR ? String(c.ERROR) : '';
}

function renderQuick() {
  var bar = el('quick-bar');
  bar.textContent = '';
  quickCmds.forEach(function (cmd, i) {
    var chip = document.createElement('button');
    chip.type = 'button';
    chip.className = 'qchip';
    chip.title = '点击执行：' + cmd;
    var label = document.createElement('span');
    label.textContent = cmd;
    var del = document.createElement('span');
    del.className = 'qchip-x';
    del.title = '删除';
    del.textContent = '×';
    chip.appendChild(label);
    chip.appendChild(del);
    chip.addEventListener('click', function (ev) {
      if (ev.target.closest('.qchip-x')) {
        quickCmds.splice(i, 1);
        saveQuick();
        renderQuick();
        toast('已删除「' + cmd + '」');
        return;
      }
      sendCommand(cmd);
    });
    bar.appendChild(chip);
  });
  // 添加按钮
  var add = document.createElement('button');
  add.type = 'button';
  add.className = 'qchip qchip--add';
  add.title = '添加常用指令';
  add.textContent = '＋ 添加';
  add.addEventListener('click', function () {
    var cmd = window.prompt('输入要收藏的指令：');
    if (cmd && cmd.trim()) {
      cmd = cmd.trim();
      if (cmd.startsWith('/')) cmd = cmd.slice(1);
      quickCmds.push(cmd);
      saveQuick();
      renderQuick();
      toast('已添加「' + cmd + '」');
    }
  });
  bar.appendChild(add);
}

function renderConn() {
  if (!state.connected) el('side-dot').className = 'srv__dot is-offline';
  el('side-status').textContent = state.connected
    ? (state.stats ? '服务器运行正常' : '已连接，等待数据…')
    : '连接断开，重连中…';
}

function refreshAll() {
  renderStats();
  renderTpsSpark();
  renderPlayers();
  renderConsole();
  renderCounts();
  renderConn();
}

/* ============================== 交互 ============================== */
function setConn(on) {
  state.connected = on;
  renderConn();
}

function appendLocal(text, cls, level) {
  pushLine({ t: nowHMS(), level: level || 'OTHER', text: text, cls: cls || '' });
  renderConsole();
  renderCounts();
}

var cmdHistory = [];
var histPos = -1;

function sendCommand(cmd) {
  if (!cmd || !state.token) return;
  var dangerous = /^(stop|restart|reload|op|deop|ban|ban-ip|whitelist|pardon|kill|kick)\b/i;
  if (dangerous.test(cmd)) {
    if (!window.confirm('指令「' + cmd + '」可能产生破坏性影响，确定要发送吗？')) return;
  }
  appendLocal('> ' + cmd, 'line-cmd', 'INFO');
  api('/api/command', { method: 'POST', body: { command: cmd } }).then(function (r) {
    appendLocal(r.output || '(无输出)', '', 'OTHER');
  }).catch(function (err) {
    appendLocal('[面板] ' + (err.message || '指令发送失败'), '', 'ERROR');
    if (err.status === 401) resetToLogin('会话已失效，请重新登录');
  });
}

function enterApp() {
  el('login-view').hidden = true;
  el('app-view').hidden = false;
  el('logout-btn').hidden = false;
  loadQuick();
  renderQuick();
  refreshAll();
  connectStream();
}

function resetToLogin(msg) {
  state.token = null;
  if (state.streamAbort) { try { state.streamAbort.abort(); } catch (_) {} }
  setConn(false);
  el('app-view').hidden = true;
  el('login-view').hidden = false;
  el('logout-btn').hidden = true;
  el('password').value = '';
  if (msg) renderLoginError(msg);
  el('password').focus();
}

function applyTheme(mode) {
  document.documentElement.dataset.theme = mode;
  try { localStorage.setItem('paper-panel-theme', mode); } catch (_) {}
  var lbl = el('theme-label');
  if (lbl) lbl.textContent = mode === 'dark' ? '浅色' : '深色';
}

(function initTheme() {
  var saved = null;
  try { saved = localStorage.getItem('paper-panel-theme'); } catch (_) {}
  applyTheme(saved || 'dark'); // 与 MCDRS 站点一致，默认深色
})();

/* ---- 登录 ---- */
el('toggle-pw').addEventListener('click', function () {
  var input = el('password');
  input.type = input.type === 'text' ? 'password' : 'text';
  input.focus();
});

el('login-form').addEventListener('submit', function (e) {
  e.preventDefault();
  renderLoginError('');
  var pw = el('password').value;
  if (!pw) { renderLoginError('请输入密码'); return; }
  var btn = el('login-btn');
  btn.disabled = true;
  btn.textContent = '验证中…';
  login(pw).then(function (data) {
    state.token = data.token;
    el('password').value = '';
    btn.disabled = false;
    btn.textContent = '进入控制台';
    enterApp();
  }).catch(function (err) {
    btn.disabled = false;
    btn.textContent = '进入控制台';
    renderLoginError(err.message || '登录失败');
    el('password').value = '';
    el('password').focus();
  });
});

el('logout-btn').addEventListener('click', function () {
  logout().then(function () { resetToLogin('已退出登录'); });
});

/* ---- 主题切换 ---- */
el('theme-btn').addEventListener('click', function () {
  applyTheme(document.documentElement.dataset.theme === 'light' ? 'dark' : 'light');
});

/* ---- 分段筛选器：日志级别 ---- */
document.querySelectorAll('.seg-btn[data-filter]').forEach(function (btn) {
  btn.addEventListener('click', function () {
    document.querySelectorAll('.seg-btn[data-filter]').forEach(function (b) { b.classList.remove('is-active'); });
    btn.classList.add('is-active');
    state.levelFilter = btn.dataset.filter;
    var map = { ALL: '控制台', INFO: '信息', WARN: '警告', ERROR: '错误' };
    el('crumb-title').textContent = map[state.levelFilter] || '控制台';
    renderConsole();
  });
});

/* ---- 日志搜索 ---- */
el('log-search').addEventListener('input', function () {
  state.searchQuery = this.value.trim().toLowerCase();
  renderConsole();
});

/* ---- 玩家 chips：点名字发悄悄话、×踢人 ---- */
el('player-chips').addEventListener('click', function (e) {
  var chip = e.target.closest('.chip');
  if (!chip) return;
  var name = chip.querySelector('span:not(.chip-x)').textContent;
  if (e.target.classList.contains('chip-x')) {
    sendCommand('kick ' + name);
  } else {
    var input = el('cmd-input');
    input.value = 'tell ' + name + ' ';
    input.focus();
  }
});

/* ---- 清空 ---- */
el('clear-btn').addEventListener('click', function () {
  state.lines = [];
  renderConsole();
  renderCounts();
  toast('已清空当前显示');
});

/* ---- 顶栏滚动态 ---- */
window.addEventListener('scroll', function () {
  document.querySelector('.topbar').classList.toggle('is-scrolled', window.scrollY > 0);
}, { passive: true });

/* ---- 卡片指针柔光（同 MCDRS） ---- */
document.querySelectorAll('.card.stat').forEach(function (card) {
  card.addEventListener('pointermove', function (e) {
    var r = card.getBoundingClientRect();
    card.style.setProperty('--mx', (e.clientX - r.left) + 'px');
    card.style.setProperty('--my', (e.clientY - r.top) + 'px');
  });
});

/* ---- 全屏专注模式 ---- */
var consoleCard = document.querySelector('.console-card');

function fsActive() {
  return !!(document.fullscreenElement || document.webkitFullscreenElement ||
    consoleCard.classList.contains('immersive'));
}
function updateFsBtn() {
  var on = fsActive();
  document.body.classList.toggle('fs-mode', on);
  var btn = el('fs-btn');
  btn.querySelector('.ic-expand').hidden = on;
  btn.querySelector('.ic-compress').hidden = !on;
  el('fs-label').textContent = on ? '退出' : '全屏';
  btn.setAttribute('aria-label', on ? '退出全屏' : '全屏显示控制台');
  if (on) {
    var out = el('console-out');
    if (state.autoscroll) out.scrollTop = out.scrollHeight;
    el('cmd-input').focus();
  }
}
function enterImmersive() {
  consoleCard.classList.add('immersive');
  document.body.classList.add('no-scroll');
  updateFsBtn();
}
function exitImmersive() {
  consoleCard.classList.remove('immersive');
  document.body.classList.remove('no-scroll');
  updateFsBtn();
}
function enterFs() {
  var req = consoleCard.requestFullscreen || consoleCard.webkitRequestFullscreen;
  if (req) {
    var p = req.call(consoleCard);
    if (p && p.catch) p.catch(enterImmersive);
  } else {
    enterImmersive();
  }
}
function exitFs() {
  if (document.exitFullscreen && document.fullscreenElement) document.exitFullscreen();
  else if (document.webkitExitFullscreen && document.webkitFullscreenElement) document.webkitExitFullscreen();
  else exitImmersive();
}
el('fs-btn').addEventListener('click', function () {
  if (fsActive()) exitFs();
  else enterFs();
});
document.addEventListener('fullscreenchange', function () {
  if (!document.fullscreenElement) exitImmersive();
  updateFsBtn();
});
document.addEventListener('webkitfullscreenchange', function () {
  if (!document.webkitFullscreenElement) exitImmersive();
  updateFsBtn();
});
document.addEventListener('keydown', function (e) {
  if (e.key === 'Escape' && consoleCard.classList.contains('immersive')) exitImmersive();
});

/* ---- 自动滚动 ---- */
el('autoscroll').addEventListener('change', function () {
  state.autoscroll = this.checked;
  if (state.autoscroll) {
    var out = el('console-out');
    out.scrollTop = out.scrollHeight;
  }
});

el('console-out').addEventListener('scroll', function () {
  if (!state.autoscroll) return;
  var out = this;
  var nearBottom = out.scrollHeight - out.scrollTop - out.clientHeight < 24;
  if (!nearBottom) {
    state.autoscroll = false;
    el('autoscroll').checked = false;
  }
});

/* ---- 指令输入与历史 ---- */
el('cmd-form').addEventListener('submit', function (e) {
  e.preventDefault();
  var input = el('cmd-input');
  var cmd = input.value.trim();
  if (!cmd) return;
  input.value = '';
  if (cmd.startsWith('/')) cmd = cmd.slice(1);
  if (cmdHistory[cmdHistory.length - 1] !== cmd) {
    cmdHistory.push(cmd);
    if (cmdHistory.length > 50) cmdHistory.shift();
  }
  histPos = -1;
  sendCommand(cmd);
});

el('cmd-input').addEventListener('keydown', function (e) {
  if (e.key !== 'ArrowUp' && e.key !== 'ArrowDown') return;
  if (!cmdHistory.length) return;
  e.preventDefault();
  if (e.key === 'ArrowUp') {
    histPos = histPos < 0 ? cmdHistory.length - 1 : Math.max(0, histPos - 1);
  } else {
    if (histPos < 0) return;
    histPos++;
    if (histPos >= cmdHistory.length) { histPos = -1; this.value = ''; return; }
  }
  this.value = cmdHistory[histPos];
});

/* ---- 首屏 ---- */
window.addEventListener('DOMContentLoaded', function () {
  refreshAll();
  el('password').focus();
});

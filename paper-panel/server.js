'use strict';

/**
 * Paper 服务器控制台面板 —— 零依赖 Node.js 后端
 *
 * 安全设计：
 *  - 面板密码只存在 config.json（服务端），前端与网络传输中均不出现明文密码
 *  - 登录采用「随机 nonce + SHA-256 校验值」挑战应答，一次性 nonce 防重放
 *  - 会话令牌仅存内存，页面刷新即失效（每次进入都需输入密码）
 *  - 登录失败限速 + 锁定；全程安全响应头；静态资源白名单，无目录遍历
 */

const http = require('http');
const https = require('https');
const net = require('net');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const CONFIG_PATH = path.join(ROOT, 'config.json');

/* ============================== 配置 ============================== */

function loadConfig() {
  const defaults = {
    port: 52369,
    host: '0.0.0.0',
    password: 'change-me-123',
    mock: true,
    sessionTtlMinutes: 480,
    logPath: 'logs/latest.log',
    logBacklogLines: 80,
    logBufferMax: 800,
    loginMaxFails: 8,
    loginLockSeconds: 300,
    rcon: { host: '127.0.0.1', port: 25575, password: '', timeoutMs: 5000 },
    tls: { enabled: false, certFile: '', keyFile: '' }
  };
  let user = {};
  try {
    user = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  } catch (e) {
    console.warn('[config] 读取 config.json 失败，使用默认配置: ' + e.message);
  }
  const cfg = Object.assign({}, defaults, user);
  cfg.rcon = Object.assign({}, defaults.rcon, user.rcon || {});
  cfg.tls = Object.assign({}, defaults.tls, user.tls || {});
  return cfg;
}

const cfg = loadConfig();
const MOCK = !!cfg.mock;

function sha256Hex(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}
function safeEqualHex(a, b) {
  const ba = Buffer.from(String(a), 'utf8');
  const bb = Buffer.from(String(b), 'utf8');
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

// 服务端只保留密码的派生校验量，比较时使用恒定时间函数
const PASSWORD_INNER = sha256Hex(String(cfg.password));

/* ============================== 会话 / Nonce / 限速 ============================== */

const sessions = new Map(); // token -> expireAt(ms)
const nonces = new Map();   // nonce -> expireAt(ms)
const loginGate = new Map();// ip -> { fails, windowStart, lockedUntil }

function issueToken() {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, Date.now() + cfg.sessionTtlMinutes * 60000);
  return token;
}
function checkToken(token) {
  if (!token) return false;
  const exp = sessions.get(token);
  if (!exp) return false;
  if (Date.now() > exp) { sessions.delete(token); return false; }
  return true;
}
function issueNonce() {
  const n = crypto.randomBytes(16).toString('hex');
  nonces.set(n, Date.now() + 120000);
  return n;
}
function consumeNonce(n) {
  const exp = nonces.get(n);
  if (!exp) return false;
  nonces.delete(n);
  return Date.now() <= exp;
}
function gateStatus(ip) {
  const now = Date.now();
  let rec = loginGate.get(ip);
  if (!rec) { rec = { fails: 0, windowStart: now, lockedUntil: 0 }; loginGate.set(ip, rec); }
  if (rec.lockedUntil > now) return { locked: true, waitSec: Math.ceil((rec.lockedUntil - now) / 1000) };
  if (now - rec.windowStart > 10 * 60000) { rec.fails = 0; rec.windowStart = now; }
  return { locked: false, rec };
}
function gateFail(ip) {
  const st = gateStatus(ip);
  if (st.locked) return st.waitSec;
  const rec = st.rec;
  rec.fails += 1;
  if (rec.fails >= cfg.loginMaxFails) {
    rec.lockedUntil = Date.now() + cfg.loginLockSeconds * 1000;
    rec.fails = 0;
    return cfg.loginLockSeconds;
  }
  return 0;
}

setInterval(() => {
  const now = Date.now();
  for (const [t, exp] of sessions) if (now > exp) sessions.delete(t);
  for (const [n, exp] of nonces) if (now > exp) nonces.delete(n);
}, 60000).unref();

/* ============================== RCON 客户端 ============================== */

class RconClient {
  constructor(opts) {
    this.opts = opts;
    this.sock = null;
    this.buf = Buffer.alloc(0);
    this.nextId = 1;
    this.pending = new Map();
    this.ready = false;
  }
  connect() {
    return new Promise((resolve, reject) => {
      const sock = net.connect(this.opts.port, this.opts.host);
      this.sock = sock;
      sock.setNoDelay(true);
      sock.on('data', (d) => this._onData(d));
      sock.on('error', (e) => { this.ready = false; reject(e); });
      sock.on('close', () => {
        this.ready = false;
        for (const [, p] of this.pending) p.reject(new Error('rcon closed'));
        this.pending.clear();
      });
      sock.on('connect', async () => {
        try {
          await this._auth();
          this.ready = true;
          resolve();
        } catch (e) {
          sock.destroy();
          reject(e);
        }
      });
    });
  }
  _pack(type, body) {
    const payload = Buffer.concat([
      Buffer.from(String(body), 'utf8'),
      Buffer.from([0x00, 0x00])
    ]);
    const head = Buffer.alloc(12);
    head.writeInt32LE(12 - 4 + payload.length, 0);
    head.writeInt32LE(this.nextId++, 4);
    head.writeInt32LE(type, 8);
    return Buffer.concat([head, payload]);
  }
  _onData(d) {
    this.buf = Buffer.concat([this.buf, d]);
    while (this.buf.length >= 4) {
      const len = this.buf.readInt32LE(0);
      if (len < 10 || len > 2 * 1024 * 1024) { this.buf = Buffer.alloc(0); return; }
      if (this.buf.length < 4 + len) return;
      const pkt = this.buf.slice(4, 4 + len);
      this.buf = this.buf.slice(4 + len);
      const id = pkt.readInt32LE(0);
      const type = pkt.readInt32LE(4);
      const body = pkt.slice(8, pkt.length - 2).toString('utf8');
      const p = this.pending.get(id);
      if (p) {
        clearTimeout(p.timer);
        this.pending.delete(id);
        p.resolve({ id: id, type: type, body: body });
      }
    }
  }
  _send(type, body) {
    const self = this;
    return new Promise(function (resolve, reject) {
      const pkt = self._pack(type, body);
      const id = pkt.readInt32LE(4);
      const timer = setTimeout(function () {
        self.pending.delete(id);
        reject(new Error('rcon timeout'));
      }, self.opts.timeoutMs || 5000);
      self.pending.set(id, { resolve: resolve, reject: reject, timer: timer });
      self.sock.write(pkt);
    });
  }
  async _auth() {
    const resp = await this._send(3, this.opts.password || '');
    if (resp.id === -1) throw new Error('rcon 认证失败');
  }
  command(cmd) {
    if (!this.ready) return Promise.reject(new Error('rcon 未连接'));
    return this._send(2, cmd).then(function (r) { return r.body; });
  }
  destroy() {
    if (this.sock) { try { this.sock.destroy(); } catch (_) {} }
    this.ready = false;
  }
}

const rcon = new RconClient(cfg.rcon);

/* ============================== 指标采集 ============================== */

let prevCpu = os.cpus();
function cpuUsagePercent() {
  const cur = os.cpus();
  let idleD = 0, totalD = 0;
  for (let i = 0; i < cur.length; i++) {
    const c = cur[i], p = prevCpu[i] || c;
    let idle = c.times.idle - p.times.idle;
    let total = 0;
    for (const k of Object.keys(c.times)) total += (c.times[k] - (p.times[k] || 0));
    if (total <= 0) {
      idle = c.times.idle;
      total = Object.keys(c.times).reduce(function (s, k) { return s + c.times[k]; }, 0);
    }
    idleD += idle; totalD += total;
  }
  prevCpu = cur;
  if (totalD <= 0) return 0;
  return Math.max(0, Math.min(100, (1 - idleD / totalD) * 100));
}

function stripColor(s) { return String(s).replace(/§./g, ''); }

function parseTps(out) {
  const m = stripColor(out).match(/([\d.]+),\s*([\d.]+),\s*([\d.]+)/);
  if (!m) return null;
  return [parseFloat(m[1]), parseFloat(m[2]), parseFloat(m[3])];
}
function parseList(out) {
  const s = stripColor(out);
  const m = s.match(/are\s+(\d+)\s+of\s+a\s+max\s+of\s+(\d+)\s+players?\s+online:?\s*(.*)/i);
  if (!m) return null;
  const names = m[3] ? m[3].split(',').map(function (x) { return x.trim(); }).filter(Boolean) : [];
  return { online: parseInt(m[1], 10), max: parseInt(m[2], 10), names: names };
}

// mock 状态
const mock = {
  tps: [20, 20, 20],
  players: { online: 3, max: 20, names: ['Steve', 'Alex', 'Notch_Fan'] },
  cpu: 27.5,
  memUsed: 4.2e9
};

let stats = {
  tps: [20, 20, 20],
  players: { online: 0, max: 0, names: [] },
  cpu: 0,
  mem: { used: 0, total: os.totalmem() },
  ts: Date.now(),
  mock: MOCK
};

const tpsHistory = [];

async function refreshStats() {
  const cpu = MOCK ? mock.cpu : cpuUsagePercent();
  let tps = stats.tps;
  let players = stats.players;
  if (MOCK) {
    tps = mock.tps.map(function (v) { return Math.round(v * 100) / 100; });
    players = {
      online: mock.players.online,
      max: mock.players.max,
      names: mock.players.names.slice()
    };
  } else if (rcon.ready) {
    try {
      const t = parseTps(await rcon.command('tps'));
      if (t) tps = t;
    } catch (_) {}
    try {
      const p = parseList(await rcon.command('list'));
      if (p) players = p;
    } catch (_) {}
  }
  tpsHistory.push(tps[0]);
  if (tpsHistory.length > 40) tpsHistory.shift();
  stats = {
    tps: tps,
    tpsHist: tpsHistory.slice(),
    players: players,
    cpu: Math.round(cpu * 10) / 10,
    mem: {
      used: MOCK ? mock.memUsed : os.totalmem() - os.freemem(),
      total: os.totalmem()
    },
    ts: Date.now(),
    mock: MOCK
  };
  broadcast('stats', stats);
}

/* ============================== 日志尾随 + SSE ============================== */

const sseClients = new Set();
const logRing = [];
let logSeq = 0;
let logSize = -1;
const logPathResolved = path.isAbsolute(cfg.logPath) ? cfg.logPath : path.join(ROOT, cfg.logPath);

function levelOf(line) {
  if (/\b(ERROR|FATAL)\b/.test(line)) return 'ERROR';
  if (/\b(WARN|WARNING)\b/.test(line)) return 'WARN';
  if (/\bINFO\b/.test(line)) return 'INFO';
  return 'OTHER';
}
function nowStamp() {
  const d = new Date();
  const p = function (n) { return String(n).padStart(2, '0'); };
  return p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
}
function pushLog(raw) {
  const text = String(raw).replace(/\r$/, '');
  if (!text.trim()) return;
  const entry = { seq: ++logSeq, t: nowStamp(), level: levelOf(text), text: text };
  logRing.push(entry);
  if (logRing.length > cfg.logBufferMax) logRing.splice(0, logRing.length - cfg.logBufferMax);
  broadcast('log', entry);
}
function broadcast(event, data) {
  const chunk = 'event: ' + event + '\ndata: ' + JSON.stringify(data) + '\n\n';
  for (const res of sseClients) {
    try { res.write(chunk); } catch (_) {}
  }
}

function tailTick() {
  if (MOCK) return;
  let st;
  try { st = fs.statSync(logPathResolved); } catch (_) { return; }
  if (st.size < logSize) logSize = 0; // 日志轮转
  if (st.size === logSize) return;
  try {
    const fd = fs.openSync(logPathResolved, 'r');
    const len = st.size - logSize;
    const buf = Buffer.alloc(len);
    fs.readSync(fd, buf, 0, len, logSize);
    fs.closeSync(fd);
    logSize = st.size;
    buf.toString('utf8').split('\n').forEach(function (line) { if (line.trim()) pushLog(line); });
  } catch (_) {}
}

function initLogTail() {
  if (MOCK) {
    const seed = [
      'INFO]: Starting minecraft server version 26.3 (Paper)',
      'INFO]: Loading properties',
      'INFO]: Default game type: SURVIVAL',
      'INFO]: Done (2.143s)! For help, type "help"'
    ];
    const loop = [
      'INFO]: Steve joined the game',
      'INFO]: Alex joined the game',
      'INFO]: [Steve] 大家好，今天打末影龙',
      'WARN]: Can\'t keep up! Is the server overloaded? Running 2312ms behind',
      'INFO]: [Alex] 收到，我先去准备床',
      'INFO]: Notch_Fan joined the game',
      'ERROR]: Failed to load datapack demo-pack (示例错误日志，用于展示级别着色)',
      'INFO]: [Server] 自动保存完成',
      'INFO]: Steve left the game',
      'INFO]: [Notch_Fan] 有人一起挖远古残骸吗'
    ];
    seed.forEach(function (s) { pushLog(s); });
    let i = 0;
    const emit = function () {
      pushLog(loop[i % loop.length]);
      i++;
      setTimeout(emit, 1200 + Math.random() * 2200);
    };
    setTimeout(emit, 1500);
    return;
  }
  try {
    const st = fs.statSync(logPathResolved);
    logSize = st.size;
    const fd = fs.openSync(logPathResolved, 'r');
    const sample = Math.min(st.size, 64 * 1024);
    const buf = Buffer.alloc(sample);
    fs.readSync(fd, buf, 0, sample, st.size - sample);
    fs.closeSync(fd);
    const lines = buf.toString('utf8').split('\n').filter(function (l) { return l.trim(); });
    lines.slice(-cfg.logBacklogLines).forEach(function (l) { pushLog(l); });
    console.log('[log] 已加载最近 ' + Math.min(lines.length, cfg.logBacklogLines) + ' 行日志');
  } catch (e) {
    console.log('[log] 暂未读取到日志文件（' + logPathResolved + '）: ' + e.message);
    logSize = 0;
  }
  setInterval(tailTick, 1500).unref();
}

/* ============================== 模拟数据心跳 ============================== */

function mockTick() {
  if (!MOCK) return;
  mock.tps = mock.tps.map(function (v, idx) {
    const jitter = (Math.random() - 0.5) * (idx === 0 ? 0.6 : 0.25);
    return Math.max(17.5, Math.min(20, v + jitter));
  });
  mock.cpu = Math.max(8, Math.min(96, mock.cpu + (Math.random() - 0.5) * 9));
  mock.memUsed = Math.max(2e9, Math.min(os.totalmem() * 0.85, mock.memUsed + (Math.random() - 0.5) * 1.2e8));
  if (Math.random() < 0.12) {
    const pool = ['Steve', 'Alex', 'Notch_Fan', 'Enderman_007', '红石工程师'];
    const cur = new Set(mock.players.names);
    if (cur.size < 2 || (Math.random() < 0.5 && cur.size < mock.players.max)) {
      const add = pool.find(function (n) { return !cur.has(n); });
      if (add) {
        mock.players.names.push(add);
        pushLog('INFO]: ' + add + ' joined the game');
      }
    } else if (cur.size > 0) {
      const drop = mock.players.names.splice(Math.floor(Math.random() * cur.size), 1)[0];
      pushLog('INFO]: ' + drop + ' left the game');
    }
    mock.players.online = mock.players.names.length;
  }
}
if (MOCK) setInterval(mockTick, 2500).unref();

/* ============================== HTTP 服务 ============================== */

const STATIC = {
  '/': { file: 'index.html', type: 'text/html; charset=utf-8' },
  '/index.html': { file: 'index.html', type: 'text/html; charset=utf-8' },
  '/app.css': { file: 'app.css', type: 'text/css; charset=utf-8' },
  '/app.js': { file: 'app.js', type: 'application/javascript; charset=utf-8' },
  '/sha256.js': { file: 'sha256.js', type: 'application/javascript; charset=utf-8' }
};

const SECURITY_HEADERS = {
  'Content-Security-Policy':
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
    "connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; " +
    "frame-ancestors 'none'; object-src 'none'",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cache-Control': 'no-store'
};

function applyHeaders(res) {
  for (const k of Object.keys(SECURITY_HEADERS)) res.setHeader(k, SECURITY_HEADERS[k]);
}
function sendJSON(res, code, obj) {
  applyHeaders(res);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(obj));
}
function readBody(req, limit) {
  limit = limit || 64 * 1024;
  return new Promise(function (resolve, reject) {
    let size = 0;
    const chunks = [];
    req.on('data', function (c) {
      size += c.length;
      if (size > limit) { reject(new Error('请求体过大')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', function () {
      try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); }
      catch (_) { reject(new Error('JSON 解析失败')); }
    });
    req.on('error', reject);
  });
}
function bearer(req) {
  const h = req.headers['authorization'] || '';
  const m = h.match(/^Bearer\s+([A-Za-z0-9_-]+)$/i);
  return m ? m[1] : '';
}
function clientIP(req) {
  return (req.socket.remoteAddress || '').replace(/^::ffff:/, '') || 'unknown';
}

function serveStatic(res, route) {
  const fp = path.join(PUBLIC_DIR, route.file);
  fs.readFile(fp, function (err, data) {
    if (err) { sendJSON(res, 404, { error: 'not found' }); return; }
    applyHeaders(res);
    res.writeHead(200, { 'Content-Type': route.type });
    res.end(data);
  });
}

function mockCommand(cmd) {
  const c = cmd.trim();
  if (/^tps$/i.test(c)) {
    return 'TPS from last 1m, 5m, 15m: ' + mock.tps.map(function (v) { return v.toFixed(2); }).join(', ');
  }
  if (/^list$/i.test(c)) {
    return 'There are ' + mock.players.online + ' of a max of ' + mock.players.max +
      ' players online: ' + mock.players.names.join(', ');
  }
  if (/^say\s+/i.test(c)) {
    const msg = c.replace(/^say\s+/i, '');
    pushLog('INFO]: [Server] ' + msg);
    return '[Server] ' + msg;
  }
  if (/^version$/i.test(c)) return 'This server is running Paper version 26.3 (API 26.3)';
  if (/^help$/i.test(c)) return '可用示例指令: tps / list / say <消息> / version';
  return '(mock) 指令已下发: ' + c;
}

async function handleApi(req, res, pathname) {
  const ip = clientIP(req);

  if (req.method === 'GET' && pathname === '/api/nonce') {
    sendJSON(res, 200, { nonce: issueNonce() });
    return;
  }

  if (req.method === 'POST' && pathname === '/api/login') {
    const st = gateStatus(ip);
    if (st.locked) {
      sendJSON(res, 429, { error: '尝试过于频繁，请 ' + st.waitSec + ' 秒后再试' });
      return;
    }
    let body;
    try { body = await readBody(req); } catch (e) { sendJSON(res, 400, { error: e.message }); return; }
    const nonce = String(body.nonce || '');
    const digest = String(body.digest || '').toLowerCase();
    if (!consumeNonce(nonce)) {
      sendJSON(res, 401, { error: '登录凭证已过期，请重试' });
      return;
    }
    // 校验值：SHA256(nonce + ":" + SHA256(password))，明文密码不参与网络传输
    const expected = sha256Hex(nonce + ':' + PASSWORD_INNER);
    if (!safeEqualHex(digest, expected)) {
      const wait = gateFail(ip);
      sendJSON(res, 401, wait ? { error: '密码错误，请 ' + wait + ' 秒后再试' } : { error: '密码错误' });
      return;
    }
    loginGate.delete(ip);
    sendJSON(res, 200, { token: issueToken(), ttlMinutes: cfg.sessionTtlMinutes });
    return;
  }

  if (req.method === 'POST' && pathname === '/api/logout') {
    const t = bearer(req);
    if (t) sessions.delete(t);
    sendJSON(res, 200, { ok: true });
    return;
  }

  // ---- 以下均需鉴权 ----
  if (!checkToken(bearer(req))) {
    sendJSON(res, 401, { error: '未登录或会话已失效' });
    return;
  }

  if (req.method === 'GET' && pathname === '/api/stats') {
    sendJSON(res, 200, stats);
    return;
  }

  if (req.method === 'GET' && pathname === '/api/stream') {
    applyHeaders(res);
    res.writeHead(200, {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Connection': 'keep-alive'
    });
    res.write('event: backlog\ndata: ' + JSON.stringify(logRing.slice(-cfg.logBacklogLines)) + '\n\n');
    res.write('event: stats\ndata: ' + JSON.stringify(stats) + '\n\n');
    sseClients.add(res);
    req.on('close', function () { sseClients.delete(res); });
    return;
  }

  if (req.method === 'POST' && pathname === '/api/command') {
    let body;
    try { body = await readBody(req); } catch (e) { sendJSON(res, 400, { error: e.message }); return; }
    const cmd = String(body.command || '').trim();
    if (!cmd) { sendJSON(res, 400, { error: '指令不能为空' }); return; }
    if (cmd.length > 400) { sendJSON(res, 400, { error: '指令过长' }); return; }
    try {
      const out = MOCK ? mockCommand(cmd) : await rcon.command(cmd);
      pushLog('INFO]: > ' + cmd + (out ? ' -> ' + out : ''));
      sendJSON(res, 200, { ok: true, output: out || '(无输出)' });
    } catch (e) {
      sendJSON(res, 502, { error: '指令执行失败: ' + e.message });
    }
    return;
  }

  sendJSON(res, 404, { error: 'not found' });
}

function requestHandler(req, res) {
  let pathname;
  try { pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname); }
  catch (_) { sendJSON(res, 400, { error: 'bad url' }); return; }

  if (pathname.indexOf('/api/') === 0) {
    handleApi(req, res, pathname).catch(function () {
      try { sendJSON(res, 500, { error: '服务器内部错误' }); } catch (_) {}
    });
    return;
  }
  const route = STATIC[pathname];
  if (route) { serveStatic(res, route); return; }
  sendJSON(res, 404, { error: 'not found' });
}

const useTls = !!(cfg.tls.enabled && cfg.tls.certFile && cfg.tls.keyFile);
const httpd = useTls
  ? https.createServer({
    cert: fs.readFileSync(cfg.tls.certFile),
    key: fs.readFileSync(cfg.tls.keyFile)
  }, requestHandler)
  : http.createServer(requestHandler);

/* ============================== 启动 ============================== */

function lanIPs() {
  const out = [];
  const ifs = os.networkInterfaces();
  for (const name of Object.keys(ifs)) {
    for (const ni of ifs[name] || []) {
      if (ni.family === 'IPv4' && !ni.internal) out.push(ni.address);
    }
  }
  return out;
}

async function main() {
  initLogTail();
  await refreshStats();
  setInterval(refreshStats, 3000).unref();

  if (!MOCK) {
    const tryConnect = async function () {
      try {
        await rcon.connect();
        console.log('[rcon] 已连接 ' + cfg.rcon.host + ':' + cfg.rcon.port);
      } catch (e) {
        console.log('[rcon] 连接失败（' + e.message + '），10 秒后重试');
        setTimeout(tryConnect, 10000).unref();
      }
    };
    tryConnect();
  }

  httpd.listen(cfg.port, cfg.host, function () {
    const scheme = useTls ? 'https' : 'http';
    console.log('==================================================');
    console.log('  Paper 服务器控制台面板已启动');
    console.log('  本地访问:  ' + scheme + '://127.0.0.1:' + cfg.port);
    for (const ip of lanIPs()) console.log('  局域网:    ' + scheme + '://' + ip + ':' + cfg.port);
    console.log('  运行模式:  ' + (MOCK ? '演示 mock（未连接真实服务器）' : 'RCON 实连 ' + cfg.rcon.host + ':' + cfg.rcon.port));
    console.log('  日志来源:  ' + (MOCK ? 'mock 生成' : logPathResolved));
    console.log('  提示:      公网暴露时请务必启用 TLS 或置于反向代理之后');
    console.log('==================================================');
  });

  const shutdown = function () {
    console.log('\n[exit] 正在关闭…');
    try { rcon.destroy(); } catch (_) {}
    httpd.close(function () { process.exit(0); });
    setTimeout(function () { process.exit(0); }, 1500).unref();
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

main().catch(function (e) {
  console.error('启动失败:', e);
  process.exit(1);
});

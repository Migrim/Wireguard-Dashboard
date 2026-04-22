// Shared helpers + API client for WG-Quick dashboard

const BASE = document.body.dataset.base || '';
const HS_TIMEOUT = 130; // seconds without handshake = offline (all client confs have PersistentKeepalive=25)
const TRAFFIC_RANGES = { '1m': 60_000, '5m': 5 * 60_000, '1h': 60 * 60_000, '24h': 24 * 60 * 60_000 };

async function apiCall(path, opt = {}) {
  const url = path.startsWith('http') ? path : BASE + path;
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), 15000);
  try {
    const res = await fetch(url, {
      ...opt,
      headers: { 'Content-Type': 'application/json', ...(opt.headers || {}) },
      signal: ac.signal,
    });
    let data = null;
    try { data = await res.json(); } catch (_) {}
    if (!res.ok) {
      const msg = (data && (data.hint || data.error || data.out)) || ('HTTP ' + res.status);
      throw new Error(String(msg));
    }
    return data;
  } finally {
    clearTimeout(t);
  }
}

function mapApiPeers(issued, live) {
  const now = Date.now();
  return (issued || []).map((iss, idx) => {
    const lv = (live || []).find(l => l.name === iss.name);
    const hs = lv ? (lv.last_handshake || 0) : 0;
    const isOnline = hs > 0 && (now / 1000 - hs) < HS_TIMEOUT;
    return {
      id: iss.name,
      name: iss.name,
      addr: iss.ip || '—',
      status: isOnline ? 'connected' : 'offline',
      bytesIn: lv ? (lv.bytes_recv || 0) : 0,
      bytesOut: lv ? (lv.bytes_sent || 0) : 0,
      lastHs: hs > 0 ? hs * 1000 : null,
      device: iss.created ? `Added ${iss.created}` : '',
      endpoint: (lv && lv.remote) ? lv.remote : '—',
      key: '',
      pubKey: iss.public_key || '',
      allowedIps: iss.ip || '',
      country: '',
      pingMs: null,
      handshakeInterval: null,
    };
  });
}

const _MONTHS = { Jan:0,Feb:1,Mar:2,Apr:3,May:4,Jun:5,Jul:6,Aug:7,Sep:8,Oct:9,Nov:10,Dec:11 };

function parseLogLines(lines) {
  const now = Date.now();
  const year = new Date().getFullYear();
  return (lines || []).map((line, i) => {
    const lower = line.toLowerCase();
    const level = lower.includes('error') || lower.includes('failed') ? 'error'
      : lower.includes('warn') || lower.includes('delayed') ? 'warn' : 'info';
    // Parse real timestamp from journalctl short / short-precise format:
    // "Apr 22 14:35:22[.123456] hostname unit[pid]: message"
    let t = now - (lines.length - i) * 1000;
    const tsMatch = line.match(/^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})/);
    if (tsMatch) {
      const d = new Date(year, _MONTHS[tsMatch[1]] ?? 0, +tsMatch[2], +tsMatch[3], +tsMatch[4], +tsMatch[5]);
      if (!isNaN(d.getTime())) t = d.getTime();
    }
    // Strip the journalctl prefix (handles short and short-precise formats)
    const msg = line.replace(/^[A-Z][a-z]{2}\s+\d{1,2}\s+[\d:.]+\s+\S+\s+\S+:\s*/, '').trim() || line;
    return { t, level, msg };
  });
}

// Simple seeded noise for pretty charts
function seededNoise(seed) {
  let s = seed;
  return () => {
    s = (s * 9301 + 49297) % 233280;
    return s / 233280;
  };
}

function initThroughput(seed = 42, base = 1_000_000) {
  const rand = seededNoise(seed);
  const buf = [];
  let v = base;
  for (let i = 0; i < 120; i++) {
    v += (rand() - 0.5) * base * 0.4;
    v = Math.max(base * 0.1, Math.min(base * 3, v));
    buf.push(v);
  }
  return buf;
}

function initSparkline(seed, n = 24) {
  const rand = seededNoise(seed);
  const buf = [];
  for (let i = 0; i < n; i++) buf.push(rand());
  return buf;
}

function formatBytes(b) {
  if (b === 0) return '0 B';
  if (!b) return '—';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(b) / Math.log(1024));
  return `${(b / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

function formatRate(bps) {
  if (!bps) return '0 B/s';
  const units = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
  const i = Math.min(units.length - 1, Math.floor(Math.log(Math.max(bps, 1)) / Math.log(1024)));
  return `${(bps / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 2)} ${units[i]}`;
}

function formatRelTime(ts) {
  if (!ts) return '—';
  const diff = Date.now() - ts;
  if (diff < 60_000) return `${Math.floor(diff / 1000)}s ago`;
  if (diff < 3600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86400_000) return `${Math.floor(diff / 3600_000)}h ago`;
  return `${Math.floor(diff / 86400_000)}d ago`;
}

function formatAbsTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

const LOG_TEMPLATES = [
  { level: 'info', msg: (p) => `peer ${p.name} handshake completed` },
  { level: 'info', msg: (p) => `received data from ${p.name}` },
  { level: 'info', msg: (p) => `keepalive sent to ${p.name} @ ${p.endpoint}` },
  { level: 'warn', msg: (p) => `peer ${p.name} handshake delayed (>120s)` },
  { level: 'info', msg: () => `wg0: interface up, peers active` },
  { level: 'info', msg: (p) => `peer ${p.name} transferred data` },
];

function makeInitialLogs() {
  const now = Date.now();
  return [
    { t: now - 240_000, level: 'info', msg: 'wg0: interface up, listening on 51820' },
    { t: now - 180_000, level: 'info', msg: 'wg0: loading configuration' },
    { t: now - 120_000, level: 'info', msg: 'wg0: peers loaded from config' },
    { t: now - 60_000,  level: 'info', msg: 'wg0: service ready' },
  ];
}

window.WG = {
  apiCall, mapApiPeers, parseLogLines, HS_TIMEOUT,
  TRAFFIC_RANGES,
  initThroughput, initSparkline, seededNoise,
  formatBytes, formatRate, formatRelTime, formatAbsTime,
  LOG_TEMPLATES, makeInitialLogs,
};

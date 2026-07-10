// Main WG-Quick dashboard — real API integration

const { useState: uS, useEffect: uE, useRef: uR, useMemo: uM, useCallback: uC } = React;
const IS_MAC = /mac/i.test(navigator.userAgentData?.platform ?? navigator.userAgent);
const LOG_VERBOSE_KEY = 'WG_LOG_VERBOSE';
const DISMISSED_ALERTS_KEY = 'WG_DISMISSED_ALERTS';
const BUDGET_TOASTED_KEY = 'WG_BUDGET_TOASTED';
const AVG_PING_HISTORY_KEY = 'WG_AVG_PING_HISTORY';


function App({ tweaks, setTweaks, onLogout }) {
  const [peers, setPeers] = uS([]);
  const [peersLoaded, setPeersLoaded] = uS(false);
  const [selectedPeer, setSelectedPeer] = uS(null);
  const [dataDrawerOpen, setDataDrawerOpen] = uS(false);
  const [trafficModeOpen, setTrafficModeOpen] = uS(false);
  const [portCheckOpen, setPortCheckOpen] = uS(false);
  const [dyndnsOpen, setDyndnsOpen] = uS(false);
  const [logsDrawerOpen, setLogsDrawerOpen] = uS(false);
  const [addOpen, setAddOpen] = uS(false);
  const [settingsOpen, setSettingsOpen] = uS(false);
  const [uptimeOpen, setUptimeOpen] = uS(false);
  const [updateAvailable, setUpdateAvailable] = uS(false);
  const [dataBudget, setDataBudget] = uS(50);
  const [budgetEnabled, setBudgetEnabled] = uS(true);
  const [budgetAlerts, setBudgetAlerts] = uS(true);
  const [resetTime, setResetTime] = uS('00:00');
  const [enforcement, setEnforcement] = uS({ action: 'none', throttle_mbps: 5 });
  const [peerBudgets, setPeerBudgets] = uS({});
  const setPeerBudget = uC((id, val) => {
    setPeerBudgets(prev => {
      const next = { ...prev, [id]: val };
      window.WG.apiCall('/api/data-budget', { method: 'POST', body: JSON.stringify({ peer_budgets: next }) })
        .then(r => { if (r.settings?.peer_budgets) setPeerBudgets(r.settings.peer_budgets); })
        .catch(() => {});
      return next;
    });
  }, []);
  const [budgetUsage, setBudgetUsage] = uS({ total: 0, peers: [], pct: 0, period_start_iso: '' });
  const [filter, setFilter] = uS('');
  const searchRef = uR(null);
  const [statusFilter, setStatusFilter] = uS('all');
  const [logs, setLogs] = uS(() => window.WG.makeInitialLogs());
  const [bgNotifs, setBgNotifs] = uS([]);
  const [logsVerbose, setLogsVerbose] = uS(() => localStorage.getItem(LOG_VERBOSE_KEY) === '1');
  const [serviceActive, setServiceActive] = uS(false);
  const [serviceEnabled, setServiceEnabled] = uS(false);
  const [serviceLoading, setServiceLoading] = uS(null);
  const [unit, setUnit] = uS('wg-quick@wg0');
  const [startedAt, setStartedAt] = uS(0);
  const [servicePort, setServicePort] = uS(null);
  const [ifaceName, setIfaceName] = uS('wg0');
  const [internetState, setInternetState] = uS('unknown');

  const [trafficRange, setTrafficRange] = uS(() => localStorage.getItem('trafficRange') || '1m');
  const [trafficPaused, setTrafficPaused] = uS(false);
  const [trafficHistory, setTrafficHistory] = uS([]);
  const [dismissedAlerts, setDismissedAlerts] = uS(() => {
    try { return new Set(JSON.parse(localStorage.getItem(DISMISSED_ALERTS_KEY) || '[]')); }
    catch { return new Set(); }
  });

  // Per-peer sparklines (values = byte delta per poll cycle)
  const [sparks, setSparks] = uS({});
  const [avgPingHistory, setAvgPingHistory] = uS(() => {
    try {
      const saved = JSON.parse(localStorage.getItem(AVG_PING_HISTORY_KEY) || 'null');
      if (Array.isArray(saved) && saved.length === 20) return saved;
    } catch (_) {}
    return new Array(20).fill(0);
  });

  // Per-peer drawer throughput buffer
  const [peerThr, setPeerThr] = uS({});

  // Per-peer geo: { [name]: { lat, lng, country } } — filled from /diag responses
  const [peerGeo, setPeerGeo] = uS({});
  // Per-peer ping in ms — filled from /diag responses
  const [peerPings, setPeerPings] = uS({});
  // Per-peer ping history: { [name]: number[] } oldest-first, 24 slots, persisted
  const [peerPingHistory, setPeerPingHistory] = uS(() => {
    try { return JSON.parse(localStorage.getItem('WG_PEER_PING_HISTORY') || 'null') || {}; } catch { return {}; }
  });

  // Previous cumulative bytes per peer — used to compute sparkline deltas
  const prevBytesRef = uR({});

  const refreshPeers = uC(() => {
    window.WG.apiCall('/api/status', { silent: true })
      .then(j => setPeers(window.WG.mapApiPeers(j.clients.issued, j.clients.live)))
      .catch(() => {});
  }, []);

  uE(() => {
    const handler = e => {
      if ((IS_MAC ? e.metaKey : e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        searchRef.current?.focus();
        searchRef.current?.select();
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  uE(() => {
    localStorage.setItem(LOG_VERBOSE_KEY, logsVerbose ? '1' : '0');
  }, [logsVerbose]);

  uE(() => {
    localStorage.setItem(DISMISSED_ALERTS_KEY, JSON.stringify([...dismissedAlerts]));
  }, [dismissedAlerts]);

  // Toast once per threshold per budget period when 70% / 90% is crossed (total + per-peer)
  uE(() => {
    if (!budgetEnabled || !budgetAlerts) return;
    const period = budgetUsage.period_start_iso || '';
    if (!period) return;
    const pending = [];
    const levelOf = (p) => p >= 100 ? '100' : p >= 90 ? '90' : p >= 70 ? '70' : '';
    const enfAction = enforcement.action || 'none';
    const enfNote = (plural) => enfAction === 'pause' || enfAction === 'combined'
      ? (plural ? ' Peers are paused until the next reset.' : ' Peer is paused until the next reset.')
      : enfAction === 'throttle' ? ` Speed is capped at ${enforcement.throttle_mbps || 5} Mbps.` : '';
    const pct = budgetUsage.pct || 0;
    const level = levelOf(pct);
    if (level) {
      pending.push({
        key: `budget-${level}-${period}`,
        title: level === '100' ? 'Budget exceeded' : level === '90' ? 'Budget nearly exhausted' : 'Budget at 70%',
        desc: `${pct.toFixed(0)}% of ${dataBudget} GB daily budget used.` + (level === '100' ? enfNote(true) : ''),
      });
    }
    (budgetUsage.peers || []).forEach(row => {
      const pb = peerBudgets[row.name];
      if (!pb || pb === 'inf') return;
      const ppct = ((row.bytes || 0) / (pb * 1024 * 1024 * 1024)) * 100;
      const plevel = levelOf(ppct);
      if (!plevel) return;
      pending.push({
        key: `budget-peer-${row.name}-${plevel}-${period}`,
        title: plevel === '100' ? `${row.name}: budget exceeded` : plevel === '90' ? `${row.name}: budget nearly exhausted` : `${row.name}: budget at 70%`,
        desc: `${ppct.toFixed(0)}% of ${pb} GB peer budget used.` + (plevel === '100' ? enfNote(false) : ''),
      });
    });
    if (!pending.length) return;
    let shown;
    try { shown = new Set(JSON.parse(localStorage.getItem(BUDGET_TOASTED_KEY) || '[]')); }
    catch { shown = new Set(); }
    const fresh = pending.filter(p => !shown.has(p.key));
    if (!fresh.length) return;
    fresh.forEach(p => { shown.add(p.key); window.WG.toast?.warning?.(p.title, p.desc); });
    localStorage.setItem(BUDGET_TOASTED_KEY, JSON.stringify([...shown].slice(-40)));
  }, [budgetEnabled, budgetAlerts, budgetUsage, dataBudget, peerBudgets, enforcement]);

  uE(() => {
    localStorage.setItem(AVG_PING_HISTORY_KEY, JSON.stringify(avgPingHistory));
  }, [avgPingHistory]);

  uE(() => {
    const check = () => fetch('/api/update/check').then(r => r.json()).then(j => {
      if (j.available) setUpdateAvailable(true);
    }).catch(() => {});
    check();
    const id = setInterval(check, 10 * 60 * 1000);
    return () => clearInterval(id);
  }, []);

  const connectedPeerNames = uM(
    () => peers.filter(p => p.status === 'connected').map(p => p.name).sort(),
    [peers]
  );
  const connectedPeerKey = connectedPeerNames.join('|');

  // Initialize per-peer drawer buffers for newly seen peers (40 pts × 3s = 2-min window)
  const ensurePeerState = (mapped) => {
    setPeerThr(prev => {
      const next = { ...prev };
      mapped.forEach(p => {
        if (!next[p.id]) {
          next[p.id] = { rx: new Array(40).fill(0), tx: new Array(40).fill(0) };
        }
      });
      return next;
    });
  };

  // Poll /api/status every 3s — drives sparklines + drawer charts from real byte deltas
  uE(() => {
    let cancelled = false;
    const fetchStatus = async () => {
      try {
        const j = await window.WG.apiCall('/api/status', { silent: true });
        if (cancelled) return;
        setServiceActive(!!j.service.active);
        setServiceEnabled(!!j.service.enabled);
        if (j.service.unit) setUnit(j.service.unit);
        if (j.service.started_at) setStartedAt(j.service.started_at);
        if (j.network?.port) setServicePort(`${j.network.port}/udp`);
        if (j.network?.iface) setIfaceName(j.network.iface);
        if (j.network?.internet) setInternetState(j.network.internet);
        if (j.data_budget) {
          setBudgetUsage(j.data_budget);
          setDataBudget(j.data_budget.settings?.budget_gb || 50);
          setBudgetEnabled(j.data_budget.settings?.enabled !== false);
          setBudgetAlerts(j.data_budget.settings?.alerts !== false);
          setResetTime(j.data_budget.settings?.reset_time || '00:00');
          if (j.data_budget.settings?.peer_budgets) setPeerBudgets(j.data_budget.settings.peer_budgets);
          if (j.data_budget.settings?.enforcement) setEnforcement(j.data_budget.settings.enforcement);
        }
        const mapped = window.WG.mapApiPeers(j.clients.issued, j.clients.live);
        setPeers(prev => {
          const prevMap = new Map(prev.map(p => [p.id, p]));
          return mapped.map(p => {
            const old = prevMap.get(p.id);
            return old ? { ...old, ...p } : p;
          });
        });
        setPeersLoaded(true);
        ensurePeerState(mapped);
        const serverSparks = j.clients.spark_history || {};
        const serverPeerThr = j.clients.peer_throughput_history || {};

        // Pre-compute per-peer deltas before touching state
        const prev = prevBytesRef.current;
        const next = {};
        const deltas = {};  // {id: {rxBps, txBps, total}}
        mapped.forEach(p => {
          next[p.id] = { rx: p.bytesIn, tx: p.bytesOut };
          const pr = prev[p.id];
          if (p.status === 'connected' && pr !== undefined) {
            const rxDelta = Math.max(0, p.bytesIn  - pr.rx);
            const txDelta = Math.max(0, p.bytesOut - pr.tx);
            deltas[p.id] = { rxBps: rxDelta / 3, txBps: txDelta / 3, total: rxDelta + txDelta, hasPrev: true };
          } else {
            deltas[p.id] = { rxBps: 0, txBps: 0, total: 0, hasPrev: false };
          }
        });
        prevBytesRef.current = next;

        // Sparklines (combined bytes per poll)
        setSparks(s => {
          const out = { ...s };
          mapped.forEach(p => {
            const seeded = (serverSparks[p.id] || []).slice(-20);
            const seedBuf = seeded.length ? [...new Array(Math.max(0, 20 - seeded.length)).fill(0), ...seeded] : new Array(20).fill(0);
            const buf = out[p.id] || seedBuf;
            out[p.id] = deltas[p.id].hasPrev ? [...buf.slice(1), deltas[p.id].total] : buf;
          });
          return out;
        });

        // Drawer throughput charts (separate rx / tx bytes/s)
        setPeerThr(pt => {
          const out = { ...pt };
          mapped.forEach(p => {
            const seeded = serverPeerThr[p.id] || {};
            const seededRx = (seeded.rx || []).slice(-40);
            const seededTx = (seeded.tx || []).slice(-40);
            const seedBuf = {
              rx: seededRx.length ? [...new Array(Math.max(0, 40 - seededRx.length)).fill(0), ...seededRx] : new Array(40).fill(0),
              tx: seededTx.length ? [...new Array(Math.max(0, 40 - seededTx.length)).fill(0), ...seededTx] : new Array(40).fill(0),
            };
            const existing = out[p.id];
            const existingHasData = existing && (
              (existing.rx || []).some(v => v > 0) ||
              (existing.tx || []).some(v => v > 0)
            );
            const seedHasData = seedBuf.rx.some(v => v > 0) || seedBuf.tx.some(v => v > 0);
            const buf = existingHasData || !seedHasData ? (existing || seedBuf) : seedBuf;
            out[p.id] = deltas[p.id].hasPrev ? {
              rx: [...buf.rx.slice(1), deltas[p.id].rxBps],
              tx: [...buf.tx.slice(1), deltas[p.id].txBps],
            } : buf;
          });
          return out;
        });
      } catch (_) {}
    };
    fetchStatus();
    const id = setInterval(fetchStatus, 3000);
    return () => { cancelled = true; clearInterval(id); };
  }, []);

  uE(() => {
    let cancelled = false;
    const pollAveragePing = async () => {
      if (!connectedPeerNames.length) {
        setAvgPingHistory(prev => [...prev.slice(1), 0]);
        return;
      }
      try {
        const results = await Promise.all(
          connectedPeerNames.map(name => window.WG.apiCall('/api/users/' + encodeURIComponent(name) + '/diag', { silent: true }).catch(() => null))
        );
        if (cancelled) return;
        const values = results
          .map(r => Number(r && r.ping_ms))
          .filter(v => Number.isFinite(v) && v >= 0);
        const avg = values.length ? values.reduce((sum, v) => sum + v, 0) / values.length : 0;
        setAvgPingHistory(prev => [...prev.slice(1), avg]);
        const newGeo = {};
        const newPings = {};
        results.forEach((r, i) => {
          if (!r) return;
          const ping = Number(r.ping_ms);
          if (Number.isFinite(ping) && ping >= 0) newPings[connectedPeerNames[i]] = ping;
          if (!r.ok || !r.name) return;
          const loc = r.location || {};
          if (loc.lat != null && loc.lng != null) {
            newGeo[r.name] = { lat: loc.lat, lng: loc.lng, country: loc.label || loc.country || '' };
          }
        });
        if (Object.keys(newPings).length > 0) {
          setPeerPings(prev => ({ ...prev, ...newPings }));
          setPeerPingHistory(prev => {
            const out = { ...prev };
            Object.entries(newPings).forEach(([name, ms]) => {
              const buf = out[name] || new Array(24).fill(0);
              out[name] = [...buf.slice(1), ms]; // oldest at 0, newest at end
            });
            try { localStorage.setItem('WG_PEER_PING_HISTORY', JSON.stringify(out)); } catch (_) {}
            return out;
          });
        }
        if (Object.keys(newGeo).length > 0) setPeerGeo(prev => ({ ...prev, ...newGeo }));
      } catch (_) {}
    };
    pollAveragePing();
    const id = setInterval(pollAveragePing, 5000);
    return () => { cancelled = true; clearInterval(id); };
  }, [connectedPeerKey]);

  // Fetch initial history once on mount (5 minutes covers all short ranges)
  uE(() => {
    let cancelled = false;
    window.WG.apiCall('/api/traffic/history?range=5m&max_points=3000', { silent: true })
      .then(h => {
        if (cancelled) return;
        setTrafficHistory((h.samples || []).map(s => ({
          ts: Number(s.ts) * 1000,
          rx: Math.max(0, Number(s.rx_bps) || 0),
          tx: Math.max(0, Number(s.tx_bps) || 0),
        })));
      })
      .catch(() => {});
    return () => { cancelled = true; };
  }, []);

  // When switching to 1h or 24h, extend the buffer with server history (merge, don't replace)
  uE(() => {
    if (trafficRange !== '1h' && trafficRange !== '24h') return;
    let cancelled = false;
    window.WG.apiCall(`/api/traffic/history?range=${trafficRange}&max_points=3600`, { silent: true })
      .then(h => {
        if (cancelled) return;
        const fetched = (h.samples || []).map(s => ({
          ts: Number(s.ts) * 1000,
          rx: Math.max(0, Number(s.rx_bps) || 0),
          tx: Math.max(0, Number(s.tx_bps) || 0),
        }));
        setTrafficHistory(prev => {
          const existingTs = new Set(prev.map(s => s.ts));
          const toAdd = fetched.filter(s => !existingTs.has(s.ts));
          if (!toAdd.length) return prev;
          return [...prev, ...toAdd].sort((a, b) => a.ts - b.ts);
        });
      })
      .catch(() => {});
    return () => { cancelled = true; };
  }, [trafficRange]);

  // Poll /api/traffic on configurable interval; the server keeps the rolling 24h history.
  uE(() => {
    let cancelled = false;
    const interval = tweaks.refreshInterval || 1000;
    const fetchTraffic = async () => {
      try {
        const t = await window.WG.apiCall('/api/traffic', { silent: true });
        if (cancelled) return;
        const sample = {
          ts: Number(t.ts) * 1000,
          rx: Math.max(0, Number(t.rx_bps) || 0),
          tx: Math.max(0, Number(t.tx_bps) || 0),
        };
        setTrafficHistory(prev => {
          const cutoff = Date.now() - 24 * 60 * 60 * 1000; // keep up to 24h in memory
          const next = prev.length && sample.ts <= prev[prev.length - 1].ts
            ? [...prev.slice(0, -1), sample]
            : [...prev, sample];
          return next.filter(s => s.ts >= cutoff);
        });
      } catch (_) {}
    };
    fetchTraffic();
    const id = setInterval(fetchTraffic, interval);
    return () => { cancelled = true; clearInterval(id); };
  }, [tweaks.refreshInterval]);

  // Poll /api/logs every 8s
  uE(() => {
    let cancelled = false;
    const fetchLogs = async () => {
      try {
        const j = await window.WG.apiCall('/api/logs?n=60', { silent: true });
        if (cancelled) return;
        if (j.lines) setLogs(window.WG.parseLogLines(j.lines));
      } catch (_) {}
    };
    fetchLogs();
    const id = setInterval(fetchLogs, 8000);
    return () => { cancelled = true; clearInterval(id); };
  }, []);

  uE(() => {
    const fetch = () => window.WG.apiCall('/api/diag/bg-notifications', { silent: true })
      .then(r => { if (Array.isArray(r)) setBgNotifs(r); }).catch(() => {});
    fetch();
    const id = setInterval(fetch, 30 * 1000);
    return () => clearInterval(id);
  }, []);

  const doService = async (action) => {
    setServiceLoading(action);
    const startLabel  = { start: 'Starting',   restart: 'Restarting', stop: 'Stopping'  }[action] ?? action;
    const doneLabel   = { start: 'Server started', restart: 'Server restarted', stop: 'Server stopped' }[action] ?? 'Done';
    const t = window.WG.toast?.loading?.(`${startLabel} server…`);
    try {
      const r = await window.WG.apiCall('/api/service', { silent: true, method: 'POST', body: JSON.stringify({ action }) });
      if (!r.ok) throw new Error(r.out || 'Service action failed');
      const j = await window.WG.apiCall('/api/status', { silent: true });
      setServiceActive(!!j.service.active);
      setServiceEnabled(!!j.service.enabled);
      t?.success?.(doneLabel);
    } catch (e) {
      t?.error?.('Action failed', e?.message || 'API error');
    }
    setServiceLoading(null);
  };

  const updateBudgetSettings = async (patch) => {
    const r = await window.WG.apiCall('/api/data-budget', { silent: true, method: 'POST', body: JSON.stringify(patch) });
    setBudgetUsage(r);
    setDataBudget(r.settings?.budget_gb || 50);
    setBudgetEnabled(r.settings?.enabled !== false);
    setBudgetAlerts(r.settings?.alerts !== false);
    setResetTime(r.settings?.reset_time || '00:00');
    if (r.settings?.peer_budgets) setPeerBudgets(r.settings.peer_budgets);
    if (r.settings?.enforcement) setEnforcement(r.settings.enforcement);
    return r;
  };

  const chartTraffic = uM(() => {
    const rangeMs = window.WG.TRAFFIC_RANGES[trafficRange] || window.WG.TRAFFIC_RANGES['1m'];
    const cutoff = Date.now() - rangeMs;
    const samples = trafficHistory.filter(s => s.ts >= cutoff);
    const maxPoints = 900;
    const bucketSize = Math.max(1, Math.ceil(samples.length / maxPoints));
    const compact = [];
    for (let i = 0; i < samples.length; i += bucketSize) {
      const bucket = samples.slice(i, i + bucketSize);
      const rx = bucket.reduce((sum, s) => sum + s.rx, 0) / bucket.length;
      const tx = bucket.reduce((sum, s) => sum + s.tx, 0) / bucket.length;
      compact.push({ rx, tx });
    }
    while (compact.length < 2) compact.unshift({ rx: 0, tx: 0 });
    return {
      rx: compact.map(s => s.rx),
      tx: compact.map(s => s.tx),
    };
  }, [trafficHistory, trafficRange]);

  const connectedCount = peers.filter(p => p.status === 'connected').length;
  const latestTraffic = trafficHistory[trafficHistory.length - 1] || { rx: 0, tx: 0 };
  const currentRx = latestTraffic.rx || 0;
  const currentTx = latestTraffic.tx || 0;
  const totalToday = budgetUsage.total || 0;
  const offlineLong = peers.filter(p => p.status === 'offline' && p.lastHs && (Date.now() - p.lastHs) > 24 * 3600_000);
  const neverConnected = peers.filter(p => p.status === 'offline' && !p.lastHs);

  const dismissAlert = uC((key) => setDismissedAlerts(s => { const n = new Set(s); n.add(key); return n; }), []);

  const alerts = [];
  if (updateAvailable && !dismissedAlerts.has('update-available')) {
    alerts.push({ level: 'update', title: 'Update available', desc: 'A new version is ready. Open Dashboard settings to install it.', key: 'update-available' });
  }
  if (offlineLong.length > 0 || neverConnected.length > 0) {
    const parts = [];
    if (offlineLong.length) parts.push(offlineLong.map(p => `${p.name}: offline >24h`).join(' · '));
    if (neverConnected.length) parts.push(neverConnected.map(p => `${p.name}: never connected`).join(' · '));
    const desc = parts.join(' · ');
    if (!dismissedAlerts.has(desc)) {
      alerts.push({ level: 'warn', title: `${offlineLong.length + neverConnected.length} peer(s) need attention`, desc, key: desc });
    }
  }
  if (budgetEnabled && budgetAlerts) {
    const bpct = budgetUsage.pct || 0;
    const period = budgetUsage.period_start_iso || '';
    const levelOf = (p) => p >= 100 ? '100' : p >= 90 ? '90' : p >= 70 ? '70' : '';
    const enfAction = enforcement.action || 'none';
    const enfNote = (plural) => enfAction === 'pause' || enfAction === 'combined'
      ? (plural ? ' Peers are paused until the next reset.' : ' Peer is paused until the next reset.')
      : enfAction === 'throttle' ? ` Speed is capped at ${enforcement.throttle_mbps || 5} Mbps.` : '';
    const blevel = levelOf(bpct);
    if (blevel) {
      const key = `budget-${blevel}-${period}`;
      if (!dismissedAlerts.has(key)) {
        alerts.push({
          level: 'warn',
          title: blevel === '100' ? 'Budget exceeded' : blevel === '90' ? 'Budget nearly exhausted' : 'Budget at 70%',
          desc: `${bpct.toFixed(0)}% of ${dataBudget} GB daily budget used.` + (blevel === '100' ? enfNote(true) : ''),
          key,
        });
      }
    }
    (budgetUsage.peers || []).forEach(row => {
      const pb = peerBudgets[row.name];
      if (!pb || pb === 'inf') return;
      const ppct = ((row.bytes || 0) / (pb * 1024 * 1024 * 1024)) * 100;
      const level = levelOf(ppct);
      if (!level) return;
      const key = `budget-peer-${row.name}-${level}-${period}`;
      if (!dismissedAlerts.has(key)) {
        alerts.push({
          level: 'warn',
          title: level === '100' ? `${row.name}: budget exceeded` : level === '90' ? `${row.name}: budget nearly exhausted` : `${row.name}: budget at 70%`,
          desc: `${ppct.toFixed(0)}% of ${pb} GB peer budget used.` + (level === '100' ? enfNote(false) : ''),
          key,
        });
      }
    });
  }
  bgNotifs.forEach(n => {
    if (!dismissedAlerts.has(n.id)) {
      alerts.push({ level: n.level, title: n.title, desc: n.desc + (n.checked_at ? `  ·  checked ${n.checked_at}` : ''), key: n.id });
    }
  });

  const filtered = peers.filter(p => {
    if (statusFilter !== 'all' && p.status !== statusFilter) return false;
    if (!filter) return true;
    const f = filter.toLowerCase();
    return p.name.toLowerCase().includes(f) || p.addr.includes(f) || (p.pubKey || '').toLowerCase().includes(f);
  });

  const searchSuggestion = (() => {
    if (!filter) return '';
    const f = filter.toLowerCase();
    for (const p of peers) {
      if (p.name.toLowerCase().startsWith(f)) return p.name;
      if (p.addr.toLowerCase().startsWith(f)) return p.addr;
    }
    return '';
  })();
  const ghostSuffix = searchSuggestion.length > filter.length ? searchSuggestion.slice(filter.length) : '';

  const density = tweaks.density || 'dense';
  const WGToaster = window.Toaster;

  return (
    <div className={`app density-${density}`}>
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
              <path d="M12 2L3 7v6c0 5 4 9 9 10 5-1 9-5 9-10V7l-9-5z" />
              <path d="M9 12l2 2 4-4" />
            </svg>
          </div>
          <div className="brand-text">
            <div className="brand-name">WG-Quick</div>
          </div>
        </div>
        <div className="topbar-center">
          <div className="search">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>
            <div className="search-input-wrap">
              {ghostSuffix && (
                <span className="search-ghost" aria-hidden="true">
                  <span className="search-ghost-typed">{filter}</span>{ghostSuffix}<span className="search-ghost-tab"><svg width="12" height="10" viewBox="0 0 12 10" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M1 5h7M5 2l3 3-3 3"/><line x1="11" y1="1" x2="11" y2="9"/></svg></span>
                </span>
              )}
              <input
                ref={searchRef}
                type="text"
                placeholder="Filter peers by name, IP, or public key…"
                value={filter}
                onChange={e => setFilter(e.target.value)}
                onKeyDown={e => {
                  if (e.key === 'Tab' && ghostSuffix) {
                    e.preventDefault();
                    setFilter(searchSuggestion);
                  } else if (e.key === 'Escape') {
                    e.preventDefault();
                    setFilter('');
                    searchRef.current?.blur();
                  } else if (e.key === 'Enter' && filter && filtered.length > 0) {
                    e.preventDefault();
                    const suggested = searchSuggestion
                      ? filtered.find(p => p.name === searchSuggestion || p.addr === searchSuggestion)
                      : null;
                    setSelectedPeer((suggested || filtered[0]).id);
                    setFilter('');
                    searchRef.current?.blur();
                  }
                }}
              />
            </div>
            {filter
              ? <button className="search-clear" onClick={() => { setFilter(''); searchRef.current?.focus(); }} aria-label="Clear search">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M18 6L6 18M6 6l12 12"/></svg>
                </button>
              : <span className="kbd">{IS_MAC ? '⌘K' : 'Ctrl+K'}</span>
            }
          </div>
        </div>
        <div className="topbar-right">
          {tweaks.trafficMode && (
            <button className="btn btn-ghost" onClick={() => setTrafficModeOpen(true)}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="9"/><path d="M2 12h20M12 2a15.3 15.3 0 010 20M12 2a15.3 15.3 0 000 20"/></svg>
              Traffic
            </button>
          )}
          <button className="btn btn-ghost" onClick={() => setDyndnsOpen(true)}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="9"/><path d="M2 12h20M12 2a15.3 15.3 0 010 20M12 2a15.3 15.3 0 000 20"/></svg>
            DynDNS
          </button>
          <button className="btn btn-ghost" onClick={() => setPortCheckOpen(true)}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="3"/><path d="M12 1v6m0 10v6m-9-9h6m10 0h6"/></svg>
            Port check
          </button>
          <button className="btn btn-primary" onClick={() => setAddOpen(true)}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="8" r="4"/><path d="M4 21v-2a6 6 0 016-6h4a6 6 0 016 6v2M18 10v6M15 13h6"/></svg>
            Add peer
          </button>
          <button
            className="icon-btn theme-toggle"
            onClick={() => setTweaks({ ...tweaks, theme: tweaks.theme === 'dark' ? 'light' : 'dark' })}
            aria-label={`Switch to ${tweaks.theme === 'dark' ? 'light' : 'dark'} mode`}
            title={`Switch to ${tweaks.theme === 'dark' ? 'light' : 'dark'} mode`}
          >
            <span className="theme-toggle-icon" key={tweaks.theme}>
              {tweaks.theme === 'dark' ? (
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.9 4.9l1.4 1.4m11.4 11.4l1.4 1.4M2 12h2m16 0h2M4.9 19.1l1.4-1.4m11.4-11.4l1.4-1.4"/></svg>
              ) : (
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M21 12.8A9 9 0 1111.2 3a7 7 0 009.8 9.8z"/></svg>
              )}
            </span>
          </button>
          {onLogout && (
            <button className="icon-btn" onClick={onLogout} aria-label="Sign out" title="Sign out">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4M16 17l5-5-5-5M21 12H9"/></svg>
            </button>
          )}
        </div>
      </header>

      <section className="kpi-row">
        <KPIServiceControl
          serviceActive={serviceActive}
          serviceEnabled={serviceEnabled}
          unit={unit}
          startedAt={startedAt}
          servicePort={servicePort}
          connectedCount={connectedCount}
          totalCount={peers.length}
          internetState={internetState}
          doService={doService}
          serviceLoading={serviceLoading}
          updateAvailable={updateAvailable}
          onOpenSettings={() => { setSettingsOpen(true); setUpdateAvailable(false); }}
          onOpenUptime={() => setUptimeOpen(true)}
        />
        <KPIThroughput currentRx={currentRx} currentTx={currentTx} dataIn={chartTraffic.rx} dataOut={chartTraffic.tx} smooth={tweaks.smoothThroughput} />
        <KPIDataToday total={totalToday} budget={dataBudget} enabled={budgetEnabled} peerBudgets={peerBudgets} onClick={() => setDataDrawerOpen(true)} />
        <KPIActiveSessions connectedCount={connectedCount} totalCount={peers.length} avgPingHistory={avgPingHistory} />
      </section>

      <section className="main-grid">
        <div className="hero-card">
          <div className="hero-head">
            <div>
              <div className="section-label">LIVE THROUGHPUT</div>
              <div className="hero-values">
                <div className="hero-val">
                  <span className="hero-num">{window.WG.formatRate(currentRx).split(' ')[0]}</span>
                  <span className="hero-unit">{window.WG.formatRate(currentRx).split(' ')[1]}</span>
                  <span className="hero-lbl">
                    <span className="legend-dot" style={{ background: 'var(--accent)' }} /> inbound
                  </span>
                </div>
                <div className="hero-val">
                  <span className="hero-num">{window.WG.formatRate(currentTx).split(' ')[0]}</span>
                  <span className="hero-unit">{window.WG.formatRate(currentTx).split(' ')[1]}</span>
                  <span className="hero-lbl">
                    <span className="legend-dot" style={{ background: 'var(--accent-2)' }} /> outbound
                  </span>
                </div>
              </div>
            </div>
            <div className="hero-head-right">
              <RangePills
                options={['10s', '30s', '1m', '5m', '1h', '24h']}
                value={trafficRange}
                onChange={r => { localStorage.setItem('trafficRange', r); setTrafficRange(r); }}
              />
              <button
                className={`chart-pause-btn ${trafficPaused ? 'active' : ''}`}
                title={trafficPaused ? 'Resume live chart' : 'Pause chart to inspect'}
                aria-label={trafficPaused ? 'Resume live chart' : 'Pause chart'}
                onClick={() => setTrafficPaused(p => !p)}
              >
                <span className="chart-pause-ico">
                  <svg className="ico-pause" width="10" height="10" viewBox="0 0 10 10"><rect x="1.6" y="1" width="2.5" height="8" rx="0.8" fill="currentColor" /><rect x="5.9" y="1" width="2.5" height="8" rx="0.8" fill="currentColor" /></svg>
                  <svg className="ico-play" width="10" height="10" viewBox="0 0 10 10"><path d="M2.6 1.2 L8.8 5 L2.6 8.8 Z" fill="currentColor" /></svg>
                </span>
              </button>
            </div>
          </div>
          <ThroughputChart samples={trafficHistory} width={900} height={240} range={trafficRange} spline={tweaks.splineChart} splineTension={tweaks.splineTension ?? 1} smoothScroll={tweaks.smoothThroughput} smoothScale={tweaks.smoothScale} paused={trafficPaused} />
        </div>

        <div className="logs-card-shell">
          <LogsPanel logs={logs} notifications={alerts} onExpand={() => setLogsDrawerOpen(true)} onDismiss={dismissAlert} serviceActive={serviceActive} ifaceName={ifaceName} />
        </div>
      </section>

      <section className="peers-card">
        <div className="peers-head">
          <div>
            <div className="section-label">PEERS</div>
            <div className="peers-count">{filtered.length} of {peers.length}</div>
          </div>
          <div className="peers-filters">
            {[
              { key: 'all',       label: 'All',     count: null },
              { key: 'connected', label: 'Online',  count: peers.filter(p => p.status === 'connected').length },
              { key: 'offline',   label: 'Offline', count: peers.filter(p => p.status === 'offline').length },
            ].map(({ key, label, count }) => (
              <button key={key} className={`filter-pill ${statusFilter === key ? 'active' : ''}`} onClick={() => setStatusFilter(key)}>
                {label}{count !== null && <span className="filter-pill-count">{count}</span>}
              </button>
            ))}
          </div>
        </div>
        <div className="peers-table">
          <PeerTableHeader />
          {!peersLoaded && [0, 1, 2, 3].map(i => <PeerRowSkeleton key={i} seed={i} />)}
          {peersLoaded && peers.length === 0 && (
            <div className="peers-empty-state">
              <div className="peers-empty-icon">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><circle cx="12" cy="8" r="4"/><path d="M4 21v-2a6 6 0 016-6h4a6 6 0 016 6v2M18 10v6M15 13h6"/></svg>
              </div>
              <div className="peers-empty-title">No peers yet</div>
              <div className="peers-empty-desc">Add your first peer to get started. They'll appear here once created.</div>
              <button className="btn btn-primary peers-empty-btn" onClick={() => setAddOpen(true)}>
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="8" r="4"/><path d="M4 21v-2a6 6 0 016-6h4a6 6 0 016 6v2M18 10v6M15 13h6"/></svg>
                Add peer
              </button>
            </div>
          )}
          {peersLoaded && peers.length > 0 && filtered.length === 0 && (
            <div style={{ padding: '32px 20px', textAlign: 'center', color: 'var(--muted)', fontFamily: 'var(--mono)', fontSize: 12 }}>
              No peers match the current filter
            </div>
          )}
          {filtered.map(p => (
            <PeerRow key={p.id} peer={p} spark={sparks[p.id] || []} onClick={() => setSelectedPeer(p.id)} onPeerUpdated={refreshPeers} />
          ))}
        </div>
      </section>

      {selectedPeer && (
        <PeerDrawer
          peer={peers.find(p => p.id === selectedPeer)}
          onClose={() => setSelectedPeer(null)}
          throughputBuffers={peerThr}
          peerPingHistory={peerPingHistory}
          tweaks={tweaks}
          onRevoke={refreshPeers}
          onPeerUpdated={refreshPeers}
        />
      )}

      {dataDrawerOpen && (
        <DataBudgetDrawer
          total={totalToday}
          budget={dataBudget}
          setBudget={setDataBudget}
          enabled={budgetEnabled}
          alerts={budgetAlerts}
          setAlerts={setBudgetAlerts}
          resetTime={resetTime}
          setResetTime={setResetTime}
          peers={peers}
          peerBudgets={peerBudgets}
          setPeerBudget={setPeerBudget}
          enforcement={enforcement}
          budgetUsage={budgetUsage}
          updateBudgetSettings={updateBudgetSettings}
          onClose={() => setDataDrawerOpen(false)}
        />
      )}

      {trafficModeOpen && (
        <TrafficMode
          peers={peers.map(p => ({ ...p, ...(peerGeo[p.name] || {}), pingMs: peerPings[p.name] ?? p.pingMs }))}
          theme={tweaks.theme}
          serverName={unit.replace('wg-quick@', '')}
          onClose={() => setTrafficModeOpen(false)}
        />
      )}
      {settingsOpen && <SettingsDrawer tweaks={tweaks} setTweaks={setTweaks} onClose={() => setSettingsOpen(false)} onUpdateAvailable={setUpdateAvailable} />}
      {uptimeOpen && <UptimeDrawer unit={unit} onClose={() => setUptimeOpen(false)} />}
      {dyndnsOpen && <DynDNSDrawer onClose={() => setDyndnsOpen(false)} />}
      {portCheckOpen && <PortCheckDrawer peers={peers} onClose={() => setPortCheckOpen(false)} />}
      {logsDrawerOpen && <LogsDrawer alerts={alerts} onClose={() => setLogsDrawerOpen(false)} verbose={logsVerbose} setVerbose={setLogsVerbose} onDismiss={dismissAlert} />}
      {addOpen && (
        <AddPeerDrawer
          peers={peers}
          onClose={() => setAddOpen(false)}
          onCreated={() => {
            window.WG.apiCall('/api/status', { silent: true }).then(j => {
              const mapped = window.WG.mapApiPeers(j.clients.issued, j.clients.live);
              setPeers(mapped);
              ensurePeerState(mapped);
            }).catch(() => {});
            window.WG.toast?.success?.('Peer added', 'New peer is ready to connect');
          }}
        />
      )}
      {WGToaster && <WGToaster />}
    </div>
  );
}

// ============================================================
// KPI tiles
// ============================================================
function KPIServiceControl({ serviceActive, startedAt, servicePort, connectedCount, totalCount, internetState, doService, serviceLoading, updateAvailable, onOpenSettings, onOpenUptime }) {
  const internetDown = internetState === 'down';
  const uptime = (() => {
    if (!serviceActive) return 'stopped';
    if (!startedAt) return '—';
    const mins = Math.floor((Date.now() - startedAt) / 60000);
    const hrs = Math.floor(mins / 60);
    const days = Math.floor(hrs / 24);
    if (days > 0) return `${days}d ${hrs % 24}h`;
    return hrs > 0 ? `${hrs}h ${mins % 60}m` : `${mins}m`;
  })();

  return (
    <div className="kpi-tile">
      <div className="kpi-head">
        <span className="section-label">SERVICE CONTROL</span>
        <span className={`kpi-badge ${serviceActive ? 'badge-ok' : ''}`}>
          {serviceActive && <span className="pulse-dot" />}
          {serviceActive ? 'running' : 'stopped'}
        </span>
      </div>
      <div className="svc-buttons">
        <button className={`svc-btn ${serviceActive || serviceLoading ? 'disabled' : ''}`} disabled={serviceActive || !!serviceLoading} onClick={() => doService('start')}>
          {serviceLoading === 'start' ? <span className="pc-spinner" /> : <svg width="11" height="11" viewBox="0 0 24 24" fill="currentColor"><path d="M6 4l14 8-14 8V4z"/></svg>}
          Start
        </button>
        <button className={`svc-btn ${serviceLoading ? 'disabled' : ''}`} disabled={!!serviceLoading} onClick={() => {
          window.WG.toast?.confirm?.(
            'Restart the server?',
            'Peers will briefly disconnect during the restart.',
            { confirmLabel: 'Restart', onConfirm: () => doService('restart'), dedup: 'confirm-restart' }
          );
        }}>
          {serviceLoading === 'restart' ? <span className="pc-spinner" /> : <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 12a9 9 0 11-9-9c2.5 0 4.7 1 6.4 2.6L21 3v6h-6"/></svg>}
          Restart
        </button>
        <button className={`svc-btn ${!serviceActive || serviceLoading ? 'disabled' : ''}`} disabled={!serviceActive || !!serviceLoading} onClick={() => {
          window.WG.toast?.confirm?.(
            'Stop the server?',
            'All connected peers will be disconnected.',
            { confirmLabel: 'Stop server', onConfirm: () => doService('stop'), dedup: 'confirm-stop' }
          );
        }}>
          {serviceLoading === 'stop' ? <span className="pc-spinner" /> : <svg width="11" height="11" viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="6" width="12" height="12" rx="1"/></svg>}
          Stop
        </button>
      </div>
      <div className="svc-stats">
        <button className="svc-stat svc-stat-btn" onClick={onOpenUptime} title={internetDown ? 'Internet is unreachable — show uptime history' : 'Show uptime history'}>
          <div className="svc-stat-label">
            Uptime
            {internetDown && <span className="svc-stat-dot" title="Internet is unreachable" />}
            <svg className="svc-stat-chev" width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4"><path d="M9 18l6-6-6-6"/></svg>
          </div>
          <div className="svc-stat-val mono">{uptime}</div>
        </button>
        <div className="svc-stat">
          <div className="svc-stat-label">Port</div>
          <div className="svc-stat-val mono">{servicePort || '—'}</div>
        </div>
        <div className="svc-stat">
          <div className="svc-stat-label">Peers</div>
          <div className="svc-stat-val mono">{connectedCount}/{totalCount}</div>
        </div>
      </div>
      <div className="kpi-foot kpi-foot-center">
        <button className="svc-settings-btn" onClick={onOpenSettings}>
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 11-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 11-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 11-2.83-2.83l.06-.06a1.65 1.65 0 00.33-1.82 1.65 1.65 0 00-1.51-1H3a2 2 0 110-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 112.83-2.83l.06.06a1.65 1.65 0 001.82.33H9a1.65 1.65 0 001-1.51V3a2 2 0 114 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 112.83 2.83l-.06.06a1.65 1.65 0 00-.33 1.82V9a1.65 1.65 0 001.51 1H21a2 2 0 110 4h-.09a1.65 1.65 0 00-1.51 1z"/></svg>
          Dashboard settings
          {updateAvailable && <span className="svc-update-dot" title="Update available" />}
          <svg className="svc-settings-chev" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M9 18l6-6-6-6"/></svg>
        </button>
      </div>
    </div>
  );
}

// Segmented range control with a sliding highlight behind the active pill.
// The thumb is measured from the active button so it follows the mono-font
// width differences and the mobile two-row grid layout.
function RangePills({ options, value, onChange }) {
  const wrapRef = uR(null);
  const [thumb, setThumb] = uS(null); // { left, top, width, height }

  const measure = uC(() => {
    const el = wrapRef.current?.querySelector('.range-pill.active');
    if (!el) { setThumb(null); return; }
    setThumb({ left: el.offsetLeft, top: el.offsetTop, width: el.offsetWidth, height: el.offsetHeight });
  }, []);

  React.useLayoutEffect(measure, [value, measure]);
  uE(() => {
    const wrap = wrapRef.current;
    if (!wrap) return;
    const ro = new ResizeObserver(measure);
    ro.observe(wrap);
    return () => ro.disconnect();
  }, [measure]);

  return (
    <div ref={wrapRef} className="range-pills">
      {thumb && <span className="range-pill-thumb" style={{ left: thumb.left, top: thumb.top, width: thumb.width, height: thumb.height }} />}
      {options.map(r => (
        <button key={r} className={`range-pill ${value === r ? 'active' : ''}`} onClick={() => onChange(r)}>{r}</button>
      ))}
    </div>
  );
}

function KPIThroughput({ currentRx, currentTx, dataIn, dataOut, smooth = false }) {
  const miniData = dataIn.map((v, i) => v + (dataOut[i] || 0));
  const total = currentRx + currentTx;
  return (
    <div className="kpi-tile">
      <div className="kpi-head">
        <span className="section-label">THROUGHPUT</span>
      </div>
      <div className="kpi-body">
        <div className="kpi-number">
          <span className="kpi-big">{window.WG.formatRate(total).split(' ')[0]}</span>
          <span className="kpi-unit">{window.WG.formatRate(total).split(' ')[1]}</span>
        </div>
        <div className="kpi-mini">
          <MiniBars data={miniData} width={140} height={40} color="var(--accent)" smooth={smooth} slots={20} format={v => window.WG.formatRate(v)} />
        </div>
      </div>
      <div className="kpi-foot">
        <span className="mono" style={{ color: 'var(--accent)' }}>↓ {window.WG.formatRate(currentRx)}</span>
        <span className="mono" style={{ color: 'var(--accent-2)' }}>↑ {window.WG.formatRate(currentTx)}</span>
      </div>
    </div>
  );
}

function KPIDataToday({ total, budget = 50, enabled = true, peerBudgets = {}, onClick }) {
  const entries = Object.values(peerBudgets);
  const budgetGB = entries.reduce((s, b) => s + (b === 'inf' || b == null ? 0 : b), 0);
  const allInfinite = entries.length > 0 && budgetGB === 0;
  const unlimited = !enabled || allInfinite;
  const effectiveGB = budgetGB > 0 ? budgetGB : budget;
  const cap = unlimited ? Math.max(total, 1) : effectiveGB * 1024 * 1024 * 1024;
  const pct = unlimited ? 0 : (total / cap) * 100;
  return (
    <div className="kpi-tile kpi-clickable" onClick={onClick} role="button" tabIndex={0}>
      <div className="kpi-head">
        <span className="section-label">DATA TODAY</span>
        {enabled && <span className="kpi-badge">{allInfinite ? '∞ no limit' : `of ${effectiveGB} GB`}</span>}
      </div>
      <div className="kpi-body kpi-body-radial">
        <RadialGauge
          value={total}
          max={cap}
          unlimited={unlimited}
          width={110}
          color={unlimited ? 'var(--accent)' : pct > 90 ? 'var(--danger)' : pct > 70 ? 'var(--warn)' : 'var(--accent)'}
          label={window.WG.formatBytes(total).split(' ')[0]}
          sublabel={window.WG.formatBytes(total).split(' ')[1]}
        />
      </div>
      <div className="kpi-foot">
        <span className="mono">{unlimited ? 'used today' : `${pct.toFixed(1)}% of budget`}</span>
        <span className="mono kpi-link">configure <svg className="kpi-link-chev" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4"><path d="M9 18l6-6-6-6"/></svg></span>
      </div>
    </div>
  );
}

function KPIActiveSessions({ connectedCount, totalCount, avgPingHistory }) {
  const avgPing = avgPingHistory.length ? avgPingHistory[avgPingHistory.length - 1] : 0;

  return (
    <div className="kpi-tile">
      <div className="kpi-head">
        <span className="section-label">ACTIVE SESSIONS</span>
      </div>
      <div className="kpi-body" style={{ gap: 6 }}>
        <div className="kpi-number">
          <span className="kpi-big">{connectedCount}</span>
          <span className="kpi-unit">/ {totalCount}</span>
        </div>
        <div className="kpi-mini" style={{ maxWidth: 210, marginLeft: -12 }}>
          <Sparkline data={avgPingHistory} width={200} height={48} color="var(--accent-2)" format={v => v > 0 ? `${Math.round(v)} ms` : 'no data'} />
        </div>
      </div>
      <div className="kpi-foot">
        <span className="mono">{totalCount > 0 ? Math.round((connectedCount / totalCount) * 100) : 0}% online</span>
        <span className="mono">avg ping {avgPing > 0 ? `${avgPing.toFixed(1)} ms` : '—'}</span>
      </div>
    </div>
  );
}

// ============================================================
// Peer row
// ============================================================
function OfflinePlaceholder({ width = 110, height = 30 }) {
  return (
    <svg viewBox={`0 0 ${width} ${height}`} style={{ width, height, display: 'block', opacity: 0.3 }}>
      <line x1={6} y1={height / 2} x2={width - 6} y2={height / 2}
        stroke="var(--muted)" strokeWidth="1.5" strokeDasharray="4 4" strokeLinecap="round" />
    </svg>
  );
}

function PeerRowSkeleton({ seed = 0 }) {
  // Vary widths per row so the placeholder reads as real content
  const w = (base, spread) => base + ((seed * 37) % spread);
  return (
    <div className="peers-row row-skeleton" aria-hidden="true">
      <div className="peer-status-cell"><span className="skel skel-dot" /></div>
      <div className="peer-name-cell">
        <span className="skel skel-avatar" />
        <div>
          <div><span className="skel" style={{ width: w(72, 44) }} /></div>
          <div><span className="skel skel-sub" style={{ width: w(42, 26), marginTop: 4 }} /></div>
        </div>
      </div>
      <div><span className="skel" style={{ width: w(78, 28) }} /></div>
      <div><span className="skel" style={{ width: 92, height: 8 }} /></div>
      <div className="num"><span className="skel" style={{ width: w(46, 18) }} /></div>
      <div className="num" style={{ paddingRight: 16 }}><span className="skel" style={{ width: w(46, 22) }} /></div>
      <div>
        <div><span className="skel" style={{ width: w(58, 32) }} /></div>
        <div><span className="skel skel-sub" style={{ width: w(74, 20), marginTop: 4 }} /></div>
      </div>
      <div />
    </div>
  );
}

// ============================================================
// Peer row context menu — portaled so the table never clips it
// ============================================================
const CTX_ICON = {
  details: <><path d="M4 5h16a1 1 0 011 1v12a1 1 0 01-1 1H4a1 1 0 01-1-1V6a1 1 0 011-1z" /><path d="M14 5v14" /></>,
  copy: <><rect x="9" y="9" width="11" height="11" rx="2" /><path d="M5 15V5a2 2 0 012-2h8" /></>,
  download: <><path d="M12 3v12" /><path d="M8 11l4 4 4-4" /><path d="M4 20h16" /></>,
  qr: <><rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" /><rect x="3" y="14" width="7" height="7" /><path d="M14 14h3v3M21 14v3M14 17v4h3M17 21h4" /></>,
  pause: <><rect x="7" y="5" width="3.5" height="14" rx="1" /><rect x="13.5" y="5" width="3.5" height="14" rx="1" /></>,
  resume: <path d="M7 4.5l12 7.5-12 7.5z" />,
  revoke: <><path d="M4 7h16" /><path d="M9 7V4h6v3" /><path d="M6 7l1 13h10l1-13" /><path d="M10 11v6M14 11v6" /></>,
};

const ARROW = 10;
const ARROW_INSET = 22; // distance from the menu's right edge to the arrow's tip

function PeerContextMenu({ peer, anchor, triggerRef, onClose, onOpenDetails, onShowQr, onPeerUpdated }) {
  const menuRef = uR(null);
  const [pos, setPos] = uS(null);
  const [active, setActive] = uS(-1);

  const statusColor = peer.paused ? 'var(--warn)' : peer.throttled ? 'var(--danger)' : peer.status === 'connected' ? 'var(--success)' : 'var(--muted)';
  const statusLabel = peer.paused ? 'Paused' : peer.throttled ? 'Throttled' : peer.status === 'connected' ? 'Online' : 'Offline';

  const copyAddress = () => {
    navigator.clipboard?.writeText(peer.addr);
    window.WG.toast?.success?.('Address copied', peer.addr);
  };

  const downloadConfig = async () => {
    const t = window.WG.toast?.loading?.(`Preparing "${peer.name}.conf"…`);
    try {
      await window.WG.downloadPeerConfig(peer.name);
      t?.success?.('Config downloaded', `${peer.name}.conf`);
    } catch (e) {
      t?.error?.('Download failed', e.message || 'API error');
    }
  };

  const togglePause = async () => {
    const wasPaused = peer.paused;
    const t = window.WG.toast?.loading?.(wasPaused ? `Resuming "${peer.name}"…` : `Pausing "${peer.name}"…`);
    try {
      await window.WG.setPeerPaused(peer.name, !wasPaused);
      onPeerUpdated?.();
      if (wasPaused) t?.success?.('Peer resumed', `"${peer.name}" is active again`);
      else t?.update?.({ type: 'pause', title: 'Peer paused', desc: `"${peer.name}" is now blocked`, duration: 4000 });
    } catch (e) {
      t?.error?.(`Failed to ${wasPaused ? 'resume' : 'pause'} peer`, e.message || 'API error');
    }
  };

  const revoke = () => {
    window.WG.toast?.confirm?.(
      'Revoke this peer?',
      `"${peer.name}" will be permanently removed and disconnected.`,
      {
        confirmLabel: 'Revoke',
        onConfirm: async () => {
          const t = window.WG.toast?.loading?.(`Revoking "${peer.name}"…`);
          try {
            await window.WG.revokePeer(peer.name);
            t?.success?.('Peer revoked', `"${peer.name}" has been removed`);
            onPeerUpdated?.();
          } catch (e) {
            t?.error?.('Revoke failed', e.message || 'API error');
          }
        },
      }
    );
  };

  const items = [
    { key: 'details', label: 'View details', icon: CTX_ICON.details, run: onOpenDetails },
    { key: 'copy', label: 'Copy address', icon: CTX_ICON.copy, hint: peer.addr, run: copyAddress, disabled: !peer.addr || peer.addr === '—' },
    { key: 'download', label: 'Download config', icon: CTX_ICON.download, hint: '.conf', run: downloadConfig },
    { key: 'qr', label: 'Show QR code', icon: CTX_ICON.qr, hint: 'phone', run: onShowQr },
    { key: 'pause', label: peer.paused ? 'Resume peer' : 'Pause peer', icon: peer.paused ? CTX_ICON.resume : CTX_ICON.pause, run: togglePause },
    { sep: true },
    { key: 'revoke', label: 'Revoke peer', icon: CTX_ICON.revoke, run: revoke, danger: true },
  ];
  const selectable = items.filter(it => !it.sep && !it.disabled);

  const select = (item) => {
    if (!item || item.disabled) return;
    onClose();
    item.run();
  };

  // Measure, then clamp into the viewport and flip upward when short on space
  React.useLayoutEffect(() => {
    const el = menuRef.current;
    if (!el) return;
    const M = 12;
    const { offsetWidth: w, offsetHeight: h } = el;
    let top = anchor.top;
    let flipped = false;
    if (top + h > window.innerHeight - M) {
      top = anchor.flipTop - h;
      flipped = true;
    }
    const left = Math.min(Math.max(M, anchor.left), window.innerWidth - w - M);
    setPos({
      left,
      top: Math.max(M, top),
      origin: flipped ? 'bottom right' : 'top right',
      flipped,
      // Point the arrow at the trigger's centre, but keep it clear of the corners
      arrowLeft: anchor.arrowX == null
        ? null
        : Math.min(Math.max(14, anchor.arrowX - left - ARROW / 2), w - 14 - ARROW),
    });
    // Take focus off the trigger, otherwise Enter re-toggles the button
    el.focus({ preventScroll: true });
  }, [anchor]);

  uE(() => {
    const onKeyDown = (e) => {
      if (e.key === 'Escape' || e.key === 'Tab') {
        if (e.key === 'Escape') triggerRef?.current?.focus({ preventScroll: true });
        onClose();
        return;
      }
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        e.preventDefault();
        const step = e.key === 'ArrowDown' ? 1 : -1;
        setActive(i => i < 0
          ? (step > 0 ? 0 : selectable.length - 1)
          : (i + step + selectable.length) % selectable.length);
      } else if (e.key === 'Enter' && active >= 0) {
        e.preventDefault();
        select(selectable[active]);
      }
    };
    // The trigger owns its own toggle — let its click handler close the menu
    const onPointerDown = (e) => {
      if (menuRef.current?.contains(e.target) || triggerRef?.current?.contains(e.target)) return;
      onClose();
    };
    document.addEventListener('keydown', onKeyDown);
    document.addEventListener('pointerdown', onPointerDown, true);
    window.addEventListener('resize', onClose);
    window.addEventListener('scroll', onClose, true);
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      document.removeEventListener('pointerdown', onPointerDown, true);
      window.removeEventListener('resize', onClose);
      window.removeEventListener('scroll', onClose, true);
    };
  });

  let sIdx = -1;
  return ReactDOM.createPortal(
    <div
      ref={menuRef}
      className="ctx-menu"
      role="menu"
      tabIndex={-1}
      aria-label={`Actions for ${peer.name}`}
      style={{
        left: pos ? pos.left : anchor.left,
        top: pos ? pos.top : anchor.top,
        visibility: pos ? 'visible' : 'hidden',
        '--ctx-origin': pos ? pos.origin : 'top right',
      }}
      onClick={e => e.stopPropagation()}
      onContextMenu={e => { e.preventDefault(); e.stopPropagation(); }}
    >
      {pos?.arrowLeft != null && (
        <span
          className={`ctx-arrow${pos.flipped ? ' is-flipped' : ''}`}
          style={{ left: pos.arrowLeft }}
          aria-hidden="true"
        />
      )}
      <div className="ctx-menu-head">
        <div className={`peer-avatar-sm${peer.paused ? ' is-paused' : ''}`}>
          {peer.paused
            ? <svg width="11" height="11" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><rect x="6" y="4" width="4" height="16" rx="1" /><rect x="14" y="4" width="4" height="16" rx="1" /></svg>
            : peer.name.split('-').map(s => s[0]).join('').slice(0, 2).toUpperCase()}
        </div>
        <div className="ctx-menu-ident">
          <div className="ctx-menu-name">{peer.name}</div>
          <div className="ctx-menu-sub"><i style={{ background: statusColor }} />{statusLabel}</div>
        </div>
      </div>
      {items.map((item, i) => {
        if (item.sep) return <div key={`sep-${i}`} className="ctx-sep" />;
        if (!item.disabled) sIdx += 1;
        const idx = item.disabled ? -1 : sIdx;
        return (
          <button
            key={item.key}
            type="button"
            role="menuitem"
            className={`ctx-item${item.danger ? ' danger' : ''}${idx >= 0 && idx === active ? ' is-active' : ''}`}
            disabled={item.disabled}
            onMouseEnter={() => setActive(idx)}
            onClick={() => select(item)}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">{item.icon}</svg>
            <span className="ctx-item-label">{item.label}</span>
            {item.hint && <span className="ctx-item-hint">{item.hint}</span>}
          </button>
        );
      })}
    </div>,
    document.body
  );
}

const CTX_MENU_W = 224;

function PeerRow({ peer, spark, onClick, onPeerUpdated }) {
  const [menuAnchor, setMenuAnchor] = uS(null);
  const [qrOpen, setQrOpen] = uS(false);
  const menuBtnRef = uR(null);
  const statusColor = peer.paused ? 'var(--warn)' : peer.throttled ? 'var(--danger)' : peer.status === 'connected' ? 'var(--success)' : 'var(--muted)';
  const isOnline = peer.status === 'connected';
  const statusLabel = peer.paused ? 'Paused' : peer.throttled ? 'Throttled' : isOnline ? 'Online' : 'Offline';
  const statusDetail = peer.paused ? 'Traffic suspended'
    : peer.throttled ? 'Rate limited'
    : peer.lastHs ? `${isOnline ? 'Handshake' : 'Last seen'} ${window.WG.formatRelTime(peer.lastHs)}`
    : 'Never connected';
  let hasDraft = false;
  try { hasDraft = !!localStorage.getItem('WG_PEER_DRAFT_' + peer.name); } catch (_) {}

  const openMenuFromButton = (e) => {
    e.stopPropagation();
    if (menuAnchor) { setMenuAnchor(null); return; }
    const r = e.currentTarget.getBoundingClientRect();
    const arrowX = r.left + r.width / 2;
    setMenuAnchor({
      // Right-aligned, but pulled in far enough that the arrow clears the corner radius
      left: arrowX - (CTX_MENU_W - ARROW_INSET),
      top: r.bottom + 8,
      flipTop: r.top - 8,
      arrowX,
    });
  };

  const openMenuFromRow = (e) => {
    e.preventDefault();
    setMenuAnchor({ left: e.clientX, top: e.clientY + 4, flipTop: e.clientY - 4 });
  };

  return (
    <div className={`peers-row data-row${!isOnline ? ' row-offline' : ''}`} onClick={onClick} onContextMenu={openMenuFromRow}>
      <div className="peer-status-cell">
        <span
          className={`status-dot-wrap status-${peer.paused ? 'paused' : peer.throttled ? 'paused' : peer.status}`}
          role="img"
          aria-label={`${statusLabel} — ${statusDetail}`}
        >
          <span className="status-dot" style={{ background: statusColor }} />
        </span>
        <div className="pingbar-tip status-tip" aria-hidden="true">
          <span className="pingbar-tip-val status-tip-val">
            <i className="status-tip-dot" style={{ background: statusColor }} />
            {statusLabel}
          </span>
          <span className="pingbar-tip-lbl">{statusDetail}</span>
        </div>
      </div>
      <div className="peer-name-cell">
        <div className={`peer-avatar-sm${peer.paused ? ' is-paused' : ''}`}
          role={peer.paused ? 'img' : undefined}
          aria-label={peer.paused ? 'Paused' : undefined}>
          {peer.paused
            ? <svg className="peer-avatar-pause" width="12" height="12" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><rect x="6" y="4" width="4" height="16" rx="1" /><rect x="14" y="4" width="4" height="16" rx="1" /></svg>
            : peer.name.split('-').map(s => s[0]).join('').slice(0, 2).toUpperCase()}
        </div>
        <div>
          <div className="peer-name">
            {peer.name}
            {hasDraft && <span className="peer-draft-dot" title="Unsaved config changes" />}
            {peer.throttled && !peer.paused && (
              <span style={{ marginLeft: 6, fontSize: 10, fontFamily: 'var(--mono)', color: 'var(--danger)', background: 'color-mix(in oklch, var(--danger) 12%, transparent)', padding: '1px 5px', borderRadius: 4, verticalAlign: 'middle' }}>throttled</span>
            )}
          </div>
          <div className="peer-device">{peer.device}</div>
        </div>
      </div>
      <div className="mono peer-address-cell">{peer.addr}</div>
      <div className="peer-traffic-cell">
        {isOnline
          ? <Sparkline data={spark} width={110} height={30} color="var(--accent)" active={true} />
          : <OfflinePlaceholder width={110} height={30} />
        }
      </div>
      <div className="mono num peer-bytes-in-cell">{window.WG.formatBytes(peer.bytesIn)}</div>
      <div className="mono num peer-bytes-out-cell">{window.WG.formatBytes(peer.bytesOut)}</div>
      <div className="mono handshake-cell peer-handshake-cell">
        <div>{window.WG.formatRelTime(peer.lastHs)}</div>
        <div className="handshake-abs">{peer.lastHs ? window.WG.formatAbsTime(peer.lastHs) : ''}</div>
      </div>
      <div className="row-action">
        <button
          ref={menuBtnRef}
          className={`icon-btn-sm${menuAnchor ? ' is-open' : ''}`}
          aria-label={`Actions for ${peer.name}`}
          aria-haspopup="menu"
          aria-expanded={!!menuAnchor}
          onClick={openMenuFromButton}
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/></svg>
        </button>
      </div>
      {menuAnchor && (
        <PeerContextMenu
          peer={peer}
          anchor={menuAnchor}
          triggerRef={menuBtnRef}
          onClose={() => setMenuAnchor(null)}
          onOpenDetails={onClick}
          onShowQr={() => setQrOpen(true)}
          onPeerUpdated={onPeerUpdated}
        />
      )}
      {qrOpen && <window.PeerQrModal peer={peer} onClose={() => setQrOpen(false)} />}
    </div>
  );
}

// ============================================================
// Peer table header
// ============================================================
function PeerTableHeader() {
  return (
    <div className="peers-row peers-head-row">
      <div>Status</div>
      <div>Name</div>
      <div>Address</div>
      <div>Traffic (60s)</div>
      <div className="num">Bytes in</div>
      <div className="num">Bytes out</div>
      <div>Last handshake</div>
      <div />
    </div>
  );
}

// ============================================================
// Login screen
// ============================================================
function LoginScreen({ onLogin, loading, exiting, meta }) {
  const [password, setPassword] = uS('');
  const [showPw, setShowPw] = uS(false);
  const inputRef = uR(null);

  uE(() => { inputRef.current?.focus(); }, []);

  // Redirect stray typing into the password field
  uE(() => {
    const onKeyDown = (e) => {
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      if (e.key.length !== 1 && e.key !== 'Backspace') return;
      const el = document.activeElement;
      if (el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable)) return;
      inputRef.current?.focus();
    };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, []);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!loading && password) onLogin(password);
  };

  const version = meta?.version && meta.version !== 'unknown'
    ? (/^dev\s+/.test(meta.version) ? `v${meta.version.replace(/^dev\s+/, '')}-dev` : `v${meta.version}`)
    : null;
  const serviceActive = meta?.service_active;

  return (
    <div className={`login-screen${exiting ? ' exit' : ''}`}>
      <div className={`login-inner${exiting ? ' exit' : ''}`}>
        <div className="login-brand">
          <div className="login-brand-mark">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
              <path d="M12 2L3 7v6c0 5 4 9 9 10 5-1 9-5 9-10V7l-9-5z"/>
              <path d="M9 12l2 2 4-4"/>
            </svg>
          </div>
          <div className="login-brand-text">
            <div className="login-title">WG-Quick</div>
            <div className="login-subtitle">Dashboard</div>
          </div>
        </div>
        <form onSubmit={handleSubmit} className="login-form">
          <div>
            <label className="login-label">Password</label>
            <div className="login-input-wrap">
              <input
                ref={inputRef}
                type={showPw ? 'text' : 'password'}
                className="login-input"
                placeholder="Enter dashboard password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                autoComplete="current-password"
                disabled={loading}
              />
              <button
                type="button"
                className="login-eye"
                onClick={() => setShowPw(v => !v)}
                tabIndex={-1}
                aria-label={showPw ? 'Hide password' : 'Show password'}
                style={{ color: showPw ? 'var(--accent)' : undefined }}
              >
                {showPw
                  ? <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/><path d="M4 4l16 16"/></svg>
                  : <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                }
              </button>
            </div>
          </div>
          <button type="submit" className="btn btn-primary login-btn" disabled={loading || !password}>
            {loading && <span className="login-spinner-sm" />}
            {loading ? 'Signing in…' : 'Sign in'}
          </button>
        </form>
      </div>
      <div className="login-footer">
        {version && <span className="login-meta-item">{version}</span>}
        {version && serviceActive !== undefined && <span className="login-meta-sep" aria-hidden="true">·</span>}
        {serviceActive !== undefined && (
          <span className="login-meta-item">
            <span className={`login-status-dot ${serviceActive ? 'ok' : 'down'}`} />
            {serviceActive ? 'VPN service running' : 'VPN service stopped'}
          </span>
        )}
        {(version || serviceActive !== undefined) && <span className="login-meta-sep" aria-hidden="true">·</span>}
        <a
          className="login-help"
          href="https://github.com/Migrim/OpenVPN-Dashboard/issues"
          target="_blank"
          rel="noopener noreferrer"
        >Need help?</a>
      </div>
    </div>
  );
}

// ============================================================
// Auth wrapper — gates the full App behind a login screen
// ============================================================
function AuthWrapper({ tweaks, setTweaks }) {
  const WGToaster = window.Toaster;
  const [authState, setAuthStateRaw] = uS('checking');
  const authStateRef = uR('checking');
  const setAuthState = (s) => { authStateRef.current = s; setAuthStateRaw(s); };
  const [loginLoading, setLoginLoading] = uS(false);
  const [exiting, setExiting] = uS(false);
  const [loginMeta, setLoginMeta] = uS(null);

  uE(() => {
    window.WG.onUnauthorized = () => {
      if (authStateRef.current === 'dashboard') {
        window.WG.toast.warning('Session expired', 'Please sign in again');
      }
      setExiting(false);
      setLoginLoading(false);
      setAuthState('login');
    };
    window.WG.apiCall('/api/auth/check', { silent: true })
      .then(j => { setLoginMeta(j); setAuthState(j.authenticated ? 'dashboard' : 'login'); })
      .catch(() => setAuthState('login'));
    return () => { window.WG.onUnauthorized = null; };
  }, []);

  const handleLogin = async (password) => {
    setLoginLoading(true);
    try {
      await window.WG.apiCall('/api/auth/login', { silent: true, method: 'POST', body: JSON.stringify({ password }) });
      setExiting(true);
      setTimeout(() => { setExiting(false); setLoginLoading(false); setAuthState('dashboard'); }, 480);
    } catch (_) {
      window.WG.toast.error('Incorrect password', 'Please try again');
      setLoginLoading(false);
    }
  };

  const handleLogout = async () => {
    try { await window.WG.apiCall('/api/auth/logout', { silent: true, method: 'POST' }); } catch (_) {}
    setLoginLoading(false);
    setAuthState('login');
  };

  if (authState === 'checking') {
    return (
      <div className="login-screen">
        <div className="login-checking-spinner" />
      </div>
    );
  }
  if (authState === 'login') {
    return <>
      <LoginScreen onLogin={handleLogin} loading={loginLoading} exiting={exiting} meta={loginMeta} />
      {WGToaster && <WGToaster />}
    </>;
  }
  return <App tweaks={tweaks} setTweaks={setTweaks} onLogout={handleLogout} />;
}

Object.assign(window, { App, AuthWrapper, LoginScreen, PeerRow, KPIServiceControl, KPIThroughput, KPIDataToday, KPIActiveSessions, OfflinePlaceholder });

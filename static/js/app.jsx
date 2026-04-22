// Main WG-Quick dashboard — real API integration

const { useState: uS, useEffect: uE, useRef: uR, useMemo: uM, useCallback: uC } = React;
const LOG_VERBOSE_KEY = 'WG_LOG_VERBOSE';

function App({ tweaks, setTweaks }) {
  const [peers, setPeers] = uS([]);
  const [selectedPeer, setSelectedPeer] = uS(null);
  const [dataDrawerOpen, setDataDrawerOpen] = uS(false);
  const [portCheckOpen, setPortCheckOpen] = uS(false);
  const [logsDrawerOpen, setLogsDrawerOpen] = uS(false);
  const [addOpen, setAddOpen] = uS(false);
  const [dataBudget, setDataBudget] = uS(50);
  const [budgetAlerts, setBudgetAlerts] = uS(true);
  const [resetTime, setResetTime] = uS('00:00');
  const [filter, setFilter] = uS('');
  const [statusFilter, setStatusFilter] = uS('all');
  const [logs, setLogs] = uS(() => window.WG.makeInitialLogs());
  const [logsVerbose, setLogsVerbose] = uS(() => localStorage.getItem(LOG_VERBOSE_KEY) === '1');
  const [serviceActive, setServiceActive] = uS(false);
  const [serviceEnabled, setServiceEnabled] = uS(false);
  const [unit, setUnit] = uS('wg-quick@wg0');
  const [startedAt] = uS(() => Date.now() - 60_000);

  const [trafficRange, setTrafficRange] = uS('1m');
  const [trafficHistory, setTrafficHistory] = uS([]);

  // Per-peer sparklines (values = byte delta per poll cycle)
  const [sparks, setSparks] = uS({});
  const [avgPingHistory, setAvgPingHistory] = uS(() => new Array(20).fill(0));

  // Per-peer drawer throughput buffer
  const [peerThr, setPeerThr] = uS({});

  // Previous cumulative bytes per peer — used to compute sparkline deltas
  const prevBytesRef = uR({});

  uE(() => {
    localStorage.setItem(LOG_VERBOSE_KEY, logsVerbose ? '1' : '0');
  }, [logsVerbose]);

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
        const j = await window.WG.apiCall('/api/status');
        if (cancelled) return;
        setServiceActive(!!j.service.active);
        setServiceEnabled(!!j.service.enabled);
        if (j.service.unit) setUnit(j.service.unit);
        const mapped = window.WG.mapApiPeers(j.clients.issued, j.clients.live);
        setPeers(prev => {
          const prevMap = new Map(prev.map(p => [p.id, p]));
          return mapped.map(p => {
            const old = prevMap.get(p.id);
            return old ? { ...old, ...p } : p;
          });
        });
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
          connectedPeerNames.map(name => window.WG.apiCall('/api/users/' + encodeURIComponent(name) + '/diag').catch(() => null))
        );
        if (cancelled) return;
        const values = results
          .map(r => Number(r && r.ping_ms))
          .filter(v => Number.isFinite(v) && v >= 0);
        const avg = values.length ? values.reduce((sum, v) => sum + v, 0) / values.length : 0;
        setAvgPingHistory(prev => [...prev.slice(1), avg]);
      } catch (_) {}
    };
    pollAveragePing();
    const id = setInterval(pollAveragePing, 5000);
    return () => { cancelled = true; clearInterval(id); };
  }, [connectedPeerKey]);

  uE(() => {
    let cancelled = false;
    const fetchTrafficHistory = async () => {
      try {
        const h = await window.WG.apiCall(`/api/traffic/history?range=${trafficRange}&max_points=1800`);
        if (cancelled) return;
        setTrafficHistory((h.samples || []).map(s => ({
          ts: Number(s.ts) * 1000,
          rx: Math.max(0, Number(s.rx_bps) || 0),
          tx: Math.max(0, Number(s.tx_bps) || 0),
        })));
      } catch (_) {}
    };
    fetchTrafficHistory();
    return () => { cancelled = true; };
  }, [trafficRange]);

  // Poll /api/traffic every 1s; the server keeps the rolling 24h history.
  uE(() => {
    let cancelled = false;
    const fetchTraffic = async () => {
      try {
        const t = await window.WG.apiCall('/api/traffic');
        if (cancelled) return;
        const sample = {
          ts: Number(t.ts) * 1000,
          rx: Math.max(0, Number(t.rx_bps) || 0),
          tx: Math.max(0, Number(t.tx_bps) || 0),
        };
        setTrafficHistory(prev => {
          const rangeMs = window.WG.TRAFFIC_RANGES[trafficRange] || window.WG.TRAFFIC_RANGES['1m'];
          const cutoff = Date.now() - rangeMs;
          const next = prev.length && sample.ts <= prev[prev.length - 1].ts
            ? [...prev.slice(0, -1), sample]
            : [...prev, sample];
          return next.filter(s => s.ts >= cutoff);
        });
      } catch (_) {}
    };
    fetchTraffic();
    const id = setInterval(fetchTraffic, 1000);
    return () => { cancelled = true; clearInterval(id); };
  }, [trafficRange]);

  // Poll /api/logs every 8s
  uE(() => {
    let cancelled = false;
    const fetchLogs = async () => {
      try {
        const j = await window.WG.apiCall('/api/logs?n=60');
        if (cancelled) return;
        if (j.lines && j.lines.length) {
          setLogs(window.WG.parseLogLines(j.lines));
        }
      } catch (_) {}
    };
    fetchLogs();
    const id = setInterval(fetchLogs, 8000);
    return () => { cancelled = true; clearInterval(id); };
  }, []);


  const doService = async (action) => {
    try {
      await window.WG.apiCall('/api/service', { method: 'POST', body: JSON.stringify({ action }) });
      // Force a status refresh
      const j = await window.WG.apiCall('/api/status');
      setServiceActive(!!j.service.active);
      setServiceEnabled(!!j.service.enabled);
    } catch (_) {}
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
  const totalToday = peers.reduce((s, p) => s + p.bytesIn + p.bytesOut, 0);
  const offlineLong = peers.filter(p => p.status === 'offline' && p.lastHs && (Date.now() - p.lastHs) > 24 * 3600_000);
  const neverConnected = peers.filter(p => p.status === 'offline' && !p.lastHs);

  const alerts = [];
  if (offlineLong.length > 0 || neverConnected.length > 0) {
    const parts = [];
    if (offlineLong.length) parts.push(offlineLong.map(p => `${p.name}: offline >24h`).join(' · '));
    if (neverConnected.length) parts.push(neverConnected.map(p => `${p.name}: never connected`).join(' · '));
    alerts.push({ level: 'warn', title: `${offlineLong.length + neverConnected.length} peer(s) need attention`, desc: parts.join(' · ') });
  }

  const filtered = peers.filter(p => {
    if (statusFilter !== 'all' && p.status !== statusFilter) return false;
    if (!filter) return true;
    const f = filter.toLowerCase();
    return p.name.toLowerCase().includes(f) || p.addr.includes(f) || (p.pubKey || '').toLowerCase().includes(f);
  });

  const density = tweaks.density || 'dense';
  const accent = tweaks.accent || 'terracotta';

  return (
    <div className={`app density-${density} accent-${accent}`}>
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
            <input
              type="text"
              placeholder="Filter peers by name, IP, or public key…"
              value={filter}
              onChange={e => setFilter(e.target.value)}
            />
            <span className="kbd">⌘K</span>
          </div>
        </div>
        <div className="topbar-right">
          <button className="btn btn-ghost" onClick={() => setPortCheckOpen(true)}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="3"/><path d="M12 1v6m0 10v6m-9-9h6m10 0h6"/></svg>
            Check ports
          </button>
          <button className="btn btn-primary" onClick={() => setAddOpen(true)}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="8" r="4"/><path d="M4 21v-2a6 6 0 016-6h4a6 6 0 016 6v2M18 10v6M15 13h6"/></svg>
            Add peer
          </button>
          <button className="icon-btn" onClick={() => setTweaks({ ...tweaks, theme: tweaks.theme === 'dark' ? 'light' : 'dark' })} aria-label="Toggle theme">
            {tweaks.theme === 'dark' ? (
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.9 4.9l1.4 1.4m11.4 11.4l1.4 1.4M2 12h2m16 0h2M4.9 19.1l1.4-1.4m11.4-11.4l1.4-1.4"/></svg>
            ) : (
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M21 12.8A9 9 0 1111.2 3a7 7 0 009.8 9.8z"/></svg>
            )}
          </button>
        </div>
      </header>

      <section className="kpi-row">
        <KPIServiceControl
          serviceActive={serviceActive}
          serviceEnabled={serviceEnabled}
          unit={unit}
          startedAt={startedAt}
          connectedCount={connectedCount}
          totalCount={peers.length}
          doService={doService}
        />
        <KPIThroughput currentRx={currentRx} currentTx={currentTx} dataIn={chartTraffic.rx} dataOut={chartTraffic.tx} />
        <KPIDataToday total={totalToday} budget={dataBudget} onClick={() => setDataDrawerOpen(true)} />
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
              <div className="range-pills">
                {['1m', '5m', '1h', '24h'].map(r => (
                  <button key={r} className={`range-pill ${trafficRange === r ? 'active' : ''}`} onClick={() => setTrafficRange(r)}>{r}</button>
                ))}
              </div>
            </div>
          </div>
          <ThroughputChart dataIn={chartTraffic.rx} dataOut={chartTraffic.tx} width={900} height={240} range={trafficRange} />
        </div>

        <LogsPanel logs={logs} alerts={alerts} onExpand={() => setLogsDrawerOpen(true)} />
      </section>

      <section className="peers-card">
        <div className="peers-head">
          <div>
            <div className="section-label">PEERS</div>
            <div className="peers-count">{filtered.length} of {peers.length}</div>
          </div>
          <div className="peers-filters">
            {['all', 'connected', 'offline'].map(s => (
              <button key={s} className={`filter-pill ${statusFilter === s ? 'active' : ''}`} onClick={() => setStatusFilter(s)}>
                {s === 'all' ? 'All' : s === 'connected' ? 'Online' : 'Offline'}
              </button>
            ))}
          </div>
        </div>
        <div className="peers-table">
          <div className="peers-row peers-head-row">
            <div>Status</div>
            <div>Name</div>
            <div>Address</div>
            <div>Traffic (60s)</div>
            <div className="num">Bytes in</div>
            <div className="num">Bytes out</div>
            <div>Last handshake</div>
            <div></div>
          </div>
          {filtered.length === 0 && (
            <div style={{ padding: '32px 20px', textAlign: 'center', color: 'var(--muted)', fontFamily: 'var(--mono)', fontSize: 12 }}>
              {peers.length === 0 ? 'Loading peers…' : 'No peers match the current filter'}
            </div>
          )}
          {filtered.map(p => (
            <PeerRow key={p.id} peer={p} spark={sparks[p.id] || []} onClick={() => setSelectedPeer(p.id)} />
          ))}
        </div>
      </section>

      {selectedPeer && (
        <PeerDrawer
          peer={peers.find(p => p.id === selectedPeer)}
          onClose={() => setSelectedPeer(null)}
          sparklines={sparks}
          throughputBuffers={peerThr}
          onRevoke={() => {
            // Re-fetch peers after revoke
            window.WG.apiCall('/api/status').then(j => {
              setPeers(window.WG.mapApiPeers(j.clients.issued, j.clients.live));
            }).catch(() => {});
          }}
        />
      )}

      {dataDrawerOpen && (
        <DataBudgetDrawer
          total={totalToday}
          budget={dataBudget}
          setBudget={setDataBudget}
          alerts={budgetAlerts}
          setAlerts={setBudgetAlerts}
          resetTime={resetTime}
          setResetTime={setResetTime}
          peers={peers}
          onClose={() => setDataDrawerOpen(false)}
        />
      )}

      {tweaks._tweaksOpen && <TweaksPanel tweaks={tweaks} setTweaks={setTweaks} />}
      {portCheckOpen && <PortCheckDrawer peers={peers} onClose={() => setPortCheckOpen(false)} />}
      {logsDrawerOpen && <LogsDrawer alerts={alerts} onClose={() => setLogsDrawerOpen(false)} verbose={logsVerbose} setVerbose={setLogsVerbose} />}
      {addOpen && (
        <AddPeerModal
          onClose={() => setAddOpen(false)}
          onSuccess={() => {
            setAddOpen(false);
            window.WG.apiCall('/api/status').then(j => {
              const mapped = window.WG.mapApiPeers(j.clients.issued, j.clients.live);
              setPeers(mapped);
              ensurePeerState(mapped);
            }).catch(() => {});
          }}
        />
      )}
    </div>
  );
}

// ============================================================
// KPI tiles
// ============================================================
function KPIServiceControl({ serviceActive, serviceEnabled, unit, startedAt, connectedCount, totalCount, doService }) {
  const uptimeMs = Date.now() - startedAt;
  const mins = Math.floor(uptimeMs / 60000);
  const hrs = Math.floor(mins / 60);
  const uptime = hrs > 0 ? `${hrs}h ${mins % 60}m` : `${mins}m`;

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
        <button className={`svc-btn ${serviceActive ? 'disabled' : ''}`} disabled={serviceActive} onClick={() => doService('start')}>
          <svg width="11" height="11" viewBox="0 0 24 24" fill="currentColor"><path d="M6 4l14 8-14 8V4z"/></svg>
          Start
        </button>
        <button className="svc-btn" onClick={() => doService('restart')}>
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 12a9 9 0 11-9-9c2.5 0 4.7 1 6.4 2.6L21 3v6h-6"/></svg>
          Restart
        </button>
        <button className={`svc-btn ${!serviceActive ? 'disabled' : ''}`} disabled={!serviceActive} onClick={() => doService('stop')}>
          <svg width="11" height="11" viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="6" width="12" height="12" rx="1"/></svg>
          Stop
        </button>
      </div>
      <div className="svc-stats">
        <div className="svc-stat">
          <div className="svc-stat-label">Uptime</div>
          <div className="svc-stat-val mono">{uptime}</div>
        </div>
        <div className="svc-stat">
          <div className="svc-stat-label">Port</div>
          <div className="svc-stat-val mono">51820/udp</div>
        </div>
        <div className="svc-stat">
          <div className="svc-stat-label">Peers</div>
          <div className="svc-stat-val mono">{connectedCount}/{totalCount}</div>
        </div>
      </div>
      <div className="kpi-foot">
        <span className="mono">{unit} · {serviceEnabled ? 'enabled' : 'disabled'}</span>
      </div>
    </div>
  );
}

function KPIThroughput({ currentRx, currentTx, dataIn, dataOut }) {
  const miniData = dataIn.slice(-20).map((v, i) => v + (dataOut[dataIn.length - 20 + i] || 0));
  const total = currentRx + currentTx;
  return (
    <div className="kpi-tile">
      <div className="kpi-head">
        <span className="section-label">THROUGHPUT</span>
        <span className="kpi-badge">live</span>
      </div>
      <div className="kpi-body">
        <div className="kpi-number">
          <span className="kpi-big">{window.WG.formatRate(total).split(' ')[0]}</span>
          <span className="kpi-unit">{window.WG.formatRate(total).split(' ')[1]}</span>
        </div>
        <div className="kpi-mini">
          <MiniBars data={miniData} width={140} height={32} color="var(--accent)" />
        </div>
      </div>
      <div className="kpi-foot">
        <span className="mono" style={{ color: 'var(--accent)' }}>↓ {window.WG.formatRate(currentRx)}</span>
        <span className="mono" style={{ color: 'var(--accent-2)' }}>↑ {window.WG.formatRate(currentTx)}</span>
      </div>
    </div>
  );
}

function KPIDataToday({ total, budget = 50, onClick }) {
  const cap = budget * 1024 * 1024 * 1024;
  const pct = (total / cap) * 100;
  return (
    <div className="kpi-tile kpi-clickable" onClick={onClick} role="button" tabIndex={0}>
      <div className="kpi-head">
        <span className="section-label">DATA TODAY</span>
        <span className="kpi-badge">of {budget} GB</span>
      </div>
      <div className="kpi-body kpi-body-radial">
        <RadialGauge
          value={total}
          max={cap}
          width={110}
          color={pct > 90 ? 'var(--danger)' : pct > 70 ? 'var(--warn)' : 'var(--accent)'}
          label={window.WG.formatBytes(total).split(' ')[0]}
          sublabel={window.WG.formatBytes(total).split(' ')[1]}
        />
      </div>
      <div className="kpi-foot">
        <span className="mono">{pct.toFixed(1)}% of budget</span>
        <span className="mono kpi-link">configure →</span>
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
          <Sparkline data={avgPingHistory} width={200} height={48} color="var(--accent-2)" />
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

function PeerRow({ peer, spark, onClick }) {
  const statusColor = peer.status === 'connected' ? 'var(--success)' : 'var(--muted)';
  const isOnline = peer.status === 'connected';

  return (
    <div className={`peers-row data-row ${!isOnline ? 'row-offline' : ''}`} onClick={onClick}>
      <div>
        <span className={`status-pill status-${peer.status}`}>
          <span className="status-dot" style={{ background: statusColor }} />
          {peer.status}
        </span>
      </div>
      <div className="peer-name-cell">
        <div className="peer-avatar-sm">
          {peer.name.split('-').map(s => s[0]).join('').slice(0, 2).toUpperCase()}
        </div>
        <div>
          <div className="peer-name">{peer.name}</div>
          <div className="peer-device">{peer.device}</div>
        </div>
      </div>
      <div className="mono">{peer.addr}</div>
      <div>
        {isOnline
          ? <Sparkline data={spark} width={110} height={30} color="var(--accent)" active={true} />
          : <OfflinePlaceholder width={110} height={30} />
        }
      </div>
      <div className="mono num">{window.WG.formatBytes(peer.bytesIn)}</div>
      <div className="mono num">{window.WG.formatBytes(peer.bytesOut)}</div>
      <div className="mono handshake-cell">
        <div>{window.WG.formatRelTime(peer.lastHs)}</div>
        <div className="handshake-abs">{peer.lastHs ? window.WG.formatAbsTime(peer.lastHs) : ''}</div>
      </div>
      <div className="row-action">
        <button className="icon-btn-sm" onClick={(e) => { e.stopPropagation(); onClick(); }}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/></svg>
        </button>
      </div>
    </div>
  );
}

// ============================================================
// Add Peer Modal
// ============================================================
function AddPeerModal({ onClose, onSuccess }) {
  const [name, setName] = uS('');
  const [ip, setIp] = uS('');
  const [error, setError] = uS('');
  const [loading, setLoading] = uS(false);

  uE(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const submit = async (e) => {
    e.preventDefault();
    setError('');
    const trimName = name.trim();
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(trimName)) {
      setError('Invalid name (A-Z, a-z, 0-9, .-_ max 64 chars)');
      return;
    }
    const trimIp = ip.trim();
    if (trimIp && !/^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(trimIp)) {
      setError('Invalid IP (use 10.8.0.x or 10.8.0.x/32)');
      return;
    }
    setLoading(true);
    try {
      const r = await window.WG.apiCall('/api/users', {
        method: 'POST',
        body: JSON.stringify({ name: trimName, cn: trimName, ip: trimIp }),
      });
      if (r && r.profile) {
        const blob = new Blob([r.profile], { type: 'text/plain' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = trimName + '.conf';
        document.body.appendChild(a);
        a.click();
        a.remove();
      }
      onSuccess();
    } catch (e) {
      setError(e.message || 'Failed to create peer');
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <div className="drawer-scrim" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label="Add peer" style={{ maxWidth: 420 }}>
        <header className="drawer-head">
          <div className="drawer-head-left">
            <div className="peer-avatar" style={{ background: 'var(--accent-soft)' }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="8" r="4"/><path d="M4 21v-2a6 6 0 016-6h4a6 6 0 016 6v2M18 10v6M15 13h6"/></svg>
            </div>
            <div>
              <h2 className="drawer-title">Add peer</h2>
              <div className="drawer-sub">Generate keys and download config</div>
            </div>
          </div>
          <button className="icon-btn" onClick={onClose} aria-label="Close">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M6 6l12 12M18 6L6 18"/></svg>
          </button>
        </header>
        <form className="drawer-body" onSubmit={submit} style={{ gap: 16 }}>
          <section className="drawer-section">
            <div className="settings-list">
              <div className="setting-row" style={{ flexDirection: 'column', alignItems: 'flex-start', gap: 8 }}>
                <div className="setting-title">Peer name</div>
                <input
                  style={{ width: '100%', background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 7, color: 'var(--ink)', padding: '8px 10px', fontFamily: 'var(--mono)', fontSize: 12, outline: 'none' }}
                  placeholder="e.g. Laptop, Phone-iOS"
                  value={name}
                  onChange={e => setName(e.target.value)}
                  required
                />
              </div>
              <div className="setting-row" style={{ flexDirection: 'column', alignItems: 'flex-start', gap: 8 }}>
                <div className="setting-title">Static IP <span style={{ fontWeight: 400, color: 'var(--muted)' }}>(optional)</span></div>
                <input
                  style={{ width: '100%', background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 7, color: 'var(--ink)', padding: '8px 10px', fontFamily: 'var(--mono)', fontSize: 12, outline: 'none' }}
                  placeholder="10.8.0.x or leave blank for auto"
                  value={ip}
                  onChange={e => setIp(e.target.value)}
                />
              </div>
            </div>
            {error && <div style={{ color: 'var(--danger)', fontFamily: 'var(--mono)', fontSize: 11, marginTop: 8 }}>{error}</div>}
          </section>
          <section className="drawer-section">
            <div className="action-row">
              <button type="button" className="btn" onClick={onClose}>Cancel</button>
              <button type="submit" className="btn btn-primary" disabled={loading}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="8" r="4"/><path d="M4 21v-2a6 6 0 016-6h4a6 6 0 016 6v2M18 10v6M15 13h6"/></svg>
                {loading ? 'Creating…' : 'Create peer'}
              </button>
            </div>
          </section>
        </form>
      </aside>
    </>
  );
}

// ============================================================
// Tweaks panel
// ============================================================
function TweaksPanel({ tweaks, setTweaks }) {
  const update = (k, v) => {
    const next = { ...tweaks, [k]: v };
    setTweaks(next);
  };
  return (
    <div className="tweaks-panel">
      <div className="tweaks-head">
        <span>Tweaks</span>
        <button className="icon-btn-sm" onClick={() => setTweaks({ ...tweaks, _tweaksOpen: false })}>
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M6 6l12 12M18 6L6 18"/></svg>
        </button>
      </div>
      <div className="tweaks-body">
        <div className="tweak-row">
          <label>Theme</label>
          <div className="seg">
            {['light', 'dark'].map(v => (
              <button key={v} className={tweaks.theme === v ? 'on' : ''} onClick={() => update('theme', v)}>{v}</button>
            ))}
          </div>
        </div>
        <div className="tweak-row">
          <label>Density</label>
          <div className="seg">
            {['compact', 'dense', 'spacious'].map(v => (
              <button key={v} className={tweaks.density === v ? 'on' : ''} onClick={() => update('density', v)}>{v}</button>
            ))}
          </div>
        </div>
        <div className="tweak-row">
          <label>Accent</label>
          <div className="swatches">
            {[
              { id: 'terracotta', c: 'oklch(62% 0.13 45)' },
              { id: 'forest', c: 'oklch(55% 0.11 150)' },
              { id: 'ink', c: 'oklch(40% 0.04 250)' },
              { id: 'plum', c: 'oklch(48% 0.12 330)' },
              { id: 'amber', c: 'oklch(70% 0.15 75)' },
            ].map(s => (
              <button key={s.id} className={`swatch ${tweaks.accent === s.id ? 'on' : ''}`} style={{ background: s.c }} onClick={() => update('accent', s.id)} />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

Object.assign(window, { App, PeerRow, TweaksPanel, KPIServiceControl, KPIThroughput, KPIDataToday, KPIActiveSessions, AddPeerModal });

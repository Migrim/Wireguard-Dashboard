// Peer detail drawer + logs panel + port check + data budget

const { useState: _useState, useEffect: _useEffect, useRef: _useRef, useMemo: _useMemo } = React;

// ============================================================
// PeerDrawer — slide-out detail with charts + controls
// ============================================================
function PeerDrawer({ peer, onClose, sparklines, throughputBuffers, onRevoke }) {
  const [copied, setCopied] = _useState('');
  const [downloading, setDownloading] = _useState(false);
  const [revoking, setRevoking] = _useState(false);
  const [diag, setDiag] = _useState({ loading: true, pingMs: null, pingStatus: '', location: null, endpointIp: '', pingIp: '' });

  _useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  _useEffect(() => {
    if (!peer) return;
    let cancelled = false;
    const fetchDiag = async () => {
      try {
        const r = await window.WG.apiCall('/api/users/' + encodeURIComponent(peer.name) + '/diag');
        if (cancelled) return;
        setDiag({
          loading: false,
          pingMs: r.ping_ms,
          pingStatus: r.ping_status || '',
          location: r.location || null,
          endpointIp: r.endpoint_ip || '',
          pingIp: r.ping_ip || '',
        });
      } catch (_) {
        if (!cancelled) setDiag(d => ({ ...d, loading: false, pingMs: null, pingStatus: 'error' }));
      }
    };
    setDiag({ loading: true, pingMs: null, pingStatus: '', location: null, endpointIp: '', pingIp: '' });
    fetchDiag();
    const id = setInterval(fetchDiag, 5000);
    return () => { cancelled = true; clearInterval(id); };
  }, [peer && peer.name]);

  if (!peer) return null;

  const spark = sparklines[peer.id] || [];
  const thr = throughputBuffers[peer.id] || { rx: [], tx: [] };
  const pingLabel = diag.loading ? 'checking' : (diag.pingMs != null ? `${diag.pingMs} ms` : (diag.pingStatus || 'timeout'));
  const locationLabel = (diag.location && diag.location.label) || peer.country || '—';

  const copy = (val, key) => {
    navigator.clipboard?.writeText(val);
    setCopied(key);
    setTimeout(() => setCopied(''), 1500);
  };

  const downloadConfig = async () => {
    setDownloading(true);
    try {
      const r = await window.WG.apiCall('/api/users/' + encodeURIComponent(peer.name) + '/ovpn');
      if (r && r.profile) {
        const blob = new Blob([r.profile], { type: 'text/plain' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = peer.name + '.conf';
        document.body.appendChild(a);
        a.click();
        a.remove();
      }
    } catch (e) {
      alert('Failed to download config: ' + (e.message || 'API error'));
    } finally {
      setDownloading(false);
    }
  };

  const revokePeer = async () => {
    if (!confirm(`Revoke peer "${peer.name}"? This will disconnect them immediately.`)) return;
    setRevoking(true);
    try {
      await window.WG.apiCall('/api/users/' + encodeURIComponent(peer.name) + '/revoke', { method: 'POST' });
      onClose();
      if (onRevoke) onRevoke();
    } catch (e) {
      alert('Failed to revoke peer: ' + (e.message || 'API error'));
    } finally {
      setRevoking(false);
    }
  };

  const statusColor = {
    connected: 'var(--success)',
    offline: 'var(--muted)',
    warning: 'var(--warn)',
  }[peer.status] || 'var(--muted)';

  return (
    <>
      <div className="drawer-scrim" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label={`Peer ${peer.name}`}>
        <header className="drawer-head">
          <div className="drawer-head-left">
            <div className="peer-avatar" style={{ background: peer.status === 'connected' ? 'var(--accent-soft)' : 'var(--border)' }}>
              {peer.name.split('-').map(s => s[0]).join('').slice(0, 2).toUpperCase()}
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <h2 className="drawer-title">{peer.name}</h2>
                <span className={`status-pill status-${peer.status}`}>
                  <span className="status-dot" style={{ background: statusColor }} />
                  {peer.status}
                </span>
              </div>
              <div className="drawer-sub">{peer.device} · {peer.addr}</div>
            </div>
          </div>
          <button className="icon-btn" onClick={onClose} aria-label="Close">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M6 6l12 12M18 6L6 18"/></svg>
          </button>
        </header>

        <div className="drawer-body">
          <section className="drawer-section">
            <div className="section-head">
              <span className="section-label">LIVE THROUGHPUT</span>
              <span className="section-meta">
                <span className="legend-dot" style={{ background: 'var(--accent)' }} /> rx&nbsp;
                <span className="legend-dot" style={{ background: 'var(--accent-2)' }} /> tx
              </span>
            </div>
            <div className="drawer-chart">
              {thr.rx.length > 0 ? (
                <ThroughputChart dataIn={thr.rx} dataOut={thr.tx} width={500} height={180} />
              ) : (
                <div className="empty-chart">No recent activity</div>
              )}
            </div>
          </section>

          <section className="drawer-section">
            <div className="stats-grid">
              <div className="stat-cell">
                <div className="stat-label">BYTES IN</div>
                <div className="stat-val">{window.WG.formatBytes(peer.bytesIn)}</div>
              </div>
              <div className="stat-cell">
                <div className="stat-label">BYTES OUT</div>
                <div className="stat-val">{window.WG.formatBytes(peer.bytesOut)}</div>
              </div>
              <div className="stat-cell">
                <div className="stat-label">PING</div>
                <div className="stat-val">{pingLabel}</div>
              </div>
              <div className="stat-cell">
                <div className="stat-label">HANDSHAKE</div>
                <div className="stat-val">{window.WG.formatRelTime(peer.lastHs)}</div>
              </div>
            </div>
          </section>

          <section className="drawer-section">
            <div className="section-head">
              <span className="section-label">CONNECTION</span>
            </div>
            <dl className="kv">
              <dt>Endpoint</dt>
              <dd className="mono">{peer.endpoint}</dd>
              <dt>Endpoint IP</dt>
              <dd className="mono">{diag.endpointIp || '—'}</dd>
              <dt>Location</dt>
              <dd>{locationLabel}</dd>
              <dt>Ping target</dt>
              <dd className="mono">{diag.pingIp || peer.allowedIps || peer.addr || '—'}</dd>
              <dt>Allowed IPs</dt>
              <dd className="mono">{peer.allowedIps || peer.addr}</dd>
              {peer.pubKey && (
                <>
                  <dt>Public key</dt>
                  <dd className="mono key-val">
                    <span className="truncate">{peer.pubKey}</span>
                    <button className="mini-btn" onClick={() => copy(peer.pubKey, 'pk')}>
                      {copied === 'pk' ? '✓' : 'copy'}
                    </button>
                  </dd>
                </>
              )}
            </dl>
          </section>

          <section className="drawer-section">
            <div className="section-head">
              <span className="section-label">ACTIONS</span>
            </div>
            <div className="action-row">
              <button className="btn btn-primary" onClick={downloadConfig} disabled={downloading}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 3v12m0 0l-4-4m4 4l4-4M4 21h16"/></svg>
                {downloading ? 'Downloading…' : 'Download config'}
              </button>
              <button className="btn btn-danger" onClick={revokePeer} disabled={revoking}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M3 6h18M8 6V4a2 2 0 012-2h4a2 2 0 012 2v2m3 0v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6"/></svg>
                {revoking ? 'Revoking…' : 'Revoke'}
              </button>
            </div>
          </section>
        </div>
      </aside>
    </>
  );
}

// ============================================================
// LogsPanel — live streaming logs with alerts callout
// ============================================================
function LogsPanel({ logs, alerts, onExpand }) {
  const scrollRef = _useRef(null);

  _useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs.length]);

  return (
    <div className="logs-card logs-card-clickable" onClick={onExpand} role="button" tabIndex={0}>
      {alerts.length > 0 && (
        <div className="alerts-block">
          {alerts.map((a, i) => (
            <div key={i} className={`alert alert-${a.level}`}>
              <span className="alert-icon">
                {a.level === 'error' ? (
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="10"/><path d="M12 8v5M12 16h.01"/></svg>
                ) : (
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0zM12 9v4M12 17h.01"/></svg>
                )}
              </span>
              <div className="alert-body">
                <div className="alert-title">{a.title}</div>
                <div className="alert-desc">{a.desc}</div>
              </div>
            </div>
          ))}
        </div>
      )}
      <div className="logs-head">
        <span className="section-label">LIVE LOGS</span>
        <div className="log-meta">
          <span className="pulse-dot" /> wg0
          <span className="log-expand-hint">expand →</span>
        </div>
      </div>
      <div className="logs-stream" ref={scrollRef}>
        {logs.map((l, i) => (
          <div key={i} className={`log-line log-${l.level}`}>
            <span className="log-time">{new Date(l.t).toTimeString().slice(0, 8)}</span>
            <span className="log-level">{l.level}</span>
            <span className="log-msg">{l.msg}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ============================================================
// DataBudgetDrawer
// ============================================================
function DataBudgetDrawer({ total, budget, setBudget, alerts, setAlerts, resetTime, setResetTime, peers, onClose }) {
  _useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const cap = budget * 1024 * 1024 * 1024;
  const pct = Math.min(100, (total / cap) * 100);
  const remaining = Math.max(0, cap - total);

  const peerBreakdown = [...peers]
    .map(p => ({ ...p, total: p.bytesIn + p.bytesOut }))
    .sort((a, b) => b.total - a.total);
  const maxPeerTotal = Math.max(...peerBreakdown.map(p => p.total), 1);

  return (
    <>
      <div className="drawer-scrim" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label="Data budget">
        <header className="drawer-head">
          <div className="drawer-head-left">
            <div className="peer-avatar" style={{ background: 'var(--accent-soft)' }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M3 3v18h18"/><path d="M7 14l4-4 4 4 5-5"/></svg>
            </div>
            <div>
              <h2 className="drawer-title">Data budget</h2>
              <div className="drawer-sub">Cumulative usage · resets at {resetTime} local</div>
            </div>
          </div>
          <button className="icon-btn" onClick={onClose} aria-label="Close">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M6 6l12 12M18 6L6 18"/></svg>
          </button>
        </header>

        <div className="drawer-body">
          <section className="drawer-section">
            <div className="budget-hero">
              <div className="budget-hero-nums">
                <div className="budget-used">
                  <div className="budget-big">{window.WG.formatBytes(total).split(' ')[0]}<span className="budget-unit">{window.WG.formatBytes(total).split(' ')[1]}</span></div>
                  <div className="budget-lbl">used</div>
                </div>
                <div className="budget-divider" />
                <div className="budget-used">
                  <div className="budget-big">{window.WG.formatBytes(remaining).split(' ')[0]}<span className="budget-unit">{window.WG.formatBytes(remaining).split(' ')[1]}</span></div>
                  <div className="budget-lbl">remaining</div>
                </div>
              </div>
              <div className="budget-bar-wrap">
                <div className="budget-bar">
                  <div className="budget-bar-fill" style={{ width: `${pct}%`, background: pct > 90 ? 'var(--danger)' : pct > 70 ? 'var(--warn)' : 'var(--accent)' }} />
                  {[70, 90].map(t => (
                    <div key={t} className="budget-marker" style={{ left: `${t}%` }} title={`${t}% threshold`} />
                  ))}
                </div>
                <div className="budget-bar-labels">
                  <span>0</span>
                  <span className="mono">{pct.toFixed(1)}%</span>
                  <span>{budget} GB</span>
                </div>
              </div>
            </div>
          </section>

          <section className="drawer-section">
            <div className="section-head">
              <span className="section-label">USAGE BY PEER</span>
            </div>
            <div className="peer-usage-list">
              {peerBreakdown.map(p => (
                <div key={p.id} className="peer-usage-row">
                  <div className="peer-usage-name">{p.name}</div>
                  <div className="peer-usage-bar">
                    <div className="peer-usage-fill" style={{ width: `${(p.total / maxPeerTotal) * 100}%`, background: p.status === 'connected' ? 'var(--accent)' : 'var(--muted)' }} />
                  </div>
                  <div className="peer-usage-val mono">{window.WG.formatBytes(p.total)}</div>
                </div>
              ))}
            </div>
          </section>

          <section className="drawer-section">
            <div className="section-head">
              <span className="section-label">SETTINGS</span>
            </div>
            <div className="settings-list">
              <div className="setting-row">
                <div>
                  <div className="setting-title">Daily budget</div>
                  <div className="setting-desc">Target data volume per day across all peers</div>
                </div>
                <div className="setting-control">
                  <div className="stepper">
                    <button onClick={() => setBudget(Math.max(1, budget - 5))}>−</button>
                    <span className="mono">{budget} GB</span>
                    <button onClick={() => setBudget(budget + 5)}>+</button>
                  </div>
                </div>
              </div>
              <div className="setting-row">
                <div>
                  <div className="setting-title">Reset time</div>
                  <div className="setting-desc">When the daily counter rolls over</div>
                </div>
                <div className="setting-control">
                  <select className="select-input" value={resetTime} onChange={e => setResetTime(e.target.value)}>
                    <option value="00:00">00:00</option>
                    <option value="04:00">04:00</option>
                    <option value="06:00">06:00</option>
                    <option value="12:00">12:00</option>
                  </select>
                </div>
              </div>
              <div className="setting-row">
                <div>
                  <div className="setting-title">Alerts at 70% / 90%</div>
                  <div className="setting-desc">Show warnings when approaching budget limit</div>
                </div>
                <div className="setting-control">
                  <button className={`toggle ${alerts ? 'on' : ''}`} onClick={() => setAlerts(!alerts)} aria-pressed={alerts}>
                    <span className="toggle-knob" />
                  </button>
                </div>
              </div>
            </div>
          </section>

          <section className="drawer-section">
            <div className="action-row">
              <button className="btn">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 3v12m0 0l-4-4m4 4l4-4M4 21h16"/></svg>
                Export CSV
              </button>
            </div>
          </section>
        </div>
      </aside>
    </>
  );
}

// ============================================================
// LogsDrawer — full log history, own polling, verbose, retention, download
// ============================================================
function LogsDrawer({ alerts, onClose, verbose, setVerbose }) {
  const [levelFilter, setLevelFilter] = _useState('all');
  const [search, setSearch] = _useState('');
  const [autoScroll, setAutoScroll] = _useState(true);
  const [retention, setRetention] = _useState('7d');
  const [retentionSaving, setRetentionSaving] = _useState(false);
  const [retentionMsg, setRetentionMsg] = _useState('');
  const [localLogs, setLocalLogs] = _useState([]);
  const [loading, setLoading] = _useState(true);
  const streamRef = _useRef(null);
  const wasAtBottom = _useRef(true);

  // Keyboard close
  _useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  // Own fast polling — restarts when verbose changes
  _useEffect(() => {
    let cancelled = false;
    const poll = async () => {
      try {
        const n = verbose ? 1000 : 300;
        const j = await window.WG.apiCall(`/api/logs?n=${n}&verbose=${verbose ? 1 : 0}`);
        if (cancelled) return;
        if (j.lines && j.lines.length) {
          setLocalLogs(window.WG.parseLogLines(j.lines));
          setLoading(false);
        }
      } catch (_) {}
    };
    poll();
    const id = setInterval(poll, 3000);
    return () => { cancelled = true; clearInterval(id); };
  }, [verbose]);

  // Auto-scroll — only if user was already at the bottom
  _useEffect(() => {
    const el = streamRef.current;
    if (!el) return;
    if (autoScroll && wasAtBottom.current) {
      el.scrollTop = el.scrollHeight;
    }
  }, [localLogs.length, autoScroll]);

  const onScroll = () => {
    const el = streamRef.current;
    if (!el) return;
    wasAtBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
  };

  const saveRetention = async (val) => {
    setRetention(val);
    if (val === 'forever') { setRetentionMsg('Retention set to forever'); return; }
    setRetentionSaving(true);
    setRetentionMsg('');
    try {
      const r = await window.WG.apiCall('/api/logs/retention', {
        method: 'POST',
        body: JSON.stringify({ retention: val }),
      });
      setRetentionMsg(r.ok ? `Vacuumed journal (kept last ${val})` : 'Vacuum failed — check server logs');
    } catch (e) {
      setRetentionMsg('Error: ' + (e.message || 'API unreachable'));
    } finally {
      setRetentionSaving(false);
      setTimeout(() => setRetentionMsg(''), 4000);
    }
  };

  const downloadLogs = () => {
    const rows = localLogs.map(l => {
      const ts = new Date(l.t).toISOString();
      return `${ts} [${l.level.toUpperCase().padEnd(5)}] ${l.msg}`;
    }).join('\n');
    const blob = new Blob([rows], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `wg0-logs-${new Date().toISOString().slice(0, 10)}.txt`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(a.href);
  };

  const filtered = localLogs.filter(l => {
    if (levelFilter !== 'all' && l.level !== levelFilter) return false;
    if (search && !l.msg.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const counts = {
    info:  localLogs.filter(l => l.level === 'info').length,
    warn:  localLogs.filter(l => l.level === 'warn').length,
    error: localLogs.filter(l => l.level === 'error').length,
  };

  return (
    <>
      <div className="drawer-scrim" onClick={onClose} />
      <aside className="drawer drawer-wide" role="dialog" aria-label="Logs">
        <header className="drawer-head">
          <div className="drawer-head-left">
            <div className="peer-avatar" style={{ background: 'var(--accent-soft)' }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/></svg>
            </div>
            <div>
              <h2 className="drawer-title">Logs</h2>
              <div className="drawer-sub">
                <span className="pulse-dot" /> wg0 · {loading ? 'loading…' : `${filtered.length} of ${localLogs.length} lines`}
                {verbose && <span style={{ marginLeft: 6, color: 'var(--accent)', fontFamily: 'var(--mono)', fontSize: 10 }}>VERBOSE</span>}
              </div>
            </div>
          </div>
          <button className="icon-btn" onClick={onClose} aria-label="Close">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M6 6l12 12M18 6L6 18"/></svg>
          </button>
        </header>

        <div className="drawer-body">
          {alerts.length > 0 && (
            <section className="drawer-section">
              <div className="section-head"><span className="section-label">WARNINGS</span></div>
              <div className="alerts-block" style={{ padding: 0 }}>
                {alerts.map((a, i) => (
                  <div key={i} className={`alert alert-${a.level}`}>
                    <span className="alert-icon">
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0zM12 9v4M12 17h.01"/></svg>
                    </span>
                    <div className="alert-body">
                      <div className="alert-title">{a.title}</div>
                      <div className="alert-desc">{a.desc}</div>
                    </div>
                  </div>
                ))}
              </div>
            </section>
          )}

          <section className="drawer-section">
            <div className="log-stats">
              <div className="log-stat"><div className="log-stat-val" style={{ color: 'var(--accent-2)' }}>{counts.info}</div><div className="log-stat-lbl">info</div></div>
              <div className="log-stat"><div className="log-stat-val" style={{ color: 'var(--warn)' }}>{counts.warn}</div><div className="log-stat-lbl">warn</div></div>
              <div className="log-stat"><div className="log-stat-val" style={{ color: 'var(--danger)' }}>{counts.error}</div><div className="log-stat-lbl">error</div></div>
              <div className="log-stat"><div className="log-stat-val">{localLogs.length}</div><div className="log-stat-lbl">total</div></div>
            </div>
          </section>

          <section className="drawer-section">
            <div className="log-toolbar">
              <div className="search" style={{ flex: 1, height: 32 }}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>
                <input type="text" placeholder="Search logs…" value={search} onChange={e => setSearch(e.target.value)} />
              </div>
              <div className="peers-filters">
                {['all', 'info', 'warn', 'error'].map(s => (
                  <button key={s} className={`filter-pill ${levelFilter === s ? 'active' : ''}`} onClick={() => setLevelFilter(s)}>{s}</button>
                ))}
              </div>
            </div>
          </section>

          <section className="drawer-section">
            <div className="logs-stream logs-stream-tall" ref={streamRef} onScroll={onScroll}>
              {loading ? (
                <div style={{ padding: 40, textAlign: 'center', color: 'var(--muted)', fontFamily: 'var(--mono)', fontSize: 11 }}>Loading…</div>
              ) : filtered.length === 0 ? (
                <div style={{ padding: 40, textAlign: 'center', color: 'var(--muted)', fontFamily: 'var(--mono)', fontSize: 11 }}>No matching logs</div>
              ) : filtered.map((l, i) => (
                <div key={i} className={`log-line log-${l.level}`}>
                  <span className="log-time">{new Date(l.t).toTimeString().slice(0, 8)}</span>
                  <span className="log-level">{l.level}</span>
                  <span className="log-msg">{l.msg}</span>
                </div>
              ))}
            </div>
          </section>

          <section className="drawer-section">
            <div className="section-head"><span className="section-label">SETTINGS</span></div>
            <div className="settings-list">
              <div className="setting-row">
                <div>
                  <div className="setting-title">Auto-scroll</div>
                  <div className="setting-desc">Follow new log lines as they arrive</div>
                </div>
                <div className="setting-control">
                  <button className={`toggle ${autoScroll ? 'on' : ''}`} onClick={() => setAutoScroll(v => !v)}>
                    <span className="toggle-knob" />
                  </button>
                </div>
              </div>
              <div className="setting-row">
                <div>
                  <div className="setting-title">Verbose logging</div>
                  <div className="setting-desc">Fetch 1000 lines with microsecond timestamps (journalctl short-precise)</div>
                </div>
                <div className="setting-control">
                  <button className={`toggle ${verbose ? 'on' : ''}`} onClick={() => setVerbose(v => !v)}>
                    <span className="toggle-knob" />
                  </button>
                </div>
              </div>
              <div className="setting-row">
                <div>
                  <div className="setting-title">Retention</div>
                  <div className="setting-desc">
                    Vacuum journal on disk — removes entries older than selected period
                    {retentionMsg && <span style={{ display: 'block', marginTop: 3, color: retentionMsg.startsWith('Error') ? 'var(--danger)' : 'var(--accent-2)', fontFamily: 'var(--mono)', fontSize: 10 }}>{retentionMsg}</span>}
                  </div>
                </div>
                <div className="setting-control">
                  <select className="select-input" value={retention} disabled={retentionSaving} onChange={e => saveRetention(e.target.value)}>
                    <option value="1d">1 day</option>
                    <option value="7d">7 days</option>
                    <option value="30d">30 days</option>
                    <option value="forever">Forever</option>
                  </select>
                </div>
              </div>
            </div>
          </section>

          <section className="drawer-section">
            <div className="action-row">
              <button className="btn btn-primary" onClick={downloadLogs} disabled={localLogs.length === 0}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 3v12m0 0l-4-4m4 4l4-4M4 21h16"/></svg>
                Download logs ({localLogs.length} lines)
              </button>
            </div>
          </section>
        </div>
      </aside>
    </>
  );
}

// ============================================================
// PortCheckDrawer — animated diagnostic using real API
// ============================================================
function PortCheckDrawer({ peers, onClose }) {
  const steps = [
    { id: 'iface',     label: 'Interface wg0 present',       detail: 'Check link state and systemd unit' },
    { id: 'listen',    label: 'Listening on UDP 51820',       detail: 'Verify port is bound' },
    { id: 'fw-in',     label: 'Firewall accepts inbound',     detail: 'UFW / iptables INPUT rule' },
    { id: 'fw-fwd',    label: 'Forwarding enabled',           detail: 'net.ipv4.ip_forward = 1' },
    { id: 'nat',       label: 'NAT / MASQUERADE rule',        detail: 'PostUp POSTROUTING rule present' },
    { id: 'dns',       label: 'External connectivity',        detail: 'Ping 1.1.1.1 from server' },
    { id: 'handshake', label: 'Peer handshakes verified',     detail: `${peers.filter(p => p.status === 'connected').length} online · ${peers.filter(p => p.status === 'offline').length} offline` },
  ];

  const [current, setCurrent] = _useState(-1);
  const [results, setResults] = _useState({});
  const [done, setDone] = _useState(false);
  const [running, setRunning] = _useState(false);
  const [apiError, setApiError] = _useState(null);

  _useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const run = async () => {
    setRunning(true);
    setDone(false);
    setResults({});
    setCurrent(0);
    setApiError(null);

    try {
      // Fetch all diagnostic data in parallel
      const [status, diag, health] = await Promise.all([
        window.WG.apiCall('/api/status').catch(() => null),
        window.WG.apiCall('/api/diag/vpn').catch(() => null),
        window.WG.apiCall('/api/health').catch(() => null),
      ]);

      const port = (status && status.network && status.network.port) || 51820;
      const portStatus = await window.WG.apiCall('/api/ports?proto=udp&port=' + port).catch(() => null);

      const connectedPeers = peers.filter(p => p.status === 'connected').length;

      const stepResults = {
        'iface':     (status && status.service && status.service.active) ? 'ok' : 'fail',
        'listen':    (portStatus && portStatus.listening) ? 'ok' : 'fail',
        'fw-in':     (portStatus && portStatus.ufw_allowed) ? 'ok' : 'warn',
        'fw-fwd':    (diag && diag.ip_forward) ? 'ok' : 'fail',
        'nat':       (diag && diag.has_postup) ? 'ok' : 'warn',
        'dns':       (health && health.ping_ok) ? 'ok' : 'warn',
        'handshake': connectedPeers > 0 ? 'ok' : (peers.length > 0 ? 'warn' : 'ok'),
      };

      // Reveal one by one with animation
      for (let i = 0; i < steps.length; i++) {
        setCurrent(i);
        await new Promise(r => setTimeout(r, 350 + Math.random() * 300));
        setResults(prev => ({ ...prev, [steps[i].id]: stepResults[steps[i].id] }));
      }
    } catch (e) {
      setApiError(e.message || 'API unreachable');
      steps.forEach(s => setResults(prev => ({ ...prev, [s.id]: 'fail' })));
    }

    setRunning(false);
    setDone(true);
    setCurrent(-1);
  };

  _useEffect(() => { run(); }, []);

  const passed = Object.values(results).filter(v => v === 'ok').length;
  const warned = Object.values(results).filter(v => v === 'warn').length;
  const failed = Object.values(results).filter(v => v === 'fail').length;
  const progress = current === -1 && done ? 1 : current === -1 ? 0 : (current + 0.5) / steps.length;

  return (
    <>
      <div className="drawer-scrim" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label="Port check">
        <header className="drawer-head">
          <div className="drawer-head-left">
            <div className="peer-avatar" style={{ background: 'var(--accent-soft)' }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 3v18M3 12h18"/><circle cx="12" cy="12" r="9"/></svg>
            </div>
            <div>
              <h2 className="drawer-title">Port check</h2>
              <div className="drawer-sub">
                {running ? 'Running diagnostics…' : done ? `Completed · ${passed} passed, ${warned} warnings, ${failed} failed` : 'Idle'}
              </div>
            </div>
          </div>
          <button className="icon-btn" onClick={onClose} aria-label="Close">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M6 6l12 12M18 6L6 18"/></svg>
          </button>
        </header>

        <div className="drawer-body">
          <section className="drawer-section">
            <div className="pc-hero">
              <div className="pc-hero-head">
                <span className="section-label">DIAGNOSTIC</span>
                <span className="mono" style={{ color: 'var(--muted)' }}>
                  {done ? `${steps.length}/${steps.length}` : current === -1 ? `0/${steps.length}` : `${current}/${steps.length}`}
                </span>
              </div>
              <div className="pc-progress">
                <div className="pc-progress-fill" style={{ width: `${progress * 100}%` }} />
                {running && <div className="pc-progress-glow" style={{ left: `${progress * 100}%` }} />}
              </div>
              <div className="pc-summary">
                <span className="pc-stat pc-ok"><span className="pc-dot" /> {passed} passed</span>
                <span className="pc-stat pc-warn"><span className="pc-dot" /> {warned} warnings</span>
                <span className="pc-stat pc-fail"><span className="pc-dot" /> {failed} failed</span>
              </div>
            </div>
          </section>

          <section className="drawer-section">
            <div className="pc-steps">
              <div className="pc-line" />
              <div className="pc-line-fill" style={{ height: `${progress * 100}%` }} />
              {steps.map((s, i) => {
                const result = results[s.id];
                const isActive = current === i;
                const isDone = result !== undefined;
                return (
                  <div key={s.id} className={`pc-step ${isActive ? 'active' : ''} ${isDone ? 'done' : ''} ${result ? `result-${result}` : ''}`}>
                    <div className="pc-marker">
                      {isDone ? (
                        result === 'ok' ? (
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><path d="M5 12l5 5L20 7"/></svg>
                        ) : result === 'warn' ? (
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z"/><path d="M12 9v4M12 17h.01"/></svg>
                        ) : (
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><path d="M6 6l12 12M18 6L6 18"/></svg>
                        )
                      ) : isActive ? (
                        <span className="pc-spinner" />
                      ) : (
                        <span className="pc-idle-dot" />
                      )}
                    </div>
                    <div className="pc-step-body">
                      <div className="pc-step-title">{s.label}</div>
                      <div className="pc-step-detail">
                        {s.detail}
                        {isActive && <span className="pc-typing">...</span>}
                      </div>
                      {isDone && (
                        <div className={`pc-badge pc-badge-${result}`}>
                          {result === 'ok' ? 'OK' : result === 'warn' ? 'WARNING' : 'FAILED'}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </section>

          {done && (() => {
            if (apiError) {
              return (
                <section className="drawer-section">
                  <div className="pc-tip">
                    <div className="pc-tip-icon">
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><path d="M12 8v5M12 16h.01"/></svg>
                    </div>
                    <div className="pc-tip-body">
                      <div className="pc-tip-title">API unreachable</div>
                      <div className="pc-tip-desc">{apiError}</div>
                    </div>
                  </div>
                </section>
              );
            }
            const firstIssue = steps.find(s => results[s.id] === 'warn' || results[s.id] === 'fail');
            if (!firstIssue) {
              return (
                <section className="drawer-section">
                  <div className="pc-tip pc-tip-ok">
                    <div className="pc-tip-icon">
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M5 12l5 5L20 7"/></svg>
                    </div>
                    <div className="pc-tip-body">
                      <div className="pc-tip-title">All checks passed</div>
                      <div className="pc-tip-desc">Your tunnel is configured correctly and reachable from the internet. No action required.</div>
                    </div>
                  </div>
                </section>
              );
            }
            const tips = {
              iface:     { title: 'Interface wg0 missing or down',     desc: 'The WireGuard service is not active. Start it and verify the config file.', cmd: 'sudo systemctl start wg-quick@wg0\nsudo wg show wg0' },
              listen:    { title: 'Port 51820 is not bound',            desc: 'Nothing is listening on the WireGuard UDP port. Check ListenPort in the config, then restart.', cmd: 'sudo ss -ulnp | grep 51820\nsudo systemctl restart wg-quick@wg0' },
              'fw-in':   { title: 'Inbound UDP not in UFW rules',       desc: 'Add an accept rule for UDP 51820 on your WAN interface.', cmd: 'sudo ufw allow 51820/udp\nsudo ufw reload' },
              'fw-fwd':  { title: 'IP forwarding disabled',             desc: 'Packets from peers cannot be routed. Enable forwarding in the kernel.', cmd: 'sudo sysctl -w net.ipv4.ip_forward=1\necho "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-wg.conf' },
              nat:       { title: 'NAT / PostUp rule missing',          desc: 'Outbound traffic from peers is not being masqueraded. Use the "Fix Issues" button or add the rule manually.', cmd: 'sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE' },
              dns:       { title: 'No internet connectivity from server', desc: 'The server cannot reach 1.1.1.1. Check your routing table and default gateway.', cmd: 'ping -c3 1.1.1.1\nip route show' },
              handshake: { title: 'No peers have connected recently',   desc: 'Verify peer configs are correct, PersistentKeepalive is set, and their endpoint points to this server.', cmd: 'sudo wg show wg0 latest-handshakes' },
            };
            const tip = tips[firstIssue.id];
            return (
              <section className="drawer-section">
                <div className="section-head"><span className="section-label">HOW TO RESOLVE</span></div>
                <div className="pc-tip">
                  <div className="pc-tip-icon">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 2a7 7 0 00-4 12.7V17a2 2 0 002 2h4a2 2 0 002-2v-2.3A7 7 0 0012 2zM9 22h6"/></svg>
                  </div>
                  <div className="pc-tip-body">
                    <div className="pc-tip-title">{tip.title}</div>
                    <div className="pc-tip-desc">{tip.desc}</div>
                    <div className="pc-tip-cmd">
                      <button className="cmd-copy" onClick={() => navigator.clipboard?.writeText(tip.cmd)}>COPY</button>
                      {tip.cmd.split('\n').map((line, i) => (
                        <div key={i}>
                          <span className="cmd-prompt">{line.startsWith('#') ? '' : '$ '}</span>{line}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </section>
            );
          })()}

          <section className="drawer-section">
            <div className="action-row">
              <button className="btn btn-primary" onClick={run} disabled={running}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M21 12a9 9 0 11-9-9c2.5 0 4.7 1 6.4 2.6L21 3v6h-6"/></svg>
                {running ? 'Running…' : 'Re-run check'}
              </button>
            </div>
          </section>
        </div>
      </aside>
    </>
  );
}

Object.assign(window, { PeerDrawer, LogsPanel, DataBudgetDrawer, LogsDrawer, PortCheckDrawer });

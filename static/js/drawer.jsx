// Peer detail drawer + logs panel + port check + data budget

const { useState: _useState, useEffect: _useEffect, useRef: _useRef, useMemo: _useMemo } = React;

// ============================================================
// PingBars — thin bar chart with Y-axis, newest bar on the left
// ============================================================
function PingBars({ data, height = 68, color = 'var(--accent-2)' }) {
  const containerRef = _useRef(null);
  const [cw, setCw] = _useState(500);

  _useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    setCw(Math.round(el.getBoundingClientRect().width) || 500);
    const ro = new ResizeObserver(entries => {
      const w = entries[0]?.contentRect.width;
      if (w > 0) setCw(Math.round(w));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const PL = 40, PR = 8, PT = 8, PB = 14;
  const iw = cw - PL - PR;
  const ih = height - PT - PB;
  const n = data.length;

  const maxRaw = Math.max(...data, 10);
  const mag = Math.pow(10, Math.floor(Math.log10(maxRaw)));
  const norm = maxRaw / mag;
  const niceMax = norm <= 1 ? mag : norm <= 2 ? 2 * mag : norm <= 5 ? 5 * mag : 10 * mag;

  const ticks = [0, Math.round(niceMax / 2), niceMax];
  const yAt = v => PT + ih - (v / niceMax) * ih;
  const gap = 2;
  const barW = Math.max(2, (iw - gap * (n - 1)) / n);
  const fmt = v => v === 0 ? '0' : v >= 1000 ? `${(v / 1000).toFixed(v % 1000 === 0 ? 0 : 1)}s` : `${v}ms`;

  return (
    <div ref={containerRef} style={{ width: '100%' }}>
      <svg viewBox={`0 0 ${cw} ${height}`} preserveAspectRatio="none" style={{ width: '100%', height, display: 'block' }}>
        {ticks.map((t, i) => {
          const y = yAt(t);
          return (
            <g key={i}>
              <line x1={PL} x2={cw - PR} y1={y} y2={y} stroke="var(--border)" strokeWidth="1"
                strokeDasharray={t === 0 ? '' : '2 3'} opacity="0.6" />
              <text x={PL - 5} y={y + 3.5} textAnchor="end" fontSize="9" fill="var(--muted)" fontFamily="var(--mono)">{fmt(t)}</text>
            </g>
          );
        })}
        {data.map((v, i) => {
          const x = PL + i * (barW + gap);
          const bh = (v / niceMax) * ih;
          return <rect key={i} x={x} y={yAt(v)} width={barW} height={bh}
            fill={color} opacity={0.2 + 0.8 * (i / Math.max(n - 1, 1))} rx="1" />;
        })}
      </svg>
    </div>
  );
}

// ============================================================
// PeerDrawer — slide-out detail with charts + controls
// ============================================================
function PeerDrawer({ peer, onClose, throughputBuffers, peerPingHistory = {}, onRevoke, onPeerUpdated, tweaks = {} }) {
  const [copied, setCopied] = _useState('');
  const [downloading, setDownloading] = _useState(false);
  const [revoking, setRevoking] = _useState(false);
  const [pendingAction, setPendingAction] = _useState(null); // 'pause' | 'resume' | null
  const [tab, setTab] = _useState('overview');
  const [settingsDirty, setSettingsDirty] = _useState(() => {
    try { return !!localStorage.getItem('WG_PEER_DRAFT_' + peer?.name); } catch { return false; }
  });
  const [diag, setDiag] = _useState({ loading: true, pingMs: null, pingStatus: '', location: null, endpointIp: '', pingIp: '' });
  const pingHistory = peerPingHistory[peer?.name] || new Array(24).fill(0);
  const latestPing = pingHistory[pingHistory.length - 1] > 0 ? pingHistory[pingHistory.length - 1] : null;

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
        const r = await window.WG.apiCall('/api/users/' + encodeURIComponent(peer.name) + '/diag', { silent: true });
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

  const thr = throughputBuffers[peer.id] || { rx: [], tx: [] };
  const thrSamples = _useMemo(() => {
    const { rx, tx } = thr;
    const n = Math.min(rx.length, tx.length);
    const now = Date.now();
    return Array.from({ length: n }, (_, i) => ({
      ts: now - (n - 1 - i) * 3000,
      rx: rx[i] || 0,
      tx: tx[i] || 0,
    }));
  }, [thr]);
  const pingLabel = diag.pingMs != null ? `${diag.pingMs} ms` : (diag.pingStatus || 'timeout');
  const locationLabel = (diag.location && diag.location.label) || peer.country || '—';

  const copy = (val, key) => {
    navigator.clipboard?.writeText(val);
    setCopied(key);
    setTimeout(() => setCopied(''), 1500);
  };

  const downloadConfig = async () => {
    setDownloading(true);
    try {
      const r = await window.WG.apiCall('/api/users/' + encodeURIComponent(peer.name) + '/ovpn', { silent: true });
      if (r && r.profile) {
        const blob = new Blob([r.profile], { type: 'text/plain' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = peer.name + '.conf';
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.WG.toast?.success?.('Config downloaded', `${peer.name}.conf`);
      }
    } catch (e) {
      window.WG.toast?.error?.('Download failed', e.message || 'API error');
    } finally {
      setDownloading(false);
    }
  };

  const revokePeer = () => {
    window.WG.toast?.confirm?.(
      'Revoke this peer?',
      `"${peer.name}" will be permanently removed and disconnected.`,
      {
        confirmLabel: 'Revoke',
        onConfirm: async () => {
          setRevoking(true);
          const t = window.WG.toast?.loading?.(`Revoking "${peer.name}"…`);
          try {
            await window.WG.apiCall('/api/users/' + encodeURIComponent(peer.name) + '/revoke', { silent: true, method: 'POST' });
            t?.success?.('Peer revoked', `"${peer.name}" has been removed`);
            onClose();
            if (onRevoke) onRevoke();
          } catch (e) {
            t?.error?.('Revoke failed', e.message || 'API error');
          } finally {
            setRevoking(false);
          }
        },
      }
    );
  };

  const togglePause = async () => {
    const wasPaused = peer.paused;
    const action = wasPaused ? 'resume' : 'pause';
    setPendingAction(action);
    const t = window.WG.toast?.loading?.(wasPaused ? `Resuming "${peer.name}"…` : `Pausing "${peer.name}"…`);
    try {
      await window.WG.apiCall('/api/users/' + encodeURIComponent(peer.name) + '/' + action, { silent: true, method: 'POST' });
      if (onPeerUpdated) onPeerUpdated();
      if (wasPaused) {
        t?.success?.('Peer resumed', `"${peer.name}" is active again`);
      } else {
        t?.update?.({ type: 'pause', title: 'Peer paused', desc: `"${peer.name}" is now blocked`, duration: 4000 });
      }
    } catch (e) {
      t?.error?.(`Failed to ${action} peer`, e.message || 'API error');
    } finally {
      setPendingAction(null);
    }
  };

  return (
    <>
      <div className="drawer-scrim" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label={`Peer ${peer.name}`}>
        <header className="drawer-head">
          <div className="drawer-head-left">
            <div className="peer-avatar" style={{ background: peer.status === 'connected' ? 'var(--avatar-bg)' : 'var(--border-strong)' }}>
              {peer.name.split('-').map(s => s[0]).join('').slice(0, 2).toUpperCase()}
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <h2 className="drawer-title">{peer.name}</h2>
                <span className={`status-pill status-${peer.status}`}>
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

        <div className="drawer-tabs">
          <button className={`drawer-tab ${tab === 'overview' ? 'on' : ''}`} onClick={() => setTab('overview')}>Overview</button>
          <button className={`drawer-tab ${tab === 'settings' ? 'on' : ''}`} onClick={() => setTab('settings')}>
            Settings
            {settingsDirty && <span className="drawer-tab-dot" title="Unsaved config changes" />}
          </button>
        </div>

        {tab === 'settings' ? (
          <div className="drawer-body">
            <window.PeerSettings peer={peer} onDirtyChange={setSettingsDirty} onPeerUpdated={onPeerUpdated} />
          </div>
        ) : (
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
              {thrSamples.some(s => s.rx > 0 || s.tx > 0) ? (
                <ThroughputChart samples={thrSamples} height={180} range="1m" spline={tweaks.splineChart} splineTension={tweaks.splineTension ?? 1} smoothScroll={tweaks.smoothThroughput} smoothScale={tweaks.smoothScale} />
              ) : (
                <div className="empty-chart">No recent activity</div>
              )}
            </div>
          </section>

          <section className="drawer-section">
            <div className="section-head">
              <span className="section-label">PING LATENCY</span>
              <span className="section-meta">{latestPing != null ? `${latestPing} ms` : '—'}</span>
            </div>
            <div className="drawer-chart">
              <PingBars data={pingHistory} height={68} color="var(--accent-2)" />
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
                <div className="stat-val">
                  {diag.loading
                    ? <span className="pc-spinner" style={{ width: 16, height: 16, display: 'block', margin: '5px auto 0' }} />
                    : <span className="ping-val-in">{pingLabel}</span>}
                </div>
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
              <span className="section-label">NOTES</span>
              <button className="mini-btn" onClick={() => setTab('settings')}>edit →</button>
            </div>
            <div className="notes-block">
              {(peer.note || peer.longNote) ? (
                <>
                  {peer.note && <div className="notes-short">{peer.note}</div>}
                  {peer.longNote && <div className="notes-long">{peer.longNote}</div>}
                </>
              ) : (
                <span className="notes-empty">No notes</span>
              )}
            </div>
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
              {(() => {
                // Use pendingAction to determine display so background status polls
                // can't flip the icon/text mid-operation.
                const showAsResuming = pendingAction === 'resume' || (!pendingAction && peer.paused);
                return (
                  <button className="btn btn-ghost" onClick={togglePause} disabled={!!pendingAction}
                    title={showAsResuming ? 'Re-enable this peer on the server' : 'Block this peer server-side without revoking it'}>
                    {showAsResuming ? (
                      <>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M5 3l14 9-14 9V3z"/></svg>
                        {pendingAction === 'resume' ? 'Resuming…' : 'Resume'}
                      </>
                    ) : (
                      <>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><rect x="6" y="4" width="4" height="16" rx="1"/><rect x="14" y="4" width="4" height="16" rx="1"/></svg>
                        {pendingAction === 'pause' ? 'Pausing…' : 'Pause'}
                      </>
                    )}
                  </button>
                );
              })()}
              <button className="btn btn-danger" onClick={revokePeer} disabled={revoking}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M3 6h18M8 6V4a2 2 0 012-2h4a2 2 0 012 2v2m3 0v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6"/></svg>
                {revoking ? 'Revoking…' : 'Revoke'}
              </button>
            </div>
            {peer.paused && (
              <div style={{ marginTop: 8, padding: '6px 10px', borderRadius: 6, background: 'color-mix(in oklch, var(--warn) 12%, transparent)', color: 'var(--warn)', fontFamily: 'var(--mono)', fontSize: 11 }}>
                Peer is paused — traffic is blocked server-side. The device tunnel may still show as connected.
              </div>
            )}
          </section>
        </div>
        )}
      </aside>
    </>
  );
}

// ============================================================
// LogsPanel — live streaming logs with alerts callout
// ============================================================
function NotifIcon({ level }) {
  if (level === 'error') return <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="10"/><path d="M12 8v5M12 16h.01"/></svg>;
  if (level === 'warn') return <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0zM12 9v4M12 17h.01"/></svg>;
  if (level === 'success') return <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="10"/><path d="M8 12l2.5 2.5L16 9"/></svg>;
  if (level === 'update') return <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 2v11m0 0l-4-4m4 4l4-4M4 18h16"/></svg>;
  return <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="10"/><path d="M12 11v5M12 8h.01"/></svg>;
}

function LogsPanel({ logs, notifications = [], onExpand, onDismiss = () => {}, serviceActive = false, ifaceName = 'wg0' }) {
  const scrollRef = _useRef(null);
  const [idx, setIdx] = _useState(0);
  const [leaving, setLeaving] = _useState(false);
  const [notifsCollapsed, setNotifsCollapsed] = _useState(
    () => localStorage.getItem('WG_NOTIFS_COLLAPSED') === 'true'
  );

  _useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [logs.length]);

  const visible = notifications;
  const safeIdx = visible.length ? idx % visible.length : 0;
  const current = visible[safeIdx];

  _useEffect(() => {
    if (visible.length <= 1) return;
    let swapT;
    const id = setInterval(() => {
      setLeaving(true);
      swapT = setTimeout(() => {
        setIdx(i => (i + 1) % visible.length);
        setLeaving(false);
      }, 550);
    }, 7000);
    return () => { clearInterval(id); clearTimeout(swapT); };
  }, [visible.length]);

  const toggleNotifs = (e) => {
    e.stopPropagation();
    const next = !notifsCollapsed;
    setNotifsCollapsed(next);
    localStorage.setItem('WG_NOTIFS_COLLAPSED', String(next));
  };

  return (
    <div className="logs-card logs-card-clickable" onClick={onExpand} role="button" tabIndex={0}>
      <div className="logs-split">
        <div className="notif-panel" onClick={e => e.stopPropagation()}>
          <div className="notif-head" onClick={toggleNotifs} role="button" tabIndex={0} title={notifsCollapsed ? 'Show notifications' : 'Hide notifications'}>
            <span className="section-label">NOTIFICATIONS</span>
            <div className="notif-head-end">
              {visible.length > 0 && <span className="notif-count">{visible.length}</span>}
              {(() => {
                const lvl = visible.some(n => n.level === 'error') ? 'error'
                  : visible.some(n => n.level === 'warn') ? 'warn'
                  : visible.length > 0 ? 'info' : null;
                return lvl && <span className={`notif-indicator notif-indicator-${lvl}`} />;
              })()}
              <svg className={`notif-arrow${notifsCollapsed ? ' is-collapsed' : ''}`} width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                <path d="M18 15l-6-6-6 6"/>
              </svg>
            </div>
          </div>
          <div className={`notif-col${notifsCollapsed ? ' is-collapsed' : ''}`}>
            <div className="notif-col-inner">
              <div className="notif-body">
                {current ? (
                  <div className={`notif-item notif-${current.level}${leaving ? ' is-leaving' : ''}`}>
                    <span className="notif-icon"><NotifIcon level={current.level} /></span>
                    <div className="notif-text">
                      <div className="notif-title">{current.title}</div>
                      <div className="notif-desc">{current.desc}</div>
                    </div>
                    <button
                      className="notif-dismiss"
                      aria-label="Dismiss notification"
                      onClick={e => { e.stopPropagation(); onDismiss(current.key); }}
                    >
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M18 6L6 18M6 6l12 12"/></svg>
                    </button>
                  </div>
                ) : (
                  <div className="notif-empty">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" opacity="0.5"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/><line x1="1" y1="1" x2="23" y2="23" stroke="currentColor" strokeWidth="1.5"/></svg>
                    No notifications
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        <div className="logs-col">
          <div className="logs-head">
            <span className="section-label">LIVE LOGS</span>
            <div className="log-meta">
              <span className={serviceActive ? 'pulse-dot' : 'pulse-dot pulse-dot-off'} /> {ifaceName}
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
      </div>
    </div>
  );
}

// ============================================================
// DataBudgetDrawer
// ============================================================
function DataBudgetDrawer({ total, budget, alerts, resetTime, peers, peerBudgets = {}, setPeerBudget, enforcement = { action: 'none', throttle_mbps: 5 }, budgetUsage, updateBudgetSettings, onClose }) {
  const [saving, setSaving] = _useState(false);
  const [msg, setMsg] = _useState('');

  _useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const cap = budget * 1024 * 1024 * 1024;
  const pct = Math.min(100, (total / cap) * 100);
  const remaining = Math.max(0, cap - total);

  const peerByName = new Map(peers.map(p => [p.name, p]));
  const peerBreakdown = (budgetUsage?.peers || []).map(row => {
    const p = peerByName.get(row.name) || {};
    return { ...p, id: row.name, name: row.name, total: row.bytes || 0 };
  });
  const maxPeerTotal = Math.max(...peerBreakdown.map(p => p.total), 1);

  const saveSettings = async (patch) => {
    setSaving(true);
    setMsg('');
    try {
      const r = await updateBudgetSettings(patch);
      setMsg('Saved');
      setTimeout(() => setMsg(''), 2000);
      return r;
    } catch (e) {
      setMsg('Error: ' + (e.message || 'save failed'));
    } finally {
      setSaving(false);
    }
  };

  const exportCsv = async () => {
    setSaving(true);
    setMsg('');
    try {
      const r = await window.WG.apiCall('/api/data-budget/export', { silent: true, method: 'POST', body: JSON.stringify({}) });
      const blob = new Blob([r.csv || ''], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = r.filename || 'data-budget.csv';
      a.style.display = 'none';
      document.body.appendChild(a);
      a.click();
      setTimeout(() => {
        a.remove();
        URL.revokeObjectURL(url);
      }, 0);
      setMsg('Exported CSV');
      setTimeout(() => setMsg(''), 2000);
    } catch (e) {
      setMsg('Error: ' + (e.message || 'export failed'));
    } finally {
      setSaving(false);
    }
  };

  return (
    <>
      <div className="drawer-scrim" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label="Data budget">
        <header className="drawer-head">
          <div className="drawer-head-left">
            <div className="peer-avatar" style={{ background: 'var(--avatar-bg)' }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M3 3v18h18"/><path d="M7 14l4-4 4 4 5-5"/></svg>
            </div>
            <div>
              <h2 className="drawer-title">Data budget</h2>
              <div className="drawer-sub">Usage since {budgetUsage?.period_start_iso ? new Date(budgetUsage.period_start_iso).toLocaleString() : 'current reset'} · resets at {resetTime} local time</div>
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
              <span className="section-label">BUDGET BY PEER</span>
              <span className="section-meta">{peerBreakdown.length} peers · daily</span>
            </div>
            <div className="peer-budget-list">
              {peerBreakdown.map(p => {
                const b = peerBudgets[p.id] != null ? peerBudgets[p.id] : 'inf';
                const isInf = b === 'inf';
                const pcap = isInf ? 0 : b * 1024 * 1024 * 1024;
                const ppct = isInf ? 0 : Math.min(100, (p.total / pcap) * 100);
                const over = !isInf && p.total > pcap;
                const fillColor = over ? 'var(--danger)' : ppct > 80 ? 'var(--warn)' : 'var(--accent)';
                return (
                  <div key={p.id} className={`pb-row${isInf ? ' is-inf' : ''}`}>
                    <div className="pb-top">
                      <div className="pb-id">
                        <span className="pb-name">{p.name}</span>
                        <span className="pb-device">{p.device || ''}</span>
                      </div>
                      <div className="pb-ctrl">
                        {!isInf && (
                          <div className="stepper stepper-sm">
                            <button onClick={() => setPeerBudget(p.id, Math.max(1, b - 1))}>−</button>
                            <span className="mono">{b} GB</span>
                            <button onClick={() => setPeerBudget(p.id, b + 1)}>+</button>
                          </div>
                        )}
                        <button
                          className={`pb-inf-btn${isInf ? ' on' : ''}`}
                          onClick={() => setPeerBudget(p.id, isInf ? 5 : 'inf')}
                          title={isInf ? 'Set a daily limit' : 'Remove limit'}
                        >∞</button>
                      </div>
                    </div>
                    <div className={`pb-bar${isInf ? ' inf' : ''}`}>
                      {isInf
                        ? <div className="pb-bar-fill" style={{ width: `${(p.total / maxPeerTotal) * 100}%`, background: 'var(--muted)' }} />
                        : <div className="pb-bar-fill" style={{ width: `${ppct}%`, background: fillColor }} />}
                    </div>
                    <div className="pb-foot">
                      <span className="pb-used mono">{window.WG.formatBytes(p.total)} <span className="pb-used-lbl">today</span></span>
                      {isInf
                        ? <span className="pb-status mono pb-status-inf">∞ no limit</span>
                        : <span className={`pb-status mono${over ? ' pb-status-over' : ''}`}>{over ? `over by ${window.WG.formatBytes(p.total - pcap)}` : `${ppct.toFixed(0)}% of ${b} GB`}</span>}
                    </div>
                  </div>
                );
              })}
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
                  <div className="setting-desc">Daily data limit across all peers</div>
                </div>
                <div className="setting-control">
                  <div className="stepper">
                    <button disabled={saving} onClick={() => saveSettings({ budget_gb: Math.max(1, budget - 5) })}>−</button>
                    <span className="mono">{budget} GB</span>
                    <button disabled={saving} onClick={() => saveSettings({ budget_gb: budget + 5 })}>+</button>
                  </div>
                  {msg && <span style={{ display: 'block', marginTop: 3, color: msg.startsWith('Error') ? 'var(--danger)' : 'var(--accent-2)', fontFamily: 'var(--mono)', fontSize: 10 }}>{msg}</span>}
                </div>
              </div>
              <div className="setting-row">
                <div>
                  <div className="setting-title">Reset time</div>
                  <div className="setting-desc">When the daily counter rolls over</div>
                </div>
                <div className="setting-control">
                  <select className="select-input" value={resetTime} disabled={saving} onChange={e => saveSettings({ reset_time: e.target.value })}>
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
                  <button className={`toggle ${alerts ? 'on' : ''}`} disabled={saving} onClick={() => saveSettings({ alerts: !alerts })} aria-pressed={alerts}>
                    <span className="toggle-knob" />
                  </button>
                </div>
              </div>
              <div className="setting-row">
                <div>
                  <div className="setting-title">When budget exceeded</div>
                  <div className="setting-desc">Action applied per peer once their limit is hit</div>
                </div>
                <div className="setting-control">
                  <select
                    className="select-input"
                    value={enforcement.action}
                    disabled={saving}
                    onChange={e => saveSettings({ enforcement: { ...enforcement, action: e.target.value } })}
                  >
                    <option value="none">No action</option>
                    <option value="throttle">Reduce speed</option>
                    <option value="pause">Pause connection</option>
                    <option value="combined">Combined — slow at 80%, pause at 100%</option>
                  </select>
                </div>
              </div>
              {(enforcement.action === 'throttle' || enforcement.action === 'combined') && (
                <div className="setting-row">
                  <div>
                    <div className="setting-title">Reduced speed</div>
                    <div className="setting-desc">Speed cap applied when peer exceeds their budget</div>
                  </div>
                  <div className="setting-control">
                    <div className="stepper">
                      <button disabled={saving} onClick={() => saveSettings({ enforcement: { ...enforcement, throttle_mbps: Math.max(1, (enforcement.throttle_mbps || 5) - 1) } })}>−</button>
                      <span className="mono">{enforcement.throttle_mbps || 5} Mbps</span>
                      <button disabled={saving} onClick={() => saveSettings({ enforcement: { ...enforcement, throttle_mbps: (enforcement.throttle_mbps || 5) + 1 } })}>+</button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </section>

          <section className="drawer-section">
            <div className="action-row">
              <button className="btn btn-primary" onClick={exportCsv} disabled={saving}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 3v12m0 0l-4-4m4 4l4-4M4 21h16"/></svg>
                {saving ? 'Working…' : 'Export CSV'}
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
function LogsDrawer({ alerts, onClose, verbose, setVerbose, onDismiss }) {
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
  const logSearchRef = _useRef(null);

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
        const j = await window.WG.apiCall(`/api/logs?n=${n}&verbose=${verbose ? 1 : 0}`, { silent: true });
        if (cancelled) return;
        if (j.lines && j.lines.length) {
          setLocalLogs(window.WG.parseLogLines(j.lines, verbose));
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
      const r = await window.WG.apiCall('/api/logs/retention', { silent: true, method: 'POST', body: JSON.stringify({ retention: val }) });
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
            <div className="peer-avatar" style={{ background: 'var(--avatar-bg)' }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/></svg>
            </div>
            <div>
              <h2 className="drawer-title">Logs</h2>
              <div className="drawer-sub">
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
                    {onDismiss && (
                      <button className="alert-dismiss" onClick={() => onDismiss(a.key)} aria-label="Dismiss">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M6 6l12 12M18 6L6 18"/></svg>
                      </button>
                    )}
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
                <input ref={logSearchRef} type="text" placeholder="Search logs…" value={search} onChange={e => setSearch(e.target.value)} />
                {search && (
                  <button className="search-clear" onClick={() => { setSearch(''); logSearchRef.current?.focus(); }} aria-label="Clear search">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M18 6L6 18M6 6l12 12"/></svg>
                  </button>
                )}
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
                <div key={i} className={`log-line log-${l.level}${verbose ? ' no-ts' : ''}`}>
                  {!verbose && <span className="log-time">{new Date(l.t).toTimeString().slice(0, 8)}</span>}
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
                    Vacuum journal on disk — removes entries older than the selected period
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
  const [hidden, setHidden] = _useState(false);
  const bgToastRef     = _useRef(null);
  const closedRef      = _useRef(false);
  const runningRef     = _useRef(false);
  const cleanupTimerRef = _useRef(null);

  const handleClose = () => {
    if (runningRef.current) {
      closedRef.current = true;
      setHidden(true);
      bgToastRef.current = window.WG.toast?.loading('Port check in progress…');
    } else {
      onClose();
    }
  };

  _useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') handleClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const run = async () => {
    // Reset background-run state so re-runs behave like a fresh open
    closedRef.current = false;
    clearTimeout(cleanupTimerRef.current);
    bgToastRef.current?.dismiss();
    bgToastRef.current = null;

    runningRef.current = true;
    setRunning(true);
    setDone(false);
    setResults({});
    setCurrent(0);
    setApiError(null);

    let stepResults = {};
    try {
      // Fetch all diagnostic data in parallel
      const [status, diag, health] = await Promise.all([
        window.WG.apiCall('/api/status', { silent: true }).catch(() => null),
        window.WG.apiCall('/api/diag/vpn', { silent: true }).catch(() => null),
        window.WG.apiCall('/api/health', { silent: true }).catch(() => null),
      ]);

      const port = (status && status.network && status.network.port) || 51820;
      const portStatus = await window.WG.apiCall('/api/ports?proto=udp&port=' + port, { silent: true }).catch(() => null);

      const connectedPeers = peers.filter(p => p.status === 'connected').length;

      stepResults = {
        'iface':     (status && status.service && status.service.active) ? 'ok' : 'fail',
        'listen':    (portStatus && portStatus.listening) ? 'ok' : 'fail',
        'fw-in':     (portStatus && portStatus.ufw_allowed) ? 'ok' : 'warn',
        'fw-fwd':    (diag && diag.ip_forward) ? 'ok' : 'fail',
        'nat':       (diag && diag.has_postup) ? 'ok' : 'warn',
        'dns':       (health && health.ping_ok) ? 'ok' : 'warn',
        'handshake': connectedPeers > 0 ? 'ok' : (peers.length > 0 ? 'warn' : 'ok'),
      };

      // Reveal one by one with animation (skip if hidden in background)
      if (!closedRef.current) {
        for (let i = 0; i < steps.length; i++) {
          setCurrent(i);
          await new Promise(r => setTimeout(r, 350 + Math.random() * 300));
          setResults(prev => ({ ...prev, [steps[i].id]: stepResults[steps[i].id] }));
        }
      }
    } catch (e) {
      setApiError(e.message || 'API unreachable');
      steps.forEach(s => { stepResults[s.id] = 'fail'; });
    }

    runningRef.current = false;
    setRunning(false);
    setDone(true);
    setCurrent(-1);
    window.WG.apiCall('/api/diag/refresh', { method: 'POST', silent: true }).catch(() => {});

    if (closedRef.current && bgToastRef.current) {
      const vals = Object.values(stepResults);
      const f = vals.filter(v => v === 'fail').length;
      const w = vals.filter(v => v === 'warn').length;
      const p = vals.filter(v => v === 'ok').length;

      const DURATION = 8000;
      const stats = [
        f > 0 && { color: 'var(--danger)', count: f, label: f === 1 ? 'failed'  : 'failed'  },
        w > 0 && { color: 'var(--warn)',   count: w, label: w === 1 ? 'warning' : 'warnings' },
        p > 0 && { color: 'var(--success)',count: p, label: p === 1 ? 'passed'  : 'passed'  },
      ].filter(Boolean);

      const viewResultsIcon = <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>;

      bgToastRef.current.update({
        type: f > 0 ? 'error' : w > 0 ? 'warning' : 'success',
        title: 'Port check complete',
        stats,
        action: {
          label: 'View results',
          icon: viewResultsIcon,
          onClick: () => {
            clearTimeout(cleanupTimerRef.current);
            setHidden(false);
          },
        },
        duration: DURATION,
      });

      cleanupTimerRef.current = setTimeout(onClose, DURATION + 300);
    }
  };

  _useEffect(() => {
    run();
    return () => { clearTimeout(cleanupTimerRef.current); bgToastRef.current?.dismiss(); };
  }, []);

  const passed = Object.values(results).filter(v => v === 'ok').length;
  const warned = Object.values(results).filter(v => v === 'warn').length;
  const failed = Object.values(results).filter(v => v === 'fail').length;
  const progress = current === -1 && done ? 1 : current === -1 ? 0 : (current + 0.5) / steps.length;

  if (hidden) return null;

  return (
    <>
      <div className="drawer-scrim" onClick={handleClose} />
      <aside className="drawer" role="dialog" aria-label="Port check">
        <header className="drawer-head">
          <div className="drawer-head-left">
            <div className="peer-avatar" style={{ background: 'var(--avatar-bg)' }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 3v18M3 12h18"/><circle cx="12" cy="12" r="9"/></svg>
            </div>
            <div>
              <h2 className="drawer-title">Port check</h2>
              <div className="drawer-sub">
                {running ? 'Running diagnostics…' : done ? `Completed · ${passed} passed, ${warned} warnings, ${failed} failed` : 'Idle'}
              </div>
            </div>
          </div>
          <button className="icon-btn" onClick={handleClose} aria-label="Close">
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

// ============================================================
// SettingsDrawer — accent color, server info, software update
// ============================================================
const UPDATE_STAGES = [
  { id: 'fetch',   label: 'Fetching updates',  detail: 'checking origin/main' },
  { id: 'pull',    label: 'Pulling changes',    detail: 'merging commits' },
  { id: 'restart', label: 'Restarting service', detail: 'wg-dashboard' },
];

const UPD_COOLDOWN_MS = 30_000;
const UPD_COOLDOWN_KEY = 'WG_UPDATE_COOLDOWN_END';

function CountdownRing({ remaining }) {
  const secs = Math.ceil(remaining / 1000);
  const digits = String(secs).split('');
  return (
    <span style={{ fontSize: 10, fontFamily: 'var(--mono)', color: 'var(--muted)', flexShrink: 0 }}>
      {digits.map((d, i) => (
        <span key={`${i}_${d}`} style={{ display: 'inline-block', animation: 'numFlyUp 0.3s cubic-bezier(0.2, 0.9, 0.25, 1) both' }}>{d}</span>
      ))}s
    </span>
  );
}

function ChangePasswordSection() {
  return (
    <section className="drawer-section">
      <div className="section-head"><span className="section-label">SECURITY</span></div>
      <div className="settings-list">
        <div className="setting-row">
          <div>
            <div className="setting-title">Dashboard password</div>
            <div className="setting-desc">Change the password used to log in to this dashboard</div>
          </div>
          <div className="setting-control">
            <button className="btn btn-primary" onClick={() => window.location.href = '/change-password'}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
              Change
            </button>
          </div>
        </div>
      </div>
    </section>
  );
}

function SettingsDrawer({ tweaks, setTweaks, connectedCount, totalPeers, onClose, onUpdateAvailable }) {
  const accent = tweaks.accent || 'terracotta';
  const [version, setVersion] = _useState('…');
  const [newVersion, setNewVersion] = _useState('');
  const [phase, setPhase] = _useState('loading');
  const [sysInfo, setSysInfo] = _useState(null);
  const [stageIdx, setStageIdx] = _useState(-1);
  const [stageDetails, setStageDetails] = _useState({});
  const [updateError, setUpdateError] = _useState('');
  const rafRef = _useRef(null);
  const fillRef = _useRef(null);
  const glowRef = _useRef(null);
  const pctRef = _useRef(null);
  const progressRef = _useRef(0);

  const paint = (p) => {
    progressRef.current = p;
    if (fillRef.current) fillRef.current.style.width = p + '%';
    if (glowRef.current) glowRef.current.style.left = p + '%';
    if (pctRef.current) pctRef.current.textContent = Math.round(p) + '%';
  };

  const animateTo = (target, dur, onDone) => {
    dur = dur || 500;
    if (rafRef.current) cancelAnimationFrame(rafRef.current);
    const from = progressRef.current;
    const start = performance.now();
    const step = (now) => {
      const t = Math.min(1, (now - start) / dur);
      const eased = t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2;
      paint(from + (target - from) * eased);
      if (t < 1) {
        rafRef.current = requestAnimationFrame(step);
      } else if (onDone) {
        onDone();
      }
    };
    rafRef.current = requestAnimationFrame(step);
  };

  const [checking, setChecking] = _useState(false);
  const [cooldownEnd, setCooldownEnd] = _useState(() => {
    try { const v = Number(localStorage.getItem(UPD_COOLDOWN_KEY)); return (v && v > Date.now()) ? v : null; } catch { return null; }
  });
  const [remaining, setRemaining] = _useState(() => {
    try { const v = Number(localStorage.getItem(UPD_COOLDOWN_KEY)); return (v && v > Date.now()) ? v - Date.now() : 0; } catch { return 0; }
  });
  const onCooldown = remaining > 0;
  const [advancedOpen, setAdvancedOpen] = _useState(false);
  const devUpdatesRef = _useRef(tweaks.devUpdates);
  devUpdatesRef.current = tweaks.devUpdates;
  const prevDevUpdatesRef = _useRef(tweaks.devUpdates);

  const checkForUpdates = (manual) => {
    const devParam = devUpdatesRef.current ? '?dev=1' : '';
    if (manual) setChecking(true);
    Promise.all([
      fetch(`/api/update/check${devParam}`).then(r => r.json()),
      fetch('/api/system/info').then(r => r.json()),
      manual ? new Promise(r => setTimeout(r, 2000)) : Promise.resolve(),
    ]).then(([upd, sys]) => {
      setVersion(upd.local || 'unknown');
      setNewVersion(upd.remote || '');
      setPhase(upd.available ? 'available' : 'idle');
      setSysInfo(sys);
      if (upd.available && onUpdateAvailable) onUpdateAvailable(true);
    }).catch(() => { setVersion('unknown'); setPhase('idle'); })
      .finally(() => {
        if (!manual) return;
        setChecking(false);
        const end = Date.now() + UPD_COOLDOWN_MS;
        setCooldownEnd(end);
        try { localStorage.setItem(UPD_COOLDOWN_KEY, String(end)); } catch {}
      });
  };

  _useEffect(() => {
    if (!cooldownEnd) { setRemaining(0); return; }
    const tick = () => {
      const r = Math.max(0, cooldownEnd - Date.now());
      setRemaining(r);
      if (r === 0) {
        setCooldownEnd(null);
        try { localStorage.removeItem(UPD_COOLDOWN_KEY); } catch {}
      }
    };
    tick();
    const id = setInterval(tick, 100);
    return () => clearInterval(id);
  }, [cooldownEnd]);

  _useEffect(() => {
    checkForUpdates(false);
    const id = setInterval(() => checkForUpdates(false), 10 * 60 * 1000);
    return () => clearInterval(id);
  }, []);

  _useEffect(() => {
    if (prevDevUpdatesRef.current === tweaks.devUpdates) return;
    prevDevUpdatesRef.current = tweaks.devUpdates;
    checkForUpdates(false);
  }, [tweaks.devUpdates]);

  _useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && phase !== 'updating') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose, phase]);

  _useEffect(() => () => {
    if (rafRef.current) cancelAnimationFrame(rafRef.current);
  }, []);

  const setAccent = (id) => {
    setTweaks({ ...tweaks, accent: id });
  };

  const runUpdate = () => {
    setPhase('updating');
    setStageIdx(0);
    setStageDetails({});
    setUpdateError('');
    paint(0);

    fetch(`/api/update/apply${tweaks.devUpdates ? '?dev=1' : ''}`, { method: 'POST' })
      .then(res => {
        if (!res.ok || !res.body) throw new Error('Request failed');
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buf = '';
        const read = () => reader.read().then(({ done, value }) => {
          if (done) return;
          buf += decoder.decode(value, { stream: true });
          const parts = buf.split('\n\n');
          buf = parts.pop();
          parts.forEach(part => {
            const line = part.trim();
            if (!line.startsWith('data: ')) return;
            try {
              const evt = JSON.parse(line.slice(6));
              if (evt.event === 'stage') {
                const idx = UPDATE_STAGES.findIndex(s => s.id === evt.id);
                if (idx >= 0) setStageIdx(idx);
                if (evt.detail) setStageDetails(prev => {
                  const existing = prev[evt.id] || [];
                  const last = existing[existing.length - 1];
                  return last === evt.detail ? prev : { ...prev, [evt.id]: [...existing, evt.detail] };
                });
                animateTo(evt.progress || 0);
              } else if (evt.event === 'done') {
                animateTo(100, 600, () => {
                  setStageIdx(UPDATE_STAGES.length);
                  if (evt.version) setVersion(evt.version);
                  setPhase('done');
                });
              } else if (evt.event === 'error') {
                setUpdateError(evt.detail || 'Unknown error');
                setPhase('error');
              }
            } catch (_) {}
          });
          read();
        }).catch(err => {
          setUpdateError('Stream error: ' + (err.message || 'closed'));
          setPhase('error');
        });
        read();
      })
      .catch(err => {
        setUpdateError('Connection failed: ' + (err.message || ''));
        setPhase('error');
      });
  };

  const SI = sysInfo || {};
  const stats = [
    { label: 'Version',      value: version !== '…' ? version : null,               skelW: 72,  mono: true,  highlight: phase === 'done' },
    { label: 'Platform',     value: SI.platform   || null,                           skelW: 110, mono: false },
    { label: 'Kernel',       value: SI.kernel     || null,                           skelW: 150, mono: true  },
    { label: 'Uptime',       value: SI.uptime     || null,                           skelW: 120, mono: false },
    { label: 'Interface',    value: SI.interface  || null,                           skelW: 36,  mono: true  },
    { label: 'Service',      value: SI.service    || null,                           skelW: 100, mono: true  },
    { label: 'Status',       value: SI.service_enabled != null ? (SI.service_enabled ? 'enabled' : 'disabled') : null, skelW: 52, mono: true },
    { label: 'Peers online', value: `${connectedCount} / ${totalPeers}`,             skelW: 40,  mono: true  },
  ];

  const accents = [
    { id: 'terracotta', c: 'oklch(59% 0.15 33)',  name: 'Terracotta' },
    { id: 'forest',     c: 'oklch(55% 0.11 150)', name: 'Forest' },
    { id: 'blue',       c: 'oklch(55% 0.22 235)', name: 'Iris'  },
    { id: 'plum',       c: 'oklch(48% 0.12 330)', name: 'Plum' },
    { id: 'ink',        c: 'oklch(55% 0.19 27)',  name: 'Ember' },
  ];

  return (
    <>
      <div className="drawer-scrim" onClick={() => phase !== 'updating' && onClose()} />
      <aside className="drawer" role="dialog" aria-label="Dashboard settings">
        <header className="drawer-head">
          <div className="drawer-head-left">
            <div className="peer-avatar" style={{ background: 'var(--avatar-bg)' }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 11-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 11-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 11-2.83-2.83l.06-.06a1.65 1.65 0 00.33-1.82 1.65 1.65 0 00-1.51-1H3a2 2 0 110-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 112.83-2.83l.06.06a1.65 1.65 0 001.82.33H9a1.65 1.65 0 001-1.51V3a2 2 0 114 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 112.83 2.83l-.06.06a1.65 1.65 0 00-.33 1.82V9a1.65 1.65 0 001.51 1H21a2 2 0 110 4h-.09a1.65 1.65 0 00-1.51 1z"/></svg>
            </div>
            <div>
              <h2 className="drawer-title">Dashboard settings</h2>
              <div className="drawer-sub" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                {SI.service ? SI.service : <span className="skel skel-sub" style={{ width: 100 }} />}
                {' · '}
                {SI.service_enabled != null ? (SI.service_enabled ? 'enabled' : 'disabled') : <span className="skel skel-sub" style={{ width: 52 }} />}
              </div>
            </div>
          </div>
          <button className="icon-btn" onClick={onClose} aria-label="Close" disabled={phase === 'updating'}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M6 6l12 12M18 6L6 18"/></svg>
          </button>
        </header>

        <div className="drawer-body">
          <section className="drawer-section">
            <div className="section-head"><span className="section-label">ACCENT COLOR</span></div>
            <div className="set-accent-grid">
              {accents.map(a => (
                <button key={a.id} className={`set-accent ${accent === a.id ? 'on' : ''}`} onClick={() => setAccent(a.id)}>
                  <span className="set-accent-dot" style={{ background: a.c }}>
                    {accent === a.id && (
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="3.2"><path d="M5 12l5 5L20 7"/></svg>
                    )}
                  </span>
                  <span className="set-accent-name">{a.name}</span>
                </button>
              ))}
            </div>
          </section>

          <section className="drawer-section">
            <div className="section-head"><span className="section-label">CHARTS</span></div>
            <div className="settings-list">
              <div className="setting-row">
                <div>
                  <div className="setting-title">Smooth lines</div>
                  <div className="setting-desc">Use spline interpolation on the live throughput chart</div>
                </div>
                <div className="setting-control" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <div className={`tension-slider-wrap${tweaks.splineChart ? ' visible' : ''}`}>
                    <span style={{ fontSize: 10, color: 'var(--muted)', fontFamily: 'var(--mono)', minWidth: 26, textAlign: 'right' }}>
                      {(tweaks.splineTension ?? 1).toFixed(1)}
                    </span>
                    <input
                      type="range" min="0" max="3" step="0.1"
                      value={tweaks.splineTension ?? 1}
                      onChange={e => setTweaks({ ...tweaks, splineTension: parseFloat(e.target.value) })}
                      className="tension-slider"
                      style={{ background: `linear-gradient(to right, var(--accent) ${((tweaks.splineTension ?? 1) / 3) * 100}%, var(--border) ${((tweaks.splineTension ?? 1) / 3) * 100}%)` }}
                    />
                  </div>
                  <button
                    className={`toggle ${tweaks.splineChart ? 'on' : ''}`}
                    onClick={() => setTweaks({ ...tweaks, splineChart: !tweaks.splineChart })}
                    aria-pressed={tweaks.splineChart}
                  >
                    <span className="toggle-knob" />
                  </button>
                </div>
              </div>
              <div className="setting-row">
                <div>
                  <div className="setting-title">Continuous scroll</div>
                  <div className="setting-desc">Scrolls the chart between poll updates instead of jumping at each interval</div>
                </div>
                <div className="setting-control">
                  <button
                    className={`toggle ${tweaks.smoothThroughput ? 'on' : ''}`}
                    onClick={() => setTweaks({ ...tweaks, smoothThroughput: !tweaks.smoothThroughput })}
                    aria-pressed={tweaks.smoothThroughput}
                  >
                    <span className="toggle-knob" />
                  </button>
                </div>
              </div>
              <div className="setting-row">
                <div>
                  <div className="setting-title">Smooth Y-axis scaling</div>
                  <div className="setting-desc">Animates the Y-axis when throughput crosses unit boundaries instead of snapping</div>
                </div>
                <div className="setting-control">
                  <button
                    className={`toggle ${tweaks.smoothScale ? 'on' : ''}`}
                    onClick={() => setTweaks({ ...tweaks, smoothScale: !tweaks.smoothScale })}
                    aria-pressed={tweaks.smoothScale}
                  >
                    <span className="toggle-knob" />
                  </button>
                </div>
              </div>
            </div>
          </section>

          <section className="drawer-section">
            <div className="section-head"><span className="section-label">SERVER</span></div>
            <div className="set-stats">
              {stats.map(s => (
                <div className="set-stat" key={s.label}>
                  <div className="set-stat-label">{s.label}</div>
                  <div className={`set-stat-val ${s.mono ? 'mono' : ''} ${s.highlight ? 'is-new' : ''}`}>
                    {s.value != null
                      ? s.value
                      : <span className="skel" style={{ width: s.skelW }} />}
                  </div>
                </div>
              ))}
            </div>
          </section>

          <section className="drawer-section">
            <div className="section-head"><span className="section-label">SOFTWARE UPDATE</span></div>

            {phase === 'loading' && (
              <div className="upd-card" style={{display:'flex',alignItems:'center',gap:'8px',color:'var(--text-2)',fontSize:'13px'}}>
                <span className="pc-spinner" style={{width:'14px',height:'14px',flexShrink:0}} />
                Fetching updates…
              </div>
            )}

            {phase === 'idle' && (
              <div className="upd-card upd-idle-card">
                <div className={`upd-idle-content${checking ? ' is-blurring' : ''}`}>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" strokeWidth="2.2" style={{flexShrink:0}}><path d="M5 12l5 5L20 7"/></svg>
                  <span style={{color:'var(--text-2)',fontSize:'13px',flex:1}}>Up to date · <span className="mono">{version}</span></span>
                  {onCooldown && <CountdownRing remaining={remaining} />}
                  <button className="icon-btn" onClick={() => checkForUpdates(true)} aria-label="Check for updates" title={onCooldown ? 'Check again in a moment' : 'Check for updates'} disabled={checking || onCooldown}>
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 12a9 9 0 11-9-9c2.5 0 4.7 1 6.4 2.6L21 3v6h-6"/></svg>
                  </button>
                </div>
                <div className={`upd-fetch-overlay${checking ? ' is-active' : ''}`}>
                  <span className="pc-spinner" style={{width:'12px',height:'12px',flexShrink:0}} />
                  <span className="upd-fetch-text">Fetching updates</span>
                </div>
              </div>
            )}

            {phase === 'available' && (
              <div className="upd-card upd-available">
                <div className="upd-badge-row">
                  <span className="upd-pill">
                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4"><path d="M12 3v12m0 0l-4-4m4 4l4-4M4 21h16"/></svg>
                    Update available
                  </span>
                </div>
                <div className="upd-ver-flow">
                  <span className="upd-ver upd-ver-old mono">{version}</span>
                  <svg className="upd-arrow" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M5 12h14m-6-6l6 6-6 6"/></svg>
                  <span className="upd-ver upd-ver-new mono">{newVersion}</span>
                </div>
                <div className="upd-notes">New version available on GitHub. The service will be restarted to apply the update.</div>
                <button className="btn btn-primary upd-btn" onClick={runUpdate}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M21 12a9 9 0 11-9-9c2.5 0 4.7 1 6.4 2.6L21 3v6h-6"/></svg>
                  Install update
                </button>
              </div>
            )}

            {phase === 'updating' && (
              <div className="upd-card">
                <div className="upd-progress-head">
                  <span className="upd-stage-name">{UPDATE_STAGES[Math.min(stageIdx, UPDATE_STAGES.length - 1)]?.label}<span className="pc-typing">…</span></span>
                  <span className="upd-pct mono" ref={pctRef}>0%</span>
                </div>
                <div className="upd-progress">
                  <div className="upd-progress-fill" ref={fillRef} />
                  <div className="upd-progress-glow" ref={glowRef} />
                </div>
                <div className="upd-steplist">
                  {UPDATE_STAGES.map((s, i) => {
                    const done = i < stageIdx;
                    const active = i === stageIdx;
                    const details = stageDetails[s.id] || [s.detail];
                    return (
                      <div key={s.id} className={`upd-step ${done ? 'done' : ''} ${active ? 'active' : ''}`}>
                        <span className="upd-step-marker">
                          {done ? (
                            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><path d="M5 12l5 5L20 7"/></svg>
                          ) : active ? (
                            <span className="pc-spinner" />
                          ) : (
                            <span className="pc-idle-dot" />
                          )}
                        </span>
                        <span className="upd-step-body">
                          <span className="upd-step-label">{s.label}</span>
                          {(active || done) && details.map((d, di) => (
                            <span key={di} className="upd-step-detail mono">{d}</span>
                          ))}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {phase === 'error' && (
              <div className="upd-card" style={{borderColor:'oklch(72% 0.16 25)',background:'oklch(99% 0.01 25)'}}>
                <div style={{display:'flex',gap:'8px',alignItems:'flex-start'}}>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="oklch(55% 0.18 25)" strokeWidth="2" style={{marginTop:'1px',flexShrink:0}}><circle cx="12" cy="12" r="10"/><path d="M12 8v4m0 4h.01"/></svg>
                  <div>
                    <div style={{fontWeight:'600',fontSize:'13px',color:'oklch(45% 0.15 25)'}}>Update failed</div>
                    <div style={{fontSize:'12px',color:'var(--text-2)',marginTop:'3px',fontFamily:'var(--font-mono)',wordBreak:'break-all'}}>{updateError}</div>
                  </div>
                </div>
                <button className="btn btn-primary upd-btn" onClick={runUpdate} style={{marginTop:'12px'}}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M21 12a9 9 0 11-9-9c2.5 0 4.7 1 6.4 2.6L21 3v6h-6"/></svg>
                  Retry
                </button>
              </div>
            )}

            {phase === 'done' && (
              <div className="upd-card upd-done">
                <div className="upd-done-check">
                  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.6"><path d="M5 12l5 5L20 7"/></svg>
                </div>
                <div className="upd-done-title">Update installed</div>
                <div className="upd-done-desc">Now running <span className="mono">{version}</span>. Reload the dashboard to apply the changes.</div>
                <button className="btn btn-primary upd-refresh-btn" onClick={() => window.location.reload()}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9"><path d="M21 12a9 9 0 11-9-9c2.5 0 4.7 1 6.4 2.6L21 3v6h-6"/></svg>
                  Refresh dashboard
                </button>
              </div>
            )}

            <div style={{ marginBottom: '12px' }} />

          <ChangePasswordSection />

            <div className="settings-list" style={{ marginTop: '10px' }}>
              <button
                className="setting-row"
                onClick={() => setAdvancedOpen(v => !v)}
                style={{ width: '100%', textAlign: 'left', cursor: 'pointer', background: 'none', border: 'none', color: 'inherit' }}
              >
                <span style={{ fontSize: '12px', color: 'var(--muted)', fontWeight: '500' }}>Advanced settings</span>
                <svg style={{ transform: advancedOpen ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform 0.2s', color: 'var(--muted)', flexShrink: 0 }} width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M6 9l6 6 6-6"/></svg>
              </button>
              {advancedOpen && (
                <>
                  <div className="setting-row">
                    <div>
                      <div className="setting-title">Throughput refresh rate</div>
                      <div className="setting-desc">How often the live throughput chart polls for new data</div>
                    </div>
                    <div className="setting-control" style={{ flexDirection: 'column', alignItems: 'flex-end' }}>
                      <div className="seg" style={{ width: 'fit-content' }}>
                        {[{ v: 10, label: '10ms' }, { v: 500, label: '500ms' }, { v: 1000, label: '1s' }, { v: 2000, label: '2s' }, { v: 5000, label: '5s' }].map(({ v, label }) => (
                          <button
                            key={v}
                            className={tweaks.refreshInterval === v ? 'on' : ''}
                            onClick={() => setTweaks({ ...tweaks, refreshInterval: v })}
                          >{label}</button>
                        ))}
                      </div>
                      <div style={{
                        display: 'flex', alignItems: 'center', gap: 4,
                        maxHeight: tweaks.refreshInterval <= 500 ? '20px' : '0',
                        opacity: tweaks.refreshInterval <= 500 ? 1 : 0,
                        marginTop: tweaks.refreshInterval <= 500 ? '5px' : '0',
                        overflow: 'hidden',
                        transition: 'max-height 0.22s ease, opacity 0.18s ease, margin-top 0.22s ease',
                      }}>
                        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="var(--warn)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" style={{ flexShrink: 0 }}><path d="M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0zM12 9v4M12 17h.01"/></svg>
                        <span style={{ fontSize: '10px', color: 'var(--muted)' }}>High server load</span>
                      </div>
                    </div>
                  </div>
                  <div className="setting-row">
                    <div>
                      <div className="setting-title">Developer updates</div>
                      <div className="setting-desc">Opt in to pre-release builds — may be unstable or contain bugs</div>
                    </div>
                    <div className="setting-control">
                      <button
                        className={`toggle ${tweaks.devUpdates ? 'on' : ''}`}
                        onClick={() => setTweaks({ ...tweaks, devUpdates: !tweaks.devUpdates })}
                        aria-pressed={tweaks.devUpdates}
                      >
                        <span className="toggle-knob" />
                      </button>
                    </div>
                  </div>
                  <div className="setting-row">
                    <div>
                      <div className="setting-title">Traffic mode <span style={{ fontSize: 10, fontFamily: 'var(--mono)', color: 'var(--muted)', marginLeft: 4 }}>experimental</span></div>
                      <div className="setting-desc">Show per-peer live traffic breakdown — not fully implemented yet</div>
                    </div>
                    <div className="setting-control">
                      <button
                        className={`toggle ${tweaks.trafficMode ? 'on' : ''}`}
                        onClick={() => setTweaks({ ...tweaks, trafficMode: !tweaks.trafficMode })}
                        aria-pressed={!!tweaks.trafficMode}
                      >
                        <span className="toggle-knob" />
                      </button>
                    </div>
                  </div>
                  <div className="setting-row">
                    <div>
                      <div className="setting-title">Welcome tour</div>
                      <div className="setting-desc">Re-open the setup walkthrough from the beginning</div>
                    </div>
                    <div className="setting-control">
                      <button
                        className="btn"
                        onClick={() => window.location.href = '/welcome'}
                      >Show</button>
                    </div>
                  </div>
                </>
              )}
            </div>
          </section>
        </div>
      </aside>
    </>
  );
}

// ============================================================
Object.assign(window, { PeerDrawer, LogsPanel, DataBudgetDrawer, LogsDrawer, PortCheckDrawer, SettingsDrawer, NotifIcon });

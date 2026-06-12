// Peer detail drawer + logs panel + port check + data budget

const { useState: _useState, useEffect: _useEffect, useRef: _useRef, useMemo: _useMemo } = React;

// ============================================================
// PeerDrawer — slide-out detail with charts + controls
// ============================================================
function PeerDrawer({ peer, onClose, throughputBuffers, onRevoke, onPeerUpdated }) {
  const [copied, setCopied] = _useState('');
  const [downloading, setDownloading] = _useState(false);
  const [revoking, setRevoking] = _useState(false);
  const [diag, setDiag] = _useState({ loading: true, pingMs: null, pingStatus: '', location: null, endpointIp: '', pingIp: '' });

  // Settings edit state
  const [note, setNote] = _useState('');
  const [dns, setDns] = _useState('');
  const [clientAllowedIps, setClientAllowedIps] = _useState('');
  const [keepaliveEnabled, setKeepaliveEnabled] = _useState(true);
  const [keepaliveVal, setKeepaliveVal] = _useState('25');
  const [settingsSaving, setSettingsSaving] = _useState(false);
  const [settingsMsg, setSettingsMsg] = _useState('');
  const [renaming, setRenaming] = _useState(false);
  const [newName, setNewName] = _useState('');
  const [renameSaving, setRenameSaving] = _useState(false);

  _useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  // Sync settings state when peer changes
  _useEffect(() => {
    if (!peer) return;
    setNote(peer.note || '');
    setDns(peer.dns || '');
    setClientAllowedIps(peer.clientAllowedIps || '');
    const ka = peer.keepalive || '25';
    setKeepaliveEnabled(ka !== '0');
    setKeepaliveVal(ka === '0' ? '25' : ka);
    setNewName(peer.name);
    setSettingsMsg('');
    setRenaming(false);
  }, [peer && peer.name]);

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

  const saveSettings = async (patch) => {
    setSettingsSaving(true);
    setSettingsMsg('');
    try {
      await window.WG.apiCall('/api/users/' + encodeURIComponent(peer.name) + '/settings', {
        method: 'PATCH',
        body: JSON.stringify(patch),
      });
      setSettingsMsg('Saved');
      setTimeout(() => setSettingsMsg(''), 2000);
      if (onPeerUpdated) onPeerUpdated();
    } catch (e) {
      setSettingsMsg('Error: ' + (e.message || 'save failed'));
    } finally {
      setSettingsSaving(false);
    }
  };

  const renamePeer = async () => {
    const trimmed = newName.trim();
    if (!trimmed || trimmed === peer.name) { setRenaming(false); return; }
    setRenameSaving(true);
    try {
      await window.WG.apiCall('/api/users/' + encodeURIComponent(peer.name) + '/rename', {
        method: 'POST',
        body: JSON.stringify({ name: trimmed }),
      });
      setRenaming(false);
      if (onPeerUpdated) onPeerUpdated();
    } catch (e) {
      alert('Rename failed: ' + (e.message || 'API error'));
    } finally {
      setRenameSaving(false);
    }
  };

  if (!peer) return null;

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
              <span className="section-label">CONFIGURATION</span>
              {settingsMsg && (
                <span style={{ fontFamily: 'var(--mono)', fontSize: 11, color: settingsMsg.startsWith('Error') ? 'var(--danger)' : 'var(--accent-2)' }}>
                  {settingsMsg}
                </span>
              )}
            </div>
            <div className="settings-list">

              {/* Rename */}
              <div className="setting-row">
                <div>
                  <div className="setting-title">Name</div>
                  <div className="setting-desc">Identifier used in WireGuard config</div>
                </div>
                <div className="setting-control">
                  {renaming ? (
                    <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                      <input
                        className="select-input"
                        style={{ width: 130 }}
                        value={newName}
                        onChange={e => setNewName(e.target.value)}
                        onKeyDown={e => { if (e.key === 'Enter') renamePeer(); if (e.key === 'Escape') setRenaming(false); }}
                        autoFocus
                        maxLength={64}
                      />
                      <button className="mini-btn" onClick={renamePeer} disabled={renameSaving}>
                        {renameSaving ? '…' : 'save'}
                      </button>
                      <button className="mini-btn" onClick={() => { setRenaming(false); setNewName(peer.name); }}>✕</button>
                    </div>
                  ) : (
                    <button className="mini-btn" onClick={() => setRenaming(true)}>rename</button>
                  )}
                </div>
              </div>

              {/* Note */}
              <div className="setting-row">
                <div>
                  <div className="setting-title">Note</div>
                  <div className="setting-desc">Free-text label (e.g. "John's laptop")</div>
                </div>
                <div className="setting-control">
                  <input
                    className="select-input"
                    style={{ width: 160 }}
                    placeholder="—"
                    value={note}
                    maxLength={200}
                    onChange={e => setNote(e.target.value)}
                    onBlur={() => saveSettings({ note })}
                  />
                </div>
              </div>

              {/* Routing mode */}
              <div className="setting-row">
                <div>
                  <div className="setting-title">Routing mode</div>
                  <div className="setting-desc">
                    What traffic is tunnelled in the generated config
                    <div style={{ marginTop: 4 }}>
                      <select
                        className="select-input"
                        value={clientAllowedIps || 'full'}
                        disabled={settingsSaving}
                        onChange={e => {
                          const v = e.target.value;
                          if (v === 'full') {
                            setClientAllowedIps('');
                            saveSettings({ client_allowed_ips: '' });
                          } else if (v === 'split') {
                            const val = peer.addr || peer.allowedIps || '10.8.0.0/24';
                            setClientAllowedIps(val);
                            saveSettings({ client_allowed_ips: val });
                          } else {
                            setClientAllowedIps(v);
                            saveSettings({ client_allowed_ips: v });
                          }
                        }}
                      >
                        <option value="full">Full tunnel (0.0.0.0/0, ::/0)</option>
                        <option value="split">Split tunnel (peer subnet only)</option>
                        {clientAllowedIps && clientAllowedIps !== 'full' && clientAllowedIps !== 'split' && (
                          <option value={clientAllowedIps}>Custom: {clientAllowedIps}</option>
                        )}
                      </select>
                    </div>
                  </div>
                </div>
              </div>

              {/* DNS */}
              <div className="setting-row">
                <div style={{ flex: 1 }}>
                  <div className="setting-title">DNS override</div>
                  <div className="setting-desc">DNS servers in generated config (blank = server default)</div>
                </div>
                <div className="setting-control">
                  <input
                    className="select-input"
                    style={{ width: 160 }}
                    placeholder="1.1.1.1, 1.0.0.1"
                    value={dns}
                    onChange={e => setDns(e.target.value)}
                    onBlur={() => saveSettings({ dns })}
                  />
                </div>
              </div>

              {/* Keepalive */}
              <div className="setting-row">
                <div>
                  <div className="setting-title">Persistent keepalive</div>
                  <div className="setting-desc">Interval (seconds) — keeps NAT mapping alive</div>
                </div>
                <div className="setting-control" style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  {keepaliveEnabled && (
                    <div className="stepper">
                      <button disabled={settingsSaving} onClick={() => {
                        const v = String(Math.max(1, parseInt(keepaliveVal, 10) - 5));
                        setKeepaliveVal(v);
                        saveSettings({ keepalive: parseInt(v, 10) });
                      }}>−</button>
                      <span className="mono">{keepaliveVal}s</span>
                      <button disabled={settingsSaving} onClick={() => {
                        const v = String(Math.min(300, parseInt(keepaliveVal, 10) + 5));
                        setKeepaliveVal(v);
                        saveSettings({ keepalive: parseInt(v, 10) });
                      }}>+</button>
                    </div>
                  )}
                  <button
                    className={`toggle ${keepaliveEnabled ? 'on' : ''}`}
                    disabled={settingsSaving}
                    onClick={() => {
                      const next = !keepaliveEnabled;
                      setKeepaliveEnabled(next);
                      saveSettings({ keepalive: next ? parseInt(keepaliveVal, 10) : 0 });
                    }}
                    aria-pressed={keepaliveEnabled}
                  >
                    <span className="toggle-knob" />
                  </button>
                </div>
              </div>

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
function NotifIcon({ level }) {
  if (level === 'error') return <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="10"/><path d="M12 8v5M12 16h.01"/></svg>;
  if (level === 'warn') return <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0zM12 9v4M12 17h.01"/></svg>;
  if (level === 'success') return <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="10"/><path d="M8 12l2.5 2.5L16 9"/></svg>;
  if (level === 'update') return <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 2v11m0 0l-4-4m4 4l4-4M4 18h16"/></svg>;
  return <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="10"/><path d="M12 11v5M12 8h.01"/></svg>;
}

function LogsPanel({ logs, notifications = [], onExpand }) {
  const scrollRef = _useRef(null);
  const [dismissed, setDismissed] = _useState([]);
  const [idx, setIdx] = _useState(0);
  const [leaving, setLeaving] = _useState(false);

  _useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [logs.length]);

  const visible = notifications.filter(n => !dismissed.includes(n.title));
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

  return (
    <div className="logs-card logs-card-clickable" onClick={onExpand} role="button" tabIndex={0}>
      <div className="logs-split">
        <div className="notif-col" onClick={e => e.stopPropagation()}>
          <div className="notif-head">
            <span className="section-label">NOTIFICATIONS</span>
            {visible.length > 0 && <span className="notif-count">{visible.length}</span>}
          </div>
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
                  onClick={e => { e.stopPropagation(); setDismissed(d => [...d, current.title]); }}
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

        <div className="logs-sep" />

        <div className="logs-col">
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
      </div>
    </div>
  );
}

// ============================================================
// DataBudgetDrawer
// ============================================================
function DataBudgetDrawer({ total, budget, alerts, resetTime, peers, peerBudgets = {}, setPeerBudget, budgetUsage, updateBudgetSettings, onClose }) {
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
      const r = await window.WG.apiCall('/api/data-budget/export', { method: 'POST', body: JSON.stringify({}) });
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
            <div className="peer-avatar" style={{ background: 'var(--accent-soft)' }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M3 3v18h18"/><path d="M7 14l4-4 4 4 5-5"/></svg>
            </div>
            <div>
              <h2 className="drawer-title">Data budget</h2>
              <div className="drawer-sub">Actual usage since {budgetUsage?.period_start_iso ? new Date(budgetUsage.period_start_iso).toLocaleString() : 'current reset'} · resets at {resetTime} local</div>
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
                  <div className="setting-desc">Target data volume per day across all peers</div>
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

// ============================================================
// SettingsDrawer — accent color, server info, software update
// ============================================================
const UPDATE_STAGES = [
  { id: 'fetch',   label: 'Fetching updates',  detail: 'checking origin/main' },
  { id: 'pull',    label: 'Pulling changes',    detail: 'merging commits' },
  { id: 'restart', label: 'Restarting service', detail: 'wg-dashboard' },
];

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
  const [onCooldown, setOnCooldown] = _useState(false);
  const cooldownRef = _useRef(null);

  const checkForUpdates = (manual) => {
    if (manual) setChecking(true);
    Promise.all([
      fetch('/api/update/check').then(r => r.json()),
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
        setOnCooldown(true);
        clearTimeout(cooldownRef.current);
        cooldownRef.current = setTimeout(() => setOnCooldown(false), 30_000);
      });
  };

  _useEffect(() => {
    checkForUpdates(false);
    const id = setInterval(() => checkForUpdates(false), 10 * 60 * 1000);
    return () => clearInterval(id);
  }, []);

  _useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && phase !== 'updating') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose, phase]);

  _useEffect(() => () => {
    if (rafRef.current) cancelAnimationFrame(rafRef.current);
    clearTimeout(cooldownRef.current);
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

    fetch('/api/update/apply', { method: 'POST' })
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
                if (evt.detail) setStageDetails(prev => ({ ...prev, [evt.id]: evt.detail }));
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
    { label: 'Version',      value: version,                                         mono: true,  highlight: phase === 'done' },
    { label: 'Platform',     value: SI.platform   || '…',                            mono: false },
    { label: 'Kernel',       value: SI.kernel     || '…',                            mono: true  },
    { label: 'Uptime',       value: SI.uptime     || '…',                            mono: false },
    { label: 'Interface',    value: SI.interface  || '…',                            mono: true  },
    { label: 'Service',      value: SI.service    || '…',                            mono: true  },
    { label: 'Status',       value: SI.service_enabled != null ? (SI.service_enabled ? 'enabled' : 'disabled') : '…', mono: true },
    { label: 'Peers online', value: `${connectedCount} / ${totalPeers}`,             mono: true  },
  ];

  const accents = [
    { id: 'terracotta', c: 'oklch(62% 0.14 45)',  name: 'Terracotta' },
    { id: 'forest',     c: 'oklch(55% 0.11 150)', name: 'Forest' },
    { id: 'amber',      c: 'oklch(70% 0.15 75)',  name: 'Amber' },
    { id: 'plum',       c: 'oklch(48% 0.12 330)', name: 'Plum' },
    { id: 'ink',        c: 'oklch(55% 0.19 27)',  name: 'Ember' },
  ];

  return (
    <>
      <div className="drawer-scrim" onClick={() => phase !== 'updating' && onClose()} />
      <aside className="drawer" role="dialog" aria-label="Dashboard settings">
        <header className="drawer-head">
          <div className="drawer-head-left">
            <div className="peer-avatar" style={{ background: 'var(--accent-soft)' }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 11-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 11-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 11-2.83-2.83l.06-.06a1.65 1.65 0 00.33-1.82 1.65 1.65 0 00-1.51-1H3a2 2 0 110-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 112.83-2.83l.06.06a1.65 1.65 0 001.82.33H9a1.65 1.65 0 001-1.51V3a2 2 0 114 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 112.83 2.83l-.06.06a1.65 1.65 0 00-.33 1.82V9a1.65 1.65 0 001.51 1H21a2 2 0 110 4h-.09a1.65 1.65 0 00-1.51 1z"/></svg>
            </div>
            <div>
              <h2 className="drawer-title">Dashboard settings</h2>
              <div className="drawer-sub">
                <span className="pulse-dot" /> {SI.service || '…'} · {SI.service_enabled != null ? (SI.service_enabled ? 'enabled' : 'disabled') : '…'}
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
            <div className="section-head"><span className="section-label">SERVER</span></div>
            <div className="set-stats">
              {stats.map(s => (
                <div className="set-stat" key={s.label}>
                  <div className="set-stat-label">{s.label}</div>
                  <div className={`set-stat-val ${s.mono ? 'mono' : ''} ${s.highlight ? 'is-new' : ''}`}>{s.value}</div>
                </div>
              ))}
            </div>
          </section>

          <section className="drawer-section">
            <div className="section-head"><span className="section-label">SOFTWARE UPDATE</span></div>

            {phase === 'loading' && (
              <div className="upd-card" style={{display:'flex',alignItems:'center',gap:'8px',color:'var(--text-2)',fontSize:'13px'}}>
                <span className="pc-spinner" style={{width:'14px',height:'14px',flexShrink:0}} />
                Checking for updates…
              </div>
            )}

            {phase === 'idle' && (
              <div className="upd-card upd-idle-card">
                <div className={`upd-idle-content${checking ? ' is-blurring' : ''}`}>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" strokeWidth="2.2" style={{flexShrink:0}}><path d="M5 12l5 5L20 7"/></svg>
                  <span style={{color:'var(--text-2)',fontSize:'13px',flex:1}}>Up to date · <span className="mono">{version}</span></span>
                  <button className="icon-btn" onClick={() => checkForUpdates(true)} aria-label="Check for updates" title={onCooldown ? 'Check again in a moment' : 'Check for updates'} disabled={checking || onCooldown}>
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 12a9 9 0 11-9-9c2.5 0 4.7 1 6.4 2.6L21 3v6h-6"/></svg>
                  </button>
                </div>
                <div className={`upd-fetch-overlay${checking ? ' is-active' : ''}`}>
                  <span className="pc-spinner" style={{width:'12px',height:'12px',flexShrink:0}} />
                  Fetching updates<span className="pc-typing">…</span>
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
                <div className="upd-notes">New version available on GitHub. Pulls latest commits and restarts the service.</div>
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
                    const detail = stageDetails[s.id] || s.detail;
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
                        <span className="upd-step-label">{s.label}</span>
                        <span className="upd-step-detail mono">{detail}</span>
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
          </section>
        </div>
      </aside>
    </>
  );
}

// ============================================================
Object.assign(window, { PeerDrawer, LogsPanel, DataBudgetDrawer, LogsDrawer, PortCheckDrawer, SettingsDrawer, NotifIcon });

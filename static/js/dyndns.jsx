// DynDNS configuration drawer
// Allows configuring a dynamic DNS hostname as the server endpoint
// so peers reconnect automatically after a public IP change.

const { useState: uSD, useEffect: uED, useCallback: uCD } = React;

const DYNDNS_PROVIDERS = [
  {
    id: 'duckdns',
    label: 'Duck DNS',
    site: 'duckdns.org',
    tokenHelp: 'Token from your Duck DNS account page',
    domainHelp: 'Subdomain only — e.g. "myhome" for myhome.duckdns.org',
    tokenLabel: 'Token',
    domainLabel: 'Subdomain',
  },
  {
    id: 'noip',
    label: 'No-IP',
    site: 'noip.com',
    tokenHelp: 'username:password (colon-separated)',
    domainHelp: 'Full hostname — e.g. myhome.ddns.net',
    tokenLabel: 'Credentials',
    domainLabel: 'Hostname',
    disabled: true,
  },
  {
    id: 'dynu',
    label: 'Dynu',
    site: 'dynu.com',
    tokenHelp: 'username:password (colon-separated)',
    domainHelp: 'Full hostname — e.g. myhome.freeddns.org',
    tokenLabel: 'Credentials',
    domainLabel: 'Hostname',
    disabled: true,
  },
  {
    id: 'custom',
    label: 'Custom URL',
    site: null,
    tokenHelp: null,
    domainHelp: null,
    tokenLabel: null,
    domainLabel: null,
  },
];

function TestButton({ resolving, resolveResult, onResolve, hasHostname }) {
  const [hovered, setHovered] = uSD(false);
  const hasResult = resolveResult !== null;

  const icon = (() => {
    if (resolving) {
      return <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" style={{ animation: 'spin 1s linear infinite' }}><path d="M21 12a9 9 0 11-18 0"/></svg>;
    }
    if (hasResult && hovered) {
      return <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M21 2v6h-6M3 12a9 9 0 0115-6.7L21 8M3 22v-6h6M21 12a9 9 0 01-15 6.7L3 16"/></svg>;
    }
    if (resolveResult?.ok === true) {
      return <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--success, #22c55e)" strokeWidth="2.5"><path d="M5 12l5 5L20 7"/></svg>;
    }
    if (resolveResult?.ok === false) {
      return <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--danger, #ef4444)" strokeWidth="2.5"><path d="M18 6L6 18M6 6l12 12"/></svg>;
    }
    return 'Test';
  })();

  return (
    <button
      className="btn btn-ghost"
      style={{ flexShrink: 0 }}
      onClick={onResolve}
      disabled={resolving || !hasHostname}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      {icon}
    </button>
  );
}

function DynDNSDrawer({ onClose }) {
  // Collapsible is defined in addpeer.jsx which loads before this file
  const Collapsible = window.Collapsible;

  const [cfg, setCfg]               = uSD(null);
  const [loading, setLoading]       = uSD(true);
  const [saving, setSaving]         = uSD(false);
  const [tokenDirty, setTokenDirty] = uSD(false);
  const [providersOpen, setProvidersOpen] = uSD(false);

  const [resolveResult, setResolveResult] = uSD(null);
  const [resolving, setResolving]         = uSD(false);

  const [updateResult, setUpdateResult] = uSD(null);
  const [updating, setUpdating]         = uSD(false);

  uED(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  uED(() => {
    window.WG.apiCall('/api/dyndns')
      .then(d => { setCfg({ token: d.has_token ? '••••' : '', ...d }); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  const save = uCD(async () => {
    if (!cfg) return;
    setSaving(true);
    try {
      const body = { ...cfg };
      if (!tokenDirty) delete body.token;
      await window.WG.apiCall('/api/dyndns', { method: 'POST', body: JSON.stringify(body) });
      window.WG.toast?.success?.('Saved', 'DynDNS settings updated');
    } catch (e) {
      window.WG.toast?.error?.('Save failed', e?.message || 'Unknown error');
    } finally {
      setSaving(false);
    }
  }, [cfg, tokenDirty]);

  const resolve = uCD(async () => {
    if (!cfg?.hostname) return;
    setResolving(true);
    setResolveResult(null);
    try {
      const r = await window.WG.apiCall('/api/dyndns/resolve', {
        method: 'POST',
        body: JSON.stringify({ hostname: cfg.hostname }),
      });
      setResolveResult({ ok: true, ip: r.ip });
    } catch (e) {
      setResolveResult({ ok: false, error: e?.message || 'Resolution failed' });
    } finally {
      setResolving(false);
    }
  }, [cfg?.hostname]);

  const updateNow = uCD(async () => {
    setUpdating(true);
    setUpdateResult(null);
    try {
      const r = await window.WG.apiCall('/api/dyndns/update', { method: 'POST' });
      setUpdateResult({ ok: true, response: r.response });
      window.WG.toast?.success?.('Updated', 'DynDNS record pushed successfully');
    } catch (e) {
      const msg = e?.message || 'Update failed';
      setUpdateResult({ ok: false, error: msg });
      window.WG.toast?.error?.('Update failed', msg);
    } finally {
      setUpdating(false);
    }
  }, []);

  const set = (key, val) => setCfg(prev => ({ ...prev, [key]: val }));

  const providerInfo  = DYNDNS_PROVIDERS.find(p => p.id === cfg?.provider);
  const isDynDNS      = cfg?.mode === 'dyndns';

  return (
    <>
      <div className="drawer-scrim" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label="DynDNS settings">

        <header className="drawer-head">
          <div className="drawer-head-left">
            <div className="peer-avatar" style={{ background: 'var(--avatar-bg)' }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7">
                <circle cx="12" cy="12" r="9"/>
                <path d="M2 12h20M12 2a15.3 15.3 0 010 20M12 2a15.3 15.3 0 000 20"/>
              </svg>
            </div>
            <div>
              <h2 className="drawer-title">DynDNS</h2>
              <div className="drawer-sub">
                {loading ? 'Loading…' : isDynDNS
                  ? (cfg?.hostname || 'No hostname set')
                  : 'Static public IP mode'}
              </div>
            </div>
          </div>
          <button className="icon-btn" onClick={onClose} aria-label="Close">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
              <path d="M6 6l12 12M18 6L6 18"/>
            </svg>
          </button>
        </header>

        <div className="drawer-body">
          {loading ? (
            <section className="drawer-section">
              <div className="skel" style={{ height: 60, borderRadius: 8 }} />
            </section>
          ) : (
            <>

              {/* ── Mode ─────────────────────────────────────── */}
              <section className="drawer-section">
                <div className="section-head">
                  <span className="section-label">ENDPOINT MODE</span>
                </div>
                <div className="settings-list">
                  <div className="setting-row" style={{ paddingTop: 4 }}>
                    <div>
                      <div className="setting-title">Use DynDNS hostname</div>
                      <div className="setting-desc">
                        Peers stay connected even after your public IP changes.
                      </div>
                    </div>
                    <div className="setting-control">
                      <button
                        className={`toggle ${isDynDNS ? 'on' : ''}`}
                        onClick={() => set('mode', isDynDNS ? 'static' : 'dyndns')}
                        aria-pressed={isDynDNS}
                      >
                        <span className="toggle-knob" />
                      </button>
                    </div>
                  </div>
                </div>
              </section>

              {isDynDNS && (
                <>
                  {/* ── Hostname ──────────────────────────────── */}
                  <section className="drawer-section">
                    <div className="section-head">
                      <span className="section-label">HOSTNAME</span>
                    </div>

                    <label className="ap-label">DynDNS hostname</label>
                    <div style={{ display: 'flex', gap: 8 }}>
                      <input
                        className="ap-input mono"
                        style={{ flex: 1 }}
                        placeholder="myhome.duckdns.org"
                        value={cfg?.hostname || ''}
                        onChange={e => { set('hostname', e.target.value); setResolveResult(null); }}
                      />
                      <TestButton resolving={resolving} resolveResult={resolveResult} onResolve={resolve} hasHostname={!!cfg?.hostname} />
                    </div>

                    {resolveResult && (
                      <div style={{ marginTop: 8 }}>
                        <label className="ap-label">Resolved IP</label>
                        <input
                          className="ap-input mono"
                          readOnly
                          value={resolveResult.ok ? resolveResult.ip : resolveResult.error}
                          style={{ cursor: 'default', pointerEvents: 'none' }}
                        />
                      </div>
                    )}

                    <div className="ap-hint">
                      This hostname is written into every generated peer .conf as the Endpoint.
                    </div>
                  </section>

                  {/* ── Auto-update provider ──────────────────── */}
                  <section className="drawer-section">
                    <div className="section-head">
                      <span className="section-label">AUTO-UPDATE PROVIDER</span>
                      <span className="section-meta">optional</span>
                    </div>

                    <div className="settings-list">
                      <div className="setting-row" style={{ paddingTop: 4 }}>
                        <div>
                          <div className="setting-title">Provider</div>
                          <div className="setting-desc">Push your current IP to the provider on demand</div>
                        </div>
                        <div className="setting-control">
                          <select
                            className="select-input"
                            style={{ fontSize: 13, padding: '8px 12px' }}
                            value={cfg?.provider || ''}
                            onChange={e => set('provider', e.target.value || null)}
                          >
                            <option value="">None</option>
                            {DYNDNS_PROVIDERS.map(p => (
                              <option key={p.id} value={p.id} disabled={!!p.disabled}>
                                {p.label}{p.site ? ` · ${p.site}` : ''}{p.disabled ? ' (coming soon)' : ''}
                              </option>
                            ))}
                          </select>
                        </div>
                      </div>
                    </div>

                    {cfg?.provider && cfg.provider !== 'custom' && (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 14, marginTop: 14 }}>
                        <div>
                          <label className="ap-label">{providerInfo?.domainLabel || 'Domain'}</label>
                          <input
                            className="ap-input mono"
                            placeholder={providerInfo?.domainHelp || ''}
                            value={cfg?.domain || ''}
                            onChange={e => set('domain', e.target.value)}
                          />
                          {providerInfo?.domainHelp && (
                            <div className="ap-hint">{providerInfo.domainHelp}</div>
                          )}
                        </div>
                        <div>
                          <label className="ap-label">{providerInfo?.tokenLabel || 'Token'}</label>
                          <input
                            className="ap-input mono"
                            type="password"
                            autoComplete="new-password"
                            placeholder={cfg?.has_token ? '••••  (saved)' : providerInfo?.tokenHelp || ''}
                            value={cfg?.token || ''}
                            onChange={e => { set('token', e.target.value); setTokenDirty(true); }}
                          />
                          {providerInfo?.tokenHelp && (
                            <div className="ap-hint">{providerInfo.tokenHelp}</div>
                          )}
                        </div>
                      </div>
                    )}

                    {cfg?.provider === 'custom' && (
                      <div style={{ marginTop: 14 }}>
                        <label className="ap-label">Update URL</label>
                        <input
                          className="ap-input mono"
                          placeholder="https://example.com/update?ip={ip}"
                          value={cfg?.custom_url || ''}
                          onChange={e => set('custom_url', e.target.value)}
                        />
                        <div className="ap-hint">
                          Use <code style={{ fontFamily: 'var(--mono)', background: 'var(--bg-2)', padding: '0 3px', borderRadius: 3 }}>{'{ip}'}</code> — replaced with the server's current public IP.
                        </div>
                      </div>
                    )}

                    {cfg?.provider && (
                      <div style={{ marginTop: 16 }}>
                        <div className="settings-list">
                          <div className="setting-row" style={{ paddingTop: 4 }}>
                            <div>
                              <div className="setting-title">Update record now</div>
                              <div className="setting-desc">Push the server's current public IP to your provider</div>
                            </div>
                            <div className="setting-control">
                              <button className="btn btn-ghost" onClick={updateNow} disabled={updating}>
                                {updating
                                  ? <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" style={{ animation: 'spin 1s linear infinite' }}><path d="M21 12a9 9 0 11-18 0"/></svg>
                                  : <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M21 2v6h-6M3 12a9 9 0 0115-6.7L21 8M3 22v-6h6M21 12a9 9 0 01-15 6.7L3 16"/></svg>
                                }
                                {updating ? 'Updating…' : 'Push now'}
                              </button>
                            </div>
                          </div>
                        </div>

                        {updateResult && (
                          <div style={{
                            marginTop: 8, fontSize: 12, padding: '7px 10px', borderRadius: 7,
                            background: updateResult.ok ? 'var(--success-soft, rgba(34,197,94,.1))' : 'var(--danger-soft, rgba(239,68,68,.1))',
                            color: updateResult.ok ? 'var(--success, #22c55e)' : 'var(--danger, #ef4444)',
                            display: 'flex', alignItems: 'center', gap: 6,
                          }}>
                            {updateResult.ok ? (
                              <>
                                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M5 12l5 5L20 7"/></svg>
                                Provider: <span style={{ fontFamily: 'var(--mono)' }}>{updateResult.response}</span>
                              </>
                            ) : (
                              <>
                                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M18 6L6 18M6 6l12 12"/></svg>
                                {updateResult.error}
                              </>
                            )}
                          </div>
                        )}
                      </div>
                    )}
                  </section>

                  {/* ── Free providers (collapsible) ───────────── */}
                  <section className="drawer-section">
                    <Collapsible
                      icon={
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
                          <circle cx="12" cy="12" r="9"/>
                          <path d="M2 12h20M12 2a15.3 15.3 0 010 20M12 2a15.3 15.3 0 000 20"/>
                        </svg>
                      }
                      title="Free DynDNS providers"
                      summary="Duck DNS · No-IP · Dynu"
                      open={providersOpen}
                      onToggle={() => setProvidersOpen(o => !o)}
                    >
                      <div className="set-stats">
                        {[
                          { name: 'Duck DNS', url: 'duckdns.org',       note: 'Free forever, no expiry' },
                          { name: 'No-IP',    url: 'noip.com',          note: 'Free tier, monthly confirm' },
                          { name: 'Dynu',     url: 'dynu.com',          note: 'Free forever, no expiry' },
                        ].map(p => (
                          <div className="set-stat" key={p.name}>
                            <div className="set-stat-label">{p.name}</div>
                            <div className="set-stat-val mono">{p.url}</div>
                            <div style={{ fontSize: 10, color: 'var(--muted)', marginTop: 3 }}>{p.note}</div>
                          </div>
                        ))}
                      </div>
                      <div className="ap-hint" style={{ marginTop: 0 }}>
                        Register a hostname at your chosen provider, point it at your server's IP, then configure the provider above. Hit <strong>Push now</strong> whenever your IP changes.
                      </div>
                    </Collapsible>
                  </section>
                </>
              )}

            </>
          )}
        </div>

        {/* ── Sticky footer ────────────────────────────── */}
        <footer className="ap-foot">
          <span style={{ fontSize: 12, color: 'var(--muted)', fontFamily: 'var(--mono)' }}>
            {!loading && (isDynDNS
              ? (cfg?.hostname || 'no hostname set')
              : 'static public ip')}
          </span>
          <button
            className="btn btn-primary"
            onClick={save}
            disabled={saving || loading}
          >
            {saving
              ? <><span className="pc-spinner" style={{ width: 12, height: 12 }} />Saving…</>
              : <><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M5 12l5 5L20 7"/></svg>Save settings</>
            }
          </button>
        </footer>

      </aside>
    </>
  );
}

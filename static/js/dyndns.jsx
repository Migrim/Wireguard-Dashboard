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
    domainPh: 'myhome',
  },
  {
    id: 'noip',
    label: 'No-IP',
    site: 'noip.com',
    tokenHelp: 'username:password (colon-separated)',
    domainHelp: 'Full hostname — e.g. myhome.ddns.net',
    tokenLabel: 'Credentials',
    domainLabel: 'Hostname',
    domainPh: 'myhome.ddns.net',
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
    domainPh: 'myhome.freeddns.org',
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

function ddTimeAgo(ts) {
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (s < 60) return 'just now';
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  if (d < 30) return `${d}d ago`;
  return new Date(ts * 1000).toLocaleDateString();
}

const ddSpinner = (size = 13) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" style={{ animation: 'spin 1s linear infinite' }}><path d="M21 12a9 9 0 11-18 0"/></svg>
);

function DynDNSDrawer({ onClose }) {
  const Collapsible = window.Collapsible;

  const [cfg, setCfg]               = uSD(null);
  const [loading, setLoading]       = uSD(true);
  const [saving, setSaving]         = uSD(false);
  const [dirty, setDirty]           = uSD(false);
  const [tokenDirty, setTokenDirty] = uSD(false);
  const [providersOpen, setProvidersOpen] = uSD(false);
  const [tokenRevealed, setTokenRevealed] = uSD(false);
  const [revealingToken, setRevealingToken] = uSD(false);

  const [resolveResult, setResolveResult] = uSD(null);
  const [resolving, setResolving]         = uSD(false);

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

  const set = (key, val) => { setCfg(prev => ({ ...prev, [key]: val })); setDirty(true); };

  const providerInfo = DYNDNS_PROVIDERS.find(p => p.id === cfg?.provider);
  const isDynDNS     = cfg?.mode === 'dyndns';
  const hostname     = (cfg?.hostname || '').trim();
  const publicIp     = cfg?.public_ip || '';
  const lastUpdate   = cfg?.last_update || null;

  // Is the auto-update provider fully filled in?
  const providerConfigured = !!cfg?.provider && (
    cfg.provider === 'custom'
      ? !!(cfg.custom_url || '').trim()
      : !!(cfg.domain || '').trim() && (cfg.has_token || (tokenDirty && !!(cfg.token || '').trim()))
  );

  const resolve = uCD(async (host) => {
    setResolving(true);
    try {
      const r = await window.WG.apiCall('/api/dyndns/resolve', {
        method: 'POST',
        body: JSON.stringify({ hostname: host }),
        silent: true,
      });
      // The server re-detects its own public IP on every check, so the
      // sync comparison never uses a stale boot-time snapshot.
      if (r.public_ip) setCfg(prev => prev ? { ...prev, public_ip: r.public_ip, public_ip_source: r.public_ip_source || prev.public_ip_source } : prev);
      setResolveResult({ ok: true, ip: r.ip, host });
    } catch (e) {
      setResolveResult({ ok: false, error: e?.message || 'Resolution failed', host });
    } finally {
      setResolving(false);
    }
  }, []);

  // Live check: resolve the hostname on open and (debounced) while typing,
  // so the sync status is always visible without pressing a button.
  uED(() => {
    if (loading || !isDynDNS) return;
    if (!hostname) { setResolveResult(null); return; }
    const t = setTimeout(() => resolve(hostname), resolveResult ? 650 : 0);
    return () => clearTimeout(t);
  }, [hostname, isDynDNS, loading]);

  const persist = uCD(async () => {
    if (!cfg) return;
    const body = { ...cfg };
    if (!tokenDirty) delete body.token;
    await window.WG.apiCall('/api/dyndns', { method: 'POST', body: JSON.stringify(body), silent: true });
  }, [cfg, tokenDirty]);

  const save = uCD(async () => {
    if (!cfg) return;
    setSaving(true);
    try {
      await persist();
      setDirty(false);
      window.WG.toast?.success?.('Saved', 'DynDNS settings updated');
    } catch (e) {
      window.WG.toast?.error?.('Save failed', e?.message || 'Unknown error');
    } finally {
      setSaving(false);
    }
  }, [persist]);

  const updateNow = uCD(async () => {
    setUpdating(true);
    try {
      await persist();
      setDirty(false);
      const r = await window.WG.apiCall('/api/dyndns/update', { method: 'POST', silent: true });
      setCfg(prev => ({
        ...prev,
        public_ip: r.record_ip || prev?.public_ip,
        public_ip_source: r.record_ip ? `${providerInfo?.label || prev?.provider} update reply` : prev?.public_ip_source,
        last_update: {
          ts: Math.floor(Date.now() / 1000), ok: true, ip: r.ip, provider: prev?.provider, detail: r.response || '',
        },
      }));
      const lines = [`Provider: ${providerInfo?.label || cfg?.provider}`];
      if (r.domain) lines.push(`Domain: ${r.domain}`);
      if (r.record_ip) lines.push(`Record now points to: ${r.record_ip}`);
      else if (r.ip) lines.push(`Public IP: ${r.ip}`);
      if (r.response) lines.push(`Response: ${r.response}`);
      window.WG.toast?.success?.('DynDNS record updated', lines.join('\n'));
      if (hostname) resolve(hostname);
    } catch (e) {
      const msg = e?.message || 'Update failed';
      setCfg(prev => ({ ...prev, last_update: {
        ts: Math.floor(Date.now() / 1000), ok: false, ip: publicIp, provider: prev?.provider, detail: msg,
      }}));
      window.WG.toast?.error?.('DynDNS update failed', [`Provider: ${providerInfo?.label || cfg?.provider || 'none'}`, msg].join('\n'));
    } finally {
      setUpdating(false);
    }
  }, [persist, providerInfo, cfg?.provider, hostname, publicIp, resolve]);

  const toggleReveal = uCD(async () => {
    if (tokenRevealed) { setTokenRevealed(false); return; }
    if (tokenDirty) { setTokenRevealed(true); return; }
    setRevealingToken(true);
    try {
      const r = await window.WG.apiCall('/api/dyndns/token');
      setCfg(prev => ({ ...prev, token: r.token || '' }));
      setTokenRevealed(true);
    } catch (e) {
      window.WG.toast?.error?.('Reveal failed', e?.message || 'Unknown error');
    } finally {
      setRevealingToken(false);
    }
  }, [tokenRevealed, tokenDirty]);

  // ── Overall status for the hero card ─────────────────
  const status = (() => {
    if (!isDynDNS) return {
      level: 'idle', icon: 'globe',
      title: 'Static public IP mode',
      sub: publicIp ? `Peers connect to ${publicIp}` : 'Peers connect via the server’s public IP',
    };
    if (!hostname) return {
      level: 'warn', icon: 'warn',
      title: 'Hostname required',
      sub: 'Enter your DynDNS hostname below to get started',
    };
    if (resolving || !resolveResult) return {
      level: 'busy', icon: 'spinner',
      title: 'Checking hostname…',
      sub: hostname,
    };
    if (!resolveResult.ok) return {
      level: 'fail', icon: 'fail',
      title: 'Hostname doesn’t resolve',
      sub: resolveResult.error,
    };
    if (publicIp && resolveResult.ip !== publicIp) return {
      level: 'warn', icon: 'warn',
      title: 'Out of sync',
      sub: `${hostname} → ${resolveResult.ip} · server is ${publicIp}`,
    };
    return {
      level: 'ok', icon: 'ok',
      title: 'In sync — everything working',
      sub: `${hostname} → ${resolveResult.ip}`,
    };
  })();

  const statusIcon = {
    ok:      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4"><path d="M5 12l5 5L20 7"/></svg>,
    warn:    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 8v5M12 16.8v.2"/><path d="M10.3 3.9L1.8 18.5a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z"/></svg>,
    fail:    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4"><path d="M18 6L6 18M6 6l12 12"/></svg>,
    spinner: ddSpinner(15),
    globe:   <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><circle cx="12" cy="12" r="9"/><path d="M2 12h20M12 2a15.3 15.3 0 010 20M12 2a15.3 15.3 0 000 20"/></svg>,
  }[status.icon];

  const heroClass = { ok: 'dd-ok', warn: 'dd-warn', fail: 'dd-fail' }[status.level] || '';

  // One-line field status under the hostname input (single source of
  // truth for resolve feedback — the hero shows only the overall state).
  const hostnameStatus = !hostname ? null
    : resolving ? (
      <div className="dd-field-status">{ddSpinner(11)}<span>resolving…</span></div>
    ) : resolveResult?.ok ? (
      publicIp && resolveResult.ip === publicIp ? (
        <div className="dd-field-status ok"><span className="dd-dot ok" /><span>resolves to {resolveResult.ip} — matches this server</span></div>
      ) : (
        <div className="dd-field-status warn"><span className="dd-dot warn" /><span>
          resolves to {resolveResult.ip}{publicIp ? ` — server IP is ${publicIp}` : ''}
          {lastUpdate?.ok && (Date.now() / 1000 - lastUpdate.ts) < 180 ? ' · just pushed, DNS can lag ~1 min' : ''}
        </span></div>
      )
    ) : resolveResult ? (
      <div className="dd-field-status fail"><span className="dd-dot fail" /><span>{resolveResult.error}</span></div>
    ) : null;

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
                  ? (hostname || 'No hostname set')
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
              <div className="skel" style={{ height: 96, width: '100%', borderRadius: 12 }} />
              <div className="skel" style={{ height: 60, width: '100%', borderRadius: 8, marginTop: 24 }} />
            </section>
          ) : (
            <>

              {/* ── Status overview ──────────────────────────── */}
              <section className="drawer-section">
                <div className="section-head">
                  <span className="section-label">STATUS</span>
                  {isDynDNS && hostname && (
                    <button
                      className="icon-btn"
                      style={{ width: 24, height: 24 }}
                      onClick={() => resolve(hostname)}
                      disabled={resolving}
                      aria-label="Re-check hostname"
                      title="Re-check hostname"
                    >
                      {resolving
                        ? ddSpinner(12)
                        : <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M21 2v6h-6M3 12a9 9 0 0115-6.7L21 8M3 22v-6h6M21 12a9 9 0 01-15 6.7L3 16"/></svg>}
                    </button>
                  )}
                </div>

                <div className={`dd-hero ${heroClass}`}>
                  <div className="dd-hero-status">
                    <div className="dd-status-icon">{statusIcon}</div>
                    <div className="dd-hero-text">
                      <div className="dd-hero-title">{status.title}</div>
                      <div className="dd-hero-sub">{status.sub}</div>
                    </div>
                  </div>

                  {isDynDNS && (
                    <div className="dd-stats">
                      <div className="dd-stat">
                        <div className="dd-stat-label">Server public IP</div>
                        <div className={`dd-stat-val ${publicIp ? '' : 'is-muted'}`}>
                          {publicIp || 'unknown'}
                        </div>
                        {cfg?.public_ip_source && (
                          <div className="dd-stat-src" title={`Detected via ${cfg.public_ip_source}`}>
                            via {cfg.public_ip_source}
                          </div>
                        )}
                      </div>
                      <div className="dd-stat">
                        <div className="dd-stat-label">Auto-update</div>
                        <div className={`dd-stat-val ${cfg?.provider ? '' : 'is-muted'}`}>
                          {!cfg?.provider
                            ? 'manual'
                            : !providerConfigured
                              ? <><span className="dd-dot warn" />{providerInfo?.label || cfg.provider} · incomplete</>
                              : lastUpdate
                                ? <><span className={`dd-dot ${lastUpdate.ok ? 'ok' : 'fail'}`} />{providerInfo?.label || cfg.provider} · {ddTimeAgo(lastUpdate.ts)}</>
                                : <><span className="dd-dot" />{providerInfo?.label || cfg.provider} · never pushed</>}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </section>

              {/* ── Endpoint: mode toggle + hostname ─────────── */}
              <section className="drawer-section">
                <div className="section-head">
                  <span className="section-label">ENDPOINT</span>
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

                {isDynDNS && (
                  <div style={{ marginTop: 6 }}>
                    <label className="ap-label">Hostname</label>
                    <input
                      className="ap-input mono"
                      placeholder="myhome.duckdns.org"
                      value={cfg?.hostname || ''}
                      onChange={e => set('hostname', e.target.value)}
                    />
                    {hostnameStatus}
                    <div className="ap-hint">
                      Written into every generated peer .conf as the Endpoint.
                    </div>
                  </div>
                )}
              </section>

              {isDynDNS && (
                <>
                  {/* ── Auto-update provider ──────────────────── */}
                  <section className="drawer-section">
                    <div className="section-head">
                      <span className="section-label">AUTO-UPDATE</span>
                      {cfg?.provider && !providerConfigured
                        ? <span className="dd-conf-pill warn">INCOMPLETE</span>
                        : !cfg?.provider && <span className="section-meta">optional</span>}
                    </div>

                    <label className="ap-label">Provider</label>
                    <select
                      className="select-input dd-provider-select"
                      value={cfg?.provider || ''}
                      onChange={e => set('provider', e.target.value || null)}
                    >
                      <option value="">None — update the record yourself</option>
                      {DYNDNS_PROVIDERS.map(p => (
                        <option key={p.id} value={p.id} disabled={!!p.disabled}>
                          {p.label}{p.site ? ` · ${p.site}` : ''}{p.disabled ? ' (coming soon)' : ''}
                        </option>
                      ))}
                    </select>

                    {cfg?.provider && cfg.provider !== 'custom' && (
                      <div className="dd-provider-fields">
                        <div>
                          <label className="ap-label">{providerInfo?.domainLabel || 'Domain'}</label>
                          <input
                            className="ap-input mono"
                            placeholder={providerInfo?.domainPh || ''}
                            value={cfg?.domain || ''}
                            onChange={e => set('domain', e.target.value)}
                          />
                          {providerInfo?.domainHelp && (
                            <div className="ap-hint">{providerInfo.domainHelp}</div>
                          )}
                        </div>
                        <div>
                          <label className="ap-label">
                            {providerInfo?.tokenLabel || 'Token'}
                            {cfg?.has_token && !tokenDirty && <span className="ap-label-opt">saved</span>}
                          </label>
                          <div className="ap-input-wrap">
                            <input
                              className="ap-input mono"
                              type={tokenRevealed ? 'text' : 'password'}
                              autoComplete="new-password"
                              placeholder={cfg?.has_token ? '••••  (saved)' : '••••'}
                              value={cfg?.token || ''}
                              onChange={e => { set('token', e.target.value); setTokenDirty(true); }}
                            />
                            {(cfg?.has_token || tokenDirty) && (
                              <button
                                type="button"
                                className="login-eye"
                                onClick={toggleReveal}
                                disabled={revealingToken}
                                tabIndex={-1}
                                aria-label={tokenRevealed ? 'Hide token' : 'Show token'}
                                title={tokenRevealed ? 'Hide token' : 'Show token'}
                              >
                                {revealingToken ? (
                                  ddSpinner(14)
                                ) : tokenRevealed ? (
                                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M17.94 17.94A10.94 10.94 0 0112 20c-5.5 0-9.4-3.7-10.9-8 .58-1.6 1.5-3.1 2.7-4.32M9.9 4.24A10.9 10.9 0 0112 4c5.5 0 9.4 3.7 10.9 8a12.9 12.9 0 01-2.36 3.9M14.12 14.12a3 3 0 11-4.24-4.24"/><path d="M1 1l22 22"/></svg>
                                ) : (
                                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                                )}
                              </button>
                            )}
                          </div>
                          {providerInfo?.tokenHelp && (
                            <div className="ap-hint">{providerInfo.tokenHelp}</div>
                          )}
                        </div>
                      </div>
                    )}

                    {cfg?.provider === 'custom' && (
                      <div className="dd-provider-fields">
                        <div>
                          <label className="ap-label">Update URL</label>
                          <input
                            className="ap-input mono"
                            placeholder="https://example.com/update?ip={ip}"
                            value={cfg?.custom_url || ''}
                            onChange={e => set('custom_url', e.target.value)}
                          />
                          <div className="ap-hint">
                            Use <code className="dd-code">{'{ip}'}</code> — replaced with the server's current public IP.
                          </div>
                        </div>
                      </div>
                    )}

                    {cfg?.provider && (
                      <div className="dd-push-row">
                        <div className="dd-push-info">
                          {lastUpdate ? (
                            <div className={`dd-field-status ${lastUpdate.ok ? 'ok' : 'fail'}`} style={{ marginTop: 0 }}>
                              <span className={`dd-dot ${lastUpdate.ok ? 'ok' : 'fail'}`} />
                              <span>
                                last push {ddTimeAgo(lastUpdate.ts)}
                                {lastUpdate.ok
                                  ? (lastUpdate.ip ? ` · ${lastUpdate.ip}` : '')
                                  : ` · failed${lastUpdate.detail ? `: ${lastUpdate.detail}` : ''}`}
                              </span>
                            </div>
                          ) : (
                            <div className="dd-field-status" style={{ marginTop: 0 }}>
                              <span className="dd-dot" />
                              <span>never pushed — sends your current IP to {providerInfo?.label || 'the provider'}</span>
                            </div>
                          )}
                        </div>
                        <button className="btn btn-ghost" onClick={updateNow} disabled={updating || !providerConfigured}>
                          {updating
                            ? ddSpinner(14)
                            : <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M21 2v6h-6M3 12a9 9 0 0115-6.7L21 8M3 22v-6h6M21 12a9 9 0 01-15 6.7L3 16"/></svg>
                          }
                          {updating ? 'Updating…' : 'Push now'}
                        </button>
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
          <span className="dd-foot-note">
            {!loading && dirty && <><span className="dd-dot warn" />unsaved changes</>}
          </span>
          <button
            className="btn btn-primary"
            onClick={save}
            disabled={saving || loading || !dirty}
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

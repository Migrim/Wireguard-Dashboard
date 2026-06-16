// PeerSettings — editable settings for an existing peer, shown in the peer
// drawer's Settings tab. Mirrors the Add Peer drawer controls, split into:
//   "Applies instantly"  — server-side/metadata only. Saved immediately.
//   "Changes device config" — lives in the .conf. Editing marks the peer
//                             out-of-sync and surfaces a re-provision banner.

const { useState: pS, useEffect: pE, useMemo: pM, useRef: pR } = React;

const PS_ICONS = {
  tag:    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><path d="M20.6 14.6l-7 7a2 2 0 01-2.8 0L3 13.8V3h10.8l7.8 7.8a2 2 0 010 2.8z"/><circle cx="7.5" cy="7.5" r="1.5"/></svg>,
  clock:  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></svg>,
  gauge:  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><path d="M17 3l4 4-4 4M21 7H8"/><path d="M7 21l-4-4 4-4M3 17h13"/></svg>,
  dns:    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14c0 1.7 4 3 9 3s9-1.3 9-3V5"/><path d="M3 12c0 1.7 4 3 9 3s9-1.3 9-3"/></svg>,
  tune:   <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><path d="M4 6h16M4 12h16M4 18h16"/><circle cx="8" cy="6" r="2"/><circle cx="16" cy="12" r="2"/><circle cx="10" cy="18" r="2"/></svg>,
  key:    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><circle cx="7.5" cy="15.5" r="5.5"/><path d="M21 2l-9.6 9.6M15.5 7.5l3 3"/></svg>,
  script: <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>,
  route:  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><circle cx="6" cy="19" r="2.5"/><circle cx="18" cy="5" r="2.5"/><path d="M8 17.5 16 6.5M6 16.5V12a4 4 0 0 1 4-4h4"/></svg>,
};

function routingPresetFromAllowedIps(clientAllowedIps) {
  if (!clientAllowedIps || clientAllowedIps === '0.0.0.0/0, ::/0' || clientAllowedIps === '0.0.0.0/0,::/0') return 'all';
  return 'split';
}

function normalizeEndpoint(ep) {
  return ep && ep.includes(':') ? ep : 'vpn.example.com:51820';
}

function PeerSettings({ peer, onDirtyChange, onPeerUpdated }) {
  const seeds = pM(() => ({
    routingPreset: routingPresetFromAllowedIps(peer.clientAllowedIps),
    allowedIps: peer.clientAllowedIps || '0.0.0.0/0, ::/0',
    dns: peer.dns || '1.1.1.1, 1.0.0.1',
    searchDomains: '',
    blockAds: false,
    endpoint: normalizeEndpoint(peer.endpoint),
    mtu: '1420',
    keepalive: (peer.keepalive && peer.keepalive !== '0') ? String(peer.keepalive) : '25',
    listenPort: '',
    table: 'auto',
    fwmark: '',
    preUp: '', postUp: '', preDown: '', postDown: '',
    usePsk: false,
    rekeyed: false,
    note: peer.note || '',
    owner: peer.owner || '',
    longNote: peer.longNote || '',
  }), [peer.name]);

  // Config-group state (lives in the .conf — needs re-import)
  const [routingPreset, setRoutingPreset] = pS(seeds.routingPreset);
  const [allowedIps, setAllowedIps] = pS(seeds.allowedIps);
  const [dns, setDns] = pS(seeds.dns);
  const [searchDomains, setSearchDomains] = pS(seeds.searchDomains);
  const [blockAds, setBlockAds] = pS(seeds.blockAds);
  const [endpoint, setEndpoint] = pS(seeds.endpoint);
  const [mtu, setMtu] = pS(seeds.mtu);
  const [keepalive, setKeepalive] = pS(seeds.keepalive);
  const [listenPort, setListenPort] = pS(seeds.listenPort);
  const [table, setTable] = pS(seeds.table);
  const [fwmark, setFwmark] = pS(seeds.fwmark);
  const [preUp, setPreUp] = pS(seeds.preUp);
  const [postUp, setPostUp] = pS(seeds.postUp);
  const [preDown, setPreDown] = pS(seeds.preDown);
  const [postDown, setPostDown] = pS(seeds.postDown);
  const [usePsk, setUsePsk] = pS(seeds.usePsk);
  const [rekeyed, setRekeyed] = pS(false);
  const [keys, setKeys] = pS(() => ({
    privateKey: window.randKey(),
    publicKey: peer.pubKey || window.randKey(),
    presharedKey: window.randKey(),
  }));

  // Server-side / instant state
  const [note, setNote] = pS(seeds.note);
  const [owner, setOwner] = pS(seeds.owner);
  const [longNote, setLongNote] = pS(seeds.longNote);
  const [expiry, setExpiry] = pS('never');
  const [disableIdle, setDisableIdle] = pS(false);
  const [idleDays, setIdleDays] = pS('30');
  const [dataCap, setDataCap] = pS('');
  const [rateDown, setRateDown] = pS('');
  const [rateUp, setRateUp] = pS('');

  // Saved baseline for dirty detection
  function snapshotConfig(src) {
    return {
      routingPreset: src.routingPreset,
      allowedIps: src.allowedIps,
      dns: src.dns,
      searchDomains: src.searchDomains || '',
      blockAds: src.blockAds || false,
      endpoint: src.endpoint,
      mtu: src.mtu,
      keepalive: src.keepalive,
      listenPort: src.listenPort || '',
      table: src.table || 'auto',
      fwmark: src.fwmark || '',
      preUp: src.preUp || '', postUp: src.postUp || '',
      preDown: src.preDown || '', postDown: src.postDown || '',
      usePsk: src.usePsk || false,
      rekeyed: src.rekeyed || false,
    };
  }
  const [saved, setSaved] = pS(() => snapshotConfig(seeds));

  // Reset all state when switching peers — restore any saved draft
  pE(() => {
    let draft = null;
    try { draft = JSON.parse(localStorage.getItem('WG_PEER_DRAFT_' + peer.name) || 'null'); } catch (_) {}
    const base = draft || seeds;
    setRoutingPreset(base.routingPreset ?? seeds.routingPreset); setAllowedIps(base.allowedIps ?? seeds.allowedIps);
    setDns(base.dns ?? seeds.dns); setSearchDomains(base.searchDomains || ''); setBlockAds(base.blockAds || false);
    setEndpoint(base.endpoint ?? seeds.endpoint); setMtu(base.mtu || '1420'); setKeepalive(base.keepalive ?? seeds.keepalive); setListenPort(base.listenPort || '');
    setTable(base.table || 'auto'); setFwmark(base.fwmark || ''); setPreUp(base.preUp || ''); setPostUp(base.postUp || ''); setPreDown(base.preDown || ''); setPostDown(base.postDown || '');
    setUsePsk(base.usePsk || false); setRekeyed(base.rekeyed || false);
    setKeys(draft?.keys || { privateKey: window.randKey(), publicKey: peer.pubKey || window.randKey(), presharedKey: window.randKey() });
    setNote(seeds.note); setOwner(seeds.owner); setLongNote(seeds.longNote);
    setExpiry('never'); setDisableIdle(false); setIdleDays('30');
    setDataCap(''); setRateDown(''); setRateUp('');
    setSaved(snapshotConfig(seeds));
  }, [peer.name]);

  const [openSection, setOpenSection] = pS({});
  const toggle = (id) => setOpenSection((s) => ({ ...s, [id]: !s[id] }));

  const [copied, setCopied] = pS('');
  const copy = (val, key) => {
    navigator.clipboard?.writeText(val);
    setCopied(key);
    setTimeout(() => setCopied(''), 1400);
  };

  const current = {
    routingPreset, allowedIps, dns, searchDomains, blockAds,
    endpoint, mtu, keepalive, listenPort, table, fwmark,
    preUp, postUp, preDown, postDown, usePsk, rekeyed,
  };

  const changedLabels = (() => {
    const out = [];
    if (current.routingPreset !== saved.routingPreset || current.allowedIps !== saved.allowedIps) out.push('Allowed IPs');
    if (current.dns !== saved.dns || current.searchDomains !== saved.searchDomains || current.blockAds !== saved.blockAds) out.push('DNS');
    if (current.endpoint !== saved.endpoint) out.push('Endpoint');
    if (current.mtu !== saved.mtu) out.push('MTU');
    if (current.keepalive !== saved.keepalive) out.push('Keepalive');
    if (current.listenPort !== saved.listenPort) out.push('Listen port');
    if (current.table !== saved.table || current.fwmark !== saved.fwmark) out.push('Routing table');
    if (current.preUp !== saved.preUp || current.postUp !== saved.postUp ||
        current.preDown !== saved.preDown || current.postDown !== saved.postDown) out.push('Hooks');
    if (current.usePsk !== saved.usePsk) out.push('Pre-shared key');
    if (current.rekeyed !== saved.rekeyed) out.push('New keypair');
    return out;
  })();
  const dirty = changedLabels.length > 0;

  pE(() => { onDirtyChange?.(dirty); }, [dirty]);

  pE(() => {
    const key = 'WG_PEER_DRAFT_' + peer.name;
    if (!dirty) { localStorage.removeItem(key); return; }
    try { localStorage.setItem(key, JSON.stringify({ ...current, keys })); } catch (_) {}
  }, [dirty, routingPreset, allowedIps, dns, searchDomains, blockAds, endpoint, mtu, keepalive, listenPort, table, fwmark, preUp, postUp, preDown, postDown, usePsk, rekeyed, keys]);

  // Instant-save flash
  const [flash, setFlash] = pS(false);
  const flashRef = pR(null);
  const [saving, setSaving] = pS(false);
  const [saveMsg, setSaveMsg] = pS('');

  const [showQr, setShowQr] = pS(false);
  const [qrUrl, setQrUrl] = pS('');

  const instantSave = async (patch) => {
    setSaving(true);
    setSaveMsg('');
    try {
      await window.WG.apiCall('/api/users/' + encodeURIComponent(peer.name) + '/settings', {
        method: 'PATCH',
        body: JSON.stringify(patch),
      });
      setFlash(true);
      clearTimeout(flashRef.current);
      flashRef.current = setTimeout(() => setFlash(false), 1700);
      if (onPeerUpdated) onPeerUpdated();
    } catch (e) {
      setSaveMsg('Error: ' + (e.message || 'save failed'));
      setTimeout(() => setSaveMsg(''), 3000);
    } finally {
      setSaving(false);
    }
  };

  // Config preview using the buildConfig helper from addpeer.jsx
  const previewConfig = window.buildConfig({
    name: peer.name,
    address: peer.addr,
    dns: blockAds ? '10.7.0.1' : dns,
    searchDomains, mtu, keepalive, listenPort,
    table, fwmark, preUp, postUp, preDown, postDown,
    endpoint,
    allowedIps: routingPreset === 'all' ? '0.0.0.0/0, ::/0' : allowedIps,
    presharedKey: usePsk ? keys.presharedKey : '',
    privateKey: rekeyed ? keys.privateKey : '‹kept on device — unchanged›',
    serverPubKey: peer.pubKey || '(server public key)',
  });

  const [showPreview, setShowPreview] = pS(false);
  const [provisioning, setProvisioning] = pS(false);

  pE(() => {
    if (!showQr || !previewConfig || !window.QRious) { if (!showQr) setQrUrl(''); return; }
    try {
      const qr = new window.QRious({ value: previewConfig, size: 200, level: 'L' });
      setQrUrl(qr.toDataURL());
    } catch (_) {}
  }, [showQr, previewConfig]);

  // Build the API patch for config-group fields that have server support
  function buildConfigPatch() {
    const patch = {};
    if (current.dns !== saved.dns || current.blockAds !== saved.blockAds) {
      patch.dns = blockAds ? '10.7.0.1' : dns;
    }
    if (current.routingPreset !== saved.routingPreset || current.allowedIps !== saved.allowedIps) {
      patch.client_allowed_ips = routingPreset === 'split' ? allowedIps : '';
    }
    if (current.keepalive !== saved.keepalive) {
      const ka = parseInt(keepalive, 10);
      if (!isNaN(ka)) patch.keepalive = ka;
    }
    return patch;
  }

  const downloadConfig = async () => {
    setProvisioning(true);
    try {
      const patch = buildConfigPatch();
      if (Object.keys(patch).length > 0) {
        await window.WG.apiCall('/api/users/' + encodeURIComponent(peer.name) + '/settings', {
          method: 'PATCH',
          body: JSON.stringify(patch),
        });
      }
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
      alert('Failed to download: ' + (e.message || 'API error'));
    } finally {
      setProvisioning(false);
    }
  };

  const markReprovisioned = async () => {
    setSaving(true);
    setSaveMsg('');
    try {
      const patch = buildConfigPatch();
      if (Object.keys(patch).length > 0) {
        await window.WG.apiCall('/api/users/' + encodeURIComponent(peer.name) + '/settings', {
          method: 'PATCH',
          body: JSON.stringify(patch),
        });
        if (onPeerUpdated) onPeerUpdated();
      }
      localStorage.removeItem('WG_PEER_DRAFT_' + peer.name);
      setSaved(snapshotConfig(current));
      setShowPreview(false);
    } catch (e) {
      setSaveMsg('Error: ' + (e.message || 'save failed'));
      setTimeout(() => setSaveMsg(''), 3000);
    } finally {
      setSaving(false);
    }
  };

  const revert = () => {
    localStorage.removeItem('WG_PEER_DRAFT_' + peer.name);
    setRoutingPreset(saved.routingPreset); setAllowedIps(saved.allowedIps);
    setDns(saved.dns); setSearchDomains(saved.searchDomains); setBlockAds(saved.blockAds);
    setEndpoint(saved.endpoint); setMtu(saved.mtu); setKeepalive(saved.keepalive); setListenPort(saved.listenPort);
    setTable(saved.table); setFwmark(saved.fwmark);
    setPreUp(saved.preUp); setPostUp(saved.postUp); setPreDown(saved.preDown); setPostDown(saved.postDown);
    setUsePsk(saved.usePsk); setRekeyed(saved.rekeyed);
    setShowPreview(false); setShowQr(false);
  };

  const rekey = () => {
    setKeys({ privateKey: window.randKey(), publicKey: window.randKey(), presharedKey: keys.presharedKey });
    setRekeyed(true);
  };

  const ICN = PS_ICONS;

  // ---- Section bodies ----
  function renderSection(id) {
    if (id === 'route') return (
      <>
        <div className="ap-routing">
          {[
            { id: 'all', t: 'All traffic', d: 'Full tunnel — route everything through the VPN' },
            { id: 'split', t: 'Custom', d: 'Specify Allowed IPs manually' },
          ].map((o) => (
            <button key={o.id} className={`ap-routing-card ${routingPreset === o.id ? 'on' : ''}`} onClick={() => {
              setRoutingPreset(o.id);
              if (o.id === 'all') setAllowedIps('0.0.0.0/0, ::/0');
            }}>
              <div className="ap-routing-radio"><span /></div>
              <div>
                <div className="ap-routing-t">{o.t}</div>
                <div className="ap-routing-d">{o.d}</div>
              </div>
            </button>
          ))}
        </div>
        {routingPreset === 'split' && (
          <input type="text" className="ap-input mono" value={allowedIps}
            onChange={(e) => setAllowedIps(e.target.value)}
            placeholder="10.7.0.0/24, 192.168.1.0/24" />
        )}
        <div className="ap2-help">Stored in the generated <span className="mono">[Peer] AllowedIPs</span> on the device config.</div>
      </>
    );
    if (id === 'dns') return (
      <>
        <div className="ap2-field">
          <label className="ap-label">DNS servers</label>
          <input type="text" className="ap-input mono" value={dns} onChange={(e) => setDns(e.target.value)}
            placeholder="1.1.1.1, 1.0.0.1" disabled={blockAds} />
          <div className="ap-dns-presets">
            {[
              { lbl: 'Cloudflare', val: '1.1.1.1, 1.0.0.1' },
              { lbl: 'Quad9',      val: '9.9.9.9, 149.112.112.112' },
              { lbl: 'Google',     val: '8.8.8.8, 8.8.4.4' },
              { lbl: 'Server',     val: '10.7.0.1' },
              { lbl: 'None',       val: '' },
            ].map((p) => (
              <button key={p.lbl} className={`mini-btn ${dns === p.val ? 'on' : ''}`}
                onClick={() => setDns(p.val)} disabled={blockAds}>{p.lbl}</button>
            ))}
          </div>
        </div>
        <div className="ap2-field">
          <label className="ap-label">Search domains <span className="ap-label-opt">optional</span></label>
          <input type="text" className="ap-input mono" value={searchDomains}
            onChange={(e) => setSearchDomains(e.target.value)} placeholder="corp.internal, home.lan" />
        </div>
        <div className="ap2-inline-toggle">
          <div>
            <div className="setting-title">Route DNS through server</div>
            <div className="setting-desc">Resolve via the gateway with ad / tracker blocking</div>
          </div>
          <button className={`toggle ${blockAds ? 'on' : ''}`} onClick={() => setBlockAds(!blockAds)} aria-pressed={blockAds}>
            <span className="toggle-knob" />
          </button>
        </div>
      </>
    );
    if (id === 'tune') return (
      <>
        <div className="ap2-field">
          <label className="ap-label">Server endpoint</label>
          <input type="text" className="ap-input mono" value={endpoint}
            onChange={(e) => setEndpoint(e.target.value)} placeholder="host:port" />
        </div>
        <div className="ap2-mini-grid c3">
          <div className="ap2-field">
            <label className="ap-label">MTU</label>
            <input type="text" className="ap-input mono" value={mtu} onChange={(e) => setMtu(e.target.value)} />
          </div>
          <div className="ap2-field">
            <label className="ap-label">Keepalive (s)</label>
            <input type="text" className="ap-input mono" value={keepalive} onChange={(e) => setKeepalive(e.target.value)} />
          </div>
          <div className="ap2-field">
            <label className="ap-label">Listen port</label>
            <input type="text" className="ap-input mono" value={listenPort}
              onChange={(e) => setListenPort(e.target.value)} placeholder="auto" />
          </div>
        </div>
        <div className="ap2-help">Keepalive keeps NAT mappings warm — 25s suits most mobile clients. Leave MTU at 1420 unless you see fragmentation.</div>
      </>
    );
    if (id === 'crypto') return (
      <>
        <div className="ap2-field">
          <label className="ap-label">Public key <span className="ap-label-opt">{rekeyed ? 'newly rotated' : 'current'}</span></label>
          <div className="key-val">
            <span className="ap-key-tag mono">pub</span>
            <span className="truncate mono">{keys.publicKey}</span>
            <button className="mini-btn" onClick={() => copy(keys.publicKey, 'pub')}>{copied === 'pub' ? '✓' : 'copy'}</button>
          </div>
        </div>
        <div className="ap2-inline-toggle">
          <div>
            <div className="setting-title">Rotate keypair</div>
            <div className="setting-desc">Generate a fresh private/public key for this peer</div>
          </div>
          <button className="btn" onClick={rekey} disabled={rekeyed}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M21 12a9 9 0 11-9-9c2.5 0 4.7 1 6.4 2.6L21 3v6h-6"/></svg>
            {rekeyed ? 'Rotated' : 'Rekey'}
          </button>
        </div>
        {rekeyed && (
          <div className="ap2-help" style={{ color: 'var(--warn)' }}>
            The old key stops working the moment the new config is imported — provision the device before the next handshake window.
          </div>
        )}
        <div className="ap2-inline-toggle">
          <div>
            <div className="setting-title">Pre-shared key</div>
            <div className="setting-desc">Symmetric layer for post-quantum hardening</div>
          </div>
          <button className={`toggle ${usePsk ? 'on' : ''}`} onClick={() => setUsePsk(!usePsk)} aria-pressed={usePsk}>
            <span className="toggle-knob" />
          </button>
        </div>
        {usePsk && (
          <div className="key-val">
            <span className="ap-key-tag mono">psk</span>
            <span className="truncate mono">{keys.presharedKey}</span>
            <button className="mini-btn" onClick={() => copy(keys.presharedKey, 'psk')}>{copied === 'psk' ? '✓' : 'copy'}</button>
          </div>
        )}
      </>
    );
    if (id === 'scripts') return (
      <>
        <div className="ap2-mini-grid c2">
          <div className="ap2-field">
            <label className="ap-label">Routing table</label>
            <div className="ap2-seg">
              {['auto', 'off', 'main', '51820'].map((t) => (
                <button key={t} className={table === t ? 'on' : ''} onClick={() => setTable(t)}>{t}</button>
              ))}
            </div>
          </div>
          <div className="ap2-field">
            <label className="ap-label">FwMark <span className="ap-label-opt">optional</span></label>
            <input type="text" className="ap-input mono" value={fwmark} onChange={(e) => setFwmark(e.target.value)} placeholder="0xca6c" />
          </div>
        </div>
        <div className="ap2-field">
          <label className="ap-label">PostUp</label>
          <textarea className="ap2-textarea" value={postUp} onChange={(e) => setPostUp(e.target.value)}
            placeholder="iptables -A FORWARD -i %i -j ACCEPT; ..." />
        </div>
        <div className="ap2-field">
          <label className="ap-label">PostDown</label>
          <textarea className="ap2-textarea" value={postDown} onChange={(e) => setPostDown(e.target.value)}
            placeholder="iptables -D FORWARD -i %i -j ACCEPT; ..." />
        </div>
        <div className="ap2-mini-grid c2">
          <div className="ap2-field">
            <label className="ap-label">PreUp <span className="ap-label-opt">optional</span></label>
            <input type="text" className="ap-input mono" value={preUp} onChange={(e) => setPreUp(e.target.value)} />
          </div>
          <div className="ap2-field">
            <label className="ap-label">PreDown <span className="ap-label-opt">optional</span></label>
            <input type="text" className="ap-input mono" value={preDown} onChange={(e) => setPreDown(e.target.value)} />
          </div>
        </div>
      </>
    );
    if (id === 'meta') return (
      <>
        <div className="ap2-field">
          <label className="ap-label">Note <span className="ap-label-opt">device label</span></label>
          <input type="text" className="ap-input" value={note} onChange={(e) => setNote(e.target.value)}
            onBlur={() => instantSave({ note })} placeholder="John's laptop" />
        </div>
        <div className="ap2-field">
          <label className="ap-label">Owner <span className="ap-label-opt">email or name</span></label>
          <input type="text" className="ap-input" value={owner} onChange={(e) => setOwner(e.target.value)}
            onBlur={() => instantSave({ owner })} placeholder="alex@example.com" />
        </div>
        <div className="ap2-field">
          <label className="ap-label">Notes <span className="ap-label-opt">optional</span></label>
          <textarea className="ap2-textarea" style={{ fontFamily: 'var(--sans)', fontSize: '12.5px' }}
            value={longNote} onChange={(e) => setLongNote(e.target.value)}
            onBlur={() => instantSave({ long_note: longNote })}
            placeholder="Anything future-you should know about this peer…" />
        </div>
        <div className="ap2-help">All fields saved when you leave them.</div>
      </>
    );
    if (id === 'life') return (
      <>
        <div className="ap2-field">
          <label className="ap-label">Access expires</label>
          <div className="ap-radio-grid">
            {[{ id: 'never', label: 'Never' }, { id: '7d', label: '7 days' }, { id: '30d', label: '30 days' }, { id: '1y', label: '1 year' }].map((o) => (
              <button key={o.id} className={`ap-radio ${expiry === o.id ? 'on' : ''}`} onClick={() => setExpiry(o.id)}>{o.label}</button>
            ))}
          </div>
        </div>
        <div className="ap2-inline-toggle">
          <div>
            <div className="setting-title">Auto-disable when idle</div>
            <div className="setting-desc">Revoke if no handshake within the window</div>
          </div>
          <button className={`toggle ${disableIdle ? 'on' : ''}`} onClick={() => setDisableIdle(!disableIdle)} aria-pressed={disableIdle}>
            <span className="toggle-knob" />
          </button>
        </div>
        {disableIdle && (
          <div className="ap2-field">
            <label className="ap-label">Idle window (days)</label>
            <input type="text" className="ap-input mono" value={idleDays}
              onChange={(e) => setIdleDays(e.target.value)} style={{ maxWidth: 120 }} />
          </div>
        )}
        <div className="ap2-help" style={{ color: 'var(--muted)' }}>Lifecycle tracking is coming soon — these settings are stored locally for now.</div>
      </>
    );
    if (id === 'bw') return (
      <>
        <div className="ap2-field">
          <label className="ap-label">Monthly data cap <span className="ap-label-opt">GB · blank = unlimited</span></label>
          <input type="text" className="ap-input mono" value={dataCap}
            onChange={(e) => setDataCap(e.target.value)} placeholder="unlimited" style={{ maxWidth: 160 }} />
        </div>
        <div className="ap2-mini-grid c2">
          <div className="ap2-field">
            <label className="ap-label">Rate limit ↓ <span className="ap-label-opt">Mbps</span></label>
            <input type="text" className="ap-input mono" value={rateDown}
              onChange={(e) => setRateDown(e.target.value)} placeholder="—" />
          </div>
          <div className="ap2-field">
            <label className="ap-label">Rate limit ↑ <span className="ap-label-opt">Mbps</span></label>
            <input type="text" className="ap-input mono" value={rateUp}
              onChange={(e) => setRateUp(e.target.value)} placeholder="—" />
          </div>
        </div>
        <div className="ap2-help" style={{ color: 'var(--muted)' }}>Per-peer shaping via tc — coming soon.</div>
      </>
    );
    return null;
  }

  const instantSections = [
    {
      id: 'meta', icon: ICN.tag, title: 'Tags & metadata',
      summary: (note ? `"${note.slice(0, 22)}${note.length > 22 ? '…' : ''}"` : 'no note') + (owner ? ` · ${owner}` : ''),
      modified: note !== seeds.note || owner !== seeds.owner || longNote !== seeds.longNote,
    },
    {
      id: 'life', icon: ICN.clock, title: 'Lifecycle & expiry',
      summary: (expiry === 'never' ? 'never expires' : `expires in ${expiry}`) + (disableIdle ? ` · idle ${idleDays}d` : ''),
      modified: expiry !== 'never' || disableIdle,
    },
    {
      id: 'bw', icon: ICN.gauge, title: 'Bandwidth & quotas',
      summary: (dataCap ? `${dataCap} GB / mo` : 'unlimited data') + (rateDown || rateUp ? ' · shaped' : ''),
      modified: !!(dataCap || rateDown || rateUp),
    },
  ];

  const configSections = [
    {
      id: 'route', icon: ICN.route, title: 'Tunnel routing',
      summary: routingPreset === 'all' ? 'full tunnel · 0.0.0.0/0' : (allowedIps || 'custom'),
      modified: routingPreset !== saved.routingPreset || allowedIps !== saved.allowedIps,
    },
    {
      id: 'dns', icon: ICN.dns, title: 'DNS & search domains',
      summary: (blockAds ? 'server (ad-block)' : dns || 'none') + (searchDomains ? ` · ${searchDomains}` : ''),
      modified: dns !== saved.dns || searchDomains !== saved.searchDomains || blockAds !== saved.blockAds,
    },
    {
      id: 'tune', icon: ICN.tune, title: 'Connection tuning',
      summary: `MTU ${mtu} · keepalive ${keepalive}s${listenPort ? ` · port ${listenPort}` : ''}`,
      modified: mtu !== saved.mtu || keepalive !== saved.keepalive || listenPort !== saved.listenPort || endpoint !== saved.endpoint,
    },
    {
      id: 'crypto', icon: ICN.key, title: 'Cryptography & keys',
      summary: `${rekeyed ? 'rotated key' : 'current key'} · ${usePsk ? 'PSK on' : 'no PSK'}`,
      modified: rekeyed !== saved.rekeyed || usePsk !== saved.usePsk,
    },
    {
      id: 'scripts', icon: ICN.script, title: 'Routing scripts & firewall',
      summary: postUp || postDown || preUp || preDown ? 'custom hooks set' : `table ${table}${fwmark ? ` · fwmark ${fwmark}` : ''}`,
      modified: !!(preUp !== saved.preUp || postUp !== saved.postUp ||
                   preDown !== saved.preDown || postDown !== saved.postDown ||
                   fwmark !== saved.fwmark || table !== saved.table),
    },
  ];

  const Coll = window.Collapsible;

  return (
    <div className="ps-body">
      {/* Re-provision banner */}
      {dirty ? (
        <div className="ps-reprov">
          <div className="ps-reprov-main">
            <div className="ps-reprov-icon">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 9v4M12 17h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/>
              </svg>
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div className="ps-reprov-title">New config required</div>
              <div className="ps-reprov-desc">
                <span className="mono" style={{ color: 'var(--ink)' }}>{peer.name}</span> keeps running on its current config until the device re-imports the updated one.
              </div>
              <div className="ps-reprov-chips">
                {changedLabels.map((c) => <span key={c} className="ps-reprov-chip">{c}</span>)}
              </div>
            </div>
          </div>
          <div className="ps-reprov-actions">
            <button className="btn" onClick={() => setShowPreview((v) => !v)}>
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
              {showPreview ? 'Hide preview' : 'Show new config'}
            </button>
            <button className="btn" onClick={downloadConfig} disabled={provisioning}>
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 3v12m0 0l-4-4m4 4l4-4M4 21h16"/></svg>
              {provisioning ? 'Downloading…' : 'Download .conf'}
            </button>
            <button className="btn" onClick={() => setShowQr((v) => !v)}>
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><path d="M14 14h3v3M21 14v3M14 17v4h3M17 21h4"/></svg>
              {showQr ? 'Hide QR' : 'Show QR'}
            </button>
            <span style={{ flex: 1 }} />
            <button className="btn btn-danger" onClick={revert}>
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M3 10h10a4 4 0 0 1 0 8H9"/><polyline points="7 6 3 10 7 14"/></svg>
              Revert
            </button>
            <button className="btn btn-primary" onClick={markReprovisioned} disabled={saving}>
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M5 12l5 5L20 7"/></svg>
              {saving ? 'Saving…' : 'Mark re-provisioned'}
            </button>
          </div>
          {showPreview && (
            <div className="ps-reprov-preview">
              <pre className="ap-config-block" style={{ margin: 0, maxHeight: 260, overflow: 'auto' }}>{previewConfig}</pre>
            </div>
          )}
          {showQr && (
            <div className="ps-reprov-qr">
              {qrUrl
                ? <img src={qrUrl} width={200} height={200} alt="Config QR code" className="ap-qr-img" />
                : <div style={{ width: 200, height: 200, display: 'grid', placeItems: 'center', color: 'var(--muted)', fontFamily: 'var(--mono)', fontSize: 11 }}>Generating…</div>}
              <span className="ap-qr-hint">Scan with WireGuard mobile to import</span>
            </div>
          )}
        </div>
      ) : (
        <div className="ps-insync">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--success)" strokeWidth="2.2">
            <path d="M5 12l5 5L20 7"/>
          </svg>
          Device config is in sync — no re-import needed.
        </div>
      )}

      {/* Applies instantly */}
      <div className="ps-group">
        <div className="ps-group-head">
          <div className="ps-group-head-left">
            <span className="ps-group-kicker">Applies instantly</span>
            <span className="ps-group-badge ps-badge-live"><span className="pulse-dot" /> server-side</span>
          </div>
          {saveMsg && (
            <span className="ps-save-msg" style={{ color: saveMsg.startsWith('Error') ? 'var(--danger)' : 'var(--muted)' }}>{saveMsg}</span>
          )}
          {flash && !saveMsg && (
            <span className="ps-saved">
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><path d="M5 12l5 5L20 7"/></svg>
              Applied
            </span>
          )}
        </div>
        <div className="ps-stack">
          {instantSections.map((s) => (
            <Coll key={s.id} icon={s.icon} title={s.title} summary={s.summary}
              modified={s.modified} open={!!openSection[s.id]} onToggle={() => toggle(s.id)}>
              {renderSection(s.id)}
            </Coll>
          ))}
        </div>
      </div>

      {/* Changes device config */}
      <div className="ps-group">
        <div className="ps-group-head">
          <div className="ps-group-head-left">
            <span className="ps-group-kicker">Changes the device config</span>
            <span className="ps-group-badge ps-badge-config">
              <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4">
                <path d="M12 9v4M12 17h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/>
              </svg>
              needs re-import
            </span>
          </div>
        </div>
        <div className="ps-stack">
          {configSections.map((s) => (
            <Coll key={s.id} icon={s.icon} title={s.title} summary={s.summary}
              modified={s.modified} open={!!openSection[s.id]} onToggle={() => toggle(s.id)}>
              {renderSection(s.id)}
            </Coll>
          ))}
        </div>
      </div>
    </div>
  );
}

Object.assign(window, { PeerSettings });

// AddPeerDrawer — easy primary path + collapsible pro sections (API-integrated)

const { useState: aS, useEffect: aE, useMemo: aM, useRef: aR } = React;

// ============================================================
// Helpers
// ============================================================
function randKey() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let out = '';
  for (let i = 0; i < 43; i++) out += chars[Math.floor(Math.random() * chars.length)];
  return out + '=';
}

function detectSubnetPrefix(peers) {
  for (const p of peers) {
    const ip = (p.addr || '').split('/')[0];
    if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) {
      return ip.split('.').slice(0, 3).join('.');
    }
  }
  return '10.8.0'; // matches server default SERVER_ADDR_ENV
}

function nextFreeIp(peers) {
  const prefix = detectSubnetPrefix(peers);
  const taken = new Set(peers.map((p) => (p.addr || '').split('/')[0]));
  taken.add(prefix + '.1');
  for (let i = 2; i < 254; i++) {
    const ip = `${prefix}.${i}`;
    if (!taken.has(ip)) return ip + '/32';
  }
  return prefix + '.254/32';
}

function buildConfig(o) {
  const lines = [
    '[Interface]',
    `# ${o.name}`,
    `PrivateKey = ${o.privateKey}`,
    `Address = ${o.address}`,
  ];
  if (o.dns) {
    const dnsLine = o.searchDomains ? `${o.dns}, ${o.searchDomains}` : o.dns;
    lines.push(`DNS = ${dnsLine}`);
  }
  if (o.mtu && o.mtu !== '1420') lines.push(`MTU = ${o.mtu}`);
  if (o.listenPort) lines.push(`ListenPort = ${o.listenPort}`);
  if (o.table && o.table !== 'auto') lines.push(`Table = ${o.table}`);
  if (o.fwmark) lines.push(`FwMark = ${o.fwmark}`);
  if (o.preUp) lines.push(`PreUp = ${o.preUp}`);
  if (o.postUp) lines.push(`PostUp = ${o.postUp}`);
  if (o.preDown) lines.push(`PreDown = ${o.preDown}`);
  if (o.postDown) lines.push(`PostDown = ${o.postDown}`);
  lines.push('', '[Peer]');
  lines.push(`PublicKey = ${o.serverPubKey}`);
  if (o.presharedKey) lines.push(`PresharedKey = ${o.presharedKey}`);
  lines.push(`AllowedIPs = ${o.allowedIps}`);
  lines.push(`Endpoint = ${o.endpoint}`);
  if (o.keepalive) lines.push(`PersistentKeepalive = ${o.keepalive}`);
  return lines.join('\n');
}

// Decorative pseudo-QR for the live preview rail
function PseudoQR({ seed = 'wg', size = 168 }) {
  const cells = 21;
  let h = 0;
  for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) >>> 0;
  const rand = () => { h = (h * 1664525 + 1013904223) >>> 0; return h / 0xffffffff; };
  const grid = [];
  for (let y = 0; y < cells; y++) {
    const row = [];
    for (let x = 0; x < cells; x++) {
      const inFinder = (xx, yy) =>
        (xx < 7 && yy < 7) || (xx >= cells - 7 && yy < 7) || (xx < 7 && yy >= cells - 7);
      if (inFinder(x, y)) {
        const fx = x < 7 ? x : x - (cells - 7);
        const fy = y < 7 ? y : y - (cells - 7);
        const isBorder = fx === 0 || fy === 0 || fx === 6 || fy === 6;
        const isCenter = fx >= 2 && fx <= 4 && fy >= 2 && fy <= 4;
        row.push(isBorder || isCenter ? 1 : 0);
      } else {
        row.push(rand() > 0.55 ? 1 : 0);
      }
    }
    grid.push(row);
  }
  const cell = size / cells;
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="pseudo-qr">
      <rect width={size} height={size} fill="#FFFCF4" rx="6" />
      {grid.map((row, y) =>
        row.map((v, x) =>
          v ? <rect key={`${x}-${y}`} x={x * cell} y={y * cell} width={cell} height={cell} fill="#1A1613" rx="0.5" /> : null
        )
      )}
    </svg>
  );
}

// ============================================================
// Collapsible — reusable pro-option card
// ============================================================
function Collapsible({ icon, title, summary, open, onToggle, modified, children }) {
  return (
    <section className={`coll ${open ? 'open' : ''}`}>
      <button type="button" className="coll-head" onClick={onToggle} aria-expanded={open}>
        <span className="coll-icon">{icon}</span>
        <span className="coll-text">
          <span className="coll-title">
            {title}
            {modified && !open && <span className="coll-dot" title="Changed from default" />}
          </span>
          <span className="coll-sum">{summary}</span>
        </span>
        <svg className="coll-chev" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M9 6l6 6-6 6" />
        </svg>
      </button>
      <div className="coll-wrap">
        <div className="coll-inner">
          <div className="coll-body">{children}</div>
        </div>
      </div>
    </section>
  );
}

// Inline icon set for collapsible headers
const I = {
  dns:    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.5 2.5 16 0 18M12 3c-2.5 2.5-2.5 16 0 18"/></svg>,
  key:    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><circle cx="8" cy="15" r="4"/><path d="M10.8 12.2 20 3M16 7l3 3M14 9l2 2"/></svg>,
  tune:   <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><path d="M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12M20 18h0"/><circle cx="16" cy="6" r="2"/><circle cx="10" cy="12" r="2"/><circle cx="18" cy="18" r="2"/></svg>,
  script: <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><path d="M7 8l-3 4 3 4M17 8l3 4-3 4M14 5l-4 14"/></svg>,
  clock:  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>,
  gauge:  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><path d="M12 13l4-4M3 14a9 9 0 0118 0"/><circle cx="12" cy="13" r="1.6"/></svg>,
  tag:    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><path d="M3 7v5l9 9 6-6-9-9H3z"/><circle cx="7" cy="11" r="1.3"/></svg>,
};

// ============================================================
// DeviceIcon
// ============================================================
function DeviceIcon({ kind }) {
  const common = { width: 18, height: 18, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: 1.6, strokeLinecap: 'round', strokeLinejoin: 'round' };
  if (kind === 'phone')   return <svg {...common}><rect x="7" y="2" width="10" height="20" rx="2"/><path d="M11 18h2"/></svg>;
  if (kind === 'laptop')  return <svg {...common}><rect x="3" y="5" width="18" height="11" rx="1"/><path d="M2 20h20"/></svg>;
  if (kind === 'desktop') return <svg {...common}><rect x="3" y="3" width="18" height="13" rx="1"/><path d="M9 21h6M12 16v5"/></svg>;
  if (kind === 'server')  return <svg {...common}><rect x="3" y="4" width="18" height="6" rx="1"/><rect x="3" y="14" width="18" height="6" rx="1"/><path d="M7 7h.01M7 17h.01"/></svg>;
  if (kind === 'router')  return <svg {...common}><rect x="3" y="13" width="18" height="7" rx="1"/><path d="M7 17h.01M11 17h.01M7 13V9a5 5 0 0110 0v4M12 6V4"/></svg>;
  return null;
}

// ============================================================
// AddPeerDrawer
// ============================================================
const PRESET_DEFAULTS = {
  dns: '1.1.1.1, 1.0.0.1', searchDomains: '', blockAds: false,
  usePsk: false,
  endpoint: `${window.location.hostname}:51820`, mtu: '1420', keepalive: '25', listenPort: '',
  preUp: '', postUp: '', preDown: '', postDown: '', table: 'auto', fwmark: '',
  expiry: 'never', disableIdle: false, idleDays: '30',
  dataCap: '', rateDown: '', rateUp: '',
  owner: '', notes: '',
};

function AddPeerDrawer({ peers, onClose, onCreated }) {
  const [created, setCreated] = aS(false);
  const [serverProfile, setServerProfile] = aS('');
  const [openSection, setOpenSection] = aS({});
  const [creating, setCreating] = aS(false);
  const [createError, setCreateError] = aS('');

  // essentials
  const [name, setName] = aS('');
  const [device, setDevice] = aS('phone');
  const [address, setAddress] = aS(() => nextFreeIp(peers));
  const [routingPreset, setRoutingPreset] = aS('all');
  const [allowedIps, setAllowedIps] = aS('0.0.0.0/0, ::/0');

  // pro: dns
  const [dns, setDns] = aS(PRESET_DEFAULTS.dns);
  const [searchDomains, setSearchDomains] = aS('');
  const [blockAds, setBlockAds] = aS(false);
  // pro: crypto
  const [usePsk, setUsePsk] = aS(false);
  // pro: connection
  const [endpoint, setEndpoint] = aS(PRESET_DEFAULTS.endpoint);
  const [mtu, setMtu] = aS('1420');
  const [keepalive, setKeepalive] = aS('25');
  const [listenPort, setListenPort] = aS('');
  // pro: scripts
  const [preUp, setPreUp] = aS('');
  const [postUp, setPostUp] = aS('');
  const [preDown, setPreDown] = aS('');
  const [postDown, setPostDown] = aS('');
  const [table, setTable] = aS('auto');
  const [fwmark, setFwmark] = aS('');
  // pro: lifecycle
  const [expiry, setExpiry] = aS('never');
  const [disableIdle, setDisableIdle] = aS(false);
  const [idleDays, setIdleDays] = aS('30');
  // pro: bandwidth
  const [dataCap, setDataCap] = aS('');
  const [rateDown, setRateDown] = aS('');
  const [rateUp, setRateUp] = aS('');
  // pro: metadata
  const [owner, setOwner] = aS('');
  const [tags, setTags] = aS([]);
  const [tagDraft, setTagDraft] = aS('');
  const [notes, setNotes] = aS('');

  const subnetLabel = aM(() => detectSubnetPrefix(peers) + '.0/24', [peers]);

  const keys = aM(() => ({
    privateKey: randKey(),
    publicKey: randKey(),
    presharedKey: randKey(),
    serverPubKey: 'OZJ3kF8mY2sN/RtVcwQ7L9pXgHaBdEi6vCfTqM4uYjU=',
  }), []);

  const [copied, setCopied] = aS('');
  const copy = (val, key) => {
    navigator.clipboard?.writeText(val);
    setCopied(key);
    setTimeout(() => setCopied(''), 1400);
  };

  aE(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const ipTaken = peers.some((p) => (p.addr || '').split('/')[0] === address.split('/')[0]);
  const nameTaken = peers.some((p) => p.name.toLowerCase() === name.toLowerCase());

  aE(() => {
    if (routingPreset === 'all') setAllowedIps('0.0.0.0/0, ::/0');
    else if (routingPreset === 'lan') setAllowedIps('10.7.0.0/24, 192.168.1.0/24');
  }, [routingPreset]);

  const canCreate = name.length >= 2 && !ipTaken && !nameTaken;

  const toggle = (id) => setOpenSection((s) => ({ ...s, [id]: !s[id] }));

  const effectiveDns = blockAds ? 'server (ad-block)' : dns || 'none';
  const sections = [
    {
      id: 'dns', icon: I.dns, title: 'DNS & search domains',
      summary: effectiveDns + (searchDomains ? ` · ${searchDomains}` : ''),
      modified: dns !== PRESET_DEFAULTS.dns || searchDomains !== '' || blockAds,
    },
    {
      id: 'crypto', icon: I.key, title: 'Cryptography & keys',
      summary: `Curve25519 keypair · ${usePsk ? 'pre-shared key on' : 'no pre-shared key'}`,
      modified: usePsk,
    },
    {
      id: 'tune', icon: I.tune, title: 'Connection tuning',
      summary: `MTU ${mtu} · keepalive ${keepalive}s${listenPort ? ` · port ${listenPort}` : ''}`,
      modified: mtu !== '1420' || keepalive !== '25' || listenPort !== '' || endpoint !== PRESET_DEFAULTS.endpoint,
    },
    {
      id: 'scripts', icon: I.script, title: 'Routing scripts & firewall',
      summary: postUp || postDown || preUp || preDown ? 'custom hooks set' : `table ${table}${fwmark ? ` · fwmark ${fwmark}` : ''}`,
      modified: !!(preUp || postUp || preDown || postDown || fwmark || table !== 'auto'),
    },
    {
      id: 'life', icon: I.clock, title: 'Lifecycle & expiry',
      summary: (expiry === 'never' ? 'never expires' : `expires in ${expiry}`) + (disableIdle ? ` · idle ${idleDays}d` : ''),
      modified: expiry !== 'never' || disableIdle,
    },
    {
      id: 'bw', icon: I.gauge, title: 'Bandwidth & quotas',
      summary: (dataCap ? `${dataCap} GB / mo` : 'unlimited data') + (rateDown || rateUp ? ' · shaped' : ''),
      modified: !!(dataCap || rateDown || rateUp),
    },
    {
      id: 'meta', icon: I.tag, title: 'Tags & metadata',
      summary: (tags.length ? `${tags.length} tag${tags.length > 1 ? 's' : ''}` : 'no tags') + (owner ? ` · ${owner}` : ''),
      modified: !!(tags.length || owner || notes),
    },
  ];

  const proCount = sections.filter((s) => s.modified).length;
  const allOpen = sections.every((s) => openSection[s.id]);
  const setAll = (v) => setOpenSection(Object.fromEntries(sections.map((s) => [s.id, v])));

  const addTag = (t) => {
    const v = t.trim().replace(/\s+/g, '-').toLowerCase();
    if (v && !tags.includes(v)) setTags([...tags, v]);
  };

  const handleCreate = async () => {
    if (!canCreate || creating) return;
    setCreating(true);
    setCreateError('');
    try {
      const ipRaw = address.split('/')[0];
      const r = await window.WG.apiCall('/api/users', {
        method: 'POST',
        body: JSON.stringify({ name, ip: ipRaw }),
      });
      if (!r?.profile) {
        setCreateError(`Peer "${name}" was created but the server failed to generate its config. Refresh the page to see it.`);
        onCreated?.();
        return;
      }
      setServerProfile(r.profile);
      setCreated(true);
      onCreated?.();
    } catch (err) {
      setCreateError(err.message || 'Failed to create peer');
    } finally {
      setCreating(false);
    }
  };

  const deviceOptions = [
    { id: 'phone',   label: 'Phone' },
    { id: 'laptop',  label: 'Laptop' },
    { id: 'desktop', label: 'Desktop' },
    { id: 'server',  label: 'Server' },
    { id: 'router',  label: 'Router' },
  ];

  const routeOptions = [
    { id: 'all',   t: 'All traffic', d: 'Full tunnel — route everything through the VPN' },
    { id: 'lan',   t: 'LAN only',    d: 'Only the LAN and WireGuard subnet' },
    { id: 'split', t: 'Custom',      d: 'Specify Allowed IPs manually' },
  ];

  // ===== Created (success) state =====
  if (created) {
    return (
      <CreatedView
        name={name}
        address={address}
        endpoint={endpoint}
        allowedIps={allowedIps}
        profile={serverProfile}
        copy={copy}
        copied={copied}
        onAddAnother={() => {
          setCreated(false);
          setName('');
          setServerProfile('');
          setCreateError('');
          setAddress(nextFreeIp([...peers, { addr: address }]));
        }}
        onClose={onClose}
      />
    );
  }

  // ====== Pro-options stack ======
  const proStack = (
    <div className="ap2-pro">
      <div className="ap2-pro-head">
        <div className="ap2-pro-head-left">
          <span className="ap2-pro-kicker">ADVANCED OPTIONS</span>
          {proCount > 0 && <span className="ap2-pro-count">{proCount} changed</span>}
        </div>
        <button type="button" className="ap2-expand-all" onClick={() => setAll(!allOpen)}>
          {allOpen ? 'Collapse all' : 'Expand all'}
        </button>
      </div>

      {sections.map((s) => (
        <Collapsible
          key={s.id}
          icon={s.icon}
          title={s.title}
          summary={s.summary}
          modified={s.modified}
          open={!!openSection[s.id]}
          onToggle={() => toggle(s.id)}
        >
          {renderSection(s.id)}
        </Collapsible>
      ))}
    </div>
  );

  function renderSection(id) {
    if (id === 'dns') return (
      <>
        <div className="ap2-field">
          <label className="ap-label">DNS servers</label>
          <input type="text" className="ap-input mono" value={dns} onChange={(e) => setDns(e.target.value)} placeholder="1.1.1.1, 1.0.0.1" disabled={blockAds} />
          <div className="ap-dns-presets">
            {[
              { lbl: 'Cloudflare', val: '1.1.1.1, 1.0.0.1' },
              { lbl: 'Quad9',      val: '9.9.9.9, 149.112.112.112' },
              { lbl: 'Google',     val: '8.8.8.8, 8.8.4.4' },
              { lbl: 'Server',     val: '10.7.0.1' },
              { lbl: 'None',       val: '' },
            ].map((p) => (
              <button key={p.lbl} className={`mini-btn ${dns === p.val ? 'on' : ''}`} onClick={() => setDns(p.val)} disabled={blockAds}>{p.lbl}</button>
            ))}
          </div>
        </div>
        <div className="ap2-field">
          <label className="ap-label">Search domains <span className="ap-label-opt">optional</span></label>
          <input type="text" className="ap-input mono" value={searchDomains} onChange={(e) => setSearchDomains(e.target.value)} placeholder="corp.internal, home.lan" />
        </div>
        <div className="ap2-inline-toggle">
          <div>
            <div className="setting-title">Route DNS through server</div>
            <div className="setting-desc">Resolve via the gateway with ad / tracker blocking</div>
          </div>
          <button className={`toggle ${blockAds ? 'on' : ''}`} onClick={() => setBlockAds(!blockAds)} aria-pressed={blockAds}><span className="toggle-knob" /></button>
        </div>
      </>
    );

    if (id === 'crypto') return (
      <>
        <div className="ap2-field">
          <label className="ap-label">Keypair <span className="ap-label-opt">generated in-browser</span></label>
          <div className="ap-key-mini">
            <div className="key-val">
              <span className="ap-key-tag mono">priv</span>
              <span className="truncate mono">{keys.privateKey}</span>
              <button className="mini-btn" onClick={() => copy(keys.privateKey, 'priv')}>{copied === 'priv' ? '✓' : 'copy'}</button>
            </div>
            <div className="key-val">
              <span className="ap-key-tag mono">pub</span>
              <span className="truncate mono">{keys.publicKey}</span>
              <button className="mini-btn" onClick={() => copy(keys.publicKey, 'pub')}>{copied === 'pub' ? '✓' : 'copy'}</button>
            </div>
          </div>
          <div className="ap2-help">The private key never leaves this browser. The server only stores the public key.</div>
        </div>
        <div className="ap2-inline-toggle">
          <div>
            <div className="setting-title">Pre-shared key</div>
            <div className="setting-desc">Symmetric layer for post-quantum hardening</div>
          </div>
          <button className={`toggle ${usePsk ? 'on' : ''}`} onClick={() => setUsePsk(!usePsk)} aria-pressed={usePsk}><span className="toggle-knob" /></button>
        </div>
        {usePsk && (
          <div className="ap2-field">
            <label className="ap-label">Pre-shared key</label>
            <div className="key-val">
              <span className="ap-key-tag mono">psk</span>
              <span className="truncate mono">{keys.presharedKey}</span>
              <button className="mini-btn" onClick={() => copy(keys.presharedKey, 'psk')}>{copied === 'psk' ? '✓' : 'copy'}</button>
            </div>
          </div>
        )}
      </>
    );

    if (id === 'tune') return (
      <>
        <div className="ap2-field">
          <label className="ap-label">Server endpoint</label>
          <input type="text" className="ap-input mono" value={endpoint} onChange={(e) => setEndpoint(e.target.value)} placeholder="host:port" />
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
            <input type="text" className="ap-input mono" value={listenPort} onChange={(e) => setListenPort(e.target.value)} placeholder="auto" />
          </div>
        </div>
        <div className="ap2-help">Keepalive keeps NAT mappings warm — 25s suits most mobile clients. Leave MTU at 1420 unless you see fragmentation.</div>
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
          <textarea className="ap2-textarea" value={postUp} onChange={(e) => setPostUp(e.target.value)} placeholder="iptables -A FORWARD -i %i -j ACCEPT; ..." />
        </div>
        <div className="ap2-field">
          <label className="ap-label">PostDown</label>
          <textarea className="ap2-textarea" value={postDown} onChange={(e) => setPostDown(e.target.value)} placeholder="iptables -D FORWARD -i %i -j ACCEPT; ..." />
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
          <button className={`toggle ${disableIdle ? 'on' : ''}`} onClick={() => setDisableIdle(!disableIdle)} aria-pressed={disableIdle}><span className="toggle-knob" /></button>
        </div>
        {disableIdle && (
          <div className="ap2-field">
            <label className="ap-label">Idle window (days)</label>
            <input type="text" className="ap-input mono" value={idleDays} onChange={(e) => setIdleDays(e.target.value)} style={{ maxWidth: 120 }} />
          </div>
        )}
      </>
    );

    if (id === 'bw') return (
      <>
        <div className="ap2-field">
          <label className="ap-label">Monthly data cap <span className="ap-label-opt">GB · blank = unlimited</span></label>
          <input type="text" className="ap-input mono" value={dataCap} onChange={(e) => setDataCap(e.target.value)} placeholder="unlimited" style={{ maxWidth: 160 }} />
        </div>
        <div className="ap2-mini-grid c2">
          <div className="ap2-field">
            <label className="ap-label">Rate limit ↓ <span className="ap-label-opt">Mbps</span></label>
            <input type="text" className="ap-input mono" value={rateDown} onChange={(e) => setRateDown(e.target.value)} placeholder="—" />
          </div>
          <div className="ap2-field">
            <label className="ap-label">Rate limit ↑ <span className="ap-label-opt">Mbps</span></label>
            <input type="text" className="ap-input mono" value={rateUp} onChange={(e) => setRateUp(e.target.value)} placeholder="—" />
          </div>
        </div>
        <div className="ap2-help">Shaping is enforced server-side via tc. Caps over a billing period notify the owner at 80% and 100%.</div>
      </>
    );

    if (id === 'meta') return (
      <>
        <div className="ap2-field">
          <label className="ap-label">Owner <span className="ap-label-opt">email or name</span></label>
          <input type="text" className="ap-input" value={owner} onChange={(e) => setOwner(e.target.value)} placeholder="alex@example.com" />
        </div>
        <div className="ap2-field">
          <label className="ap-label">Tags</label>
          <div className="ap-tag-row">
            {tags.map((t) => (
              <span key={t} className="ap-tag">
                {t}
                <button onClick={() => setTags(tags.filter((x) => x !== t))} aria-label={`Remove ${t}`}>×</button>
              </span>
            ))}
            <input
              className="ap-tag-input"
              value={tagDraft}
              onChange={(e) => setTagDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); addTag(tagDraft); setTagDraft(''); }
                else if (e.key === 'Backspace' && !tagDraft && tags.length) setTags(tags.slice(0, -1));
              }}
              placeholder={tags.length ? '' : 'team, role, location…'}
            />
          </div>
          <div className="ap-tag-presets">
            {['work', 'personal', 'admin', 'mobile', 'iot'].map((t) => (
              <button key={t} className="mini-btn" onClick={() => addTag(t)}>+ {t}</button>
            ))}
          </div>
        </div>
        <div className="ap2-field">
          <label className="ap-label">Notes <span className="ap-label-opt">optional</span></label>
          <textarea className="ap2-textarea" style={{ fontFamily: 'var(--sans)', fontSize: '12.5px' }} value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Anything future-you should know about this peer…" />
        </div>
      </>
    );

    return null;
  }

  // ====== Essentials ======
  const essentials = (
    <>
      <section className="ap2-sec">
        <div className="ap2-sec-head">
          <span className="ap2-sec-title">Name &amp; device</span>
          <span className="ap2-sec-note">required</span>
        </div>
        <div className="ap2-field">
          <div className="ap2-name-wrap">
            <input
              type="text"
              className={`ap-input ${nameTaken ? 'ap-input-err' : ''}`}
              placeholder="e.g. cobalt-phone"
              value={name}
              onChange={(e) => setName(e.target.value.replace(/\s+/g, '-').toLowerCase())}
              autoFocus
            />
            {name.length >= 2 && !nameTaken && (
              <span className="ap2-name-ok">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4"><path d="M5 12l5 5L20 7"/></svg>
              </span>
            )}
          </div>
          {nameTaken
            ? <div className="ap-hint ap-err">A peer named "{name}" already exists</div>
            : <div className="ap-hint">Lowercase letters, numbers and dashes</div>}
        </div>
        <div className="ap-device-grid">
          {deviceOptions.map((d) => (
            <button key={d.id} className={`ap-device ${device === d.id ? 'on' : ''}`} onClick={() => setDevice(d.id)}>
              <DeviceIcon kind={d.id} />
              <span>{d.label}</span>
            </button>
          ))}
        </div>
      </section>

      <section className="ap2-sec">
        <div className="ap2-sec-head">
          <span className="ap2-sec-title">What it routes</span>
          <span className="ap2-sec-note">allowed IPs</span>
        </div>
        <div className="ap-routing">
          {routeOptions.map((o) => (
            <button key={o.id} className={`ap-routing-card ${routingPreset === o.id ? 'on' : ''}`} onClick={() => setRoutingPreset(o.id)}>
              <div className="ap-routing-radio"><span /></div>
              <div>
                <div className="ap-routing-t">{o.t}</div>
                <div className="ap-routing-d">{o.d}</div>
              </div>
            </button>
          ))}
        </div>
        {routingPreset === 'split' && (
          <input type="text" className="ap-input mono" value={allowedIps} onChange={(e) => setAllowedIps(e.target.value)} placeholder="10.7.0.0/24, 192.168.1.0/24" />
        )}
      </section>

      <section className="ap2-sec">
        <div className="ap2-sec-head">
          <span className="ap2-sec-title">Tunnel address</span>
          <span className="ap2-sec-note">on {subnetLabel}</span>
        </div>
        <div className="ap2-ip-row">
          <span className="ap2-ip-lbl">IP</span>
          <input className={ipTaken ? 'ap-err' : ''} value={address} onChange={(e) => setAddress(e.target.value)} />
          <button className="mini-btn" onClick={() => setAddress(nextFreeIp(peers))}>auto</button>
        </div>
        {ipTaken && <div className="ap-hint ap-err">{address.split('/')[0]} is already assigned</div>}
      </section>
    </>
  );

  const footChips = (
    <div className="ap2-foot-chips">
      {nameTaken ? (
        <span className="ap-err" style={{ fontFamily: 'var(--mono)', fontSize: 11 }}>Name already in use</span>
      ) : ipTaken ? (
        <span className="ap-err" style={{ fontFamily: 'var(--mono)', fontSize: 11 }}>IP {address} already assigned</span>
      ) : createError ? (
        <span className="ap-err" style={{ fontFamily: 'var(--mono)', fontSize: 11 }}>{createError}</span>
      ) : !name ? (
        <span style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--muted)' }}>Enter a name to continue</span>
      ) : (
        <>
          <span className="ap2-chip"><b>ip</b>{address.split('/')[0]}</span>
          <span className="ap2-chip"><b>routes</b>{routingPreset}</span>
          <span className="ap2-chip"><b>dns</b>{blockAds ? 'server' : dns ? dns.split(',')[0] : 'none'}</span>
          {proCount > 0 && <span className="ap2-chip"><b>pro</b>{proCount}</span>}
        </>
      )}
    </div>
  );

  return (
    <>
      <div className="drawer-scrim" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label="Add peer">
        <header className="drawer-head">
          <div className="drawer-head-left">
            <div className="peer-avatar" style={{ background: 'var(--accent-soft)', color: 'var(--accent)' }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
                <circle cx="12" cy="8" r="4"/><path d="M4 21v-2a6 6 0 016-6h4a6 6 0 016 6v2M18 10v6M15 13h6"/>
              </svg>
            </div>
            <div>
              <h2 className="drawer-title">Add peer</h2>
              <div className="drawer-sub">A new device on the <span className="mono" style={{ color: 'var(--ink-2)' }}>{subnetLabel}</span> tunnel</div>
            </div>
          </div>
          <div className="drawer-head-actions">
            <button className="icon-btn" onClick={onClose} aria-label="Close">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M6 6l12 12M18 6L6 18"/></svg>
            </button>
          </div>
        </header>

        <div className="drawer-body ap2-body">
          {essentials}
          {proStack}
        </div>

        <footer className="ap-foot">
          {footChips}
          <button className="btn btn-primary" onClick={handleCreate} disabled={!canCreate || creating}>
            {creating
              ? <><span className="pc-spinner" style={{ width: 12, height: 12 }} />Creating…</>
              : <><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M5 12l5 5L20 7"/></svg>Create peer</>
            }
          </button>
        </footer>
      </aside>
    </>
  );
}

// ============================================================
// CreatedView — post-create provisioning screen
// ============================================================
function CreatedView({ name, address, endpoint, allowedIps, profile, copy, copied, onAddAnother, onClose }) {
  const [tab, setTab] = aS('qr');
  const [qrUrl, setQrUrl] = aS('');

  aE(() => {
    if (!profile || !window.QRious) return;
    try {
      const qr = new window.QRious({ value: profile, size: 220, level: 'L' });
      setQrUrl(qr.toDataURL());
    } catch (_) {}
  }, [profile]);

  const handleDownload = () => {
    const blob = new Blob([profile], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${name || 'peer'}.conf`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <>
      <div className="drawer-scrim" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label="Peer created">
        <header className="drawer-head">
          <div className="drawer-head-left">
            <div className="peer-avatar ap-avatar-ok">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4"><path d="M5 12l5 5L20 7"/></svg>
            </div>
            <div>
              <h2 className="drawer-title">{name} is ready</h2>
              <div className="drawer-sub"><span className="mono" style={{ color: 'var(--ink-2)' }}>{address}</span> · provision the device below</div>
            </div>
          </div>
          <div className="drawer-head-actions">
            <button className="icon-btn" onClick={onClose} aria-label="Close">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M6 6l12 12M18 6L6 18"/></svg>
            </button>
          </div>
        </header>

        <div className="drawer-body ap-body">
          <div className="ap-prov-tabs">
            <button className={`ap-prov-tab ${tab === 'qr' ? 'on' : ''}`} onClick={() => setTab('qr')}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><path d="M14 14h3v3M21 14v3M14 17v4h3M17 21h4"/></svg>
              <span>Scan QR</span>
            </button>
            <button className={`ap-prov-tab ${tab === 'file' ? 'on' : ''}`} onClick={() => setTab('file')}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 3v12m0 0l-4-4m4 4l4-4M4 21h16"/></svg>
              <span>Download file</span>
            </button>
            <button className={`ap-prov-tab ${tab === 'text' ? 'on' : ''}`} onClick={() => setTab('text')}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M4 6h16M4 12h16M4 18h10"/></svg>
              <span>Copy config</span>
            </button>
          </div>

          {tab === 'qr' && (
            <div className="ap-prov-hero">
              {qrUrl
                ? <img src={qrUrl} width={220} height={220} alt="WireGuard QR code" className="ap-qr-img" style={{ marginBottom: 14 }} />
                : profile
                  ? <div style={{ width: 220, height: 220, display: 'grid', placeItems: 'center', color: 'var(--muted)', fontFamily: 'var(--mono)', fontSize: 11, marginBottom: 14 }}>Generating…</div>
                  : <PseudoQR seed={name + address} size={220} />
              }
              <div className="ap-prov-hero-title">Scan with WireGuard mobile</div>
              <div className="ap-prov-hero-sub">Open the WireGuard app on the device · tap <span className="mono" style={{ color: 'var(--ink-2)' }}>＋</span> · Create from QR code</div>
            </div>
          )}

          {tab === 'file' && (
            <div className="ap-prov-hero">
              <div className="ap-file-icon">
                <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.4"><path d="M14 3H6a2 2 0 00-2 2v14a2 2 0 002 2h12a2 2 0 002-2V9zM14 3v6h6"/></svg>
                <span className="ap-file-name mono">{name}.conf</span>
              </div>
              <div className="ap-prov-hero-title">Download the config file</div>
              <div className="ap-prov-hero-sub">Transfer to the device and import in the WireGuard client</div>
              <button className="btn btn-primary" style={{ marginTop: 14 }} onClick={handleDownload}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 3v12m0 0l-4-4m4 4l4-4M4 21h16"/></svg>
                Download {name}.conf
              </button>
            </div>
          )}

          {tab === 'text' && (
            <div className="ap-prov-text">
              <div className="ap-prov-text-head">
                <span className="section-label">{name}.conf</span>
                <button className="mini-btn" onClick={() => copy(profile, 'conf')}>{copied === 'conf' ? '✓ copied' : 'copy all'}</button>
              </div>
              <pre className="ap-config-block">{profile}</pre>
            </div>
          )}

          <div className="ap-detail-strip">
            <div className="ap-detail-strip-item">
              <span className="ap-detail-lbl">Address</span>
              <span className="mono">{address}</span>
            </div>
            <div className="ap-detail-strip-item">
              <span className="ap-detail-lbl">Endpoint</span>
              <span className="mono">{endpoint}</span>
            </div>
            <div className="ap-detail-strip-item">
              <span className="ap-detail-lbl">Routes</span>
              <span className="mono ap-kv-truncate">{allowedIps}</span>
            </div>
          </div>

          <div className="ap-warn-strip">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 2L1 21h22L12 2zM12 9v5M12 18h.01"/></svg>
            <span>The private key is shown only on this device. Save it before closing.</span>
          </div>
        </div>

        <footer className="ap-foot">
          <button className="btn" onClick={onAddAnother}>+ Add another peer</button>
          <button className="btn btn-primary" onClick={onClose}>Done</button>
        </footer>
      </aside>
    </>
  );
}

Object.assign(window, { AddPeerDrawer, Collapsible, buildConfig, randKey });

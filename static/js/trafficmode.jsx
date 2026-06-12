// Traffic Mode — Orbital 2D latency-ring visualization
// Peers arranged radially by ping latency on concentric rings.
// Log is in a slide-in drawer toggled by the log button.

const TM_SERVER = { name: 'wg0 · DE-FRA-01', country: 'Frankfurt' };
const RING_MS = [25, 75, 150, 250];

const ORBITAL_THEMES = {
  dark: {
    bg0: '#221A13', bg1: '#150F0B',
    star: 'rgba(230,220,200,',
    ring: 'rgba(245,220,188,0.28)', ringLabel: 'rgba(245,220,188,0.48)',
    spoke: 'rgba(245,220,188,0.10)', spokeHot: 'rgba(245,220,188,0.30)',
    serverGlow: '247,175,130', serverRing: '217,119,87', serverCore: '#FFE6CC',
    peerOn: '#CFEFD8', peerOnGlow: '120,220,170', peerOff: '#6B5D4D',
    label: 'rgba(248,235,216,', labelOff: 'rgba(154,139,120,',
    rx: '247,175,130', tx: '120,220,170', hs: '200,180,255', ka: '230,210,150',
  },
  light: {
    bg0: '#F6F1E6', bg1: '#E7DECB',
    star: 'rgba(150,130,100,',
    ring: 'rgba(90,60,30,0.26)', ringLabel: 'rgba(90,60,30,0.55)',
    spoke: 'rgba(90,60,30,0.12)', spokeHot: 'rgba(90,60,30,0.34)',
    serverGlow: '217,119,87', serverRing: '180,80,40', serverCore: '#B7521F',
    peerOn: '#2E7A4E', peerOnGlow: '60,160,110', peerOff: '#B5A893',
    label: 'rgba(42,37,32,', labelOff: 'rgba(122,110,94,',
    rx: '193,90,45', tx: '40,130,80', hs: '120,90,200', ka: '150,110,40',
  }
};

function pingToNorm(ping) {
  if (ping == null) return 1.18;
  return 0.30 + Math.sqrt(Math.min(ping, 260) / 260) * 0.78;
}

function buildOrderedPeers(peers) {
  const withOrig = peers.map((p, i) => ({ ...p, origIdx: i }));
  withOrig.sort((a, b) => (a.pingMs ?? 9999) - (b.pingMs ?? 9999));
  return withOrig.map((p, idx) => ({
    ...p,
    angle: idx * 2.39996323 + (p.origIdx % 2 ? 0.18 : -0.18),
    norm: pingToNorm(p.pingMs),
    connected: p.status === 'connected',
    phase: (p.origIdx * 137.5) % (Math.PI * 2),
  }));
}

function orbitalPeerPos(p, rotation, zoom, W, H) {
  const cx = W / 2;
  const cy = H / 2 + 10;
  const R = Math.min(W, H) * 0.40 * zoom;
  const a = p.angle + rotation;
  return { x: cx + Math.cos(a) * R * p.norm, y: cy + Math.sin(a) * R * p.norm * 0.62 };
}

function TrafficMode({ peers, theme, onClose }) {
  const canvasRef = React.useRef(null);
  const rafRef = React.useRef(null);
  const rotRef = React.useRef(0);
  const zoomRef = React.useRef(1);
  const draggingRef = React.useRef(false);
  const dragXRef = React.useRef(0);
  const hoverPeerRef = React.useRef(null);
  const particlesRef = React.useRef([]);
  const orderedRef = React.useRef([]);
  const themeRef = React.useRef(theme);
  const pausedRef = React.useRef(false);
  const statsRef = React.useRef({ events: 0, bytes: 0 });

  const [paused, setPaused] = React.useState(false);
  const [logOpen, setLogOpen] = React.useState(false);
  const [events, setEvents] = React.useState([]);
  const [stats, setStats] = React.useState({ events: 0, bytes: 0 });

  React.useEffect(() => { pausedRef.current = paused; }, [paused]);
  React.useEffect(() => { themeRef.current = theme; }, [theme]);
  React.useEffect(() => { orderedRef.current = buildOrderedPeers(peers); }, [peers]);

  // Particle emission — restarts whenever connected peer set changes
  React.useEffect(() => {
    const fire = (p) => {
      if (pausedRef.current) return;
      const roll = Math.random();
      let kind, label, size;
      if (roll < 0.46)      { kind = 'rx'; label = 'rx';        size = Math.random() * 4200 + 600; }
      else if (roll < 0.66) { kind = 'rx'; label = 'rx';        size = Math.random() * 900  + 120; }
      else if (roll < 0.88) { kind = 'tx'; label = 'tx';        size = Math.random() * 1600 + 90;  }
      else if (roll < 0.95) { kind = 'hs'; label = 'handshake'; size = 0; }
      else                   { kind = 'ka'; label = 'keepalive'; size = 0; }
      const dir = kind === 'tx' ? 1 : kind === 'rx' ? -1 : (Math.random() < 0.5 ? 1 : -1);
      particlesRef.current.push({ peer: p, kind, dir, size, t0: performance.now(), dur: 900 + Math.random() * 700 });
      p.lastHit = performance.now();
      statsRef.current = { events: statsRef.current.events + 1, bytes: statsRef.current.bytes + size * 1024 };
      setStats({ ...statsRef.current });
      setEvents(prev => [{ ts: Date.now(), peer: p.name, kind, label, size }, ...prev].slice(0, 20));
    };

    const emit = () => {
      if (pausedRef.current) return;
      const conn = orderedRef.current.filter(p => p.connected);
      if (!conn.length) return;
      const burst = 2 + Math.floor(Math.random() * 3);
      const shuffled = [...conn].sort(() => Math.random() - 0.5);
      for (let i = 0; i < burst; i++) {
        const p = shuffled[i % shuffled.length];
        setTimeout(() => fire(p), i * 90 + Math.random() * 80);
      }
    };

    const t1 = setTimeout(emit, 300);
    const t2 = setTimeout(emit, 650);
    const id = setInterval(emit, 540);
    return () => { clearTimeout(t1); clearTimeout(t2); clearInterval(id); };
  }, [peers]);

  // Render loop — runs once; reads all state via refs
  React.useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let dpr = 1, W = 0, H = 0, lastTime = performance.now();

    const resize = () => {
      dpr = window.devicePixelRatio || 1;
      const r = canvas.getBoundingClientRect();
      W = r.width; H = r.height;
      canvas.width = W * dpr;
      canvas.height = H * dpr;
    };
    resize();
    window.addEventListener('resize', resize);

    const tick = (now) => {
      const dt = Math.min(50, now - lastTime);
      lastTime = now;
      if (!pausedRef.current) rotRef.current += dt * 0.00004;

      const P = ORBITAL_THEMES[themeRef.current === 'light' ? 'light' : 'dark'];
      const ordered = orderedRef.current;
      const cx = W / 2, cy = H / 2 + 10;
      const R = Math.min(W, H) * 0.40 * zoomRef.current;

      // Background + star field
      ctx.save();
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      const bg = ctx.createRadialGradient(cx, cy, 0, cx, cy, Math.max(W, H) * 0.85);
      bg.addColorStop(0, P.bg0); bg.addColorStop(1, P.bg1);
      ctx.fillStyle = bg;
      ctx.fillRect(0, 0, W, H);
      for (let i = 0; i < 120; i++) {
        const s = (i * 2654435761) >>> 0;
        const sx = (s % 10000) / 10000 * W;
        const sy = ((s >> 8) % 10000) / 10000 * H;
        const a = 0.06 + ((s >> 16) % 100) / 100 * 0.12;
        ctx.fillStyle = P.star + a + ')';
        ctx.fillRect(sx, sy, 1.1, 1.1);
      }
      ctx.restore();

      // Latency rings
      ctx.save(); ctx.scale(dpr, dpr);
      RING_MS.forEach(ms => {
        const rr = pingToNorm(ms) * R;
        ctx.beginPath(); ctx.setLineDash([2, 6]);
        ctx.strokeStyle = P.ring; ctx.lineWidth = 1;
        ctx.ellipse(cx, cy, rr, rr * 0.62, 0, 0, Math.PI * 2);
        ctx.stroke(); ctx.setLineDash([]);
        ctx.font = `500 9.5px 'JetBrains Mono', ui-monospace, monospace`;
        ctx.fillStyle = P.ringLabel;
        ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
        ctx.fillText(ms + 'ms', cx, cy - rr * 0.62 - 2);
      });
      ctx.restore();

      // Spokes from server to each peer
      ctx.save(); ctx.scale(dpr, dpr);
      ordered.forEach(p => {
        const pos = orbitalPeerPos(p, rotRef.current, zoomRef.current, W, H);
        const hot = hoverPeerRef.current === p;
        ctx.strokeStyle = hot ? P.spokeHot : P.spoke;
        ctx.lineWidth = hot ? 1.4 : (p.connected ? 1 : 0.7);
        ctx.beginPath(); ctx.moveTo(cx, cy); ctx.lineTo(pos.x, pos.y); ctx.stroke();
      });
      ctx.restore();

      // Animated traffic particles
      ctx.save(); ctx.scale(dpr, dpr); ctx.lineCap = 'round';
      for (let i = particlesRef.current.length - 1; i >= 0; i--) {
        const pr = particlesRef.current[i];
        const t = (now - pr.t0) / pr.dur;
        if (t >= 1) { particlesRef.current.splice(i, 1); continue; }
        const pos = orbitalPeerPos(pr.peer, rotRef.current, zoomRef.current, W, H);
        const u = pr.dir > 0 ? t : 1 - t;
        const trail = 0.16;
        const u2 = pr.dir > 0 ? Math.max(0, u - trail) : Math.min(1, u + trail);
        const hx = cx + (pos.x - cx) * u, hy = cy + (pos.y - cy) * u;
        const tx2 = cx + (pos.x - cx) * u2, ty2 = cy + (pos.y - cy) * u2;
        const col = P[pr.kind] || P.rx;
        const grad = ctx.createLinearGradient(tx2, ty2, hx, hy);
        grad.addColorStop(0, `rgba(${col}, 0)`);
        grad.addColorStop(1, `rgba(${col}, 0.85)`);
        ctx.strokeStyle = grad;
        ctx.lineWidth = pr.size > 2000 ? 2.6 : pr.size > 600 ? 1.9 : 1.4;
        ctx.beginPath(); ctx.moveTo(tx2, ty2); ctx.lineTo(hx, hy); ctx.stroke();
        const gr = pr.size > 2000 ? 8 : 5.5;
        const g = ctx.createRadialGradient(hx, hy, 0, hx, hy, gr);
        g.addColorStop(0, `rgba(${col}, 0.95)`); g.addColorStop(1, `rgba(${col}, 0)`);
        ctx.fillStyle = g; ctx.beginPath(); ctx.arc(hx, hy, gr, 0, Math.PI * 2); ctx.fill();
        ctx.fillStyle = themeRef.current === 'dark' ? 'rgba(255,255,255,0.95)' : `rgba(${col},1)`;
        ctx.beginPath(); ctx.arc(hx, hy, 1.6, 0, Math.PI * 2); ctx.fill();
      }
      ctx.restore();

      // Server origin marker
      ctx.save(); ctx.scale(dpr, dpr);
      const ptA = (now / 1500) % 1;
      ctx.strokeStyle = `rgba(${P.serverRing}, ${(1 - ptA) * 0.5})`; ctx.lineWidth = 1.6;
      ctx.beginPath(); ctx.arc(cx, cy, 7 + ptA * 26, 0, Math.PI * 2); ctx.stroke();
      const ptB = ((now / 1500) + 0.5) % 1;
      ctx.strokeStyle = `rgba(${P.serverRing}, ${(1 - ptB) * 0.32})`;
      ctx.beginPath(); ctx.arc(cx, cy, 7 + ptB * 26, 0, Math.PI * 2); ctx.stroke();
      const sg = ctx.createRadialGradient(cx, cy, 0, cx, cy, 26);
      sg.addColorStop(0, `rgba(${P.serverGlow}, 0.55)`); sg.addColorStop(1, `rgba(${P.serverGlow}, 0)`);
      ctx.fillStyle = sg; ctx.beginPath(); ctx.arc(cx, cy, 26, 0, Math.PI * 2); ctx.fill();
      ctx.fillStyle = P.serverCore; ctx.strokeStyle = `rgba(${P.serverRing}, 0.9)`; ctx.lineWidth = 1.5;
      ctx.beginPath(); ctx.arc(cx, cy, 6, 0, Math.PI * 2); ctx.fill(); ctx.stroke();
      ctx.font = `600 12px 'Inter', system-ui, sans-serif`;
      ctx.fillStyle = P.label + '0.95)'; ctx.textAlign = 'center'; ctx.textBaseline = 'top';
      ctx.fillText(TM_SERVER.name, cx, cy + 14);
      ctx.font = `9.5px 'JetBrains Mono', ui-monospace, monospace`;
      ctx.fillStyle = P.label + '0.45)';
      ctx.fillText(TM_SERVER.country.toUpperCase(), cx, cy + 30);
      ctx.restore();

      // Peer nodes + labels
      ctx.save(); ctx.scale(dpr, dpr);
      ordered.forEach(p => {
        const pos = orbitalPeerPos(p, rotRef.current, zoomRef.current, W, H);
        const hot = hoverPeerRef.current === p;
        if (p.connected) {
          const recent = p.lastHit ? Math.max(0, 1 - (now - p.lastHit) / 600) : 0;
          const pulseT = ((now + p.phase * 300) / 1900) % 1;
          ctx.strokeStyle = `rgba(${P.peerOnGlow}, ${(1 - pulseT) * 0.4})`; ctx.lineWidth = 1.1;
          ctx.beginPath(); ctx.arc(pos.x, pos.y, 3 + pulseT * 15, 0, Math.PI * 2); ctx.stroke();
          const gr2 = 11 + recent * 7;
          const g2 = ctx.createRadialGradient(pos.x, pos.y, 0, pos.x, pos.y, gr2);
          g2.addColorStop(0, `rgba(${P.peerOnGlow}, ${0.5 + recent * 0.3})`);
          g2.addColorStop(1, `rgba(${P.peerOnGlow}, 0)`);
          ctx.fillStyle = g2; ctx.beginPath(); ctx.arc(pos.x, pos.y, gr2, 0, Math.PI * 2); ctx.fill();
          ctx.fillStyle = P.peerOn;
          ctx.beginPath(); ctx.arc(pos.x, pos.y, hot ? 4.4 : 3.4 + recent * 1.2, 0, Math.PI * 2); ctx.fill();
        } else {
          ctx.fillStyle = P.peerOff;
          ctx.beginPath(); ctx.arc(pos.x, pos.y, 2.6, 0, Math.PI * 2); ctx.fill();
        }
        if (hot || p.connected) {
          const onRight = pos.x >= cx;
          ctx.font = `${hot ? '600 ' : '500 '}11px 'Inter', system-ui, sans-serif`;
          ctx.textAlign = onRight ? 'left' : 'right'; ctx.textBaseline = 'middle';
          const lx = pos.x + (onRight ? 9 : -9);
          ctx.fillStyle = (p.connected ? P.label : P.labelOff) + (hot ? '1)' : '0.88)');
          ctx.fillText(p.name, lx, pos.y - (hot ? 6 : 0));
          if (hot) {
            ctx.font = `9.5px 'JetBrains Mono', ui-monospace, monospace`;
            ctx.fillStyle = P.label + '0.5)';
            const sub = p.connected
              ? `${p.pingMs != null ? p.pingMs + 'ms' : '—'} · ${p.country || p.addr}`
              : `offline · ${p.country || p.addr}`;
            ctx.fillText(sub, lx, pos.y + 7);
          }
        }
      });
      ctx.restore();

      rafRef.current = requestAnimationFrame(tick);
    };
    rafRef.current = requestAnimationFrame(tick);
    return () => {
      cancelAnimationFrame(rafRef.current);
      window.removeEventListener('resize', resize);
    };
  }, []);

  // Mouse / touch / wheel interaction
  React.useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    let W = 0, H = 0;
    const updateSize = () => { const r = canvas.getBoundingClientRect(); W = r.width; H = r.height; };
    updateSize();
    window.addEventListener('resize', updateSize);

    const onMouseMove = (e) => {
      const rect = canvas.getBoundingClientRect();
      const mx = e.clientX - rect.left, my = e.clientY - rect.top;
      if (draggingRef.current) {
        rotRef.current += (mx - dragXRef.current) * 0.005;
        dragXRef.current = mx;
        return;
      }
      let best = null, bestD = 26 * 26;
      orderedRef.current.forEach(p => {
        const pos = orbitalPeerPos(p, rotRef.current, zoomRef.current, W, H);
        const d = (pos.x - mx) ** 2 + (pos.y - my) ** 2;
        if (d < bestD) { bestD = d; best = p; }
      });
      hoverPeerRef.current = best;
      canvas.style.cursor = best ? 'pointer' : 'crosshair';
    };
    const onMouseLeave = () => { hoverPeerRef.current = null; };
    const onMouseDown = (e) => {
      draggingRef.current = true;
      dragXRef.current = e.clientX - canvas.getBoundingClientRect().left;
      canvas.style.cursor = 'grabbing';
    };
    const onMouseUp = () => { draggingRef.current = false; canvas.style.cursor = 'crosshair'; };
    const onWheel = (e) => {
      e.preventDefault();
      zoomRef.current = Math.max(0.5, Math.min(2.0, zoomRef.current * Math.exp(-e.deltaY * 0.0012)));
    };
    const onTouchStart = (e) => { draggingRef.current = true; dragXRef.current = e.touches[0].clientX; };
    const onTouchMove = (e) => {
      if (!draggingRef.current) return;
      rotRef.current += (e.touches[0].clientX - dragXRef.current) * 0.005;
      dragXRef.current = e.touches[0].clientX;
    };
    const onTouchEnd = () => { draggingRef.current = false; };

    canvas.addEventListener('mousemove', onMouseMove);
    canvas.addEventListener('mouseleave', onMouseLeave);
    canvas.addEventListener('mousedown', onMouseDown);
    window.addEventListener('mouseup', onMouseUp);
    canvas.addEventListener('wheel', onWheel, { passive: false });
    canvas.addEventListener('touchstart', onTouchStart, { passive: true });
    canvas.addEventListener('touchmove', onTouchMove, { passive: true });
    canvas.addEventListener('touchend', onTouchEnd);
    return () => {
      canvas.removeEventListener('mousemove', onMouseMove);
      canvas.removeEventListener('mouseleave', onMouseLeave);
      canvas.removeEventListener('mousedown', onMouseDown);
      window.removeEventListener('mouseup', onMouseUp);
      canvas.removeEventListener('wheel', onWheel);
      canvas.removeEventListener('touchstart', onTouchStart);
      canvas.removeEventListener('touchmove', onTouchMove);
      canvas.removeEventListener('touchend', onTouchEnd);
      window.removeEventListener('resize', updateSize);
    };
  }, []);

  // Keyboard shortcuts
  React.useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') onClose();
      if (e.key === ' ') { e.preventDefault(); setPaused(p => !p); }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const connected = peers.filter(p => p.status === 'connected');
  const lightClass = theme === 'light' ? ' tm-light' : '';

  return (
    <div className={'tm-root' + lightClass}>
      <canvas ref={canvasRef} className="tm-canvas tm-canvas-orbital" />

      <div className="tm-top">
        <div className="tm-top-left">
          <div className="tm-brand">
            <div className="tm-brand-dot" />
            <div>
              <div className="tm-brand-name">Traffic View</div>
            </div>
          </div>
        </div>
        <div className="tm-top-center">
          <div className="tm-toptag"><span className="tm-tag-dot" /> {connected.length} peer{connected.length === 1 ? '' : 's'} active</div>
          <div className="tm-toptag tm-toptag-mono">{stats.events} events · {formatTmBytes(stats.bytes)}</div>
        </div>
        <div className="tm-top-right">
          <button
            className={'tm-iconbtn tm-log-btn' + (logOpen ? ' tm-log-btn-active' : '')}
            onClick={() => setLogOpen(o => !o)}
            title="Toggle access log"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
              <path d="M4 6h16M4 12h16M4 18h10"/>
            </svg>
          </button>
          <button className="tm-iconbtn" onClick={() => setPaused(p => !p)} title="Pause (space)">
            {paused ? (
              <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M6 4l14 8-14 8V4z"/></svg>
            ) : (
              <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="5" width="4" height="14"/><rect x="14" y="5" width="4" height="14"/></svg>
            )}
          </button>
          <button className="tm-iconbtn" onClick={onClose} title="Close (esc)">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M6 6l12 12M18 6L6 18"/>
            </svg>
          </button>
        </div>
      </div>

      {/* Log drawer — slides in from the right */}
      <div className={'tm-orbital-log' + (logOpen ? ' tm-orbital-log-open' : '')}>
        <div className="tm-log-head">
          <span className="tm-log-title">LIVE ACCESS LOG</span>
          <div className="tm-head-right">
            <span className="tm-log-meta"><span className="tm-livedot" /> streaming</span>
            <button className="tm-iconbtn tm-log-close-btn" onClick={() => setLogOpen(false)} title="Close log">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M6 6l12 12M18 6L6 18"/>
              </svg>
            </button>
          </div>
        </div>
        <div className="tm-log-body tm-orbital-log-scroll">
          {events.length === 0 && <div className="tm-log-empty">Waiting for traffic…</div>}
          {events.map((e, i) => (
            <div key={i} className={`tm-log-row tm-log-${e.kind}`} style={{ opacity: Math.max(0.25, 1 - i * 0.04) }}>
              <span className="tm-log-time">{formatTmClock(e.ts)}</span>
              <span className={`tm-log-kind tm-log-kind-${e.kind}`}>{e.label}</span>
              <span className="tm-log-peer">{e.peer}</span>
              {e.size > 0 && <span className="tm-log-size">{e.size.toFixed(0)} KB</span>}
            </div>
          ))}
        </div>
        <div className="tm-orbital-legend">
          <div className="tm-leg-row">
            <span className="tm-leg-swatch" style={{ color: 'var(--tm-accent)' }} />
            inbound · rx
          </div>
          <div className="tm-leg-row">
            <span className="tm-leg-swatch" style={{ color: 'var(--tm-green)' }} />
            outbound · tx
          </div>
          <div className="tm-leg-divider" />
          <div className="tm-leg-note">
            Rings map round-trip latency, not geography.<br/>
            inner → outer: <b>25 · 75 · 150 · 250 ms</b>
          </div>
        </div>
      </div>

      <div className="tm-orbital-hint">drag to rotate · scroll to zoom · hover a node</div>
    </div>
  );
}

function formatTmBytes(b) {
  if (b < 1024) return b.toFixed(0) + ' B';
  if (b < 1024 * 1024) return (b / 1024).toFixed(1) + ' KB';
  if (b < 1024 * 1024 * 1024) return (b / 1024 / 1024).toFixed(1) + ' MB';
  return (b / 1024 / 1024 / 1024).toFixed(2) + ' GB';
}
function formatTmClock(t) {
  const d = new Date(t);
  const pad = (n) => String(n).padStart(2, '0');
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

Object.assign(window, { TrafficMode });

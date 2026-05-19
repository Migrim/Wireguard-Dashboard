// Traffic Mode — fullscreen 3D globe with live peer access visualization
// Supports light + dark themes with smooth crossfade.

const TM_SERVER = { name: 'wg0 · DE-FRA-01', lat: 50.11, lng: 8.68, country: 'Frankfurt' };

// ============================================================
// Palettes — dark + light. Canvas blends between these per-frame.
// ============================================================
const TM_DARK = {
  bg: [8, 6, 10],
  star: [230, 220, 200],
  haloCore: [217, 119, 87],
  sphereLight: [40, 30, 26],
  sphereMid: [20, 14, 12],
  sphereDark: [10, 8, 8],
  rim: [217, 119, 87],
  rimAlpha: 0.30,
  wire: [240, 220, 200],
  wireAlpha: 1,
  surfaceDot: [230, 210, 180],
  landDot: [245, 220, 188],
  country: [255, 230, 200],
  countryAlpha: 0.55,
  serverGlow: [247, 175, 130],
  serverRing: [217, 119, 87],
  serverCore: [255, 220, 190],
  serverCoreStroke: [255, 100, 50],
  peerOnGlow: [150, 230, 180],
  peerOnRing: [120, 220, 170],
  peerOnCore: [220, 255, 230],
  peerOnCoreStroke: [80, 200, 140],
  peerOff: [180, 160, 140],
  label: [220, 255, 230],
  labelOff: [200, 190, 180],
  arcTrailWhite: [255, 255, 255],
};
const TM_LIGHT = {
  bg: [248, 244, 235],
  star: [200, 180, 150],
  haloCore: [217, 119, 87],
  sphereLight: [255, 252, 244],
  sphereMid: [245, 238, 224],
  sphereDark: [230, 218, 196],
  rim: [180, 110, 70],
  rimAlpha: 0.35,
  wire: [120, 90, 60],
  wireAlpha: 1.2,
  surfaceDot: [120, 90, 60],
  landDot: [70, 50, 35],
  country: [50, 30, 15],
  countryAlpha: 0.7,
  serverGlow: [217, 119, 87],
  serverRing: [180, 80, 40],
  serverCore: [180, 70, 30],
  serverCoreStroke: [255, 240, 220],
  peerOnGlow: [60, 160, 110],
  peerOnRing: [40, 130, 90],
  peerOnCore: [30, 110, 70],
  peerOnCoreStroke: [220, 255, 230],
  peerOff: [150, 130, 110],
  label: [40, 80, 55],
  labelOff: [130, 115, 95],
  arcTrailWhite: [40, 30, 20],
};

function tmBlendPalette(t) {
  const out = {};
  for (const k of Object.keys(TM_DARK)) {
    const a = TM_DARK[k], b = TM_LIGHT[k];
    if (Array.isArray(a)) {
      out[k] = [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t];
    } else {
      out[k] = a + (b - a) * t;
    }
  }
  return out;
}
function rgba(c, a) { return `rgba(${c[0]|0}, ${c[1]|0}, ${c[2]|0}, ${a})`; }

function TrafficMode({ peers, theme, onClose }) {
  const canvasRef = React.useRef(null);
  const rafRef = React.useRef(null);
  const eventsRef = React.useRef([]);
  const rotRef = React.useRef({ y: 0, x: 0, ty: 0, tx: 0, vy: 0.0006, manualUntil: 0 });
  const dragRef = React.useRef({ active: false, lastX: 0, lastY: 0 });
  const zoomRef = React.useRef(1);
  const pinchRef = React.useRef(null);
  const [zoom, setZoom] = React.useState(1);
  const [dragging, setDragging] = React.useState(false);
  const [countryLines, setCountryLines] = React.useState(null);
  const [logCollapsed, setLogCollapsed] = React.useState(false);
  const [peersCollapsed, setPeersCollapsed] = React.useState(false);
  const themeMixRef = React.useRef(theme === 'light' ? 1 : 0);
  const themeTargetRef = React.useRef(theme === 'light' ? 1 : 0);
  const [events, setEvents] = React.useState([]);
  const [stats, setStats] = React.useState({ pings: 0, bytes: 0, started: Date.now() });
  const [paused, setPaused] = React.useState(false);
  const pausedRef = React.useRef(false);
  React.useEffect(() => { pausedRef.current = paused; }, [paused]);

  // Cluster expansion state — ref mirrors state so tick loop always reads current value
  const [expandedCluster, setExpandedCluster] = React.useState(null); // { peers: [] }
  const expandedClusterRef = React.useRef(null);
  React.useEffect(() => { expandedClusterRef.current = expandedCluster; }, [expandedCluster]);

  // Last-frame cluster hit areas for click detection (canvas-px coords)
  const clustersLastFrameRef = React.useRef([]);

  // Smooth zoom — target is animated toward in the tick loop
  const zoomTargetRef = React.useRef(1);

  React.useEffect(() => {
    themeTargetRef.current = theme === 'light' ? 1 : 0;
  }, [theme]);

  React.useEffect(() => {
    const v = latLngToVec(TM_SERVER.lat, TM_SERVER.lng);
    const y0 = Math.atan2(-v[0], v[2]);
    const x0 = Math.atan2(v[1], Math.hypot(v[0], v[2])) * 0.7;
    rotRef.current.y = y0; rotRef.current.ty = y0;
    rotRef.current.x = x0; rotRef.current.tx = x0;
  }, []);

  React.useEffect(() => {
    let alive = true;
    fetch('https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/countries-110m.json')
      .then(r => r.json())
      .then(topo => {
        if (!alive || !window.topojson) return;
        const mesh = window.topojson.mesh(topo, topo.objects.countries);
        const lines = mesh.coordinates.map(line =>
          line.map(([lng, lat]) => latLngToVec(lat, lng))
        );
        setCountryLines(lines);
      })
      .catch(() => {});
    return () => { alive = false; };
  }, []);

  const sphereDots = React.useMemo(() => {
    const n = 1600;
    const pts = [];
    const golden = Math.PI * (3 - Math.sqrt(5));
    for (let i = 0; i < n; i++) {
      const y = 1 - (i / (n - 1)) * 2;
      const r = Math.sqrt(1 - y * y);
      const th = golden * i;
      pts.push([Math.cos(th) * r, y, Math.sin(th) * r]);
    }
    return pts;
  }, []);

  const wireLines = React.useMemo(() => {
    const lines = [];
    for (let lat = -60; lat <= 60; lat += 30) {
      const ring = [];
      for (let lng = 0; lng <= 360; lng += 6) ring.push(latLngToVec(lat, lng));
      lines.push(ring);
    }
    for (let lng = 0; lng < 360; lng += 30) {
      const meridian = [];
      for (let lat = -90; lat <= 90; lat += 6) meridian.push(latLngToVec(lat, lng));
      lines.push(meridian);
    }
    return lines;
  }, []);

  const landDots = React.useMemo(() => buildLandDots(), []);

  React.useEffect(() => {
    const connected = peers.filter(p => p.status === 'connected');
    if (connected.length === 0) return;
    const emit = () => {
      if (pausedRef.current) return;
      const peer = connected[Math.floor(Math.random() * connected.length)];
      if (peer.lat != null && peer.lng != null && !dragRef.current.active && performance.now() > rotRef.current.manualUntil) {
        const pv = latLngToVec(peer.lat, peer.lng);
        rotRef.current.ty = Math.atan2(-pv[0], pv[2]);
        rotRef.current.tx = Math.atan2(pv[1], Math.hypot(pv[0], pv[2])) * 0.55;
      }
      const kinds = [
        { k: 'rx', label: 'rx', size: Math.random() * 800 + 80 },
        { k: 'rx', label: 'rx', size: Math.random() * 1500 + 200 },
        { k: 'tx', label: 'tx', size: Math.random() * 400 + 40 },
        { k: 'hs', label: 'handshake', size: 0 },
        { k: 'ka', label: 'keepalive', size: 0 },
      ];
      const kind = kinds[Math.floor(Math.random() * kinds.length)];
      const ev = {
        id: 'e' + Date.now() + Math.random(),
        from: latLngToVec(TM_SERVER.lat, TM_SERVER.lng),
        to: latLngToVec(peer.lat != null ? peer.lat : 0, peer.lng != null ? peer.lng : 0),
        peer, kind: kind.k, label: kind.label, sizeKB: kind.size,
        t0: performance.now(), dur: 1400 + Math.random() * 600,
      };
      eventsRef.current.push(ev);
      setEvents(prev => [{ ts: Date.now(), peer: peer.name, kind: kind.k, label: kind.label, size: kind.size }, ...prev].slice(0, 8));
      setStats(s => ({ ...s, pings: s.pings + 1, bytes: s.bytes + kind.size * 1024 }));
    };
    setTimeout(emit, 400);
    setTimeout(emit, 900);
    const interval = setInterval(emit, 1100 + Math.random() * 500);
    return () => clearInterval(interval);
  }, [peers]);

  React.useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let dpr = window.devicePixelRatio || 1;

    const resize = () => {
      dpr = window.devicePixelRatio || 1;
      const r = canvas.getBoundingClientRect();
      canvas.width = r.width * dpr;
      canvas.height = r.height * dpr;
    };
    resize();
    window.addEventListener('resize', resize);

    const tick = () => {
      const w = canvas.width;
      const h = canvas.height;
      const cx = w / 2;
      const cy = h / 2;
      const R = Math.min(w, h) * 0.38 * zoomRef.current;

      if (!pausedRef.current) {
        const r = rotRef.current;
        if (!dragRef.current.active && performance.now() > r.manualUntil) {
          const dY = wrapAngle(r.ty - r.y);
          const dX = r.tx - r.x;
          r.y += dY * 0.03 + r.vy;
          r.x += dX * 0.05;
        }
        r.x = Math.max(-Math.PI * 0.45, Math.min(Math.PI * 0.45, r.x));
      }

      // Smooth zoom animation toward target
      {
        const zCur = zoomRef.current;
        const zTgt = zoomTargetRef.current;
        const zDiff = zTgt - zCur;
        if (Math.abs(zDiff) > 0.005) {
          zoomRef.current = zCur + zDiff * 0.12;
          setZoom(zoomRef.current);
        }
      }

      const target = themeTargetRef.current;
      const cur = themeMixRef.current;
      const diff = target - cur;
      themeMixRef.current = Math.abs(diff) < 0.001 ? target : cur + diff * 0.08;
      const t = themeMixRef.current;
      const P = tmBlendPalette(t);
      const isLight = t > 0.5;

      ctx.fillStyle = rgba(P.bg, 1);
      ctx.fillRect(0, 0, w, h);

      drawStars(ctx, w, h, P, t);

      // ── Glow layers (drawn back-to-front before the sphere) ──
      if (!isLight) {
        // 1. Deep-space void: large, very faint cool-purple ambient
        const spaceAmb = ctx.createRadialGradient(cx, cy, R * 0.6, cx, cy, R * 2.8);
        spaceAmb.addColorStop(0,   rgba([20, 14, 34], 0));
        spaceAmb.addColorStop(0.4, rgba([14, 10, 26], 0.22));
        spaceAmb.addColorStop(1,   rgba([6,  4, 12],  0));
        ctx.fillStyle = spaceAmb;
        ctx.beginPath(); ctx.arc(cx, cy, R * 2.8, 0, Math.PI * 2); ctx.fill();
      }

      // 2. Tight atmospheric rim — warm terracotta hugging the sphere edge
      const atmAlpha = isLight ? 0.05 : 0.38;
      const atm = ctx.createRadialGradient(cx, cy, R * 0.88, cx, cy, R * 1.20);
      atm.addColorStop(0,    rgba(P.haloCore, 0));
      atm.addColorStop(0.45, rgba(P.haloCore, atmAlpha));
      atm.addColorStop(0.80, rgba(P.haloCore, atmAlpha * 0.25));
      atm.addColorStop(1,    rgba(P.haloCore, 0));
      ctx.fillStyle = atm;
      ctx.beginPath(); ctx.arc(cx, cy, R * 1.20, 0, Math.PI * 2); ctx.fill();

      // 3. Soft outer corona — wide, very faint halo for depth
      const coronaAlpha = isLight ? 0.02 : 0.10;
      const corona = ctx.createRadialGradient(cx, cy, R * 1.0, cx, cy, R * 1.75);
      corona.addColorStop(0, rgba(P.haloCore, coronaAlpha));
      corona.addColorStop(1, rgba(P.haloCore, 0));
      ctx.fillStyle = corona;
      ctx.beginPath(); ctx.arc(cx, cy, R * 1.75, 0, Math.PI * 2); ctx.fill();

      // ── Globe sphere ──────────────────────────────────────────
      const sphere = ctx.createRadialGradient(cx - R * 0.3, cy - R * 0.4, 0, cx, cy, R);
      sphere.addColorStop(0,   rgba(P.sphereLight, isLight ? 0.95 : 0.88));
      sphere.addColorStop(0.7, rgba(P.sphereMid,   0.94));
      sphere.addColorStop(1,   rgba(P.sphereDark,  1.00));
      ctx.fillStyle = sphere;
      ctx.beginPath(); ctx.arc(cx, cy, R, 0, Math.PI * 2); ctx.fill();

      // Crisp rim stroke
      ctx.strokeStyle = rgba(P.rim, P.rimAlpha);
      ctx.lineWidth = (isLight ? 1.0 : 1.5) * dpr;
      ctx.beginPath(); ctx.arc(cx, cy, R, 0, Math.PI * 2); ctx.stroke();

      // Dark mode: second, slightly wider softer rim for a clean glowing edge
      if (!isLight) {
        ctx.strokeStyle = rgba(P.haloCore, 0.12);
        ctx.lineWidth = 4 * dpr;
        ctx.beginPath(); ctx.arc(cx, cy, R, 0, Math.PI * 2); ctx.stroke();
      }

      const ry = rotRef.current.y;
      const rx = rotRef.current.x;

      ctx.lineWidth = 0.5 * dpr;
      wireLines.forEach(line => {
        ctx.beginPath();
        let drawing = false;
        line.forEach(v => {
          const [x, y, z] = applyRot(v, ry, rx);
          const sx = cx + x * R;
          const sy = cy - y * R;
          if (z > -0.05) {
            const baseA = Math.max(0.05, Math.min(0.22, z * 0.3 + 0.12));
            ctx.strokeStyle = rgba(P.wire, baseA * P.wireAlpha);
            if (!drawing) { ctx.moveTo(sx, sy); drawing = true; }
            else ctx.lineTo(sx, sy);
          } else {
            if (drawing) { ctx.stroke(); ctx.beginPath(); drawing = false; }
          }
        });
        if (drawing) ctx.stroke();
      });

      sphereDots.forEach(v => {
        const [x, y, z] = applyRot(v, ry, rx);
        if (z < 0) return;
        const sx = cx + x * R;
        const sy = cy - y * R;
        const a = Math.pow(z, 1.5) * (isLight ? 0.22 : 0.18);
        ctx.fillStyle = rgba(P.surfaceDot, a);
        ctx.fillRect(sx - 0.5 * dpr, sy - 0.5 * dpr, 1 * dpr, 1 * dpr);
      });

      const landDotMul = countryLines ? 0.35 : 1;
      landDots.forEach(v => {
        const [x, y, z] = applyRot(v, ry, rx);
        if (z < 0) return;
        const sx = cx + x * R;
        const sy = cy - y * R;
        const a = Math.pow(z, 1.2) * (isLight ? 0.85 : 0.7) * landDotMul;
        ctx.fillStyle = rgba(P.landDot, a);
        ctx.beginPath();
        ctx.arc(sx, sy, 1.2 * dpr, 0, Math.PI * 2);
        ctx.fill();
      });

      if (countryLines) {
        ctx.lineWidth = 0.7 * dpr;
        ctx.lineCap = 'round';
        ctx.lineJoin = 'round';
        for (let li = 0; li < countryLines.length; li++) {
          const line = countryLines[li];
          let prev = null;
          let prevZ = -1;
          for (let pi = 0; pi < line.length; pi++) {
            const v = applyRot(line[pi], ry, rx);
            const z = v[2];
            if (prev && (prevZ > -0.02 || z > -0.02)) {
              const mz = (prevZ + z) * 0.5;
              if (mz > -0.02) {
                const a = Math.max(0.05, Math.min(0.95, mz * 0.9 + 0.15)) * P.countryAlpha;
                ctx.strokeStyle = rgba(P.country, a);
                ctx.beginPath();
                ctx.moveTo(cx + prev[0] * R, cy - prev[1] * R);
                ctx.lineTo(cx + v[0] * R, cy - v[1] * R);
                ctx.stroke();
              }
            }
            prev = v;
            prevZ = z;
          }
        }
      }

      const serverVec = latLngToVec(TM_SERVER.lat, TM_SERVER.lng);
      drawServerMarker(ctx, serverVec, ry, rx, cx, cy, R, dpr, performance.now(), P);

      // ── Cluster-aware peer rendering ──────────────────────────
      const CLUSTER_PX = 28 * dpr;
      const now2 = performance.now();

      // 1. Compute screen positions for all geolocated peers
      const peerItems = [];
      peers.forEach(p => {
        if (p.lat == null || p.lng == null) return;
        const vec = latLngToVec(p.lat, p.lng);
        const [vx, vy, vz] = applyRot(vec, ry, rx);
        peerItems.push({ peer: p, vec, sx: cx + vx * R, sy: cy - vy * R, z: vz });
      });

      // 2. Greedy cluster pass (screen-space proximity)
      const assigned = new Set();
      const clusters = [];
      peerItems.forEach((item, i) => {
        if (assigned.has(i)) return;
        const grp = [item];
        assigned.add(i);
        peerItems.forEach((other, j) => {
          if (i === j || assigned.has(j)) return;
          if (Math.hypot(other.sx - item.sx, other.sy - item.sy) < CLUSTER_PX) {
            grp.push(other); assigned.add(j);
          }
        });
        const avgSx = grp.reduce((s, c) => s + c.sx, 0) / grp.length;
        const avgSy = grp.reduce((s, c) => s + c.sy, 0) / grp.length;
        const avgZ  = grp.reduce((s, c) => s + c.z,  0) / grp.length;
        clusters.push({ items: grp, sx: avgSx, sy: avgSy, z: avgZ });
      });
      clustersLastFrameRef.current = clusters;

      // 3. Draw each cluster
      const expanded = expandedClusterRef.current;
      const expandedIds = expanded ? new Set(expanded.peers.map(p => p.id)) : null;

      clusters.forEach(cluster => {
        const n = cluster.items.length;
        if (n === 1) {
          // Single peer — normal marker
          const { vec, peer, z } = cluster.items[0];
          drawPeerMarker(ctx, vec, ry, rx, cx, cy, R, dpr, peer, now2, P);
        } else {
          // Multi-peer cluster
          const isExpanded = expandedIds && cluster.items.every(item => expandedIds.has(item.peer.id));
          if (isExpanded) {
            // Spread peers in screen space around cluster center
            const { sx: csx, sy: csy } = cluster;
            const spreadPx = 70 * dpr;
            cluster.items.forEach((item, i) => {
              const angle = n === 2
                ? (i === 0 ? Math.PI : 0)        // left / right for 2 peers
                : (i / n) * Math.PI * 2 - Math.PI / 2;
              const ox = Math.cos(angle) * spreadPx * (n === 2 ? 1 : 0.9);
              const oy = Math.sin(angle) * spreadPx * (n === 2 ? 0.3 : 0.9);
              drawPeerMarker(ctx, item.vec, ry, rx, cx, cy, R, dpr, item.peer, now2, P, ox, oy);
            });
            // Distance line + label between first two
            if (n >= 2) {
              const aItem = cluster.items[0], bItem = cluster.items[1];
              const ax = csx - spreadPx,  ay = csy;
              const bx = csx + spreadPx, by = csy;
              const padding = 12 * dpr;
              ctx.save();
              ctx.setLineDash([4 * dpr, 4 * dpr]);
              ctx.strokeStyle = rgba(P.wire, 0.45);
              ctx.lineWidth = 1 * dpr;
              ctx.beginPath();
              ctx.moveTo(ax + padding, ay);
              ctx.lineTo(bx - padding, by);
              ctx.stroke();
              ctx.restore();

              const distKm = haversineKm(aItem.peer.lat, aItem.peer.lng, bItem.peer.lat, bItem.peer.lng);
              const distLabel = distKm < 0.05
                ? 'same location'
                : distKm < 1
                  ? `${(distKm * 1000).toFixed(0)} m apart`
                  : `${distKm.toFixed(1)} km apart`;
              ctx.font = `${9 * dpr}px ui-monospace, SF Mono, JetBrains Mono, monospace`;
              ctx.textAlign = 'center';
              ctx.textBaseline = 'bottom';
              ctx.fillStyle = rgba(P.wire, 0.7);
              ctx.fillText(distLabel, (ax + bx) / 2, ay - 6 * dpr);
            }
            // "click to collapse" hint
            ctx.font = `${8 * dpr}px ui-monospace, SF Mono, JetBrains Mono, monospace`;
            ctx.textAlign = 'center';
            ctx.textBaseline = 'top';
            ctx.fillStyle = rgba(P.peerOnRing, 0.5);
            ctx.fillText('tap to collapse', cluster.sx, cluster.sy + 24 * dpr);
          } else {
            drawClusterBadge(ctx, cluster.sx, cluster.sy, cluster.z, dpr, n, now2, P);
          }
        }
      });

      const now = performance.now();
      eventsRef.current = eventsRef.current.filter(ev => now - ev.t0 < ev.dur + 600);
      eventsRef.current.forEach(ev => drawArc(ctx, ev, ry, rx, cx, cy, R, dpr, now, P));

      rafRef.current = requestAnimationFrame(tick);
    };
    rafRef.current = requestAnimationFrame(tick);

    return () => {
      cancelAnimationFrame(rafRef.current);
      window.removeEventListener('resize', resize);
    };
  }, [peers, sphereDots, wireLines, landDots, countryLines]);

  React.useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const SENS = 0.005;
    const getPt = (e) => e.touches && e.touches[0] ? e.touches[0] : e;
    const onDown = (e) => {
      const pt = getPt(e);
      dragRef.current.active = true;
      dragRef.current.lastX = pt.clientX;
      dragRef.current.lastY = pt.clientY;
      dragRef.current.downX = pt.clientX;
      dragRef.current.downY = pt.clientY;
      rotRef.current.manualUntil = Number.POSITIVE_INFINITY;
      setDragging(true);
      if (e.preventDefault && e.touches) e.preventDefault();
      if (canvas.setPointerCapture && e.pointerId != null) {
        try { canvas.setPointerCapture(e.pointerId); } catch {}
      }
    };
    const onMove = (e) => {
      if (!dragRef.current.active) return;
      const pt = getPt(e);
      const dx = pt.clientX - dragRef.current.lastX;
      const dy = pt.clientY - dragRef.current.lastY;
      dragRef.current.lastX = pt.clientX;
      dragRef.current.lastY = pt.clientY;
      const r = rotRef.current;
      r.y += dx * SENS;
      r.x += dy * SENS;
      r.x = Math.max(-Math.PI * 0.45, Math.min(Math.PI * 0.45, r.x));
      r.ty = r.y; r.tx = r.x;
      if (e.preventDefault && e.touches) e.preventDefault();
    };
    const onUp = (e) => {
      if (!dragRef.current.active) return;
      dragRef.current.active = false;
      rotRef.current.manualUntil = performance.now() + 6000;
      setDragging(false);

      // Click detection: only fire if pointer barely moved
      const pt = getPt(e);
      const ptX = pt ? pt.clientX : dragRef.current.lastX;
      const ptY = pt ? pt.clientY : dragRef.current.lastY;
      const moved = Math.hypot(ptX - (dragRef.current.downX || ptX), ptY - (dragRef.current.downY || ptY));
      if (moved > 8) return;

      // Hit-test clusters
      const dpr = window.devicePixelRatio || 1;
      const rect = canvas.getBoundingClientRect();
      const cx = (ptX - rect.left) * dpr;
      const cy = (ptY - rect.top) * dpr;
      const clusters = clustersLastFrameRef.current;
      const hit = clusters.find(c => c.items.length >= 2 && Math.hypot(cx - c.sx, cy - c.sy) < 32 * dpr);
      if (!hit) return;

      const curExpanded = expandedClusterRef.current;
      const hitIds = new Set(hit.items.map(i => i.peer.id));
      const isSame = curExpanded && curExpanded.peers.length === hit.items.length &&
        curExpanded.peers.every(p => hitIds.has(p.id));

      if (isSame) {
        // Collapse
        setExpandedCluster(null);
        zoomTargetRef.current = 1;
        rotRef.current.manualUntil = 0; // re-enable auto-pan
      } else {
        // Expand: zoom insanely close and face the cluster
        setExpandedCluster({ peers: hit.items.map(i => i.peer) });
        zoomTargetRef.current = 22;

        // Rotate globe to center on cluster centroid
        const vecs = hit.items.map(i => i.vec);
        const raw = vecs.reduce(([ax, ay, az], v) => [ax + v[0], ay + v[1], az + v[2]], [0, 0, 0]);
        const mag = Math.hypot(...raw) || 1;
        const cv = raw.map(v => v / mag);
        rotRef.current.ty = Math.atan2(-cv[0], cv[2]);
        rotRef.current.tx = Math.atan2(cv[1], Math.hypot(cv[0], cv[2])) * 0.55;
        rotRef.current.manualUntil = Number.POSITIVE_INFINITY;
      }
    };
    canvas.addEventListener('pointerdown', onDown);
    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp);
    window.addEventListener('pointercancel', onUp);
    canvas.addEventListener('touchstart', onDown, { passive: false });
    window.addEventListener('touchmove', onMove, { passive: false });
    window.addEventListener('touchend', onUp);

    const ZOOM_MIN = 0.5, ZOOM_MAX = 30;
    const onWheel = (e) => {
      e.preventDefault();
      const factor = Math.exp(-e.deltaY * 0.0015);
      const next = Math.max(ZOOM_MIN, Math.min(ZOOM_MAX, zoomTargetRef.current * factor));
      zoomTargetRef.current = next;
      // Also collapse expanded cluster when manually zooming out
      if (next < 8 && expandedClusterRef.current) {
        setExpandedCluster(null);
      }
    };
    canvas.addEventListener('wheel', onWheel, { passive: false });

    const onTouchStart = (e) => {
      if (e.touches.length === 2) {
        const dx = e.touches[0].clientX - e.touches[1].clientX;
        const dy = e.touches[0].clientY - e.touches[1].clientY;
        pinchRef.current = { dist: Math.hypot(dx, dy), zoom: zoomTargetRef.current };
        dragRef.current.active = false;
        e.preventDefault();
      }
    };
    const onTouchMove = (e) => {
      if (e.touches.length === 2 && pinchRef.current) {
        const dx = e.touches[0].clientX - e.touches[1].clientX;
        const dy = e.touches[0].clientY - e.touches[1].clientY;
        const dist = Math.hypot(dx, dy);
        const next = Math.max(ZOOM_MIN, Math.min(ZOOM_MAX, pinchRef.current.zoom * dist / pinchRef.current.dist));
        zoomTargetRef.current = next;
        rotRef.current.manualUntil = Number.POSITIVE_INFINITY;
        e.preventDefault();
      }
    };
    const onTouchEnd = (e) => {
      if (pinchRef.current && e.touches.length < 2) {
        pinchRef.current = null;
        rotRef.current.manualUntil = performance.now() + 6000;
      }
    };
    canvas.addEventListener('touchstart', onTouchStart, { passive: false });
    canvas.addEventListener('touchmove', onTouchMove, { passive: false });
    canvas.addEventListener('touchend', onTouchEnd);

    return () => {
      canvas.removeEventListener('pointerdown', onDown);
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', onUp);
      window.removeEventListener('pointercancel', onUp);
      canvas.removeEventListener('touchstart', onDown);
      window.removeEventListener('touchmove', onMove);
      window.removeEventListener('touchend', onUp);
      canvas.removeEventListener('wheel', onWheel);
      canvas.removeEventListener('touchstart', onTouchStart);
      canvas.removeEventListener('touchmove', onTouchMove);
      canvas.removeEventListener('touchend', onTouchEnd);
    };
  }, []);

  React.useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') {
        if (expandedClusterRef.current) {
          setExpandedCluster(null);
          zoomTargetRef.current = 1;
          rotRef.current.manualUntil = 0;
        } else {
          onClose();
        }
      }
      if (e.key === ' ') { e.preventDefault(); setPaused(p => !p); }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const connected = peers.filter(p => p.status === 'connected');
  const lightClass = theme === 'light' ? ' tm-light' : '';

  return (
    <div className={'tm-root' + lightClass}>
      <canvas ref={canvasRef} className={'tm-canvas' + (dragging ? ' tm-grabbing' : '')} />

      <div className="tm-top">
        <div className="tm-top-left">
          <div className="tm-brand">
            <div className="tm-brand-dot" />
            <div>
              <div className="tm-brand-name">Traffic Mode</div>
              <div className="tm-brand-sub">wg0 · live access · {TM_SERVER.country}</div>
            </div>
          </div>
        </div>
        <div className="tm-top-center">
          <div className="tm-toptag"><span className="tm-tag-dot" /> {connected.length} peer{connected.length === 1 ? '' : 's'} streaming</div>
          <div className="tm-toptag tm-toptag-mono">{stats.pings} events · {formatTmBytes(stats.bytes)} since {formatTmClock(stats.started)}</div>
        </div>
        <div className="tm-top-right">
          <button className="tm-iconbtn" onClick={() => setPaused(p => !p)} title="Pause (space)">
            {paused ? (
              <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M6 4l14 8-14 8V4z"/></svg>
            ) : (
              <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="5" width="4" height="14"/><rect x="14" y="5" width="4" height="14"/></svg>
            )}
          </button>
          <button className="tm-iconbtn" onClick={onClose} title="Close (esc)">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M6 6l12 12M18 6L6 18"/></svg>
          </button>
        </div>
      </div>

      <div className={'tm-log' + (logCollapsed ? ' tm-collapsed' : '')}>
        <div className="tm-log-head">
          <span className="tm-log-title">LIVE ACCESS LOG</span>
          <div className="tm-head-right">
            <span className="tm-log-meta"><span className="tm-livedot" /> streaming</span>
            <button
              className="tm-collapse-btn"
              onClick={() => setLogCollapsed(c => !c)}
              title={logCollapsed ? 'Show log' : 'Hide log'}
              aria-label={logCollapsed ? 'Show log' : 'Hide log'}
            >
              <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M2 4l3 3 3-3"/></svg>
            </button>
          </div>
        </div>
        <div className="tm-log-body">
          {events.length === 0 && <div className="tm-log-empty">Waiting for traffic…</div>}
          {events.map((e, i) => (
            <div key={i} className={`tm-log-row tm-log-${e.kind}`} style={{ opacity: 1 - i * 0.08 }}>
              <span className="tm-log-time">{formatTmClock(e.ts)}</span>
              <span className={`tm-log-kind tm-log-kind-${e.kind}`}>{e.label}</span>
              <span className="tm-log-peer">{e.peer}</span>
              {e.size > 0 && <span className="tm-log-size">{e.size.toFixed(0)} KB</span>}
            </div>
          ))}
        </div>
      </div>

      <div className={'tm-peers' + (peersCollapsed ? ' tm-collapsed' : '')}>
        <div className="tm-peers-head">
          <span className="tm-log-title">PEERS</span>
          <div className="tm-head-right">
            <span className="tm-log-meta tm-mono">{connected.length}/{peers.length}</span>
            <button
              className="tm-collapse-btn"
              onClick={() => setPeersCollapsed(c => !c)}
              title={peersCollapsed ? 'Show peers' : 'Hide peers'}
              aria-label={peersCollapsed ? 'Show peers' : 'Hide peers'}
            >
              <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M2 4l3 3 3-3"/></svg>
            </button>
          </div>
        </div>
        <div className="tm-peers-body">
          <div className="tm-peer-row tm-peer-server">
            <span className="tm-pin tm-pin-server" />
            <div className="tm-peer-info">
              <div className="tm-peer-name">{TM_SERVER.name}</div>
              <div className="tm-peer-loc">{TM_SERVER.country} · {TM_SERVER.lat.toFixed(2)}, {TM_SERVER.lng.toFixed(2)}</div>
            </div>
            <span className="tm-peer-status">origin</span>
          </div>
          {peers.map(p => (
            <div key={p.id} className={`tm-peer-row ${p.status === 'connected' ? 'tm-peer-on' : 'tm-peer-off'}`}>
              <span className={`tm-pin ${p.status === 'connected' ? 'tm-pin-on' : 'tm-pin-off'}`} />
              <div className="tm-peer-info">
                <div className="tm-peer-name">{p.name}</div>
                <div className="tm-peer-loc">{p.country || (p.lat != null ? `${p.lat.toFixed(2)}, ${p.lng.toFixed(2)}` : p.addr)}</div>
              </div>
              <span className="tm-peer-status">{p.status === 'connected' ? `${p.pingMs != null ? p.pingMs + 'ms' : '—'}` : 'offline'}</span>
            </div>
          ))}
        </div>
      </div>

      <TmScaleBar zoom={zoom} />
    </div>
  );
}

function TmScaleBar({ zoom }) {
  const [vp, setVp] = React.useState({ w: window.innerWidth, h: window.innerHeight });
  React.useEffect(() => {
    const on = () => setVp({ w: window.innerWidth, h: window.innerHeight });
    window.addEventListener('resize', on);
    return () => window.removeEventListener('resize', on);
  }, []);
  const R = Math.min(vp.w, vp.h) * 0.38 * zoom;
  const EARTH_R_KM = 6378;
  const pxPerKm = R / EARTH_R_KM;
  const targetPx = 130;
  const targetKm = targetPx / pxPerKm;
  const pow = Math.pow(10, Math.floor(Math.log10(targetKm)));
  const mantissa = targetKm / pow;
  const nice = mantissa < 1.5 ? 1 : mantissa < 3 ? 2 : mantissa < 4 ? 2.5 : mantissa < 7 ? 5 : 10;
  const km = nice * pow;
  const barWidth = Math.max(40, Math.min(220, km * pxPerKm));
  const label = km >= 1000
    ? `${(km / 1000).toLocaleString(undefined, { maximumFractionDigits: 1 })} × 1000 KM`
    : `${km.toLocaleString()} KM`;
  return (
    <div className="tm-scale">
      <div className="tm-scale-bar" style={{ width: barWidth + 'px' }} />
      <div>
        <span className="tm-scale-label">{label} at equator</span>
        <span className="tm-scale-zoom">· {zoom.toFixed(2)}× zoom</span>
      </div>
    </div>
  );
}

// ============================================================
// Geometry helpers
// ============================================================
function latLngToVec(lat, lng) {
  const phi = (90 - lat) * Math.PI / 180;
  const theta = (lng + 180) * Math.PI / 180;
  return [-Math.sin(phi) * Math.cos(theta), Math.cos(phi), Math.sin(phi) * Math.sin(theta)];
}
function rotateY([x, y, z], ang) {
  const c = Math.cos(ang), s = Math.sin(ang);
  return [c * x + s * z, y, -s * x + c * z];
}
function rotateX([x, y, z], ang) {
  const c = Math.cos(ang), s = Math.sin(ang);
  return [x, c * y - s * z, s * y + c * z];
}
function applyRot(v, ry, rx) {
  return rotateX(rotateY(v, ry), rx);
}
function wrapAngle(a) {
  while (a > Math.PI) a -= Math.PI * 2;
  while (a < -Math.PI) a += Math.PI * 2;
  return a;
}
function slerp(a, b, t) {
  const dot = Math.max(-1, Math.min(1, a[0]*b[0]+a[1]*b[1]+a[2]*b[2]));
  const omega = Math.acos(dot);
  if (omega < 0.0001) return a;
  const so = Math.sin(omega);
  const k0 = Math.sin((1 - t) * omega) / so;
  const k1 = Math.sin(t * omega) / so;
  return [a[0]*k0 + b[0]*k1, a[1]*k0 + b[1]*k1, a[2]*k0 + b[2]*k1];
}

function drawStars(ctx, w, h, P, mix) {
  const baseAlpha = 1 - mix * 0.7;
  ctx.save();
  for (let i = 0; i < 220; i++) {
    const s = ((i * 2654435761) >>> 0);
    const x = (s % 10000) / 10000 * w;
    const y = (((s >> 8) % 10000) / 10000) * h;
    const a = (0.15 + ((s >> 16) % 100) / 100 * 0.35) * baseAlpha;
    const r = ((s >> 24) % 10) > 7 ? 1.2 : 0.6;
    ctx.fillStyle = rgba(P.star, a);
    ctx.fillRect(x, y, r, r);
  }
  ctx.restore();
}

function drawServerMarker(ctx, vec, ry, rx, cx, cy, R, dpr, t, P) {
  const [x, y, z] = applyRot(vec, ry, rx);
  const sx = cx + x * R;
  const sy = cy - y * R;
  if (z <= -0.1) return;
  const dim = z < 0 ? 0.3 : 1;

  const pulseT = (t / 1400) % 1;
  const pulseR = 6 * dpr + pulseT * 24 * dpr;
  ctx.strokeStyle = rgba(P.serverRing, (1 - pulseT) * 0.5 * dim);
  ctx.lineWidth = 1.5 * dpr;
  ctx.beginPath();
  ctx.arc(sx, sy, pulseR, 0, Math.PI * 2);
  ctx.stroke();

  const glow = ctx.createRadialGradient(sx, sy, 0, sx, sy, 18 * dpr);
  glow.addColorStop(0, rgba(P.serverGlow, 0.55 * dim));
  glow.addColorStop(1, rgba(P.serverGlow, 0));
  ctx.fillStyle = glow;
  ctx.beginPath();
  ctx.arc(sx, sy, 18 * dpr, 0, Math.PI * 2);
  ctx.fill();

  ctx.fillStyle = rgba(P.serverCore, dim);
  ctx.strokeStyle = rgba(P.serverCoreStroke, dim);
  ctx.lineWidth = 1.5 * dpr;
  ctx.beginPath();
  ctx.arc(sx, sy, 4.5 * dpr, 0, Math.PI * 2);
  ctx.fill();
  ctx.stroke();
}

function haversineKm(lat1, lng1, lat2, lng2) {
  const R = 6371;
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLng = (lng2 - lng1) * Math.PI / 180;
  const a = Math.sin(dLat / 2) ** 2 +
    Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * Math.sin(dLng / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(a));
}

function drawClusterBadge(ctx, sx, sy, z, dpr, count, t, P) {
  if (z < -0.15) return;
  const dim = z > 0 ? 1 : 0.25;
  const size = 16 * dpr;

  // Expanding pulse ring
  const pulseT = (t / 2000) % 1;
  const pulseR = size + pulseT * 14 * dpr;
  ctx.strokeStyle = rgba(P.peerOnRing, (1 - pulseT) * 0.5 * dim);
  ctx.lineWidth = 1.5 * dpr;
  ctx.beginPath();
  ctx.arc(sx, sy, pulseR, 0, Math.PI * 2);
  ctx.stroke();

  // Badge fill
  ctx.fillStyle = rgba(P.peerOnGlow, 0.35 * dim);
  ctx.beginPath();
  ctx.arc(sx, sy, size, 0, Math.PI * 2);
  ctx.fill();

  ctx.strokeStyle = rgba(P.peerOnRing, 0.9 * dim);
  ctx.lineWidth = 1.8 * dpr;
  ctx.beginPath();
  ctx.arc(sx, sy, size, 0, Math.PI * 2);
  ctx.stroke();

  // Count text e.g. "2×"
  ctx.font = `bold ${11 * dpr}px ui-monospace, SF Mono, JetBrains Mono, monospace`;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillStyle = rgba(P.peerOnCore, dim);
  ctx.fillText(`${count}×`, sx, sy);
}

function drawPeerMarker(ctx, vec, ry, rx, cx, cy, R, dpr, peer, t, P, offSx = 0, offSy = 0) {
  const [x, y, z] = applyRot(vec, ry, rx);
  const sx = cx + x * R + offSx;
  const sy = cy - y * R + offSy;
  if (z < -0.15) return;
  const visible = z > 0;
  const dim = visible ? 1 : 0.25;
  const on = peer.status === 'connected';

  if (on) {
    const pulseT = ((t + peer.id.charCodeAt(0) * 100) / 1800) % 1;
    const pulseR = 3 * dpr + pulseT * 18 * dpr;
    ctx.strokeStyle = rgba(P.peerOnRing, (1 - pulseT) * 0.45 * dim);
    ctx.lineWidth = 1.2 * dpr;
    ctx.beginPath();
    ctx.arc(sx, sy, pulseR, 0, Math.PI * 2);
    ctx.stroke();

    const glow = ctx.createRadialGradient(sx, sy, 0, sx, sy, 12 * dpr);
    glow.addColorStop(0, rgba(P.peerOnGlow, 0.6 * dim));
    glow.addColorStop(1, rgba(P.peerOnGlow, 0));
    ctx.fillStyle = glow;
    ctx.beginPath();
    ctx.arc(sx, sy, 12 * dpr, 0, Math.PI * 2);
    ctx.fill();

    ctx.fillStyle = rgba(P.peerOnCore, dim);
    ctx.strokeStyle = rgba(P.peerOnCoreStroke, dim);
    ctx.lineWidth = 1.2 * dpr;
    ctx.beginPath();
    ctx.arc(sx, sy, 3.2 * dpr, 0, Math.PI * 2);
    ctx.fill();
    ctx.stroke();
  } else {
    ctx.fillStyle = rgba(P.peerOff, 0.5 * dim);
    ctx.beginPath();
    ctx.arc(sx, sy, 2.4 * dpr, 0, Math.PI * 2);
    ctx.fill();
  }

  if (visible) {
    ctx.font = `${10 * dpr}px ui-monospace, SF Mono, JetBrains Mono, monospace`;
    ctx.textAlign = 'left';
    ctx.textBaseline = 'middle';
    ctx.fillStyle = on ? rgba(P.label, 0.92) : rgba(P.labelOff, 0.6);
    ctx.fillText(peer.name, sx + 8 * dpr, sy - 8 * dpr);
  }
}

function drawArc(ctx, ev, ry, rx, cx, cy, R, dpr, now, P) {
  const t = (now - ev.t0) / ev.dur;
  if (t < 0 || t > 1.3) return;
  const SAMPLES = 50;
  const lift = 0.18;
  const pts = [];
  for (let i = 0; i <= SAMPLES; i++) {
    const u = i / SAMPLES;
    const s = slerp(ev.from, ev.to, u);
    const liftFactor = 1 + lift * Math.sin(u * Math.PI);
    pts.push([s[0] * liftFactor, s[1] * liftFactor, s[2] * liftFactor]);
  }

  const isLight = (P.bg[0] + P.bg[1] + P.bg[2]) > 380;
  let color;
  if (ev.kind === 'tx')      color = isLight ? [40, 140, 90]  : [120, 220, 170];
  else if (ev.kind === 'rx') color = isLight ? [200, 95, 50]  : [247, 175, 130];
  else if (ev.kind === 'hs') color = isLight ? [120, 90, 200] : [200, 180, 255];
  else                       color = isLight ? [165, 130, 50] : [230, 210, 150];

  const headU = Math.min(1, t);
  const tailU = Math.max(0, t - 0.45);
  const fade = t > 1 ? Math.max(0, 1 - (t - 1) / 0.3) : 1;

  ctx.lineCap = 'round';
  ctx.lineWidth = 1.4 * dpr;

  for (let i = 0; i < SAMPLES; i++) {
    const u0 = i / SAMPLES;
    const u1 = (i + 1) / SAMPLES;
    if (u1 < tailU || u0 > headU) continue;
    const [x0, y0, z0] = applyRot(pts[i], ry, rx);
    const [x1, y1, z1] = applyRot(pts[i + 1], ry, rx);
    if (z0 < -0.05 && z1 < -0.05) continue;
    const sx0 = cx + x0 * R, sy0 = cy - y0 * R;
    const sx1 = cx + x1 * R, sy1 = cy - y1 * R;
    const distFromHead = Math.max(0, headU - u1);
    const alpha = Math.max(0, 1 - distFromHead / 0.45) * fade * 0.9;
    ctx.strokeStyle = rgba(color, alpha);
    ctx.beginPath();
    ctx.moveTo(sx0, sy0);
    ctx.lineTo(sx1, sy1);
    ctx.stroke();
  }

  if (t <= 1) {
    const headIdx = Math.floor(headU * SAMPLES);
    const headPt = pts[Math.min(SAMPLES, headIdx)];
    const [hx, hy, hz] = applyRot(headPt, ry, rx);
    if (hz > -0.05) {
      const sx = cx + hx * R, sy = cy - hy * R;
      const glow = ctx.createRadialGradient(sx, sy, 0, sx, sy, 10 * dpr);
      glow.addColorStop(0, rgba(color, 0.9 * fade));
      glow.addColorStop(1, rgba(color, 0));
      ctx.fillStyle = glow;
      ctx.beginPath();
      ctx.arc(sx, sy, 10 * dpr, 0, Math.PI * 2);
      ctx.fill();
      ctx.fillStyle = rgba(P.arcTrailWhite, fade);
      ctx.beginPath();
      ctx.arc(sx, sy, 2 * dpr, 0, Math.PI * 2);
      ctx.fill();
    }
  }
}

function buildLandDots() {
  const regions = [
    { lats: [25, 70],  lngs: [-160, -55], density: 0.18 },
    { lats: [-55, 15], lngs: [-82, -35],  density: 0.16 },
    { lats: [36, 70],  lngs: [-10, 40],   density: 0.30 },
    { lats: [-35, 36], lngs: [-18, 52],   density: 0.22 },
    { lats: [12, 75],  lngs: [40, 180],   density: 0.18 },
    { lats: [-10, 35], lngs: [70, 145],   density: 0.22 },
    { lats: [-40, -10],lngs: [110, 155],  density: 0.20 },
    { lats: [30, 45],  lngs: [125, 145],  density: 0.30 },
    { lats: [50, 60],  lngs: [-10, 2],    density: 0.40 },
    { lats: [-10, 18], lngs: [95, 135],   density: 0.25 },
  ];
  const holes = [
    { lats: [20, 60],  lngs: [-50, -15] },
    { lats: [-30, 20], lngs: [-25, 10] },
    { lats: [-30, 30], lngs: [50, 95] },
    { lats: [-40, 30], lngs: [-180, -90] },
    { lats: [-40, 30], lngs: [145, 180] },
    { lats: [10, 40],  lngs: [10, 30] },
    { lats: [50, 70],  lngs: [10, 40] },
    { lats: [60, 80],  lngs: [-100, -50] },
  ];
  const out = [];
  let seed = 7;
  const rand = () => { seed = (seed * 9301 + 49297) % 233280; return seed / 233280; };
  regions.forEach(r => {
    const stepLat = 2.5, stepLng = 4;
    for (let lat = r.lats[0]; lat <= r.lats[1]; lat += stepLat) {
      for (let lng = r.lngs[0]; lng <= r.lngs[1]; lng += stepLng) {
        if (rand() > r.density) continue;
        const inHole = holes.some(h => lat >= h.lats[0] && lat <= h.lats[1] && lng >= h.lngs[0] && lng <= h.lngs[1]);
        if (inHole && rand() > 0.05) continue;
        const jl = lat + (rand() - 0.5) * stepLat * 0.6;
        const jg = lng + (rand() - 0.5) * stepLng * 0.6;
        out.push(latLngToVec(jl, jg));
      }
    }
  });
  return out;
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

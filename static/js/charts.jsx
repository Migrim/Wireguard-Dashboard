// Live animated SVG charts for WG-Quick

const { useState, useEffect, useLayoutEffect, useRef, useMemo } = React;

// ============================================================
// ThroughputChart — hero live chart, area + line, scrolls left
// ============================================================
// Maps range labels to milliseconds — mirrors TRAFFIC_RANGES in data.jsx
const CHART_RANGE_MS = { '10s': 10000, '30s': 30000, '1m': 60000, '5m': 300000, '1h': 3600000, '24h': 86400000, '2m': 120000 };

const PAD = { l: 70, r: 16, t: 18, b: 28 };

function ThroughputChart({ dataIn, dataOut, width: widthProp = 900, height = 280, accent = 'var(--accent)', accent2 = 'var(--accent-2)', range = '2m', spline = false, smoothScroll = false }) {
  const uid = useRef(`tc-${Math.random().toString(36).slice(2)}`).current;
  const containerRef = useRef(null);
  const [containerWidth, setContainerWidth] = useState(widthProp);

  // targetWidthRef: latest measured container width (written by ResizeObserver)
  // displayWidthRef: current animated width (lerps toward target in RAF tick)
  const targetWidthRef = useRef(widthProp);
  const displayWidthRef = useRef(widthProp);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const measure = (cw) => {
      if (cw > 0) { targetWidthRef.current = cw; setContainerWidth(cw); }
    };
    measure(Math.round(el.getBoundingClientRect().width));
    const ro = new ResizeObserver(entries => {
      const cw = entries[0]?.contentRect.width;
      if (cw > 0) measure(Math.round(cw));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const n = Math.max(dataIn.length, dataOut.length);
  const width = containerWidth;
  const w = width - PAD.l - PAD.r;
  const h = height - PAD.t - PAD.b;

  // ── SVG element refs (RAF writes to these directly) ──────────────────────
  const svgRef        = useRef(null);
  const innerGroupRef = useRef(null);
  const clipRectRef   = useRef(null);
  const pathAreaOutRef  = useRef(null);
  const pathAreaInRef   = useRef(null);
  const pathLineOutRef  = useRef(null);
  const pathLineInRef   = useRef(null);
  const dotInRef      = useRef(null);
  const dotOutRef     = useRef(null);
  const vGridRef      = useRef(null);   // <g> containing vertical grid lines
  const hGridRef      = useRef(null);   // <g> containing horizontal tick lines+labels
  const lblLeft       = useRef(null);
  const lblMid        = useRef(null);
  const lblRight      = useRef(null);

  // ── Per-frame animation state ─────────────────────────────────────────────
  const rafRef     = useRef(null);
  const offsetRef  = useRef(0);
  const dotInYRef  = useRef(null);  // null = uninitialised (snaps on first tick)
  const dotOutYRef = useRef(null);
  const prevDataRef = useRef({ dataIn, dataOut });

  // ── Live data snapshot — written every render, read inside RAF tick ───────
  const snap = useRef({});

  const { maxVal, ticks } = useMemo(() => {
    let m = 0;
    for (let i = 0; i < n; i++) m = Math.max(m, dataIn[i] || 0, dataOut[i] || 0);
    const raw = Math.max(m, 10 * 1024);
    const unitBytes = raw < 1024 * 1024 ? 1024 : 1024 * 1024;
    const unitName  = unitBytes === 1024 ? 'KB/s' : 'MB/s';
    const rawInUnit = raw / unitBytes;
    const roughStep = rawInUnit / 4;
    const mag  = Math.pow(10, Math.floor(Math.log10(Math.max(roughStep, 0.001))));
    const norm = roughStep / mag;
    const niceStep = norm < 1.5 ? mag : norm < 3 ? 2 * mag : norm < 7 ? 5 * mag : 10 * mag;
    const niceMaxInUnit = Math.ceil(rawInUnit / niceStep) * niceStep;
    const niceMax = niceMaxInUnit * unitBytes;
    const hInner  = height - PAD.t - PAD.b;
    const ticksArr = [];
    for (let s = 0; s <= niceMaxInUnit + niceStep * 0.01; s += niceStep) {
      const v  = s * unitBytes;
      const y  = PAD.t + hInner - (v / niceMax) * hInner;
      const lbl = s === 0 ? '0 B/s' : `${Number(s.toFixed(4))} ${unitName}`;
      ticksArr.push({ v, y, label: lbl });
    }
    return { maxVal: niceMax, ticks: ticksArr };
  }, [dataIn, dataOut, n, height]);

  const extIn  = smoothScroll && n > 0 ? [...dataIn,  dataIn[dataIn.length - 1]   || 0] : dataIn;
  const extOut = smoothScroll && n > 0 ? [...dataOut, dataOut[dataOut.length - 1] || 0] : dataOut;
  const extN   = smoothScroll ? n + 1 : n;

  const lastIn  = dataIn[n - 1]  || 0;
  const lastOut = dataOut[n - 1] || 0;

  const rangeLabels = {
    '10s': ['-10s', '-5s', 'now'],
    '30s': ['-30s', '-15s', 'now'],
    '1m':  ['-1m', '-30s', 'now'],
    '5m':  ['-5m', '-2.5m', 'now'],
    '1h':  ['-1h', '-30m', 'now'],
    '24h': ['-24h', '-12h', 'now'],
    '2m':  ['-2m', '-1m', 'now'],
  };
  const labels = rangeLabels[range] || rangeLabels['2m'];

  // Update snapshot every render (safe: RAF reads after commit)
  snap.current = { extIn, extOut, extN, n, maxVal, lastIn, lastOut, range, labels, h, spline };

  // React-computed helpers for the initial/non-smooth render pass
  const slotW = n <= 1 ? w : w / (n - 1);
  const xAt = (i) => PAD.l + i * slotW;
  const yAt = (v) => PAD.t + h - (v / maxVal) * h;

  const linePath = (data, count, xFn, yFn) => {
    let d = '';
    for (let i = 0; i < count; i++) d += (i === 0 ? 'M' : 'L') + xFn(i).toFixed(1) + ',' + yFn(data[i] || 0).toFixed(1) + ' ';
    return d;
  };
  const splinePath = (data, count, xFn, yFn, sW) => {
    let d = `M${xFn(0).toFixed(1)},${yFn(data[0] || 0).toFixed(1)}`;
    for (let i = 1; i < count; i++) {
      const y0 = yFn(data[Math.max(0, i - 2)]         || 0);
      const y1 = yFn(data[i - 1]                       || 0);
      const y2 = yFn(data[i]                           || 0);
      const y3 = yFn(data[Math.min(count - 1, i + 1)] || 0);
      const x1 = xFn(i - 1), x2 = xFn(i);
      const spL = i === 1         ? sW : 2 * sW;
      const spR = i === count - 1 ? sW : 2 * sW;
      d += ` C${(x1 + spL / 6).toFixed(1)},${(y1 + (y2 - y0) / 6).toFixed(1)} ${(x2 - spR / 6).toFixed(1)},${(y2 - (y3 - y1) / 6).toFixed(1)} ${x2.toFixed(1)},${y2.toFixed(1)}`;
    }
    return d;
  };
  const buildLine = (data, count, xFn = xAt, yFn = yAt, sW = slotW) =>
    (spline && count >= 2) ? splinePath(data, count, xFn, yFn, sW) : linePath(data, count, xFn, yFn);
  const buildArea = (data, count, xFn = xAt, yFn = yAt, sW = slotW) =>
    buildLine(data, count, xFn, yFn, sW) +
    `L${xFn(count - 1).toFixed(1)},${(PAD.t + h).toFixed(1)} L${xFn(0).toFixed(1)},${(PAD.t + h).toFixed(1)} Z`;

  // ── Main animation loop ───────────────────────────────────────────────────
  useLayoutEffect(() => {
    const dataChanged = prevDataRef.current.dataIn !== dataIn || prevDataRef.current.dataOut !== dataOut;
    prevDataRef.current = { dataIn, dataOut };

    cancelAnimationFrame(rafRef.current);

    if (!smoothScroll || n < 2) {
      if (innerGroupRef.current) innerGroupRef.current.setAttribute('transform', '');
      offsetRef.current  = 0;
      dotInYRef.current  = null;
      dotOutYRef.current = null;
      return;
    }

    if (dataChanged) {
      if (innerGroupRef.current) innerGroupRef.current.setAttribute('transform', '');
      offsetRef.current = 0;
    }

    let lastTime = performance.now();

    const tick = (now) => {
      const dt = Math.min(now - lastTime, 100);
      lastTime = now;

      const { extIn, extOut, extN, n: dN, maxVal, lastIn, lastOut, range, h: dh, spline: sp } = snap.current;
      if (!dN || dN < 2) { rafRef.current = requestAnimationFrame(tick); return; }

      // ── 1. Spring-lerp display width toward measured target ──────────────
      const tw  = targetWidthRef.current;
      const gap = tw - displayWidthRef.current;
      displayWidthRef.current = Math.abs(gap) > 0.3
        ? displayWidthRef.current + gap * (1 - Math.exp(-dt / 80))
        : tw;
      const dW = displayWidthRef.current;
      const cW = dW - PAD.l - PAD.r;

      svgRef.current?.setAttribute('viewBox', `0 0 ${dW.toFixed(1)} ${height}`);

      // ── 2. Scroll offset ─────────────────────────────────────────────────
      const rangeMs = CHART_RANGE_MS[range] || 60000;
      const sW      = dN <= 1 ? cW : cW / (dN - 1);
      offsetRef.current = Math.min(offsetRef.current + dt * cW / rangeMs, sW);
      innerGroupRef.current?.setAttribute('transform', `translate(${(-offsetRef.current).toFixed(2)}, 0)`);

      // ── 3. Geometry helpers based on animated width ───────────────────────
      const xA = (i) => PAD.l + i * sW;
      const yA = (v) => PAD.t + dh - (v / maxVal) * dh;

      // ── 4. Rebuild and apply path data ───────────────────────────────────
      const mkLine = (data, count) => {
        if (sp && count >= 2) {
          let d = `M${xA(0).toFixed(1)},${yA(data[0] || 0).toFixed(1)}`;
          for (let i = 1; i < count; i++) {
            const y0 = yA(data[Math.max(0, i - 2)]         || 0);
            const y1 = yA(data[i - 1]                       || 0);
            const y2 = yA(data[i]                           || 0);
            const y3 = yA(data[Math.min(count - 1, i + 1)] || 0);
            const x1 = xA(i - 1), x2 = xA(i);
            const spL = i === 1         ? sW : 2 * sW;
            const spR = i === count - 1 ? sW : 2 * sW;
            d += ` C${(x1 + spL / 6).toFixed(1)},${(y1 + (y2 - y0) / 6).toFixed(1)} ${(x2 - spR / 6).toFixed(1)},${(y2 - (y3 - y1) / 6).toFixed(1)} ${x2.toFixed(1)},${y2.toFixed(1)}`;
          }
          return d;
        }
        let d = '';
        for (let i = 0; i < count; i++) d += (i === 0 ? 'M' : 'L') + xA(i).toFixed(1) + ',' + yA(data[i] || 0).toFixed(1) + ' ';
        return d;
      };
      const mkArea = (data, count) =>
        mkLine(data, count) + `L${xA(count - 1).toFixed(1)},${(PAD.t + dh).toFixed(1)} L${xA(0).toFixed(1)},${(PAD.t + dh).toFixed(1)} Z`;

      pathAreaOutRef.current?.setAttribute('d', mkArea(extOut, extN));
      pathAreaInRef.current?.setAttribute('d',  mkArea(extIn,  extN));
      pathLineOutRef.current?.setAttribute('d', mkLine(extOut, extN));
      pathLineInRef.current?.setAttribute('d',  mkLine(extIn,  extN));

      // ── 5. Clip rect width ───────────────────────────────────────────────
      clipRectRef.current?.setAttribute('width', cW.toFixed(1));

      // ── 6. Dots: spring-lerp Y toward current value ──────────────────────
      const tInY  = yA(lastIn);
      const tOutY = yA(lastOut);
      if (dotInYRef.current  === null) dotInYRef.current  = tInY;
      if (dotOutYRef.current === null) dotOutYRef.current = tOutY;
      const lf = 1 - Math.exp(-dt / 120);   // ~120 ms time-constant
      dotInYRef.current  += (tInY  - dotInYRef.current)  * lf;
      dotOutYRef.current += (tOutY - dotOutYRef.current) * lf;
      const dX = xA(dN - 1).toFixed(1);
      dotInRef.current?.setAttribute('cx',  dX);
      dotInRef.current?.setAttribute('cy',  dotInYRef.current.toFixed(2));
      dotOutRef.current?.setAttribute('cx', dX);
      dotOutRef.current?.setAttribute('cy', dotOutYRef.current.toFixed(2));

      // ── 7. Vertical grid lines ───────────────────────────────────────────
      if (vGridRef.current) {
        const lines = vGridRef.current.children;
        const fracs = [0, 0.25, 0.5, 0.75, 1];
        for (let i = 0; i < Math.min(lines.length, fracs.length); i++) {
          const x = (PAD.l + cW * fracs[i]).toFixed(1);
          lines[i].setAttribute('x1', x);
          lines[i].setAttribute('x2', x);
        }
      }

      // ── 8. Horizontal tick line right endpoints ──────────────────────────
      if (hGridRef.current) {
        const x2 = (PAD.l + cW).toFixed(1);
        hGridRef.current.querySelectorAll('line').forEach(l => l.setAttribute('x2', x2));
      }

      // ── 9. Time-axis labels ──────────────────────────────────────────────
      lblLeft.current?.setAttribute('x',  PAD.l.toString());
      lblMid.current?.setAttribute('x',   (PAD.l + cW / 2).toFixed(1));
      lblRight.current?.setAttribute('x', (PAD.l + cW).toFixed(1));

      rafRef.current = requestAnimationFrame(tick);
    };

    rafRef.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(rafRef.current);
  }, [smoothScroll, dataIn, dataOut, n, range, spline, height]);

  return (
    <div ref={containerRef} style={{ width: '100%' }}>
      <svg ref={svgRef} viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" style={{ width: '100%', height, display: 'block' }}>
        <defs>
          <linearGradient id={`${uid}-gIn`} x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor={accent} stopOpacity="0.35" />
            <stop offset="100%" stopColor={accent} stopOpacity="0.02" />
          </linearGradient>
          <linearGradient id={`${uid}-gOut`} x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor={accent2} stopOpacity="0.28" />
            <stop offset="100%" stopColor={accent2} stopOpacity="0.01" />
          </linearGradient>
          <clipPath id={`${uid}-clip`}>
            {/* In smooth mode: RAF manages clip width; no SMIL animate needed */}
            <rect ref={clipRectRef} x={PAD.l} y={PAD.t} width={w} height={h}>
              {!smoothScroll && <animate attributeName="width" from="0" to={w} dur="1.1s" fill="freeze" calcMode="spline" keyTimes="0;1" keySplines="0 0 0.2 1" />}
            </rect>
          </clipPath>
        </defs>

        {/* Horizontal tick lines + Y labels — React-rendered (y-coords are data-driven, not width-driven).
            RAF updates the x2 endpoint of each line during resize. */}
        <g ref={hGridRef}>
          {ticks.map((t, i) => (
            <g key={i}>
              <line x1={PAD.l} x2={PAD.l + w} y1={t.y} y2={t.y} stroke="var(--border)" strokeDasharray={i === 0 ? '' : '2 3'} strokeWidth="1" opacity="0.6" />
              <text x={PAD.l - 8} y={t.y + 3} textAnchor="end" fontSize="10" fill="var(--muted)" fontFamily="var(--mono)">{t.label}</text>
            </g>
          ))}
        </g>

        {/* Vertical grid lines — initial positions from React, RAF updates x on resize */}
        <g ref={vGridRef}>
          {[0, 0.25, 0.5, 0.75, 1].map((f, i) => (
            <line key={i} x1={PAD.l + w * f} x2={PAD.l + w * f} y1={PAD.t} y2={PAD.t + h} stroke="var(--border)" strokeDasharray="2 3" strokeWidth="1" opacity="0.35" />
          ))}
        </g>

        <g clipPath={`url(#${uid}-clip)`}>
          <g ref={innerGroupRef}>
            {/* In smooth mode d="" — RAF fills on first tick (~1 frame). Non-smooth: React-rendered. */}
            <path ref={pathAreaOutRef} d={smoothScroll ? '' : buildArea(extOut, extN)} fill={`url(#${uid}-gOut)`} />
            <path ref={pathAreaInRef}  d={smoothScroll ? '' : buildArea(extIn,  extN)} fill={`url(#${uid}-gIn)`} />
            <path ref={pathLineOutRef} d={smoothScroll ? '' : buildLine(extOut, extN)} fill="none" stroke={accent2} strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round" opacity="0.8" />
            <path ref={pathLineInRef}  d={smoothScroll ? '' : buildLine(extIn,  extN)} fill="none" stroke={accent}  strokeWidth="2"   strokeLinejoin="round" strokeLinecap="round" />
          </g>

          {/* Dots: RAF spring-lerps cy each frame in smooth mode */}
          <circle ref={dotInRef}  cx={xAt(n - 1)} cy={yAt(lastIn)}  r="3" fill={accent}  opacity={smoothScroll ? 1 : 0}>
            {!smoothScroll && <animate attributeName="opacity" from="0" to="1" begin="0.9s" dur="0.3s" fill="freeze" calcMode="spline" keyTimes="0;1" keySplines="0 0 0.2 1" />}
          </circle>
          <circle ref={dotOutRef} cx={xAt(n - 1)} cy={yAt(lastOut)} r="3" fill={accent2} opacity={smoothScroll ? 1 : 0}>
            {!smoothScroll && <animate attributeName="opacity" from="0" to="1" begin="0.9s" dur="0.3s" fill="freeze" calcMode="spline" keyTimes="0;1" keySplines="0 0 0.2 1" />}
          </circle>
        </g>

        {/* Time-axis labels — RAF updates x on resize */}
        <text ref={lblLeft}  x={PAD.l}           y={height - 8} fontSize="10" fill="var(--muted)" fontFamily="var(--mono)">{labels[0]}</text>
        <text ref={lblMid}   x={PAD.l + w / 2}   y={height - 8} fontSize="10" fill="var(--muted)" fontFamily="var(--mono)" textAnchor="middle">{labels[1]}</text>
        <text ref={lblRight} x={PAD.l + w}        y={height - 8} fontSize="10" fill="var(--muted)" fontFamily="var(--mono)" textAnchor="end">{labels[2]}</text>
      </svg>
    </div>
  );
}

// ============================================================
// Sparkline — tiny live chart for peer rows
// ============================================================
function Sparkline({ data, width = 120, height = 32, color = 'var(--accent)', active = true }) {
  const uid = useRef(`sp-${Math.random().toString(36).slice(2)}`).current;
  const n = data.length;
  if (n < 2) return <svg style={{ width, height, display: 'block' }} />;
  const max = Math.max(...data, 0.01);
  const min = Math.min(...data);
  const range = max - min || 1;
  const pts = data.map((v, i) => {
    const x = (i / (n - 1)) * (width - 2) + 1;
    const y = height - 3 - ((v - min) / range) * (height - 6);
    return [x, y];
  });
  const d = pts.map((p, i) => (i ? 'L' : 'M') + p[0].toFixed(1) + ',' + p[1].toFixed(1)).join(' ');
  const area = d + ` L${(width - 1).toFixed(1)},${height - 1} L1,${height - 1} Z`;
  const last = pts[n - 1];

  return (
    <svg viewBox={`0 0 ${width} ${height}`} style={{ width, height, display: 'block' }}>
      <defs>
        <linearGradient id={`sg-${color.replace(/[^a-z0-9]/gi, '')}`} x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.3" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
        <clipPath id={uid}>
          <rect x="0" y="0" height={height}>
            <animate attributeName="width" from="0" to={width} dur="0.8s" fill="freeze" calcMode="spline" keyTimes="0;1" keySplines="0 0 0.2 1" />
          </rect>
        </clipPath>
      </defs>
      <g clipPath={`url(#${uid})`}>
        <path d={area} fill={`url(#sg-${color.replace(/[^a-z0-9]/gi, '')})`} opacity={active ? 1 : 0.3} />
        <path d={d} fill="none" stroke={color} strokeWidth="1.4" strokeLinejoin="round" strokeLinecap="round" opacity={active ? 1 : 0.4} />
      </g>
      {active && (
        <>
          <circle cx={last[0]} cy={last[1]} r="3" fill={color} opacity="0">
            <animate attributeName="opacity" from="0" to="0.5" begin="0.65s" dur="0.2s" fill="freeze" calcMode="spline" keyTimes="0;1" keySplines="0 0 0.2 1" />
            <animate attributeName="r" values="2;5;2" dur="1.4s" repeatCount="indefinite" begin="0.85s" />
            <animate attributeName="opacity" values="0.5;0;0.5" dur="1.4s" repeatCount="indefinite" begin="0.85s" />
          </circle>
          <circle cx={last[0]} cy={last[1]} r="1.8" fill={color} opacity="0">
            <animate attributeName="opacity" from="0" to="1" begin="0.65s" dur="0.2s" fill="freeze" calcMode="spline" keyTimes="0;1" keySplines="0 0 0.2 1" />
          </circle>
        </>
      )}
    </svg>
  );
}

// ============================================================
// MiniBar — per-KPI live mini chart (bars)
// ============================================================
function MiniBars({ data, width = 140, height = 36, color = 'var(--accent)' }) {
  const uid = useRef(`mb-${Math.random().toString(36).slice(2)}`).current;
  const n = data.length;
  const max = Math.max(...data, 0.01);
  const barW = (width - (n - 1) * 2) / n;
  return (
    <svg viewBox={`0 0 ${width} ${height}`} style={{ width: '100%', height, display: 'block' }}>
      <defs>
        <clipPath id={uid}>
          <rect x="0" width={width}>
            <animate attributeName="y" from={height} to="0" dur="0.7s" fill="freeze" calcMode="spline" keyTimes="0;1" keySplines="0 0 0.2 1" />
            <animate attributeName="height" from="0" to={height} dur="0.7s" fill="freeze" calcMode="spline" keyTimes="0;1" keySplines="0 0 0.2 1" />
          </rect>
        </clipPath>
      </defs>
      <g clipPath={`url(#${uid})`}>
        {data.map((v, i) => {
          const h = (v / max) * (height - 4);
          const x = i * (barW + 2);
          const y = height - h - 2;
          return <rect key={i} x={x} y={y} width={barW} height={h} fill={color} opacity={0.3 + 0.7 * (i / n)} rx="1" />;
        })}
      </g>
    </svg>
  );
}

// ============================================================
// RadialGauge — data-transferred-today style
// ============================================================
function RadialGauge({ value, max, width = 120, color = 'var(--accent)', label, sublabel }) {
  const r = width / 2 - 8;
  const cx = width / 2, cy = width / 2;
  const c = 2 * Math.PI * r;
  const pct = Math.min(1, value / max);
  const arc = c * 0.75;

  const [displayPct, setDisplayPct] = useState(0);
  const mounted = useRef(false);
  useEffect(() => {
    if (!mounted.current) {
      mounted.current = true;
      setTimeout(() => setDisplayPct(pct), 50);
    } else {
      setDisplayPct(pct);
    }
  }, [pct]);

  const dash = arc * displayPct;
  return (
    <svg viewBox={`0 0 ${width} ${width}`} style={{ width: '100%', height: width, display: 'block' }}>
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="var(--border)" strokeWidth="6"
        strokeDasharray={`${arc} ${c}`} strokeLinecap="round"
        transform={`rotate(135 ${cx} ${cy})`} />
      <circle cx={cx} cy={cy} r={r} fill="none" stroke={color} strokeWidth="6"
        strokeDasharray={`${dash} ${c}`} strokeLinecap="round"
        transform={`rotate(135 ${cx} ${cy})`}
        style={{ transition: 'stroke-dasharray 1s cubic-bezier(0, 0, 0.2, 1)' }} />
      <text x={cx} y={cy - 2} textAnchor="middle" fontSize="22" fontFamily="var(--serif)" fill="var(--ink)" fontWeight="400">{label}</text>
      <text x={cx} y={cy + 16} textAnchor="middle" fontSize="9.5" fill="var(--muted)" fontFamily="var(--mono)" letterSpacing="0.08em">{sublabel}</text>
    </svg>
  );
}

Object.assign(window, { ThroughputChart, Sparkline, MiniBars, RadialGauge });

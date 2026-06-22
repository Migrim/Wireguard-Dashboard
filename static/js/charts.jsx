// Live animated SVG charts for WG-Quick

const { useState, useEffect, useLayoutEffect, useRef, useMemo } = React;

// ============================================================
// ThroughputChart — hero live chart, area + line, scrolls left
// ============================================================
// Maps range labels to milliseconds — mirrors TRAFFIC_RANGES in data.jsx
const CHART_RANGE_MS = { '10s': 10000, '30s': 30000, '1m': 60000, '5m': 300000, '1h': 3600000, '24h': 86400000, '2m': 120000 };

function ThroughputChart({ dataIn, dataOut, width = 900, height = 280, accent = 'var(--accent)', accent2 = 'var(--accent-2)', range = '2m', spline = false, smoothScroll = false }) {
  const uid = useRef(`tc-${Math.random().toString(36).slice(2)}`).current;
  const n = Math.max(dataIn.length, dataOut.length);
  const pad = { l: 70, r: 16, t: 18, b: 28 };
  const w = width - pad.l - pad.r;
  const h = height - pad.t - pad.b;

  const rafRef = useRef(null);
  const lastUpdateRef = useRef(Date.now());
  const innerGroupRef = useRef(null);

  // useLayoutEffect runs synchronously before paint, so the transform is always
  // reset to "" in the same frame that new SVG content lands — no teleport flash.
  useLayoutEffect(() => {
    cancelAnimationFrame(rafRef.current);

    if (innerGroupRef.current) innerGroupRef.current.setAttribute('transform', '');
    lastUpdateRef.current = Date.now();

    if (!smoothScroll || n < 2) return;

    // Scroll speed = w / rangeMs px/ms — one full chart width per range duration.
    // This is correct regardless of poll rate or bucketing because chartTraffic
    // always maps the full range onto width w evenly.
    const rangeMs = CHART_RANGE_MS[range] || 60000;
    const slotWidth = w / (n - 1);
    const pixelsPerMs = w / rangeMs;
    const tick = () => {
      const elapsed = Date.now() - lastUpdateRef.current;
      const offset = Math.min(elapsed * pixelsPerMs, slotWidth);
      if (innerGroupRef.current) innerGroupRef.current.setAttribute('transform', `translate(${-offset}, 0)`);
      rafRef.current = requestAnimationFrame(tick);
    };
    rafRef.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(rafRef.current);
  }, [smoothScroll, dataIn, dataOut, n, w, range]);

  // When smooth, extend data by one extrapolated point so the right side fills continuously
  const extIn  = smoothScroll && n > 0 ? [...dataIn,  dataIn[dataIn.length   - 1] || 0] : dataIn;
  const extOut = smoothScroll && n > 0 ? [...dataOut, dataOut[dataOut.length  - 1] || 0] : dataOut;
  const extN   = smoothScroll ? n + 1 : n;

  const { maxVal, ticks } = useMemo(() => {
    let m = 0;
    for (let i = 0; i < n; i++) m = Math.max(m, dataIn[i] || 0, dataOut[i] || 0);

    // Work in KB/s or MB/s to get nice round labels
    const raw = Math.max(m, 10 * 1024); // at least 10 KB/s so the idle chart looks sane
    const unitBytes = raw < 1024 * 1024 ? 1024 : 1024 * 1024;
    const unitName = unitBytes === 1024 ? 'KB/s' : 'MB/s';
    const rawInUnit = raw / unitBytes;

    // Nice step: target 4 intervals
    const roughStep = rawInUnit / 4;
    const mag = Math.pow(10, Math.floor(Math.log10(Math.max(roughStep, 0.001))));
    const norm = roughStep / mag;
    const niceStep = norm < 1.5 ? mag : norm < 3 ? 2 * mag : norm < 7 ? 5 * mag : 10 * mag;

    const niceMaxInUnit = Math.ceil(rawInUnit / niceStep) * niceStep;
    const niceMax = niceMaxInUnit * unitBytes;
    const hInner = height - pad.t - pad.b;

    const ticksArr = [];
    for (let s = 0; s <= niceMaxInUnit + niceStep * 0.01; s += niceStep) {
      const v = s * unitBytes;
      const y = pad.t + hInner - (v / niceMax) * hInner;
      const label = s === 0 ? '0 B/s' : `${Number(s.toFixed(4))} ${unitName}`;
      ticksArr.push({ v, y, label });
    }

    return { maxVal: niceMax, ticks: ticksArr };
  }, [dataIn, dataOut, n, height]);

  // xAt is still keyed on the original n so the extrapolated point at index n sits
  // exactly one slotWidth beyond the right edge, scrolling in as the offset grows
  const xAt = (i) => pad.l + (n <= 1 ? w : (i / (n - 1)) * w);
  const yAt = (v) => pad.t + h - (v / maxVal) * h;

  const pathFor = (data, count) => {
    let d = '';
    for (let i = 0; i < count; i++) {
      d += (i === 0 ? 'M' : 'L') + xAt(i).toFixed(1) + ',' + yAt(data[i] || 0).toFixed(1) + ' ';
    }
    return d;
  };

  const smoothPathFor = (data, count) => {
    if (count < 2) return pathFor(data, count);
    const px = (i) => xAt(i);
    const py = (i) => yAt(data[i] || 0);
    let d = `M${px(0).toFixed(1)},${py(0).toFixed(1)}`;
    for (let i = 1; i < count; i++) {
      const p0x = px(Math.max(0, i - 2)), p0y = py(Math.max(0, i - 2));
      const p1x = px(i - 1),             p1y = py(i - 1);
      const p2x = px(i),                 p2y = py(i);
      const p3x = px(Math.min(count - 1, i + 1)), p3y = py(Math.min(count - 1, i + 1));
      const cp1x = p1x + (p2x - p0x) / 6;
      const cp1y = p1y + (p2y - p0y) / 6;
      const cp2x = p2x - (p3x - p1x) / 6;
      const cp2y = p2y - (p3y - p1y) / 6;
      d += ` C${cp1x.toFixed(1)},${cp1y.toFixed(1)} ${cp2x.toFixed(1)},${cp2y.toFixed(1)} ${p2x.toFixed(1)},${p2y.toFixed(1)}`;
    }
    return d;
  };

  const line = (data, count) => (spline ? smoothPathFor : pathFor)(data, count);
  const areaFor = (data, count) => line(data, count) + `L${xAt(count - 1).toFixed(1)},${(pad.t + h).toFixed(1)} L${xAt(0).toFixed(1)},${(pad.t + h).toFixed(1)} Z`;

  const lastIn = dataIn[n - 1] || 0;
  const lastOut = dataOut[n - 1] || 0;
  const rangeLabels = {
    '10s': ['-10s', '-5s', 'now'],
    '30s': ['-30s', '-15s', 'now'],
    '1m': ['-1m', '-30s', 'now'],
    '5m': ['-5m', '-2.5m', 'now'],
    '1h': ['-1h', '-30m', 'now'],
    '24h': ['-24h', '-12h', 'now'],
    '2m': ['-2m', '-1m', 'now'],
  };
  const labels = rangeLabels[range] || rangeLabels['2m'];

  return (
    <svg viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" style={{ width: '100%', height, display: 'block' }}>
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
          <rect x={pad.l} y={pad.t} height={h}>
            <animate attributeName="width" from="0" to={w} dur="1.1s" fill="freeze" calcMode="spline" keyTimes="0;1" keySplines="0 0 0.2 1" />
          </rect>
        </clipPath>
      </defs>

      {ticks.map((t, i) => (
        <g key={i}>
          <line x1={pad.l} x2={pad.l + w} y1={t.y} y2={t.y} stroke="var(--border)" strokeDasharray={i === 0 ? '' : '2 3'} strokeWidth="1" opacity="0.6" />
          <text x={pad.l - 8} y={t.y + 3} textAnchor="end" fontSize="10" fill="var(--muted)" fontFamily="var(--mono)">{t.label}</text>
        </g>
      ))}

      {[0, 0.25, 0.5, 0.75, 1].map((f, i) => (
        <line key={i} x1={pad.l + w * f} x2={pad.l + w * f} y1={pad.t} y2={pad.t + h} stroke="var(--border)" strokeDasharray="2 3" strokeWidth="1" opacity="0.35" />
      ))}

      <g clipPath={`url(#${uid}-clip)`}>
        <g ref={innerGroupRef}>
          <path d={areaFor(extOut, extN)} fill={`url(#${uid}-gOut)`} />
          <path d={areaFor(extIn, extN)} fill={`url(#${uid}-gIn)`} />
          <path d={line(extOut, extN)} fill="none" stroke={accent2} strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round" opacity="0.8" />
          <path d={line(extIn, extN)} fill="none" stroke={accent} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
        </g>
        {/* Dots are outside the scrolling group so they stay pinned at the right edge */}
        <circle cx={xAt(n - 1)} cy={yAt(lastIn)} r="3" fill={accent} opacity={smoothScroll ? 1 : 0}>
          {!smoothScroll && <animate attributeName="opacity" from="0" to="1" begin="0.9s" dur="0.3s" fill="freeze" calcMode="spline" keyTimes="0;1" keySplines="0 0 0.2 1" />}
        </circle>
        <circle cx={xAt(n - 1)} cy={yAt(lastOut)} r="3" fill={accent2} opacity={smoothScroll ? 1 : 0}>
          {!smoothScroll && <animate attributeName="opacity" from="0" to="1" begin="0.9s" dur="0.3s" fill="freeze" calcMode="spline" keyTimes="0;1" keySplines="0 0 0.2 1" />}
        </circle>
      </g>

      <text x={pad.l} y={height - 8} fontSize="10" fill="var(--muted)" fontFamily="var(--mono)">{labels[0]}</text>
      <text x={pad.l + w / 2} y={height - 8} fontSize="10" fill="var(--muted)" fontFamily="var(--mono)" textAnchor="middle">{labels[1]}</text>
      <text x={pad.l + w} y={height - 8} fontSize="10" fill="var(--muted)" fontFamily="var(--mono)" textAnchor="end">{labels[2]}</text>
    </svg>
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

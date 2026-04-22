// Live animated SVG charts for WG-Quick

const { useState, useEffect, useRef, useMemo } = React;

// ============================================================
// ThroughputChart — hero live chart, area + line, scrolls left
// ============================================================
function ThroughputChart({ dataIn, dataOut, width = 900, height = 280, accent = 'var(--accent)', accent2 = 'var(--accent-2)' }) {
  const n = dataIn.length;
  const pad = { l: 52, r: 16, t: 18, b: 28 };
  const w = width - pad.l - pad.r;
  const h = height - pad.t - pad.b;

  const maxVal = useMemo(() => {
    let m = 0;
    for (let i = 0; i < n; i++) m = Math.max(m, dataIn[i], dataOut[i]);
    return Math.max(m * 1.15, 100_000);
  }, [dataIn, dataOut]);

  const xAt = (i) => pad.l + (i / (n - 1)) * w;
  const yAt = (v) => pad.t + h - (v / maxVal) * h;

  const pathFor = (data) => {
    let d = '';
    for (let i = 0; i < n; i++) {
      d += (i === 0 ? 'M' : 'L') + xAt(i).toFixed(1) + ',' + yAt(data[i]).toFixed(1) + ' ';
    }
    return d;
  };
  const areaFor = (data) => pathFor(data) + `L${xAt(n - 1).toFixed(1)},${(pad.t + h).toFixed(1)} L${xAt(0).toFixed(1)},${(pad.t + h).toFixed(1)} Z`;

  const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => {
    const v = maxVal * f;
    return { v, y: yAt(v), label: window.WG.formatRate(v) };
  });

  const lastIn = dataIn[n - 1];
  const lastOut = dataOut[n - 1];

  return (
    <svg viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" style={{ width: '100%', height, display: 'block' }}>
      <defs>
        <linearGradient id="gIn" x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%" stopColor={accent} stopOpacity="0.35" />
          <stop offset="100%" stopColor={accent} stopOpacity="0.02" />
        </linearGradient>
        <linearGradient id="gOut" x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%" stopColor={accent2} stopOpacity="0.28" />
          <stop offset="100%" stopColor={accent2} stopOpacity="0.01" />
        </linearGradient>
        <clipPath id="chartClip">
          <rect x={pad.l} y={pad.t} width={w} height={h} />
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

      <g clipPath="url(#chartClip)">
        <path d={areaFor(dataOut)} fill="url(#gOut)" />
        <path d={areaFor(dataIn)} fill="url(#gIn)" />
        <path d={pathFor(dataOut)} fill="none" stroke={accent2} strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round" opacity="0.8" />
        <path d={pathFor(dataIn)} fill="none" stroke={accent} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
      </g>

      <circle cx={xAt(n - 1)} cy={yAt(lastIn)} r="4" fill={accent}>
        <animate attributeName="r" values="4;7;4" dur="1.6s" repeatCount="indefinite" />
        <animate attributeName="opacity" values="1;0.4;1" dur="1.6s" repeatCount="indefinite" />
      </circle>
      <circle cx={xAt(n - 1)} cy={yAt(lastIn)} r="2.5" fill={accent} />
      <circle cx={xAt(n - 1)} cy={yAt(lastOut)} r="2" fill={accent2} />

      <text x={pad.l} y={height - 8} fontSize="10" fill="var(--muted)" fontFamily="var(--mono)">-2m</text>
      <text x={pad.l + w / 2} y={height - 8} fontSize="10" fill="var(--muted)" fontFamily="var(--mono)" textAnchor="middle">-1m</text>
      <text x={pad.l + w} y={height - 8} fontSize="10" fill="var(--muted)" fontFamily="var(--mono)" textAnchor="end">now</text>
    </svg>
  );
}

// ============================================================
// Sparkline — tiny live chart for peer rows
// ============================================================
function Sparkline({ data, width = 120, height = 32, color = 'var(--accent)', active = true }) {
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
      </defs>
      <path d={area} fill={`url(#sg-${color.replace(/[^a-z0-9]/gi, '')})`} opacity={active ? 1 : 0.3} />
      <path d={d} fill="none" stroke={color} strokeWidth="1.4" strokeLinejoin="round" strokeLinecap="round" opacity={active ? 1 : 0.4} />
      {active && (
        <>
          <circle cx={last[0]} cy={last[1]} r="3" fill={color} opacity="0.3">
            <animate attributeName="r" values="2;5;2" dur="1.4s" repeatCount="indefinite" />
            <animate attributeName="opacity" values="0.5;0;0.5" dur="1.4s" repeatCount="indefinite" />
          </circle>
          <circle cx={last[0]} cy={last[1]} r="1.8" fill={color} />
        </>
      )}
    </svg>
  );
}

// ============================================================
// MiniBar — per-KPI live mini chart (bars)
// ============================================================
function MiniBars({ data, width = 140, height = 36, color = 'var(--accent)' }) {
  const n = data.length;
  const max = Math.max(...data, 0.01);
  const barW = (width - (n - 1) * 2) / n;
  return (
    <svg viewBox={`0 0 ${width} ${height}`} style={{ width: '100%', height, display: 'block' }}>
      {data.map((v, i) => {
        const h = (v / max) * (height - 4);
        const x = i * (barW + 2);
        const y = height - h - 2;
        return <rect key={i} x={x} y={y} width={barW} height={h} fill={color} opacity={0.3 + 0.7 * (i / n)} rx="1" />;
      })}
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
  const dash = arc * pct;
  return (
    <svg viewBox={`0 0 ${width} ${width}`} style={{ width: '100%', height: width, display: 'block' }}>
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="var(--border)" strokeWidth="6"
        strokeDasharray={`${arc} ${c}`} strokeLinecap="round"
        transform={`rotate(135 ${cx} ${cy})`} />
      <circle cx={cx} cy={cy} r={r} fill="none" stroke={color} strokeWidth="6"
        strokeDasharray={`${dash} ${c}`} strokeLinecap="round"
        transform={`rotate(135 ${cx} ${cy})`}
        style={{ transition: 'stroke-dasharray 0.6s ease' }} />
      <text x={cx} y={cy - 2} textAnchor="middle" fontSize="22" fontFamily="var(--serif)" fill="var(--ink)" fontWeight="400">{label}</text>
      <text x={cx} y={cy + 16} textAnchor="middle" fontSize="9.5" fill="var(--muted)" fontFamily="var(--mono)" letterSpacing="0.08em">{sublabel}</text>
    </svg>
  );
}

Object.assign(window, { ThroughputChart, Sparkline, MiniBars, RadialGauge });

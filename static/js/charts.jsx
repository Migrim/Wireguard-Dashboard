// Live animated SVG charts for WG-Quick

const { useState, useEffect, useLayoutEffect, useRef, useMemo } = React;

// ============================================================
// ThroughputChart — hero live chart, real time-axis based
// ============================================================
const CHART_RANGE_MS = { '10s': 10000, '30s': 30000, '1m': 60000, '5m': 300000, '1h': 3600000, '24h': 86400000 };
const PAD = { l: 70, r: 16, t: 18, b: 28 };
const MAX_YTICKS = 6;

// samples: [{ts: ms, rx: bytes/s, tx: bytes/s}, ...]
function ThroughputChart({ samples = [], width: widthProp = 900, height = 280, accent = 'var(--accent)', accent2 = 'var(--accent-2)', range = '1m', spline = false, splineTension = 1, smoothScroll = false, smoothScale = false, paused = false }) {
  const uid = useRef(`tc-${Math.random().toString(36).slice(2)}`).current;
  const containerRef   = useRef(null);
  const svgRef         = useRef(null);
  const clipRectRef    = useRef(null);
  const pathAreaInRef  = useRef(null);
  const pathAreaOutRef = useRef(null);
  const pathLineInRef  = useRef(null);
  const pathLineOutRef = useRef(null);
  const dotInRef       = useRef(null);
  const dotOutRef      = useRef(null);
  const vGridRef       = useRef(null);
  const hGridRef       = useRef(null);
  const lblLeft        = useRef(null);
  const lblMid         = useRef(null);
  const lblRight       = useRef(null);

  // Refs read inside RAF — updated synchronously each render, no stale-closure risk
  const widthRef      = useRef(widthProp);
  const samplesRef    = useRef(samples);
  const rangeRef      = useRef(range);
  const splineRef     = useRef(spline);
  const smoothRef         = useRef(smoothScroll);
  const smoothScaleRef    = useRef(smoothScale);
  const splineTensionRef  = useRef(splineTension);
  const dotInYRef     = useRef(null);
  const dotOutYRef    = useRef(null);
  const animNiceMaxRef = useRef(null);
  const animRangeRef  = useRef(null);
  const rafRef        = useRef(null);
  const nowMsRef      = useRef(null);
  const pausedRef     = useRef(paused);
  const pausedNowRef  = useRef(null);
  const hoverRef      = useRef(null);
  const xhairRef      = useRef(null);
  const mkInRef       = useRef(null);
  const mkOutRef      = useRef(null);
  const tipRef        = useRef(null);
  const tipTimeRef    = useRef(null);
  const tipInRef      = useRef(null);
  const tipOutRef     = useRef(null);
  // Eased hover geometry — lerped toward their targets each frame so the
  // crosshair/markers glide between samples instead of snapping slot to slot,
  // and the tooltip trails the cursor instead of teleporting.
  const hoverShownRef = useRef(false);
  const xhairXRef     = useRef(0);
  const mkInYRef      = useRef(0);
  const mkOutYRef     = useRef(0);
  const tipXRef       = useRef(0);
  const tipYRef       = useRef(0);

  samplesRef.current  = samples;
  rangeRef.current    = range;
  splineRef.current   = spline;
  smoothRef.current         = smoothScroll;
  smoothScaleRef.current    = smoothScale;
  splineTensionRef.current  = splineTension;
  pausedRef.current         = paused;

  // Measure container width
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    widthRef.current = Math.round(el.getBoundingClientRect().width) || widthProp;
    const ro = new ResizeObserver(entries => {
      const cw = entries[0]?.contentRect.width;
      if (cw > 0) widthRef.current = Math.round(cw);
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // Main RAF loop — runs for the component lifetime, reads refs each frame
  useEffect(() => {
    let lastTime = performance.now();

    const fmtDur = (ms) => {
      const s = ms / 1000;
      if (s < 60) return `${Math.round(s)}s`;
      const m = s / 60;
      if (m < 60) return `${Number(m.toFixed(m < 10 ? 1 : 0))}m`;
      return `${Number((m / 60).toFixed(1))}h`;
    };

    const tick = (now) => {
      const dt       = Math.min(now - lastTime, 100);
      lastTime       = now;
      const W        = widthRef.current;
      const selMs    = CHART_RANGE_MS[rangeRef.current] || 60000;
      const w        = W - PAD.l - PAD.r;
      const h        = height - PAD.t - PAD.b;
      const all = samplesRef.current;

      // In smooth mode, advance nowMs monotonically at real-time rate (dt per frame).
      // Anchoring to Date.now()-lag would recalculate lag every frame from sample
      // timestamps; when a new sample arrives with a slightly different interval the
      // lag changes and nowMs jumps backward — the "glitch back". Advancing a ref
      // instead guarantees nowMs never decreases regardless of sample timing, and
      // also fixes Windows clock-skew (server ts > Date.now()) because we anchor to
      // the last sample's ts rather than the client clock.
      let nowMs;
      if (smoothRef.current) {
        if (all.length === 0) {
          // No data yet (history still loading / fresh server) — stay unanchored.
          // Anchoring to Date.now() here would leave zero lag behind the data, so
          // every later sample would land inside the visible window and pop into
          // view instead of scrolling in from the right.
          nowMsRef.current = null;
          nowMs = Date.now();
        } else {
          const lastTs = all[all.length - 1].ts;
          // Anchor roughly one sample gap behind the newest sample so arrivals land
          // off-screen right (past the clip edge) and scroll into view smoothly.
          const gap  = all.length > 1 ? Math.min(5000, Math.max(800, lastTs - all[all.length - 2].ts)) : 1500;
          const lead = gap + 300;
          if (nowMsRef.current === null || lastTs - nowMsRef.current > lead + 10000) {
            // First anchor, or the data jumped far ahead of the window (e.g. stale
            // history replaced by live samples after reopening the page) — since
            // nowMs only advances at 1× real time it could never catch up; snap it.
            nowMsRef.current = lastTs - lead;
          }
          // Clamp forward drift to the same look-ahead window used for sampleCeil below,
          // so a stalled poll (backgrounded tab, slow network) never lets nowMs run far
          // ahead of real data — this avoids the hard "reset" jump that used to snap the
          // window backward once drift exceeded 10 s, which was visible to the user.
          nowMsRef.current = Math.min(nowMsRef.current + dt, lastTs + 6000);
          nowMs = nowMsRef.current;
        }
      } else {
        nowMsRef.current = null; // reset so re-enabling smooth mode re-anchors
        nowMs = all.length > 0 ? all[all.length - 1].ts : Date.now();
      }
      // Paused: freeze the display window where it is. Samples keep accumulating
      // and the smooth-mode anchor above keeps advancing, so resuming jumps
      // straight back to live.
      if (pausedRef.current) {
        if (pausedNowRef.current === null) pausedNowRef.current = nowMs;
        nowMs = pausedNowRef.current;
      } else {
        pausedNowRef.current = null;
      }
      // Clamp the window to the data actually available so the plot is always
      // fully used — with only 20s of samples a 1m/1h window would squeeze the
      // line into the right edge. The window grows with the data (10s → 30s → …)
      // until it reaches the selected range; jumps (pill switch, history load)
      // are eased in smooth mode so the zoom animates.
      let targetRange = selMs;
      if (all.length > 1) {
        targetRange = Math.max(10000, Math.min(selMs, nowMs - all[0].ts));
      }
      if (animRangeRef.current === null) animRangeRef.current = targetRange;
      if (smoothRef.current) {
        animRangeRef.current += (targetRange - animRangeRef.current) * (1 - Math.exp(-dt / 300));
      } else {
        animRangeRef.current = targetRange;
      }
      const rangeMs  = animRangeRef.current;
      const winStart = nowMs - rangeMs;

      // Include samples up to 6 s beyond nowMs so new arrivals (still off-screen
      // to the right) are already in the path and scroll into view smoothly.
      // The clipPath handles the visual right boundary.
      // While paused, exclude the off-screen lead so late arrivals can't shift
      // the y-scale of the frozen view.
      const sampleCeil = (smoothRef.current && !pausedRef.current) ? nowMs + 6000 : nowMs;
      const visible = [];
      for (let i = 0; i < all.length; i++) {
        if (all[i].ts >= winStart - 2000 && all[i].ts <= sampleCeil) visible.push(all[i]);
      }

      // Y-axis: nice ticks based on max of visible data
      let maxRaw = 0;
      for (const s of visible) {
        if (s.rx > maxRaw) maxRaw = s.rx;
        if (s.tx > maxRaw) maxRaw = s.tx;
      }
      maxRaw = Math.max(maxRaw, 10 * 1024);
      const tUnitBytes   = maxRaw < 1024 * 1024 ? 1024 : 1024 * 1024;
      const tRawInUnit   = maxRaw / tUnitBytes;
      const tRoughStep   = tRawInUnit / 4;
      const tMag         = Math.pow(10, Math.floor(Math.log10(Math.max(tRoughStep, 0.001))));
      const tNorm        = tRoughStep / tMag;
      const tNiceStep    = tNorm < 1.5 ? tMag : tNorm < 3 ? 2 * tMag : tNorm < 7 ? 5 * tMag : 10 * tMag;
      const tNiceMaxUnit = Math.ceil(tRawInUnit / tNiceStep) * tNiceStep;
      const targetNiceMax = tNiceMaxUnit * tUnitBytes;

      // In smooth mode, lerp the displayed scale toward the target so KB↔MB transitions animate
      if (animNiceMaxRef.current === null) animNiceMaxRef.current = targetNiceMax;
      if (smoothScaleRef.current) {
        animNiceMaxRef.current += (targetNiceMax - animNiceMaxRef.current) * (1 - Math.exp(-dt / 400));
      } else {
        animNiceMaxRef.current = targetNiceMax;
      }
      const niceMax = animNiceMaxRef.current;

      // Derive display unit and tick spacing from the animated scale
      const unitBytes = niceMax < 1024 * 1024 ? 1024 : 1024 * 1024;
      const unitName  = unitBytes === 1024 ? 'KB/s' : 'MB/s';
      const rawInUnit = niceMax / unitBytes;
      const roughStep = rawInUnit / 4;
      const mag       = Math.pow(10, Math.floor(Math.log10(Math.max(roughStep, 0.001))));
      const norm      = roughStep / mag;
      const niceStep  = norm < 1.5 ? mag : norm < 3 ? 2 * mag : norm < 7 ? 5 * mag : 10 * mag;

      const ticks = [];
      for (let s = 0; s <= rawInUnit + niceStep * 0.01 && ticks.length < MAX_YTICKS; s += niceStep) {
        ticks.push({
          y:   PAD.t + h - (s * unitBytes / niceMax) * h,
          lbl: s === 0 ? '0 B/s' : `${Number(s.toFixed(4))} ${unitName}`,
        });
      }

      // Coordinate helpers — x is time-based, NOT index-based
      const xAt = (ts) => PAD.l + ((ts - winStart) / rangeMs) * w;
      const yAt = (v)  => PAD.t + h - (v / niceMax) * h;

      // Build SVG path string for rx or tx
      const buildPath = (key, close) => {
        if (visible.length < 2) return '';
        const sp = splineRef.current;
        let d = '';
        if (sp) {
          d = `M${xAt(visible[0].ts).toFixed(1)},${yAt(visible[0][key] || 0).toFixed(1)}`;
          for (let i = 1; i < visible.length; i++) {
            const p0 = visible[Math.max(0, i - 2)];
            const p1 = visible[i - 1];
            const p2 = visible[i];
            const p3 = visible[Math.min(visible.length - 1, i + 1)];
            const x1 = xAt(p1.ts), x2 = xAt(p2.ts);
            const dx = (x2 - x1) / 3;
            const t = splineTensionRef.current;
            d += ` C${(x1 + dx).toFixed(1)},${(yAt(p1[key]||0) + (yAt(p2[key]||0) - yAt(p0[key]||0)) / 6 * t).toFixed(1)}` +
                 ` ${(x2 - dx).toFixed(1)},${(yAt(p2[key]||0) - (yAt(p3[key]||0) - yAt(p1[key]||0)) / 6 * t).toFixed(1)}` +
                 ` ${x2.toFixed(1)},${yAt(p2[key] || 0).toFixed(1)}`;
          }
        } else {
          for (let i = 0; i < visible.length; i++) {
            d += (i === 0 ? 'M' : 'L') + xAt(visible[i].ts).toFixed(1) + ',' + yAt(visible[i][key] || 0).toFixed(1) + ' ';
          }
        }
        if (close) {
          const lx = xAt(visible[visible.length - 1].ts).toFixed(1);
          const fx = xAt(visible[0].ts).toFixed(1);
          d += ` L${lx},${(PAD.t + h).toFixed(1)} L${fx},${(PAD.t + h).toFixed(1)} Z`;
        }
        return d;
      };

      // Apply paths
      svgRef.current?.setAttribute('viewBox', `0 0 ${W} ${height}`);
      clipRectRef.current?.setAttribute('width', w.toFixed(1));
      pathAreaInRef.current?.setAttribute('d',  buildPath('rx', true));
      pathAreaOutRef.current?.setAttribute('d', buildPath('tx', true));
      pathLineInRef.current?.setAttribute('d',  buildPath('rx', false));
      pathLineOutRef.current?.setAttribute('d', buildPath('tx', false));

      // Dots — use the actual latest sample for Y so the live value is shown.
      // In smooth mode, pin X to the right clip edge (the lag puts data off-screen
      // to the right, so the last sample's xAt() would be outside the clip).
      const dotSrc = all.length > 0 ? all[all.length - 1] : null;
      if (dotSrc) {
        const tInY  = yAt(dotSrc.rx || 0);
        const tOutY = yAt(dotSrc.tx || 0);
        if (dotInYRef.current  === null) dotInYRef.current  = tInY;
        if (dotOutYRef.current === null) dotOutYRef.current = tOutY;
        const lf = 1 - Math.exp(-dt / 120);
        dotInYRef.current  += (tInY  - dotInYRef.current)  * lf;
        dotOutYRef.current += (tOutY - dotOutYRef.current) * lf;
        const dX = smoothRef.current
          ? (PAD.l + w).toFixed(1)
          : Math.min(PAD.l + w, xAt(dotSrc.ts)).toFixed(1);
        // Hide the live dot while paused — it tracks the newest sample, which
        // sits outside the frozen window.
        const dotOpacity = (smoothRef.current || pausedRef.current) ? '0' : '1';
        dotInRef.current?.setAttribute('cx', dX);
        dotInRef.current?.setAttribute('cy', dotInYRef.current.toFixed(2));
        dotInRef.current?.setAttribute('opacity', dotOpacity);
        dotOutRef.current?.setAttribute('cx', dX);
        dotOutRef.current?.setAttribute('cy', dotOutYRef.current.toFixed(2));
        dotOutRef.current?.setAttribute('opacity', dotOpacity);
      }

      // Y-axis grid + labels — show/hide placeholder groups
      if (hGridRef.current) {
        const groups = hGridRef.current.children;
        for (let i = 0; i < groups.length; i++) {
          const t = ticks[i];
          if (!t) { groups[i].setAttribute('visibility', 'hidden'); continue; }
          groups[i].setAttribute('visibility', 'visible');
          const line = groups[i].querySelector('line');
          const text = groups[i].querySelector('text');
          if (line) { line.setAttribute('y1', t.y.toFixed(1)); line.setAttribute('y2', t.y.toFixed(1)); line.setAttribute('x2', (PAD.l + w).toFixed(1)); }
          if (text) { text.setAttribute('y', (t.y + 3).toFixed(1)); text.textContent = t.lbl; }
        }
      }

      // Vertical grid lines
      if (vGridRef.current) {
        const lines = vGridRef.current.children;
        const fracs = [0, 0.25, 0.5, 0.75, 1];
        for (let i = 0; i < Math.min(lines.length, fracs.length); i++) {
          const x = (PAD.l + w * fracs[i]).toFixed(1);
          lines[i].setAttribute('x1', x); lines[i].setAttribute('x2', x);
        }
      }

      // Time-axis labels — reflect the effective (possibly clamped) window
      if (lblLeft.current)  { lblLeft.current.setAttribute('x',  PAD.l.toString());              lblLeft.current.textContent  = `-${fmtDur(rangeMs)}`; }
      if (lblMid.current)   { lblMid.current.setAttribute('x',   (PAD.l + w / 2).toFixed(1));   lblMid.current.textContent   = `-${fmtDur(rangeMs / 2)}`; }
      if (lblRight.current) { lblRight.current.setAttribute('x', (PAD.l + w).toFixed(1));        lblRight.current.textContent = pausedRef.current ? 'paused' : 'now'; }

      // Hover crosshair + tooltip — driven from the RAF so it stays glued to the
      // nearest sample even while the window scrolls under a stationary cursor.
      const hv = hoverRef.current;
      let hovered = null;
      if (hv && visible.length > 0 && hv.x >= PAD.l && hv.x <= PAD.l + w) {
        const hoverTs = winStart + ((hv.x - PAD.l) / w) * rangeMs;
        let bestD = Infinity;
        for (const s of visible) {
          if (s.ts > winStart + rangeMs) continue; // off-screen lead in smooth mode
          const d = Math.abs(s.ts - hoverTs);
          if (d < bestD) { bestD = d; hovered = s; }
        }
      }
      if (hovered) {
        // Targets: crosshair and markers stay locked to the hovered sample (the
        // values in the tooltip must be the ones being pointed at), while the
        // tooltip itself tracks the raw cursor position.
        const tXhair = Math.max(PAD.l, Math.min(PAD.l + w, xAt(hovered.ts)));
        const tMkIn  = yAt(hovered.rx || 0);
        const tMkOut = yAt(hovered.tx || 0);
        const tTipX  = Math.max(PAD.l + 46, Math.min(PAD.l + w - 46, hv.x));
        const tTipY  = Math.max(12, hv.y - 14);

        // On the first frame of a hover, snap — easing from wherever the cursor
        // left the chart last time would fling the tooltip across the plot.
        const fresh = !hoverShownRef.current;
        hoverShownRef.current = true;
        // ~55 ms time constant: fast enough to feel glued to the cursor, slow
        // enough to smear the sample-to-sample steps into a glide.
        const ease = fresh ? 1 : 1 - Math.exp(-dt / 55);
        xhairXRef.current += (tXhair - xhairXRef.current) * ease;
        mkInYRef.current  += (tMkIn  - mkInYRef.current)  * ease;
        mkOutYRef.current += (tMkOut - mkOutYRef.current) * ease;
        tipXRef.current   += (tTipX  - tipXRef.current)   * ease;
        tipYRef.current   += (tTipY  - tipYRef.current)   * ease;

        const sx = xhairXRef.current;
        xhairRef.current?.setAttribute('x1', sx.toFixed(1));
        xhairRef.current?.setAttribute('x2', sx.toFixed(1));
        xhairRef.current?.setAttribute('y1', PAD.t.toFixed(1));
        xhairRef.current?.setAttribute('y2', (PAD.t + h).toFixed(1));
        xhairRef.current?.setAttribute('opacity', '0.45');
        mkInRef.current?.setAttribute('cx', sx.toFixed(1));
        mkInRef.current?.setAttribute('cy', mkInYRef.current.toFixed(1));
        mkInRef.current?.setAttribute('opacity', '1');
        mkOutRef.current?.setAttribute('cx', sx.toFixed(1));
        mkOutRef.current?.setAttribute('cy', mkOutYRef.current.toFixed(1));
        mkOutRef.current?.setAttribute('opacity', '1');
        if (tipRef.current) {
          // transform (not left/top) so the per-frame move is composited rather
          // than relayed out; the -50%/-100% recentring lives here now instead
          // of in the .pingbar-tip base rule.
          tipRef.current.style.transform =
            `translate3d(${tipXRef.current.toFixed(1)}px, ${tipYRef.current.toFixed(1)}px, 0) translate(-50%, -100%)`;
          tipRef.current.style.opacity = '1';
          const d = new Date(hovered.ts);
          if (tipTimeRef.current) tipTimeRef.current.textContent = rangeMs <= 300000
            ? d.toLocaleTimeString()
            : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
          if (tipInRef.current)  tipInRef.current.textContent  = window.WG.formatRate(hovered.rx || 0);
          if (tipOutRef.current) tipOutRef.current.textContent = window.WG.formatRate(hovered.tx || 0);
        }
      } else {
        hoverShownRef.current = false;
        xhairRef.current?.setAttribute('opacity', '0');
        mkInRef.current?.setAttribute('opacity', '0');
        mkOutRef.current?.setAttribute('opacity', '0');
        if (tipRef.current) tipRef.current.style.opacity = '0';
      }

      rafRef.current = requestAnimationFrame(tick);
    };

    rafRef.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(rafRef.current);
  }, [height]); // re-create only if height changes

  return (
    <div
      ref={containerRef}
      style={{ width: '100%', position: 'relative', cursor: 'crosshair' }}
      onMouseMove={e => {
        const rect = containerRef.current?.getBoundingClientRect();
        if (rect) hoverRef.current = { x: e.clientX - rect.left, y: e.clientY - rect.top };
      }}
      onMouseLeave={() => { hoverRef.current = null; }}
    >
      <svg ref={svgRef} viewBox={`0 0 ${widthProp} ${height}`} preserveAspectRatio="none" style={{ width: '100%', height, display: 'block' }}>
        <defs>
          <linearGradient id={`${uid}-gIn`}  x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%"   stopColor={accent}  stopOpacity="0.35" />
            <stop offset="100%" stopColor={accent}  stopOpacity="0.02" />
          </linearGradient>
          <linearGradient id={`${uid}-gOut`} x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%"   stopColor={accent2} stopOpacity="0.28" />
            <stop offset="100%" stopColor={accent2} stopOpacity="0.01" />
          </linearGradient>
          <clipPath id={`${uid}-clip`}>
            <rect ref={clipRectRef} x={PAD.l} y={PAD.t} width={widthProp - PAD.l - PAD.r} height={height - PAD.t - PAD.b} />
          </clipPath>
        </defs>

        {/* Y-axis: MAX_YTICKS placeholder groups, RAF shows/hides and positions them */}
        <g ref={hGridRef}>
          {Array.from({ length: MAX_YTICKS }).map((_, i) => (
            <g key={i} visibility="hidden">
              <line x1={PAD.l} x2={PAD.l} y1={0} y2={0} stroke="var(--border)" strokeDasharray={i === 0 ? '' : '2 3'} strokeWidth="1" opacity="0.6" />
              <text x={PAD.l - 8} y={0} textAnchor="end" fontSize="10" fill="var(--muted)" fontFamily="var(--mono)" />
            </g>
          ))}
        </g>

        {/* Vertical grid lines — RAF updates x positions */}
        <g ref={vGridRef}>
          {[0, 0.25, 0.5, 0.75, 1].map((_, i) => (
            <line key={i} x1={PAD.l} x2={PAD.l} y1={PAD.t} y2={PAD.t + height - PAD.t - PAD.b} stroke="var(--border)" strokeDasharray="2 3" strokeWidth="1" opacity="0.35" />
          ))}
        </g>

        <g clipPath={`url(#${uid}-clip)`}>
          <path ref={pathAreaOutRef} d="" fill={`url(#${uid}-gOut)`} />
          <path ref={pathAreaInRef}  d="" fill={`url(#${uid}-gIn)`} />
          <path ref={pathLineOutRef} d="" fill="none" stroke={accent2} strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round" opacity="0.8" />
          <path ref={pathLineInRef}  d="" fill="none" stroke={accent}  strokeWidth="2"   strokeLinejoin="round" strokeLinecap="round" />
        </g>
        {/* Dots outside clip — always visible; in smooth mode pinned to right edge */}
        <circle ref={dotInRef}  cx={0} cy={0} r="3" fill={accent}  opacity="0" />
        <circle ref={dotOutRef} cx={0} cy={0} r="3" fill={accent2} opacity="0" />

        {/* Hover crosshair + sample markers — positioned by the RAF loop */}
        <line ref={xhairRef} x1={0} x2={0} y1={0} y2={0} stroke="var(--ink)" strokeWidth="1" strokeDasharray="3 3" opacity="0" />
        <circle ref={mkInRef}  cx={0} cy={0} r="3.5" fill={accent}  stroke="var(--card)" strokeWidth="1.5" opacity="0" />
        <circle ref={mkOutRef} cx={0} cy={0} r="3.5" fill={accent2} stroke="var(--card)" strokeWidth="1.5" opacity="0" />

        <text ref={lblLeft}  x={PAD.l} y={height - 8} fontSize="10" fill="var(--muted)" fontFamily="var(--mono)" />
        <text ref={lblMid}   x={PAD.l} y={height - 8} fontSize="10" fill="var(--muted)" fontFamily="var(--mono)" textAnchor="middle" />
        <text ref={lblRight} x={PAD.l} y={height - 8} fontSize="10" fill="var(--muted)" fontFamily="var(--mono)" textAnchor="end" />
      </svg>
      <div ref={tipRef} className="pingbar-tip chart-tip" style={{ left: 0, top: 0, opacity: 0 }}>
        <span ref={tipTimeRef} className="pingbar-tip-lbl" />
        <div className="chart-tip-row">
          <i className="chart-tip-key" style={{ background: accent }} />
          <span ref={tipInRef} className="pingbar-tip-val" />
          <span className="chart-tip-name">inbound</span>
        </div>
        <div className="chart-tip-row">
          <i className="chart-tip-key" style={{ background: accent2 }} />
          <span ref={tipOutRef} className="pingbar-tip-val" />
          <span className="chart-tip-name">outbound</span>
        </div>
      </div>
    </div>
  );
}

// ============================================================
// Sparkline — tiny live chart for peer rows
// ============================================================
function Sparkline({ data, width = 120, height = 32, color = 'var(--accent)', active = true, format }) {
  const uid = useRef(`sp-${Math.random().toString(36).slice(2)}`).current;
  const [hover, setHover] = useState(null); // { i }
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
  const hv = format && hover ? hover : null;

  const svg = (
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
      {active && !hv && (
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
      {hv && (
        <>
          <line x1={pts[hv.i][0]} x2={pts[hv.i][0]} y1={2} y2={height - 2} stroke="var(--ink)" strokeWidth="1" strokeDasharray="2 2" opacity="0.35" />
          <circle cx={pts[hv.i][0]} cy={pts[hv.i][1]} r="2.6" fill={color} stroke="var(--card)" strokeWidth="1.2" />
        </>
      )}
    </svg>
  );

  if (!format) return svg;
  return (
    <div
      style={{ position: 'relative', width, height, cursor: 'crosshair' }}
      onMouseMove={e => {
        const rect = e.currentTarget.getBoundingClientRect();
        const x = (e.clientX - rect.left) / (rect.width || width) * width;
        const i = Math.max(0, Math.min(n - 1, Math.round(((x - 1) / (width - 2)) * (n - 1))));
        setHover({ i });
      }}
      onMouseLeave={() => setHover(null)}
    >
      {svg}
      {hv && (
        <div
          className="pingbar-tip"
          style={{ left: Math.max(14, Math.min(width - 14, pts[hv.i][0])), top: Math.max(4, pts[hv.i][1] - 8) }}
        >
          <span className="pingbar-tip-val">{format(data[hv.i])}</span>
        </div>
      )}
    </div>
  );
}

// ============================================================
// MiniBar — per-KPI live mini chart (bars)
// ============================================================
function MiniBars({ data, width = 140, height = 36, color = 'var(--accent)', smooth = false, slots = 20, format }) {
  const uid = useRef(`mb-${Math.random().toString(36).slice(2)}`).current;
  const [hover, setHover] = useState(null); // { i, px }
  // Fixed slot count: left-pad with zeros so the bar count never changes —
  // values shift through the slots instead of new bars mounting.
  const vals = data.length >= slots
    ? data.slice(-slots)
    : [...Array(slots - data.length).fill(0), ...data];
  const max = Math.max(...vals, 0.01);
  const barW = (width - (slots - 1) * 2) / slots;
  // In smooth mode each slot's height eases toward the value that shifted
  // into it, so the data appears to flow from bar to bar.
  const barStyle = smooth ? { transition: 'y 0.6s ease, height 0.6s ease' } : undefined;
  const hv = format && hover ? hover : null;
  const svg = (
    <svg viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" style={{ width: '100%', height, display: 'block' }}>
      <defs>
        <clipPath id={uid}>
          <rect x="0" width={width}>
            <animate attributeName="y" from={height} to="0" dur="0.7s" fill="freeze" calcMode="spline" keyTimes="0;1" keySplines="0 0 0.2 1" />
            <animate attributeName="height" from="0" to={height} dur="0.7s" fill="freeze" calcMode="spline" keyTimes="0;1" keySplines="0 0 0.2 1" />
          </rect>
        </clipPath>
      </defs>
      <g clipPath={`url(#${uid})`}>
        {vals.map((v, i) => {
          const h = Math.max(1.5, (v / max) * (height - 4));
          const x = i * (barW + 2);
          const y = height - h - 2;
          return <rect key={i} x={x} y={y} width={barW} height={h} fill={color}
            opacity={hv && hv.i === i ? 1 : 0.3 + 0.7 * (i / slots)} rx="1" style={barStyle} />;
        })}
      </g>
    </svg>
  );
  if (!format) return svg;
  return (
    <div
      style={{ position: 'relative', width: '100%', cursor: 'crosshair' }}
      onMouseMove={e => {
        const rect = e.currentTarget.getBoundingClientRect();
        const vx = (e.clientX - rect.left) / (rect.width || width) * width;
        const i = Math.max(0, Math.min(slots - 1, Math.floor(vx / (barW + 2))));
        const px = ((i * (barW + 2) + barW / 2) / width) * (rect.width || width);
        setHover({ i, px });
      }}
      onMouseLeave={() => setHover(null)}
    >
      {svg}
      {hv && (
        <div className="pingbar-tip" style={{ left: hv.px, top: -2 }}>
          <span className="pingbar-tip-val">{format(vals[hv.i])}</span>
        </div>
      )}
    </div>
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

// ============================================================
// BudgetComposition — part-to-whole bar of today's traffic by peer.
// Shown wherever there is no cap to measure against, since "percent of nothing"
// has no answer but "who used it" always does.
// ============================================================
const BCOMP_MAX_SEGMENTS = 5;
const bcompColor = (i) => `var(--bcomp-${i})`;

// Top peers by usage, remainder folded into one "others" segment. The ramp is
// never cycled: an 8th peer joins "others", it does not reuse step 0.
function budgetComposition(rows) {
  const ranked = rows.filter(r => r.total > 0).sort((a, b) => b.total - a.total);
  if (ranked.length <= BCOMP_MAX_SEGMENTS) return ranked;
  const keep = ranked.slice(0, BCOMP_MAX_SEGMENTS - 1);
  const rest = ranked.slice(BCOMP_MAX_SEGMENTS - 1);
  return [...keep, {
    id: '__other',
    name: `${rest.length} others`,
    total: rest.reduce((s, r) => s + r.total, 0),
  }];
}

function BudgetComposition({ rows, height = 10, legend = true, legendMax = Infinity, compact = false, emptyLabel = 'no traffic recorded yet today' }) {
  const [hover, setHover] = useState(null); // { i, x }
  const barRef = useRef(null);

  const comp = useMemo(() => budgetComposition(rows || []), [rows]);
  // Sized against their own sum, not the interface total — per-peer counters can
  // lag it, and a bar that stops short of its track reads as a rendering bug.
  const compTotal = comp.reduce((s, p) => s + p.total, 0) || 1;

  if (comp.length === 0) {
    return (
      <div className="bcomp-wrap">
        <div className="bcomp-empty" style={{ height }} />
        {legend && <div className="bcomp-legend"><span>{emptyLabel}</span></div>}
      </div>
    );
  }

  const share = (p) => (p.total / compTotal) * 100;
  const onEnter = (i, e) => {
    const bar = barRef.current;
    if (!bar) return;
    const seg = e.currentTarget.getBoundingClientRect();
    const box = bar.getBoundingClientRect();
    setHover({ i, x: seg.left - box.left + seg.width / 2 });
  };

  const hovering = hover !== null;
  const legendItems = comp.slice(0, legendMax);
  const hiddenCount = comp.length - legendItems.length;

  return (
    <div className="bcomp-wrap">
      {hovering && (
        <div className="pingbar-tip bcomp-tip" style={{ left: hover.x, top: -6 }}>
          <span className="bcomp-tip-name">{comp[hover.i].name}</span>
          <span className="bcomp-tip-val">
            {window.WG.formatBytes(comp[hover.i].total)} · {share(comp[hover.i]).toFixed(1)}%
          </span>
        </div>
      )}
      <div
        ref={barRef}
        className={`bcomp-bar${hovering ? ' is-hovering' : ''}`}
        style={{ height }}
        onMouseLeave={() => setHover(null)}
      >
        {comp.map((p, i) => (
          <div
            key={p.id}
            className={`bcomp-seg${hover?.i === i ? ' on' : ''}`}
            style={{ width: `${share(p)}%`, background: bcompColor(i) }}
            onMouseEnter={(e) => onEnter(i, e)}
          />
        ))}
      </div>
      {legend && (
        <div className={`bcomp-legend${compact ? ' bcomp-legend-sm' : ''}${hovering ? ' is-hovering' : ''}`}>
          {legendItems.map((p, i) => (
            <span key={p.id} className={`bcomp-item${hover?.i === i ? ' on' : ''}`}>
              <span className="bcomp-dot" style={{ background: bcompColor(i) }} />
              <span className="bcomp-name" title={p.name}>{p.name}</span>
              <span>{window.WG.formatBytes(p.total)}</span>
            </span>
          ))}
          {hiddenCount > 0 && <span className="bcomp-item">+{hiddenCount} more</span>}
        </div>
      )}
    </div>
  );
}

Object.assign(window, { ThroughputChart, Sparkline, MiniBars, RadialGauge, BudgetComposition });

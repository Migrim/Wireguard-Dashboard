// Sonner-style toast notification system — no external deps

(function () {
  const { useState: _tS, useEffect: _tE, useRef: _tR, useLayoutEffect: _tL } = React;

  // ── Event bus ──────────────────────────────────────────────────────────────
  const _fns = [];
  const _sub = fn => { _fns.push(fn); return () => { const i = _fns.indexOf(fn); if (i >= 0) _fns.splice(i, 1); }; };
  const _emit = ev => _fns.slice().forEach(fn => fn(ev));
  let _seq = 0;

  function _add(opts) {
    const id = ++_seq;
    _emit({ type: 'add', toast: { duration: 4000, ...opts, id } });
    const upd = patch => _emit({ type: 'update', id, patch });
    return {
      dismiss: ()            => _emit({ type: 'dismiss', id }),
      success: (title, desc) => upd({ type: 'success', title, desc: desc ?? null, duration: 4000 }),
      error:   (title, desc) => upd({ type: 'error',   title, desc: desc ?? null, duration: 6000 }),
      update:  upd,
    };
  }

  const toast = Object.assign(
    (title, opts)       => _add({ type: 'info',    title, ...opts }),
    {
      success: (title, desc, opts) => _add({ type: 'success', title, desc, ...opts }),
      error:   (title, desc, opts) => _add({ type: 'error',   title, desc, duration: 6000, ...opts }),
      warning: (title, desc, opts) => _add({ type: 'warning', title, desc, ...opts }),
      info:    (title, desc, opts) => _add({ type: 'info',    title, desc, ...opts }),
      loading: (title, desc, opts) => _add({ type: 'loading', title, desc, duration: Infinity, ...opts }),
      confirm: (title, desc, opts) => _add({ type: 'confirm', title, desc, duration: Infinity, ...opts }),
    }
  );
  window.WG.toast = toast;

  // ── Icon per type ──────────────────────────────────────────────────────────
  function ToastIcon({ type }) {
    if (type === 'loading') return <span className="toast-spin" />;
    const inner = {
      success: <><circle cx="12" cy="12" r="10"/><path d="M8 12l2.5 2.5L16 9"/></>,
      error:   <><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></>,
      warning: <><path d="M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z"/><path d="M12 9v4M12 17h.01"/></>,
      info:    <><circle cx="12" cy="12" r="10"/><path d="M12 11v5M12 8h.01"/></>,
      confirm: <><path d="M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z"/><path d="M12 9v4M12 17h.01"/></>,
    };
    return (
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor"
        strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
        {inner[type] || inner.info}
      </svg>
    );
  }

  // ── Single toast item ──────────────────────────────────────────────────────
  function ToastItem({ toast: t, onRemove }) {
    const [out, setOut] = _tS(false);
    const [pct, setPct] = _tS(100);
    // Stable mutable state lives in a ref to avoid stale closure issues
    const r = _tR({
      remaining: t.duration, start: Date.now(), duration: t.duration,
      paused: false, exiting: false, timer: null,
    });

    const itemRef = _tR(null);
    const szRef   = _tR(null);

    // FLIP resize — must be declared BEFORE size-capture so szRef still holds the OLD size
    _tL(() => {
      const el = itemRef.current;
      if (!el || !szRef.current) return;
      const { w: oldW, h: oldH } = szRef.current;
      const newW = el.offsetWidth;
      const newH = el.offsetHeight;
      if (oldW === newW && oldH === newH) return;
      el.style.transition = 'none';
      el.style.width  = oldW + 'px';
      el.style.height = oldH + 'px';
      void el.offsetWidth; // force layout before enabling transition
      el.style.transition = 'width 0.28s cubic-bezier(0.16,1,0.3,1), height 0.28s cubic-bezier(0.16,1,0.3,1)';
      el.style.width  = newW + 'px';
      el.style.height = newH + 'px';
      const id = setTimeout(() => {
        if (!el) return;
        el.style.width = '';
        el.style.height = '';
        el.style.transition = '';
      }, 300);
      return () => clearTimeout(id);
    }, [t.type, t.title, t.desc]); // eslint-disable-line react-hooks/exhaustive-deps

    // Capture size after every render — runs AFTER FLIP so szRef holds new size for next render
    _tL(() => {
      const el = itemRef.current;
      if (el) szRef.current = { w: el.offsetWidth, h: el.offsetHeight };
    });

    const exitRef = _tR(null);
    exitRef.current = () => {
      if (r.current.exiting) return;
      r.current.exiting = true;
      clearInterval(r.current.timer);
      setOut(true);
      // 260ms matches toastOut animation duration
      setTimeout(() => onRemove(t.id), 260);
    };

    // Restart timer whenever type or duration changes (e.g. loading → success)
    _tE(() => {
      clearInterval(r.current.timer);
      if (r.current.exiting) return;
      r.current.remaining = t.duration;
      r.current.duration  = t.duration;
      r.current.start     = Date.now();
      // Intentionally do NOT reset r.current.paused — preserve hover state
      setPct(100);
      if (!isFinite(t.duration) || t.duration <= 0) return;
      r.current.timer = setInterval(() => {
        if (r.current.paused) return;
        const elapsed = Date.now() - r.current.start;
        const left = Math.max(0, r.current.remaining - elapsed);
        setPct((left / r.current.duration) * 100);
        if (left <= 0) { clearInterval(r.current.timer); exitRef.current(); }
      }, 50);
      return () => clearInterval(r.current.timer);
    }, [t.type, t.duration]); // eslint-disable-line react-hooks/exhaustive-deps

    const pause = () => {
      if (r.current.paused) return;
      if (isFinite(r.current.duration)) {
        r.current.remaining = Math.max(0, r.current.remaining - (Date.now() - r.current.start));
      }
      r.current.paused = true;
    };
    const resume = () => {
      if (!r.current.paused) return;
      r.current.paused = false;
      r.current.start = Date.now();
    };

    return (
      <div
        ref={itemRef}
        className={`toast-item toast-${t.type}${out ? ' t-out' : ''}`}
        onMouseEnter={pause}
        onMouseLeave={resume}
        role="status"
        aria-live="polite"
      >
        <div className="toast-row">
          <span className={`toast-ico toast-ico-${t.type}`}><ToastIcon type={t.type} /></span>
          <div className="toast-txt">
            <div className="toast-ttl">{t.title}</div>
            {t.desc && <div className="toast-dsc">{t.desc}</div>}
          </div>
          <button className="toast-x" onClick={() => exitRef.current()} aria-label="Dismiss notification">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
              <path d="M18 6L6 18M6 6l12 12"/>
            </svg>
          </button>
        </div>
        {t.type === 'confirm' && (
          <div className="toast-actions">
            <button className="toast-act toast-act-cancel" onClick={() => exitRef.current()}>
              Cancel
            </button>
            <button
              className="toast-act toast-act-ok"
              onClick={() => { exitRef.current(); t.onConfirm?.(); }}
            >
              {t.confirmLabel || 'Confirm'}
            </button>
          </div>
        )}
        {isFinite(t.duration) && t.duration > 0 && (
          <div className="toast-bar">
            <div className="toast-bar-fill" style={{ width: pct + '%' }} />
          </div>
        )}
      </div>
    );
  }

  // ── Container ──────────────────────────────────────────────────────────────
  function Toaster() {
    const [list, setList] = _tS([]);
    const removeRef = _tR(id => setList(p => p.filter(t => t.id !== id)));

    _tE(() => _sub(ev => {
      setList(p => {
        if (ev.type === 'add')     return [...p.slice(-4), ev.toast]; // max 5 visible
        if (ev.type === 'dismiss') return p.filter(t => t.id !== ev.id);
        if (ev.type === 'update')  return p.map(t => t.id === ev.id ? { ...t, ...ev.patch } : t);
        return p;
      });
    }), []);

    if (!list.length) return null;

    return (
      <div className="toaster" aria-label="Notifications">
        {list.map(t => (
          <ToastItem key={t.id} toast={t} onRemove={removeRef.current} />
        ))}
      </div>
    );
  }

  window.Toaster = Toaster;
})();

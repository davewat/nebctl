import { useEffect, useMemo, useRef } from 'react';
import type { Connections, Peer } from '../api/types';
import { geometry, hash, place, seeded } from '../lib/layout';
import type { Geometry, Placed } from '../lib/layout';
import { isExpiring, shortName } from '../lib/format';
import { useReducedMotion } from '../lib/hooks';

const C = {
  night: '#070B1A',
  edge: '#22305A',
  star: '#C9D3F2',
  dim: '#8390B5',
  ember: '#FDBA74',
  flare: '#F472B6',
  relay: '#818CF8',
  danger: '#F87171',
};

interface Props {
  self: Connections['self'];
  peers: Peer[];
  lighthouses: Set<string>;
  blocked: Set<string>;
  selected: string | null;
  onSelect: (addr: string | null) => void;
  /** Width covered by the drawer; the mesh is centred in what is left. */
  coveredRight: number;
  summary: string;
}

interface Model {
  self: Props['self'];
  peers: Peer[];
  lighthouses: Set<string>;
  blocked: Set<string>;
  selected: string | null;
  coveredRight: number;
}

interface Star {
  x: number;
  y: number;
  r: number;
  a: number;
  p: number;
}

const SANS = '"Sora", ui-sans-serif, system-ui, sans-serif';
const MONO = '"IBM Plex Mono", ui-monospace, Menlo, monospace';

export function MeshCanvas(props: Props) {
  const { peers, selected, onSelect, summary } = props;
  const reduce = useReducedMotion();
  const wrap = useRef<HTMLDivElement>(null);
  const cv = useRef<HTMLCanvasElement>(null);
  const model = useRef<Model>(props);
  model.current = props;
  const size = useRef({ w: 0, h: 0, dpr: 1 });
  const stars = useRef<Star[]>([]);
  const hover = useRef<string | null>(null);
  const focus = useRef<string | null>(null);
  const placed = useRef<{ key: string; map: Map<string, Placed>; geo: Geometry }>({ key: '', map: new Map(), geo: { cx: 0, cy: 0, rx: [0, 0], ry: [0, 0] } });
  const raf = useRef(0);
  const drawRef = useRef<(now: number) => void>(() => {});
  const t0 = useRef(performance.now());

  const schedule = () => {
    if (!reduce) return; // the loop is already running
    cancelAnimationFrame(raf.current);
    raf.current = requestAnimationFrame((n) => drawRef.current(n));
  };

  drawRef.current = (now: number) => {
    const canvas = cv.current;
    const { w, h, dpr } = size.current;
    if (!canvas || !w) return;
    const g = canvas.getContext('2d');
    if (!g) return;
    const m = model.current;
    const t = reduce ? 0 : now - t0.current;
    g.setTransform(dpr, 0, 0, dpr, 0, 0);
    g.clearRect(0, 0, w, h);

    // starfield, very faint
    for (const s of stars.current) {
      const tw = reduce ? 1 : 0.8 + 0.2 * Math.sin(t / 2600 + s.p);
      g.globalAlpha = s.a * tw;
      g.fillStyle = C.star;
      g.beginPath();
      g.arc(s.x, s.y, s.r, 0, 7);
      g.fill();
    }
    g.globalAlpha = 1;

    // placement
    const usable = Math.max(w - m.coveredRight, 280);
    const addrs = m.peers.map((p) => p.vpnAddr);
    const key = `${Math.round(w)}x${Math.round(h)}:${Math.round(usable)}:${[...addrs].sort().join(',')}:${[...m.lighthouses].sort().join(',')}`;
    if (placed.current.key !== key) {
      const geo = geometry(h, usable);
      placed.current = { key, map: place(addrs, m.lighthouses, geo), geo };
    }
    const { map: pos, geo } = placed.current;
    const c = { x: geo.cx, y: geo.cy };
    const act = hover.current ?? focus.current;

    // faint rings
    g.strokeStyle = 'rgba(131,144,181,.10)';
    g.lineWidth = 1;
    g.setLineDash([2, 7]);
    for (const r of [0, 1] as const) {
      g.beginPath();
      g.ellipse(c.x, c.y, geo.rx[r], geo.ry[r], 0, 0, Math.PI * 2);
      g.stroke();
    }
    g.setLineDash([]);

    // tunnels
    for (const p of m.peers) {
      const P = pos.get(p.vpnAddr);
      if (!P) continue;
      const on = act === p.vpnAddr || (!act && m.selected === p.vpnAddr);
      const dimmed = act !== null && act !== p.vpnAddr ? 0.45 : 1;
      const relayed = !p.pending && !p.currentRemote && p.relayedThrough.length > 0;
      if (p.pending) {
        g.strokeStyle = 'rgba(131,144,181,.16)';
        g.lineWidth = 1;
        g.setLineDash([1, 7]);
        g.beginPath();
        g.moveTo(c.x, c.y);
        g.lineTo(P.x, P.y);
        g.stroke();
        g.setLineDash([]);
      } else if (relayed) {
        const R = pos.get(p.relayedThrough[0]);
        g.strokeStyle = C.relay;
        g.globalAlpha = (on ? 1 : 0.7) * dimmed;
        g.lineWidth = on ? 2.2 : 1.4;
        g.setLineDash([7, 5]);
        g.lineDashOffset = reduce ? 0 : -t / 90;
        g.beginPath();
        g.moveTo(c.x, c.y);
        if (R) {
          // a curve that passes through the relay host at its midpoint
          g.quadraticCurveTo(2 * R.x - (c.x + P.x) / 2, 2 * R.y - (c.y + P.y) / 2, P.x, P.y);
        } else {
          g.lineTo(P.x, P.y);
        }
        g.stroke();
        g.setLineDash([]);
        g.lineDashOffset = 0;
        g.globalAlpha = 1;
      } else {
        g.strokeStyle = C.flare;
        g.globalAlpha = (on ? 1 : 0.55) * dimmed;
        g.lineWidth = on ? 2.4 : 1.3;
        g.beginPath();
        g.moveTo(c.x, c.y);
        g.lineTo(P.x, P.y);
        g.stroke();
        g.globalAlpha = 1;
        if (!reduce) {
          // one slow packet per tunnel
          const hh = hash(p.vpnAddr);
          const u = ((t / (3600 + (hh % 2400))) + (hh % 997) / 997) % 1;
          g.fillStyle = '#FBCFE8';
          g.globalAlpha = 0.75 * dimmed;
          g.beginPath();
          g.arc(c.x + (P.x - c.x) * u, c.y + (P.y - c.y) * u, 1.7, 0, 7);
          g.fill();
          g.globalAlpha = 1;
        }
      }
    }

    const lighthouseDot = (x: number, y: number, phase: number, r = 5) => {
      const pulse = reduce ? 0.5 : ((t + phase) / 2800) % 1;
      g.strokeStyle = `rgba(253,186,116,${0.5 * (1 - pulse)})`;
      g.lineWidth = 1.5;
      g.beginPath();
      g.arc(x, y, 9 + pulse * 46, 0, 7);
      g.stroke();
      const glow = g.createRadialGradient(x, y, 0, x, y, 30);
      glow.addColorStop(0, 'rgba(253,186,116,.55)');
      glow.addColorStop(1, 'rgba(253,186,116,0)');
      g.fillStyle = glow;
      g.beginPath();
      g.arc(x, y, 30, 0, 7);
      g.fill();
      g.fillStyle = C.ember;
      g.beginPath();
      g.arc(x, y, r, 0, 7);
      g.fill();
    };

    const label = (x: number, y: number, name: string, addr: string, strong: boolean, alpha: number) => {
      g.textAlign = 'center';
      g.textBaseline = 'alphabetic';
      g.globalAlpha = alpha;
      g.font = `600 12.5px ${SANS}`;
      g.fillStyle = strong ? C.ember : '#FFFFFF';
      g.fillText(name, x, y + 24);
      g.font = `400 11px ${MONO}`;
      g.fillStyle = C.dim;
      g.fillText(addr, x, y + 39);
      g.globalAlpha = 1;
    };

    // the target at the centre
    if (m.self.role === 'lighthouse') {
      lighthouseDot(c.x, c.y, 0, 6);
    } else {
      const glow = g.createRadialGradient(c.x, c.y, 0, c.x, c.y, 34);
      glow.addColorStop(0, 'rgba(201,211,242,.28)');
      glow.addColorStop(1, 'rgba(201,211,242,0)');
      g.fillStyle = glow;
      g.beginPath();
      g.arc(c.x, c.y, 34, 0, 7);
      g.fill();
      g.strokeStyle = 'rgba(201,211,242,.55)';
      g.lineWidth = 1.2;
      g.beginPath();
      g.arc(c.x, c.y, 11, 0, 7);
      g.stroke();
      g.fillStyle = C.star;
      g.beginPath();
      g.arc(c.x, c.y, 5.5, 0, 7);
      g.fill();
    }
    label(c.x, c.y, shortName(m.self.name), m.self.vpnAddr, false, 1);

    // peers
    for (const p of m.peers) {
      const P = pos.get(p.vpnAddr);
      if (!P) continue;
      const isLh = m.lighthouses.has(p.vpnAddr);
      const revoked = m.blocked.has(p.fingerprint);
      const isSel = m.selected === p.vpnAddr;
      const isAct = act === p.vpnAddr;
      const dimmed = act !== null && !isAct ? 0.55 : 1;
      g.globalAlpha = dimmed;
      if (isLh) {
        lighthouseDot(P.x, P.y, hash(p.vpnAddr) % 2800, 5);
      } else if (p.pending) {
        g.strokeStyle = C.dim;
        g.lineWidth = 1.3;
        g.setLineDash([3, 3]);
        g.lineDashOffset = reduce ? 0 : -t / 120;
        g.beginPath();
        g.arc(P.x, P.y, 8, 0, 7);
        g.stroke();
        g.setLineDash([]);
        g.lineDashOffset = 0;
        g.fillStyle = 'rgba(201,211,242,.35)';
        g.beginPath();
        g.arc(P.x, P.y, 2.4, 0, 7);
        g.fill();
      } else {
        if (isAct) {
          const glow = g.createRadialGradient(P.x, P.y, 0, P.x, P.y, 26);
          glow.addColorStop(0, 'rgba(244,114,182,.45)');
          glow.addColorStop(1, 'rgba(244,114,182,0)');
          g.fillStyle = glow;
          g.beginPath();
          g.arc(P.x, P.y, 26, 0, 7);
          g.fill();
        }
        g.fillStyle = C.star;
        g.beginPath();
        g.arc(P.x, P.y, isAct ? 5.4 : 4.4, 0, 7);
        g.fill();
      }
      g.globalAlpha = 1;

      if (isSel || focus.current === p.vpnAddr) {
        g.strokeStyle = C.ember;
        g.lineWidth = 2;
        g.beginPath();
        g.arc(P.x, P.y, 13, 0, 7);
        g.stroke();
      }

      // markers: revoked (danger, with a cross) and near expiry (ember, "!")
      if (revoked || isExpiring(p)) {
        const mx = P.x + 10;
        const my = P.y - 10;
        g.lineWidth = 1.6;
        if (revoked) {
          g.fillStyle = C.danger;
          g.beginPath();
          g.arc(mx, my, 5.5, 0, 7);
          g.fill();
          g.strokeStyle = C.night;
          g.beginPath();
          g.moveTo(mx - 2.2, my - 2.2);
          g.lineTo(mx + 2.2, my + 2.2);
          g.moveTo(mx + 2.2, my - 2.2);
          g.lineTo(mx - 2.2, my + 2.2);
          g.stroke();
        } else {
          g.fillStyle = C.night;
          g.strokeStyle = C.ember;
          g.beginPath();
          g.arc(mx, my, 5.5, 0, 7);
          g.fill();
          g.stroke();
          g.fillStyle = C.ember;
          g.font = `600 8px ${SANS}`;
          g.textAlign = 'center';
          g.textBaseline = 'middle';
          g.fillText('!', mx, my + 0.5);
        }
      }

      label(P.x, P.y, shortName(p.name), p.vpnAddr, isSel, p.pending ? 0.6 * dimmed : dimmed);
    }
  };

  // size, stars and the draw loop
  useEffect(() => {
    const el = wrap.current;
    const canvas = cv.current;
    if (!el || !canvas) return;
    const layout = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      const w = el.clientWidth;
      const h = el.clientHeight;
      size.current = { w, h, dpr };
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      const rnd = seeded(7);
      stars.current = Array.from({ length: Math.round((w * h) / 7000) }, () => ({
        x: rnd() * w,
        y: rnd() * h,
        r: rnd() * 1.0 + 0.2,
        a: rnd() * 0.4 + 0.1,
        p: rnd() * 6.28,
      }));
      placed.current.key = '';
      schedule();
    };
    layout();
    const ro = new ResizeObserver(layout);
    ro.observe(el);
    void document.fonts?.ready.then(schedule);
    if (!reduce) {
      const loop = (now: number) => {
        drawRef.current(now);
        raf.current = requestAnimationFrame(loop);
      };
      raf.current = requestAnimationFrame(loop);
    }
    return () => {
      ro.disconnect();
      cancelAnimationFrame(raf.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reduce]);

  // redraw on data changes when animation is off
  useEffect(() => {
    schedule();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [props.peers, props.selected, props.blocked, props.coveredRight, props.self, props.lighthouses]);

  const hit = (clientX: number, clientY: number): string | null => {
    const rect = cv.current?.getBoundingClientRect();
    if (!rect) return null;
    const x = clientX - rect.left;
    const y = clientY - rect.top;
    let best: string | null = null;
    let bestD = 1e9;
    for (const [a, P] of placed.current.map) {
      const d = Math.hypot(P.x - x, P.y - y);
      const inLabel = Math.abs(P.x - x) < 52 && y > P.y + 10 && y < P.y + 44;
      const dd = inLabel ? Math.min(d, 20) : d;
      if (dd < 20 && dd < bestD) {
        best = a;
        bestD = dd;
      }
    }
    return best;
  };

  const sorted = useMemo(() => [...peers].sort((a, b) => a.vpnAddr.localeCompare(b.vpnAddr, undefined, { numeric: true })), [peers]);

  return (
    <div className="mesh" ref={wrap}>
      <canvas
        ref={cv}
        role="img"
        aria-label={summary}
        onPointerMove={(e) => {
          const a = hit(e.clientX, e.clientY);
          if (a !== hover.current) {
            hover.current = a;
            if (cv.current) cv.current.style.cursor = a ? 'pointer' : 'default';
            schedule();
          }
        }}
        onPointerLeave={() => {
          hover.current = null;
          schedule();
        }}
        onClick={(e) => {
          const a = hit(e.clientX, e.clientY);
          onSelect(a && a === selected ? null : a);
        }}
      />
      {/* The same hosts as real buttons, for keyboard and screen reader users. */}
      <ul className="sr-only" aria-label="Hosts on the map">
        {sorted.map((p) => (
          <li key={p.vpnAddr}>
            <button
              type="button"
              onFocus={() => {
                focus.current = p.vpnAddr;
                schedule();
              }}
              onBlur={() => {
                focus.current = null;
                schedule();
              }}
              onClick={() => onSelect(p.vpnAddr)}
            >
              {shortName(p.name)}, {p.vpnAddr}, {p.pending ? 'handshaking' : p.currentRemote ? 'connected directly' : 'relayed'}
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}

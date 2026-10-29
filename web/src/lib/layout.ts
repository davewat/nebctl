// Where each peer sits on the map. Positions come from the peer's vpnAddr
// (a hash gives its angle and ring), so a poll that returns the same hosts
// never moves anything. A small, deterministic pass nudges apart neighbours
// whose labels would overlap; it only changes when the set of hosts does.

export interface Placed {
  x: number;
  y: number;
  ring: 0 | 1;
}

export function hash(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

export function seeded(seed: number): () => number {
  let s = seed % 2147483647;
  if (s <= 0) s += 2147483646;
  return () => (s = (s * 16807) % 2147483647) / 2147483647;
}

export interface Geometry {
  cx: number;
  cy: number;
  rx: [number, number];
  ry: [number, number];
}

export function geometry(h: number, usableW: number): Geometry {
  const cx = usableW / 2;
  const cy = h / 2 + 8;
  const maxRx = Math.max(usableW / 2 - 78, 120);
  const maxRy = Math.max(h / 2 - 62, 100);
  return { cx, cy, rx: [maxRx * 0.5, maxRx * 0.94], ry: [maxRy * 0.5, maxRy * 0.94] };
}

export function place(addrs: string[], lighthouses: Set<string>, g: Geometry): Map<string, Placed> {
  const sorted = [...addrs].sort();
  const items = sorted.map((a) => {
    const h = hash(a);
    const ring: 0 | 1 = lighthouses.has(a) ? 0 : ((h >>> 11) & 1) as 0 | 1;
    return { a, ring, angle: ((h % 3600) / 3600) * Math.PI * 2 };
  });
  const pos = (i: { ring: 0 | 1; angle: number }) => ({
    x: g.cx + Math.cos(i.angle) * g.rx[i.ring],
    y: g.cy + Math.sin(i.angle) * g.ry[i.ring],
  });
  // Labels are about 104px wide and 40px tall below the dot.
  for (let pass = 0; pass < 40; pass++) {
    let moved = false;
    // keep clear of the target's own label at the centre
    for (const it of items) {
      const p = pos(it);
      if (Math.abs(p.x - g.cx) < 104 && p.y > g.cy - 18 && p.y < g.cy + 50) {
        const dir = Math.sin(it.angle) > 0 ? (Math.cos(it.angle) >= 0 ? -1 : 1) : Math.cos(it.angle) >= 0 ? 1 : -1;
        it.angle += dir * 0.05;
        moved = true;
      }
    }
    for (let i = 0; i < items.length; i++) {
      for (let j = i + 1; j < items.length; j++) {
        const a = pos(items[i]);
        const b = pos(items[j]);
        if (Math.abs(a.x - b.x) < 108 && Math.abs(a.y - b.y) < 46) {
          // push along the ring: positive angle direction for the later one
          const dir = items[j].angle >= items[i].angle ? 1 : -1;
          items[i].angle -= dir * 0.035;
          items[j].angle += dir * 0.035;
          moved = true;
        }
      }
    }
    if (!moved) break;
  }
  const out = new Map<string, Placed>();
  for (const i of items) out.set(i.a, { ...pos(i), ring: i.ring });
  return out;
}

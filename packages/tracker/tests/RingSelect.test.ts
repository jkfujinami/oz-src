import { describe, it, expect } from 'vitest';
import { selectJoinPeers, type RingCandidate } from '../src/RingSelect';

let seed = 12345;
const rnd = (): number => {
  seed = (seed * 1103515245 + 12345) & 0x7fffffff;
  return seed / 0x80000000;
};
const randomInt = (n: number): number => Math.floor(rnd() * n);

function makeNodes(n: number): RingCandidate<number>[] {
  return Array.from({ length: n }, (_, i) => ({ item: i, position: rnd(), joinedAt: i }));
}

const cw = (from: number, to: number): number => {
  const d = to - from;
  return d < 0 ? d + 1 : d;
};

describe('RingSelect', () => {
  it('k が小さい (< 6) ときは純ランダムで k 件', () => {
    const nodes = makeNodes(50);
    const out = selectJoinPeers(0.5, nodes, 2, randomInt);
    expect(out).toHaveLength(2);
  });

  it('候補が k 以下なら全員を返す', () => {
    const nodes = makeNodes(5);
    expect(selectJoinPeers(0.5, nodes, 8, randomInt).sort()).toEqual([0, 1, 2, 3, 4]);
  });

  it('時計回り最近接 2・反時計回り最近接 2・新着 2 を必ず含み、重複なしで k 件', () => {
    const nodes = makeNodes(100);
    const self = 0.37;
    const out = selectJoinPeers(self, nodes, 8, randomInt);
    expect(out).toHaveLength(8);
    expect(new Set(out).size).toBe(8);

    const byCw = [...nodes].sort((a, b) => cw(self, a.position) - cw(self, b.position)).slice(0, 2);
    const byCcw = [...nodes].sort((a, b) => cw(a.position, self) - cw(b.position, self)).slice(0, 2);
    for (const c of [...byCw, ...byCcw]) expect(out).toContain(c.item);

    const recent = [...nodes].sort((a, b) => b.joinedAt - a.joinedAt);
    const ring = new Set([...byCw, ...byCcw].map((c) => c.item));
    const recentPicked = recent.filter((c) => !ring.has(c.item)).slice(0, 2);
    for (const c of recentPicked) expect(out).toContain(c.item);
  });

  it('対称性: v が u の時計回り最近接 2 なら、u は v の反時計回り最近接 2 に入る', () => {
    const nodes = makeNodes(200);
    for (const u of nodes) {
      const others = nodes.filter((x) => x !== u);
      const cw2 = [...others].sort((a, b) => cw(u.position, a.position) - cw(u.position, b.position)).slice(0, 2);
      for (const v of cw2) {
        const vOthers = nodes.filter((x) => x !== v);
        const ccw2 = [...vOthers].sort((a, b) => cw(a.position, v.position) - cw(b.position, v.position)).slice(0, 2);
        expect(ccw2).toContain(u);
      }
    }
  });
});

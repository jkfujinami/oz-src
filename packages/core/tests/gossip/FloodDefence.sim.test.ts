import { describe, it, expect } from 'vitest';
import { EffortAdvisor, packetCells, packetEffortPerCell } from '../../src/network/gossip/EffortAdvisor';
import { RelayQueue, RELAY_QUEUE } from '../../src/network/gossip/RelayQueue';
import { effortFor, POW_POLICY } from '../../src/crypto/PowPolicy';
import type { GossipPacket } from '../../src/types';

/**
 * A3 シミュレーション: 低 effort の洪水 (予算の 10 倍) の中で、推奨 effort に従った正直な投稿が届くか。
 *
 * 仮想時間のイベントループに、本物の EffortAdvisor / RelayQueue を載せる (PoW と暗号は省く。
 * 優先度に効くのは effort_exp とペイロード長だけ)。比較対象は同じ予算の FIFO (先着順・満杯なら末尾を捨てる)。
 * ★ 「キュー無し」を無制限に即時中継とすると何も混まないので比較にならない。現実には回線と CPU が有限で、
 *   溢れた分は先着順に捨てられる。それを FIFO で表している。
 */

const NODES = 40;
const DEGREE = 5;
const HOP_MS = 50;
const FLOOD_PER_SEC = 200;            // CAPACITY_CELLS_PER_SEC (20) の 10 倍
const FLOOD_SECONDS = 90;
const HONEST_PER_SEC = 1;
const WARMUP_S = 15;                  // 推奨 effort が上がり始めるまで (この間の投稿は報告のみ)

class Rng {
  constructor(private s: number) {}
  next() { this.s = (this.s * 1664525 + 1013904223) >>> 0; return this.s / 0x1_0000_0000; }
  int(n: number) { return Math.floor(this.next() * n); }
}

interface Ev { at: number; seq: number; fn: () => void; off?: boolean }
class Sim {
  now = 0;
  private heap: Ev[] = [];
  private seq = 0;
  at(ms: number, fn: () => void): Ev {
    const e: Ev = { at: this.now + ms, seq: this.seq++, fn };
    const h = this.heap; h.push(e);
    let i = h.length - 1;
    while (i > 0) { const p = (i - 1) >> 1; if (!this.lt(h[i], h[p])) break; [h[i], h[p]] = [h[p], h[i]]; i = p; }
    return e;
  }
  private lt(a: Ev, b: Ev) { return a.at !== b.at ? a.at < b.at : a.seq < b.seq; }
  run(until: number) {
    const h = this.heap;
    while (h.length && h[0].at <= until) {
      const top = h[0], last = h.pop()!;
      if (h.length) {
        h[0] = last; let i = 0;
        for (;;) {
          const l = 2 * i + 1, r = l + 1; let m = i;
          if (l < h.length && this.lt(h[l], h[m])) m = l;
          if (r < h.length && this.lt(h[r], h[m])) m = r;
          if (m === i) break; [h[i], h[m]] = [h[m], h[i]]; i = m;
        }
      }
      this.now = top.at;
      if (!top.off) top.fn();
    }
    this.now = until;
  }
}

/** 比較用: 同じ予算の FIFO (満杯なら末尾を捨てる) */
class FifoQueue {
  private q: Array<[GossipPacket, any]> = [];
  private tokens: number = RELAY_QUEUE.BURST_CELLS;
  private last = 0;
  private timer: Ev | null = null;
  constructor(private sim: Sim, private send: (p: GossipPacket, ex: any) => void) {}
  offer(p: GossipPacket, ex: any) {
    this.refill();
    if (this.q.length === 0 && this.tokens >= 1) { this.tokens -= 1; this.send(p, ex); return; }
    if (this.q.length >= RELAY_QUEUE.MAX_PACKETS) return;
    this.q.push([p, ex]);
    this.drain();
  }
  private refill() {
    this.tokens = Math.min(RELAY_QUEUE.BURST_CELLS, this.tokens + ((this.sim.now - this.last) / 1000) * RELAY_QUEUE.RELAY_CELLS_PER_SEC);
    this.last = this.sim.now;
  }
  private drain() {
    this.refill();
    while (this.q.length && this.tokens >= 1) { this.tokens -= 1; const [p, ex] = this.q.shift()!; this.send(p, ex); }
    if (this.timer) this.timer.off = true;
    this.timer = this.q.length
      ? this.sim.at(Math.ceil(((1 - this.tokens) / RELAY_QUEUE.RELAY_CELLS_PER_SEC) * 1000) || 1, () => { this.timer = null; this.drain(); })
      : null;
  }
}

let pid = 0;
const makePacket = (effortExp: number): GossipPacket => ({
  packet_id: (pid++).toString(16).padStart(32, '0'),
  timestamp: 0, tag: 0, age: 0, effort_exp: effortExp, pow_nonce: 0, pow_solution: new Uint8Array(16),
  payload: new Uint8Array(200), // 1 セル
});

interface Result {
  honest: number; ratioAll: number; ratioSteady: number;
  latMeanMs: number; latP95Ms: number; maxHonestExp: number; suggestedEnd: number;
}

function simulate(mode: 'priority' | 'fifo', withFlood: boolean, followAdvice = true, seed = 7): Result {
  const rng = new Rng(seed);
  const sim = new Sim();
  // 全ノードが 2 本の環 + 乱択でつながる (連結を保証)
  const adj: Set<number>[] = Array.from({ length: NODES }, () => new Set());
  const link = (a: number, b: number) => { if (a !== b) { adj[a].add(b); adj[b].add(a); } };
  for (let i = 0; i < NODES; i++) link(i, (i + 1) % NODES);
  while (adj.some(s => s.size < DEGREE)) link(rng.int(NODES), rng.int(NODES));

  const seen: Set<string>[] = Array.from({ length: NODES }, () => new Set());
  const advisors = Array.from({ length: NODES }, () => new EffortAdvisor({ now: () => sim.now }));
  const honestIds = new Map<string, { t0: number; exp: number }>();
  const arrivals = new Map<string, number[]>(); // honest id → 各ノードの到着遅延

  const receive = (node: number, from: number | null, p: GossipPacket) => {
    if (seen[node].has(p.packet_id)) return;
    seen[node].add(p.packet_id);
    advisors[node].observe(p, sim.now);
    const h = honestIds.get(p.packet_id);
    if (h) arrivals.get(p.packet_id)!.push(sim.now - h.t0);
    queues[node].offer(p, from);
  };
  const transmit = (node: number) => (p: GossipPacket, ex: any) => {
    for (const nb of adj[node]) if (nb !== ex) sim.at(HOP_MS, () => receive(nb, node, p));
  };
  const queues: Array<{ offer(p: GossipPacket, ex: any): void }> = Array.from({ length: NODES }, (_, i) =>
    mode === 'priority'
      ? new RelayQueue(transmit(i), { now: () => sim.now, setTimer: (fn, ms) => sim.at(ms, fn), clearTimer: h => { (h as Ev).off = true; } })
      : new FifoQueue(sim, transmit(i)),
  );

  let maxHonestExp = 0;
  // 正直な投稿: 毎秒、ランダムなノードが自分の推奨 effort に従って投稿する
  for (let s = 0; s < FLOOD_SECONDS; s++) {
    for (let k = 0; k < HONEST_PER_SEC; k++) {
      sim.at(s * 1000 + rng.int(1000), () => {
        const node = rng.int(NODES);
        const cells = 1;
        const { exp } = effortFor(POW_POLICY.HEADER_BYTES + 200, followAdvice ? advisors[node].suggestedFor(cells, sim.now) : undefined);
        maxHonestExp = Math.max(maxHonestExp, exp);
        const p = makePacket(exp);
        honestIds.set(p.packet_id, { t0: sim.now, exp });
        arrivals.set(p.packet_id, []);
        receive(node, null, p);
      });
    }
  }
  // 攻撃者: 最低 effort (e=0) のパケットを、毎秒 200 セル、ランダムな 3 ノードの入口へ注入
  if (withFlood) {
    const entries = [rng.int(NODES), rng.int(NODES), rng.int(NODES)];
    for (let ms = 0; ms < FLOOD_SECONDS * 1000; ms += 5) {
      sim.at(ms, () => { const p = makePacket(0); receive(entries[rng.int(3)], null, p); });
    }
  }
  sim.run(FLOOD_SECONDS * 1000 + 60_000);

  let delivered = 0, total = 0, dSteady = 0, tSteady = 0;
  const lat: number[] = [];
  for (const [id, h] of honestIds) {
    const got = arrivals.get(id)!.length;
    delivered += got; total += NODES;
    if (h.t0 >= WARMUP_S * 1000) { dSteady += got; tSteady += NODES; }
    lat.push(...arrivals.get(id)!);
  }
  lat.sort((a, b) => a - b);
  return {
    honest: honestIds.size,
    ratioAll: delivered / total,
    ratioSteady: dSteady / tSteady,
    latMeanMs: lat.reduce((a, b) => a + b, 0) / Math.max(1, lat.length),
    latP95Ms: lat[Math.floor(lat.length * 0.95)] ?? 0,
    maxHonestExp,
    suggestedEnd: advisors[0].suggestedPerCell(FLOOD_SECONDS * 1000),
  };
}

describe('A3 シミュレーション: 予算の 10 倍の低 effort 洪水と正直な投稿', () => {
  const fmt = (r: Result) =>
    `honest=${r.honest} delivery(all)=${(r.ratioAll * 100).toFixed(1)}% delivery(t>=${WARMUP_S}s)=${(r.ratioSteady * 100).toFixed(1)}% ` +
    `latency mean=${r.latMeanMs.toFixed(0)}ms p95=${r.latP95Ms.toFixed(0)}ms maxExp=${r.maxHonestExp} suggestedPerCell@end=${r.suggestedEnd.toFixed(2)}`;

  it('キューあり / FIFO / 洪水なし の比較', () => {
    const quiet = simulate('priority', false);
    const withQ = simulate('priority', true);
    const fifo = simulate('fifo', true);
    const ignoring = simulate('priority', true, false);
    // eslint-disable-next-line no-console
    console.log(`[A3 sim] quiet            : ${fmt(quiet)}\n[A3 sim] flood + priority : ${fmt(withQ)}\n[A3 sim] flood + FIFO     : ${fmt(fifo)}\n[A3 sim] flood + priority, honest ignore advice: ${fmt(ignoring)}`);

    // 洪水が無ければ全員に届き、推奨は最小のまま (平常時は PoW も遅延も増えない)
    expect(quiet.ratioAll).toBeGreaterThanOrEqual(0.99);
    expect(quiet.maxHonestExp).toBe(0);
    // 優先度キュー + 推奨 effort: 洪水の中でも 95% 以上が届く
    expect(withQ.ratioAll).toBeGreaterThanOrEqual(0.95);
    expect(withQ.ratioSteady).toBeGreaterThanOrEqual(0.95);
    // キューと推奨の効果: 正直な投稿は推奨で攻撃者 (e=0) より上に出ている
    expect(withQ.maxHonestExp).toBeGreaterThan(0);
    // FIFO は同じ洪水に負ける
    expect(withQ.ratioAll).toBeGreaterThan(fifo.ratioAll);
    // 推奨に従わない (最低 effort のまま) 投稿は、キューがあっても洪水と同列で負ける
    expect(withQ.ratioAll).toBeGreaterThan(ignoring.ratioAll);
  }, 120_000);
});

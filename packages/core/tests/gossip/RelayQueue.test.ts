import { describe, it, expect } from 'vitest';
import { RelayQueue } from '../../src/network/gossip/RelayQueue';
import { POW_POLICY } from '../../src/crypto/PowPolicy';
import type { GossipPacket } from '../../src/types';

let n = 0;
const pkt = (effortExp: number, cells = 1, bytes?: number): GossipPacket => ({
  packet_id: String(n++).padStart(32, '0'),
  timestamp: 0, tag: 0, age: 0, effort_exp: effortExp, pow_nonce: 0, pow_solution: new Uint8Array(16),
  payload: new Uint8Array(bytes ?? cells * POW_POLICY.EFFORT_CELL_BYTES - POW_POLICY.HEADER_BYTES),
});

/** 手動の時計とタイマー */
function clock() {
  let now = 0;
  const timers: Array<{ at: number; fn: () => void; id: number; off?: boolean }> = [];
  let id = 0;
  return {
    now: () => now,
    setTimer: (fn: () => void, ms: number) => { const t = { at: now + ms, fn, id: id++ }; timers.push(t); return t; },
    clearTimer: (h: any) => { h.off = true; },
    advance(ms: number) {
      const end = now + ms;
      for (;;) {
        const due = timers.filter(t => !t.off && t.at <= end).sort((a, b) => a.at - b.at)[0];
        if (!due) break;
        now = due.at; due.off = true; due.fn();
      }
      now = end;
    },
  };
}

function make(opts: any = {}) {
  const c = clock();
  const sent: GossipPacket[] = [];
  const q = new RelayQueue(p => sent.push(p), { now: c.now, setTimer: c.setTimer, clearTimer: c.clearTimer, ...opts });
  return { c, q, sent };
}

describe('RelayQueue', () => {
  it('予算内 (バースト) は同じ呼び出しの中で即座に流れる', () => {
    const { q, sent } = make({ cellsPerSec: 40, burstCells: 200 });
    for (let i = 0; i < 200; i++) q.offer(pkt(0));
    expect(sent.length).toBe(200);
    expect(q.size).toBe(0);
  });

  it('予算を超えたら待たされ、予算が溜まるにつれて流れる', () => {
    const { q, sent, c } = make({ cellsPerSec: 40, burstCells: 10 });
    for (let i = 0; i < 30; i++) q.offer(pkt(0));
    expect(sent.length).toBe(10);
    expect(q.size).toBe(20);
    c.advance(250); // 10 セル溜まる
    expect(sent.length).toBe(20);
    c.advance(1000);
    expect(sent.length).toBe(30);
    expect(q.size).toBe(0);
  });

  it('待っている間は effort の高い順 (同じなら古い順) に流れる', () => {
    const { q, sent, c } = make({ cellsPerSec: 10, burstCells: 1 });
    q.offer(pkt(0)); // 即時
    const lowOld = pkt(0), mid = pkt(8), high = pkt(16), lowNew = pkt(0), mid2 = pkt(8);
    [lowOld, mid, high, lowNew, mid2].forEach(p => q.offer(p));
    c.advance(10_000);
    expect(sent.slice(1)).toEqual([high, mid, mid2, lowOld, lowNew]);
  });

  it('優先度は 1 セルあたり: 3 セルの投稿は effort が 3 倍必要', () => {
    const { q, sent, c } = make({ cellsPerSec: 10, burstCells: 3 });
    q.offer(pkt(0, 3)); // バーストを使い切る
    const threeCells = pkt(7, 3);   // effort 3 → e_c 1
    const oneCell = pkt(4, 1);      // effort 2 → e_c 2
    q.offer(threeCells); q.offer(oneCell);
    c.advance(10_000);
    expect(sent.slice(1)).toEqual([oneCell, threeCells]);
  });

  it('待ち行列があるときは、予算が余っていても割り込ませない', () => {
    const { q, sent, c } = make({ cellsPerSec: 10, burstCells: 1 });
    q.offer(pkt(0));
    const low = pkt(0), high = pkt(12);
    q.offer(low);
    c.advance(50); // 0.5 セルしか溜まっていない
    q.offer(high);
    c.advance(5000);
    expect(sent.slice(1)).toEqual([high, low]);
  });

  it('件数が満杯なら最低 e_c を捨てる。低いものは入れてもらえない', () => {
    const { q, sent, c } = make({ cellsPerSec: 10, burstCells: 1, maxPackets: 3 });
    q.offer(pkt(0)); // 即時
    const a = pkt(4), b = pkt(8), d = pkt(12);
    q.offer(a); q.offer(b); q.offer(d);
    expect(q.size).toBe(3);
    const e = pkt(16);
    q.offer(e); // a が落ちる
    expect(q.size).toBe(3);
    expect(q.dropped).toBe(1);
    q.offer(pkt(0)); // 最低より低い → 自分が落ちる
    expect(q.dropped).toBe(2);
    expect(q.size).toBe(3);
    c.advance(10_000);
    expect(sent.slice(1)).toEqual([e, d, b]);
  });

  it('同じ e_c で満杯なら新しい方を捨てる (先に待った方を優先)', () => {
    const { q, sent, c } = make({ cellsPerSec: 10, burstCells: 1, maxPackets: 2 });
    q.offer(pkt(0));
    const a = pkt(4), b = pkt(4), d = pkt(4);
    q.offer(a); q.offer(b); q.offer(d);
    c.advance(10_000);
    expect(sent.slice(1)).toEqual([a, b]);
  });

  it('メモリが有界: バイト数の上限を超えない', () => {
    const { q } = make({ cellsPerSec: 1, burstCells: 1, maxPackets: 100_000, maxBytes: 50_000 });
    for (let i = 0; i < 5000; i++) q.offer(pkt(i % 40, 1, 500));
    expect(q.queuedBytes).toBeLessThanOrEqual(50_000);
    expect(q.size).toBeLessThanOrEqual(50_000 / 564);
  });

  it('洪水の中でも件数が有界で、内部のヒープも膨らまない', () => {
    const { q, c } = make({ cellsPerSec: 40, burstCells: 10, maxPackets: 500 });
    for (let s = 0; s < 120; s++) {
      for (let i = 0; i < 200; i++) q.offer(pkt(i % 7));
      c.advance(1000);
    }
    expect(q.size).toBeLessThanOrEqual(500);
    expect((q as any).best.length + (q as any).worst.length).toBeLessThanOrEqual(4 * 500 + 128 + 2);
  });

  it('待ちすぎたものは捨てる', () => {
    const { q, sent, c } = make({ cellsPerSec: 1, burstCells: 1, maxWaitMs: 5000 });
    q.offer(pkt(0));
    for (let i = 0; i < 10; i++) q.offer(pkt(0));
    c.advance(60_000);
    expect(sent.length).toBeLessThan(11);
    expect(q.size).toBe(0);
    expect(q.dropped).toBeGreaterThan(0);
  });

  it('exclude をそのまま send に渡す / destroy 後は何もしない', () => {
    const c = clock();
    const got: Array<string | null> = [];
    const q = new RelayQueue((_p, ex) => got.push(ex), { now: c.now, setTimer: c.setTimer, clearTimer: c.clearTimer });
    q.offer(pkt(0), 'peerA');
    q.offer(pkt(0));
    expect(got).toEqual(['peerA', null]);
    q.destroy();
    q.offer(pkt(0));
    expect(got.length).toBe(2);
  });
});

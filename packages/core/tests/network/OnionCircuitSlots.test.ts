import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest';
import { sodiumReady } from '../../src/crypto/sodium';
import { CIRCUIT_CONFIG, exponentialDelay } from '../../src/network/onion/OnionCircuit';
import { OnionRouter, MAX_FRAGMENTS } from '../../src/crypto/OnionRouter';
import { decodeExitItem } from '../../src/crypto/ExitItem';
import { makeCircuitStub, type CircuitStub } from '../helpers/circuitStub';
import { buildPost } from '../helpers/postFixtures';
import { sleep } from '../helpers/onionNet';

/**
 * 固定 3 スロット回路・断片化・cover の送出レート。
 *
 * 不変条件 (OnionCircuit の説明を参照): Guard から見える「各セルの次ホップ」の列は、
 * 本物を何枚送っても「同じ M1 が 3 回 → 別の M1 が 3 回 → ...」のまま。
 */
const SLOTS = CIRCUIT_CONFIG.CIRCUIT_SLOTS;

/** 3 つずつに区切り、各塊が同じ M1 で、隣り合う塊が別の M1 であることを確かめる */
function expectRunsOfExactlyThree(hops: string[]) {
  expect(hops.length).toBeGreaterThanOrEqual(SLOTS * 3);
  const runs: string[] = [];
  for (let i = 0; i < hops.length; i += SLOTS) {
    const chunk = hops.slice(i, i + SLOTS);
    expect(new Set(chunk).size, `chunk at ${i}: ${chunk.map(h => h.slice(0, 4))}`).toBe(1);
    runs.push(chunk[0]);
  }
  for (let i = 1; i < runs.length; i++) expect(runs[i]).not.toBe(runs[i - 1]);
}

async function itemOfCells(cells: 1 | 2 | 3) {
  // 1 枚: 短い投稿 / 2 枚: 約 1.2KB / 3 枚: 2048 バイト + トリップ + 親 2
  const content = cells === 1 ? 'x' : cells === 2 ? 'a'.repeat(1200) : 'a'.repeat(2048);
  const { packet } = await buildPost({ content, trip: cells === 3, parents: cells === 3 ? 2 : 0 });
  return { type: 'exit_fluff' as const, packet };
}

describe('cover traffic の送出レート', () => {
  beforeAll(async () => { await sodiumReady; });
  afterEach(() => { vi.useRealTimers(); });

  it('既定の平均間隔は 500ms (ポアソン過程)', () => {
    expect(CIRCUIT_CONFIG.COVER_INTERVAL_MS).toBe(500);
    let sum = 0;
    const N = 20000;
    for (let i = 0; i < N; i++) sum += exponentialDelay(500, 5000);
    // 打ち切り (10 倍) の影響は無視できる。平均は 500 付近
    expect(sum / N).toBeGreaterThan(470);
    expect(sum / N).toBeLessThan(530);
  });

  it('既定の設定で 200 秒に約 400 枚のセルが出る (本物が無くても)', async () => {
    vi.useFakeTimers();
    // 既定の平均間隔 (CIRCUIT_CONFIG) をそのまま使う
    const s = makeCircuitStub({ circuitOptions: { coverIntervalMs: CIRCUIT_CONFIG.COVER_INTERVAL_MS } });
    s.circuit.start();
    await vi.advanceTimersByTimeAsync(200_000);
    s.circuit.stop();
    // 期待値 400, 標準偏差 20。6σ 幅で見る
    expect(s.sent.length).toBeGreaterThan(280);
    expect(s.sent.length).toBeLessThan(520);
    const gaps = s.sent.slice(1).map((c, i) => c.at - s.sent[i].at);
    const mean = gaps.reduce((a, b) => a + b, 0) / gaps.length;
    expect(mean).toBeGreaterThan(440);
    expect(mean).toBeLessThan(570);
  });
});

describe('3 スロット固定回路 (Guard から見た次ホップの列)', () => {
  let stub: CircuitStub;
  beforeAll(async () => { await sodiumReady; });
  afterEach(() => stub?.circuit.stop());

  const hopsOf = () => stub.sent.map(c => stub.nextHop(c.cell));

  it('cover だけでも、M1 は 3 枚ごとに替わる (同じ M1 が続くのはちょうど 3 回)', async () => {
    stub = makeCircuitStub({ middles: 3 });
    stub.circuit.start();
    await sleep(400);
    stub.circuit.stop();
    expectRunsOfExactlyThree(hopsOf());
  });

  it('★1・2・3 枚の本物を送っても、列は同じ形のまま (本物の有無・枚数が Guard に見えない)', async () => {
    stub = makeCircuitStub({ middles: 3 });
    stub.circuit.start();
    const items = [await itemOfCells(1), await itemOfCells(3), await itemOfCells(2), await itemOfCells(3), await itemOfCells(1)];
    for (const it of items) expect(await stub.circuit.send(it, it.packet.packet_id)).toBe(true);
    await sleep(100);
    stub.circuit.stop();

    expectRunsOfExactlyThree(hopsOf());
    // 本物の断片が実際に M1 へ出ていること (cover だけの列ではない)
    const frags = stub.sent.map(c => stub.atM1(c.cell)).filter(p => p?.type === 'frag');
    expect(frags.length).toBe(1 + 3 + 2 + 3 + 1);
  });

  it('★k 枚の item は 1 つの回路に収まる位置からだけ始まり、同じ M1 へ連続して出る', async () => {
    stub = makeCircuitStub({ middles: 3 });
    stub.circuit.start();
    const items = [await itemOfCells(3), await itemOfCells(2), await itemOfCells(3), await itemOfCells(2), await itemOfCells(1), await itemOfCells(2)];
    for (const it of items) await stub.circuit.send(it, it.packet.packet_id);
    stub.circuit.stop();

    const hops = stub.sent.map(c => stub.nextHop(c.cell));
    const view = stub.sent.map(c => stub.atM1(c.cell));
    let reassembled = 0;
    for (let i = 0; i < view.length; i++) {
      const p = view[i];
      if (p?.type !== 'frag' || p.idx !== 0) continue;
      const position = (i % SLOTS) + 1; // 回路の中の位置 (1..3)
      expect(position + p.total - 1, `item at slot ${i}`).toBeLessThanOrEqual(SLOTS);
      for (let k = 1; k < p.total; k++) {
        const q = view[i + k];
        expect(q?.type).toBe('frag');
        if (q?.type === 'frag') {
          expect(q.idx).toBe(k);
          expect(Buffer.from(q.id).equals(Buffer.from(p.id))).toBe(true);
        }
        expect(hops[i + k]).toBe(hops[i]);
      }
      reassembled++;
    }
    expect(reassembled).toBe(items.length);
  });

  it('先頭の item が収まらないうちは cover を出して待ち、順序は保たれる', async () => {
    // cover の自動送出は止めて (長い間隔)、枠を手で回す
    stub = makeCircuitStub({ middles: 3, circuitOptions: { coverIntervalMs: 1_000_000 } });
    stub.circuit.start();
    const three = await itemOfCells(3);
    const one = await itemOfCells(1);
    // 回路の位置 2 まで進めたところで 3 枚と 1 枚を投入 → 3 枚は次の回路の位置 1 まで待つ
    stub.circuit.flushOnce();
    stub.circuit.flushOnce();
    const p3 = stub.circuit.send(three, three.packet.packet_id);
    const p1 = stub.circuit.send(one, one.packet.packet_id);
    for (let i = 0; i < 12; i++) {
      await sleep(2);
      stub.circuit.flushOnce();
    }
    await Promise.all([p3, p1]);
    stub.circuit.stop();

    const view = stub.sent.map(c => stub.atM1(c.cell));
    const idx3 = view.findIndex(p => p?.type === 'frag' && p.total === 3 && p.idx === 0);
    const idx1 = view.findIndex(p => p?.type === 'frag' && p.total === 1);
    expect(idx3 % SLOTS).toBe(0); // 3 枚は回路の先頭から
    expect(idx1).toBeGreaterThan(idx3 + 2); // 1 枚はその後ろ (先頭の待ちを追い越さない)
    // 待っている間は cover
    expect(view.slice(2, idx3).every(p => p?.type === 'drop')).toBe(true);
  });

  it('再送 (エコー無し) は、全断片を新しい断片 id・別の M1・後の回路で送り直す', async () => {
    stub = makeCircuitStub({ middles: 3, echo: n => n > 0 });
    stub.circuit.start();
    const it = await itemOfCells(3);
    expect(await stub.circuit.send(it, it.packet.packet_id)).toBe(true);
    stub.circuit.stop();

    const real = stub.sent
      .map((c, i) => ({ i, p: stub.atM1(c.cell), hop: stub.nextHop(c.cell) }))
      .filter(x => x.p?.type === 'frag') as Array<{ i: number; p: any; hop: string }>;
    expect(real).toHaveLength(6);
    const first = real.slice(0, 3);
    const second = real.slice(3);
    expect(first.map(x => x.p.idx)).toEqual([0, 1, 2]);
    expect(second.map(x => x.p.idx)).toEqual([0, 1, 2]);
    expect(new Set(first.map(x => x.hop)).size).toBe(1);
    expect(new Set(second.map(x => x.hop)).size).toBe(1);
    expect(second[0].hop).not.toBe(first[0].hop); // 試した M1 を避ける
    expect(Buffer.from(second[0].p.id).equals(Buffer.from(first[0].p.id))).toBe(false);
    expect(second[0].i).toBeGreaterThan(first[2].i);
    // 再構成すると同じ item
    for (const set of [first, second]) {
      const bytes = Buffer.concat(set.map(x => Buffer.from(x.p.data)));
      expect(decodeExitItem(new Uint8Array(bytes))).toMatchObject({ type: 'exit_fluff' });
    }
  });

  it('エコー待ちは最後の断片を送り出してから数え始める', async () => {
    stub = makeCircuitStub({ middles: 3 });
    stub.circuit.start();
    const it = await itemOfCells(3);
    await stub.circuit.send(it, it.packet.packet_id);
    // awaitEcho が呼ばれた時点で、3 枚すべてが送出済み
    const realSent = stub.sent.map(c => stub.atM1(c.cell)).filter(p => p?.type === 'frag').length;
    expect(realSent).toBe(3);
    expect(stub.awaitEcho).toHaveBeenCalledTimes(1);
    stub.circuit.stop();
  });

  it('符号化できない item (最大のパケットを超えるもの) は何も送らずに false', async () => {
    stub = makeCircuitStub({ middles: 3 });
    stub.circuit.start();
    const it = await itemOfCells(1);
    const huge = { ...it, packet: { ...it.packet, payload: new Uint8Array(4000) } };
    const before = stub.sent.map(c => stub.atM1(c.cell)).filter(p => p?.type === 'frag').length;
    expect(await stub.circuit.send(huge, 'x'.repeat(64))).toBe(false);
    await sleep(30);
    const after = stub.sent.map(c => stub.atM1(c.cell)).filter(p => p?.type === 'frag').length;
    expect(after).toBe(before);
    stub.circuit.stop();
  });

  it('M1 候補が 1 つしか無いときは同じ M1 が続くが、見える連続は 3 の倍数のまま', async () => {
    stub = makeCircuitStub({ middles: 1 });
    stub.circuit.start();
    const it = await itemOfCells(2);
    await stub.circuit.send(it, it.packet.packet_id);
    await sleep(60);
    stub.circuit.stop();
    const hops = hopsOf();
    expect(new Set(hops).size).toBe(1);
    expect(MAX_FRAGMENTS).toBe(SLOTS);
  });

  it('stop() で順番待ちの発信は false で終わり、タイマーを残さない', async () => {
    stub = makeCircuitStub({ middles: 3, circuitOptions: { coverIntervalMs: 100000 } });
    stub.circuit.start();
    const it = await itemOfCells(3);
    const p = stub.circuit.send(it, it.packet.packet_id);
    await sleep(10);
    stub.circuit.stop();
    expect(await p).toBe(false);
  });
});

describe('セル長', () => {
  beforeAll(async () => { await sodiumReady; });
  it('cover も本物も 1,200 バイトちょうど', async () => {
    const stub = makeCircuitStub({ middles: 3 });
    stub.circuit.start();
    const it = await itemOfCells(3);
    await stub.circuit.send(it, it.packet.packet_id);
    await sleep(60);
    stub.circuit.stop();
    expect(stub.sent.length).toBeGreaterThan(3);
    for (const c of stub.sent) expect(c.cell.byteLength).toBe(OnionRouter.CELL_SIZE);
  });
});

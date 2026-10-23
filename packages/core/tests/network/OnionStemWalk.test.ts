import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest';
import sodium, { sodiumReady } from '../../src/crypto/sodium';
import { WireType } from '../../src/network/wire/WireTypes';
import { WireCodec } from '../../src/network/wire/WireCodec';
import { CIRCUIT_CONFIG } from '../../src/network/onion/OnionCircuit';
import { makeCheapPacket } from '../helpers/cheapPow';
import type { GuardPolicy } from '../../src/trust/GuardManager';
import type { GossipPacket } from '../../src/types';
import {
  createSimNode, link, startAll, stopAll, sleep, makePacket, type SimNode,
} from '../helpers/onionNet';

/**
 * Stem の歩き (M1 → W1 → ... → Fluff) の規則を検証する。
 *
 *   author --onion--> Guard --onion--> M1 --stem--> W1 --stem--> ... --> F が flood
 *
 * - M1 は本物を絶対に Fluff せず、cover は M1 で消える
 * - walker は確率 STEM_FLUFF_PROBABILITY で Fluff し、外れたら直前の相手以外の隣人へ渡す
 * - ループ (再着) は普通の 1 歩として扱う / flood 済みは捨てる / 検証に通らないものは歩かせない
 * - 途中で握りつぶされたら、作者のエコー待ちが切れて別の M1 でやり直される (walker は代わりに Fluff しない)
 */

const OPTS = (extra: Record<string, unknown> = {}) => ({
  coverIntervalMs: 15, relayDelayMs: 1, echoTimeoutMs: 2000, readyWaitMs: 150, ...extra,
});

/**
 * 正当な item はコンパクト形式で符号化する。符号化できない (壊れた) ものは、
 * 悪意ある隣人が送りつける想定で、読めないバイト列を item に載せる。
 */
const stemFrame = (item: unknown) => {
  try {
    return WireCodec.encode(WireType.STEM, { item });
  } catch {
    return WireCodec.encode(WireType.STEM, { item: new Uint8Array([9, 9, 9]) });
  }
};
const feedStem = (to: SimNode, from: SimNode, item: unknown) =>
  (to.peerManager as any).handleData(from.identity.peerId, stemFrame(item));
const fluffItem = (packet: GossipPacket) => ({ type: 'exit_fluff', packet });

/** to が from から受け取った type のメッセージ */
const received = (to: SimNode, from: SimNode, type: number) =>
  to.inbox.filter(m => m.from === from.identity.peerId && m.type === type);

/** Fluff を決めたノードを記録する (ZoneGossipRouter の Fluff 入口を観測) */
function trackFluffs(nodes: SimNode[]): SimNode[] {
  const fluffers: SimNode[] = [];
  for (const n of nodes) {
    const orig = (n.gossip as any).handleExitFluff.bind(n.gossip);
    (n.gossip as any).handleExitFluff = (p: GossipPacket) => {
      fluffers.push(n);
      return orig(p);
    };
  }
  return fluffers;
}

/** 条件が成り立つまで待つ (固定 sleep だと cover の枠の揺れで不安定になる) */
async function until(cond: () => boolean, timeoutMs = 2000): Promise<void> {
  const end = Date.now() + timeoutMs;
  while (!cond() && Date.now() < end) await sleep(5);
}

// 保留の上限の試験だけが大量のパケットを要る。印付きの安い PoW を受け入れる (cheapPow.ts 参照。印の無い解は本物の検証)
vi.mock('../../src/crypto/PowPolicy', async (orig) => (await import('../helpers/cheapPowMock')).cheapPowPolicyFactory(orig as any));

describe('Stem の歩き: walker の規則', () => {
  let nodes: SimNode[] = [];
  beforeAll(async () => { await sodiumReady; });
  afterEach(() => stopAll(nodes));

  /** x ── w ── y,z (w の隣人は x, y, z)。回路は起動しない (cover を出さない) */
  async function star(random: () => number, withYZ = true) {
    const w = await createSimNode('w', OPTS({ random }));
    const x = await createSimNode('x', OPTS());
    const ys = withYZ ? [await createSimNode('y', OPTS()), await createSimNode('z', OPTS())] : [];
    nodes = [w, x, ...ys];
    link(x, w);
    for (const y of ys) {
      link(w, y);
      // 下流は Stem を受け取っても動かさない (w の出力だけを観測するため)
      (y.dispatcher as any).handlers.set(WireType.STEM, new Set());
    }
    return { w, x, ys };
  }

  it('確率 STEM_FLUFF_PROBABILITY の内側 (0.2499) なら Fluff: 全隣人へ flood し、Stem は出さない', async () => {
    const { w, x, ys } = await star(() => CIRCUIT_CONFIG.STEM_FLUFF_PROBABILITY - 0.0001);
    const p = makePacket([1]);
    feedStem(w, x, fluffItem(p));
    await sleep(40);

    expect(w.received.map(r => r.packet_id)).toEqual([p.packet_id]);
    for (const n of [x, ...ys]) expect(received(n, w, WireType.GOSSIP)).toHaveLength(1);
    for (const n of [x, ...ys]) expect(received(n, w, WireType.STEM)).toHaveLength(0);
  });

  it('確率の外側 (0.25) なら Fluff せず、直前の相手 (x) 以外の隣人へ Stem で渡す', async () => {
    const { w, x, ys } = await star(() => CIRCUIT_CONFIG.STEM_FLUFF_PROBABILITY);
    const p = makePacket([2]);
    feedStem(w, x, fluffItem(p));
    await sleep(40);

    expect(w.received).toHaveLength(0);
    expect(received(x, w, WireType.STEM)).toHaveLength(0);
    expect(nodes.flatMap(n => received(n, w, WireType.GOSSIP))).toHaveLength(0);
    const forwarded = ys.flatMap(y => received(y, w, WireType.STEM));
    expect(forwarded).toHaveLength(1);
    // ワイヤにホップ数などは載せない (本体は item のバイト列だけ。型名の注入も無い)
    expect(Object.keys(forwarded[0].payload)).toEqual(['item']);
    expect(forwarded[0].payload.item.packet.packet_id).toBe(p.packet_id);
  });

  it('渡す先は直前の相手以外から一様に選ばれる (乱数で選択が変わる)', async () => {
    const pick = async (r: number) => {
      // 最初の乱数で Fluff を外し (0.9)、次の乱数 r で隣人を選ぶ
      const seq = [0.9, r];
      const { w, x, ys } = await star(() => seq.shift() ?? 0.9);
      feedStem(w, x, fluffItem(makePacket([3])));
      await sleep(30);
      const hit = ys.filter(y => received(y, w, WireType.STEM).length === 1).map(y => y.name);
      stopAll(nodes);
      return hit;
    };
    expect(await pick(0.0)).toEqual(['y']);
    expect(await pick(0.99)).toEqual(['z']);
  });

  it('同じものが Stem でもう一度届いても (ループ・やり直し) 即 Fluff せず、普通の 1 歩として扱う', async () => {
    // ★ 「一度見たら Fluff」だと、やり直し (別の M1' 経由) のときに 1 回目で通ったノードが
    //   M1' のすぐ隣で Fluff し、Guard から Fluff 地点が読みやすくなる。
    const { w, x, ys } = await star(() => 0.9); // 乱数 0.9 = Fluff しない
    const p = makePacket([4]);
    feedStem(w, x, fluffItem(p));
    await sleep(30);
    expect(ys.flatMap(y => received(y, w, WireType.STEM))).toHaveLength(1);
    expect(w.received).toHaveLength(0);

    feedStem(w, ys[0], fluffItem(p));
    await sleep(30);
    expect(w.received).toHaveLength(0); // Fluff していない
    expect(received(x, w, WireType.GOSSIP)).toHaveLength(0);
    // 直前の相手 (ys[0]) 以外へもう一度渡した
    const forwarded = [x, ...ys].flatMap(n => received(n, w, WireType.STEM));
    expect(forwarded).toHaveLength(2);
    expect(received(ys[0], w, WireType.STEM).length).toBeLessThanOrEqual(1);
  });

  it('既に flood 済みのものは捨てる (Fluff も転送もしない)', async () => {
    const { w, x, ys } = await star(() => 0.0); // 乱数が 0 なら本来は必ず Fluff
    const p = makePacket([5]);
    (w.peerManager as any).handleData(x.identity.peerId, WireCodec.encode(WireType.GOSSIP, { packet: p }));
    await sleep(30);
    const before = nodes.flatMap(n => n.inbox.filter(m => m.from === w.identity.peerId)).length;

    feedStem(w, x, fluffItem(p));
    await sleep(30);
    const after = nodes.flatMap(n => n.inbox.filter(m => m.from === w.identity.peerId)).length;
    expect(after).toBe(before);
    expect(ys.flatMap(y => received(y, w, WireType.STEM))).toHaveLength(0);
  });

  it('検証 (PacketValidator) を通らないものは歩かせない', async () => {
    const { w, x, ys } = await star(() => 0.0);
    // 中身を差し替えて packet_id (CHK) と合わなくする。PoW の外れ値は 1/256 で通ってしまうので使わない
    const bad: GossipPacket = { ...makePacket([6]), payload: Uint8Array.from([6, 6, 6, 6]) };
    feedStem(w, x, fluffItem(bad));
    feedStem(w, x, { type: 'exit_fluff', packet: { not: 'a packet' } });
    feedStem(w, x, { type: 'drop' });
    feedStem(w, x, { type: 'unknown' });
    feedStem(w, x, 'garbage');
    await sleep(40);
    expect(w.received).toHaveLength(0);
    expect(nodes.flatMap(n => n.inbox.filter(m => m.from === w.identity.peerId))).toHaveLength(0);
    expect(ys).toHaveLength(2);
  });

  it('渡す相手が居ない行き止まりでは、その場で Fluff する (タイマーではなく規則として)', async () => {
    const { w, x } = await star(() => 0.9, false);
    const p = makePacket([7]);
    feedStem(w, x, fluffItem(p));
    await sleep(30);
    expect(w.received.map(r => r.packet_id)).toEqual([p.packet_id]);
    expect(received(x, w, WireType.GOSSIP)).toHaveLength(1);
  });

  it('形式の壊れた item は歩かせない (検証できないものを増幅しない)', async () => {
    const c = await star(() => 0.1);
    feedStem(c.w, c.x, { type: 'exit_hint', hint: new Uint8Array(5) });
    feedStem(c.w, c.x, { type: 'exit_fluff', packet: { ...makePacket([8]), pow_nonce: -1 } });
    await sleep(30);
    expect(nodes.flatMap(n => n.inbox.filter(m => m.from === c.w.identity.peerId))).toHaveLength(0);
  });

  it('保留の上限が Stem にも掛かる: 隣人 1 人が一度に送りつけても、処理されるのは送信者あたり上限まで', async () => {
    const w = await createSimNode('w', OPTS({ relayDelayMs: 300, random: () => 0.0 }));
    const x = await createSimNode('x', OPTS());
    nodes = [w, x];
    link(x, w);
    const total = CIRCUIT_CONFIG.MAX_PENDING_PER_PEER + 20;
    for (let i = 0; i < total; i++) feedStem(w, x, fluffItem(makeCheapPacket([i, i >> 8, 9])));
    await sleep(3000);
    // 乱数 0 なので処理された分はすべて Fluff され、自分の UI に届く
    expect(w.received.length).toBeGreaterThan(0);
    expect(w.received.length).toBeLessThanOrEqual(CIRCUIT_CONFIG.MAX_PENDING_PER_PEER);
  });
});

describe('M1 と経路全体', () => {
  let nodes: SimNode[] = [];
  beforeAll(async () => { await sodiumReady; });
  afterEach(() => stopAll(nodes));

  /**
   * 一本道: alice ── guard ── m1 ── w1 ── w2 ── w3
   * 歩きが戻れる枝が無いので、Fluff するのは w1..w3 のどれかに決まる。
   * M1 の乱数は 0 (walker なら必ず Fluff する値) にして、M1 が Fluff しないことを強く試す。
   */
  async function path(echoTimeoutMs = 2000) {
    const alice = await createSimNode('alice', OPTS({ echoTimeoutMs }));
    const guard = await createSimNode('guard', OPTS());
    const m1 = await createSimNode('m1', OPTS({ random: () => 0 }));
    const w1 = await createSimNode('w1', OPTS());
    const w2 = await createSimNode('w2', OPTS());
    const w3 = await createSimNode('w3', OPTS());
    nodes = [alice, guard, m1, w1, w2, w3];
    link(alice, guard); link(guard, m1); link(m1, w1); link(w1, w2); link(w2, w3);
    return { alice, guard, m1, w1, w2, w3 };
  }

  it('cover セルは M1 で消える: 投稿が無い間、Stem も GOSSIP も一切出ない', async () => {
    const { alice, guard, m1 } = await path();
    startAll(nodes);
    await sleep(250);
    // cover は流れている (Guard は alice から受け取っている) が、M1 は何も歩かせない
    expect(received(guard, alice, WireType.ONION_STEM).length).toBeGreaterThan(3);
    expect(received(m1, guard, WireType.ONION_STEM).length).toBeGreaterThan(3);
    expect(nodes.flatMap(n => n.inbox).filter(m => m.type === WireType.STEM || m.type === WireType.GOSSIP)).toHaveLength(0);
  });

  it('本物の投稿: M1 は Fluff せず、Stem で w1 へ渡す。Fluff するのは walker で、全員に届き、エコーが解ける', async () => {
    const { alice, guard, m1, w1, w2, w3 } = await path();
    const fluffers = trackFluffs(nodes);
    startAll(nodes);
    await sleep(80); // Guard の隣人表 (PEX)

    const p = makePacket([1, 2, 3]);
    expect(await alice.gossip.broadcast(p)).toBe(true); // echo が返る
    await sleep(60);

    // Fluff を決めたのは w1..w3 のどれか 1 人。Guard / M1 / 作者ではない
    expect(fluffers).toHaveLength(1);
    expect([w1, w2, w3]).toContain(fluffers[0]);
    // M1 は w1 にだけ Stem を出し、Guard へは返さない
    expect(received(w1, m1, WireType.STEM).length).toBeGreaterThanOrEqual(1);
    expect(received(guard, m1, WireType.STEM)).toHaveLength(0);
    // 作者は Guard へ ONION_STEM しか出さない
    const fromAlice = guard.inbox.filter(m => m.from === alice.identity.peerId);
    const PLAIN = [WireType.GOSSIP, WireType.STEM];
    expect(fromAlice.filter(m => PLAIN.includes(m.type))).toHaveLength(0);
    expect(fromAlice.some(m => m.type === WireType.ONION_STEM)).toBe(true);
    // 全員に届く
    for (const n of nodes) expect(n.received.map(r => r.packet_id)).toContain(p.packet_id);
  });

  it('何度投稿しても Fluff するのは M1 でも Guard でもない (小さな網での繰り返し)', async () => {
    const { alice, guard, m1 } = await path();
    const fluffers = trackFluffs(nodes);
    startAll(nodes);
    await sleep(80);
    for (let i = 0; i < 12; i++) {
      expect(await alice.gossip.broadcast(makePacket([i, 1]))).toBe(true);
    }
    expect(fluffers).toHaveLength(12);
    expect(fluffers.filter(n => n === guard || n === m1 || n === alice)).toHaveLength(0);
  });

  it('M1 に Stem が戻ってきても M1 は Fluff せず、自分の Guard にも渡さない (行き止まりなら直前の相手へ返す)', async () => {
    const { alice, guard, m1, w1 } = await path(300);
    // w1 と Guard は Stem を受け取っても動かさない。手で M1 に突き返す
    for (const n of [w1, guard]) (n.dispatcher as any).handlers.set(WireType.STEM, new Set());
    const fluffers = trackFluffs(nodes);
    startAll([alice, guard, m1]);
    await sleep(80);

    const p = makePacket([8, 8]);
    const sending = alice.gossip.broadcast(p);
    await until(() => received(w1, m1, WireType.STEM).length > 0);
    expect(received(w1, m1, WireType.STEM)).toHaveLength(1);
    expect(received(guard, m1, WireType.STEM)).toHaveLength(0); // 最初の一歩は Guard へ戻さない

    // w1 が M1 に突き返す (ループ)。M1 は確率によらず Fluff しない
    feedStem(m1, w1, fluffItem(p));
    // ★ M1 の隣人は Guard と w1 だけ。Guard は「直前に M1 へ中継したセル」と「M1 から届いた
    //   Stem」を時刻で突き合わせられるので、Guard には渡さない。行き止まりなので w1 へ返す。
    await until(() => received(w1, m1, WireType.STEM).length > 1);
    expect(fluffers).not.toContain(m1);
    expect(m1.received.map(r => r.packet_id)).not.toContain(p.packet_id);
    expect(received(guard, m1, WireType.STEM)).toHaveLength(0);
    expect(received(w1, m1, WireType.STEM)).toHaveLength(2);
    expect(await sending).toBe(false); // 誰も Fluff しないのでエコーは返らない
  });

  it('途中の walker が握りつぶしたら、タイマーでの Fluff はせず、エコー切れで別の M1 からやり直す', async () => {
    const alice = await createSimNode('alice', OPTS({ echoTimeoutMs: 800 }));
    const guard = await createSimNode('guard', OPTS());
    const m1a = await createSimNode('m1a', OPTS());
    const m1b = await createSimNode('m1b', OPTS());
    const wa = await createSimNode('wa', OPTS());
    const wb = await createSimNode('wb', OPTS());
    nodes = [alice, guard, m1a, m1b, wa, wb];
    link(alice, guard); link(guard, m1a); link(guard, m1b); link(m1a, wa); link(m1b, wb);

    // 網全体で最初に届いた Stem だけを握りつぶす (1 回目の試行の walker)
    let blackholed = 0;
    for (const w of [wa, wb]) {
      const handlers = (w.dispatcher as any).handlers.get(WireType.STEM) as Set<(s: string, m: any) => void>;
      const originals = [...handlers];
      handlers.clear();
      handlers.add((s, m) => {
        if (blackholed === 0) { blackholed++; return; }
        originals.forEach(h => h(s, m));
      });
    }
    const fluffers = trackFluffs(nodes);
    startAll(nodes);
    await sleep(80);

    const p = makePacket([9, 9, 9]);
    const started = Date.now();
    expect(await alice.gossip.broadcast(p)).toBe(true);
    // 1 回目はエコー切れ (echoTimeoutMs=800) を待ってからのやり直し
    expect(Date.now() - started).toBeGreaterThanOrEqual(750);
    expect(blackholed).toBe(1);
    // 2 つの M1 がそれぞれ 1 回ずつ Stem を出した
    const stemsFrom = (n: SimNode) => nodes.flatMap(x => received(x, n, WireType.STEM)).length;
    expect(stemsFrom(m1a)).toBe(1);
    expect(stemsFrom(m1b)).toBe(1);
    expect(fluffers).toHaveLength(1);
    expect([wa, wb]).toContain(fluffers[0]);
  });

  it('全員が握りつぶすなら誰も Fluff せず、false を返す (walker の fail-safe Fluff は無い)', async () => {
    const { alice, w1 } = await path(300);
    (w1.dispatcher as any).handlers.set(WireType.STEM, new Set());
    const fluffers = trackFluffs(nodes);
    startAll(nodes);
    await sleep(80);

    expect(await alice.gossip.broadcast(makePacket([4, 4]))).toBe(false);
    await sleep(500); // タイマーによる Fluff があるならここまでに起きる
    expect(fluffers).toHaveLength(0);
    expect(nodes.flatMap(n => n.inbox).filter(m => m.type === WireType.GOSSIP)).toHaveLength(0);
  });

  it('M1 が渡す先を持たない (隣人は Guard だけ) なら捨てる。M1 は Fluff しない', async () => {
    const alice = await createSimNode('alice', OPTS({ echoTimeoutMs: 300 }));
    const guard = await createSimNode('guard', OPTS());
    const leaf = await createSimNode('leaf', OPTS({ random: () => 0 }));
    nodes = [alice, guard, leaf];
    link(alice, guard); link(guard, leaf);
    const fluffers = trackFluffs(nodes);
    startAll(nodes);
    await sleep(80);

    expect(await alice.gossip.broadcast(makePacket([6, 6]))).toBe(false);
    expect(fluffers).toHaveLength(0);
  });
});

describe('回路が使えるようになるまで待つ (READY_WAIT_MS)', () => {
  let nodes: SimNode[] = [];
  beforeAll(async () => { await sodiumReady; });
  afterEach(() => { vi.useRealTimers(); stopAll(nodes); });

  /** ready が立つまで Guard を選ばない方針 (起動直後の待機の再現) */
  function gatedPolicy() {
    const gate = { ready: false };
    const policy: GuardPolicy = {
      now: () => Date.now(),
      select: (candidates) => (gate.ready ? candidates[0] ?? null : null),
    };
    return { gate, policy };
  }

  async function world(readyWaitMs: number, policy: GuardPolicy) {
    const client = await createSimNode('client', OPTS({ readyWaitMs, echoTimeoutMs: 1500 }), policy);
    const guard = await createSimNode('guard', OPTS());
    const m1 = await createSimNode('m1', OPTS());
    const w1 = await createSimNode('w1', OPTS());
    nodes = [client, guard, m1, w1];
    link(client, guard); link(guard, m1); link(m1, w1);
    startAll(nodes);
    return { client, guard, m1, w1 };
  }

  it('Guard が決まる前に送ると、決まるまで待ってから成功する', async () => {
    const { gate, policy } = gatedPolicy();
    const { client, guard } = await world(5000, policy);
    await sleep(60);
    expect(client.dandelion.getPinnedGuardId()).toBeNull();

    let settled = false;
    const sending = client.gossip.broadcast(makePacket([1])).then(r => { settled = true; return r; });
    await sleep(200);
    expect(settled).toBe(false); // 待っている (即エラーにしない)
    // 待っている間は何も送らない
    expect(received(guard, client, WireType.ONION_STEM)).toHaveLength(0);
    expect(received(guard, client, WireType.GOSSIP)).toHaveLength(0);

    gate.ready = true; // Guard が選ばれる
    expect(await sending).toBe(true);
  });

  it('READY_WAIT_MS を過ぎても揃わなければ false (何も送らない)', async () => {
    const { policy } = gatedPolicy();
    const { client, guard } = await world(250, policy);
    const started = Date.now();
    expect(await client.gossip.broadcast(makePacket([2]))).toBe(false);
    const elapsed = Date.now() - started;
    expect(elapsed).toBeGreaterThanOrEqual(230);
    expect(elapsed).toBeLessThan(1500);
    const sent = guard.inbox.filter(m => m.from === client.identity.peerId).map(m => m.type);
    expect(sent.filter(t => t === WireType.ONION_STEM || t === WireType.GOSSIP || t === WireType.STEM)).toHaveLength(0);
  });

  it('Guard はあるが M1 候補 (Guard の隣人表) がまだ無い間も待ち、PEX が届けば成功する', async () => {
    const client = await createSimNode('client', OPTS({ readyWaitMs: 5000, echoTimeoutMs: 1500 }));
    const guard = await createSimNode('guard', OPTS());
    const m1 = await createSimNode('m1', OPTS());
    const w1 = await createSimNode('w1', OPTS());
    nodes = [client, guard, m1, w1];
    link(client, guard); link(m1, w1);
    startAll(nodes);
    await sleep(80);
    // Guard の背後にまだ誰も居ない
    let settled = false;
    const sending = client.gossip.broadcast(makePacket([3])).then(r => { settled = true; return r; });
    await sleep(150);
    expect(settled).toBe(false);

    link(guard, m1);
    // 隣人表は定期 PEX を待たず、Guard が変わったときに取り直されるだけなので、明示的に問い合わせる
    (client.circuit as any).requestGuardNeighbors();
    expect(await sending).toBe(true);
  });

  it('待っている最中に stop() すると false で終わり、待機は残らない', async () => {
    const { policy } = gatedPolicy();
    const { client } = await world(60_000, policy);
    const sending = client.gossip.broadcast(makePacket([4]));
    await sleep(60);
    expect((client.circuit as any).readyWaiters.size).toBe(1);

    client.circuit.stop();
    expect(await sending).toBe(false);
    expect((client.circuit as any).readyWaiters.size).toBe(0);
  });

  it('stop() の後はタイマーが 1 つも残らない', async () => {
    const { policy } = gatedPolicy();
    const client = await createSimNode('client', OPTS({ readyWaitMs: 60_000 }), policy);
    const guard = await createSimNode('guard', OPTS());
    nodes = [client, guard];
    link(client, guard);

    vi.useFakeTimers();
    client.circuit.start();
    const sending = client.circuit.send({ type: 'exit_fluff', packet: makePacket([1]) }, 'abcd1234');
    await vi.advanceTimersByTimeAsync(5_000);
    expect(vi.getTimerCount()).toBeGreaterThan(0);

    client.circuit.stop();
    expect(await sending).toBe(false);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('止まっている回路には待たずに false', async () => {
    const { policy } = gatedPolicy();
    const client = await createSimNode('client', OPTS({ readyWaitMs: 60_000 }), policy);
    nodes = [client];
    const started = Date.now();
    expect(await client.gossip.broadcast(makePacket([5]))).toBe(false);
    expect(Date.now() - started).toBeLessThan(500);
  });
});

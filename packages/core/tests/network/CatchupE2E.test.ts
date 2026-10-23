import 'fake-indexeddb/auto';
import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest';
import { sodiumReady } from '../../src/crypto/sodium';
import { WireType } from '../../src/network/wire/WireTypes';
import { CATCHUP_STATUS } from '../../src/network/wire/WireCodec';
import { CatchupClient } from '../../src/network/history/CatchupClient';
import { RECENT_BUFFER } from '../../src/network/history/RecentBuffer';
import { msToMinutes } from '../../src/crypto/PowPolicy';
import {
  createSimNode, link, stopAll, sleep, makePacket, announceVerified, disconnectNodes, type SimNode,
} from '../helpers/onionNet';
import { unlockedStore } from '../helpers/logicHarness';
import type { GossipPacket } from '../../src/types';

/**
 * 本物の PeerManager・WireCodec・GossipRouter・CatchupServer / Client を通した、複数ノードの追いつき。
 *
 *   poster ─┐
 *           ├─ guard (role: guard。72 時間バッファ) ─ client ─ bystander
 *   watcher ┘
 *
 * 時計は Date だけ偽装する (リンクの配送とサーバの帯域待ちは実タイマー)。
 */
const MIN = 60_000;
const H = 3600_000;
const t0 = Date.UTC(2026, 9, 14, 12, 0, 0);

const gossipFrames = (n: SimNode, from?: string) =>
  n.inbox.filter(m => m.type === WireType.GOSSIP && (from === undefined || m.from === from));
const catchupFrames = (n: SimNode, type: number) => n.inbox.filter(m => m.type === type);

async function until(cond: () => boolean, timeoutMs = 3000): Promise<void> {
  const end = performance.now() + timeoutMs;
  while (!cond() && performance.now() < end) await sleep(5);
  if (!cond()) throw new Error('until: condition not met');
}

describe('追いつき (Guard の 72 時間バッファ) の端から端まで', () => {
  let nodes: SimNode[] = [];
  let guard: SimNode, client: SimNode, poster: SimNode, watcher: SimNode, bystander: SimNode;

  beforeAll(async () => { await sodiumReady; });
  beforeEach(async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(t0 - H); // Guard は 1 時間前から動いている (入れ物の coverage の起点)
    guard = await createSimNode('guard', undefined, undefined, { role: 'guard', server: { minIntervalMs: 0 } });
    client = await createSimNode('client', undefined, undefined, { role: 'client' });
    poster = await createSimNode('poster');
    watcher = await createSimNode('watcher');
    bystander = await createSimNode('bystander');
    vi.setSystemTime(t0);
    nodes = [guard, client, poster, watcher, bystander];
    link(poster, guard);
    link(watcher, guard);
    link(client, bystander);
  });
  afterEach(() => {
    stopAll(nodes);
    vi.useRealTimers();
  });

  /** poster が guard へ平文の GOSSIP を送る (投稿者が flood に入る位置に居る想定) */
  const post = async (content: number, at = Date.now()): Promise<GossipPacket> => {
    const p = makePacket([content], at);
    poster.peerManager.sendMessage(guard.identity.peerId, WireType.GOSSIP, { packet: p });
    await until(() => guard.received.some(r => r.packet_id === p.packet_id));
    return p;
  };

  /** client の 1 ホップ目を guard に固定し、つないで握手が済んだことにする */
  const connectClient = async () => {
    link(client, guard);
    client.dandelion.getPinnedGuard([{ peerId: guard.identity.peerId, pubkey: guard.identity.pubkey }]);
    announceVerified(client, guard);
  };
  const caughtUp = () => until(() => client.catchupClient!.active === false && catchupFrames(client, WireType.CATCHUP_END).length > 0);
  const resetEnds = () => { client.inbox.length = 0; };

  it('★2 時間オフラインだった端末が Guard につなぎ直すと、取り逃した投稿だけを 1 回ずつ古い順に受け取る。誰も再 flood しない', async () => {
    // 1. つないで、最初の追いつき (空) と、live の投稿 P0
    await connectClient();
    await caughtUp();
    const p0 = await post(1);
    await until(() => client.received.some(r => r.packet_id === p0.packet_id));
    expect(client.received.map(r => r.packet_id)).toEqual([p0.packet_id]);
    const lastSeenBefore = client.catchupClient!.lastSeen;
    expect(lastSeenBefore).toBe(msToMinutes(p0.timestamp));

    // 2. 切断。2 時間のあいだ Guard にだけ投稿が届く
    disconnectNodes(client, guard);
    vi.setSystemTime(t0 + 10 * MIN);
    const p1 = await post(2);
    vi.setSystemTime(t0 + 60 * MIN);
    const p2 = await post(3);
    vi.setSystemTime(t0 + 110 * MIN);
    const p3 = await post(4);
    vi.setSystemTime(t0 + 2 * H);
    expect(client.received).toHaveLength(1); // オフライン中は何も届かない
    await sleep(50); // 配送中のフレームが落ち着くのを待つ
    // Guard が live で配った回数 (watcher が数える)。追いつきの前後で増えてはならない
    const floodedByGuard = gossipFrames(watcher, guard.identity.peerId).length;
    expect(floodedByGuard).toBe(4); // P0〜P3 を、投稿されたときに 1 回ずつ (poster 以外の隣人 = watcher へ)
    const bystanderBefore = gossipFrames(bystander, client.identity.peerId).length; // P0 を live で中継した 1 件
    expect(bystanderBefore).toBe(1);
    // 3. つなぎ直す
    resetEnds();
    await connectClient();
    await caughtUp();

    // 取り逃した 3 件を、1 回ずつ・古い順に
    expect(client.received.map(r => r.packet_id)).toEqual([p0, p1, p2, p3].map(p => p.packet_id));
    // 要求は lastSeen − 5 分 (P0 は重なりで再度返るが、重複として落ちる)
    const reqs = catchupFrames(guard, WireType.CATCHUP_REQ).map(m => m.payload.since);
    expect(reqs.at(-1)).toBe((lastSeenBefore as number) - 5);
    // END は OK (Guard のバッファの範囲内)
    expect(catchupFrames(client, WireType.CATCHUP_END).at(-1)!.payload.status).toBe(CATCHUP_STATUS.OK);

    // ★再 flood しない: 追いつきの間、client は誰にも GOSSIP を送っておらず (bystander が受け取っていない)、
    //   Guard もクライアントへ GOSSIP を流し直していない (DATA で運ぶだけ)
    await sleep(60);
    expect(gossipFrames(bystander, client.identity.peerId)).toHaveLength(bystanderBefore);
    expect(bystander.received.filter(r => [p1, p2, p3].some(p => p.packet_id === r.packet_id))).toHaveLength(0);
    expect(gossipFrames(client, guard.identity.peerId)).toHaveLength(0);
    expect(gossipFrames(guard, client.identity.peerId)).toHaveLength(0);
    expect(gossipFrames(watcher, guard.identity.peerId)).toHaveLength(floodedByGuard); // 追いつきで Guard は何も流し直していない
    expect(catchupFrames(client, WireType.CATCHUP_DATA).length).toBeGreaterThan(0);
    // 追いつきで届いたものは最新の時刻まで lastSeen を進める
    expect(client.catchupClient!.lastSeen).toBeGreaterThanOrEqual(msToMinutes(p3.timestamp));
  });

  it('★追いつきの途中にも live の投稿は届き、どちらも 1 回ずつ。追いつきが終わるまで lastSeen は live では進まない', async () => {
    await connectClient();
    await caughtUp();
    disconnectNodes(client, guard);
    const p1 = await post(1);
    vi.setSystemTime(t0 + 30 * MIN);
    const p2 = await post(2);
    resetEnds();
    await connectClient();
    const p3 = await post(3, Date.now()); // つながった直後の live
    await caughtUp();
    await until(() => client.received.length === 3);
    expect(client.received.map(r => r.packet_id).sort()).toEqual([p1, p2, p3].map(p => p.packet_id).sort());
    expect(new Set(client.received.map(r => r.packet_id)).size).toBe(3);
  });

  it('★Guard はバッファの 72 時間を超えたものを持たない。それより古い since には持っている分を返して PARTIAL', async () => {
    await post(1);
    vi.setSystemTime(t0 + 71 * H);
    const recent = await post(2);
    vi.setSystemTime(t0 + 73 * H); // 最初の投稿は受け取りから 73 時間 (外)、2 つ目は 2 時間
    expect(guard.buffer!.windowMs).toBe(72 * H);

    await connectClient(); // 初回 (lastSeen なし): since = 0
    await caughtUp();
    expect(client.received.map(r => r.packet_id)).toEqual([recent.packet_id]);
    expect(catchupFrames(client, WireType.CATCHUP_END).at(-1)!.payload.status).toBe(CATCHUP_STATUS.PARTIAL);
  });

  it('Guard のバッファは 72 時間・256MiB、一般ノードは 1 時間・16MiB。受け取った投稿と自分の発信の両方が入る', async () => {
    expect([guard.buffer!.windowMs, guard.buffer!.maxBytes]).toEqual([RECENT_BUFFER.GUARD_WINDOW_MS, 256 * 1024 * 1024]);
    expect([client.buffer!.windowMs, client.buffer!.maxBytes]).toEqual([RECENT_BUFFER.NODE_WINDOW_MS, 16 * 1024 * 1024]);
    const p = await post(1);
    expect(guard.buffer!.has(p.packet_id)).toBe(true);
    // 自分の発信 (回路は使えないので失敗するが、手元の入れ物には入る)
    const mine = makePacket([7], Date.now());
    client.gossip.broadcast(mine).catch(() => {});
    expect(client.buffer!.has(mine.packet_id)).toBe(true);
  });

  it('一般ノードにも同じ要求を出せる (1 時間分だけ返す)', async () => {
    // bystander の隣人 (client) が、bystander を 1 ホップ目にしたとき
    const peer = await createSimNode('peer', undefined, undefined, { role: 'client', server: { minIntervalMs: 0 } });
    nodes.push(peer);
    link(peer, poster);
    const p = makePacket([1], Date.now());
    poster.peerManager.sendMessage(peer.identity.peerId, WireType.GOSSIP, { packet: p });
    await until(() => peer.received.length === 1);
    link(client, peer);
    client.dandelion.getPinnedGuard([{ peerId: peer.identity.peerId, pubkey: peer.identity.pubkey }]);
    announceVerified(client, peer);
    await caughtUp();
    expect(client.received.map(r => r.packet_id)).toEqual([p.packet_id]);
  });

  it('同じ Guard に続けて要求しても 1 本ずつ (進行中は BUSY)。BUSY では何も受け取らない', async () => {
    const g2 = await createSimNode('g2', undefined, undefined, { role: 'guard', server: { perPeerBytesPerSec: 1000, perPeerBurstBytes: 16 * 1024 } });
    nodes.push(g2);
    link(poster, g2);
    for (let i = 0; i < 10; i++) {
      poster.peerManager.sendMessage(g2.identity.peerId, WireType.GOSSIP, { packet: makePacket(new Uint8Array(2000).fill(i + 1), Date.now(), { effort_exp: 8 }) });
    }
    await until(() => g2.buffer!.size === 10, 5000);
    link(client, g2);
    client.peerManager.sendMessage(g2.identity.peerId, WireType.CATCHUP_REQ, { since: 0 });
    client.peerManager.sendMessage(g2.identity.peerId, WireType.CATCHUP_REQ, { since: 0 });
    await until(() => catchupFrames(client, WireType.CATCHUP_END).some(m => m.payload.status === CATCHUP_STATUS.BUSY));
    expect(g2.catchupServer!.activeSessions).toBe(1);
  }, 15_000);

  it('★lastSeen は暗号化 DB の設定 (kv) に保存され、再起動 (ロックして開き直す) しても残る', async () => {
    const name = `catchup_persist_${Date.now()}`;
    const db1 = await unlockedStore(name);
    const store1 = { get: (k: string) => db1.getSetting(k), set: (k: string, v: unknown) => db1.setSetting(k, v) };
    const c1 = new CatchupClient(client.peerManager, client.dispatcher, client.dandelion, client.gossip, store1);
    await c1.init();
    expect(c1.lastSeen).toBeNull();
    link(client, guard);
    client.dandelion.getPinnedGuard([{ peerId: guard.identity.peerId, pubkey: guard.identity.pubkey }]);
    announceVerified(client, guard); // c1 と client.catchupClient の両方が反応する (同じ Guard へ)
    const p = await post(1);
    await until(() => c1.lastSeen !== null && c1.active === false);
    await c1.flush();
    const saved = c1.lastSeen!;
    expect(saved).toBeGreaterThanOrEqual(msToMinutes(p.timestamp) - 1);
    c1.destroy();
    db1.lock();

    const db2 = await unlockedStore(name);
    const c2 = new CatchupClient(
      client.peerManager, client.dispatcher, client.dandelion, client.gossip,
      { get: (k: string) => db2.getSetting(k), set: (k: string, v: unknown) => db2.setSetting(k, v) },
    );
    await c2.init();
    expect(c2.lastSeen).toBe(saved);
    c2.destroy();
  });
});

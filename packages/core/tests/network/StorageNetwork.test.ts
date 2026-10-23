import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { sodiumReady } from '../../src/crypto/sodium';
import { Encoding } from '../../src/common/Encoding';
import { closest } from '../../src/common/Ring';
import { WireType } from '../../src/network/wire/WireTypes';
import { R_STORE, birthDayOf, bucketPosition } from '../../src/network/storage/Duty';
import { decodePacket } from '../../src/crypto/PacketCodec';
import {
  createSimNode, link, stopAll, sleep, makePacket, announceVerified, type SimNode,
} from '../helpers/onionNet';
import { attachStorage, fakeLeaseSet, stopStorage, type StorageSimNode } from '../helpers/storageNet';
import type { GossipPacket } from '../../src/types';

/**
 * 本物の PeerManager・WireCodec・GossipRouter・CatchupServer / Client に、保管担当 (StorageService) をつけた複数ノード。
 *
 *   n0 ─ n1 ─ n2 ─ n3 ─ n4 (新参者: 後から n3 につながる)
 *
 * 枠の PoW は effort 1 (テスト専用)。配布 (flood / SYNC)・担当の判定・預かりは本番と同じ経路を通る。
 */
async function until(cond: () => boolean | Promise<boolean>, timeoutMs = 5000): Promise<void> {
  const end = performance.now() + timeoutMs;
  while (!(await cond()) && performance.now() < end) await sleep(10);
  if (!(await cond())) throw new Error('until: condition not met');
}

const pin = (n: SimNode, guard: SimNode) =>
  n.dandelion.getPinnedGuard([{ peerId: guard.identity.peerId, pubkey: guard.identity.pubkey }]);

const hex = (b: Uint8Array) => Encoding.toHex(b);

describe('保管担当: leaseSet の配布', () => {
  let nodes: StorageSimNode[] = [];

  beforeAll(async () => { await sodiumReady; });
  afterEach(async () => {
    await stopStorage(nodes);
    stopAll(nodes);
    nodes = [];
  });

  async function chain(n: number, slots = 1): Promise<StorageSimNode[]> {
    const sims: SimNode[] = [];
    for (let i = 0; i < n; i++) sims.push(await createSimNode(`n${i}`));
    for (let i = 0; i + 1 < n; i++) link(sims[i], sims[i + 1]);
    // 各ノードの 1 ホップ目 (受け口): 右隣 (末尾は左隣)
    sims.forEach((s, i) => pin(s, sims[i + 1] ?? sims[i - 1]));
    nodes = [];
    for (const s of sims) nodes.push(await attachStorage(s, { slots }));
    return nodes;
  }

  it('★各ノードが出した leaseSet が flood で全員に届く (IP なし・自分の SID の枠だけ)', async () => {
    const [n0, n1, n2, n3] = await chain(4, 2);
    for (const n of nodes) n.storage.router.publish();
    await until(() => nodes.every(n => n.storage.leaseSets.size === 4));

    // 全員が同じ 4 つの SID を持ち、各 SID は 2 枠
    const sidsOf = (n: StorageSimNode) => n.storage.leaseSets.allBytes().map(b => hex(b)).sort();
    expect(sidsOf(n0)).toEqual(sidsOf(n3));
    expect(sidsOf(n1)).toEqual(sidsOf(n2));
    for (const n of nodes) expect(n.storage.leaseSets.allSlots()).toHaveLength(8);
    // SID は peerId と別の鍵 (どの leaseSet にもノードの peerId の公開鍵は載らない)
    const all = new Set(n0.storage.leaseSets.allBytes().map(b => hex(b)));
    for (const n of nodes) {
      expect(hex(n.storage.identity.publicKey)).not.toBe(hex(n.identity.pubkey));
      for (const b of all) expect(b).not.toContain(hex(n.identity.pubkey));
    }
    // 受け口はそれぞれの 1 ホップ目 (peerId の raw 16 バイト)
    const gw = new Map(n0.storage.leaseSets.allBytes().map(b => {
      const hs = hex(b);
      return [hs.substring(2, 66), hs.substring(2 + 64 + 2 + 2 * 40, 2 + 64 + 2 + 2 * 40 + 32)];
    }));
    expect(gw.get(hex(n1.storage.identity.publicKey))).toBe(n2.identity.peerId);
    expect(gw.get(hex(n3.storage.identity.publicKey))).toBe(n2.identity.peerId);
    // flood の過剰な再送はない: 1 つの leaseSet は 1 本のリンクを 1 回ずつしか通らない
    const frames = nodes.flatMap(n => n.inbox.filter(m => m.type === WireType.LEASESET));
    expect(frames.length).toBeLessThanOrEqual(4 * 3 + 4); // 4 つの leaseSet × 3 リンク (+ 余裕)
  });

  it('★後から来た端末は、1 ホップ目から手持ちの leaseSet を一括で受け取る (SYNC)。受け取ったものは再 flood しない', async () => {
    const [n0, n1, n2, n3] = await chain(4);
    for (const n of nodes) n.storage.router.publish();
    await until(() => nodes.every(n => n.storage.leaseSets.size === 4));
    const before = nodes.flatMap(n => n.inbox.filter(m => m.type === WireType.LEASESET)).length;

    const sim = await createSimNode('n4');
    const n4 = await attachStorage(sim, { slots: 1 });
    nodes.push(n4);
    link(n4, n3);
    pin(n4, n3);
    announceVerified(n4, n3); // 検証済みになった → SYNC_REQ
    await until(() => n4.storage.leaseSets.size === 4);
    expect(n4.inbox.some(m => m.type === WireType.LEASESET_SYNC && m.from === n3.identity.peerId)).toBe(true);
    expect(n3.inbox.some(m => m.type === WireType.LEASESET_SYNC_REQ && m.from === n4.identity.peerId)).toBe(true);
    expect(n4.storage.router.stats.accepted).toBe(4);
    await sleep(60);
    // SYNC で受け取ったものは網に流し直されない (n3 から n2 への LEASESET は増えていない)
    const after = nodes.flatMap(n => n.inbox.filter(m => m.type === WireType.LEASESET)).length;
    expect(after).toBe(before);

    // 新参者が自分の leaseSet を出すと、全員に届く
    n4.storage.router.publish();
    await until(() => [n0, n1, n2, n3].every(n => n.storage.leaseSets.size === 5));
  });

  it('★受け口が信頼 Guard でない端末は leaseSet を出さず、他人のそれも受け付けない (リストが有効な網)', async () => {
    const sims = [await createSimNode('a'), await createSimNode('b'), await createSimNode('c')];
    link(sims[0], sims[1]);
    link(sims[1], sims[2]);
    pin(sims[0], sims[1]);
    pin(sims[2], sims[1]);
    const trusted = new Set<string>();
    const allowed = (id: string) => trusted.size === 0 || trusted.has(id); // リスト無し = open
    nodes = [];
    for (const s of sims) nodes.push(await attachStorage(s, { gatewayAllowed: allowed }));
    // open: 届く
    nodes[0].storage.router.publish();
    await until(() => nodes[2].storage.leaseSets.size === 1);

    // リストが有効になった (b だけが信頼 Guard)
    trusted.add(sims[1].identity.peerId);
    pin(sims[2], sims[1]);
    nodes[2].storage.router.publish(); // 受け口 b = 信頼 Guard → 出せる
    await until(() => nodes[0].storage.leaseSets.size === 2);
    // a の受け口が信頼 Guard でないとき (a の 1 ホップ目を c にする) は発行されない
    sims[0].dandelion.resetPinnedGuard();
    link(sims[0], sims[2]);
    pin(sims[0], sims[2]);
    expect(nodes[0].storage.router.publish()).toBeNull();
  });
});

describe('保管担当: 投稿が担当の保持者に届く', () => {
  let nodes: StorageSimNode[] = [];
  let poster: SimNode;

  beforeAll(async () => { await sodiumReady; });
  beforeEach(async () => { poster = await createSimNode('poster'); });
  afterEach(async () => {
    await stopStorage(nodes);
    stopAll([...nodes, poster]);
    nodes = [];
  });

  it('★枠が 64 未満の小さな網では、全員が全部を預かる (live の flood)', async () => {
    const sims = [await createSimNode('n0'), await createSimNode('n1'), await createSimNode('n2')];
    link(sims[0], sims[1]);
    link(sims[1], sims[2]);
    link(poster, sims[0]);
    nodes = [];
    for (const s of sims) nodes.push(await attachStorage(s));
    const packets: GossipPacket[] = [];
    for (let tag = 1; tag <= 3; tag++) {
      const p = makePacket([tag], Date.now(), { tag });
      packets.push(p);
      poster.peerManager.sendMessage(sims[0].identity.peerId, WireType.GOSSIP, { packet: p });
    }
    await until(() => sims.every(s => s.received.length === 3));
    for (const n of nodes) {
      await n.storage.holder!.flush();
      for (const p of packets) {
        const got = await n.storage.holder!.getBucket(birthDayOf(p.timestamp, p.age), p.tag);
        expect(got.map(b => decodePacket(b)!.packet_id), n.name).toEqual([p.packet_id]);
      }
    }
  });

  it('★大きな網 (枠 100 超): 投稿は「バケットに近い 72 枠」を持つノードだけに保存される (live)', async () => {
    const sims = [await createSimNode('n0'), await createSimNode('n1'), await createSimNode('n2'), await createSimNode('n3'), await createSimNode('n4')];
    for (let i = 0; i + 1 < sims.length; i++) link(sims[i], sims[i + 1]);
    link(poster, sims[0]);
    sims.forEach((s, i) => pin(s, sims[i + 1] ?? sims[i - 1]));
    nodes = [];
    for (const s of sims) nodes.push(await attachStorage(s));
    // 他に 100 の SID (各 1 枠) が居る網。全員が同じ見え方になるよう、本物の 5 ノードも leaseSet を出して共有する
    const fakes = Array.from({ length: 100 }, (_, i) => fakeLeaseSet(i + 1, 1));
    for (const n of nodes) for (const f of fakes) n.storage.leaseSets.add(f);
    for (const n of nodes) n.storage.router.publish();
    await until(() => nodes.every(n => n.storage.leaseSets.size === 105));

    // テスト側で全 105 枠の一覧を独立に作る
    const slotsAll = [
      ...fakes.flatMap(f => nodes[0].storage.leaseSets.allSlots().filter(s => s.sid === hex(f.sid))),
      ...nodes.flatMap(x => x.storage.activeSlots().map(s => ({
        id: Uint8Array.of(...x.storage.identity.publicKey, s.index), position: s.position, key: hex(x.storage.identity.publicKey) + '00', owner: x.name,
      }))),
    ];
    expect(slotsAll).toHaveLength(105);

    const packets: GossipPacket[] = [];
    for (let tag = 1; tag <= 14; tag++) {
      const p = makePacket([tag], Date.now(), { tag: tag * 211, age: tag % 3 });
      packets.push(p);
      poster.peerManager.sendMessage(sims[0].identity.peerId, WireType.GOSSIP, { packet: p });
    }
    await until(() => sims.every(s => s.received.length === packets.length), 10_000);

    let held = 0;
    let skipped = 0;
    for (const p of packets) {
      const bucket = bucketPosition(birthDayOf(p.timestamp, p.age), p.tag);
      const duty = new Set(closest(bucket, slotsAll, R_STORE).map((s: any) => s.key));
      for (const n of nodes) {
        await n.storage.holder!.flush();
        const mine = hex(n.storage.identity.publicKey) + '00';
        const should = duty.has(mine);
        const got = await n.storage.holder!.getBucket(birthDayOf(p.timestamp, p.age), p.tag);
        expect(got.length, `${n.name} tag=${p.tag}`).toBe(should ? 1 : 0);
        if (should) held++; else skipped++;
      }
    }
    // 選別が本当に効いている (全員が持つ / 誰も持たない、のどちらでもない)
    console.log(`[storage-net] 105 枠: 5 ノード × 14 投稿 = 70 組 中 保存 ${held} / 見送り ${skipped}`);
    expect(held).toBeGreaterThan(0);
    expect(skipped).toBeGreaterThan(0);
  }, 30_000);

  it('★追いつき (Guard の差分) で届いた投稿も、担当なら保存する。再 flood はしない', async () => {
    const guard = await createSimNode('guard', undefined, undefined, { role: 'guard', server: { minIntervalMs: 0 } });
    const client = await createSimNode('client', undefined, undefined, { role: 'client' });
    link(poster, guard);
    nodes = [await attachStorage(client)];
    const packets: GossipPacket[] = [];
    for (let tag = 1; tag <= 3; tag++) {
      const p = makePacket([tag], Date.now(), { tag });
      packets.push(p);
      poster.peerManager.sendMessage(guard.identity.peerId, WireType.GOSSIP, { packet: p });
    }
    await until(() => guard.received.length === 3);
    expect(nodes[0].received).toHaveLength(0); // オフライン中

    link(client, guard);
    pin(client, guard);
    announceVerified(client, guard);
    await until(() => client.received.length === 3);
    const holder = nodes[0].storage.holder!;
    await holder.flush();
    for (const p of packets) {
      expect((await holder.getBucket(birthDayOf(p.timestamp, p.age), p.tag)).map(b => decodePacket(b)!.packet_id)).toEqual([p.packet_id]);
    }
    stopAll([guard]);
  });

  it('★追いつきでも大きな網では担当だけを保存する (live と同じ判定)', async () => {
    const guard = await createSimNode('guard', undefined, undefined, { role: 'guard', server: { minIntervalMs: 0 } });
    const client = await createSimNode('client', undefined, undefined, { role: 'client' });
    link(poster, guard);
    nodes = [await attachStorage(client)];
    const fakes = Array.from({ length: 150 }, (_, i) => fakeLeaseSet(i + 1, 1));
    for (const f of fakes) nodes[0].storage.leaseSets.add(f);
    const packets: GossipPacket[] = [];
    for (let tag = 1; tag <= 12; tag++) {
      const p = makePacket([tag], Date.now(), { tag: tag * 307 });
      packets.push(p);
      poster.peerManager.sendMessage(guard.identity.peerId, WireType.GOSSIP, { packet: p });
    }
    await until(() => guard.received.length === 12, 8000);
    link(client, guard);
    pin(client, guard);
    announceVerified(client, guard);
    await until(() => client.received.length === 12, 8000);
    const holder = nodes[0].storage.holder!;
    await holder.flush();
    const mineSlot = nodes[0].storage.activeSlots()[0];
    const slotsAll = [
      ...nodes[0].storage.leaseSets.allSlots(),
      { id: Uint8Array.of(...nodes[0].storage.identity.publicKey, 0), position: mineSlot.position, key: 'mine', sid: 'mine', index: 0 },
    ];
    let held = 0;
    for (const p of packets) {
      const duty = closest(bucketPosition(birthDayOf(p.timestamp, p.age), p.tag), slotsAll, R_STORE);
      const should = duty.some(s => s.key === 'mine');
      const got = await holder.getBucket(birthDayOf(p.timestamp, p.age), p.tag);
      expect(got.length, `tag=${p.tag}`).toBe(should ? 1 : 0);
      if (should) held++;
    }
    console.log(`[storage-net] 追いつき 151 枠: 12 投稿中 保存 ${held}`);
    stopAll([guard]);
  }, 30_000);

  it('★自分の投稿 (self) も担当なら保存する', async () => {
    const sim = await createSimNode('solo');
    nodes = [await attachStorage(sim)];
    const p = makePacket([9], Date.now(), { tag: 77 });
    void sim.gossip.broadcast(p); // 回路は動いていないので網には出ない (fail-closed)。手元への配信と保存フックは先に走る
    await sleep(20);
    const holder = nodes[0].storage.holder!;
    await holder.flush();
    expect((await holder.getBucket(birthDayOf(p.timestamp, p.age), 77)).map(b => decodePacket(b)!.packet_id)).toEqual([p.packet_id]);
  });
});

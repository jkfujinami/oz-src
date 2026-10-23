import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { sodiumReady } from '../../src/crypto/sodium';
import { OnionRouter } from '../../src/crypto/OnionRouter';
import { encodeExitItem, splitIntoFragments } from '../../src/crypto/ExitItem';
import { WireType } from '../../src/network/wire/WireTypes';
import { WireCodec } from '../../src/network/wire/WireCodec';
import { CIRCUIT_CONFIG } from '../../src/network/onion/OnionCircuit';
import { PacketBuilder } from '../../src/crypto/PacketBuilder';
import { CryptoEngine } from '../../src/crypto/CryptoEngine';
import { POW_POLICY } from '../../src/crypto/PowPolicy';
import { createSimNode, link, startAll, stopAll, sleep, type SimNode } from '../helpers/onionNet';
import { buildPost } from '../helpers/postFixtures';

/**
 * 3 枚のセルに分かれる最大の投稿 (本文 2048 バイト + トリップ + 親 2) が、
 * 本物のワイヤ (PeerManager + WireCodec) を通る回路で全ノードに届く。
 */
describe('3 枚のセルに分かれる投稿の端から端まで', () => {
  let nodes: SimNode[] = [];
  let alice: SimNode, bob: SimNode, charlie: SimNode, dave: SimNode, erin: SimNode;

  beforeAll(async () => { await sodiumReady; });
  afterEach(() => stopAll(nodes));

  async function chain() {
    alice = await createSimNode('alice');
    bob = await createSimNode('bob');
    charlie = await createSimNode('charlie');
    dave = await createSimNode('dave');
    erin = await createSimNode('erin');
    nodes = [alice, bob, charlie, dave, erin];
    link(alice, bob); link(bob, charlie); link(charlie, dave); link(bob, erin); link(erin, dave);
    startAll(nodes);
    await sleep(80);
  }

  /** Bob (Guard) が Alice から受け取ったセルの次ホップの列 */
  function guardHops(): string[] {
    const secret = bob.identity.exportSecret();
    return bob.inbox
      .filter(m => m.from === alice.identity.peerId && m.type === WireType.ONION_STEM)
      .map(m => {
        const l = OnionRouter.unwrap(m.payload.onionBytes, secret.pubkey, secret.privkey);
        if (l?.type !== 'relay') throw new Error('not relay');
        return l.nextHop;
      });
  }

  function expectRunsOfThree(hops: string[]) {
    expect(hops.length).toBeGreaterThanOrEqual(6);
    const runs: string[] = [];
    for (let i = 0; i + 3 <= hops.length; i += 3) {
      expect(new Set(hops.slice(i, i + 3)).size).toBe(1);
      runs.push(hops[i]);
    }
    for (let i = 1; i < runs.length; i++) expect(runs[i]).not.toBe(runs[i - 1]);
  }

  /**
   * ちょうど 3 枚になる最小の本文 (トリップ・親 2 付き)。
   * ★ 枚数の境界は OnionRouter.FRAG_DATA_MAX から導く (オニオンの中継層が縮むと 1 セルの容量が増えるので、固定の長さにしない)
   */
  async function threeCellContent(): Promise<string> {
    const overhead = encodeExitItem({
      type: 'exit_fluff', packet: (await buildPost({ content: '', trip: true, parents: 2, pow: 'fake' })).packet,
    }).length;
    // 2 枚には収まらず (上限の 2048 バイトまで入れても 2 * FRAG_DATA_MAX を超える)、3 枚には余裕で収まる
    const n = Math.min(POW_POLICY.MAX_CONTENT_BYTES, 2 * OnionRouter.FRAG_DATA_MAX + 100 - overhead);
    expect(overhead + n).toBeGreaterThan(2 * OnionRouter.FRAG_DATA_MAX);
    expect(n).toBeLessThanOrEqual(POW_POLICY.MAX_CONTENT_BYTES);
    return 'a'.repeat(n);
  }

  it('3 枚になる投稿 (トリップ + 親 2) が 3 枚で運ばれ、全ノードに届く。Guard の列は 3 回ずつのまま', async () => {
    await chain();
    const { packet, threadKey } = await buildPost({ content: await threeCellContent(), trip: true, parents: 2 });
    const item = { type: 'exit_fluff' as const, packet };
    expect(splitIntoFragments(encodeExitItem(item), new Uint8Array(8))).toHaveLength(3);

    const before = guardHops().length;
    expect(await alice.gossip.broadcast(packet)).toBe(true);
    await sleep(100);

    for (const n of [bob, charlie, dave, erin]) {
      expect(n.received.map(p => p.packet_id), n.name).toContain(packet.packet_id);
    }
    // 届いたパケットは本物 (復号・署名検証が通る)
    const got = dave.received.find(p => p.packet_id === packet.packet_id)!;
    const post = await PacketBuilder.verifyAndDecrypt(
      got, threadKey, { kind: 'reply', boardId: 'vip', threadId: 'abcdefghij' }, new CryptoEngine(),
    );
    expect(post!.content.length).toBe(packet.payload.length - (16 + 1 + 2 * 16 + 96));
    expect(post!.parents).toHaveLength(2);
    expect(post!.trip_pubkey).not.toBeNull();
    expect(post!.session_pubkey).toBeNull();
    // 3 セル分の投稿なので、最低 effort は 3 (e=7) を満たしている
    expect(packet.effort_exp).toBe(7);

    // 3 枚が出た後も、Guard から見える列は「同じ M1 が 3 回ずつ」
    expect(guardHops().length).toBeGreaterThan(before + 3);
    expectRunsOfThree(guardHops());
    // 平文の GOSSIP は Alice から出ていない
    expect(bob.inbox.some(m => m.from === alice.identity.peerId && m.type === WireType.GOSSIP)).toBe(false);
  });

  it('★M1 に断片が揃わない (1 枚欠ける) と、M1 は Stem を始めない', async () => {
    await chain();
    const { packet } = await buildPost({ content: await threeCellContent(), trip: true, parents: 2 });
    const bytes = encodeExitItem({ type: 'exit_fluff', packet });
    const frags = splitIntoFragments(bytes, new Uint8Array(8).fill(5))!;
    expect(frags).toHaveLength(3);
    const send = (f: (typeof frags)[number]) => {
      // M1 (charlie) が Guard (bob) から受け取る形: 出口層だけを charlie 宛てに封印したセル
      const cell = OnionRouter.wrapCircuit(f, [{ peerId: charlie.identity.peerId, pubkey: charlie.identity.pubkey }]);
      (charlie.peerManager as any).handleData(bob.identity.peerId, WireCodec.encode(WireType.ONION_STEM, { onionBytes: cell }));
    };
    const stems = () => charlie.inbox.length && [bob, dave, erin].flatMap(n => n.inbox).filter(m => m.from === charlie.identity.peerId && m.type === WireType.STEM).length;
    send(frags[0]);
    send(frags[2]);
    await sleep(60);
    expect(stems()).toBe(0);
    expect([bob, charlie, dave, erin].every(n => !n.received.some(p => p.packet_id === packet.packet_id))).toBe(true);
    // 欠けていた断片が (猶予内に) 届けば Stem が始まる
    send(frags[1]);
    await sleep(60);
    expect(stems()).toBeGreaterThanOrEqual(1);
    // M1 は送ってきた Guard (bob) には Stem を返さない
    expect(bob.inbox.some(m => m.from === charlie.identity.peerId && m.type === WireType.STEM)).toBe(false);
  });

  it('設定: 1 つの回路は 3 スロットで、1 つの item の断片数の上限と一致する', () => {
    expect(CIRCUIT_CONFIG.CIRCUIT_SLOTS).toBe(3);
  });
});

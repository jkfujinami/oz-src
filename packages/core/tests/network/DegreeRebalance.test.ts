import { describe, it, expect, beforeAll, vi } from 'vitest';
import { sodiumReady } from '../../src/crypto/sodium';
import { NodeIdentity } from '../../src/crypto/NodeIdentity';
import { PeerManager } from '../../src/network/PeerManager';
import { MessageDispatcher } from '../../src/network/MessageDispatcher';
import { netGroupOf, groupCap } from '../../src/network/NetGroup';
import { RING_MESH } from '../../src/constants';

const FAST = { difficulty: 0, opsLimit: 1, memLimit: 8192 };

let seq = 0;
function makePeer(pm: PeerManager, opts: {
  direction: 'outbound' | 'inbound';
  group?: string;
  verifiedAt?: number;
  local?: boolean;
}) {
  const id = (++seq).toString(16).padStart(32, '0');
  const my = pm.myPosition;
  // ローカルリンクはリング上で自分のすぐ隣、それ以外は十分遠くに置く
  const position = opts.local ? (my + 0.00001 * (seq % 50 + 1)) % 1 : (my + 0.3 + (seq % 100) * 0.001) % 1;
  const peer: any = {
    peerId: id, position, rtt: 0,
    isConnected: true, isVerified: true,
    direction: opts.direction,
    netGroup: opts.group ?? `v4:10.${seq}`,
    verifiedAt: opts.verifiedAt ?? Date.now(),
    close: vi.fn(),
  };
  (pm as any)._peers.set(id, peer);
  (pm as any).noteGroup(peer.netGroup);
  return peer;
}

async function newManager() {
  const identity = await NodeIdentity.mine(FAST);
  const signaling: any = { connect: vi.fn(), disconnect: vi.fn(), sendRelay: vi.fn(), on: vi.fn(), isConnected: false };
  return new PeerManager(identity, new MessageDispatcher(), signaling, { powParams: FAST });
}

describe('次数の調整 (Sybil 対策 A1 / A2 / A3)', () => {
  beforeAll(async () => {
    await sodiumReady;
  });

  it('網が小さく次数が上限未満なら、誰も外さない (初期成長を妨げない)', async () => {
    const pm = await newManager();
    for (let i = 0; i < 10; i++) makePeer(pm, { direction: 'inbound', group: 'lan' });
    pm.rebalance();
    expect(pm.verifiedPeers).toHaveLength(10);
  });

  it('inbound が何人来ても、自分で選んだ outbound は押し出されない', async () => {
    const pm = await newManager();
    const outbound = Array.from({ length: 8 }, () => makePeer(pm, { direction: 'outbound' }));
    for (let i = 0; i < 8; i++) makePeer(pm, { direction: 'inbound' });

    for (let i = 0; i < 20; i++) {
      const sybil = makePeer(pm, { direction: 'inbound', group: `v4:66.${i}` });
      pm.rebalance(sybil.peerId);
    }

    expect(pm.verifiedPeers).toHaveLength(RING_MESH.MAX_DEGREE);
    for (const o of outbound) expect(pm.peers.has(o.peerId)).toBe(true);
  });

  it('枠が埋まっていても、新しい outbound は inbound と入れ替わる', async () => {
    const pm = await newManager();
    for (let i = 0; i < 4; i++) makePeer(pm, { direction: 'outbound' });
    const inbound = Array.from({ length: 12 }, () => makePeer(pm, { direction: 'inbound' }));

    const fresh = makePeer(pm, { direction: 'outbound' });
    pm.rebalance(fresh.peerId);

    expect(pm.peers.has(fresh.peerId)).toBe(true);
    expect(inbound.filter(p => !pm.peers.has(p.peerId))).toHaveLength(1);
  });

  it('多すぎる出所の区分から先に外す', async () => {
    const pm = await newManager();
    for (let i = 0; i < 8; i++) makePeer(pm, { direction: 'outbound' });
    const crowded = Array.from({ length: 6 }, () => makePeer(pm, { direction: 'inbound', group: 'v4:203.0' }));
    makePeer(pm, { direction: 'inbound', group: 'v4:198.51' });
    makePeer(pm, { direction: 'inbound', group: 'v4:192.0' });

    const newcomer = makePeer(pm, { direction: 'inbound', group: 'v4:100.1' });
    pm.rebalance(newcomer.peerId);

    // 新顔 (別区分) は残り、混みすぎた区分から 1 人外れる
    expect(pm.peers.has(newcomer.peerId)).toBe(true);
    expect(crowded.filter(p => !pm.peers.has(p.peerId))).toHaveLength(1);
  });

  it('同じ条件なら、観測期間の短い (新しい) inbound から外す', async () => {
    const pm = await newManager();
    const now = Date.now();
    for (let i = 0; i < 8; i++) makePeer(pm, { direction: 'outbound' });
    const old = Array.from({ length: 8 }, (_, i) => makePeer(pm, { direction: 'inbound', verifiedAt: now - 3_600_000 + i }));

    const young = makePeer(pm, { direction: 'inbound', verifiedAt: now });
    pm.rebalance(young.peerId);

    expect(pm.peers.has(young.peerId)).toBe(false);
    for (const p of old) expect(pm.peers.has(p.peerId)).toBe(true);
  });

  it('ローカルリンク (リング上の最近接) は inbound でも外さない', async () => {
    const pm = await newManager();
    for (let i = 0; i < 12; i++) makePeer(pm, { direction: 'outbound' });
    const locals = Array.from({ length: 4 }, () => makePeer(pm, { direction: 'inbound', local: true, verifiedAt: Date.now() + 1000 }));

    const extra = makePeer(pm, { direction: 'inbound' });
    pm.rebalance(extra.peerId);

    for (const p of locals) expect(pm.peers.has(p.peerId)).toBe(true);
    expect(pm.verifiedPeers).toHaveLength(RING_MESH.MAX_DEGREE);
  });
});

describe('NetGroup', () => {
  it('IPv4 は /16、IPv6 は /48 にまとめ、IP そのものは残さない', () => {
    expect(netGroupOf('203.0.113.5')).toBe('v4:203.0');
    expect(netGroupOf('203.0.200.9')).toBe('v4:203.0');
    expect(netGroupOf('2001:db8:abcd:1::5')).toBe('v6:2001:db8:abcd');
    expect(netGroupOf('2001:0db8:abcd:ffff::1')).toBe('v6:2001:db8:abcd');
  });

  it('私設アドレス・mDNS は lan、TURN は relay、取れなければ unknown', () => {
    expect(netGroupOf('192.168.1.10')).toBe('lan');
    expect(netGroupOf('10.1.2.3')).toBe('lan');
    expect(netGroupOf('fe80::1')).toBe('lan');
    expect(netGroupOf('8f3c2a.local')).toBe('lan');
    expect(netGroupOf('198.51.100.7', 'relay')).toBe('relay:198.51');
    expect(netGroupOf(undefined)).toBe('unknown');
    expect(netGroupOf('not-an-ip')).toBe('unknown');
  });

  it('区分の上限は見えた区分の数から決まる (1 区分なら制限なし)', () => {
    expect(groupCap(16, 1)).toBe(16);
    expect(groupCap(16, 4)).toBe(4);
    expect(groupCap(16, 100)).toBe(1);
  });
});

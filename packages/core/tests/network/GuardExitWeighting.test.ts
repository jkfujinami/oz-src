import { describe, it, expect, beforeAll } from 'vitest';
import sodium, { sodiumReady } from '../../src/crypto/sodium';
import { DandelionRouter, secureWeightedIndex, OBSERVATION_SATURATION_MS } from '../../src/network/gossip/DandelionRouter';
import { OnionCircuit } from '../../src/network/onion/OnionCircuit';
import { MessageDispatcher } from '../../src/network/MessageDispatcher';

const ID = (c: string) => c.repeat(32);

function fakePm(peers: Array<{ id: string; direction: 'outbound' | 'inbound'; verifiedAt: number }>) {
  const map = new Map(peers.map(p => [p.id, { peerId: p.id, isConnected: true, isVerified: true, direction: p.direction, verifiedAt: p.verifiedAt }]));
  return { peers: map, myPeerId: ID('f'), myPosition: 0, degree: map.size, sendMessage: () => {}, on: () => {}, off: () => {} } as any;
}

describe('Guard と M1 の選び方 (A3)', () => {
  beforeAll(async () => {
    await sodiumReady;
  });

  it('重み付き乱数は重みに比例する', () => {
    const counts = [0, 0];
    for (let i = 0; i < 4000; i++) counts[secureWeightedIndex([1, 3])]++;
    expect(counts[1] / 4000).toBeGreaterThan(0.68);
    expect(counts[1] / 4000).toBeLessThan(0.82);
  });

  it('Guard は自分で選んだ (outbound) 長く観測している隣人が選ばれやすい', () => {
    const now = Date.now();
    const pm = fakePm([
      { id: ID('a'), direction: 'outbound', verifiedAt: now - OBSERVATION_SATURATION_MS },
      { id: ID('b'), direction: 'inbound', verifiedAt: now },
    ]);
    const router = new DandelionRouter(pm);
    const candidates = [ID('a'), ID('b')].map(peerId => ({ peerId, pubkey: new Uint8Array(32) }));

    let picksA = 0;
    for (let i = 0; i < 2000; i++) {
      router.resetPinnedGuard();
      if (router.getPinnedGuard(candidates)?.peerId === ID('a')) picksA++;
    }
    // 重み 6 : 1 → 約 86%
    expect(picksA / 2000).toBeGreaterThan(0.78);
  });

  it('inbound しか居なくても Guard は選べる (拒否ではなく優先順位)', () => {
    const pm = fakePm([{ id: ID('c'), direction: 'inbound', verifiedAt: Date.now() }]);
    const router = new DandelionRouter(pm);
    expect(router.getPinnedGuard([{ peerId: ID('c'), pubkey: new Uint8Array(32) }])?.peerId).toBe(ID('c'));
  });

  it('M1 は Guard の隣人表で長く見えている候補が選ばれやすい', () => {
    const pm = fakePm([{ id: ID('a'), direction: 'outbound', verifiedAt: Date.now() }]);
    const dandelion = new DandelionRouter(pm);
    const circuit = new OnionCircuit(pm, new MessageDispatcher(), dandelion);
    const now = Date.now();
    const neighbors = (circuit as any).guardNeighbors as Map<string, any>;
    neighbors.set(ID('d'), { pubkey: sodium.randombytes_buf(32), firstSeen: now - OBSERVATION_SATURATION_MS, seenAt: now });
    neighbors.set(ID('e'), { pubkey: sodium.randombytes_buf(32), firstSeen: now, seenAt: now });

    let picksOld = 0;
    for (let i = 0; i < 2000; i++) {
      if ((circuit as any).pickMiddle(ID('a'), new Set())?.peerId === ID('d')) picksOld++;
    }
    // 重み 1.25 : 0.25 → 約 83%
    expect(picksOld / 2000).toBeGreaterThan(0.75);
    circuit.destroy();
  });
});

import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { sodiumReady } from '../../src/crypto/sodium';
import { WireType } from '../../src/network/wire/WireTypes';
import { WebRTCPeer } from '../../src/network/WebRTCPeer';
import { isLoopbackTrackerUrl } from '../../src/network/TrackerUrl';
import { originKeyOf, sameOrigin, ORIGIN_LAN, ORIGIN_PENDING, ORIGIN_UNKNOWN } from '../../src/network/NetGroup';
import { installFakeWebRTC, resetFakeWebRTC } from '../helpers/webrtc';
import { createSimNode, link, stopAll, sleep, makePacket, type SimNode } from '../helpers/onionNet';

/**
 * オニオンの各段 (作者・Guard・M1) が同じ家・同じ端末にならないこと。
 *
 * 1 台で複数のノードを立てると、作者の回路が自分の別のノードだけで組めてしまっていた。
 *   - Guard が作者と同じ家 → M1 から見た前の段の IP が作者の IP。M1 だけで作者が分かる
 *   - M1 が作者と同じ家   → M1 が出す要求や投稿が作者の IP から出る
 * 攻撃者が 1 台で多数のノードを立てる場合も同じ形になる。
 */

const OPTS = (extra: Record<string, unknown> = {}) => ({
  coverIntervalMs: 15, relayDelayMs: 1, echoTimeoutMs: 2000, readyWaitMs: 300, ...extra,
});

/** viewer から見た target の出所を決める (null = まだ求めていない) */
function setOrigin(viewer: SimNode, target: SimNode, origin: string | null): void {
  (viewer.peerManager as any)._peers.get(target.identity.peerId).origin = origin;
}

function received(to: SimNode, from: SimNode, type: number) {
  return to.inbox.filter(m => m.from === from.identity.peerId && m.type === type);
}

beforeAll(async () => {
  await sodiumReady;
});

describe('出所の鍵 (originKeyOf)', () => {
  it('同じ IPv4 は同じ鍵、違えば違う鍵。鍵に IP は残らない', () => {
    const a = originKeyOf('203.0.113.7', 'srflx');
    expect(originKeyOf('203.0.113.7', 'prflx')).toBe(a);
    expect(originKeyOf('203.0.113.8', 'srflx')).not.toBe(a);
    expect(a).not.toContain('203');
    expect(a.startsWith('o:')).toBe(true);
  });

  it('IPv6 は上位 56 ビット (同じ家の別の端末) が同じなら同じ鍵', () => {
    const a = originKeyOf('2001:db8:1234:5600::1', 'host');
    expect(originKeyOf('2001:db8:1234:56ff:abcd::9', 'srflx')).toBe(a);
    expect(originKeyOf('2001:db8:1234:5700::1', 'srflx')).not.toBe(a);
  });

  it('私設アドレス・mDNS・アドレスの載らない host 候補は同じ LAN、リレーと不明は比べない', () => {
    expect(originKeyOf('192.168.1.20', 'host')).toBe(ORIGIN_LAN);
    expect(originKeyOf('fe80::1', 'host')).toBe(ORIGIN_LAN);
    expect(originKeyOf('3f2a9c1e.local', 'host')).toBe(ORIGIN_LAN);
    expect(originKeyOf(undefined, 'host')).toBe(ORIGIN_LAN);
    expect(originKeyOf('203.0.113.7', 'relay')).toBe(ORIGIN_UNKNOWN);
    expect(originKeyOf(undefined, null)).toBe(ORIGIN_UNKNOWN);
  });

  it('比べ方: 不明は同じとみなさず、まだ求めていないものは同じとみなす', () => {
    expect(sameOrigin('o:1', 'o:1')).toBe(true);
    expect(sameOrigin(ORIGIN_LAN, ORIGIN_LAN)).toBe(true);
    expect(sameOrigin('o:1', 'o:2')).toBe(false);
    expect(sameOrigin(ORIGIN_UNKNOWN, ORIGIN_UNKNOWN)).toBe(false);
    expect(sameOrigin(ORIGIN_PENDING, 'o:2')).toBe(true);
  });

  it('接続の統計から、相手の出所と、外から見えている自分の出所を求める', async () => {
    installFakeWebRTC();
    try {
      const peer = new WebRTCPeer({
        localId: 'a'.repeat(32), remoteId: 'b'.repeat(32), initiator: true,
        onSignal: () => {}, onConnect: () => {}, onDisconnect: () => {}, onData: () => {},
      });
      expect(peer.origin).toBeNull();
      (peer as any).pc = {
        close: () => {},
        getStats: async () => new Map<string, any>([
          ['t', { id: 't', type: 'transport', selectedCandidatePairId: 'p' }],
          ['p', { id: 'p', type: 'candidate-pair', localCandidateId: 'l', remoteCandidateId: 'r' }],
          ['l', { id: 'l', type: 'local-candidate', candidateType: 'srflx', address: '198.51.100.4' }],
          ['l6', { id: 'l6', type: 'local-candidate', candidateType: 'srflx', address: '2001:db8:aa::5' }],
          ['h', { id: 'h', type: 'local-candidate', candidateType: 'host', address: '192.168.0.3' }],
          ['r', { id: 'r', type: 'remote-candidate', candidateType: 'srflx', address: '198.51.100.4' }],
        ]),
      };
      await peer.resolveNetGroup();
      // 相手は自分と同じ公開 IP (同じ端末・同じ家) にいる
      expect(peer.origin).toBe(originKeyOf('198.51.100.4', 'srflx'));
      expect([...peer.localOrigins].sort()).toEqual(
        [originKeyOf('198.51.100.4', 'srflx'), originKeyOf('2001:db8:aa::5', 'srflx')].sort(),
      );
    } finally {
      resetFakeWebRTC();
    }
  });
});

describe('回路の各段が同じ家にならない', () => {
  let nodes: SimNode[] = [];
  afterEach(() => stopAll(nodes));

  it('Guard の候補から、同じ LAN・自分と同じ公開 IP・出所の分からないうちの隣人を除く', async () => {
    const alice = await createSimNode('alice', OPTS());
    const lan = await createSimNode('lan', OPTS());
    const sameIp = await createSimNode('same-ip', OPTS());
    const pending = await createSimNode('pending', OPTS());
    const other = await createSimNode('other', OPTS());
    nodes = [alice, lan, sameIp, pending, other];
    for (const n of [lan, sameIp, pending, other]) link(alice, n);
    setOrigin(alice, lan, ORIGIN_LAN);
    setOrigin(alice, sameIp, 'o:home');
    alice.peerManager.noteSelfOrigin('o:home');
    setOrigin(alice, pending, null);
    setOrigin(alice, other, 'o:elsewhere');

    const ids = (alice.circuit as any).guardCandidates().map((h: any) => h.peerId);
    expect(ids).toEqual([other.identity.peerId]);
  });

  it('Guard は作者と同じ出所の隣人を紹介せず、作者の回路の M1 はほかの家のノードになる', async () => {
    const alice = await createSimNode('alice', OPTS());
    const guard = await createSimNode('guard', OPTS());
    const twin = await createSimNode('twin', OPTS()); // alice と同じ家の別のノード
    const m2 = await createSimNode('m2', OPTS());
    const w1 = await createSimNode('w1', OPTS());
    const w2 = await createSimNode('w2', OPTS());
    nodes = [alice, guard, twin, m2, w1, w2];
    link(alice, guard); link(guard, twin); link(guard, m2); link(m2, w1); link(w1, w2); link(twin, w1);
    setOrigin(alice, guard, 'o:guard');
    setOrigin(guard, alice, 'o:home');
    setOrigin(guard, twin, 'o:home');
    setOrigin(guard, m2, 'o:elsewhere');

    // 回路を動かすのは alice だけ (ほかのノードが自分の回路で出すセルと混ざらないように)
    alice.circuit.start();
    await sleep(120); // Guard の隣人表 (PEX)
    const table = [...(alice.circuit as any).guardNeighbors.keys()];
    expect(table).toContain(m2.identity.peerId);
    expect(table).not.toContain(twin.identity.peerId);

    for (let i = 0; i < 4; i++) expect(await alice.gossip.broadcast(makePacket([i, 7]))).toBe(true);
    // Guard は alice のセル (cover を含む) を twin へ一度も渡していない
    expect(received(twin, guard, WireType.ONION_STEM)).toHaveLength(0);
    expect(received(m2, guard, WireType.ONION_STEM).length).toBeGreaterThan(0);
  });

  it('Guard は同じ出所どうしの中継と、自分と同じ家の送り主の中継を断る', async () => {
    const guard = await createSimNode('guard', OPTS());
    const alice = await createSimNode('alice', OPTS());
    const twin = await createSimNode('twin', OPTS());
    const m2 = await createSimNode('m2', OPTS());
    const housemate = await createSimNode('housemate', OPTS());
    nodes = [guard, alice, twin, m2, housemate];
    for (const n of [alice, twin, m2, housemate]) link(guard, n);
    setOrigin(guard, alice, 'o:home');
    setOrigin(guard, twin, 'o:home');
    setOrigin(guard, m2, 'o:elsewhere');
    setOrigin(guard, housemate, ORIGIN_LAN);

    const allowed = (from: SimNode, to: SimNode) =>
      (guard.circuit as any).relayAllowed(from.identity.peerId, to.identity.peerId);
    expect(allowed(alice, twin)).toBe(false);
    expect(allowed(alice, m2)).toBe(true);
    // Guard と同じ家の送り主: M1 から見た前の段 (= Guard) の IP が送り主の IP になる
    expect(allowed(housemate, m2)).toBe(false);
    guard.peerManager.noteSelfOrigin('o:home');
    expect(allowed(alice, m2)).toBe(false);
    // 出所が分かるまでは渡さない
    setOrigin(guard, m2, null);
    expect(allowed(twin, m2)).toBe(false);
  });

  it('トラッカーが自分の端末 (開発用の網) のときだけ制限を外す', async () => {
    const alice = await createSimNode('alice', OPTS());
    const lan = await createSimNode('lan', OPTS());
    nodes = [alice, lan];
    link(alice, lan);
    setOrigin(alice, lan, ORIGIN_LAN);
    expect((alice.circuit as any).guardCandidates()).toHaveLength(0);
    (alice.peerManager as any).allowSameOriginHops = () => true;
    expect((alice.circuit as any).guardCandidates()).toHaveLength(1);

    expect(isLoopbackTrackerUrl('ws://localhost:3000/ws')).toBe(true);
    expect(isLoopbackTrackerUrl('ws://127.0.0.1:8080/ws')).toBe(true);
    expect(isLoopbackTrackerUrl('wss://[::1]/ws')).toBe(true);
    expect(isLoopbackTrackerUrl('wss://ozzy-tracker.example.net/ws')).toBe(false);
    expect(isLoopbackTrackerUrl(null)).toBe(false);
  });
});

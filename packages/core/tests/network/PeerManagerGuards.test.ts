import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest';
import { NodeIdentity } from '../../src/crypto/NodeIdentity';
import { sodiumReady } from '../../src/crypto/sodium';
import { MessageDispatcher } from '../../src/network/MessageDispatcher';
import { PeerManager, type GuardSource } from '../../src/network/PeerManager';
import { RateLimiter } from '../../src/network/RateLimiter';
import { RING_MESH } from '../../src/constants';
import { FAST } from '../helpers/guardFixtures';

const hex = (n: number) => n.toString(16).padStart(32, '0');

/** 接続状態を持つ偽のトラッカー */
function fakeSignaling() {
  const s: any = {
    isConnected: false,
    connect: vi.fn(async () => { s.isConnected = true; }),
    disconnect: vi.fn(() => { s.isConnected = false; }),
    sendRelay: vi.fn(),
    on: vi.fn(),
  };
  return s;
}

function fakePeer(peerId: string, over: Record<string, any> = {}) {
  return {
    peerId,
    position: 0.5,
    rtt: 0,
    isConnected: true,
    isConnecting: false,
    isVerified: true,
    direction: 'inbound',
    pubkey: new Uint8Array(32).fill(7),
    verifiedAt: 1_000,
    netGroup: 'g',
    send: vi.fn(),
    close: vi.fn(),
    ...over,
  };
}

describe('PeerManager: 信頼 Guard の保護・接続維持・トラッカー切り離し', () => {
  let identity: NodeIdentity;

  beforeAll(async () => {
    await sodiumReady;
    identity = await NodeIdentity.mine(FAST);
  });

  let signaling: any;
  let pm: PeerManager;
  let connectSpy: ReturnType<typeof vi.fn>;

  function make(options: Record<string, any> = {}) {
    signaling = fakeSignaling();
    pm = new PeerManager(identity, new MessageDispatcher(), signaling, {
      powParams: FAST,
      rateLimiter: new RateLimiter(),
      allowMissingDtlsFingerprint: true,
      ...options,
    });
    // 実際の WebRTC は張らない。呼ばれた引数だけ見る
    connectSpy = vi.fn();
    (pm as any).connect = connectSpy;
    return pm;
  }

  function source(wanted: string[], trusted: string[] = []): GuardSource & { wanted: string[] } {
    const src = {
      wanted,
      wantedGuardIds: () => src.wanted,
      isTrusted: (id: string) => trusted.includes(id),
    };
    return src;
  }

  const putPeer = (p: any) => (pm as any)._peers.set(p.peerId, p);

  afterEach(() => {
    pm?.stop();
    vi.useRealTimers();
  });

  describe('eviction', () => {
    function fill(n: number, guardId: string) {
      // 外される順で最後尾になる条件: inbound・最も新しく検証・リング上で最も遠い
      // (両隣に詰める。片側だけに詰めると、反対側に 1 人だけいる相手が「その方向の隣」として保護される)
      for (let i = 1; i <= n; i++) {
        const offset = (i % 2 === 0 ? 1 : -1) * 0.001 * i;
        putPeer(fakePeer(hex(i), { position: (identity.position + offset + 1) % 1, verifiedAt: 1_000 + i }));
      }
      putPeer(fakePeer(guardId, { position: (identity.position + 0.5) % 1, verifiedAt: 999_999 }));
    }

    it('信頼 Guard は、次数超過の調整で外されない', () => {
      make();
      const guardId = hex(0xabc);
      pm.setGuardSource(source([guardId], [guardId]));
      fill(RING_MESH.MAX_DEGREE + 4, guardId);

      pm.rebalance();
      expect(pm.verifiedPeers.length).toBe(RING_MESH.MAX_DEGREE);
      expect(pm.peers.has(guardId)).toBe(true);
    });

    it('(対照) 信頼 Guard として扱わなければ、同じ条件で最初に外される', () => {
      make();
      const guardId = hex(0xabc);
      fill(RING_MESH.MAX_DEGREE + 4, guardId);
      pm.rebalance();
      expect(pm.peers.has(guardId)).toBe(false);
    });

    it('新顔の信頼 Guard (outbound) も、枠を超えても諦めない', () => {
      make();
      const guardId = hex(0xabc);
      pm.setGuardSource(source([guardId], [guardId]));
      for (let i = 1; i <= RING_MESH.MAX_DEGREE; i++) {
        putPeer(fakePeer(hex(i), { direction: 'outbound', position: (identity.position + 0.001 * i) % 1 }));
      }
      putPeer(fakePeer(guardId, { direction: 'outbound', position: (identity.position + 0.5) % 1, verifiedAt: 9e9 }));
      pm.rebalance(guardId);
      expect(pm.peers.has(guardId)).toBe(true);
    });

    it('Guard 役 (maxDegree=256) は、通常の上限を超えても外さない', () => {
      make({ maxDegree: 256 });
      for (let i = 1; i <= 100; i++) putPeer(fakePeer(hex(i), { position: (identity.position + 0.003 * i) % 1 }));
      pm.rebalance();
      expect(pm.verifiedPeers.length).toBe(100);
    });
  });

  describe('待ち受け Guard への接続', () => {
    beforeEach(() => vi.useFakeTimers());

    it('起動時に待ち受け Guard へ outbound で接続しに行く', async () => {
      make();
      const g = hex(0x111);
      pm.setGuardSource(source([g]));
      await pm.start();
      expect(connectSpy).toHaveBeenCalledWith(g, true);
    });

    it('つながっていなければ 30 秒ごとの確認で、間隔を空けながら再接続する', async () => {
      make();
      const g = hex(0x111);
      pm.setGuardSource(source([g]));
      await pm.start();
      expect(connectSpy).toHaveBeenCalledTimes(1); // t=0

      await vi.advanceTimersByTimeAsync(30_000);   // t=30s: 最初の間隔 (30s) が過ぎた
      expect(connectSpy).toHaveBeenCalledTimes(2);
      await vi.advanceTimersByTimeAsync(30_000);   // t=60s: 間隔は 60s に延びている
      expect(connectSpy).toHaveBeenCalledTimes(2);
      await vi.advanceTimersByTimeAsync(30_000);   // t=90s
      expect(connectSpy).toHaveBeenCalledTimes(3);
    });

    it('検証済みでつながったら張りに行かない。切れたらまた張りに行く', async () => {
      make();
      const g = hex(0x111);
      pm.setGuardSource(source([g]));
      await pm.start();
      putPeer(fakePeer(g, { direction: 'outbound' }));
      connectSpy.mockClear();

      await vi.advanceTimersByTimeAsync(120_000);
      expect(connectSpy).not.toHaveBeenCalled();

      (pm as any)._peers.delete(g);
      await vi.advanceTimersByTimeAsync(30_000);
      expect(connectSpy).toHaveBeenCalledWith(g, true);
    });

    it('待ち受けでなくなった Guard には、もう張りに行かない', async () => {
      make();
      const g = hex(0x111);
      const src = source([g]);
      pm.setGuardSource(src);
      await pm.start();
      src.wanted = [];
      connectSpy.mockClear();
      await vi.advanceTimersByTimeAsync(300_000);
      expect(connectSpy).not.toHaveBeenCalled();
    });

    it('Guard が 1 つもつながっていないとき、トラッカーから切れていれば繋ぎ直す', async () => {
      make();
      const g = hex(0x111);
      pm.setGuardSource(source([g]));
      await pm.start();
      expect(signaling.connect).toHaveBeenCalledTimes(1);

      await vi.advanceTimersByTimeAsync(60_000); // 上限 (60 秒) で切り離される
      expect(signaling.isConnected).toBe(false);
      connectSpy.mockClear();

      await vi.advanceTimersByTimeAsync(30_000); // 次の確認でトラッカーへ繋ぎ直して、接続しに行く
      expect(signaling.connect.mock.calls.length).toBeGreaterThanOrEqual(2);
      expect(connectSpy).toHaveBeenCalledWith(g, true);
    });

    it('待ち受け Guard が無ければ、何も張りに行かずトラッカーにも繋ぎ直さない (次数が足りていれば)', async () => {
      make();
      pm.setGuardSource(source([]));
      for (let i = 1; i <= 5; i++) putPeer(fakePeer(hex(i)));
      await pm.start();
      await vi.advanceTimersByTimeAsync(15_000);
      signaling.connect.mockClear();
      await vi.advanceTimersByTimeAsync(120_000);
      expect(connectSpy).not.toHaveBeenCalled();
      expect(signaling.connect).not.toHaveBeenCalled();
    });
  });

  describe('トラッカーからの切り離し', () => {
    beforeEach(() => vi.useFakeTimers());

    it('待ち受け Guard が無ければ、従来どおり 15 秒で切り離す', async () => {
      make();
      await pm.start();
      await vi.advanceTimersByTimeAsync(14_999);
      expect(signaling.disconnect).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(1);
      expect(signaling.disconnect).toHaveBeenCalledTimes(1);
    });

    it('待ち受け Guard の検証が済むまでは切り離さず、上限 60 秒で切り離す', async () => {
      make();
      pm.setGuardSource(source([hex(0x111)]));
      await pm.start();
      await vi.advanceTimersByTimeAsync(15_000);
      await vi.advanceTimersByTimeAsync(40_000); // t=55s
      expect(signaling.disconnect).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(4_900);  // t=59.9s
      expect(signaling.disconnect).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(100);    // t=60s
      expect(signaling.disconnect).toHaveBeenCalledTimes(1);
    });

    it('待ち受け Guard が検証済みになったら、まもなく切り離す', async () => {
      make();
      const g = hex(0x111);
      pm.setGuardSource(source([g]));
      await pm.start();
      await vi.advanceTimersByTimeAsync(20_000);
      expect(signaling.disconnect).not.toHaveBeenCalled();

      putPeer(fakePeer(g, { direction: 'outbound' }));
      await vi.advanceTimersByTimeAsync(2_000);
      expect(signaling.disconnect).toHaveBeenCalledTimes(1);
    });

    it('接続はできたが未検証の Guard は「検証済み」とは見なさない', async () => {
      make();
      const g = hex(0x111);
      pm.setGuardSource(source([g]));
      await pm.start();
      putPeer(fakePeer(g, { isVerified: false }));
      await vi.advanceTimersByTimeAsync(30_000);
      expect(signaling.disconnect).not.toHaveBeenCalled();
    });

    it('Guard 役 (keepTrackerAttached) は決して切り離さない', async () => {
      make({ keepTrackerAttached: true });
      await pm.start();
      await vi.advanceTimersByTimeAsync(10 * 60_000);
      expect(signaling.disconnect).not.toHaveBeenCalled();
      expect(signaling.isConnected).toBe(true);
    });
  });

  describe('stop()', () => {
    beforeEach(() => vi.useFakeTimers());

    it('追加したタイマーを残さない (切り離し延長中・再接続の予定があっても)', async () => {
      make();
      pm.setGuardSource(source([hex(0x111), hex(0x222)]));
      await pm.start();
      await vi.advanceTimersByTimeAsync(20_000); // 切り離しの延長中
      expect(vi.getTimerCount()).toBeGreaterThan(0);

      pm.stop();
      expect(vi.getTimerCount()).toBe(0);

      connectSpy.mockClear();
      await vi.advanceTimersByTimeAsync(10 * 60_000);
      expect(connectSpy).not.toHaveBeenCalled();
    });

    it('停止後は待ち受け Guard にも張りに行かない', async () => {
      make();
      pm.setGuardSource(source([hex(0x111)]));
      pm.stop();
      connectSpy.mockClear();
      await pm.maintainWantedGuards();
      expect(connectSpy).not.toHaveBeenCalled();
    });
  });
});

import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest';
import { NodeIdentity } from '../../src/crypto/NodeIdentity';
import { sodiumReady } from '../../src/crypto/sodium';
import { MessageDispatcher } from '../../src/network/MessageDispatcher';
import { PeerManager, type GuardSource } from '../../src/network/PeerManager';
import { RateLimiter } from '../../src/network/RateLimiter';
import { GUARD_MAX_DEGREE, RING_MESH } from '../../src/constants';
import { FAST } from '../helpers/guardFixtures';

const hex = (n: number) => n.toString(16).padStart(32, '0');

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
    peerId, position: 0.5, rtt: 0, isConnected: true, isConnecting: false, isVerified: true, direction: 'inbound',
    pubkey: new Uint8Array(32).fill(7), verifiedAt: 1_000, netGroup: 'g', send: vi.fn(), close: vi.fn(), ...over,
  };
}

/**
 * Guard 同士のバックボーン (history v2 §4.4): Guard 役は、リストの他の信頼 Guard すべてとつなぎ続ける。
 * 待ち受け Guard (利用者側のサンプル) と同じ機構 (maintainWantedGuards) を使う。
 */
describe('PeerManager: Guard のバックボーン', () => {
  let identity: NodeIdentity;
  beforeAll(async () => {
    await sodiumReady;
    identity = await NodeIdentity.mine(FAST);
  });

  let pm: PeerManager;
  let signaling: any;
  let connectSpy: ReturnType<typeof vi.fn>;

  function make(options: Record<string, any> = {}) {
    signaling = fakeSignaling();
    pm = new PeerManager(identity, new MessageDispatcher(), signaling, {
      powParams: FAST, rateLimiter: new RateLimiter(), allowMissingDtlsFingerprint: true, ...options,
    });
    connectSpy = vi.fn();
    (pm as any).connect = connectSpy;
    return pm;
  }
  const putPeer = (p: any) => (pm as any)._peers.set(p.peerId, p);
  /** 自分より peerId の小さい / 大きい Guard の id (どちらも 32 文字の hex) */
  const lower = (n: number) => '0'.repeat(31) + (n % 10).toString(16);
  const higher = (n: number) => 'f'.repeat(31) + (n % 16).toString(16);

  afterEach(() => {
    pm?.stop();
    vi.useRealTimers();
  });

  it('★両側が同時に張ると offer がすれ違うので、peerId の小さい側だけが張る: 自分より大きい Guard へは起動時に張りに行く。小さい Guard は相手からの接続を待ち、45 秒たっても来なければ自分から張る', async () => {
    vi.useFakeTimers();
    make({ keepTrackerAttached: true, maxDegree: GUARD_MAX_DEGREE });
    const small = lower(1);
    const big = higher(1);
    expect(small < identity.peerId).toBe(true);
    expect(big > identity.peerId).toBe(true);
    pm.setBackboneSource(() => [small, big]);
    await pm.start();
    expect(connectSpy).toHaveBeenCalledWith(big, true);
    expect(connectSpy).not.toHaveBeenCalledWith(small, true);

    await vi.advanceTimersByTimeAsync(30_000); // 次の確認 (30 秒)。まだ猶予の内
    expect(connectSpy).not.toHaveBeenCalledWith(small, true);
    await vi.advanceTimersByTimeAsync(30_000); // 60 秒: 猶予 (45 秒) を過ぎた
    expect(connectSpy).toHaveBeenCalledWith(small, true);
  });

  it('★相手が先に張ってきたら (検証済みの inbound)、自分からは張らない。切れたらまた張りに行く', async () => {
    vi.useFakeTimers();
    make({ keepTrackerAttached: true, maxDegree: GUARD_MAX_DEGREE });
    const small = lower(2);
    pm.setBackboneSource(() => [small]);
    await pm.start();
    putPeer(fakePeer(small, { direction: 'inbound' }));
    await vi.advanceTimersByTimeAsync(120_000);
    expect(connectSpy).not.toHaveBeenCalled();
    (pm as any)._peers.delete(small);
    await vi.advanceTimersByTimeAsync(30_000);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(connectSpy).toHaveBeenCalledWith(small, true);
  });

  it('★待ち受け Guard (利用者側のサンプル) と重ねて設定できる。重複は 1 回、自分自身は含めない', async () => {
    vi.useFakeTimers();
    make({ keepTrackerAttached: true, maxDegree: GUARD_MAX_DEGREE });
    const a = higher(3);
    const b = higher(4);
    const src: GuardSource = { wantedGuardIds: () => [a], isTrusted: () => false };
    pm.setGuardSource(src);
    pm.setBackboneSource(() => [a, b, identity.peerId]);
    await pm.start();
    const targets = connectSpy.mock.calls.map(c => c[0]).sort();
    expect(targets).toEqual([a, b].sort());
    expect(connectSpy.mock.calls.every(c => c[1] === true)).toBe(true);
  });

  it('バックボーンの設定を外せば、もう張りに行かない', async () => {
    vi.useFakeTimers();
    make({ keepTrackerAttached: true, maxDegree: GUARD_MAX_DEGREE });
    pm.setBackboneSource(() => [higher(5)]);
    await pm.start();
    expect(connectSpy).toHaveBeenCalledTimes(1);
    pm.setBackboneSource(null);
    connectSpy.mockClear();
    await vi.advanceTimersByTimeAsync(10 * 60_000);
    expect(connectSpy).not.toHaveBeenCalled();
  });

  it('★バックボーンの接続は、利用者が次数の上限まで押し寄せても外されない (信頼 Guard として保護される)。上限は GUARD_MAX_DEGREE のまま', () => {
    make({ keepTrackerAttached: true, maxDegree: GUARD_MAX_DEGREE });
    const guards = Array.from({ length: 5 }, (_, i) => hex(0xb0 + i));
    const src: GuardSource = { wantedGuardIds: () => [], isTrusted: (id) => guards.includes(id) };
    pm.setGuardSource(src);
    pm.setBackboneSource(() => guards);
    // 他の Guard が先に居て、その後ろに利用者が上限を超えて押し寄せる (Guard は最も新しく検証された順に外される側)
    guards.forEach((g, i) => putPeer(fakePeer(g, { position: (identity.position + 0.5 + i * 0.001) % 1, verifiedAt: 9e9 })));
    for (let i = 1; i <= GUARD_MAX_DEGREE + 20; i++) putPeer(fakePeer(hex(i), { position: (identity.position + 0.0001 * i) % 1, verifiedAt: 1_000 + i }));
    pm.rebalance();
    expect(pm.verifiedPeers.length).toBe(GUARD_MAX_DEGREE);
    for (const g of guards) expect(pm.peers.has(g), g).toBe(true);
    // 実効の利用者枠 = 上限 − バックボーンの数
    expect(pm.verifiedPeers.filter(p => !guards.includes(p.peerId)).length).toBe(GUARD_MAX_DEGREE - guards.length);
    expect(GUARD_MAX_DEGREE).toBeGreaterThan(RING_MESH.MAX_DEGREE);
  });

  it('★予約枠: バックボーンの数だけ、握手待ちの別枠が増える (一般枠が満杯でも Guard へ張れる)', () => {
    make({ keepTrackerAttached: true, maxDegree: GUARD_MAX_DEGREE });
    const ids = Array.from({ length: 10 }, (_, i) => hex(0xc0 + i));
    const cap0 = (pm as any).reservedDialCap();
    pm.setBackboneSource(() => ids);
    expect((pm as any).reservedDialCap()).toBe(cap0 + 10);
    // 予約枠のぶんだけ、実際に握手待ちを受け入れる
    for (let i = 0; i < cap0 + 10; i++) {
      expect((pm as any).admitPending('self', true), `#${i}`).toBe(true);
      (pm as any)._peers.set(hex(0xd00 + i), fakePeer(hex(0xd00 + i), { isVerified: false, isConnected: false }));
      (pm as any).pendingMeta.set(hex(0xd00 + i), { source: 'self', startedAt: Date.now(), reserved: true });
    }
    expect((pm as any).admitPending('self', true)).toBe(false);
    // 巨大なリストでも予約枠は 32 件まで
    pm.setBackboneSource(() => Array.from({ length: 200 }, (_, i) => hex(0xe00 + i)));
    expect((pm as any).reservedDialCap()).toBe(cap0 + 32);
  });

  it('isTrustedGuard: 検証済みで、リストの peerId と公開鍵が一致する相手だけ true (TunnelRelay がバックボーンの広い枠を許す判定に使う)', () => {
    make();
    const g = hex(0xab);
    pm.setGuardSource({ wantedGuardIds: () => [], isTrusted: (id, key) => id === g && key?.[0] === 7 });
    putPeer(fakePeer(g));
    putPeer(fakePeer(hex(0xac)));
    putPeer(fakePeer(hex(0xad), { isVerified: false }));
    expect(pm.isTrustedGuard(g)).toBe(true);
    expect(pm.isTrustedGuard(hex(0xac))).toBe(false);
    expect(pm.isTrustedGuard(hex(0xad))).toBe(false);
    expect(pm.isTrustedGuard(hex(0xff))).toBe(false);
  });
});

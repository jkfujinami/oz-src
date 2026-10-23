import { describe, it, expect, beforeEach, vi } from 'vitest';
import { PeerMisbehaviorManager, ViolationType } from '../../src/network/PeerMisbehaviorManager';

describe('PeerMisbehaviorManager (局所的不正検知・悪意ノード隔離エンジン)', () => {
  let manager: PeerMisbehaviorManager;
  const PEER_A = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  const PEER_B = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

  beforeEach(() => {
    manager = new PeerMisbehaviorManager({
      banThreshold: 100,
      banDurationMs: 1000, // テスト用に1秒
      decayIntervalMs: 200, // テスト用に200ms
    });
  });

  it('即時BAN違反 (不正署名/PoW偽造) でスコアが100点に達し即座にBANされる', () => {
    expect(manager.isBanned(PEER_A)).toBe(false);

    const banned = manager.recordViolation(PEER_A, ViolationType.INVALID_SIGNATURE, 'Invalid Ed25519 signature');
    expect(banned).toBe(true);
    expect(manager.isBanned(PEER_A)).toBe(true);
  });

  it('段階的違反 (レート制限超過 25点) が累積して閾値に達するとBANされる', () => {
    expect(manager.recordViolation(PEER_B, ViolationType.RATE_LIMIT_EXCEEDED)).toBe(false);
    expect(manager.getScore(PEER_B)).toBe(25);
    expect(manager.isBanned(PEER_B)).toBe(false);

    expect(manager.recordViolation(PEER_B, ViolationType.RATE_LIMIT_EXCEEDED)).toBe(false);
    expect(manager.getScore(PEER_B)).toBe(50);

    expect(manager.recordViolation(PEER_B, ViolationType.RATE_LIMIT_EXCEEDED)).toBe(false);
    expect(manager.getScore(PEER_B)).toBe(75);

    // 4回目の違反で 100 点に達し BAN 執行
    const banned = manager.recordViolation(PEER_B, ViolationType.RATE_LIMIT_EXCEEDED);
    expect(banned).toBe(true);
    expect(manager.isBanned(PEER_B)).toBe(true);
  });

  it('スコアの半減期 (Decay) により、時間が経つとペナルティが半減して回復する', async () => {
    manager.recordViolation(PEER_A, 50, 'Moderate violation');
    expect(manager.getScore(PEER_A)).toBe(50);

    // 250ms 経過 (decayIntervalMs = 200ms)
    await new Promise((resolve) => setTimeout(resolve, 250));

    // 50 / 2 = 25点に減衰していること
    expect(manager.getScore(PEER_A)).toBe(25);

    // さらに 250ms 経過
    await new Promise((resolve) => setTimeout(resolve, 250));

    // 25 / 2 = 12点に減衰していること
    expect(manager.getScore(PEER_A)).toBe(12);
  });

  it('BAN期間が経過すると自動的にBANが解除される', async () => {
    manager.banPeer(PEER_A, 150, 'Short test ban');
    expect(manager.isBanned(PEER_A)).toBe(true);

    // 200ms 待機 (banDuration = 150ms 経過)
    await new Promise((resolve) => setTimeout(resolve, 200));

    expect(manager.isBanned(PEER_A)).toBe(false);
  });

  it('手動での unban および clear が正常に機能する', () => {
    manager.banPeer(PEER_A, 10000);
    expect(manager.isBanned(PEER_A)).toBe(true);

    manager.unbanPeer(PEER_A);
    expect(manager.isBanned(PEER_A)).toBe(false);

    manager.recordViolation(PEER_B, 50);
    manager.clear();
    expect(manager.getScore(PEER_B)).toBe(0);
  });
});

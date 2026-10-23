import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  DandelionRouter,
  DANDELION_CONFIG,
  secureRandomIndex,
  secureWeightedIndex,
} from '../../src/network/gossip/DandelionRouter';

const ID = (c: string) => c.repeat(32);
const hop = (peerId: string) => ({ peerId, pubkey: new Uint8Array(32) });

function fakePm(ids: string[]) {
  const peers = new Map<string, any>(
    ids.map(id => [id, { peerId: id, isConnected: true, isVerified: true, direction: 'outbound', verifiedAt: Date.now() }]),
  );
  return { peers, myPeerId: ID('f'), myPosition: 0, get degree() { return peers.size; }, sendMessage: vi.fn(), on: vi.fn(), off: vi.fn() } as any;
}

describe('DandelionRouter: エコーの待ち合わせ', () => {
  let router: DandelionRouter;

  beforeEach(() => {
    vi.useFakeTimers();
    router = new DandelionRouter(fakePm([]));
  });
  afterEach(() => vi.useRealTimers());

  it('エコーが届けば true で解決する', async () => {
    const p = router.awaitEcho('x', 1000);
    router.notifyEcho('x');
    await expect(p).resolves.toBe(true);
  });

  it('期限までに届かなければ false で解決する', async () => {
    const p = router.awaitEcho('x', 1000);
    await vi.advanceTimersByTimeAsync(999);
    let settled = false;
    p.then(() => { settled = true; });
    await Promise.resolve();
    expect(settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    await expect(p).resolves.toBe(false);
  });

  it('同じ ID を待つ全員に 1 回のエコーで通知する', async () => {
    const a = router.awaitEcho('same', 1000);
    const b = router.awaitEcho('same', 5000);
    router.notifyEcho('same');
    await expect(Promise.all([a, b])).resolves.toEqual([true, true]);
    expect(vi.getTimerCount()).toBe(0); // 解決した待機者のタイマーは片付けられる
  });

  it('先にタイムアウトした待機者がいても、残りの待機者のエコーは取りこぼさない', async () => {
    const short = router.awaitEcho('id', 100);
    const long = router.awaitEcho('id', 10_000);
    await vi.advanceTimersByTimeAsync(100);
    await expect(short).resolves.toBe(false);

    router.notifyEcho('id');
    await expect(long).resolves.toBe(true);
  });

  it('別 ID のエコーでは解決しない', async () => {
    const p = router.awaitEcho('mine', 50);
    router.notifyEcho('other');
    await vi.advanceTimersByTimeAsync(50);
    await expect(p).resolves.toBe(false);
  });

  it('待機者が居ないときのエコーや、期限後のエコーは何も起こさない', async () => {
    expect(() => router.notifyEcho('nobody')).not.toThrow();
    const p = router.awaitEcho('late', 10);
    await vi.advanceTimersByTimeAsync(10);
    await expect(p).resolves.toBe(false);
    expect(() => router.notifyEcho('late')).not.toThrow();
  });

  it('エコーは 1 回きり: 通知後に同じ ID を待ち直した者は、次のエコーまで待つ', async () => {
    router.notifyEcho('re');
    const p = router.awaitEcho('re', 20);
    await vi.advanceTimersByTimeAsync(20);
    await expect(p).resolves.toBe(false);
  });
});

describe('DandelionRouter: Guard の固定 (Sticky Pinning)', () => {
  it('Guard は無期限に固定される (時間で交代しない)', () => {
    expect(DANDELION_CONFIG.GUARD_PIN_DURATION).toBe(Number.POSITIVE_INFINITY);
  });

  it('一度選んだ Guard は、隣人に居て候補にある限り変わらない', () => {
    vi.useFakeTimers();
    try {
      const ids = [ID('a'), ID('b'), ID('c'), ID('d')];
      const router = new DandelionRouter(fakePm(ids));
      const first = router.getPinnedGuard(ids.map(hop))!.peerId;
      for (let i = 0; i < 50; i++) {
        vi.advanceTimersByTime(24 * 60 * 60 * 1000); // 1 日ずつ進める
        expect(router.getPinnedGuard(ids.map(hop))!.peerId).toBe(first);
      }
      expect(router.getPinnedGuardId()).toBe(first);
    } finally {
      vi.useRealTimers();
    }
  });

  it('Guard が切断されたら、残りの候補から選び直して通知する', () => {
    const ids = [ID('a'), ID('b')];
    const pm = fakePm(ids);
    const router = new DandelionRouter(pm);
    const changes: Array<string | null> = [];
    router.onGuardChange(g => changes.push(g));

    const first = router.getPinnedGuard(ids.map(hop))!.peerId;
    pm.peers.delete(first);
    const remaining = ids.filter(id => id !== first);
    const second = router.getPinnedGuard(remaining.map(hop))!.peerId;

    expect(second).toBe(remaining[0]);
    expect(changes).toEqual([first, second]);
  });

  it('Guard が候補 (公開鍵の分かる検証済みピア) から外れたら選び直す', () => {
    const ids = [ID('a'), ID('b')];
    const router = new DandelionRouter(fakePm(ids));
    const first = router.getPinnedGuard(ids.map(hop))!.peerId;
    const other = ids.find(id => id !== first)!;
    expect(router.getPinnedGuard([hop(other)])!.peerId).toBe(other);
  });

  it('候補が空になったとき: Guard が隣人から消えていれば破棄して null を通知する', () => {
    const pm = fakePm([ID('a')]);
    const router = new DandelionRouter(pm);
    const changes: Array<string | null> = [];
    router.onGuardChange(g => changes.push(g));
    router.getPinnedGuard([hop(ID('a'))]);

    pm.peers.delete(ID('a'));
    expect(router.getPinnedGuard([])).toBeNull();
    expect(router.getPinnedGuardId()).toBeNull();
    expect(changes).toEqual([ID('a'), null]);
  });

  it('候補が一時的に空でも、Guard がまだ隣人に居れば固定は外さない', () => {
    const pm = fakePm([ID('a')]);
    const router = new DandelionRouter(pm);
    router.getPinnedGuard([hop(ID('a'))]);
    expect(router.getPinnedGuard([])).toBeNull();
    expect(router.getPinnedGuardId()).toBe(ID('a'));
    expect(router.getPinnedGuard([hop(ID('a'))])!.peerId).toBe(ID('a'));
  });

  it('候補が無く Guard も居なければ null (通知しない)', () => {
    const router = new DandelionRouter(fakePm([]));
    const cb = vi.fn();
    router.onGuardChange(cb);
    expect(router.getPinnedGuard([])).toBeNull();
    expect(cb).not.toHaveBeenCalled();
  });

  it('resetPinnedGuard は Guard を破棄して null を通知し、同じ値の再設定では通知しない', () => {
    const router = new DandelionRouter(fakePm([ID('a')]));
    const changes: Array<string | null> = [];
    router.onGuardChange(g => changes.push(g));
    router.getPinnedGuard([hop(ID('a'))]);
    router.getPinnedGuard([hop(ID('a'))]);
    router.resetPinnedGuard();
    router.resetPinnedGuard();
    expect(changes).toEqual([ID('a'), null]);
  });
});

describe('暗号論的乱数インデックス', () => {
  it('secureRandomIndex は常に [0, n) を返し、n <= 1 なら 0', () => {
    expect(secureRandomIndex(0)).toBe(0);
    expect(secureRandomIndex(1)).toBe(0);
    const seen = new Set<number>();
    for (let i = 0; i < 500; i++) {
      const r = secureRandomIndex(7);
      expect(r).toBeGreaterThanOrEqual(0);
      expect(r).toBeLessThan(7);
      seen.add(r);
    }
    expect(seen.size).toBe(7);
  });

  it('secureWeightedIndex: 重みが全部 0 なら一様選択に落ちる (範囲外を返さない)', () => {
    for (let i = 0; i < 200; i++) {
      const r = secureWeightedIndex([0, 0, 0]);
      expect(r).toBeGreaterThanOrEqual(0);
      expect(r).toBeLessThan(3);
    }
  });

  it('secureWeightedIndex: 重み 0 の要素は (他に正の重みがあれば) 選ばれない', () => {
    for (let i = 0; i < 300; i++) {
      expect(secureWeightedIndex([0, 5, 0])).toBe(1);
    }
  });
});

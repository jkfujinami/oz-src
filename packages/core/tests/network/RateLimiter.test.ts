import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { RateLimiter, RATE_LIMITS } from '../../src/network/RateLimiter';

/** 手で進める時計 */
function manualClock(start = 1_000_000) {
  let t = start;
  return { now: () => t, advance: (ms: number) => { t += ms; }, set: (ms: number) => { t = ms; } };
}

const CFG = {
  fast: { ratePerSec: 10, burst: 5 },
  slow: { ratePerSec: 0.5, burst: 2 },
};

describe('RateLimiter: トークンバケット', () => {
  it('最初はバースト分だけ通し、それを超えたら拒否する', () => {
    const clock = manualClock();
    const rl = new RateLimiter(CFG, clock.now);
    for (let i = 0; i < 5; i++) expect(rl.allow('p', 'fast')).toBe(true);
    expect(rl.allow('p', 'fast')).toBe(false);
    expect(rl.allow('p', 'fast')).toBe(false);
  });

  it('時間に比例して補充される (10 件/秒 → 100ms で 1 件)', () => {
    const clock = manualClock();
    const rl = new RateLimiter(CFG, clock.now);
    for (let i = 0; i < 5; i++) rl.allow('p', 'fast');
    expect(rl.allow('p', 'fast')).toBe(false);
    clock.advance(99);
    expect(rl.allow('p', 'fast')).toBe(false);
    clock.advance(2);
    expect(rl.allow('p', 'fast')).toBe(true);
    expect(rl.allow('p', 'fast')).toBe(false);
  });

  it('補充はバースト上限で頭打ちになる (長く黙っても溜め込めない)', () => {
    const clock = manualClock();
    const rl = new RateLimiter(CFG, clock.now);
    rl.allow('p', 'fast');
    clock.advance(3_600_000);
    let passed = 0;
    for (let i = 0; i < 100; i++) if (rl.allow('p', 'fast')) passed++;
    expect(passed).toBe(5);
  });

  it('定常レートを超える流量は長期的に ratePerSec に頭打ちになる', () => {
    const clock = manualClock();
    const rl = new RateLimiter(CFG, clock.now);
    let passed = 0;
    // 10 秒間、1ms ごとに送りつける
    for (let i = 0; i < 10_000; i++) {
      if (rl.allow('p', 'fast')) passed++;
      clock.advance(1);
    }
    // バースト 5 + 10 秒 × 10 件
    expect(passed).toBeGreaterThanOrEqual(104);
    expect(passed).toBeLessThanOrEqual(105);
  });

  it('1 秒未満のレート (0.5 件/秒) も扱える', () => {
    const clock = manualClock();
    const rl = new RateLimiter(CFG, clock.now);
    expect(rl.allow('p', 'slow')).toBe(true);
    expect(rl.allow('p', 'slow')).toBe(true);
    expect(rl.allow('p', 'slow')).toBe(false);
    clock.advance(1999);
    expect(rl.allow('p', 'slow')).toBe(false);
    clock.advance(1);
    expect(rl.allow('p', 'slow')).toBe(true);
  });

  it('時計が巻き戻っても補充はマイナスにならず、予算も増えない', () => {
    const clock = manualClock(10_000);
    const rl = new RateLimiter(CFG, clock.now);
    for (let i = 0; i < 5; i++) rl.allow('p', 'fast');
    clock.set(0);
    expect(rl.allow('p', 'fast')).toBe(false);
    expect(rl.tokensFor('p', 'fast')).toBeGreaterThanOrEqual(0);
  });
});

describe('RateLimiter: 独立性', () => {
  it('ピアごとに独立 (1 人が使い切っても他人の予算は減らない)', () => {
    const rl = new RateLimiter(CFG, manualClock().now);
    for (let i = 0; i < 5; i++) rl.allow('attacker', 'fast');
    expect(rl.allow('attacker', 'fast')).toBe(false);
    expect(rl.allow('honest', 'fast')).toBe(true);
    expect(rl.tokensFor('honest', 'fast')).toBe(4);
  });

  it('カテゴリごとに独立 (DHT_PUT を撃ち込まれても GOSSIP の予算は減らない)', () => {
    const rl = new RateLimiter(RATE_LIMITS, manualClock().now);
    while (rl.allow('p', 'dhtPut')) { /* 使い切る */ }
    expect(rl.allow('p', 'gossip')).toBe(true);
    expect(rl.tokensFor('p', 'gossip')).toBe(RATE_LIMITS.gossip.burst - 1);
  });
});

describe('RateLimiter: 未定義カテゴリは fail-closed', () => {
  it('表に無いカテゴリは常に拒否し、dropped に数える', () => {
    const rl = new RateLimiter(CFG, manualClock().now);
    expect(rl.allow('p', 'unknown')).toBe(false);
    expect(rl.allow('p', 'unknown')).toBe(false);
    expect(rl.dropped.get('unknown')).toBe(2);
  });

  it('★回帰: Object.prototype のキー名はカテゴリとして通らない (何度呼んでも false)', () => {
    for (const limits of [CFG, RATE_LIMITS]) {
      const rl = new RateLimiter(limits, manualClock().now);
      for (const c of ['constructor', 'toString', '__proto__', 'hasOwnProperty', 'valueOf']) {
        for (let i = 0; i < 100; i++) expect(rl.allow('p', c), c).toBe(false);
        expect(rl.dropped.get(c)).toBe(100);
      }
    }
  });

  it('拒否した件数はカテゴリ別に数える', () => {
    const rl = new RateLimiter(CFG, manualClock().now);
    for (let i = 0; i < 8; i++) rl.allow('p', 'fast');
    rl.allow('p', 'nope');
    expect(rl.dropped.get('fast')).toBe(3);
    expect(rl.dropped.get('nope')).toBe(1);
  });
});

describe('RateLimiter: 状態管理', () => {
  it('forget はそのピアの全カテゴリを消し、他のピアは残す', () => {
    const rl = new RateLimiter(CFG, manualClock().now);
    for (let i = 0; i < 5; i++) { rl.allow('aa', 'fast'); rl.allow('baa', 'fast'); }
    rl.allow('aa', 'slow');
    rl.forget('aa');
    expect(rl.tokensFor('aa', 'fast')).toBe(5);
    expect(rl.tokensFor('aa', 'slow')).toBe(2);
    // 末尾が同じ別ピア (suffix 一致) を巻き込まない
    expect(rl.tokensFor('baa', 'fast')).toBe(0);
  });

  it('tokensFor: 未使用ならバースト値、未定義カテゴリなら Infinity', () => {
    const rl = new RateLimiter(CFG, manualClock().now);
    expect(rl.tokensFor('p', 'fast')).toBe(5);
    expect(rl.tokensFor('p', 'missing')).toBe(Infinity);
  });

  it('reset は全バケットと拒否数を消す', () => {
    const rl = new RateLimiter(CFG, manualClock().now);
    for (let i = 0; i < 6; i++) rl.allow('p', 'fast');
    rl.reset();
    expect(rl.dropped.size).toBe(0);
    expect(rl.tokensFor('p', 'fast')).toBe(5);
    expect(rl.allow('p', 'fast')).toBe(true);
  });

  describe('既定の時計 (Date.now)', () => {
    beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(0); });
    afterEach(() => { vi.useRealTimers(); });

    it('時計を渡さなければ Date.now で補充する', () => {
      const rl = new RateLimiter(CFG);
      for (let i = 0; i < 5; i++) rl.allow('p', 'fast');
      expect(rl.allow('p', 'fast')).toBe(false);
      vi.advanceTimersByTime(100);
      expect(rl.allow('p', 'fast')).toBe(true);
    });
  });
});

describe('RATE_LIMITS の既定値', () => {
  it('全カテゴリで burst ≥ 1 かつ ratePerSec > 0 (誰も永久に詰まらない)', () => {
    for (const [name, c] of Object.entries(RATE_LIMITS)) {
      expect(c.burst, name).toBeGreaterThanOrEqual(1);
      expect(c.ratePerSec, name).toBeGreaterThan(0);
    }
  });

  it('Heartbeat (15 秒に 1 回) と RingMaintainer の PEX (10 秒に 1 回) は既定値で通る', () => {
    expect(RATE_LIMITS.control.ratePerSec).toBeGreaterThanOrEqual(2 / 15); // ping + pong
    expect(RATE_LIMITS.pex.ratePerSec).toBeGreaterThanOrEqual(1 / 10);
  });

  it('ハンドシェイクは特に絞られている (NodeId PoW の検証が重い)', () => {
    for (const [name, c] of Object.entries(RATE_LIMITS)) {
      if (name !== 'handshake') expect(RATE_LIMITS.handshake.ratePerSec).toBeLessThan(c.ratePerSec);
    }
  });
});

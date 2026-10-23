import { describe, it, expect } from 'vitest';
import { equixReady, equixSolve, equixVerify, EQUIX_SOLUTION_BYTES } from '../../src/crypto/equix/EquiX';

const challenge = (n: number) => Uint8Array.from({ length: 36 }, (_, i) => (i * 7 + n) & 0xff);

describe('Equi-X (Wasm)', () => {
  it('読み込みは 1 回で、何度 await しても同じ Promise', async () => {
    await equixReady;
    await equixReady;
    expect(equixReady).toBe(equixReady);
  });

  it('解くと解 (16 バイト) が得られ、検証を通る。解は 1 試行で 0 個以上 (数回試せば必ず 1 個は出る)', () => {
    let found: Uint8Array | null = null;
    let c = challenge(0);
    const t0 = performance.now();
    let attempts = 0;
    for (let n = 0; n < 20 && !found; n++, attempts++) {
      c = challenge(n);
      const sols = equixSolve(c);
      for (const s of sols) expect(s).toHaveLength(EQUIX_SOLUTION_BYTES);
      if (sols.length > 0) found = sols[0];
    }
    const per = (performance.now() - t0) / attempts;
    // eslint-disable-next-line no-console
    console.log(`[equix] solve: ${per.toFixed(0)} ms/attempt (${attempts} attempts)`);
    expect(found).not.toBeNull();
    expect(equixVerify(c, found!)).toBe(true);
  });

  it('検証は同期で軽く (数十マイクロ秒〜)、別の challenge・壊れた解・長さ違いは false', () => {
    let c = challenge(100), s: Uint8Array | undefined;
    for (let n = 100; !s; n++) { c = challenge(n); s = equixSolve(c)[0]; }
    const t0 = performance.now();
    for (let i = 0; i < 200; i++) equixVerify(c, s);
    const us = ((performance.now() - t0) / 200) * 1000;
    // eslint-disable-next-line no-console
    console.log(`[equix] verify: ${us.toFixed(0)} us`);
    expect(us).toBeLessThan(2000);

    expect(equixVerify(challenge(999), s)).toBe(false);
    const bad = Uint8Array.from(s); bad[0] ^= 1;
    expect(equixVerify(c, bad)).toBe(false);
    expect(equixVerify(c, s.subarray(0, 15))).toBe(false);
    expect(equixVerify(c, new Uint8Array(17))).toBe(false);
    expect(equixVerify(new Uint8Array(0), s)).toBe(false);
  });

  it('同じ challenge の解は決定的', () => {
    const a = equixSolve(challenge(5));
    const b = equixSolve(challenge(5));
    expect(a.map(x => Array.from(x))).toEqual(b.map(x => Array.from(x)));
  });

  it('範囲外の challenge は solve で例外', () => {
    expect(() => equixSolve(new Uint8Array(0))).toThrow(RangeError);
    expect(() => equixSolve(new Uint8Array(2000))).toThrow(RangeError);
  });
});

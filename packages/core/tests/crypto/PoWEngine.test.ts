import { describe, it, expect } from 'vitest';
import { PoWEngine } from '../../src/crypto/PoWEngine';
import { POW_POLICY, PACKET_VERSION, type PowCommitted } from '../../src/crypto/PowPolicy';

const header = (over: Partial<PowCommitted> = {}): PowCommitted => ({
  version: PACKET_VERSION,
  time: 1_100_000,
  tag: 7,
  age: 0,
  effort_exp: 0,
  payload: new TextEncoder().encode('pow-engine'),
  ...over,
});

describe('PoWEngine', () => {
  it('Worker の無い環境では同期探索にフォールバックし、得た解は検証を通る', async () => {
    expect(typeof (globalThis as any).Worker).toBe('undefined');
    const h = header();
    const sol = await PoWEngine.compute(h);
    expect(sol.solution).toHaveLength(16);
    expect(PoWEngine.verify(h, sol)).toBe(true);
    expect(PoWEngine.computeSync(h).nonce).toBe(sol.nonce);
  });

  it('effort を上げた探索 (e=8 → effort 4) も解ける', async () => {
    const h = header({ effort_exp: 8, time: 1_100_001 });
    const sol = await PoWEngine.compute(h);
    expect(PoWEngine.verify(h, sol)).toBe(true);
  });

  it('範囲外の effort の指数では探索を始めない', async () => {
    await expect(PoWEngine.compute(header({ effort_exp: POW_POLICY.MAX_EFFORT_EXP + 1 }))).rejects.toThrow(RangeError);
    await expect(PoWEngine.compute(header({ effort_exp: -1 }))).rejects.toThrow(RangeError);
  });

  it('解を別のヘッダに流用しても通らない', async () => {
    const h = header({ time: 1_100_002 });
    const sol = await PoWEngine.compute(h);
    expect(PoWEngine.verify({ ...h, time: h.time + 1 }, sol)).toBe(false);
  });
});

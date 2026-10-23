import { describe, it, expect } from 'vitest';
import { EffortAdvisor, EFFORT_ADVISOR, packetCells, packetEffortPerCell } from '../../src/network/gossip/EffortAdvisor';
import { effortFromExp, effortFor, cellsFor, POW_POLICY } from '../../src/crypto/PowPolicy';

/** 検証を通らなくてよい (advisor は数えるだけ) 軽いパケット。cells セル分の長さ */
const pkt = (effortExp: number, cells = 1) => ({
  effort_exp: effortExp,
  payload: new Uint8Array(cells * POW_POLICY.EFFORT_CELL_BYTES - POW_POLICY.HEADER_BYTES),
});

const SEC = 1000;

describe('EffortAdvisor: 推奨 effort', () => {
  it('静かな網 (予算以内) では最小 (1 / セル)', () => {
    let t = 0;
    const a = new EffortAdvisor({ now: () => t });
    for (let i = 0; i < 600; i++) { t += SEC; a.observe(pkt(0)); } // 1 セル/秒 ≪ 20
    expect(a.suggestedPerCell()).toBe(1);
    expect(a.suggestedFor(3)).toBe(3);
  });

  it('ピーク (15 投稿/秒を 1 分) でも予算の内側なら最小のまま', () => {
    let t = 0;
    const a = new EffortAdvisor({ now: () => t });
    for (let i = 0; i < 15 * 60; i++) { t += 1000 / 15; a.observe(pkt(0)); }
    expect(a.suggestedPerCell()).toBe(1);
  });

  it('予算を超える洪水では、攻撃者の effort より上を勧める', () => {
    for (const exp of [0, 4, 8, 12, 20]) {
      let t = 0;
      const a = new EffortAdvisor({ now: () => t });
      for (let i = 0; i < 200 * 30; i++) { t += 5; a.observe(pkt(exp)); } // 200 セル/秒 × 30 秒
      const attacker = effortFromExp(exp);
      const s = a.suggestedPerCell();
      expect(s).toBeGreaterThan(attacker);
      // 実際に作者が使う effort も、攻撃者より高い
      expect(effortFor(POW_POLICY.EFFORT_CELL_BYTES, a.suggestedFor(1)).effort).toBeGreaterThan(attacker);
    }
  });

  it('予算の順位で決まる: 高 effort が予算に満たない量なら、その下の層に合わせる', () => {
    let t = 0;
    const a = new EffortAdvisor({ now: () => t });
    // 60 秒で 1,200 セルが予算。高 (e=20) を 100 セル、低 (e=4) を 5,000 セル流す
    for (let i = 0; i < 100; i++) { t += 10; a.observe(pkt(20)); }
    for (let i = 0; i < 5000; i++) { t += 10; a.observe(pkt(4)); }
    const s = a.suggestedPerCell();
    expect(s).toBeGreaterThan(effortFromExp(4));
    expect(s).toBeLessThan(effortFromExp(20));
  });

  it('洪水が止まれば窓から出て滑らかに下がり、10 分で最小に戻る', () => {
    let t = 0;
    const a = new EffortAdvisor({ now: () => t });
    for (let i = 0; i < 200 * 60; i++) { t += 5; a.observe(pkt(8)); }
    const peak = a.suggestedPerCell();
    expect(peak).toBeGreaterThan(effortFromExp(8));
    let prev = peak;
    for (let m = 1; m <= 11; m++) {
      t += 60 * SEC;
      const s = a.suggestedPerCell();
      expect(s).toBeLessThanOrEqual(prev); // 単調に下がる
      prev = s;
    }
    expect(a.suggestedPerCell()).toBe(1);
    expect(a.size()).toBe(0);
  });

  it('量子化: 推奨は 2^(i/4) の目盛りの上にあり、同じ flood を見た別の端末と一致する', () => {
    const run = () => {
      let t = 0;
      const a = new EffortAdvisor({ now: () => t });
      for (let i = 0; i < 6000; i++) { t += 5; a.observe(pkt(5 + (i % 3))); }
      return a.suggestedPerCell();
    };
    const s = run();
    const i = 4 * Math.log2(s);
    expect(Math.abs(i - Math.round(i))).toBeLessThan(1e-9);
    expect(run()).toBe(s);
  });

  it('上限 (MAX_SUGGESTED_EXP) を超えない', () => {
    let t = 0;
    const a = new EffortAdvisor({ now: () => t });
    for (let i = 0; i < 20000; i++) { t += 3; a.observe(pkt(POW_POLICY.MAX_EFFORT_EXP)); }
    expect(a.suggestedPerCell()).toBeCloseTo(Math.pow(2, EFFORT_ADVISOR.MAX_SUGGESTED_EXP / 4), 9);
  });

  it('e_c は effort / セル数。3 セルの投稿は 1 セルの 1/3 で比べる', () => {
    expect(packetCells(pkt(0, 3))).toBe(3);
    expect(packetEffortPerCell(pkt(8, 3))).toBeCloseTo(effortFromExp(8) / 3, 9);
    expect(cellsFor(POW_POLICY.HEADER_BYTES + pkt(0, 3).payload.length)).toBe(3);
    // 3 セルが effort 3 (= 最低) なら、1 セルの最低と同じ優先度
    expect(packetEffortPerCell(pkt(7, 3))).toBeCloseTo(effortFromExp(7) / 3, 9);
  });

  it('覚える件数に天井がある', () => {
    let t = 0;
    const a = new EffortAdvisor({ now: () => t, maxEntries: 100 });
    for (let i = 0; i < 1000; i++) { t += 1; a.observe(pkt(0)); }
    expect(a.size()).toBe(100);
    expect(a.windowCells()).toBe(100);
  });
});

import { describe, it, expect } from 'vitest';
import { DifficultyEstimator as D } from '../../src/crypto/DifficultyEstimator';

/** start から step ms 間隔で n 個 */
const series = (n: number, step: number, start = 1_000_000) => Array.from({ length: n }, (_, i) => start + i * step);

describe('DifficultyEstimator (旧来の適応難易度。公開 API として残っている)', () => {
  it('サンプルが 2 件未満なら MIN_DIFFICULTY', () => {
    expect(D.compute([])).toBe(D.MIN_DIFFICULTY);
    expect(D.compute([123])).toBe(D.MIN_DIFFICULTY);
  });

  it('全件が同時刻 (経過 0) なら MAX_DIFFICULTY (ゼロ除算しない)', () => {
    expect(D.compute([5, 5, 5])).toBe(D.MAX_DIFFICULTY);
  });

  it('結果は常に [MIN, MAX] に収まる整数', () => {
    for (const step of [1, 10, 100, 1000, 3000, 10_000, 1e6, 1e9]) {
      const d = D.compute(series(50, step));
      expect(Number.isInteger(d)).toBe(true);
      expect(d).toBeGreaterThanOrEqual(D.MIN_DIFFICULTY);
      expect(d).toBeLessThanOrEqual(D.MAX_DIFFICULTY);
    }
  });

  it('投稿が速いほど難易度は単調に上がる (広義)', () => {
    const steps = [1e7, 1e5, 30_000, 3000, 300, 30, 3, 1];
    const ds = steps.map((s) => D.compute(series(100, s)));
    for (let i = 1; i < ds.length; i++) expect(ds[i]).toBeGreaterThanOrEqual(ds[i - 1]);
    expect(ds[0]).toBe(D.MIN_DIFFICULTY);
    expect(ds[ds.length - 1]).toBe(D.MAX_DIFFICULTY);
  });

  it('並び順に依存しない (内部でソートし、入力配列を変更しない)', () => {
    const asc = series(30, 777);
    const shuffled = [...asc].reverse();
    const copy = [...shuffled];
    expect(D.compute(shuffled)).toBe(D.compute(asc));
    expect(shuffled).toEqual(copy);
  });

  it('直近 WINDOW 件だけを見る (古い外れ値に引きずられない)', () => {
    const recent = series(D.WINDOW, 30_000, 10_000_000_000);
    const old = series(500, 1, 0); // 大昔の超高速バースト
    expect(D.compute([...old, ...recent])).toBe(D.compute(recent));
  });
});

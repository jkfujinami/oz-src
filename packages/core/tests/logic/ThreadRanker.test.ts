import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { ThreadRanker } from '../../src/logic/ThreadRanker';

const NOW = Date.UTC(2026, 0, 15, 12, 0, 0);
const HOUR = 60 * 60 * 1000;
const GRAVITY = 1.8;
const BASE = 16;
const OFFSET = 2;

const expected = (pow: number, hours: number) => (pow + BASE) / Math.pow(hours + OFFSET, GRAVITY);

describe('ThreadRanker', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
  });
  afterEach(() => vi.useRealTimers());

  describe('calculateScore', () => {
    it('Score = (PoW + 16) / (経過時間 + 2)^1.8', () => {
      expect(ThreadRanker.calculateScore(0, NOW)).toBeCloseTo(expected(0, 0), 12);
      expect(ThreadRanker.calculateScore(12, NOW - 3 * HOUR)).toBeCloseTo(expected(12, 3), 12);
      expect(ThreadRanker.calculateScore(1000, NOW - 48 * HOUR)).toBeCloseTo(expected(1000, 48), 12);
    });

    it('秒単位の時刻 (10^10 未満) はミリ秒に直して扱う', () => {
      const secs = Math.floor((NOW - 5 * HOUR) / 1000);
      expect(ThreadRanker.calculateScore(12, secs)).toBeCloseTo(ThreadRanker.calculateScore(12, secs * 1000), 12);
      expect(ThreadRanker.calculateScore(12, secs)).toBeCloseTo(expected(12, 5), 6);
    });

    it('時刻が NaN / 0 / 負 / 数値でない場合は「たった今」として扱う', () => {
      const fresh = expected(20, 0);
      for (const bad of [NaN, 0, -5, undefined as any, null as any, '123' as any]) {
        expect(ThreadRanker.calculateScore(20, bad)).toBeCloseTo(fresh, 12);
      }
    });

    it('PoW が NaN や数値でない場合は 0 として扱う', () => {
      expect(ThreadRanker.calculateScore(NaN, NOW)).toBeCloseTo(expected(0, 0), 12);
      expect(ThreadRanker.calculateScore(undefined as any, NOW)).toBeCloseTo(expected(0, 0), 12);
    });

    it('未来の時刻は経過 0 時間として扱い、スコアを水増しできない', () => {
      expect(ThreadRanker.calculateScore(12, NOW + 100 * HOUR)).toBeCloseTo(expected(12, 0), 12);
    });

    it('結果が有限でなくなる入力 (PoW = Infinity) でも有限の既定スコアを返す', () => {
      const s = ThreadRanker.calculateScore(Infinity, NOW);
      expect(Number.isFinite(s)).toBe(true);
      expect(s).toBeCloseTo(BASE / Math.pow(OFFSET, GRAVITY), 12);
    });

    it('時間が経つほどスコアは単調に下がる', () => {
      let prev = Infinity;
      for (let h = 0; h <= 72; h += 6) {
        const s = ThreadRanker.calculateScore(100, NOW - h * HOUR);
        expect(s).toBeLessThan(prev);
        prev = s;
      }
    });
  });

  describe('sortThreadsByScore', () => {
    it('同じ経過時間なら PoW が大きい方が上', () => {
      const sorted = ThreadRanker.sortThreadsByScore([
        { id: 'low', max_pow: 12, created_at: NOW - HOUR },
        { id: 'high', max_pow: 120, created_at: NOW - HOUR },
      ]);
      expect(sorted.map(t => t.id)).toEqual(['high', 'low']);
    });

    it('同じ PoW なら新しい方が上', () => {
      const sorted = ThreadRanker.sortThreadsByScore([
        { id: 'old', max_pow: 50, created_at: NOW - 24 * HOUR },
        { id: 'new', max_pow: 50, created_at: NOW - HOUR },
      ]);
      expect(sorted.map(t => t.id)).toEqual(['new', 'old']);
    });

    it('古いスレッドでも十分に熱量 (PoW) があれば新しいスレッドより上に来る', () => {
      const sorted = ThreadRanker.sortThreadsByScore([
        { id: 'fresh-quiet', max_pow: 0, created_at: NOW },
        { id: 'old-hot', max_pow: 5000, created_at: NOW - 12 * HOUR },
      ]);
      expect(sorted.map(t => t.id)).toEqual(['old-hot', 'fresh-quiet']);
    });

    it('元の配列は変更しない', () => {
      const input = [
        { id: 'a', max_pow: 1, created_at: NOW - 10 * HOUR },
        { id: 'b', max_pow: 100, created_at: NOW },
      ];
      const copy = input.map(x => ({ ...x }));
      const sorted = ThreadRanker.sortThreadsByScore(input);
      expect(input).toEqual(copy);
      expect(sorted).not.toBe(input);
      expect(sorted.map(t => t.id)).toEqual(['b', 'a']);
    });

    it('壊れた値を含んでいても例外にならず、全件を返す', () => {
      const sorted = ThreadRanker.sortThreadsByScore([
        { id: 'nan', max_pow: NaN, created_at: NaN },
        { id: 'ok', max_pow: 12, created_at: NOW - HOUR },
        { id: 'inf', max_pow: Infinity, created_at: NOW },
      ]);
      expect(sorted.map(t => t.id).sort()).toEqual(['inf', 'nan', 'ok']);
    });
  });
});

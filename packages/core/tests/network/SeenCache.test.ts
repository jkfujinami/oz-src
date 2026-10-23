import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { SeenCache } from '../../src/network/gossip/SeenCache';

describe('SeenCache', () => {
  let cache: SeenCache;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(0);
    cache = new SeenCache();
  });
  afterEach(() => {
    cache.destroy();
    vi.useRealTimers();
  });

  it('add したものは has で見え、していないものは見えない', () => {
    expect(cache.has('a')).toBe(false);
    cache.add('a');
    expect(cache.has('a')).toBe(true);
    expect(cache.has('b')).toBe(false);
  });

  it('TTL は 15 分 (時刻検査の MAX_TIME_DRIFT と揃える二重防御)', () => {
    expect(SeenCache.TTL_MS).toBe(15 * 60 * 1000);
  });

  it('★15 分を過ぎたものは 5 分ごとの掃除で消える', () => {
    cache.add('old');
    vi.advanceTimersByTime(15 * 60 * 1000);
    // 15 分ちょうど (掃除は 5 分刻み) ではまだ TTL を「超えて」いない
    expect(cache.has('old')).toBe(true);
    vi.advanceTimersByTime(5 * 60 * 1000);
    expect(cache.has('old')).toBe(false);
  });

  it('掃除は古いものだけを消し、TTL 内のものは残す', () => {
    cache.add('t0');
    vi.advanceTimersByTime(10 * 60 * 1000);
    cache.add('t10');
    vi.advanceTimersByTime(10 * 60 * 1000); // t=20 分: t0 は 20 分経過、t10 は 10 分
    expect(cache.has('t0')).toBe(false);
    expect(cache.has('t10')).toBe(true);
  });

  it('再度 add しても挿入時刻は更新しない (重複を何度流されても寿命を延ばせない)', () => {
    cache.add('x');
    vi.advanceTimersByTime(14 * 60 * 1000);
    cache.add('x');
    vi.advanceTimersByTime(6 * 60 * 1000); // 最初の add から 20 分
    expect(cache.has('x')).toBe(false);
  });

  it('★上限 50,000 件を超えたら最も古いものから捨てる (メモリの上限)', () => {
    for (let i = 0; i < 50_000; i++) cache.add(`id${i}`);
    expect(cache.has('id0')).toBe(true);
    cache.add('overflow');
    expect(cache.has('id0')).toBe(false);
    expect(cache.has('id1')).toBe(true);
    expect(cache.has('overflow')).toBe(true);
  });

  it('既にあるものを add しても件数は増えず、何も追い出さない', () => {
    for (let i = 0; i < 50_000; i++) cache.add(`id${i}`);
    cache.add('id49999');
    cache.add('id0');
    expect(cache.has('id0')).toBe(true);
  });

  it('destroy で中身とタイマーを捨てる', () => {
    cache.add('a');
    cache.destroy();
    expect(cache.has('a')).toBe(false);
    expect(vi.getTimerCount()).toBe(0);
  });
});

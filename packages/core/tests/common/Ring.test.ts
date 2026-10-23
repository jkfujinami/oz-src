import { describe, it, expect, beforeAll } from 'vitest';
import { sodiumReady } from '../../src/crypto/sodium';
import { RING_SIZE, closest, positionFromHash, positionOf, ringDistance } from '../../src/common/Ring';

beforeAll(async () => {
  await sodiumReady;
});

describe('Ring', () => {
  it('positionFromHash は先頭 8 バイトのビッグエンディアン', () => {
    expect(positionFromHash(Uint8Array.of(0, 0, 0, 0, 0, 0, 1, 2, 9, 9))).toBe(0x0102n);
    expect(positionFromHash(new Uint8Array(8).fill(0xff))).toBe(RING_SIZE - 1n);
  });

  it('ringDistance は 2^64 を回り込む最短距離', () => {
    expect(ringDistance(5n, 5n)).toBe(0n);
    expect(ringDistance(10n, 4n)).toBe(6n);
    expect(ringDistance(0n, RING_SIZE - 1n)).toBe(1n);
    expect(ringDistance(RING_SIZE - 1n, 2n)).toBe(3n);
    expect(ringDistance(0n, RING_SIZE / 2n)).toBe(RING_SIZE / 2n);
    expect(ringDistance(3n, 90n)).toBe(ringDistance(90n, 3n));
  });

  it('positionOf は決定的で、部品の区切りを区別する', () => {
    const e = (s: string) => new TextEncoder().encode(s);
    expect(positionOf('d', e('ab'), e('c'))).toBe(positionOf('d', e('ab'), e('c')));
    expect(positionOf('d', e('ab'), e('c'))).not.toBe(positionOf('d', e('a'), e('bc')));
    expect(positionOf('d1', e('x'))).not.toBe(positionOf('d2', e('x')));
    expect(typeof positionOf('d')).toBe('bigint');
  });

  it('closest は距離順で k 個、入力順に依存しない', () => {
    const mk = (n: number, p: bigint) => ({ id: Uint8Array.of(n), position: p });
    const c = [mk(1, 100n), mk(2, RING_SIZE - 2n), mk(3, 50n), mk(4, 7n), mk(5, 2n)];
    const r = closest(0n, c, 3).map(x => x.id[0]);
    expect(r).toEqual([5, 2, 4]); // 距離 2, 2, 7 (同距離は位置の小さい方が先)
    expect(closest(0n, [...c].reverse(), 3).map(x => x.id[0])).toEqual(r);
    expect(closest(0n, c, 0)).toEqual([]);
    expect(closest(0n, c, 99)).toHaveLength(5);
  });

  it('同距離・同位置は id で決める', () => {
    const a = { id: Uint8Array.of(2), position: 10n };
    const b = { id: Uint8Array.of(1), position: 10n };
    expect(closest(10n, [a, b], 2).map(x => x.id[0])).toEqual([1, 2]);
    expect(closest(0n, [{ id: Uint8Array.of(9), position: 5n }, { id: Uint8Array.of(8), position: RING_SIZE - 5n }], 1)[0].position).toBe(5n);
  });
});

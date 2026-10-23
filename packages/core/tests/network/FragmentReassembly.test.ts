import { describe, it, expect } from 'vitest';
import { FragmentReassembler, REASSEMBLY_LIMITS, type Fragment } from '../../src/network/onion/FragmentReassembler';
import { OnionRouter } from '../../src/crypto/OnionRouter';
import { splitIntoFragments } from '../../src/crypto/ExitItem';

const MAX = OnionRouter.FRAG_DATA_MAX;
const id = (n: number) => new Uint8Array(8).fill(n);
const bytes = (len: number) => Uint8Array.from({ length: len }, (_, i) => (i * 7 + 3) & 0xff);
const frags = (len: number, n = 1): Fragment[] => splitIntoFragments(bytes(len), id(n))!;
const A = 'a'.repeat(32);
const B = 'b'.repeat(32);

describe('FragmentReassembler (M1 での断片の再構成)', () => {
  it('揃った時点で連結したバイト列を返す。順不同でもよい', () => {
    const r = new FragmentReassembler();
    const f = frags(MAX * 2 + 100);
    expect(f).toHaveLength(3);
    expect(r.add(A, f[2])).toBeNull();
    expect(r.add(A, f[0])).toBeNull();
    const out = r.add(A, f[1])!;
    expect(Array.from(out)).toEqual(Array.from(bytes(MAX * 2 + 100)));
    expect(r.size).toBe(0);
  });

  it('1 枚の item は即座に返る', () => {
    const r = new FragmentReassembler();
    expect(Array.from(r.add(A, frags(50)[0])!)).toEqual(Array.from(bytes(50)));
  });

  it('★鍵は (送り主, 断片 id): 別の送り主が同じ id を名乗っても混ざらない', () => {
    const r = new FragmentReassembler();
    const f = frags(MAX + 10);
    r.add(A, f[0]);
    // B が同じ id の idx 1 を送っても、A の item は完成しない
    expect(r.add(B, f[1])).toBeNull();
    expect(r.size).toBe(2);
    expect(r.add(A, f[1])).not.toBeNull();
  });

  it('★欠けた断片: 揃わないまま猶予 (10 秒) を過ぎたら捨てる', () => {
    const r = new FragmentReassembler();
    const f = frags(MAX * 2 + 1);
    r.add(A, f[0], 1000);
    r.add(A, f[1], 2000);
    expect(r.size).toBe(1);
    // 猶予内ならまだ持っている
    r.sweep(1000 + REASSEMBLY_LIMITS.TIMEOUT_MS);
    expect(r.size).toBe(1);
    r.sweep(1000 + REASSEMBLY_LIMITS.TIMEOUT_MS + 1);
    expect(r.size).toBe(0);
    // 遅れて届いた最後の断片は、新しい未完成として始まるだけで item は返らない
    expect(r.add(A, f[2], 20_000)).toBeNull();
  });

  it('add の中でも期限切れが掃除される (タイマー無しでメモリが戻る)', () => {
    const r = new FragmentReassembler();
    r.add(A, frags(MAX + 1, 1)[0], 0);
    r.add(A, frags(MAX + 1, 2)[0], REASSEMBLY_LIMITS.TIMEOUT_MS + 5);
    expect(r.size).toBe(1);
  });

  it('★重複した idx は item ごと捨てる', () => {
    const r = new FragmentReassembler();
    const f = frags(MAX * 2 + 1);
    r.add(A, f[0]);
    expect(r.add(A, f[0])).toBeNull();
    expect(r.size).toBe(0);
    // 捨てた後に残りを送っても完成しない
    expect(r.add(A, f[1])).toBeNull();
    expect(r.add(A, f[2])).toBeNull();
  });

  it('★total が食い違ったら item ごと捨てる', () => {
    const r = new FragmentReassembler();
    const f = frags(MAX * 2 + 1);
    r.add(A, f[0]);
    expect(r.add(A, { ...f[1], total: 2 })).toBeNull();
    expect(r.size).toBe(0);
  });

  it('範囲外 (total > 3, idx >= total, 空・過大なデータ) は受け付けない', () => {
    const r = new FragmentReassembler();
    const base = frags(10)[0];
    for (const bad of [
      { ...base, total: 4 }, { ...base, total: 0 }, { ...base, idx: 1 }, { ...base, idx: -1 },
      { ...base, data: new Uint8Array(0) }, { ...base, data: new Uint8Array(MAX + 1) },
    ]) {
      expect(r.add(A, bad as Fragment)).toBeNull();
    }
    expect(r.size).toBe(0);
  });

  it('★連結後の長さの検証: 先頭の断片が満杯でなければ(切り詰められた item)捨てる', () => {
    const r = new FragmentReassembler();
    const id9 = id(9);
    r.add(A, { type: 'frag', id: id9, idx: 0, total: 2, data: bytes(MAX - 1) });
    expect(r.add(A, { type: 'frag', id: id9, idx: 1, total: 2, data: bytes(5) })).toBeNull();
    expect(r.size).toBe(0);
  });

  it('★送り主ごとの未完成数の上限 (4): 超える新しい item は拒否し、既存のものは追い出さない', () => {
    const r = new FragmentReassembler();
    for (let n = 1; n <= REASSEMBLY_LIMITS.MAX_PARTIAL_PER_SENDER; n++) r.add(A, frags(MAX + 1, n)[0]);
    expect(r.size).toBe(4);
    r.add(A, frags(MAX + 1, 50)[0]);
    expect(r.size).toBe(4);
    // 既存のものは完成できる
    expect(r.add(A, frags(MAX + 1, 1)[1])).not.toBeNull();
    // 空きができたので新しい item を受け付ける
    r.add(A, frags(MAX + 1, 50)[0]);
    expect(r.size).toBe(4);
    // 別の送り主は影響を受けない
    r.add(B, frags(MAX + 1, 60)[0]);
    expect(r.size).toBe(5);
  });

  it('★全体の未完成数の上限 (64)', () => {
    const r = new FragmentReassembler();
    for (let s = 0; s < 16; s++) {
      for (let n = 1; n <= 4; n++) r.add(String(s).padStart(32, '0'), frags(MAX + 1, n)[0]);
    }
    expect(r.size).toBe(REASSEMBLY_LIMITS.MAX_PARTIAL_TOTAL);
    r.add('z'.repeat(32), frags(MAX + 1, 1)[0]);
    expect(r.size).toBe(REASSEMBLY_LIMITS.MAX_PARTIAL_TOTAL);
  });

  it('clear() で全て忘れる', () => {
    const r = new FragmentReassembler();
    r.add(A, frags(MAX + 1)[0]);
    r.clear();
    expect(r.size).toBe(0);
  });
});

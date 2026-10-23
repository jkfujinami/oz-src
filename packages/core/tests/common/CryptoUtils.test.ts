import { describe, it, expect, afterEach, vi } from 'vitest';
import { CryptoUtils } from '../../src/common/CryptoUtils';

afterEach(() => {
  vi.restoreAllMocks();
});

describe('CryptoUtils.generateId', () => {
  it('既定は 10 文字で、英小文字と数字のみ', () => {
    const id = CryptoUtils.generateId();
    expect(id).toMatch(/^[0-9a-z]{10}$/);
  });

  it('指定した長さを返す (0 文字も可)', () => {
    for (const n of [0, 1, 7, 32, 100]) {
      const id = CryptoUtils.generateId(n);
      expect(id).toHaveLength(n);
      expect(id).toMatch(/^[0-9a-z]*$/);
    }
  });

  it('Math.random を使わない (網に出る ID 同士の紐付けを防ぐ)', () => {
    const spy = vi.spyOn(Math, 'random');
    for (let i = 0; i < 20; i++) CryptoUtils.generateId(16);
    expect(spy).not.toHaveBeenCalled();
  });

  it('暗号論的乱数 (crypto.getRandomValues) を使う', () => {
    const spy = vi.spyOn(globalThis.crypto, 'getRandomValues');
    CryptoUtils.generateId(8);
    expect(spy).toHaveBeenCalled();
  });

  it('252 以上のバイトは捨てる (剰余による偏りの除去)', () => {
    let call = 0;
    vi.spyOn(globalThis.crypto, 'getRandomValues').mockImplementation(((buf: Uint8Array) => {
      // 1 回目: すべて棄却されるべき値。2 回目以降: 251 (=35 → 'z') と 252 (棄却) を交互に。
      if (call++ === 0) buf.fill(252);
      else for (let i = 0; i < buf.length; i++) buf[i] = i % 2 === 0 ? 251 : 255;
      return buf;
    }) as any);
    const id = CryptoUtils.generateId(4);
    expect(id).toBe('zzzz');
    expect(call).toBeGreaterThanOrEqual(2);
  });

  it('バイト値 b は alphabet[b % 36] に写る', () => {
    vi.spyOn(globalThis.crypto, 'getRandomValues').mockImplementation(((buf: Uint8Array) => {
      for (let i = 0; i < buf.length; i++) buf[i] = [0, 9, 10, 35, 36, 71][i % 6];
      return buf;
    }) as any);
    expect(CryptoUtils.generateId(6)).toBe('09az0z');
  });

  it('大量に生成しても衝突しない (16 文字)', () => {
    const set = new Set<string>();
    for (let i = 0; i < 2000; i++) set.add(CryptoUtils.generateId(16));
    expect(set.size).toBe(2000);
  });
});

describe('CryptoUtils.randomBytes', () => {
  it('指定長の Uint8Array を返し、毎回異なる', () => {
    const a = CryptoUtils.randomBytes(32);
    const b = CryptoUtils.randomBytes(32);
    expect(a).toBeInstanceOf(Uint8Array);
    expect(a).toHaveLength(32);
    expect(Array.from(a)).not.toEqual(Array.from(b));
    expect(CryptoUtils.randomBytes(0)).toHaveLength(0);
  });
});

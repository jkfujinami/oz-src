import { describe, it, expect } from 'vitest';
import { Encoding } from '../../src/common/Encoding';

const allBytes = Uint8Array.from({ length: 256 }, (_, i) => i);

describe('Encoding: hex', () => {
  it('全バイト値を小文字 2 桁でゼロ詰めして往復する', () => {
    const hex = Encoding.toHex(allBytes);
    expect(hex).toHaveLength(512);
    expect(hex).toMatch(/^[0-9a-f]+$/);
    expect(hex.startsWith('000102')).toBe(true);
    expect(hex.endsWith('fdfeff')).toBe(true);
    expect(Array.from(Encoding.fromHex(hex))).toEqual(Array.from(allBytes));
  });

  it('空配列 ↔ 空文字列', () => {
    expect(Encoding.toHex(new Uint8Array(0))).toBe('');
    expect(Encoding.fromHex('')).toHaveLength(0);
  });

  it('大文字の hex も読める', () => {
    expect(Array.from(Encoding.fromHex('DEADbeef'))).toEqual([0xde, 0xad, 0xbe, 0xef]);
  });

  it('subarray (オフセット付きビュー) はビューの範囲だけを符号化する', () => {
    const view = allBytes.subarray(10, 13);
    expect(Encoding.toHex(view)).toBe('0a0b0c');
  });
});

describe('Encoding: Base64URL', () => {
  it('パディング無し・URL 安全な文字だけを使う', () => {
    const b64 = Encoding.toBase64(allBytes);
    expect(b64).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(b64).not.toContain('=');
    // 0xfb 0xff は標準 Base64 で '+' と '/' を含む
    expect(Encoding.toBase64(Uint8Array.of(0xfb, 0xff, 0xbf))).toBe('-_-_');
  });

  it('長さ 0..40 のすべてで往復する', () => {
    for (let n = 0; n <= 40; n++) {
      const bytes = allBytes.subarray(256 - n);
      expect(Array.from(Encoding.fromBase64(Encoding.toBase64(bytes)))).toEqual(Array.from(bytes));
    }
  });

  it('標準 Base64 (パディング付き) も読める', () => {
    expect(Array.from(Encoding.fromBase64('+/+/'))).toEqual([0xfb, 0xff, 0xbf]);
    expect(Array.from(Encoding.fromBase64('AQ=='))).toEqual([1]);
    expect(Array.from(Encoding.fromBase64('AQ'))).toEqual([1]);
  });

  it('Base64 として不正な文字列は例外になる (黙って別の値を返さない)', () => {
    expect(() => Encoding.fromBase64('!!!!')).toThrow();
    expect(() => Encoding.fromBase64('A')).toThrow();
  });

  it('全バイト値を往復する', () => {
    expect(Array.from(Encoding.fromBase64(Encoding.toBase64(allBytes)))).toEqual(Array.from(allBytes));
  });
});

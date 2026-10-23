import { describe, it, expect, beforeAll } from 'vitest';
import sodium, { sodiumReady } from '../../src/crypto/sodium';
import { KeyManager } from '../../src/crypto/KeyManager';
import { Encoding } from '../../src/common/Encoding';

const hex = (u: Uint8Array) => Encoding.toHex(u);
const BOARD = new Uint8Array(32).fill(0x11);

beforeAll(async () => {
  await sodiumReady;
});

describe('KeyManager: 鍵の派生', () => {
  it('deriveThreadKey は 32 バイトで、同じ入力なら同じ鍵', () => {
    const a = KeyManager.deriveThreadKey(BOARD, 't1');
    expect(a).toHaveLength(32);
    expect(hex(KeyManager.deriveThreadKey(BOARD, 't1'))).toBe(hex(a));
  });

  it('スレッドが違えば・板が違えば別の鍵になる', () => {
    const other = new Uint8Array(32).fill(0x12);
    const keys = new Set([
      hex(KeyManager.deriveThreadKey(BOARD, 't1')),
      hex(KeyManager.deriveThreadKey(BOARD, 't2')),
      hex(KeyManager.deriveThreadKey(BOARD, '')),
      hex(KeyManager.deriveThreadKey(other, 't1')),
    ]);
    expect(keys.size).toBe(4);
  });

  it('スレッド鍵は板の鍵による MAC (板の鍵を知らない者には計算できない)', () => {
    const tk = KeyManager.deriveThreadKey(BOARD, 'abc');
    expect(sodium.crypto_auth_verify(tk, new TextEncoder().encode('thread:abc'), BOARD)).toBe(true);
    expect(hex(tk)).not.toBe(hex(BOARD));
    // ドメイン接頭辞 "thread:" が付く: 生の threadId への MAC とは一致しない
    expect(hex(tk)).not.toBe(hex(sodium.crypto_auth(new TextEncoder().encode('abc'), BOARD)));
  });

  it('32 バイト以外の板の鍵は受け付けない', () => {
    expect(() => KeyManager.deriveThreadKey(new Uint8Array(16), 't')).toThrow();
    expect(() => KeyManager.deriveThreadKey(new Uint8Array(33), 't')).toThrow();
  });

  it('VIP 板の鍵 = SHA-512("OZ_LITE_VIP_DEFAULT_SEED") の先頭 32 バイト (ゴールデンベクタ)', () => {
    const key = KeyManager.cryptoHash(new TextEncoder().encode('OZ_LITE_VIP_DEFAULT_SEED')).slice(0, 32);
    expect(hex(key)).toBe('a87054299f619cbd2e7e1acdeaafbebe7978bccf6f2be20d0f8032e5280a4c77');
  });

  it('cryptoHash は SHA-512 (既知ベクトル "abc")', () => {
    const h = KeyManager.cryptoHash(new TextEncoder().encode('abc'));
    expect(h).toHaveLength(64);
    expect(hex(h).startsWith('ddaf35a193617aba')).toBe(true);
  });
});

describe('KeyManager: 補助', () => {
  it('generateBoardKey は 32 バイトの乱数で毎回異なる', () => {
    const a = KeyManager.generateBoardKey();
    const b = KeyManager.generateBoardKey();
    expect(a).toHaveLength(32);
    expect(hex(a)).not.toBe(hex(b));
  });

  it('hex / Base64URL の変換は Encoding と同じ結果で往復する', () => {
    const k = KeyManager.generateBoardKey();
    expect(KeyManager.toHex(k)).toBe(Encoding.toHex(k));
    expect(hex(KeyManager.fromHex(KeyManager.toHex(k)))).toBe(hex(k));
    expect(KeyManager.toBase64(k)).toBe(Encoding.toBase64(k));
    expect(hex(KeyManager.fromBase64(KeyManager.toBase64(k)))).toBe(hex(k));
  });
});

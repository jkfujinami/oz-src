import { describe, it, expect, beforeAll } from 'vitest';
import vm from 'node:vm';
import { sodiumReady } from '../../src/crypto/sodium';
import { DataVault, WrongPassphraseError } from '../../src/storage/DataVault';
import { SecretVault, VAULT_PARAMS_FAST, type SealedSecret } from '../../src/storage/SecretVault';
import { containsBytes } from '../helpers/cryptoStorageFixtures';

const PASS = 'data vault passphrase';
const AD = 'kv:abc123';
const hex = (u: Uint8Array) => Buffer.from(u).toString('hex');
const flip = (u: Uint8Array, i: number) => { const c = Uint8Array.from(u); c[i] ^= 1; return c; };

let vault: DataVault;
let sealed: SealedSecret;

beforeAll(async () => {
  await sodiumReady;
  ({ vault, sealed } = DataVault.create(PASS, VAULT_PARAMS_FAST));
});

describe('DataVault: 作成とロック解除', () => {
  it('create は DEK をパスフレーズで封印し (protected)、同じパスフレーズで開ける', () => {
    expect(sealed.protected).toBe(true);
    expect(vault.isOpen).toBe(true);
    const reopened = DataVault.open(sealed, PASS);
    const blob = vault.seal({ a: 1 }, AD);
    expect(reopened.open(blob, AD)).toEqual({ a: 1 });
    expect(reopened.index('x', 'y')).toBe(vault.index('x', 'y'));
  });

  it('空・文字列でないパスフレーズでは作らない・開かない (RangeError)', () => {
    for (const p of ['', undefined, null, 42]) {
      expect(() => DataVault.create(p as any, VAULT_PARAMS_FAST)).toThrow(RangeError);
      expect(() => DataVault.open(sealed, p as any)).toThrow(RangeError);
    }
  });

  it('違うパスフレーズは WrongPassphraseError', () => {
    expect(() => DataVault.open(sealed, 'nope')).toThrow(WrongPassphraseError);
    try {
      DataVault.open(sealed, 'nope');
    } catch (e: any) {
      expect(e.name).toBe('WrongPassphraseError');
      expect(e.message).not.toContain('nope');
    }
  });

  it('封印の改竄も WrongPassphraseError (区別しない)', () => {
    expect(() => DataVault.open({ ...sealed, ciphertext: flip(sealed.ciphertext, 0) }, PASS)).toThrow(WrongPassphraseError);
    expect(() => DataVault.open({ ...sealed, v: 9 as any }, PASS)).toThrow(WrongPassphraseError);
    expect(() => DataVault.open(null as any, PASS)).toThrow(WrongPassphraseError);
  });

  it('正しく封印されていても DEK の長さが 32 バイトでなければ拒否する', () => {
    for (const n of [0, 16, 31, 33, 64]) {
      const s = SecretVault.seal(new Uint8Array(n).fill(1), PASS, VAULT_PARAMS_FAST);
      expect(() => DataVault.open(s, PASS)).toThrow(WrongPassphraseError);
      expect(() => DataVault.rewrap(s, PASS, 'x', VAULT_PARAMS_FAST)).toThrow(WrongPassphraseError);
    }
  });

  it('create のたびに別の DEK になる (別の金庫の暗号文は開けない)', () => {
    const other = DataVault.create(PASS, VAULT_PARAMS_FAST).vault;
    expect(other.open(vault.seal('x', AD), AD)).toBeNull();
    expect(other.index('l', 'v')).not.toBe(vault.index('l', 'v'));
  });
});

describe('DataVault: レコードの暗号化', () => {
  it('様々な値が往復する', () => {
    const values: unknown[] = [
      null, true, 0, -1, 1.5, 2 ** 40, 'text', '', [1, 'a', null],
      { nested: { bytes: new Uint8Array([1, 2, 3]), list: [new Uint8Array(0)] } },
      new Uint8Array(4096).fill(0xab),
    ];
    for (const v of values) expect(vault.open(vault.seal(v, AD), AD)).toEqual(v);
  });

  it('形式は nonce(24) ‖ 暗号文 で、同じ値でも毎回 nonce と暗号文が変わる', () => {
    const a = vault.seal('same', AD);
    const b = vault.seal('same', AD);
    expect(hex(a.subarray(0, 24))).not.toBe(hex(b.subarray(0, 24)));
    expect(hex(a)).not.toBe(hex(b));
    expect(a.length).toBeGreaterThan(24 + 16);
  });

  it('暗号文に平文が現れない', () => {
    const marker = 'PLAINTEXT-MARKER-XYZ';
    const blob = vault.seal({ note: marker, raw: new TextEncoder().encode(marker) }, AD);
    expect(containsBytes(blob, new TextEncoder().encode(marker))).toBe(false);
    expect(containsBytes(blob, new TextEncoder().encode(AD))).toBe(false);
  });

  it('AD (置き場所) が違えば開けない (別のレコードへのすり替え検出)', () => {
    const blob = vault.seal({ secret: 1 }, 'boards:aaaa');
    for (const ad of ['boards:aaab', 'boards:aaaa ', 'kv:aaaa', '', 'BOARDS:aaaa']) {
      expect(vault.open(blob, ad)).toBeNull();
    }
    expect(vault.open(blob, 'boards:aaaa')).toEqual({ secret: 1 });
  });

  it('どのバイトを改竄しても null (nonce・本文・タグ)', () => {
    const blob = vault.seal({ v: 'integrity' }, AD);
    for (let i = 0; i < blob.length; i++) {
      expect(vault.open(flip(blob, i), AD)).toBeNull();
    }
  });

  it('切り詰め・延長・nonce 長以下の入力は null', () => {
    const blob = vault.seal('x', AD);
    expect(vault.open(blob.subarray(0, blob.length - 1), AD)).toBeNull();
    expect(vault.open(new Uint8Array([...blob, 0]), AD)).toBeNull();
    expect(vault.open(new Uint8Array(24), AD)).toBeNull();
    expect(vault.open(new Uint8Array(0), AD)).toBeNull();
    expect(vault.open(blob.subarray(0, 24), AD)).toBeNull();
  });

  it('Uint8Array 以外は例外を投げず null', () => {
    const blob = vault.seal('x', AD);
    for (const b of [null, undefined, 'abc', 123, {}, Array.from(blob), blob.buffer, Buffer.from(blob).toString('base64'), new DataView(blob.buffer)]) {
      expect(vault.open(b, AD)).toBeNull();
    }
  });

  it('別の realm の Uint8Array (IndexedDB 経由など) でも開ける', () => {
    const blob = vault.seal({ realm: 'other' }, AD);
    const foreign = vm.runInNewContext('new Uint8Array(arr)', { arr: Array.from(blob) });
    expect(foreign instanceof Uint8Array).toBe(false);
    expect(vault.open(foreign, AD)).toEqual({ realm: 'other' });
  });

  it('Buffer (Uint8Array のサブクラス) も開ける', () => {
    const blob = vault.seal('buf', AD);
    expect(vault.open(Buffer.from(blob), AD)).toBe('buf');
  });
});

describe('DataVault.index (検索キー)', () => {
  it('決定的で 32 文字の hex。値そのものを含まない', () => {
    const k = vault.index('board', 'secret-board-id');
    expect(k).toMatch(/^[0-9a-f]{32}$/);
    expect(vault.index('board', 'secret-board-id')).toBe(k);
    expect(k).not.toContain('secret');
  });

  it('ラベルでドメイン分離される (同じ値でも用途が違えば別のキー)', () => {
    const keys = new Set(['board', 'thread', 'kv', 'mailbox', 'boardkey'].map((l) => vault.index(l, 'same')));
    expect(keys.size).toBe(5);
  });

  it('ラベルと値の境界は区切り文字で固定される ("ab"+"c" と "a"+"bc" は別)', () => {
    expect(vault.index('ab', 'c')).not.toBe(vault.index('a', 'bc'));
    expect(vault.index('a', '')).not.toBe(vault.index('', 'a'));
  });
});

describe('DataVault.rewrap (パスワード変更)', () => {
  it('DEK は変わらず、新しいパスフレーズでだけ開ける', () => {
    const blob = vault.seal({ keep: 'me' }, AD);
    const rewrapped = DataVault.rewrap(sealed, PASS, 'new pass', VAULT_PARAMS_FAST);
    expect(rewrapped.protected).toBe(true);
    expect(hex(rewrapped.salt)).not.toBe(hex(sealed.salt));
    const v2 = DataVault.open(rewrapped, 'new pass');
    expect(v2.open(blob, AD)).toEqual({ keep: 'me' });
    expect(v2.index('a', 'b')).toBe(vault.index('a', 'b'));
    expect(() => DataVault.open(rewrapped, PASS)).toThrow(WrongPassphraseError);
  });

  it('旧パスフレーズが違えば WrongPassphraseError、新パスフレーズが空なら RangeError', () => {
    expect(() => DataVault.rewrap(sealed, 'wrong', 'new', VAULT_PARAMS_FAST)).toThrow(WrongPassphraseError);
    expect(() => DataVault.rewrap(sealed, '', 'new', VAULT_PARAMS_FAST)).toThrow(WrongPassphraseError);
    expect(() => DataVault.rewrap(sealed, PASS, '', VAULT_PARAMS_FAST)).toThrow(RangeError);
  });
});

describe('DataVault.wipe (メモリ上の鍵の消去)', () => {
  it('鍵のバッファをゼロで上書きし、以後の操作は locked で失敗する', () => {
    const { vault: v } = DataVault.create(PASS, VAULT_PARAMS_FAST);
    const blob = v.seal('before wipe', AD);
    const encKey: Uint8Array = (v as any).encKey;
    const idxKey: Uint8Array = (v as any).idxKey;
    expect(encKey.some((b) => b !== 0)).toBe(true);

    v.wipe();
    expect(v.isOpen).toBe(false);
    expect(Array.from(encKey).every((b) => b === 0)).toBe(true);
    expect(Array.from(idxKey).every((b) => b === 0)).toBe(true);
    expect(() => v.seal('x', AD)).toThrow(/locked/);
    expect(() => v.open(blob, AD)).toThrow(/locked/);
    expect(() => v.index('a', 'b')).toThrow(/locked/);
    // 二重の wipe は無害
    expect(() => v.wipe()).not.toThrow();
  });

  it('wipe しても同じ封印から開き直せば読める (DEK 自体は失われない)', () => {
    const { vault: v, sealed: s } = DataVault.create(PASS, VAULT_PARAMS_FAST);
    const blob = v.seal(42, AD);
    v.wipe();
    expect(DataVault.open(s, PASS).open(blob, AD)).toBe(42);
  });

  it('暗号化鍵と検索キー鍵は別物 (用途ごとに KDF で分離)', () => {
    const { vault: v } = DataVault.create(PASS, VAULT_PARAMS_FAST);
    expect(hex((v as any).encKey)).not.toBe(hex((v as any).idxKey));
    expect((v as any).encKey).toHaveLength(32);
    expect((v as any).idxKey).toHaveLength(32);
  });
});

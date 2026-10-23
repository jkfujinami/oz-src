import { describe, it, expect, beforeAll } from 'vitest';
import sodium, { sodiumReady } from '../../src/crypto/sodium';
import { SecretVault, VAULT_PARAMS, VAULT_PARAMS_FAST, type SealedSecret } from '../../src/storage/SecretVault';
import { containsBytes } from '../helpers/cryptoStorageFixtures';

const PASS = 'vault passphrase';
const SECRET = new TextEncoder().encode('SECRET-KEY-MATERIAL-0123456789abcdef');
const hex = (u: Uint8Array) => Buffer.from(u).toString('hex');
const flip = (u: Uint8Array, i = 0) => { const c = Uint8Array.from(u); c[i] ^= 1; return c; };

let sealed: SealedSecret;

beforeAll(async () => {
  await sodiumReady;
  sealed = SecretVault.seal(SECRET, PASS, VAULT_PARAMS_FAST);
});

describe('SecretVault: 封印の形', () => {
  it('v=1・protected・salt 16・nonce 24・暗号文 = 本文 + 16・パラメータを記録する', () => {
    expect(sealed.v).toBe(1);
    expect(sealed.protected).toBe(true);
    expect(sealed.salt).toHaveLength(sodium.crypto_pwhash_SALTBYTES);
    expect(sealed.nonce).toHaveLength(sodium.crypto_secretbox_NONCEBYTES);
    expect(sealed.ciphertext).toHaveLength(SECRET.length + sodium.crypto_secretbox_MACBYTES);
    expect(sealed.opsLimit).toBe(VAULT_PARAMS_FAST.opsLimit);
    expect(sealed.memLimit).toBe(VAULT_PARAMS_FAST.memLimit);
  });

  it('既定パラメータは FAST より重い (本番で弱いパラメータが使われない)', () => {
    expect(VAULT_PARAMS.opsLimit).toBeGreaterThanOrEqual(3);
    expect(VAULT_PARAMS.memLimit).toBeGreaterThanOrEqual(64 * 1024 * 1024);
    expect(VAULT_PARAMS.memLimit).toBeGreaterThan(VAULT_PARAMS_FAST.memLimit);
  });

  it('暗号文に秘密が平文で現れず、パスフレーズも記録されない', () => {
    expect(containsBytes(sealed.ciphertext, SECRET.subarray(0, 8))).toBe(false);
    const json = JSON.stringify(sealed, (_k, v) => (v instanceof Uint8Array ? hex(v) : v));
    expect(json).not.toContain(hex(SECRET.subarray(0, 8)));
    expect(json).not.toContain(PASS);
    expect(json).not.toContain(hex(new TextEncoder().encode(PASS)));
  });

  it('同じ秘密・同じパスフレーズでも salt / nonce / 暗号文は毎回変わる', () => {
    const again = SecretVault.seal(SECRET, PASS, VAULT_PARAMS_FAST);
    expect(hex(again.salt)).not.toBe(hex(sealed.salt));
    expect(hex(again.nonce)).not.toBe(hex(sealed.nonce));
    expect(hex(again.ciphertext)).not.toBe(hex(sealed.ciphertext));
  });

  it('空のパスフレーズは protected: false として記録される', () => {
    const s = SecretVault.seal(SECRET, '', VAULT_PARAMS_FAST);
    expect(s.protected).toBe(false);
    expect(hex(SecretVault.open(s, '')!)).toBe(hex(SECRET));
    expect(SecretVault.open(s, 'anything')).toBeNull();
  });
});

describe('SecretVault.open', () => {
  it('正しいパスフレーズで元に戻る (空の秘密も)', () => {
    expect(hex(SecretVault.open(sealed, PASS)!)).toBe(hex(SECRET));
    const empty = SecretVault.seal(new Uint8Array(0), PASS, VAULT_PARAMS_FAST);
    expect(SecretVault.open(empty, PASS)).toHaveLength(0);
  });

  it('Unicode のパスフレーズも往復する', () => {
    const p = '合言葉🔑 パス';
    const s = SecretVault.seal(SECRET, p, VAULT_PARAMS_FAST);
    expect(hex(SecretVault.open(s, p)!)).toBe(hex(SECRET));
    expect(SecretVault.open(s, '合言葉🔑')).toBeNull();
  });

  it('違うパスフレーズ (1 文字違い・大文字小文字・前後空白) は null', () => {
    for (const p of ['vault passphrasE', 'vault passphras', ` ${PASS}`, `${PASS} `, '']) {
      expect(SecretVault.open(sealed, p)).toBeNull();
    }
  });

  it('暗号文・タグ・nonce・salt のどの改竄も null', () => {
    for (let i = 0; i < sealed.ciphertext.length; i += 7) {
      expect(SecretVault.open({ ...sealed, ciphertext: flip(sealed.ciphertext, i) }, PASS)).toBeNull();
    }
    expect(SecretVault.open({ ...sealed, ciphertext: flip(sealed.ciphertext, sealed.ciphertext.length - 1) }, PASS)).toBeNull();
    expect(SecretVault.open({ ...sealed, nonce: flip(sealed.nonce, 23) }, PASS)).toBeNull();
    expect(SecretVault.open({ ...sealed, salt: flip(sealed.salt, 15) }, PASS)).toBeNull();
  });

  it('記録された Argon2id パラメータを書き換えると (鍵が変わるので) 開けない', () => {
    expect(SecretVault.open({ ...sealed, opsLimit: sealed.opsLimit + 1 }, PASS)).toBeNull();
    expect(SecretVault.open({ ...sealed, memLimit: sealed.memLimit * 2 }, PASS)).toBeNull();
  });

  it('封印をすり替えても別の封印のパスフレーズでは開けない', () => {
    const other = SecretVault.seal(SECRET, 'other', VAULT_PARAMS_FAST);
    // 他の封印の暗号文だけを移植
    expect(SecretVault.open({ ...sealed, ciphertext: other.ciphertext, nonce: other.nonce }, PASS)).toBeNull();
    expect(SecretVault.open({ ...sealed, ciphertext: other.ciphertext, nonce: other.nonce }, 'other')).toBeNull();
  });

  it('形の壊れた封印は例外を投げず null', () => {
    const bads: any[] = [
      null,
      undefined,
      {},
      { ...sealed, v: 2 },
      { ...sealed, v: '1' },
      { ...sealed, salt: undefined },
      { ...sealed, salt: sealed.salt.subarray(0, 8) },
      { ...sealed, nonce: sealed.nonce.subarray(0, 12) },
      { ...sealed, nonce: undefined },
      { ...sealed, ciphertext: undefined },
      { ...sealed, ciphertext: new Uint8Array(0) },
      { ...sealed, ciphertext: sealed.ciphertext.subarray(0, 15) },
      { ...sealed, opsLimit: 0 },
      { ...sealed, memLimit: 0 },
      { ...sealed, memLimit: -1 },
      { ...sealed, opsLimit: 'x' },
    ];
    for (const b of bads) {
      expect(() => SecretVault.open(b, PASS)).not.toThrow();
      expect(SecretVault.open(b, PASS)).toBeNull();
    }
  });
});

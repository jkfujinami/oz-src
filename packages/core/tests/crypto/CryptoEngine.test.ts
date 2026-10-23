import { describe, it, expect } from 'vitest';
import sodium from '../../src/crypto/sodium';
import { CryptoEngine } from '../../src/crypto/CryptoEngine';
import { POW_POLICY } from '../../src/crypto/PowPolicy';
import { containsBytes } from '../helpers/cryptoStorageFixtures';

const KEY = new Uint8Array(32).fill(0x42);
const OTHER = new Uint8Array(32).fill(0x43);
const AAD = Uint8Array.of(2, 0, 0, 1, 0x0a, 0xbc, 3);
const msg = (s: string) => new TextEncoder().encode(s);

describe('CryptoEngine (SIV: 決定的 AEAD)', () => {
  it('暗号化して同じ鍵・同じ AAD で復号すると元に戻る (空の平文も)', () => {
    for (const p of [msg('hello world'), new Uint8Array(0), new Uint8Array(2048).fill(7)]) {
      const payload = CryptoEngine.encrypt(KEY, p, AAD);
      expect(Array.from(CryptoEngine.decrypt(KEY, payload, AAD)!)).toEqual(Array.from(p));
    }
  });

  it('ペイロードの長さは siv 16 + 平文。nonce も magic も載らない', () => {
    expect(CryptoEngine.encrypt(KEY, msg('abc'), AAD)).toHaveLength(POW_POLICY.SIV_BYTES + 3);
    expect(CryptoEngine.encrypt(KEY, new Uint8Array(0), AAD)).toHaveLength(16);
  });

  it('暗号文に平文がそのまま現れない', () => {
    const plain = msg('PLAINTEXT-MARKER-PLAINTEXT-MARKER');
    expect(containsBytes(CryptoEngine.encrypt(KEY, plain, AAD), plain)).toBe(false);
  });

  it('決定的: 同じ鍵・AAD・平文は同じペイロード。どれかが違えば変わる', () => {
    const a = CryptoEngine.encrypt(KEY, msg('same'), AAD);
    expect(Array.from(CryptoEngine.encrypt(KEY, msg('same'), AAD))).toEqual(Array.from(a));
    expect(Array.from(CryptoEngine.encrypt(KEY, msg('sane'), AAD))).not.toEqual(Array.from(a));
    expect(Array.from(CryptoEngine.encrypt(OTHER, msg('same'), AAD))).not.toEqual(Array.from(a));
    const aad2 = Uint8Array.from(AAD); aad2[6] ^= 1;
    expect(Array.from(CryptoEngine.encrypt(KEY, msg('same'), aad2))).not.toEqual(Array.from(a));
  });

  it('別の鍵では復号できず null', () => {
    expect(CryptoEngine.decrypt(OTHER, CryptoEngine.encrypt(KEY, msg('secret'), AAD), AAD)).toBeNull();
  });

  it('★AAD (ヘッダの version/time/tag/age) が 1 ビットでも違えば null', () => {
    const payload = CryptoEngine.encrypt(KEY, msg('bound to header'), AAD);
    for (let i = 0; i < AAD.length; i++) {
      for (let bit = 0; bit < 8; bit++) {
        const a = Uint8Array.from(AAD); a[i] ^= 1 << bit;
        expect(CryptoEngine.decrypt(KEY, payload, a), `aad byte ${i} bit ${bit}`).toBeNull();
      }
    }
  });

  it('siv・暗号文のどの 1 ビットを反転しても null', () => {
    const payload = CryptoEngine.encrypt(KEY, msg('integrity'), AAD);
    for (let i = 0; i < payload.length; i++) {
      for (let bit = 0; bit < 8; bit++) {
        const p = Uint8Array.from(payload); p[i] ^= 1 << bit;
        expect(CryptoEngine.decrypt(KEY, p, AAD), `byte ${i} bit ${bit}`).toBeNull();
      }
    }
  });

  it('切り詰め・空・追加バイトは null', () => {
    const payload = CryptoEngine.encrypt(KEY, msg('truncate me'), AAD);
    expect(CryptoEngine.decrypt(KEY, payload.subarray(0, payload.length - 1), AAD)).toBeNull();
    expect(CryptoEngine.decrypt(KEY, new Uint8Array(0), AAD)).toBeNull();
    expect(CryptoEngine.decrypt(KEY, new Uint8Array(15), AAD)).toBeNull();
    const longer = new Uint8Array(payload.length + 1); longer.set(payload);
    expect(CryptoEngine.decrypt(KEY, longer, AAD)).toBeNull();
  });

  it('不正な鍵長でも例外を投げず null。暗号化は例外', () => {
    const payload = CryptoEngine.encrypt(KEY, msg('x'), AAD);
    expect(CryptoEngine.decrypt(new Uint8Array(16), payload, AAD)).toBeNull();
    expect(CryptoEngine.decrypt(KEY, null as any, AAD)).toBeNull();
    expect(() => CryptoEngine.encrypt(new Uint8Array(8), msg('x'), AAD)).toThrow();
  });

  it('仕様どおりの構成: K_enc / K_mac を BLAKE2b から導き、siv = BLAKE2b-128(K_mac, AAD ‖ 平文)、nonce = siv ‖ 0*8 の XChaCha20', () => {
    const plain = msg('construction check');
    const kEnc = sodium.crypto_generichash(32, msg('oz/v5/enc'), KEY);
    const kMac = sodium.crypto_generichash(32, msg('oz/v5/mac'), KEY);
    const cat = new Uint8Array(AAD.length + plain.length); cat.set(AAD); cat.set(plain, AAD.length);
    const siv = sodium.crypto_generichash(16, cat, kMac);
    const nonce = new Uint8Array(24); nonce.set(siv);
    const ct = sodium.crypto_stream_xchacha20_xor(plain, nonce, kEnc);
    const expected = new Uint8Array(16 + ct.length); expected.set(siv); expected.set(ct, 16);
    expect(Array.from(CryptoEngine.encrypt(KEY, plain, AAD))).toEqual(Array.from(expected));
  });

  it('インスタンスメソッドは静的版と相互運用できる', () => {
    const engine = new CryptoEngine();
    const payload = engine.encrypt(KEY, msg('inst'), AAD);
    expect(new TextDecoder().decode(CryptoEngine.decrypt(KEY, payload, AAD)!)).toBe('inst');
    expect(new TextDecoder().decode(engine.decrypt(KEY, CryptoEngine.encrypt(KEY, msg('stat'), AAD), AAD)!)).toBe('stat');
  });
});

import { describe, it, expect, beforeAll } from 'vitest';
import sodium, { sodiumReady } from '../../src/crypto/sodium';
import { Encoding } from '../../src/common/Encoding';
import { StorageIdentity } from '../../src/network/storage/StorageIdentity';
import {
  RESP_KEY_BYTES, TUNNEL_CHUNK_DATA_BYTES, TUNNEL_KIND, chunkCipherBytes, decryptChunk, encryptChunk, newRespKey,
  parseRequestPlain, sealRequest, sealedRequestBytes,
} from '../../src/network/tunnel/TunnelCrypto';
import { MAX_TUNNEL_FRAME_BYTES, TUNNEL_HEADER_BYTES } from '../../src/network/wire/WireCodec';

beforeAll(async () => { await sodiumReady; });

describe('TunnelCrypto: 要求の封印 (sealed box)', () => {
  it('★H の SID 宛てに封印した要求は、その SID の持ち主だけが開ける。kind・respKey・payload が戻る', async () => {
    const holder = await StorageIdentity.loadOrCreate(null, 1);
    const other = await StorageIdentity.loadOrCreate(null, 1);
    const respKey = newRespKey();
    const payload = Uint8Array.of(1, 2, 3, 4, 5, 6, 7);
    const sealed = sealRequest(holder.publicKey, TUNNEL_KIND.FETCH_BUCKET, respKey, payload)!;
    expect(sealed.length).toBe(sealedRequestBytes(payload.length));
    expect(sealed.length).toBe(48 + 1 + 32 + 7);

    expect(other.openSealed(sealed)).toBeNull(); // 他人 (経路上の Guard を含む) には開けない
    const opened = parseRequestPlain(holder.openSealed(sealed)!)!;
    expect(opened.kind).toBe(TUNNEL_KIND.FETCH_BUCKET);
    expect(Array.from(opened.respKey)).toEqual(Array.from(respKey));
    expect(Array.from(opened.payload)).toEqual(Array.from(payload));
    await holder.destroy();
    await other.destroy();
  });

  it('★封印は毎回違うバイト列 (使い捨ての鍵)。要求者の鍵は載らない。改ざん・切り詰めは開けない', async () => {
    const holder = await StorageIdentity.loadOrCreate(null, 1);
    const respKey = newRespKey();
    const a = sealRequest(holder.publicKey, 1, respKey, Uint8Array.of(9))!;
    const b = sealRequest(holder.publicKey, 1, respKey, Uint8Array.of(9))!;
    expect(Encoding.toHex(a)).not.toBe(Encoding.toHex(b));
    const tampered = a.slice();
    tampered[tampered.length - 1] ^= 1;
    expect(holder.openSealed(tampered)).toBeNull();
    expect(holder.openSealed(a.subarray(0, a.length - 1))).toBeNull();
    expect(holder.openSealed(new Uint8Array(0))).toBeNull();
    await holder.destroy();
    expect(holder.openSealed(a)).toBeNull(); // 停止後は開けない
  });

  it('不正な SID の鍵・短すぎる平文は null', () => {
    expect(sealRequest(new Uint8Array(32), 1, newRespKey(), Uint8Array.of(1))).toBeNull();
    expect(sealRequest(new Uint8Array(5), 1, newRespKey(), Uint8Array.of(1))).toBeNull();
    expect(parseRequestPlain(new Uint8Array(32))).toBeNull();
  });
});

describe('TunnelCrypto: 応答の 1 片 (XChaCha20-Poly1305)', () => {
  const key = new Uint8Array(RESP_KEY_BYTES).fill(0x42);

  it('★往復する。nonce = u64 seq (末尾 8 バイト・ビッグエンディアン)、AAD = kind。ベクタで固定', () => {
    const data = Uint8Array.from({ length: 20 }, (_, i) => i);
    const c = encryptChunk(key, TUNNEL_KIND.FETCH_BUCKET, 3, true, data);
    expect(c.length).toBe(chunkCipherBytes(20));
    // 独立に組み立てた nonce / AAD / 平文 (final u8 ‖ データ) で同じ暗号文になる
    const nonce = new Uint8Array(24);
    nonce[23] = 3;
    const plain = new Uint8Array(21);
    plain[0] = 1;
    plain.set(data, 1);
    const expected = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plain, Uint8Array.of(1), null, nonce, key);
    expect(Encoding.toHex(c)).toBe(Encoding.toHex(expected));
    expect(Encoding.toHex(c)).toBe(VECTOR_CHUNK);
    const d = decryptChunk(key, TUNNEL_KIND.FETCH_BUCKET, 3, c)!;
    expect(d.final).toBe(true);
    expect(Array.from(d.data)).toEqual(Array.from(data));
  });

  it('★seq・kind・鍵・1 ビットの改ざん・切り詰めのどれが違っても復号できない (別の片への差し替え・並べ替えも)', () => {
    const c = encryptChunk(key, 1, 5, false, Uint8Array.of(1, 2, 3));
    expect(decryptChunk(key, 1, 5, c)).not.toBeNull();
    expect(decryptChunk(key, 1, 6, c)).toBeNull();
    expect(decryptChunk(key, 2, 5, c)).toBeNull();
    expect(decryptChunk(new Uint8Array(32).fill(1), 1, 5, c)).toBeNull();
    for (const i of [0, 3, c.length - 1]) {
      const t = c.slice();
      t[i] ^= 0x01;
      expect(decryptChunk(key, 1, 5, t), `byte ${i}`).toBeNull();
    }
    expect(decryptChunk(key, 1, 5, c.subarray(0, c.length - 1))).toBeNull();
    expect(decryptChunk(key, 1, 5, new Uint8Array(3))).toBeNull();
  });

  it('★final は暗号文の中にある: 同じデータでも final の有無で暗号文が違い、書き換えられない', () => {
    const a = encryptChunk(key, 1, 0, false, Uint8Array.of(7));
    const b = encryptChunk(key, 1, 0, true, Uint8Array.of(7));
    expect(Encoding.toHex(a)).not.toBe(Encoding.toHex(b));
    expect(decryptChunk(key, 1, 0, a)!.final).toBe(false);
    expect(decryptChunk(key, 1, 0, b)!.final).toBe(true);
  });

  it('1 片の最大 (データ 15KiB) は TUNNEL_REPLY / RESULT のフレーム (16KiB) に収まる。空のデータも運べる', () => {
    const max = encryptChunk(key, 1, 0, true, new Uint8Array(TUNNEL_CHUNK_DATA_BYTES));
    expect(max.length).toBe(TUNNEL_CHUNK_DATA_BYTES + 17);
    expect(TUNNEL_HEADER_BYTES.REPLY + max.length).toBeLessThanOrEqual(MAX_TUNNEL_FRAME_BYTES);
    const empty = encryptChunk(key, 1, 0, true, new Uint8Array(0));
    expect(decryptChunk(key, 1, 0, empty)!.data.length).toBe(0);
    expect(() => encryptChunk(key, 1, 0x10000, true, new Uint8Array(1))).toThrow(RangeError);
  });
});

/** encryptChunk(key = 0x42 × 32, kind 1, seq 3, final, データ = 0..19) の暗号文 (形式の固定。変えるならここも意図して更新する) */
const VECTOR_CHUNK = '7f03a15745b1b87a33727b904762a7b646ffc01f9fcf275cc73b0a516099fffc857985717c';

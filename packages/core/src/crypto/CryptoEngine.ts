import sodium from './sodium';
import type { ICryptoEngine } from '../types';
import { POW_POLICY } from './PowPolicy';

const enc = new TextEncoder();
const LABEL_ENC = enc.encode('oz/v5/enc');
const LABEL_MAC = enc.encode('oz/v5/mac');

/**
 * CryptoEngine — パケットの本文を包む SIV (決定的 AEAD)。
 *
 *   K_enc = BLAKE2b-256(key = K, "oz/v5/enc")
 *   K_mac = BLAKE2b-256(key = K, "oz/v5/mac")
 *   siv   = BLAKE2b-128(key = K_mac, AAD ‖ plaintext)
 *   ct    = XChaCha20(K_enc, nonce = siv ‖ 0x00 * 8, plaintext)
 *   payload = siv ‖ ct
 *
 * 復号は ct を戻して siv を計算し直し、定数時間で比べる。一致しなければ (鍵違い・AAD 違い・改竄) null。
 *
 * ★ なぜ SIV か (Rogaway–Shrimpton)。旧形式は 12 バイトの乱数 nonce を別に載せ、さらに平文の先頭に
 *   4 バイトの magic を足して「自分宛てか」の高速判定に使っていた。SIV は siv が「認証タグ」と
 *   「nonce」を兼ねるので、nonce の 12 バイトも magic の 4 バイトも要らない (タグ 16 バイトだけ)。
 *   決定的な暗号は「同じ平文 + 同じ AAD は同じ暗号文」になるが、投稿の平文には署名が入っていて
 *   投稿ごとに違う (署名は鍵・時刻・内容に依存する) ので、平文は実質的に必ず一意。
 *   一致が見えるのは「完全に同じ投稿」だけで、それは同じパケット (同じ packet_id) そのもの。
 *   乱数 nonce に頼らないので、端末の乱数の質 (起動直後・複製された VM など) にも依存しない。
 * ★ AAD は固定長 (外側ヘッダの先頭 7 バイト) なので、AAD ‖ plaintext の連結に曖昧さはない。
 *   AAD に time / tag / age を入れるので、ヘッダを書き換えると復号が通らない。
 * ★ 鍵が違えば siv が合わないので、他の板・他のスレのパケットは (署名を調べる前に) ここで落ちる。
 */
export class CryptoEngine implements ICryptoEngine {
  public encrypt(key: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Uint8Array {
    return CryptoEngine.encrypt(key, plaintext, aad);
  }

  public decrypt(key: Uint8Array, payload: Uint8Array, aad: Uint8Array): Uint8Array | null {
    return CryptoEngine.decrypt(key, payload, aad);
  }

  private static subkeys(key: Uint8Array): { kEnc: Uint8Array; kMac: Uint8Array } {
    // ★ 板 / スレの鍵は 32 バイト固定。BLAKE2b の鍵は 16〜64 バイトを受け付けてしまうので、ここで締める
    if (!(key instanceof Uint8Array) || key.length !== 32) throw new RangeError('CryptoEngine: key must be 32 bytes');
    return {
      kEnc: sodium.crypto_generichash(32, LABEL_ENC, key),
      kMac: sodium.crypto_generichash(32, LABEL_MAC, key),
    };
  }

  private static sivOf(kMac: Uint8Array, aad: Uint8Array, plaintext: Uint8Array): Uint8Array {
    const msg = new Uint8Array(aad.length + plaintext.length);
    msg.set(aad, 0);
    msg.set(plaintext, aad.length);
    return sodium.crypto_generichash(POW_POLICY.SIV_BYTES, msg, kMac);
  }

  private static nonceOf(siv: Uint8Array): Uint8Array {
    const nonce = new Uint8Array(24);
    nonce.set(siv, 0);
    return nonce;
  }

  static encrypt(key: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Uint8Array {
    const { kEnc, kMac } = CryptoEngine.subkeys(key);
    const siv = CryptoEngine.sivOf(kMac, aad, plaintext);
    const ct = sodium.crypto_stream_xchacha20_xor(plaintext, CryptoEngine.nonceOf(siv), kEnc);
    const out = new Uint8Array(siv.length + ct.length);
    out.set(siv, 0);
    out.set(ct, siv.length);
    return out;
  }

  static decrypt(key: Uint8Array, payload: Uint8Array, aad: Uint8Array): Uint8Array | null {
    if (!(payload instanceof Uint8Array) || payload.length < POW_POLICY.SIV_BYTES) return null;
    try {
      const { kEnc, kMac } = CryptoEngine.subkeys(key);
      const siv = payload.subarray(0, POW_POLICY.SIV_BYTES);
      const plaintext = sodium.crypto_stream_xchacha20_xor(
        payload.subarray(POW_POLICY.SIV_BYTES), CryptoEngine.nonceOf(siv), kEnc,
      );
      const expected = CryptoEngine.sivOf(kMac, aad, plaintext);
      // ★ 定数時間で比べる (一致した長さを時間で漏らさない)
      return sodium.memcmp(siv, expected) ? plaintext : null;
    } catch {
      return null;
    }
  }
}

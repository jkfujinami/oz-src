import sodium from './sodium';
import { Encoding } from '../common/Encoding';
import { CryptoUtils } from '../common/CryptoUtils';

export class KeyManager {
  /**
   * boardkey → thread_key を派生 (HMAC-SHA256)
   */
  static deriveThreadKey(boardkey: Uint8Array, threadId: string): Uint8Array {
    // 32バイトの派生鍵を生成
    return sodium.crypto_auth(
      new TextEncoder().encode(`thread:${threadId}`),
      boardkey,
    );
  }

  /**
   * URLフラグメントなどから取得したHex文字列をUint8Arrayに変換
   */
  static fromHex(hex: string): Uint8Array {
    return Encoding.fromHex(hex);
  }

  /**
   * Uint8ArrayをHex文字列に変換
   */
  static toHex(bytes: Uint8Array): string {
    return Encoding.toHex(bytes);
  }

  /**
   * 新しい板の鍵を生成
   */
  static generateBoardKey(): Uint8Array {
    return CryptoUtils.randomBytes(32);
  }

  /**
   * Base64URLをUint8Arrayに変換
   */
  static fromBase64(b64: string): Uint8Array {
    return Encoding.fromBase64(b64);
  }

  /**
   * Uint8ArrayをBase64URLに変換
   */
  static toBase64(bytes: Uint8Array): string {
    return Encoding.toBase64(bytes);
  }

  /**
   * SHA256ハッシュを計算
   */
  static cryptoHash(data: Uint8Array): Uint8Array {
    return sodium.crypto_hash(data);
  }
}


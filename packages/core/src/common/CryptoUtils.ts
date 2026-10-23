export class CryptoUtils {
  /**
   * ランダムなID（英数字の文字列）を生成
   * @param length 指定がない場合は10文字
   */
  static generateId(length: number = 10): string {
    // ★ Math.random は使わない。V8 の Math.random (xorshift128+) は数個の出力から
    //   内部状態を復元でき、網に出た ID 同士 (要求 ID・スレッド ID など) から
    //   「同じ端末が作った」ことを結び付けられてしまう。
    const alphabet = '0123456789abcdefghijklmnopqrstuvwxyz';
    const out: string[] = [];
    const buf = new Uint8Array(length * 2);
    while (out.length < length) {
      crypto.getRandomValues(buf);
      for (const b of buf) {
        if (b < 252 && out.length < length) out.push(alphabet[b % 36]); // 252 = 36 * 7 (偏りを消す)
      }
    }
    return out.join('');
  }

  /**
   * より強力な暗号学的に安全なランダムバイトを生成
   */
  static randomBytes(length: number): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(length));
  }

  /**
   * Uint8Array から 16進数文字列を生成（ Encoding との重複だが便宜上ここに置くこともあるが、Encoding に委譲する）
   */
}

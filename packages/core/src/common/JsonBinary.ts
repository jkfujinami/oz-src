/**
 * Uint8Array および BigInt を効率的（とは言えないが現状の仕様）にJSONで扱うためのシリアライザ
 */
const BIGINT_RE = /^-?\d{1,80}$/;

export class JsonBinary {
  /**
   * オブジェクトをJSON文字列に変換。Uint8Array および BigInt を自動的にラップする。
   */
  static stringify(obj: any): string {
    return JSON.stringify(obj, JsonBinary.replacer);
  }

  /**
   * JSON文字列をオブジェクトに復元。ラップされた Uint8Array および BigInt を自動的に復元する。
   */
  static parse<T = any>(json: string): T {
    return JSON.parse(json, JsonBinary.reviver);
  }

  /**
   * 既存の JSON.parse(reviver) 形式として使える関数のみを提供
   */
  /**
   * ★ 入力はネットワークから届く未認証のデータ (保管エントリ・同期) でもある。
   *   旧実装は data をそのまま Uint8Array のコンストラクタへ渡していたので、
   *   `{"_type":"Uint8Array","data":200000000}` (37 バイト) で 200MB を確保させたり、
   *   length だけ大きい偽の配列で数秒 CPU を占有させたりできた。
   *   配列であること・長さの上限・各要素が 0..255 の整数であることを確かめる。
   */
  static reviver(_key: string, value: any): any {
    if (value && value._type === 'BigInt') {
      if (typeof value.value !== 'string' || !BIGINT_RE.test(value.value)) {
        throw new TypeError('JsonBinary: invalid BigInt');
      }
      return BigInt(value.value);
    }
    if (value && value._type === 'Uint8Array') {
      const data = value.data;
      if (!Array.isArray(data) || data.length > JsonBinary.MAX_BYTES) {
        throw new TypeError('JsonBinary: invalid Uint8Array');
      }
      const out = new Uint8Array(data.length);
      for (let i = 0; i < data.length; i++) {
        const b = data[i];
        if (typeof b !== 'number' || !Number.isInteger(b) || b < 0 || b > 255) {
          throw new TypeError('JsonBinary: invalid byte');
        }
        out[i] = b;
      }
      return out;
    }
    return value;
  }

  /** 1 つの Uint8Array の上限 (保管エントリの上限よりも十分大きく取る) */
  static readonly MAX_BYTES = 1 << 20;

  /**
   * 既存 of JSON.stringify(replacer) 形式として使える関数のみを提供
   */
  static replacer(_key: string, value: any): any {
    if (typeof value === 'bigint') return { _type: 'BigInt', value: value.toString() };
    if (value instanceof Uint8Array) return { _type: 'Uint8Array', data: Array.from(value) };
    return value;
  }
}


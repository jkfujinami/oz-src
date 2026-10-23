/**
 * ByteIO — コンパクト形式 (PacketCodec / PostCodec / ExitItem) 用の最小の読み書き道具。
 *
 * ★ 読み取りは必ず範囲を確かめ、足りなければ例外にする。呼び出し側 (decode*) は
 *   例外を握って null を返す。ネットワークから来る入力は信用しないので、
 *   「切り詰め」「余りバイト」はすべて拒否する。
 */
export class ByteWriter {
  private parts: Uint8Array[] = [];
  private length = 0;

  u8(v: number): this {
    if (!Number.isInteger(v) || v < 0 || v > 0xff) throw new RangeError(`u8 out of range: ${v}`);
    return this.raw(Uint8Array.of(v));
  }

  u16(v: number): this {
    if (!Number.isInteger(v) || v < 0 || v > 0xffff) throw new RangeError(`u16 out of range: ${v}`);
    return this.raw(Uint8Array.of(v >>> 8, v & 0xff));
  }

  /** 48 ビット (ミリ秒時刻用) */
  u48(v: number): this {
    if (!Number.isSafeInteger(v) || v < 0 || v > 0xffffffffffff) throw new RangeError(`u48 out of range: ${v}`);
    const hi = Math.floor(v / 0x100000000);
    const lo = v >>> 0;
    return this.raw(Uint8Array.of(hi >>> 8, hi & 0xff, lo >>> 24, (lo >>> 16) & 0xff, (lo >>> 8) & 0xff, lo & 0xff));
  }

  u64(v: number | bigint): this {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, BigInt(v), false);
    return this.raw(b);
  }

  /** LEB128 (下位 7 ビットから)。安全な整数のみ */
  varint(v: number): this {
    if (!Number.isSafeInteger(v) || v < 0) throw new RangeError(`varint out of range: ${v}`);
    const out: number[] = [];
    let n = v;
    while (n >= 0x80) {
      out.push((n % 0x80) | 0x80);
      n = Math.floor(n / 0x80);
    }
    out.push(n);
    return this.raw(Uint8Array.from(out));
  }

  raw(b: Uint8Array): this {
    this.parts.push(b);
    this.length += b.length;
    return this;
  }

  finish(): Uint8Array {
    const out = new Uint8Array(this.length);
    let o = 0;
    for (const p of this.parts) {
      out.set(p, o);
      o += p.length;
    }
    return out;
  }
}

export class ByteReader {
  private o = 0;
  constructor(private readonly b: Uint8Array) {}

  get remaining(): number {
    return this.b.length - this.o;
  }

  private need(n: number): void {
    if (n < 0 || this.o + n > this.b.length) throw new RangeError('truncated');
  }

  u8(): number {
    this.need(1);
    return this.b[this.o++];
  }

  u16(): number {
    this.need(2);
    const v = (this.b[this.o] << 8) | this.b[this.o + 1];
    this.o += 2;
    return v;
  }

  u48(): number {
    this.need(6);
    const hi = (this.b[this.o] << 8) | this.b[this.o + 1];
    const lo = ((this.b[this.o + 2] << 24) | (this.b[this.o + 3] << 16) | (this.b[this.o + 4] << 8) | this.b[this.o + 5]) >>> 0;
    this.o += 6;
    return hi * 0x100000000 + lo;
  }

  u64(): bigint {
    this.need(8);
    const v = new DataView(this.b.buffer, this.b.byteOffset + this.o, 8).getBigUint64(0, false);
    this.o += 8;
    return v;
  }

  varint(): number {
    let result = 0;
    let mul = 1;
    for (let i = 0; i < 8; i++) {
      const byte = this.u8();
      result += (byte & 0x7f) * mul;
      if ((byte & 0x80) === 0) {
        // 最短形でなければ拒否 (同じ値の表現が複数あると署名対象が曖昧になる)
        if (i > 0 && byte === 0) throw new RangeError('non-canonical varint');
        if (!Number.isSafeInteger(result)) throw new RangeError('varint too large');
        return result;
      }
      mul *= 0x80;
    }
    throw new RangeError('varint too long');
  }

  bytes(n: number): Uint8Array {
    this.need(n);
    const out = this.b.subarray(this.o, this.o + n);
    this.o += n;
    return out;
  }

  rest(): Uint8Array {
    return this.bytes(this.remaining);
  }

  /** 余りバイトがあれば拒否する */
  end(): void {
    if (this.remaining !== 0) throw new RangeError('trailing bytes');
  }
}

import { describe, it, expect } from 'vitest';
import { Encoding } from '../../src/common/Encoding';
import {
  FETCH_MAX_RESPONSE_BYTES, FETCH_REQUEST_BYTES, FETCH_STATUS, buildFetchResponse, decodeFetchRequest, decodeFetchResponse,
  encodeFetchRequest, encodeFetchResponse,
} from '../../src/network/history/FetchBucket';

/** パケット (encodePacket 済み) の代役: 先頭 4 バイト = [version, time u24]、残りは詰め物 */
function fakePacket(timeMin: number, size = 100): Uint8Array {
  const b = new Uint8Array(size).fill(0xab);
  b[0] = 2;
  b[1] = timeMin >>> 16;
  b[2] = (timeMin >>> 8) & 0xff;
  b[3] = timeMin & 0xff;
  return b;
}
const timeOf = (p: Uint8Array) => (p[1] << 16) | (p[2] << 8) | p[3];

describe('FETCH_BUCKET の符号化', () => {
  it('★要求 = birthDay u16 ‖ tag u16 ‖ since u24 (7 バイト、ビッグエンディアン)。ベクタで固定', () => {
    const b = encodeFetchRequest({ birthDay: 20_500, tag: 0xabc, since: 0x0abcde });
    expect(b.length).toBe(FETCH_REQUEST_BYTES);
    expect(Encoding.toHex(b)).toBe('5014' + '0abc' + '0abcde');
    expect(decodeFetchRequest(b)).toEqual({ birthDay: 20_500, tag: 0xabc, since: 0x0abcde });
  });

  it('要求の範囲違反: encode は RangeError、decode は null (tag は 12 ビット、長さの過不足、余り)', () => {
    expect(() => encodeFetchRequest({ birthDay: 0x10000, tag: 0, since: 0 })).toThrow(RangeError);
    expect(() => encodeFetchRequest({ birthDay: 1, tag: 0x1000, since: 0 })).toThrow(RangeError);
    expect(() => encodeFetchRequest({ birthDay: 1, tag: 1, since: 0x1000000 })).toThrow(RangeError);
    expect(() => encodeFetchRequest({ birthDay: -1, tag: 1, since: 0 })).toThrow(RangeError);
    expect(decodeFetchRequest(Uint8Array.of(0x50, 0x14, 0x1a, 0xbc, 0, 0, 0))).toBeNull(); // tag 0x1abc
    expect(decodeFetchRequest(new Uint8Array(6))).toBeNull();
    expect(decodeFetchRequest(new Uint8Array(8))).toBeNull();
  });

  it('応答 = status u8 ‖ nextSince u24 ‖ { len u16 ‖ パケット } × n。往復する', () => {
    const packets = [fakePacket(100, 50), fakePacket(101, 70)];
    const b = encodeFetchResponse({ status: FETCH_STATUS.MORE, nextSince: 0x010203, packets });
    expect(b.length).toBe(1 + 3 + 2 + 50 + 2 + 70);
    expect(Array.from(b.subarray(0, 6))).toEqual([1, 1, 2, 3, 0, 50]);
    const r = decodeFetchResponse(b)!;
    expect(r.status).toBe(FETCH_STATUS.MORE);
    expect(r.nextSince).toBe(0x010203);
    expect(r.packets.map(p => Array.from(p))).toEqual(packets.map(p => Array.from(p)));
    // 0 件も運べる (OK: 「持っているが新しいものは無い」)
    expect(decodeFetchResponse(encodeFetchResponse({ status: FETCH_STATUS.OK, nextSince: 0, packets: [] }))!.packets).toEqual([]);
  });

  it('応答の壊れ方: 未知の status・切り詰め・長さ 0・NOT_HELD なのに中身がある、は null', () => {
    expect(decodeFetchResponse(Uint8Array.of(9, 0, 0, 0))).toBeNull();
    expect(decodeFetchResponse(Uint8Array.of(0, 0, 0))).toBeNull();
    expect(decodeFetchResponse(Uint8Array.of(0, 0, 0, 0, 0, 5, 1, 2))).toBeNull(); // 5 バイトと言って 2 バイト
    expect(decodeFetchResponse(Uint8Array.of(0, 0, 0, 0, 0, 0))).toBeNull(); // len = 0
    expect(decodeFetchResponse(Uint8Array.of(2, 0, 0, 0, 0, 1, 7))).toBeNull();
    expect(decodeFetchResponse(Uint8Array.of(2, 0, 0, 0))!.status).toBe(FETCH_STATUS.NOT_HELD);
    expect(() => encodeFetchResponse({ status: 0, nextSince: 0x1000000, packets: [] })).toThrow(RangeError);
    expect(() => encodeFetchResponse({ status: 0, nextSince: 0, packets: [new Uint8Array(0)] })).toThrow(RangeError);
  });
});

describe('buildFetchResponse: 4MiB で打ち切って since で続ける', () => {
  it('★上限内なら OK (nextSince は不要)。ちょうど上限でも OK', () => {
    const ps = Array.from({ length: 10 }, (_, i) => fakePacket(100 + i, 998)); // 1 件 = 2 + 998 = 1000
    const r = buildFetchResponse(ps, timeOf, 0, 10_000);
    expect(r.status).toBe(FETCH_STATUS.OK);
    expect(r.packets).toHaveLength(10);
    expect(buildFetchResponse(ps, timeOf, 0, 9_999).status).toBe(FETCH_STATUS.MORE);
  });

  it('★超えたら MORE: 入った分までを返し、nextSince = 最後に入れたパケットの時刻 (同じ分の続きも取れるよう ≥)。続きを頼むと全部揃う', () => {
    const all = Array.from({ length: 25 }, (_, i) => fakePacket(1000 + i, 998));
    const got: number[] = [];
    let since = 0;
    for (let page = 0; page < 10; page++) {
      const r = buildFetchResponse(all.filter(p => timeOf(p) >= since), timeOf, since, 10_000);
      for (const p of r.packets) got.push(timeOf(p));
      if (r.status === FETCH_STATUS.OK) break;
      expect(r.status).toBe(FETCH_STATUS.MORE);
      expect(r.nextSince).toBe(timeOf(r.packets[r.packets.length - 1]));
      since = r.nextSince;
    }
    expect(Array.from(new Set(got)).sort((a, b) => a - b)).toEqual(all.map(timeOf)); // 全部取れた (境目の 1 件は重複して返る)
  });

  it('★1 分に上限以上の投稿が重なっても進む: nextSince が since 以下なら 1 分進める (同じ所を無限に頼ませない)', () => {
    const ps = Array.from({ length: 20 }, () => fakePacket(500, 998)); // 全部同じ分
    const r = buildFetchResponse(ps, timeOf, 500, 10_000);
    expect(r.status).toBe(FETCH_STATUS.MORE);
    expect(r.nextSince).toBe(501);
  });

  it('既定の上限は 4MiB', () => {
    expect(FETCH_MAX_RESPONSE_BYTES).toBe(4 * 1024 * 1024);
    const ps = Array.from({ length: 2000 }, (_, i) => fakePacket(i, 2198)); // 1 件 2200 → 4.4MB
    const r = buildFetchResponse(ps, timeOf, 0);
    expect(r.status).toBe(FETCH_STATUS.MORE);
    const bytes = encodeFetchResponse(r).length;
    expect(bytes).toBeLessThanOrEqual(FETCH_MAX_RESPONSE_BYTES + 4);
    expect(r.packets.length).toBe(Math.floor(FETCH_MAX_RESPONSE_BYTES / 2200));
  });
});

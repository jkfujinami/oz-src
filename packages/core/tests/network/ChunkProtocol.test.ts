import { describe, it, expect, beforeAll } from 'vitest';
import sodium, { sodiumReady } from '../../src/crypto/sodium';
import { equixReady } from '../../src/crypto/equix/EquiX';
import { CHUNK_SIZE, TAG_BYTES } from '../../src/files/FileFormat';
import {
  CHUNK_MAX_CIPHER_BYTES, CHUNK_STATUS, FRAG_DATA_BYTES, MAX_FRAGMENTS, PUT_HEADER_BYTES,
  decodeGetRequest, decodeGetResponse, decodePutFragment, decodeStatusResponse, encodeGetRequest, encodeGetResponse,
  encodePutFragment, encodeStatusResponse, fragmentCountFor,
} from '../../src/network/storage/ChunkProtocol';
import { CHUNK_EFFORT, solveChunkPow, solveChunkPowSync, verifyChunkPow } from '../../src/network/storage/ChunkPow';
import { MAX_TUNNEL_FRAME_BYTES } from '../../src/network/wire/WireCodec';
import { sealedRequestBytes } from '../../src/network/tunnel/TunnelCrypto';

beforeAll(async () => { await sodiumReady; await equixReady; });

const frag = (over: Partial<Parameters<typeof encodePutFragment>[0]> = {}) => ({
  chunkId: new Uint8Array(16).fill(1), powNonce: 0xdeadbeef, powSolution: new Uint8Array(16).fill(2),
  fragIndex: 0, fragCount: 2, data: new Uint8Array(FRAG_DATA_BYTES).fill(3), ...over,
});

describe('PUT_CHUNK / GET_CHUNK の符号化', () => {
  it('★寸法: 断片は最大 18、1 断片の封印後はトンネルのフレーム (16KiB) に収まる', () => {
    expect(CHUNK_MAX_CIPHER_BYTES).toBe(CHUNK_SIZE + TAG_BYTES);
    expect(MAX_FRAGMENTS).toBe(18);
    expect(fragmentCountFor(CHUNK_MAX_CIPHER_BYTES)).toBe(18);
    expect(fragmentCountFor(1)).toBe(1);
    expect(fragmentCountFor(FRAG_DATA_BYTES)).toBe(1);
    expect(fragmentCountFor(FRAG_DATA_BYTES + 1)).toBe(2);
    expect(PUT_HEADER_BYTES).toBe(16 + 4 + 16 + 1 + 1);
    // TUNNEL_SEND の固定部 (type 1 + reqId 4 + gateway 16 + tunnelId 8 = 29) + 封印後の本体
    expect(29 + sealedRequestBytes(PUT_HEADER_BYTES + FRAG_DATA_BYTES)).toBeLessThanOrEqual(MAX_TUNNEL_FRAME_BYTES);
  });

  it('PUT の断片: 往復', () => {
    const f = frag();
    const b = encodePutFragment(f);
    expect(b.length).toBe(PUT_HEADER_BYTES + FRAG_DATA_BYTES);
    const d = decodePutFragment(b)!;
    expect(d.powNonce).toBe(0xdeadbeef);
    expect(d.fragIndex).toBe(0);
    expect(d.fragCount).toBe(2);
    expect(Array.from(d.chunkId)).toEqual(Array.from(f.chunkId));
    expect(Array.from(d.powSolution)).toEqual(Array.from(f.powSolution));
    expect(Array.from(d.data)).toEqual(Array.from(f.data));
    // 最後の断片は短くてよい
    const last = decodePutFragment(encodePutFragment(frag({ fragIndex: 1, data: new Uint8Array(7) })))!;
    expect(last.data.length).toBe(7);
  });

  it('★不正な断片は復号で弾く: 途中の断片が短い・番号が範囲外・断片数が 0 / 19・空・大きすぎ', () => {
    expect(() => encodePutFragment(frag({ data: new Uint8Array(10) }))).toThrow(); // 途中の断片は満杯
    expect(() => encodePutFragment(frag({ fragIndex: 2 }))).toThrow();
    expect(() => encodePutFragment(frag({ fragCount: 19 }))).toThrow();
    expect(() => encodePutFragment(frag({ data: new Uint8Array(0), fragIndex: 1 }))).toThrow();
    const good = encodePutFragment(frag());
    expect(decodePutFragment(good.slice(0, PUT_HEADER_BYTES))).toBeNull(); // データ無し
    expect(decodePutFragment(new Uint8Array(PUT_HEADER_BYTES + FRAG_DATA_BYTES + 1))).toBeNull();
    const shortMiddle = encodePutFragment(frag({ fragIndex: 1, data: new Uint8Array(5) })).slice();
    shortMiddle[PUT_HEADER_BYTES - 2] = 0; // fragIndex = 0 (最後ではない) なのに 5 バイト
    expect(decodePutFragment(shortMiddle)).toBeNull();
    const badCount = good.slice();
    badCount[PUT_HEADER_BYTES - 1] = 0;
    expect(decodePutFragment(badCount)).toBeNull();
    badCount[PUT_HEADER_BYTES - 1] = 19;
    expect(decodePutFragment(badCount)).toBeNull();
    const badIndex = good.slice();
    badIndex[PUT_HEADER_BYTES - 2] = 2; // index ≥ count
    expect(decodePutFragment(badIndex)).toBeNull();
  });

  it('GET と応答', () => {
    const id = new Uint8Array(16).fill(9);
    expect(Array.from(decodeGetRequest(encodeGetRequest(id))!)).toEqual(Array.from(id));
    expect(decodeGetRequest(new Uint8Array(15))).toBeNull();
    expect(decodeGetRequest(new Uint8Array(17))).toBeNull();
    const data = new Uint8Array(1000).fill(4);
    const r = decodeGetResponse(encodeGetResponse(CHUNK_STATUS.OK, data))!;
    expect(r.status).toBe(CHUNK_STATUS.OK);
    expect(r.data.length).toBe(1000);
    expect(decodeGetResponse(encodeGetResponse(CHUNK_STATUS.NOT_HELD))).toMatchObject({ status: CHUNK_STATUS.NOT_HELD });
    expect(decodeGetResponse(Uint8Array.of(CHUNK_STATUS.NOT_HELD, 1))).toBeNull(); // 余分なバイト
    expect(decodeGetResponse(Uint8Array.of(99))).toBeNull();
    expect(decodeGetResponse(new Uint8Array(0))).toBeNull();
    expect(decodeGetResponse(new Uint8Array(2 + CHUNK_MAX_CIPHER_BYTES))).toBeNull(); // 大きすぎ
    expect(decodeStatusResponse(encodeStatusResponse(CHUNK_STATUS.STORED))).toBe(CHUNK_STATUS.STORED);
    expect(decodeStatusResponse(Uint8Array.of(0, 0))).toBeNull();
    expect(decodeStatusResponse(Uint8Array.of(200))).toBeNull();
  });
});

describe('ChunkPow: 保存の PoW', () => {
  it('★解いた解は検証を通る。別のチャンク ID・別の nonce・別の effort では通らない', () => {
    const id = sodium.randombytes_buf(16);
    const sol = solveChunkPowSync(id, 2)!;
    expect(verifyChunkPow(id, sol, 2)).toBe(true);
    expect(verifyChunkPow(sodium.randombytes_buf(16), sol, 2)).toBe(false);
    expect(verifyChunkPow(id, { nonce: sol.nonce + 1, solution: sol.solution }, 2)).toBe(false);
    expect(verifyChunkPow(id, { nonce: sol.nonce, solution: new Uint8Array(16) }, 2)).toBe(false);
    expect(verifyChunkPow(id, { nonce: -1, solution: sol.solution }, 2)).toBe(false);
    expect(verifyChunkPow(id.slice(0, 15), sol, 2)).toBe(false);
  });

  it('★effort が高い基準では、低い effort で解いた解の多くは通らない (閾値が効く)', () => {
    let fails = 0;
    for (let i = 0; i < 12; i++) {
      const id = sodium.randombytes_buf(16);
      const sol = solveChunkPowSync(id, 1)!;
      if (!verifyChunkPow(id, sol, 64)) fails++;
    }
    expect(fails).toBeGreaterThanOrEqual(8);
  });

  it('非同期版 (イベントループへ戻る) も同じ解を出し、中止できる', async () => {
    const id = sodium.randombytes_buf(16);
    const sol = await solveChunkPow(id, { effort: 1 });
    expect(verifyChunkPow(id, sol!, 1)).toBe(true);
    expect(await solveChunkPow(id, { effort: 1_000_000, shouldStop: () => true })).toBeNull();
  });

  it('本番の effort は 5 (約 0.2 秒/チャンク)', () => {
    expect(CHUNK_EFFORT).toBe(5);
  });
});

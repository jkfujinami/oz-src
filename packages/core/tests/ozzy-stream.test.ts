import { describe, it, expect, beforeAll } from 'vitest';
import sodium, { sodiumReady } from '../src/crypto/sodium';
import {
  CatboxLockerAdapter,
  MemoryOverseasLockerCluster,
  OverseasMultiLockerCoordinator,
  ZeroXZeroLockerAdapter,
  maxStripePlainBytes,
  memoryManifestStore,
  writeStripesInOrder,
  type OzzyByteSink,
} from '../src/ozzy';

/**
 * ファイル全体をメモリに載せない: 上げるときはストライプ単位で読み、取るときはストライプ単位で番号順に書き出す。
 */
beforeAll(async () => { await sodiumReady; });

const CHUNK = 64 * 1024;

function recordingSink() {
  const writes: Uint8Array[] = [];
  const s = { writes, closed: false, aborted: false };
  const sink: OzzyByteSink = {
    write: (c) => { writes.push(c.slice()); },
    close: () => { s.closed = true; },
    abort: () => { s.aborted = true; },
  };
  return { sink, s };
}

describe('Ozzy: ストリームで上げる・取る', () => {
  it('★上げるときは 1 ストライプずつしか読まず、取るときはストライプ単位で番号順に書き出す', async () => {
    const cluster = new MemoryOverseasLockerCluster();
    const t = (r: Request) => cluster.handleFetch(r);
    const coordinator = new OverseasMultiLockerCoordinator({
      manifestStore: memoryManifestStore(),
      adapters: [new CatboxLockerAdapter(t), new ZeroXZeroLockerAdapter(t)],
      chunkBytes: CHUNK,
      targetBatchChunks: 4,
      idleGapMs: 5,
      maxWaitMs: 20,
    });
    const stripe = maxStripePlainBytes(CHUNK);
    const data = sodium.randombytes_buf(stripe * 3 + 12345); // 4 ストライプ
    const reads: Array<[number, number]> = [];
    const source = {
      size: data.length,
      read: async (start: number, end: number) => {
        reads.push([start, end]);
        return data.slice(start, end);
      },
    };
    const up = await coordinator.uploadFile({ source, fileName: 'big.bin', mimeType: 'application/octet-stream', stripeConcurrency: 2 });
    // 先頭から順に、1 ストライプずつ読んだ (全体を一度に読んでいない)
    expect(reads.length).toBe(4);
    for (let i = 0; i < reads.length; i++) {
      expect(reads[i][0]).toBe(i * stripe);
      expect(reads[i][1] - reads[i][0]).toBeLessThanOrEqual(stripe);
    }
    expect(up.manifest.totalFileSize).toBe(data.length);

    const { sink, s } = recordingSink();
    const manifest = await coordinator.downloadToSink(up.linkText, sink);
    expect(manifest?.fileName).toBe('big.bin');
    expect(s.closed).toBe(true);
    expect(s.aborted).toBe(false);
    expect(s.writes.length).toBe(4); // ストライプごとに 1 回
    for (const w of s.writes) expect(w.length).toBeLessThanOrEqual(stripe);
    expect(Buffer.concat(s.writes.map(w => Buffer.from(w))).equals(Buffer.from(data))).toBe(true);

    // Blob (File) からも上げられる
    const blobUp = await coordinator.uploadFile({ source: new Blob([data.slice(0, 300_000)]), fileName: 'b.bin', mimeType: 'application/octet-stream' });
    const back = await coordinator.downloadFile(blobUp.linkText);
    expect(back && Buffer.from(back.data).equals(Buffer.from(data.slice(0, 300_000)))).toBe(true);
  }, 120_000);

  it('先に終わったストライプは前が書けるまで待ち、書き出しは常に番号順', async () => {
    const parts = [new Uint8Array([1, 1]), new Uint8Array([2, 2]), new Uint8Array([3])];
    const delays = [60, 0, 10];
    const { sink, s } = recordingSink();
    const all = new Uint8Array([1, 1, 2, 2, 3]);
    const res = await writeStripesInOrder({
      stripeCount: 3,
      concurrency: 3,
      fetchStripe: async (i) => { await new Promise(r => setTimeout(r, delays[i])); return parts[i]; },
      sink,
      expectedSize: 5,
      expectedHash: sodium.crypto_generichash(32, all, null),
    });
    expect(res).toBe('ok');
    expect(s.writes.map(w => Array.from(w))).toEqual([[1, 1], [2, 2], [3]]);
    expect(s.closed).toBe(true);
  });

  it('★全体のハッシュ・大きさが合わない、または途中のストライプが取れなければ、書き出し先を abort する (close しない)', async () => {
    const parts = [new Uint8Array([1]), new Uint8Array([2])];
    const bad = recordingSink();
    expect(await writeStripesInOrder({
      stripeCount: 2, concurrency: 1, fetchStripe: async (i) => parts[i], sink: bad.sink,
      expectedSize: 2, expectedHash: new Uint8Array(32),
    })).toBe('hash-mismatch');
    expect(bad.s.aborted).toBe(true);
    expect(bad.s.closed).toBe(false);

    const missing = recordingSink();
    expect(await writeStripesInOrder({
      stripeCount: 2, concurrency: 1, fetchStripe: async (i) => (i === 1 ? null : parts[i]), sink: missing.sink,
      expectedSize: 2, expectedHash: new Uint8Array(32),
    })).toBe('failed');
    expect(missing.s.aborted).toBe(true);
    expect(missing.s.closed).toBe(false);
  });
});

import 'fake-indexeddb/auto';
import { describe, it, expect, beforeAll } from 'vitest';
import sodium, { sodiumReady } from '../../src/crypto/sodium';
import { DAY_MS } from '../../src/crypto/PowPolicy';
import { ChunkStore, CHUNK_RETENTION_DAYS } from '../../src/network/storage/ChunkStore';
import { HolderStore } from '../../src/network/storage/HolderStore';
import { StorageService, POST_QUOTA_SHARE } from '../../src/network/storage/StorageService';
import { SLOT_BYTES } from '../../src/network/storage/SlotPow';
import { unlockedStore } from '../helpers/logicHarness';
import { latin1, rawDump } from '../helpers/storageNet';
import { rowCounts } from '../helpers/fileNet';

const T0 = Math.floor(Date.UTC(2026, 9, 15, 12, 0, 0) / DAY_MS) * DAY_MS + 12 * 3600_000;
let seq = 0;

beforeAll(async () => { await sodiumReady; });

const id = (i: number) => {
  const out = new Uint8Array(16);
  new DataView(out.buffer).setUint32(0, i, false);
  out[15] = 0xcc;
  return out;
};
const body = (i: number, n = 1000) => new Uint8Array(n).fill(i & 0xff);
/** 封印で 40 バイト増える */
const SEALED = (n: number) => n + 40;

async function open(quota: number, nowMs = T0) {
  const db = await unlockedStore(`chunks_${Date.now()}_${seq++}`);
  const holderDb = await db.openHolderDb();
  let now = nowMs;
  let q = quota;
  const open = () => ChunkStore.open(holderDb.openChunkDb(), { quotaBytes: () => q, now: () => now });
  return { db, holderDb, store: await open(), reopen: open, setNow: (t: number) => { now = t; }, setQuota: (x: number) => { q = x; } };
}

describe('ChunkStore: 預かる・取り出す', () => {
  it('★預けたチャンクをそのまま取り出せる。同じ ID の再送は exists。再起動しても残る', async () => {
    const o = await open(1 << 30);
    expect(await o.store.put(id(1), body(1))).toBe('stored');
    expect(await o.store.put(id(1), body(1))).toBe('exists');
    expect(o.store.count).toBe(1);
    expect(o.store.totalBytes).toBe(SEALED(1000));
    expect(Array.from((await o.store.get(id(1)))!)).toEqual(Array.from(body(1)));
    expect(await o.store.get(id(2))).toBeNull();
    const again = await o.reopen();
    expect(again.count).toBe(1);
    expect(again.totalBytes).toBe(SEALED(1000));
    expect(Array.from((await again.get(id(1)))!)).toEqual(Array.from(body(1)));
  });

  it('★ディスクにはチャンク ID も中身も現れない (封印・鍵付きハッシュの索引)。ストアは投稿とは別 (hold_chunk / hold_cmeta)', async () => {
    const o = await open(1 << 30);
    const marker = new TextEncoder().encode('SECRET-CHUNK-PLAINTEXT-MARKER-0123456789');
    const data = new Uint8Array(500);
    data.set(marker, 100);
    await o.store.put(id(7), data);
    const dump = await rawDump((o.db as any).dbName);
    expect(dump.includes(latin1(marker))).toBe(false);
    expect(dump.includes(latin1(id(7)))).toBe(false);
    expect(dump.includes(Buffer.from(id(7)).toString('hex'))).toBe(false);
    const counts = await rowCounts((o.db as any).dbName);
    expect(counts.hold_chunk).toBe(1);
    expect(counts.hold_cmeta).toBe(1);
    expect(counts.hold_data).toBe(0); // 投稿のストアには入らない
  });
});

describe('ChunkStore: 追い出し (取られていない順 → 古い順) と保持', () => {
  it('★容量を超えたら、一度も取られていないものから預かった日が古い順に追い出す。取られたものは残る', async () => {
    const o = await open(SEALED(1000) * 3 + 10);
    await o.store.put(id(1), body(1)); // A: 日 0
    await o.store.put(id(2), body(2)); // B: 日 0
    o.setNow(T0 + DAY_MS);
    await o.store.put(id(3), body(3)); // C: 日 1
    expect(await o.store.get(id(2))).not.toBeNull(); // B は日 1 に取られた
    o.setNow(T0 + 2 * DAY_MS);
    await o.store.put(id(4), body(4)); // D: 日 2 → 満杯。取られていないのは A (日 0)・C (日 1) → A から
    expect(o.store.has(id(1))).toBe(false);
    expect(o.store.has(id(2))).toBe(true);
    expect(o.store.has(id(3))).toBe(true);
    await o.store.put(id(5), body(5)); // E → C (取られていない、日 1) が次
    expect(o.store.has(id(3))).toBe(false);
    expect(o.store.has(id(2))).toBe(true);
    await o.store.put(id(6), body(6)); // F → D (日 2、同じ日の中は預かった順)
    expect(o.store.has(id(4))).toBe(false);
    expect([id(2), id(5), id(6)].every(i => o.store.has(i))).toBe(true);
    expect(o.store.totalBytes).toBeLessThanOrEqual(o.store.quota);
  });

  it('★全部が取られたものなら、最後に取られた日が古い順 (同じ日は預かった日が古い順)', async () => {
    const o = await open(SEALED(1000) * 3 + 10);
    await o.store.put(id(1), body(1));
    await o.store.put(id(2), body(2));
    await o.store.put(id(3), body(3));
    o.setNow(T0 + 1 * DAY_MS);
    await o.store.get(id(2)); // 日 1
    await o.store.get(id(1)); // 日 1
    o.setNow(T0 + 2 * DAY_MS);
    await o.store.get(id(3)); // 日 2
    o.setNow(T0 + 3 * DAY_MS);
    await o.store.put(id(4), body(4)); // 追い出す: fetchDay 最小 = 1 (A と B)。同じ日なら預かった日が同じ → 挿入順の A
    expect(o.store.has(id(1))).toBe(false);
    expect(o.store.has(id(2))).toBe(true);
    expect(o.store.has(id(3))).toBe(true);
  });

  it('容量より大きい 1 件は full。容量を下げると enforceQuota が追い出しの順に収める', async () => {
    const o = await open(500);
    expect(await o.store.put(id(1), body(1, 1000))).toBe('full');
    o.setQuota(1 << 30);
    for (let i = 1; i <= 4; i++) await o.store.put(id(i), body(i));
    o.setQuota(SEALED(1000) * 2 + 5);
    expect(await o.store.enforceQuota()).toBe(2);
    expect(o.store.count).toBe(2);
    expect(o.store.has(id(3)) && o.store.has(id(4))).toBe(true);
  });

  it('★時刻は日の単位でしか持たない (預かった日・最後に取られた日)。同じ日に何度取られても控えは同じ', async () => {
    const o = await open(1 << 30);
    await o.store.put(id(1), body(1));
    const stored = Math.floor(T0 / DAY_MS);
    expect(o.store.metaOf(id(1))).toMatchObject({ storedDay: stored, fetchDay: 0 });
    o.setNow(T0 + 3 * DAY_MS + 7 * 3600_000 + 123_456);
    await o.store.get(id(1));
    await o.store.get(id(1));
    const m = o.store.metaOf(id(1))!;
    expect(m.fetchDay).toBe(stored + 3);
    expect(Number.isInteger(m.fetchDay) && Number.isInteger(m.storedDay)).toBe(true);
    const again = await o.reopen();
    expect(again.metaOf(id(1))).toMatchObject({ storedDay: stored, fetchDay: stored + 3 });
  });

  it('★保持 90 日: 預かった日から過ぎたら捨てる。取られるたびに延びる', async () => {
    const o = await open(1 << 30);
    await o.store.put(id(1), body(1)); // 取られない
    await o.store.put(id(2), body(2)); // 80 日目に取られる
    o.setNow(T0 + 80 * DAY_MS);
    await o.store.get(id(2));
    o.setNow(T0 + (CHUNK_RETENTION_DAYS + 1) * DAY_MS);
    expect(await o.store.prune()).toBe(1);
    expect(o.store.has(id(1))).toBe(false);
    expect(o.store.has(id(2))).toBe(true);
    o.setNow(T0 + (80 + CHUNK_RETENTION_DAYS + 1) * DAY_MS);
    expect(await o.store.prune()).toBe(1);
    expect(o.store.count).toBe(0);
    expect(o.store.totalBytes).toBe(0);
  });

  it('書き込み待ちが満杯なら full (メモリを食わせない)', async () => {
    const o = await open(1 << 30);
    const results = await Promise.all(Array.from({ length: 40 }, (_, i) => o.store.put(id(i), body(i, 100))));
    expect(results.filter(r => r === 'stored').length).toBeLessThanOrEqual(32);
    expect(results.filter(r => r === 'full').length).toBeGreaterThanOrEqual(8);
  });
});

describe('容量の分離: 投稿のバケットとチャンクは別枠', () => {
  it('★投稿は枠の 25%、チャンクは残りの 75%。合計は枠 × 256MiB', async () => {
    expect(POST_QUOTA_SHARE).toBe(0.25);
    const db = await unlockedStore(`chunksvc_${Date.now()}_${seq++}`);
    // StorageService を最小の部品で作る (配線は他のテストが見ている)。ここでは容量の分配だけを見る
    const peerManager: any = { on() {}, off() {}, peers: new Map(), sendMessage() {}, myPeerId: 'x'.repeat(32) };
    const dispatcher: any = { register() {} };
    const gossipRouter: any = { onStoredCandidate: () => () => {} };
    const svc = await StorageService.create({
      peerManager, dispatcher, dandelion: { onGuardChange() {}, getPinnedGuardId: () => null } as any, gossipRouter,
      settings: { get: (n) => db.getSetting(n), set: (n, v) => db.setSetting(n, v) },
      holderDb: await db.openHolderDb(), gatewayAllowed: () => true, defaultSlots: 4, slotEffort: 1,
    });
    const total = 4 * SLOT_BYTES;
    expect(svc.holder!.quota).toBe(Math.floor(total * 0.25));
    expect(svc.chunks!.quota).toBe(total - Math.floor(total * 0.25));
    expect(svc.holder!.quota + svc.chunks!.quota).toBe(total);
    await svc.setCapacity(8);
    expect(svc.holder!.quota + svc.chunks!.quota).toBe(8 * SLOT_BYTES);
    expect(svc.chunks!.quota).toBe(6 * SLOT_BYTES);
    await svc.stop();
    db.lock();
    void HolderStore;
  });
});

import 'fake-indexeddb/auto';
import { describe, it, expect, beforeAll } from 'vitest';
import { sodiumReady } from '../../src/crypto/sodium';
import { Encoding } from '../../src/common/Encoding';
import { DAY_MS, msToMinutes } from '../../src/crypto/PowPolicy';
import { encodePacket, decodePacket } from '../../src/crypto/PacketCodec';
import { HolderStore, HOLD_RETENTION_DAYS } from '../../src/network/storage/HolderStore';
import { birthDayOf } from '../../src/network/storage/Duty';
import { VAULT_PARAMS_FAST } from '../../src/storage/SecretVault';
import type { GossipPacket } from '../../src/types';
import { unlockedStore, PASS } from '../helpers/logicHarness';
import { latin1, rawDump } from '../helpers/storageNet';

const T0 = Date.UTC(2026, 9, 15, 12, 0, 0);
let seq = 0;

beforeAll(async () => { await sodiumReady; });

/** PoW は解かない (HolderStore は検証しない。検証は GossipRouter の前段で済んでいる) */
function pkt(i: number, over: Partial<GossipPacket> & { size?: number; fill?: number } = {}): GossipPacket {
  const idBytes = new Uint8Array(16);
  new DataView(idBytes.buffer).setUint32(0, i, false);
  idBytes[15] = 0xee;
  const size = over.size ?? 200;
  const timestamp = Math.floor((over.timestamp ?? T0) / 60_000) * 60_000;
  return {
    packet_id: Encoding.toHex(idBytes),
    timestamp,
    tag: 7,
    age: 0,
    effort_exp: 0,
    pow_nonce: i,
    pow_solution: new Uint8Array(16).fill(1),
    payload: new Uint8Array(size).fill(over.fill ?? (i & 0xff)),
    ...over,
  };
}

async function open(quotaBytes = 1 << 30, nowMs = T0, name = `holder_${Date.now()}_${seq++}`) {
  const db = await unlockedStore(name);
  const holderDb = await db.openHolderDb();
  let now = nowMs;
  const store = await HolderStore.open(holderDb, { quotaBytes: () => quotaBytes, now: () => now });
  return { db, name, store, setNow: (t: number) => { now = t; }, setQuota: (q: number) => { quotaBytes = q; } };
}

describe('HolderStore: 預かる・取り出す', () => {
  it('預けたパケットを (birthDay, tag) で取り出せる。encodePacket のバイト列そのまま', async () => {
    const { store } = await open();
    const p = pkt(1);
    expect(await store.put(p)).toBe(true);
    const bd = birthDayOf(p.timestamp, p.age);
    const got = await store.getBucket(bd, p.tag);
    expect(got).toHaveLength(1);
    expect(Array.from(got[0])).toEqual(Array.from(encodePacket(p)));
    expect(decodePacket(got[0])!.timestamp).toBe(p.timestamp);
    expect(await store.getBucket(bd, p.tag + 1)).toEqual([]);
    expect(await store.getBucket(bd - 1, p.tag)).toEqual([]);
    expect(store.bucketCount).toBe(1);
  });

  it('★同じパケットは 1 件 (live・追いつき・自分の発信のどれで何度来ても)。再起動しても重複しない', async () => {
    const o = await open();
    const p = pkt(1);
    expect(await o.store.put(p)).toBe(true);
    const bytes = o.store.totalBytes;
    expect(await o.store.put(p)).toBe(false);
    expect(await o.store.put({ ...p })).toBe(false);
    expect(o.store.totalBytes).toBe(bytes);
    const bd = birthDayOf(p.timestamp, p.age);
    expect(await o.store.getBucket(bd, p.tag)).toHaveLength(1);

    // 同じ DB を開き直す (再起動)。控えは DB から読み、重複排除も効く
    const holderDb = await o.db.openHolderDb();
    const again = await HolderStore.open(holderDb, { quotaBytes: () => 1 << 30, now: () => T0 });
    expect(again.totalBytes).toBe(bytes);
    expect(again.bucketCount).toBe(1);
    expect(await again.put(p)).toBe(false);
    expect(await again.getBucket(bd, p.tag)).toHaveLength(1);
  });

  it('バケットは (birthDay, tag) の組で分かれる: age が違えば同じ日の投稿でも別バケット', async () => {
    const { store } = await open();
    const a = pkt(1, { tag: 5, age: 0 });
    const b = pkt(2, { tag: 5, age: 3 }); // スレ立ては 3 日前 → birthDay が 3 小さい
    const c = pkt(3, { tag: 6, age: 0 });
    for (const p of [a, b, c]) await store.put(p);
    expect(store.bucketCount).toBe(3);
    expect(await store.getBucket(birthDayOf(a.timestamp, 0), 5)).toHaveLength(1);
    expect(await store.getBucket(birthDayOf(b.timestamp, 3), 5)).toHaveLength(1);
    expect(birthDayOf(b.timestamp, 3)).toBe(birthDayOf(a.timestamp, 0) - 3);
    // 同じバケット = 同じスレの別レス
    const d = pkt(4, { tag: 5, age: 0, timestamp: T0 + 3 * 60_000 });
    await store.put(d);
    expect(await store.getBucket(birthDayOf(a.timestamp, 0), 5)).toHaveLength(2);
  });

  it('getBucket は time ≥ since のものを古い順に返す', async () => {
    const { store } = await open();
    const times = [T0, T0 + 5 * 60_000, T0 + 10 * 60_000, T0 + 15 * 60_000];
    // 到着順をばらす
    for (const [i, k] of [2, 0, 3, 1].entries()) await store.put(pkt(i, { timestamp: times[k] }));
    const bd = birthDayOf(T0, 0);
    const all = await store.getBucket(bd, 7);
    expect(all.map(b => decodePacket(b)!.timestamp)).toEqual(times);
    const since = msToMinutes(times[2]);
    expect((await store.getBucket(bd, 7, since)).map(b => decodePacket(b)!.timestamp)).toEqual([times[2], times[3]]);
    expect(await store.getBucket(bd, 7, msToMinutes(times[3]) + 1)).toEqual([]);
  });
});

describe('HolderStore: 保持 (90 日)', () => {
  it('★birthDay + 90 日を過ぎたバケットは prune で丸ごと消え、期間内のものは残る', async () => {
    const o = await open();
    const old = pkt(1, { tag: 1 });
    const fresh = pkt(2, { tag: 2 });
    await o.store.put(old);
    await o.store.put(fresh);
    const oldDay = birthDayOf(old.timestamp, 0);
    // 90 日後の同時刻: まだ期限内 (now > (birthDay + 90) 日 でない)。翌日になると切れる
    o.setNow((oldDay + HOLD_RETENTION_DAYS) * DAY_MS);
    expect(await o.store.prune()).toBe(0);
    o.setNow((oldDay + HOLD_RETENTION_DAYS) * DAY_MS + 1);
    expect(await o.store.prune()).toBe(2); // 同じ日に作った 2 つとも
    expect(o.store.bucketCount).toBe(0);
    expect(o.store.totalBytes).toBe(0);
    expect(await o.store.getBucket(oldDay, 1)).toEqual([]);
  });

  it('スレ立てが古い (age が大きい) バケットは、投稿が新しくても早く切れる。期限はバケットの birthDay で決まる', async () => {
    const o = await open();
    const p = pkt(1, { age: 80, tag: 9 }); // 80 日前に立ったスレへの今日のレス
    await o.store.put(p);
    const bd = birthDayOf(p.timestamp, 80);
    o.setNow((bd + 90) * DAY_MS + 1); // あと 10 日
    expect(await o.store.prune()).toBe(1);
  });

  it('期限切れの投稿は預からない (追いつき・古いパケットの再配布で期限切れを溜めない)', async () => {
    const o = await open();
    const p = pkt(1, { age: 0, timestamp: T0 - 100 * DAY_MS });
    expect(await o.store.put(p)).toBe(false);
    expect(o.store.bucketCount).toBe(0);
  });

  it('prune は再起動をまたいで効く (DB から読んだ控えで判定する)', async () => {
    const o = await open();
    const p = pkt(1);
    await o.store.put(p);
    const holderDb = await o.db.openHolderDb();
    const later = (birthDayOf(p.timestamp, 0) + 91) * DAY_MS;
    const again = await HolderStore.open(holderDb, { quotaBytes: () => 1 << 30, now: () => later });
    expect(await again.prune()).toBe(1);
    const third = await HolderStore.open(await o.db.openHolderDb(), { quotaBytes: () => 1 << 30, now: () => later });
    expect(third.bucketCount).toBe(0);
  });
});

describe('HolderStore: 容量', () => {
  it('★容量を超えたら birthDay が古いバケットから丸ごと捨てる。新しいものは残る', async () => {
    const o = await open();
    // 1 バケット = 約 3 件 × (200 + 28 + 40) バイト ≒ 800 バイト
    const perBucket = async (day: number) => {
      for (let i = 0; i < 3; i++) await o.store.put(pkt(day * 10 + i, { tag: 50, timestamp: T0 - (10 - day) * DAY_MS, size: 200 }));
    };
    await perBucket(1);
    const oneBucket = o.store.totalBytes;
    expect(oneBucket).toBeGreaterThan(600);
    o.setQuota(Math.floor(oneBucket * 3.5)); // 3 バケットまで
    for (const day of [5, 3, 9, 2, 7]) await perBucket(day); // 到着順は不揃い
    expect(o.store.totalBytes).toBeLessThanOrEqual(Math.floor(oneBucket * 3.5));
    expect(o.store.bucketCount).toBe(3);
    // 残っているのは birthDay が新しい 3 つ (day 9, 7, 5)
    const kept: number[] = [];
    for (const day of [1, 2, 3, 5, 7, 9]) {
      const bd = birthDayOf(T0 - (10 - day) * DAY_MS, 0);
      if ((await o.store.getBucket(bd, 50)).length > 0) kept.push(day);
    }
    expect(kept).toEqual([5, 7, 9]);
    // 残ったバケットは欠けていない (歯抜けにしない)
    for (const day of kept) expect(await o.store.getBucket(birthDayOf(T0 - (10 - day) * DAY_MS, 0), 50)).toHaveLength(3);
  });

  it('容量を下げて enforceQuota を呼ぶと、その場で収まる', async () => {
    const o = await open();
    for (let d = 0; d < 6; d++) await o.store.put(pkt(d, { tag: 3, timestamp: T0 - d * DAY_MS }));
    expect(o.store.bucketCount).toBe(6);
    o.setQuota(Math.floor(o.store.totalBytes / 2));
    const dropped = await o.store.enforceQuota();
    expect(dropped).toBe(3);
    expect(o.store.totalBytes).toBeLessThanOrEqual(Math.floor(o.store.totalBytes + 1));
    expect(o.store.bucketCount).toBe(3);
    // 残るのは新しい 3 日分
    for (let d = 0; d < 6; d++) {
      const got = await o.store.getBucket(birthDayOf(T0 - d * DAY_MS, 0), 3);
      expect(got.length, `day -${d}`).toBe(d < 3 ? 1 : 0);
    }
  });

  it('総量は削除で正しく減り、再起動後の合計と一致する', async () => {
    const o = await open();
    for (let d = 0; d < 4; d++) await o.store.put(pkt(d, { tag: 3, timestamp: T0 - d * DAY_MS }));
    o.setNow((birthDayOf(T0 - 3 * DAY_MS, 0) + 91) * DAY_MS);
    await o.store.prune();
    const total = o.store.totalBytes;
    const again = await HolderStore.open(await o.db.openHolderDb(), { quotaBytes: () => 1 << 30, now: () => T0 });
    expect(again.totalBytes).toBe(total);
    expect(again.bucketCount).toBe(o.store.bucketCount);
  });
});

describe('HolderStore: 保存時の暗号化', () => {
  it('★生の IndexedDB を全部読んでも、パケットの中身・ID・birthDay・tag は平文で出てこない', async () => {
    const o = await open();
    const marker = new TextEncoder().encode('SECRET-PAYLOAD-MARKER-0123456789-abcdefghij');
    const payload = new Uint8Array(300);
    payload.set(marker, 100);
    const p = pkt(77, { payload, tag: 0x5a5, age: 2 });
    await o.store.put(p);
    await o.store.put(pkt(78, { payload: new Uint8Array(300).fill(0x42), tag: 0x5a5, age: 2 }));
    await o.store.flush();
    const bytes = encodePacket(p);
    const dump = await rawDump(o.name);
    // 暗号文が実際に書かれていること (空の dump で通らないように)
    expect(dump.length).toBeGreaterThan(1000);
    expect(dump).not.toContain(latin1(marker));
    expect(dump).not.toContain(latin1(bytes.subarray(12, 12 + 24))); // 解 + ペイロード先頭
    expect(dump).not.toContain(latin1(bytes.subarray(28, 28 + 20)));
    expect(dump).not.toContain(p.packet_id);
    expect(dump).not.toContain(latin1(Encoding.fromHex(p.packet_id)));
    expect(dump).not.toContain('SECRET');
    // 行は hold_meta / hold_data にあるが、キーは鍵付きハッシュ (birthDay / tag の文字列を含まない)
    expect(dump).not.toContain(String(birthDayOf(p.timestamp, 2)));
    expect(dump).not.toContain(`${birthDayOf(p.timestamp, 2)}:${0x5a5}`);
  });

  it('★パスワードを変えても預かったものは読める (専用の鍵は kv の再暗号化に乗る)', async () => {
    const o = await open();
    const p = pkt(5);
    await o.store.put(p);
    await o.db.changePassphrase(PASS, 'a-new-passphrase', VAULT_PARAMS_FAST);
    const store2 = await HolderStore.open(await o.db.openHolderDb(), { quotaBytes: () => 1 << 30, now: () => T0 });
    expect(store2.bucketCount).toBe(1);
    const got = await store2.getBucket(birthDayOf(p.timestamp, 0), p.tag);
    expect(Array.from(got[0])).toEqual(Array.from(encodePacket(p)));
  });

  it('close 後は預からず、鍵が消えている (ロックされたら読めない)', async () => {
    const o = await open();
    await o.store.put(pkt(1));
    await o.store.close();
    expect(await o.store.put(pkt(2))).toBe(false);
    expect(await o.store.getBucket(birthDayOf(T0, 0), 7)).toEqual([]);
    expect(o.store.hasBucket(birthDayOf(T0, 0), 7)).toBe(false);
  });

  it('HolderDB は lock 後に鍵を使おうとすると例外 (ゼロ化した鍵で別の索引を作らない)', async () => {
    const db = await unlockedStore();
    const holderDb = await db.openHolderDb();
    expect(() => holderDb.bucketKey(1, 2)).not.toThrow();
    holderDb.lock();
    expect(() => holderDb.bucketKey(1, 2)).toThrow(/locked/);
  });

  it('IndexedDB のロックを外していない間は holder を開けない', async () => {
    const o = await open();
    o.db.lock();
    await expect(o.db.openHolderDb()).rejects.toThrow(/locked/);
  });
});

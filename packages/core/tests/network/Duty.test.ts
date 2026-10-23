import { describe, it, expect, beforeAll } from 'vitest';
import { sodiumReady } from '../../src/crypto/sodium';
import { Encoding } from '../../src/common/Encoding';
import { closest, ringDistance, RING_SIZE } from '../../src/common/Ring';
import { DAY_MS, msToMinutes, minutesToMs } from '../../src/crypto/PowPolicy';
import {
  Duty, R_QUERY, R_STORE, SlotIndex, birthDayOf, bucketPosition,
} from '../../src/network/storage/Duty';
import { LEASESET_MIN_REPLACE_MS } from '../../src/network/storage/LeaseSet';
import { LEASESET_STORE_MAX, LeaseSetStore, type SlotEntry } from '../../src/network/storage/LeaseSetStore';
import { fakeLeaseSet } from '../helpers/storageNet';

/** 決定的な乱数 (mulberry32) */
function rng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rand64 = (r: () => number): bigint => (BigInt(Math.floor(r() * 0x100000000)) << 32n) | BigInt(Math.floor(r() * 0x100000000));

function entry(sidNum: number, index: number, position: bigint): SlotEntry {
  const id = new Uint8Array(33);
  id[0] = sidNum >>> 8; id[1] = sidNum & 0xff; id[32] = index;
  return { key: Encoding.toHex(id), id, position, sid: Encoding.toHex(id.subarray(0, 32)), index };
}

beforeAll(async () => { await sodiumReady; });

describe('バケットの位置', () => {
  it('birthDay = floor(time / 日) − age (UTC の日番号)', () => {
    const t = Date.UTC(2026, 9, 15, 23, 59, 59);
    expect(birthDayOf(t, 0)).toBe(Math.floor(t / DAY_MS));
    expect(birthDayOf(t, 5)).toBe(Math.floor(t / DAY_MS) - 5);
    expect(birthDayOf(t + 1000, 0)).toBe(Math.floor(t / DAY_MS) + 1); // 日付をまたぐ
  });

  it('位置は (birthDay, tag) で決まる。決定的で、どちらが違っても別の位置', () => {
    const p = bucketPosition(20000, 0x123);
    expect(bucketPosition(20000, 0x123)).toBe(p);
    expect(bucketPosition(20001, 0x123)).not.toBe(p);
    expect(bucketPosition(20000, 0x124)).not.toBe(p);
    expect(p).toBeLessThan(RING_SIZE);
  });
});

describe('SlotIndex: Ring.closest と同じ結果を速く返す', () => {
  it('★乱数で突き合わせ: 枠の数・target・k を振って、順序まで Ring.closest と一致する', () => {
    const r = rng(1);
    for (const n of [1, 2, 3, 5, 10, 63, 64, 65, 200, 1000]) {
      const entries = Array.from({ length: n }, (_, i) => entry(i, 0, rand64(r)));
      const idx = new SlotIndex(entries);
      const targets = [0n, RING_SIZE - 1n, 1n << 63n, ...entries.slice(0, 3).map(e => e.position), ...Array.from({ length: 20 }, () => rand64(r))];
      for (const target of targets) {
        for (const k of [1, 5, R_QUERY, R_STORE, n, n + 3]) {
          const expected = closest(target, entries, k).map(e => e.key);
          expect(idx.nearest(target, k).map(e => e.key), `n=${n} k=${k}`).toEqual(expected);
        }
      }
    }
  });

  it('偏った分布 (リストの片側に固まる・同じ位置が複数) でも一致する', () => {
    const r = rng(2);
    const clustered = Array.from({ length: 120 }, (_, i) => entry(i, 0, (1n << 63n) + BigInt(Math.floor(r() * 1000))));
    const dup = Array.from({ length: 30 }, (_, i) => entry(1000 + i, 0, 12345n)); // 同じ位置
    const wrap = [entry(2000, 0, 3n), entry(2001, 0, RING_SIZE - 3n), entry(2002, 0, 0n)];
    for (const entries of [clustered, [...clustered, ...dup, ...wrap]]) {
      const idx = new SlotIndex(entries);
      for (const target of [0n, 12345n, (1n << 63n) + 500n, RING_SIZE - 1n, 1n << 62n]) {
        for (const k of [1, 40, 72]) {
          expect(idx.nearest(target, k).map(e => e.key)).toEqual(closest(target, entries, k).map(e => e.key));
        }
      }
    }
  });

  it('空・k=0 は空', () => {
    expect(new SlotIndex([]).nearest(5n, 3)).toEqual([]);
    expect(new SlotIndex([entry(1, 0, 1n)]).nearest(5n, 0)).toEqual([]);
  });

  it('大きな枠の集合 (10 万枠) でも 1 回の問い合わせは 1ms 未満の桁', () => {
    const r = rng(3);
    const entries = Array.from({ length: 100_000 }, (_, i) => entry(i & 0xffff, i >> 16, rand64(r)));
    const idx = new SlotIndex(entries);
    const t = performance.now();
    for (let i = 0; i < 1000; i++) idx.nearest(rand64(r), R_STORE);
    const per = (performance.now() - t) / 1000;
    console.log(`[duty] nearest(72) over 100k slots: ${per.toFixed(3)} ms/query`);
    expect(per).toBeLessThan(2);
  });
});

/** 合成した N ノード (各 slotsPer 枠) の世界。署名・PoW は見ない (store.add に直接入れる) */
function world(nodes: number, slotsPer: number) {
  return Array.from({ length: nodes }, (_, n) => fakeLeaseSet(n + 1, slotsPer));
}
function viewOf(all: ReturnType<typeof world>, me: number, missing: () => boolean): { duty: Duty; own: SlotEntry[] } {
  const store = new LeaseSetStore();
  for (let i = 0; i < all.length; i++) if (i !== me && !missing()) store.add(all[i]);
  const mine = new LeaseSetStore();
  mine.add(all[me]);
  const own = mine.allSlots();
  const sid = own[0].sid;
  return { duty: new Duty(store, () => ({ sid, slots: own }), { minRebuildMs: 0 }), own };
}

describe('Duty: 小さな網は全員が全部、大きな網は近い 72 枠', () => {
  it('★既知の枠が 64 未満なら、どのバケットも保存する (自分の枠が 1 つでもあれば)', () => {
    const all = world(10, 4); // 40 枠
    const { duty } = viewOf(all, 0, () => false);
    expect(duty.knownSlots).toBe(40);
    const r = rng(4);
    for (let i = 0; i < 300; i++) expect(duty.shouldStore(19000 + Math.floor(r() * 500), Math.floor(r() * 4096))).toBe(true);
  });

  it('枠が 64 枠ちょうど・72 枠以下でも全部保存 (近い 72 枠が全員を含む)', () => {
    for (const nodes of [16, 17, 18]) { // 64, 68, 72 枠
      const all = world(nodes, 4);
      const { duty } = viewOf(all, 3, () => false);
      expect(duty.knownSlots).toBe(nodes * 4);
      for (let i = 0; i < 100; i++) expect(duty.shouldStore(19000 + i, i * 7)).toBe(true);
    }
  });

  it('自分の枠がまだ無い (解いている途中) なら保存しない', () => {
    const store = new LeaseSetStore();
    for (const ls of world(5, 1)) store.add(ls);
    const duty = new Duty(store, () => null, { minRebuildMs: 0 });
    expect(duty.shouldStore(19000, 1)).toBe(false);
  });

  it('不正な birthDay / tag は保存しない', () => {
    const { duty } = viewOf(world(3, 1), 0, () => false);
    expect(duty.shouldStore(-1, 0)).toBe(false);
    expect(duty.shouldStore(19000, -1)).toBe(false);
    expect(duty.shouldStore(19000, 0x10000)).toBe(false);
    expect(duty.shouldStore(1.5, 0)).toBe(false);
  });

  it('自分の枠は、store に自分の leaseSet が入っていても二重に数えない', () => {
    const all = world(5, 2);
    const store = new LeaseSetStore();
    for (const ls of all) store.add(ls);
    const mine = new LeaseSetStore();
    mine.add(all[0]);
    const own = mine.allSlots();
    const duty = new Duty(store, () => ({ sid: own[0].sid, slots: own }), { minRebuildMs: 0 });
    expect(duty.knownSlots).toBe(10);
  });

  it('★同じ見え方なら、バケットごとにちょうど 72 枠が担当で、その枠を持つノードが保存する', () => {
    const nodes = 300;
    const all = world(nodes, 4);
    const views = Array.from({ length: nodes }, (_, me) => viewOf(all, me, () => false));
    expect(views[0].duty.knownSlots).toBe(1200);
    const r = rng(5);
    for (let b = 0; b < 200; b++) {
      const birthDay = 19000 + Math.floor(r() * 90);
      const tag = Math.floor(r() * 4096);
      let slotsOnDuty = 0;
      let holders = 0;
      for (const { duty, own } of views) {
        const near = new Set(duty.closestSlots(birthDay, tag, R_STORE).map(s => s.key));
        const mineOnDuty = own.filter(s => near.has(s.key)).length;
        slotsOnDuty += mineOnDuty;
        const stores = duty.shouldStore(birthDay, tag);
        expect(stores).toBe(mineOnDuty > 0);
        if (stores) holders++;
      }
      expect(slotsOnDuty).toBe(R_STORE); // 全員で数えると、担当の枠はちょうど 72
      expect(holders).toBeLessThanOrEqual(R_STORE);
      expect(holders).toBeGreaterThan(R_STORE / 4); // 4 枠ずつなので、72 枠は少なくとも 18 ノードに散る
    }
  }, 60_000);

  it('索引は leaseSet の変化に追随する (minRebuildMs を過ぎたら作り直す)', () => {
    let t = 1_000_000;
    const store = new LeaseSetStore();
    const all = world(40, 2);
    const mine = new LeaseSetStore();
    mine.add(all[0]);
    const own = mine.allSlots();
    const duty = new Duty(store, () => ({ sid: own[0].sid, slots: own }), { minRebuildMs: 5000, now: () => t });
    expect(duty.knownSlots).toBe(2);
    store.add(all[1]);
    expect(duty.knownSlots).toBe(2); // 5 秒以内は作り直さない
    t += 5000;
    expect(duty.knownSlots).toBe(4);
  });
});

describe('Duty: 見え方のずれ (leaseSet の取りこぼし) の許容', () => {
  /**
   * N ノード × 4 枠。各ノードは他人の leaseSet を確率 missing で取りこぼす。
   * 読み手 R は自分の見え方で近い 64 枠を選ぶ。その 64 枠の持ち主 (各自の見え方で判定) が実際に保存していれば成功。
   * 失敗 = 読み手が選んだ枠のうち、持ち主が保存していない枠が 1 つでもあった。
   */
  function measure(missing: number, seed: number) {
    const nodes = 300;
    const all = world(nodes, 4);
    const r = rng(seed);
    const views = Array.from({ length: nodes }, (_, me) => viewOf(all, me, () => r() < missing));
    const ownerOf = new Map<string, number>();
    views.forEach((v, i) => v.own.forEach(s => ownerOf.set(s.key, i)));
    let pairs = 0;
    let pairFail = 0;
    let slotChecks = 0;
    let slotFail = 0;
    const buckets = 150;
    const readers = 12;
    for (let b = 0; b < buckets; b++) {
      const birthDay = 19000 + Math.floor(r() * 90);
      const tag = Math.floor(r() * 4096);
      const stores = views.map(v => v.duty.shouldStore(birthDay, tag));
      for (let k = 0; k < readers; k++) {
        const reader = Math.floor(r() * nodes);
        const chosen = views[reader].duty.closestSlots(birthDay, tag, R_QUERY);
        let failed = false;
        for (const s of chosen) {
          slotChecks++;
          if (!stores[ownerOf.get(s.key)!]) { slotFail++; failed = true; }
        }
        pairs++;
        if (failed) pairFail++;
      }
    }
    return { missing, pairs, pairFail, slotChecks, slotFail };
  }

  it('★取りこぼし 0% なら失敗は 0。1% では 読み手が選んだ 64 枠のうち保存していない枠が出る頻度を実測する', () => {
    const exact = measure(0, 11);
    expect(exact.pairFail).toBe(0);
    expect(exact.slotFail).toBe(0);

    const one = measure(0.01, 12);
    const five = measure(0.05, 13);
    const ten = measure(0.10, 14);
    for (const m of [one, five, ten]) {
      console.log(
        `[duty] missing=${(m.missing * 100).toFixed(0)}%: 読み手×バケット ${m.pairs} 組中 失敗 ${m.pairFail} ` +
        `(${((m.pairFail / m.pairs) * 100).toFixed(3)}%)、枠 ${m.slotChecks} 件中 保存していない枠 ${m.slotFail} (${((m.slotFail / m.slotChecks) * 100).toFixed(4)}%)`,
      );
    }
    // 1% の取りこぼしでは、読み手の選ぶ 64 枠は 72 枠の余裕の中に収まる
    expect(one.pairFail).toBe(0);
  }, 120_000);
});

describe('LeaseSetStore', () => {
  it('SID ごとに最新 (期限が遅い方) 1 件だけ持つ。同じ・古い期限は stale', () => {
    let now = minutesToMs(1_000_000);
    const store = new LeaseSetStore(() => now);
    const nowMin = msToMinutes(now);
    const a1 = fakeLeaseSet(1, 2, { expiresMin: nowMin + 100 });
    const a2 = fakeLeaseSet(1, 2, { expiresMin: nowMin + 200 });
    expect(store.add(a1)).toBe('added');
    expect(store.add(a1)).toBe('stale');
    now += LEASESET_MIN_REPLACE_MS; // 置き換えの間隔 (10 分) を空ける
    expect(store.add(a2)).toBe('updated');
    expect(store.add(a1)).toBe('stale');
    expect(store.size).toBe(1);
    expect(store.allSlots()).toHaveLength(2);
    expect(Array.from(store.allBytes()[0])).toEqual(Array.from(a2.bytes));
  });

  it('★置き換えは前に受け付けてから 10 分以上経ってから: 期限が新しくても too-soon (入れない)。最初の 1 件は常に受け付ける', () => {
    let now = minutesToMs(1_000_000);
    const store = new LeaseSetStore(() => now);
    const nowMin = msToMinutes(now);
    const lease = (extra: number) => fakeLeaseSet(7, 1, { expiresMin: nowMin + 100 + extra });
    expect(store.add(lease(0))).toBe('added'); // 最初の 1 件
    const v = store.version;
    // 1 分ごとに署名し直して期限を延ばしても、入らない
    for (let i = 1; i <= 9; i++) {
      now += 60_000;
      expect(store.add(lease(i))).toBe('too-soon');
    }
    expect(store.version).toBe(v);
    expect(store.get(Buffer.from(lease(0).sid).toString('hex'))!.expiresMin).toBe(nowMin + 100);
    // 10 分経てば置き換わる。起点は受け付けた時刻なので、その次はまた 10 分待つ
    now += 60_000;
    expect(store.add(lease(10))).toBe('updated');
    now += 5 * 60_000;
    expect(store.add(lease(11))).toBe('too-soon');
    now += 5 * 60_000;
    expect(store.add(lease(12))).toBe('updated');
    // 別の SID は影響しない
    expect(store.add(fakeLeaseSet(8, 1, { expiresMin: nowMin + 150 }))).toBe('added');
    // 古い (期限が遅くない) ものは、間隔が空いていても stale
    now += 20 * 60_000;
    expect(store.add(lease(3))).toBe('stale');
  });

  it('期限切れは入らない・prune で消える。version は変化のたびに増える', () => {
    let now = minutesToMs(1_000_000);
    const store = new LeaseSetStore(() => now);
    const nowMin = msToMinutes(now);
    expect(store.add(fakeLeaseSet(1, 1, { expiresMin: nowMin }))).toBe('stale'); // すでに切れている
    const v0 = store.version;
    store.add(fakeLeaseSet(2, 1, { expiresMin: nowMin + 10 }));
    store.add(fakeLeaseSet(3, 1, { expiresMin: nowMin + 100 }));
    expect(store.version).toBeGreaterThan(v0);
    expect(store.allSlots()).toHaveLength(2);
    now += 20 * 60_000;
    expect(store.allSlots()).toHaveLength(1); // 読み出しでも期限切れは除く
    expect(store.allBytes()).toHaveLength(1);
    expect(store.prune()).toBe(1);
    expect(store.size).toBe(1);
  });

  it('★上限 50,000 件: 超えたら期限が最も近いものから捨てる', () => {
    expect(LEASESET_STORE_MAX).toBe(50_000);
    const now = minutesToMs(1_000_000);
    const nowMin = msToMinutes(now);
    const store = new LeaseSetStore(() => now, 100);
    for (let i = 0; i < 100; i++) store.add(fakeLeaseSet(i + 1, 1, { expiresMin: nowMin + 100 + i }));
    expect(store.size).toBe(100);
    store.add(fakeLeaseSet(1000, 1, { expiresMin: nowMin + 1000 })); // 101 件目
    expect(store.size).toBeLessThanOrEqual(100);
    expect(store.size).toBeGreaterThanOrEqual(95); // 5% の余裕まで捨てる
    // 期限が最も近い (seed 1) は消え、最も遠い (新しく入れた seed 1000) は残る
    expect(store.get(Encoding.toHex(fakeLeaseSet(1, 1).sid))).toBeUndefined();
    expect(store.get(Encoding.toHex(fakeLeaseSet(1000, 1).sid))).toBeDefined();
    expect(store.get(Encoding.toHex(fakeLeaseSet(100, 1).sid))).toBeDefined();
  });

  it('枠の位置は ringDistance で扱える (SlotEntry の形)', () => {
    const store = new LeaseSetStore();
    store.add(fakeLeaseSet(7, 3));
    const slots = store.allSlots();
    expect(slots).toHaveLength(3);
    expect(new Set(slots.map(s => s.key)).size).toBe(3);
    for (const s of slots) expect(ringDistance(0n, s.position)).toBeLessThanOrEqual(RING_SIZE / 2n);
  });
});

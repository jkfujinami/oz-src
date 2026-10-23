import 'fake-indexeddb/auto';
import { describe, it, expect, beforeAll } from 'vitest';
import sodium, { sodiumReady } from '../../src/crypto/sodium';
import { Encoding } from '../../src/common/Encoding';
import { OZ_EPOCH_MS, MINUTE_MS, minutesToMs, msToMinutes } from '../../src/crypto/PowPolicy';
import {
  LEASESET_MAX_BYTES, LEASESET_MIN_BYTES, decodeLeaseSet, leaseSetId, signLeaseSet, verifyLeaseSet,
  type LeaseSetFields,
} from '../../src/network/storage/LeaseSet';
import {
  MAX_SLOTS, SLOT_EFFORT, slotPosition, solveSlot, verifySlotSolution, type SlotSolution,
} from '../../src/network/storage/SlotPow';
import { STORAGE_IDENTITY_KEY, StorageIdentity } from '../../src/network/storage/StorageIdentity';
import { IndexedDBStore } from '../../src/storage/IndexedDBStore';
import { VAULT_PARAMS_FAST } from '../../src/storage/SecretVault';
import { latin1, rawDump } from '../helpers/storageNet';

/**
 * LeaseSet (署名つきの保管担当の宣言) と SlotPow (枠の PoW・位置) と StorageIdentity (SID)。
 * 枠の PoW は effort 1 で解く (検証の経路は本番と同じ。SLOT_EFFORT の実物は専用のテストで 1 回だけ解く)。
 */
const EFFORT = 1;
const GATEWAY = 'ab'.repeat(16);
const T0 = Date.UTC(2026, 9, 15, 12, 0, 0);
const H = 60 * MINUTE_MS;

let kp: { publicKey: Uint8Array; privateKey: Uint8Array };
let slots: SlotSolution[];

beforeAll(async () => {
  await sodiumReady;
  kp = sodium.crypto_sign_keypair();
  slots = [];
  for (let i = 0; i < 3; i++) slots.push((await solveSlot(kp.publicKey, i, { effort: EFFORT }))!);
}, 30_000);

const fields = (over: Partial<LeaseSetFields> = {}): LeaseSetFields => ({
  sid: kp.publicKey,
  slots: slots.slice(0, 2),
  gateway: GATEWAY,
  tunnelId: Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]),
  expiresMin: msToMinutes(T0) + 360,
  ...over,
});
const sign = (f: LeaseSetFields) => signLeaseSet(f, (m) => sodium.crypto_sign_detached(m, kp.privateKey));
const ctx = (over: object = {}) => ({ nowMs: T0, gatewayAllowed: () => true, slotEffort: EFFORT, ...over });
const verify = (bytes: Uint8Array, c = ctx()) => verifyLeaseSet(decodeLeaseSet(bytes)!, c);

describe('LeaseSet: ワイヤの形', () => {
  it('1 枠で 145 バイト、1 枠増えるごとに +20、16 枠で 445。レイアウトは固定', () => {
    expect(LEASESET_MIN_BYTES).toBe(145);
    expect(LEASESET_MAX_BYTES).toBe(445);
    const one = sign(fields({ slots: slots.slice(0, 1) }));
    expect(one.length).toBe(145);
    expect(sign(fields({ slots: slots.slice(0, 3) })).length).toBe(185);

    const b = sign(fields());
    expect(b.length).toBe(165);
    expect(b[0]).toBe(1); // version
    expect(Array.from(b.subarray(1, 33))).toEqual(Array.from(kp.publicKey)); // SID
    expect(b[33]).toBe(2); // slotCount
    expect(new DataView(b.buffer, b.byteOffset).getUint32(34, false)).toBe(slots[0].nonce); // 枠 0 の nonce (BE)
    expect(Array.from(b.subarray(38, 54))).toEqual(Array.from(slots[0].solution));
    expect(Array.from(b.subarray(74, 90))).toEqual(Array.from(Encoding.fromHex(GATEWAY))); // gateway は生の 16 バイト
    expect(Array.from(b.subarray(90, 98))).toEqual([1, 2, 3, 4, 5, 6, 7, 8]); // tunnelId
    const exp = msToMinutes(T0) + 360;
    expect(Array.from(b.subarray(98, 101))).toEqual([(exp >>> 16) & 0xff, (exp >>> 8) & 0xff, exp & 0xff]); // u24
    expect(sodium.crypto_sign_verify_detached(b.subarray(101), b.subarray(0, 101), kp.publicKey)).toBe(true); // 署名は手前の全部
  });

  it('IP や peerId に当たる欄は無い: gateway (Guard の peerId) 以外に ID は載らない', () => {
    const b = sign(fields());
    // SID と gateway 以外の領域に、ノードの peerId を載せる欄は無い (長さが固定なので欄の増減で検出できる)
    expect(b.length).toBe(1 + 32 + 1 + 2 * 20 + 16 + 8 + 3 + 64);
  });

  it('decode: 往復する。切り詰め・余り・版違い・枠の数と長さの不一致は null', () => {
    const b = sign(fields());
    const ls = decodeLeaseSet(b)!;
    expect(ls.gateway).toBe(GATEWAY);
    expect(ls.slots).toHaveLength(2);
    expect(Array.from(ls.tunnelId)).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(ls.expiresMin).toBe(msToMinutes(T0) + 360);
    expect(Array.from(ls.bytes)).toEqual(Array.from(b));

    expect(decodeLeaseSet(b.subarray(0, b.length - 1))).toBeNull();
    expect(decodeLeaseSet(new Uint8Array([...b, 0]))).toBeNull();
    expect(decodeLeaseSet(Uint8Array.from(b, (v, i) => (i === 0 ? 2 : v)))).toBeNull();
    expect(decodeLeaseSet(Uint8Array.from(b, (v, i) => (i === 33 ? 3 : v)))).toBeNull(); // 枠 3 と言いつつ 2 枠分しか無い
    expect(decodeLeaseSet(Uint8Array.from(b, (v, i) => (i === 33 ? 0 : v)))).toBeNull();
    expect(decodeLeaseSet(new Uint8Array(0))).toBeNull();
  });

  it('encode: 枠 0 / 17 以上・不正な gateway / tunnelId は RangeError', () => {
    expect(() => sign(fields({ slots: [] }))).toThrow(RangeError);
    expect(() => sign(fields({ slots: Array.from({ length: MAX_SLOTS + 1 }, () => slots[0]) }))).toThrow(RangeError);
    expect(() => sign(fields({ gateway: 'zz' }))).toThrow(RangeError);
    expect(() => sign(fields({ tunnelId: new Uint8Array(7) }))).toThrow(RangeError);
  });

  it('id はバイト列のハッシュ: 内容が変われば変わる', () => {
    const a = sign(fields());
    const b = sign(fields({ tunnelId: new Uint8Array(8).fill(9) }));
    expect(leaseSetId(a)).toMatch(/^[0-9a-f]{32}$/);
    expect(leaseSetId(a)).toBe(leaseSetId(a.slice()));
    expect(leaseSetId(a)).not.toBe(leaseSetId(b));
  });
});

describe('LeaseSet: 検証', () => {
  it('正しい leaseSet は通る', () => {
    expect(verify(sign(fields()))).toEqual({ ok: true });
    expect(verify(sign(fields({ slots: slots })))).toEqual({ ok: true });
  });

  it('★改竄: SID・枠の nonce / 解・gateway・tunnelId・期限・署名のどこを 1 バイト変えても落ちる', () => {
    const good = sign(fields());
    const offsets = [1, 20, 34, 40, 74, 80, 90, 95, 100, 101, 140, 164];
    for (const o of offsets) {
      const bad = good.slice();
      bad[o] ^= 0x01;
      const ls = decodeLeaseSet(bad);
      if (!ls) continue; // 構造が壊れたものは decode で落ちる
      expect(verifyLeaseSet(ls, ctx()).ok, `offset ${o}`).toBe(false);
    }
  });

  it('署名が正しくても、枠の PoW が偽なら落ちる (別 SID の解・枠番号のずれ・解の改竄)', () => {
    const otherKp = sodium.crypto_sign_keypair();
    // 解を 1 バイト変える (署名はそれを含めて作り直すので署名は正しい)
    const tampered = { nonce: slots[0].nonce, solution: slots[0].solution.map((v, i) => (i === 0 ? v ^ 1 : v)) };
    const v1 = verify(sign(fields({ slots: [tampered] })));
    expect(v1).toEqual({ ok: false, reason: 'bad-slot-pow' });
    // 枠 0 の解を枠 1 に置く (枠番号が challenge に入るので通らない)
    expect(verify(sign(fields({ slots: [slots[0], slots[0]] })))).toEqual({ ok: false, reason: 'bad-slot-pow' });
    // 他人の SID の解を流用 (SID が challenge に入る)
    expect(verifySlotSolution(otherKp.publicKey, 0, slots[0], EFFORT)).toBe(false);
  });

  it('署名の鍵が SID と違えば落ちる', () => {
    const other = sodium.crypto_sign_keypair();
    const b = signLeaseSet(fields(), (m) => sodium.crypto_sign_detached(m, other.privateKey));
    expect(verify(b)).toEqual({ ok: false, reason: 'bad-signature' });
  });

  it('★期限: (now, now + 6h + 15 分] だけ通る', () => {
    const nowMin = msToMinutes(T0);
    const at = (min: number) => verify(sign(fields({ expiresMin: min })));
    expect(at(nowMin)).toEqual({ ok: false, reason: 'expired' }); // ちょうど今 = 切れている
    expect(at(nowMin - 30)).toEqual({ ok: false, reason: 'expired' });
    expect(at(nowMin + 1)).toEqual({ ok: true });
    expect(at(nowMin + 360)).toEqual({ ok: true }); // 6 時間
    expect(at(nowMin + 375)).toEqual({ ok: true }); // + 時計のずれ 15 分
    expect(at(nowMin + 376)).toEqual({ ok: false, reason: 'too-far' });
    expect(at(0xffffff)).toEqual({ ok: false, reason: 'too-far' });
    // 時計が進めば同じ leaseSet が切れる
    const b = sign(fields());
    expect(verify(b, ctx({ nowMs: T0 + 6 * H - MINUTE_MS }))).toEqual({ ok: true });
    expect(verify(b, ctx({ nowMs: T0 + 6 * H }))).toEqual({ ok: false, reason: 'expired' });
  });

  it('★受け口: 信頼リストが有効なら信頼 Guard だけ。open (リスト無し) なら誰でも。判定関数に peerId が渡る', () => {
    const b = sign(fields());
    const seen: string[] = [];
    const trusted = new Set([GATEWAY]);
    const list = (id: string) => { seen.push(id); return trusted.has(id); };
    expect(verify(b, ctx({ gatewayAllowed: list }))).toEqual({ ok: true });
    expect(seen).toEqual([GATEWAY]);
    trusted.clear();
    expect(verify(b, ctx({ gatewayAllowed: list }))).toEqual({ ok: false, reason: 'untrusted-gateway' });
    expect(verify(b, ctx({ gatewayAllowed: () => true }))).toEqual({ ok: true });
  });

  it('枠の数 0 / 17 の leaseSet オブジェクトは slot-count で落ちる (decode を通らない経路への備え)', () => {
    const ls = decodeLeaseSet(sign(fields()))!;
    expect(verifyLeaseSet({ ...ls, slots: [] }, ctx())).toEqual({ ok: false, reason: 'slot-count' });
    expect(verifyLeaseSet({ ...ls, slots: Array.from({ length: 17 }, () => slots[0]) }, ctx())).toEqual({ ok: false, reason: 'slot-count' });
  });

  it('安い検査が先: 期限切れ・遠すぎ・受け口は署名の検証より前に落ちる (署名が壊れていても理由は期限)', () => {
    const b = sign(fields({ expiresMin: msToMinutes(T0) - 5 }));
    b[b.length - 1] ^= 1;
    expect(verify(b)).toEqual({ ok: false, reason: 'expired' });
  });
});

describe('SlotPow: 枠の PoW と位置', () => {
  it('位置は決定的: 同じ (SID, 枠, 解) は同じ位置、枠・SID・解が違えば別の位置', () => {
    const p0 = slotPosition(kp.publicKey, 0, slots[0].solution);
    expect(slotPosition(kp.publicKey, 0, slots[0].solution)).toBe(p0);
    expect(slotPosition(kp.publicKey, 1, slots[0].solution)).not.toBe(p0);
    expect(slotPosition(sodium.crypto_sign_keypair().publicKey, 0, slots[0].solution)).not.toBe(p0);
    expect(slotPosition(kp.publicKey, 0, slots[1].solution)).not.toBe(p0);
    expect(p0).toBeGreaterThanOrEqual(0n);
    expect(p0).toBeLessThan(1n << 64n);
  });

  it('位置は仕様どおり: u64(BLAKE2b("oz/v5/slot" ‖ SID ‖ u8 i ‖ 解)[0..8]) に Ring.positionOf の長さ前置きを付けたもの', async () => {
    const { positionOf } = await import('../../src/common/Ring');
    expect(slotPosition(kp.publicKey, 2, slots[2].solution))
      .toBe(positionOf('oz/v5/slot', kp.publicKey, Uint8Array.of(2), slots[2].solution));
  });

  it('解は検証できる。nonce・解・枠番号・SID を変えると通らない', () => {
    for (let i = 0; i < 3; i++) expect(verifySlotSolution(kp.publicKey, i, slots[i], EFFORT)).toBe(true);
    expect(verifySlotSolution(kp.publicKey, 0, { ...slots[0], nonce: slots[0].nonce + 1 }, EFFORT)).toBe(false);
    expect(verifySlotSolution(kp.publicKey, 1, slots[0], EFFORT)).toBe(false);
    expect(verifySlotSolution(kp.publicKey, 0, { nonce: slots[0].nonce, solution: new Uint8Array(15) }, EFFORT)).toBe(false);
    expect(verifySlotSolution(kp.publicKey, MAX_SLOTS, slots[0], EFFORT)).toBe(false);
    expect(verifySlotSolution(new Uint8Array(31), 0, slots[0], EFFORT)).toBe(false);
  });

  it('★本番の effort (SLOT_EFFORT) で 1 枠解いて検証できる。effort 1 の解は通常これを満たさない', async () => {
    const t = performance.now();
    const sol = (await solveSlot(kp.publicKey, 0, { effort: SLOT_EFFORT }))!;
    const ms = performance.now() - t;
    console.log(`[slot-pow] SLOT_EFFORT=${SLOT_EFFORT}: 1 枠 ${ms.toFixed(0)} ms`);
    expect(verifySlotSolution(kp.publicKey, 0, sol)).toBe(true);
    expect(verifySlotSolution(kp.publicKey, 0, { ...sol, nonce: sol.nonce + 1 })).toBe(false);
    // 検証は軽い
    const t2 = performance.now();
    for (let i = 0; i < 500; i++) verifySlotSolution(kp.publicKey, 0, sol);
    const us = ((performance.now() - t2) / 500) * 1000;
    console.log(`[slot-pow] verify: ${us.toFixed(1)} µs`);
    expect(us).toBeLessThan(1000);
  }, 120_000);

  it('解く処理は shouldStop で止められる', async () => {
    let n = 0;
    const r = await solveSlot(kp.publicKey, 5, { effort: 1e9, shouldStop: () => ++n > 3 });
    expect(r).toBeNull();
  });
});

describe('StorageIdentity: SID と枠の保存', () => {
  const memStore = () => {
    const m = new Map<string, unknown>();
    return { m, get: async (k: string) => m.get(k), set: async (k: string, v: unknown) => { m.set(k, v); } };
  };

  it('初回は作って保存し、次回は同じ SID を復元する。署名は SID の公開鍵で検証できる', async () => {
    const store = memStore();
    const a = await StorageIdentity.loadOrCreate(store, EFFORT);
    expect(a.publicKey).toHaveLength(32);
    expect(store.m.has(STORAGE_IDENTITY_KEY)).toBe(true);
    const b = await StorageIdentity.loadOrCreate(store, EFFORT);
    expect(Array.from(b.publicKey)).toEqual(Array.from(a.publicKey));
    const msg = new TextEncoder().encode('hello');
    expect(sodium.crypto_sign_verify_detached(b.sign(msg), msg, a.publicKey)).toBe(true);
    // 別の端末 (別の store) は別の SID
    const c = await StorageIdentity.loadOrCreate(memStore(), EFFORT);
    expect(Array.from(c.publicKey)).not.toEqual(Array.from(a.publicKey));
    await Promise.all([a.destroy(), b.destroy(), c.destroy()]);
  });

  it('枠は 1 枠ずつ解いて保存する。再起動後は解き直さずに同じ位置を得る。増やせば足りない分だけ解く', async () => {
    const store = memStore();
    const a = await StorageIdentity.loadOrCreate(store, EFFORT);
    const solved: number[] = [];
    await a.ensureSlots(2, (s) => solved.push(s.index));
    expect(solved).toEqual([0, 1]);
    expect(a.slots.map(s => s.index)).toEqual([0, 1]);
    const positions = a.slots.map(s => s.position);
    expect((store.m.get(STORAGE_IDENTITY_KEY) as any).slots).toHaveLength(2);

    const b = await StorageIdentity.loadOrCreate(store, EFFORT);
    expect(b.slots.map(s => s.position)).toEqual(positions); // 位置は SID が続く限り変わらない
    const solvedAgain: number[] = [];
    await b.ensureSlots(3, (s) => solvedAgain.push(s.index));
    expect(solvedAgain).toEqual([2]); // 足りない 1 枠だけ
    await b.ensureSlots(2); // 減らす指示では何もしない
    expect(b.slots).toHaveLength(3);
    await Promise.all([a.destroy(), b.destroy()]);
  });

  it('保存された解が壊れていたら、その枠以降は捨てて解き直す (信用して位置にしない)', async () => {
    const store = memStore();
    const a = await StorageIdentity.loadOrCreate(store, EFFORT);
    await a.ensureSlots(3);
    const rec: any = store.m.get(STORAGE_IDENTITY_KEY);
    rec.slots[1] = { nonce: rec.slots[1].nonce, solution: new Uint8Array(16) };
    const b = await StorageIdentity.loadOrCreate(store, EFFORT);
    expect(b.slots).toHaveLength(1);
    await Promise.all([a.destroy(), b.destroy()]);
  });

  it('★読み出しが失敗したら新しく作らない (既存の SID を上書きしない)', async () => {
    const store = memStore();
    const a = await StorageIdentity.loadOrCreate(store, EFFORT);
    const before = store.m.get(STORAGE_IDENTITY_KEY);
    await expect(StorageIdentity.loadOrCreate({ get: async () => { throw new Error('idb'); }, set: store.set }, EFFORT)).rejects.toThrow('idb');
    expect(store.m.get(STORAGE_IDENTITY_KEY)).toBe(before);
    await a.destroy();
  });

  it('destroy 後は署名できない', async () => {
    const a = await StorageIdentity.loadOrCreate(memStore(), EFFORT);
    await a.destroy();
    expect(() => a.sign(new Uint8Array(1))).toThrow();
  });

  it('★暗号化 DB の上では、生の IndexedDB を全部読んでも SID の秘密鍵も枠の解も平文では出てこない', async () => {
    const name = `sid_at_rest_${Date.now()}`;
    const db = new IndexedDBStore(name);
    await db.init();
    await db.unlock('pw', VAULT_PARAMS_FAST);
    const sid = await StorageIdentity.loadOrCreate({ get: (n) => db.getSetting(n), set: (n, v) => db.setSetting(n, v) }, EFFORT);
    await sid.ensureSlots(1);
    const rec: any = await db.getSetting(STORAGE_IDENTITY_KEY);
    expect(rec.sk).toBeInstanceOf(Uint8Array); // 復号すれば読める
    const dump = await rawDump(name);
    expect(dump).not.toContain(latin1(rec.sk.subarray(0, 32)));
    expect(dump).not.toContain(latin1(sid.publicKey));
    expect(dump).not.toContain(latin1(sid.slots[0].solution));
    expect(dump).not.toContain('storage.sid');
    await sid.destroy();
    db.lock();
  });
});

describe('時刻の起点', () => {
  it('期限 u24 は OZ_EPOCH からの分 (2025-01-01)', () => {
    expect(minutesToMs(0)).toBe(OZ_EPOCH_MS);
  });
});

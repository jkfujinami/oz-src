import { describe, it, expect } from 'vitest';
import sodium from '../../src/crypto/sodium';
import {
  POW_POLICY,
  PACKET_VERSION,
  OZ_EPOCH_MS,
  POW_DOMAIN,
  msToMinutes,
  minutesToMs,
  effortFromExp,
  effortExpAtLeast,
  minEffortFor,
  effortFor,
  powSeed,
  headerPrefix,
  derivePacketId,
  verifyPow,
  solvePow,
  meetsDifficulty,
  toBytes,
  u64be,
  u32be,
  u16be,
  u24be,
  concat,
  type PowCommitted,
} from '../../src/crypto/PowPolicy';
import { equixSolve, equixVerify } from '../../src/crypto/equix/EquiX';

/** 固定値のヘッダ (乱数を使わないので結果は決定的) */
const header = (over: Partial<PowCommitted> = {}): PowCommitted => ({
  version: PACKET_VERSION,
  time: 1_000_000,
  tag: 0x0abc,
  age: 3,
  effort_exp: 0,
  payload: new TextEncoder().encode('fixed-payload-for-pow-tests'),
  ...over,
});

describe('PowPolicy: 定数', () => {
  it('版・起点・ヘッダ長', () => {
    expect(PACKET_VERSION).toBe(2);
    expect(OZ_EPOCH_MS).toBe(Date.parse('2025-01-01T00:00:00Z'));
    expect(POW_POLICY.HEADER_BYTES).toBe(28);
    expect(POW_POLICY.MIN_EFFORT_PER_CELL).toBe(1);
    expect(POW_POLICY.MAX_AGE_DAYS).toBe(90);
    expect(POW_POLICY.MAX_EFFORT_EXP).toBe(80);
    expect(new TextDecoder().decode(POW_DOMAIN)).toBe('OZ/v5/pow');
  });

  it('MAX_PAYLOAD_SIZE = siv 16 + flags 1 + スレ立ての thread_id 33 + 親 32 + 署名ブロック 96 + 本文 2048', () => {
    expect(POW_POLICY.MAX_PAYLOAD_SIZE).toBe(16 + 1 + 33 + 32 + 96 + 2048);
  });
});

describe('PowPolicy: 時刻 (起点からの分, u24)', () => {
  it('ms ⇔ 分の往復。分未満は切り捨て', () => {
    const t = Date.UTC(2026, 9, 14, 12, 34, 56, 789);
    const m = msToMinutes(t);
    expect(minutesToMs(m)).toBe(Date.UTC(2026, 9, 14, 12, 34));
    expect(msToMinutes(OZ_EPOCH_MS)).toBe(0);
    expect(msToMinutes(OZ_EPOCH_MS + 59_999)).toBe(0);
    expect(msToMinutes(OZ_EPOCH_MS + 60_000)).toBe(1);
  });

  it('起点より前・u24 を超える時刻 (約 31.9 年後) は RangeError', () => {
    expect(() => msToMinutes(OZ_EPOCH_MS - 1)).toThrow(RangeError);
    expect(msToMinutes(minutesToMs(0xffffff))).toBe(0xffffff);
    expect(() => msToMinutes(minutesToMs(0x1000000))).toThrow(RangeError);
    expect(() => msToMinutes(NaN)).toThrow(RangeError);
  });
});

describe('PowPolicy: effort の量子化 (effort = floor(2^(e/4)))', () => {
  it('代表値', () => {
    expect(effortFromExp(0)).toBe(1);
    expect(effortFromExp(3)).toBe(1);
    expect(effortFromExp(4)).toBe(2);
    expect(effortFromExp(7)).toBe(3);
    expect(effortFromExp(8)).toBe(4);
    expect(effortFromExp(40)).toBe(1024);
    expect(effortFromExp(80)).toBe(2 ** 20);
  });

  it('単調非減少で、範囲外 (負・81 以上・非整数) は RangeError', () => {
    let prev = 0;
    for (let e = 0; e <= 80; e++) {
      const v = effortFromExp(e);
      expect(v).toBeGreaterThanOrEqual(prev);
      prev = v;
    }
    for (const bad of [-1, 81, 1.5, NaN]) expect(() => effortFromExp(bad)).toThrow(RangeError);
  });

  it('effortExpAtLeast は、その effort 以上を満たす最小の指数', () => {
    expect(effortExpAtLeast(1)).toBe(0);
    expect(effortExpAtLeast(0.2)).toBe(0);
    expect(effortExpAtLeast(2)).toBe(4);
    expect(effortExpAtLeast(3)).toBe(7);
    expect(effortExpAtLeast(100)).toBe(27); // floor(2^(27/4)) = 107 / 26 -> 90
    for (const want of [1, 2, 3, 5, 9, 17, 100, 1000, 12345]) {
      const e = effortExpAtLeast(want);
      expect(effortFromExp(e)).toBeGreaterThanOrEqual(want);
      if (e > 0) expect(effortFromExp(e - 1)).toBeLessThan(want);
    }
  });
});

describe('PowPolicy: 最低 effort (長い投稿は 1000 バイト = 1 セルごとに払う)', () => {
  it('minEffortFor は ceil(バイト数 / 1000) × MIN_EFFORT_PER_CELL (最低 1 セル)', () => {
    expect(minEffortFor(0)).toBe(1);
    expect(minEffortFor(1)).toBe(1);
    expect(minEffortFor(1000)).toBe(1);
    expect(minEffortFor(1001)).toBe(2);
    expect(minEffortFor(2000)).toBe(2);
    expect(minEffortFor(2001)).toBe(3);
    expect(minEffortFor(POW_POLICY.HEADER_BYTES + POW_POLICY.MAX_PAYLOAD_SIZE)).toBe(3);
  });

  it('effortFor は最低値を満たす最小の量子化値 (1 セル → e=0, 2 セル → e=4, 3 セル → e=7)', () => {
    expect(effortFor(200)).toEqual({ exp: 0, effort: 1 });
    expect(effortFor(1500)).toEqual({ exp: 4, effort: 2 });
    expect(effortFor(2500)).toEqual({ exp: 7, effort: 3 });
  });

  it('推奨 effort のフック: 最低値より高ければそちらに合わせ、低ければ最低値のまま', () => {
    expect(effortFor(200, 16)).toEqual({ exp: 16, effort: 16 });
    expect(effortFor(200, 5).effort).toBeGreaterThanOrEqual(5);
    expect(effortFor(2500, 1)).toEqual({ exp: 7, effort: 3 });
  });
});

describe('PowPolicy: 整数のビッグエンディアン符号化', () => {
  it('u64be / u32be / u24be / u16be', () => {
    expect(Array.from(u64be(0x0102030405060708n))).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(Array.from(u64be(1))).toEqual([0, 0, 0, 0, 0, 0, 0, 1]);
    expect(Array.from(u32be(0xdeadbeef))).toEqual([0xde, 0xad, 0xbe, 0xef]);
    expect(Array.from(u24be(0x123456))).toEqual([0x12, 0x34, 0x56]);
    expect(Array.from(u16be(0x1234))).toEqual([0x12, 0x34]);
  });

  it('u64be は整数でない値を例外で拒否する', () => {
    expect(() => u64be(1.5)).toThrow(RangeError);
    expect(() => u64be(NaN)).toThrow(RangeError);
  });

  it('concat は順序どおりに連結する', () => {
    expect(Array.from(concat([Uint8Array.of(1), new Uint8Array(0), Uint8Array.of(2, 3)]))).toEqual([1, 2, 3]);
    expect(concat([])).toHaveLength(0);
  });
});

describe('PowPolicy: toBytes (MsgPack 由来の形の正規化)', () => {
  it('Uint8Array / 配列 / {data:[...]} / ArrayBuffer / Buffer / DataView が同じバイト列になる', () => {
    const want = [1, 2, 3];
    const backing = new Uint8Array([9, 1, 2, 3, 9]);
    const forms: unknown[] = [
      Uint8Array.of(1, 2, 3),
      [1, 2, 3],
      { data: [1, 2, 3] },
      Uint8Array.of(1, 2, 3).buffer,
      Buffer.from([1, 2, 3]),
      new DataView(backing.buffer, 1, 3),
      backing.subarray(1, 4),
    ];
    for (const f of forms) expect(Array.from(toBytes(f))).toEqual(want);
  });

  it('解釈できない値は空のバイト列', () => {
    for (const v of [undefined, null, 'abc', 42, {}, { data: 'x' }]) expect(toBytes(v)).toHaveLength(0);
  });
});

describe('PowPolicy: meetsDifficulty (SHA-256 hashcash。HINT と NodeId PoW が使う)', () => {
  const h = (bytes: number[]) => Uint8Array.from([...bytes, ...new Array(32 - bytes.length).fill(0xff)]);

  it('difficulty <= 0 は常に true / ハッシュ長を超えれば false', () => {
    expect(meetsDifficulty(h([0xff]), 0)).toBe(true);
    expect(meetsDifficulty(new Uint8Array(32), 257)).toBe(false);
    expect(meetsDifficulty(new Uint8Array(32), 256)).toBe(true);
  });

  it('ビット単位で境界を判定する', () => {
    const x = h([0x00, 0x1f]); // 先頭ゼロビットはちょうど 11
    expect(meetsDifficulty(x, 11)).toBe(true);
    expect(meetsDifficulty(x, 12)).toBe(false);
    expect(meetsDifficulty(h([0x80]), 1)).toBe(false);
    expect(meetsDifficulty(h([0x7f]), 1)).toBe(true);
    expect(meetsDifficulty(h([0, 0, 1]), 23)).toBe(true);
    expect(meetsDifficulty(h([0, 0, 1]), 24)).toBe(false);
  });
});

describe('PowPolicy: PoW の challenge (C) と packet_id', () => {
  it('C = BLAKE2b-256("OZ/v5/pow" ‖ version ‖ time ‖ tag ‖ age ‖ e ‖ SHA-256(payload))', () => {
    const h = header({ effort_exp: 9 });
    const want = sodium.crypto_generichash(32, concat([
      new TextEncoder().encode('OZ/v5/pow'),
      Uint8Array.of(PACKET_VERSION), u24be(h.time), u16be(h.tag), Uint8Array.of(h.age), Uint8Array.of(9),
      sodium.crypto_hash_sha256(h.payload),
    ]), null);
    expect(Array.from(powSeed(h))).toEqual(Array.from(want));
    expect(headerPrefix(h)).toHaveLength(7);
  });

  it('C は version / time / tag / age / effort / payload のどれを変えても変わる (effort も入る)', () => {
    const base = Array.from(powSeed(header()));
    for (const over of [
      { version: 3 }, { time: 1_000_001 }, { tag: 0x0abd }, { age: 4 }, { effort_exp: 1 },
      { payload: new TextEncoder().encode('fixed-payload-for-pow-tests!') },
    ] as Partial<PowCommitted>[]) {
      expect(Array.from(powSeed(header(over))), JSON.stringify(Object.keys(over))).not.toEqual(base);
    }
  });

  it('packet_id は SHA-256("OZ/v5/id" ‖ version ‖ time ‖ tag ‖ age ‖ payload) の先頭 16 バイト (hex 32 文字)', () => {
    const h = header();
    const want = sodium.crypto_hash_sha256(concat([
      new TextEncoder().encode('OZ/v5/id'), headerPrefix(h), h.payload,
    ])).slice(0, 16);
    const id = derivePacketId(h);
    expect(id).toMatch(/^[0-9a-f]{32}$/);
    expect(id).toBe(sodium.to_hex(want));
  });

  it('packet_id は time / tag / age / payload で変わるが、effort には依存しない (解き直しても同じ id)', () => {
    const base = derivePacketId(header());
    for (const over of [{ time: 1_000_001 }, { tag: 1 }, { age: 4 }, { payload: Uint8Array.of(1) }] as Partial<PowCommitted>[]) {
      expect(derivePacketId(header(over))).not.toBe(base);
    }
    expect(derivePacketId(header({ effort_exp: 0 }))).toBe(derivePacketId(header({ effort_exp: 40 })));
  });
});

describe('PowPolicy: Equi-X の解と検証', () => {
  it('solvePow の解は verifyPow を通る。effort 1 では 1 個目の解で済む (実測を出力)', () => {
    const h = header();
    const t0 = performance.now();
    const sol = solvePow(h)!;
    const ms = performance.now() - t0;
    // eslint-disable-next-line no-console
    console.log(`[pow] effort 1 solve: ${ms.toFixed(0)} ms (nonce ${sol.nonce})`);
    expect(sol.solution).toHaveLength(16);
    expect(verifyPow(h, sol)).toBe(true);
  });

  it('★解は申告した effort の challenge にだけ有効: 高い effort を名乗り直すと通らない', () => {
    const h = header({ time: 1_000_010 });
    const sol = solvePow(h)!;
    expect(verifyPow(h, sol)).toBe(true);
    for (const e of [1, 4, 8, 16, 40, 80]) expect(verifyPow({ ...h, effort_exp: e }, sol), `e=${e}`).toBe(false);
  });

  it('★Equi-X として正しい解でも、u32be(BLAKE2b(C ‖ nonce ‖ s)[0..4]) × effort が 2^32 - 1 を超えれば拒否する', () => {
    const h = header({ time: 1_000_020, effort_exp: 8 }); // effort 4
    const seed = powSeed(h);
    let checkedFail = 0, checkedPass = 0;
    for (let nonce = 0; nonce < 40 && (checkedFail < 3 || checkedPass < 1); nonce++) {
      const ch = concat([seed, u32be(nonce)]);
      for (const s of equixSolve(ch)) {
        expect(equixVerify(ch, s)).toBe(true);
        const r = sodium.crypto_generichash(32, concat([seed, u32be(nonce), s]), null);
        const v = ((r[0] << 24) | (r[1] << 16) | (r[2] << 8) | r[3]) >>> 0;
        const ok = v * 4 <= 0xffffffff;
        expect(verifyPow(h, { nonce, solution: s })).toBe(ok);
        if (ok) checkedPass++; else checkedFail++;
      }
    }
    expect(checkedFail).toBeGreaterThanOrEqual(1);
  });

  it('effort 4 の探索も解ける (nonce を進めて探す)', () => {
    const h = header({ time: 1_000_030, effort_exp: 8 });
    const sol = solvePow(h)!;
    expect(verifyPow(h, sol)).toBe(true);
  });

  it('ヘッダ (time / tag / age / payload) を書き換えた複製には同じ解は通らない', () => {
    const h = header({ time: 1_000_040 });
    const sol = solvePow(h)!;
    for (const over of [{ time: h.time + 1 }, { tag: 1 }, { age: 5 }, { payload: Uint8Array.of(1, 2) }] as Partial<PowCommitted>[]) {
      expect(verifyPow({ ...h, ...over }, sol)).toBe(false);
    }
  });

  it('壊れた入力 (範囲外の effort・nonce・解の長さ) は例外ではなく false', () => {
    const h = header({ time: 1_000_050 });
    const sol = solvePow(h)!;
    expect(verifyPow({ ...h, effort_exp: 81 }, sol)).toBe(false);
    expect(verifyPow({ ...h, effort_exp: -1 }, sol)).toBe(false);
    expect(verifyPow(h, { nonce: -1, solution: sol.solution })).toBe(false);
    expect(verifyPow(h, { nonce: 2 ** 32, solution: sol.solution })).toBe(false);
    expect(verifyPow(h, { nonce: sol.nonce, solution: sol.solution.subarray(0, 15) })).toBe(false);
  });

  it('solvePow は打ち切り上限に達すると null / 範囲外の effort は例外', () => {
    expect(solvePow(header(), 0)).toBeNull();
    expect(() => solvePow(header({ effort_exp: 81 }))).toThrow(RangeError);
  });

  it('solvePow は決定的で、最小の nonce の解を返す', () => {
    const h = header({ time: 1_000_060 });
    const a = solvePow(h)!;
    const b = solvePow(h)!;
    expect(a.nonce).toBe(b.nonce);
    expect(Array.from(a.solution)).toEqual(Array.from(b.solution));
    // effort 1 なら、解が出た最初の nonce で止まる
    for (let n = 0; n < a.nonce; n++) expect(equixSolve(concat([powSeed(h), u32be(n)]))).toHaveLength(0);
  });
});

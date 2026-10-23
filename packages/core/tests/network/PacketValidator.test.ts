import { describe, it, expect, beforeAll, vi } from 'vitest';
import { PacketValidator, GOSSIP_RULES } from '../../src/network/gossip/PacketValidator';
import {
  PACKET_VERSION, POW_POLICY, derivePacketId, minutesToMs, msToMinutes, solvePow, effortFromExp, minEffortFor,
  type PowCommitted,
} from '../../src/crypto/PowPolicy';
import { JsonBinary } from '../../src/common/JsonBinary';
import { WireCodec } from '../../src/network/wire/WireCodec';
import { WireType } from '../../src/network/wire/WireTypes';
import type { GossipPacket } from '../../src/types';

const NOW = Date.UTC(2026, 5, 1, 12, 0, 0);
const DRIFT = POW_POLICY.MAX_TIME_DRIFT;

/** 有効なパケットを作る (本物の Equi-X。既定は effort 1 で、1 個 60〜100ms) */
function makePacket(over: Partial<PowCommitted> & { payloadBytes?: number } = {}): GossipPacket {
  const { payloadBytes, ...rest } = over;
  const committed: PowCommitted = {
    version: PACKET_VERSION,
    time: msToMinutes(NOW),
    tag: 5,
    age: 0,
    effort_exp: 0,
    payload: new Uint8Array(payloadBytes ?? 150).fill(0x42),
    ...rest,
  };
  const sol = solvePow(committed);
  if (sol === null) throw new Error('no pow');
  return {
    packet_id: derivePacketId(committed),
    timestamp: minutesToMs(committed.time),
    tag: committed.tag,
    age: committed.age,
    effort_exp: committed.effort_exp,
    pow_nonce: sol.nonce,
    pow_solution: sol.solution,
    payload: committed.payload,
  };
}

let valid: GossipPacket;
beforeAll(() => {
  valid = makePacket();
});

const check = (p: any, opts: any = {}) => PacketValidator.check(p, { now: NOW, ...opts });
const reason = (p: any, opts: any = {}) => (check(p, opts) as any).reason;

describe('PacketValidator: 正当なパケット', () => {
  it('正しく作ったパケットを受理する', () => {
    expect(check(valid)).toEqual({ ok: true });
  });

  it('ワイヤ (WireCodec のコンパクト形式) を往復しても受理する。packet_id は受信側が導出する', () => {
    const { payload } = WireCodec.decode(WireCodec.encode(WireType.GOSSIP, { packet: valid }));
    expect(check(payload.packet)).toEqual({ ok: true });
    expect(payload.packet.packet_id).toBe(valid.packet_id);
  });

  it('JSON (JsonBinary) を往復した {_type, data} 形式や素の配列でも受理する (表現の揺れを正規化)', () => {
    expect(check(JsonBinary.parse(JsonBinary.stringify(valid)))).toEqual({ ok: true });
    expect(check(JSON.parse(JSON.stringify({ ...valid, pow_solution: Array.from(valid.pow_solution), payload: Array.from(valid.payload) })))).toEqual({ ok: true });
    expect(check(JSON.parse(JSON.stringify({ ...valid, pow_solution: { data: Array.from(valid.pow_solution) }, payload: { data: Array.from(valid.payload) } })))).toEqual({ ok: true });
  });

  it('ペイロード上限ちょうど (MAX_PAYLOAD_SIZE = 3 セル分なので effort 3 = e 7) は受理する', () => {
    expect(check(makePacket({ payloadBytes: POW_POLICY.MAX_PAYLOAD_SIZE, effort_exp: 7 }))).toEqual({ ok: true });
  });

  it('最低より高い effort (例: e=8 → effort 4) も受理する', () => {
    expect(check(makePacket({ effort_exp: 8 }))).toEqual({ ok: true });
  });

  it('GOSSIP_RULES は POW_POLICY と同じ値', () => {
    expect(GOSSIP_RULES).toEqual({
      MAX_PAYLOAD_SIZE: POW_POLICY.MAX_PAYLOAD_SIZE,
      MAX_TIME_DRIFT: POW_POLICY.MAX_TIME_DRIFT,
      MIN_EFFORT_PER_CELL: POW_POLICY.MIN_EFFORT_PER_CELL,
    });
  });
});

describe('PacketValidator: 形式の拒否', () => {
  it('オブジェクトでないものは malformed', () => {
    for (const p of [null, undefined, 42, 'x', true]) expect(check(p)).toEqual({ ok: false, reason: 'malformed' });
  });

  it('packet_id が 32 文字の文字列でなければ bad-packet-id-type', () => {
    for (const id of [undefined, 123, '', 'a'.repeat(31), 'a'.repeat(33), 'a'.repeat(64), ['x']]) {
      expect(reason({ ...valid, packet_id: id }), String(id)).toBe('bad-packet-id-type');
    }
  });

  it('timestamp が安全な非負整数でなく、または起点より前・u24 分を超えるなら bad-timestamp', () => {
    for (const ts of [undefined, '1700000000000', -1, 1.5, NaN, Infinity, 2 ** 53, BigInt(NOW), 0, minutesToMs(0x1000000)]) {
      expect(reason({ ...valid, timestamp: ts }), String(ts)).toBe('bad-timestamp');
    }
  });

  it('ペイロードが小さすぎる (署名ブロックに満たない)・大きすぎるなら bad-payload-size', () => {
    expect(reason({ ...valid, payload: new Uint8Array(0) })).toBe('bad-payload-size');
    expect(reason({ ...valid, payload: new Uint8Array(112) })).toBe('bad-payload-size');
    expect(reason({ ...valid, payload: new Uint8Array(POW_POLICY.MAX_PAYLOAD_SIZE + 1) })).toBe('bad-payload-size');
    // バイト列として解釈できないもの (文字列など) は長さ 0 として扱われる
    expect(reason({ ...valid, payload: 'hello' })).toBe('bad-payload-size');
  });

  it('★tag は 12 ビット (0..4095)。4096 以上は、PoW が正しくても bad-tag', () => {
    expect(check(makePacket({ tag: 4095 }))).toEqual({ ok: true });
    expect(check(makePacket({ tag: 0 }))).toEqual({ ok: true });
    expect(reason(makePacket({ tag: 4096 }))).toBe('bad-tag');
    expect(reason(makePacket({ tag: 0xffff }))).toBe('bad-tag');
    for (const t of [-1, 1.5, '5', undefined, NaN]) expect(reason({ ...valid, tag: t }), String(t)).toBe('bad-tag');
  });

  it('★age は 0..90 日。91 以上は、PoW が正しくても bad-age (中継が拒否する)', () => {
    expect(check(makePacket({ age: 90 }))).toEqual({ ok: true });
    expect(reason(makePacket({ age: 91 }))).toBe('bad-age');
    expect(reason(makePacket({ age: 255 }))).toBe('bad-age');
    for (const a of [-1, 1.5, '5', undefined, NaN]) expect(reason({ ...valid, age: a }), String(a)).toBe('bad-age');
  });

  it('effort の指数が 0..80 に収まらなければ bad-effort', () => {
    for (const e of [81, 255, -1, 1.5, '0', undefined]) expect(reason({ ...valid, effort_exp: e }), String(e)).toBe('bad-effort');
  });

  it('解が 16 バイトでなければ bad-solution / pow_nonce が u32 でなければ bad-pow-nonce', () => {
    for (const s of [new Uint8Array(0), new Uint8Array(15), new Uint8Array(17), undefined, 'x']) {
      expect(reason({ ...valid, pow_solution: s })).toBe('bad-solution');
    }
    for (const n of [-1, 1.5, '7', undefined, NaN, Infinity, 2 ** 32, 7n]) {
      expect(reason({ ...valid, pow_nonce: n }), String(n)).toBe('bad-pow-nonce');
    }
  });
});

describe('PacketValidator: 時刻', () => {
  it('未来方向は MAX_TIME_DRIFT (15 分) ちょうどまで受理し、それを超えたら time-drift', () => {
    const p = valid;
    expect(check(p, { now: p.timestamp - DRIFT })).toEqual({ ok: true });
    expect(check(p, { now: p.timestamp - DRIFT - 1 })).toEqual({ ok: false, reason: 'time-drift' });
  });

  it('過去方向も 15 分ちょうどまで受理し、それを超えたら time-drift', () => {
    expect(check(valid, { now: valid.timestamp + DRIFT })).toEqual({ ok: true });
    expect(check(valid, { now: valid.timestamp + DRIFT + 1 })).toEqual({ ok: false, reason: 'time-drift' });
  });

  it('allowStale は過去方向だけを緩める (保管・過去ログ用)。未来日付は依然として拒否', () => {
    expect(check(valid, { now: valid.timestamp + 30 * 24 * 3600_000, allowStale: true })).toEqual({ ok: true });
    expect(check(valid, { now: valid.timestamp - DRIFT - 1, allowStale: true })).toEqual({ ok: false, reason: 'time-drift' });
  });

  it('now を渡さなければ Date.now を使う', () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(valid.timestamp + 1000);
      expect(PacketValidator.check(valid)).toEqual({ ok: true });
      vi.setSystemTime(valid.timestamp + DRIFT + 1);
      expect(PacketValidator.check(valid)).toEqual({ ok: false, reason: 'time-drift' });
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('PacketValidator: packet_id (ヘッダとペイロードのハッシュ)', () => {
  it('time / tag / age / payload のどれを書き換えても packet-id-mismatch', () => {
    const tampered: Array<[string, any]> = [
      ['timestamp', { timestamp: valid.timestamp + 60_000 }],
      ['tag', { tag: valid.tag + 1 }],
      ['age', { age: valid.age + 1 }],
      ['payload', { payload: Uint8Array.from(valid.payload, (b, i) => (i === 99 ? b ^ 0x80 : b)) }],
    ];
    for (const [name, over] of tampered) {
      expect(reason({ ...valid, ...over }), name).toBe('packet-id-mismatch');
    }
  });

  it('packet_id を大文字にしただけでも一致しない (正準形は小文字 hex)', () => {
    expect(check({ ...valid, packet_id: valid.packet_id.toUpperCase() })).toEqual({ ok: false, reason: 'packet-id-mismatch' });
  });

  it('★packet_id は effort / nonce / 解を含まない: 解き直した (effort も変えた) 同じ投稿は同じ id', () => {
    const again = makePacket({ effort_exp: 8 });
    expect(again.packet_id).toBe(valid.packet_id);
    expect(check(again)).toEqual({ ok: true });
  });

  it('★time を書き換えて packet_id も計算し直しても、PoW をやり直さない限り通らない (リプレイ対策)', () => {
    const replay = { ...valid, timestamp: valid.timestamp + 60_000 };
    replay.packet_id = derivePacketId({
      version: PACKET_VERSION, time: msToMinutes(replay.timestamp), tag: replay.tag, age: replay.age, payload: replay.payload,
    });
    expect(check(replay, { now: replay.timestamp })).toEqual({ ok: false, reason: 'insufficient-pow' });
  });
});

describe('PacketValidator: 最低 effort (パケットの長さから中継が計算する)', () => {
  it('★1000 バイト以下は effort 1、1001 バイトから 2000 バイトは effort 2 (e=4)、2001 バイト以上は effort 3 (e=7)', () => {
    const H = POW_POLICY.HEADER_BYTES;
    // パケット全体 (ヘッダ込み) の長さで数える
    expect(check(makePacket({ payloadBytes: 1000 - H, effort_exp: 0 }))).toEqual({ ok: true });
    expect(reason(makePacket({ payloadBytes: 1001 - H, effort_exp: 0 }))).toBe('insufficient-effort');
    expect(reason(makePacket({ payloadBytes: 1001 - H, effort_exp: 3 }))).toBe('insufficient-effort'); // floor(2^(3/4)) = 1
    expect(check(makePacket({ payloadBytes: 1001 - H, effort_exp: 4 }))).toEqual({ ok: true });
    expect(check(makePacket({ payloadBytes: 2000 - H, effort_exp: 4 }))).toEqual({ ok: true });
    expect(reason(makePacket({ payloadBytes: 2001 - H, effort_exp: 4 }))).toBe('insufficient-effort');
    expect(check(makePacket({ payloadBytes: 2001 - H, effort_exp: 7 }))).toEqual({ ok: true });
    expect(minEffortFor(1000)).toBe(1);
    expect(effortFromExp(7)).toBeGreaterThanOrEqual(minEffortFor(2001));
  });

  it('申告より長さが優先される: 長い投稿に e=0 を名乗って e=0 の正しい PoW を付けても拒否', () => {
    expect(reason(makePacket({ payloadBytes: 2200, effort_exp: 0 }))).toBe('insufficient-effort');
  });
});

describe('PacketValidator: PoW (Equi-X)', () => {
  it('解でない nonce / 壊れた解は insufficient-pow', () => {
    expect(reason({ ...valid, pow_nonce: valid.pow_nonce + 1 })).toBe('insufficient-pow');
    expect(reason({ ...valid, pow_solution: Uint8Array.from(valid.pow_solution, (b, i) => (i === 0 ? b ^ 1 : b)) })).toBe('insufficient-pow');
    expect(reason({ ...valid, pow_solution: new Uint8Array(16) })).toBe('insufficient-pow');
  });

  it('★解を使い回して、より高い effort を名乗っても通らない (effort は challenge に入る)', () => {
    for (const e of [1, 4, 8, 40, 80]) {
      expect(reason({ ...valid, effort_exp: e }), `e=${e}`).toBe('insufficient-pow');
    }
  });

  it('★どの 1 ビットを変えても、鍵なしの検証で受理されない (version は decode が落とす)', () => {
    // ヘッダ + 解 + ペイロードの全ビット。PacketCodec 経由の往復は CompactFormat.test が見る
    const fields: Array<[string, (p: GossipPacket, bit: number) => GossipPacket]> = [
      ['pow_nonce', (p, b) => ({ ...p, pow_nonce: (p.pow_nonce ^ (1 << b)) >>> 0 })],
      ['pow_solution', (p, b) => ({ ...p, pow_solution: Uint8Array.from(p.pow_solution, (x, i) => (i === (b >> 3) % 16 ? x ^ (1 << (b & 7)) : x)) })],
      ['effort_exp', (p, b) => ({ ...p, effort_exp: p.effort_exp ^ (1 << (b & 7)) })],
    ];
    for (const [name, f] of fields) {
      for (let b = 0; b < 32; b++) expect(check(f(valid, b)).ok, `${name} bit ${b}`).toBe(false);
    }
  });
});

describe('PacketValidator.validate', () => {
  it('結果を boolean で返し、壊れた入力でも例外を投げない', () => {
    expect(PacketValidator.validate(valid, { now: NOW })).toBe(true);
    expect(PacketValidator.validate({ ...valid, payload: new Uint8Array(0) }, { now: NOW })).toBe(false);
    expect(() => PacketValidator.validate(null as any)).not.toThrow();
    expect(PacketValidator.validate(null as any)).toBe(false);
    expect(PacketValidator.validate({ packet_id: 5 } as any)).toBe(false);
  });
});

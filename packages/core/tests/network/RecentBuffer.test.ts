import { describe, it, expect, beforeAll } from 'vitest';
import { sodiumReady } from '../../src/crypto/sodium';
import { RecentBuffer, RECENT_BUFFER, CATCHUP_MAX_PAST_MS } from '../../src/network/history/RecentBuffer';
import { encodePacket } from '../../src/crypto/PacketCodec';
import { POW_POLICY } from '../../src/crypto/PowPolicy';
import { makePacket } from '../helpers/onionNet';

/** 受け取り時刻を自由に動かせる時計 */
function clock(start = Date.UTC(2026, 9, 14, 12, 0, 0)) {
  let t = start;
  return { now: () => t, set: (v: number) => { t = v; }, advance: (ms: number) => { t += ms; } };
}

const H = 3600_000;
const MIN = 60_000;

describe('RecentBuffer: 役割ごとの大きさ', () => {
  it('Guard は 72 時間・256MiB、それ以外は 1 時間・16MiB', () => {
    const g = RecentBuffer.forRole('guard');
    expect([g.windowMs, g.maxBytes]).toEqual([72 * H, 256 * 1024 * 1024]);
    const c = RecentBuffer.forRole('client');
    expect([c.windowMs, c.maxBytes]).toEqual([1 * H, 16 * 1024 * 1024]);
    expect(RECENT_BUFFER.GUARD_WINDOW_MS).toBe(72 * H);
  });

  it('追いつきで受け付ける古さの上限は 72 時間 + 時刻ドリフト (15 分)', () => {
    expect(CATCHUP_MAX_PAST_MS).toBe(72 * H + POW_POLICY.MAX_TIME_DRIFT);
  });
});

describe('RecentBuffer: 保持', () => {
  const c = clock();
  beforeAll(async () => { await sodiumReady; });

  it('同じ投稿は 1 回だけ入る。受け取った順に持つ', () => {
    const b = new RecentBuffer({ windowMs: 72 * H, maxBytes: 1 << 20, now: c.now });
    const p = makePacket([1], c.now());
    expect(b.add(p)).toBe(true);
    expect(b.add(p)).toBe(false);
    expect(b.size).toBe(1);
    expect(b.bytes).toBe(encodePacket(p).length);
    expect(b.has(p.packet_id)).toBe(true);
  });

  it('保持時間 (受け取った時刻から数える) を過ぎたものは、読み出しの時点で消える', () => {
    const t = clock();
    const b = new RecentBuffer({ windowMs: 72 * H, maxBytes: 1 << 20, now: t.now });
    const old = makePacket([1], t.now());
    b.add(old);
    t.advance(71 * H);
    const mid = makePacket([2], t.now());
    b.add(mid);
    t.advance(2 * H); // old は 73 時間前、mid は 2 時間前
    expect(b.entriesSince(0).map(e => e.id)).toEqual([mid.packet_id]);
    expect(b.has(old.packet_id)).toBe(false);
    expect(b.bytes).toBe(encodePacket(mid).length);
  });

  it('保持は「受け取った時刻」で数える: 15 分遅れて届いた投稿も、入れた直後には消えない', () => {
    const t = clock();
    const b = new RecentBuffer({ windowMs: 1 * H, maxBytes: 1 << 20, now: t.now });
    const delayed = makePacket([1], t.now() - 14 * MIN);
    b.add(delayed);
    expect(b.has(delayed.packet_id)).toBe(true);
    t.advance(59 * MIN);
    expect(b.has(delayed.packet_id)).toBe(true);
    t.advance(2 * MIN);
    expect(b.entriesSince(0)).toEqual([]);
  });

  it('★上限を超えたら古い (受け取った) 順に捨て、メモリはいつも上限以下', () => {
    const t = clock();
    const one = encodePacket(makePacket([0], t.now())).length;
    const b = new RecentBuffer({ windowMs: 72 * H, maxBytes: one * 3, now: t.now });
    const ps = [1, 2, 3, 4, 5].map(i => makePacket([i], t.now()));
    for (const p of ps) {
      t.advance(1000);
      b.add(p);
      expect(b.bytes).toBeLessThanOrEqual(one * 3);
    }
    expect(b.size).toBe(3);
    expect(b.has(ps[0].packet_id)).toBe(false);
    expect(b.has(ps[1].packet_id)).toBe(false);
    expect(ps.slice(2).every(p => b.has(p.packet_id))).toBe(true);
  });

  it('entriesSince は since 以降を投稿の時刻の古い順に返す (同じ分は受け取った順)', () => {
    const t = clock();
    const b = new RecentBuffer({ windowMs: 72 * H, maxBytes: 1 << 20, now: t.now });
    const base = t.now();
    const late = makePacket([3], base - 1 * MIN);
    const early = makePacket([1], base - 30 * MIN);
    const mid = makePacket([2], base - 10 * MIN);
    const mid2 = makePacket([9], base - 10 * MIN);
    // 受け取りは時刻順ではない
    for (const p of [late, early, mid, mid2]) b.add(p);
    expect(b.entriesSince(0).map(e => e.id)).toEqual([early, mid, mid2, late].map(p => p.packet_id));
    expect(b.entriesSince(base - 10 * MIN).map(e => e.id)).toEqual([mid, mid2, late].map(p => p.packet_id));
    expect(b.entriesSince(base).map(e => e.id)).toEqual([]);
  });

  it('packets() は受け取った順に復元する', () => {
    const t = clock();
    const b = new RecentBuffer({ windowMs: 72 * H, maxBytes: 1 << 20, now: t.now });
    const ps = [1, 2, 3].map(i => makePacket([i], t.now() - i * MIN));
    ps.forEach(p => b.add(p));
    expect(b.packets().map(p => p.packet_id)).toEqual(ps.map(p => p.packet_id));
  });
});

describe('RecentBuffer: coverageStart (どこから先を全部持っているか)', () => {
  beforeAll(async () => { await sodiumReady; });

  it('作ったばかりなら、作った時刻から (それより前は見ていない)', () => {
    const t = clock();
    const start = t.now();
    const b = new RecentBuffer({ windowMs: 72 * H, maxBytes: 1 << 20, now: t.now });
    t.advance(1 * H);
    expect(b.coverageStartMs()).toBe(start);
    t.advance(100 * H);
    expect(b.coverageStartMs()).toBe(t.now() - 72 * H); // 保持時間が先に効く
  });

  it('上限で捨てたら、捨てたものの受け取り時刻まで進む', () => {
    const t = clock();
    const one = encodePacket(makePacket([0], t.now())).length;
    const b = new RecentBuffer({ windowMs: 72 * H, maxBytes: one * 2, now: t.now });
    t.advance(1 * H);
    const first = t.now();
    b.add(makePacket([1], first));
    t.advance(MIN);
    b.add(makePacket([2], t.now()));
    t.advance(MIN);
    b.add(makePacket([3], t.now())); // 1 つ目が溢れる
    expect(b.coverageStartMs()).toBeGreaterThan(first);
  });
});

import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest';
import { sodiumReady } from '../../src/crypto/sodium';
import { MessageDispatcher } from '../../src/network/MessageDispatcher';
import { WireType } from '../../src/network/wire/WireTypes';
import { WireCodec, CATCHUP_STATUS, MAX_CATCHUP_FRAME_BYTES } from '../../src/network/wire/WireCodec';
import { RecentBuffer } from '../../src/network/history/RecentBuffer';
import { CatchupServer, CATCHUP_SERVER_LIMITS, type CatchupServerOptions } from '../../src/network/history/CatchupServer';
import { decodePacket } from '../../src/crypto/PacketCodec';
import { msToMinutes } from '../../src/crypto/PowPolicy';
import { makePacket } from '../helpers/onionNet';
import { FakePeerManager } from '../helpers/logicHarness';
import type { GossipPacket } from '../../src/types';

const MIN = 60_000;
const H = 3600_000;
const A = 'a'.repeat(32);
const B = 'b'.repeat(32);

/** 大きめのペイロード (1 件 約 2.2KB)。1 フレーム (16KiB) に 8 件入る */
const big = (i: number, at: number): GossipPacket => makePacket(new Uint8Array(2000).fill(i), at);

interface Rig {
  pm: FakePeerManager;
  dispatcher: MessageDispatcher;
  buffer: RecentBuffer;
  server: CatchupServer;
  /** 相手に送ったフレームの種別 (送った順) */
  sent: (peer?: string) => Array<{ type: number; payload: any }>;
  req: (peer: string, since: number) => void;
}

function rig(opts: CatchupServerOptions = {}, bufferOpts: { windowMs?: number; maxBytes?: number; createdAgoMs?: number } = {}): Rig {
  const pm = new FakePeerManager();
  pm.peers.set(A, { peerId: A, isConnected: true, isVerified: true });
  pm.peers.set(B, { peerId: B, isConnected: true, isVerified: true });
  const dispatcher = new MessageDispatcher();
  // 入れ物は (既定で) 24 時間前から動いていたことにする。これより前の since は PARTIAL になる
  const nowMs = Date.now();
  vi.setSystemTime(nowMs - (bufferOpts.createdAgoMs ?? 24 * H));
  const buffer = new RecentBuffer({ windowMs: bufferOpts.windowMs ?? 72 * H, maxBytes: bufferOpts.maxBytes ?? 256 << 20, now: Date.now });
  vi.setSystemTime(nowMs);
  const server = new CatchupServer(pm as any, dispatcher, buffer, { now: Date.now, ...opts });
  return {
    pm, dispatcher, buffer, server,
    sent: (peer) => pm.sendMessage.mock.calls
      .filter((c: any[]) => (peer ? c[0] === peer : true))
      .map((c: any[]) => ({ type: c[1], payload: c[2] })),
    req: (peer, since) => dispatcher.dispatch(peer, WireType.CATCHUP_REQ, { since }),
  };
}

const minute = (ms: number) => msToMinutes(ms);

describe('CatchupServer', () => {
  let r: Rig;
  const t0 = Date.UTC(2026, 9, 14, 12, 0, 0);

  beforeAll(async () => { await sodiumReady; });
  beforeEach(() => { vi.useFakeTimers({ toFake: ['Date', 'setTimeout', 'clearTimeout'] }); vi.setSystemTime(t0); });
  afterEach(() => { r?.server.destroy(); vi.useRealTimers(); });

  it('since 以降を、投稿の時刻の古い順に送り、END (OK) で終える。受け取った順ではない', async () => {
    r = rig();
    const p1 = makePacket([1], t0 - 50 * MIN);
    const p2 = makePacket([2], t0 - 30 * MIN);
    const p3 = makePacket([3], t0 - 10 * MIN);
    for (const p of [p3, p1, p2]) r.buffer.add(p); // 受け取りは順不同

    r.req(A, minute(t0 - 40 * MIN));
    const out = r.sent(A);
    expect(out.map(o => o.type)).toEqual([WireType.CATCHUP_DATA, WireType.CATCHUP_END]);
    const ids = out[0].payload.packets.map((b: Uint8Array) => decodePacket(b)!.packet_id);
    expect(ids).toEqual([p2.packet_id, p3.packet_id]);
    expect(out[1].payload).toEqual({ status: CATCHUP_STATUS.OK, nextSince: minute(t0) });
  });

  it('送るフレームはそのまま WireCodec で符号化でき、16KiB 以内。多いときは複数フレームに分ける', async () => {
    r = rig();
    const ps = Array.from({ length: 17 }, (_, i) => big(i + 1, t0 - (20 - i) * MIN));
    ps.forEach(p => r.buffer.add(p));
    r.req(A, 0);
    // バーストの 1MiB に収まるので、一気に送り切る
    const data = r.sent(A).filter(o => o.type === WireType.CATCHUP_DATA);
    expect(data.length).toBe(3); // 8 + 8 + 1
    for (const d of data) {
      expect(WireCodec.encode(WireType.CATCHUP_DATA, d.payload).length).toBeLessThanOrEqual(MAX_CATCHUP_FRAME_BYTES);
    }
    const all = data.flatMap(d => d.payload.packets.map((b: Uint8Array) => decodePacket(b)!.packet_id));
    expect(all).toEqual(ps.map(p => p.packet_id));
  });

  it('★バッファの範囲より古い since は、持っている分を全部返して PARTIAL。バッファの外 (保持時間より前) は返さない', async () => {
    r = rig({}, { windowMs: 2 * H, createdAgoMs: 0 });
    r.buffer.add(makePacket([1], t0));
    vi.setSystemTime(t0 + 1 * H);
    r.buffer.add(makePacket([2], t0 + 1 * H));
    vi.setSystemTime(t0 + 3 * H); // 1 つ目は受け取りから 3 時間 (保持 2 時間の外)、2 つ目は 2 時間
    r.buffer.add(makePacket([3], t0 + 3 * H));

    r.req(A, minute(t0 - 10 * H)); // 保持時間より古い
    const out = r.sent(A);
    const ids = out[0].payload.packets.map((b: Uint8Array) => decodePacket(b)!.packet_id);
    expect(ids).toHaveLength(2); // 最初の 1 件 (保持の外) は返らない
    expect(out.at(-1)!.payload.status).toBe(CATCHUP_STATUS.PARTIAL);
  });

  it('入れ物を作る前の時刻を指す since も PARTIAL (その前は見ていない)。作った後の since は OK', async () => {
    r = rig({}, { createdAgoMs: 0 });
    vi.setSystemTime(t0 + 1 * H);
    r.req(A, minute(t0 - 1 * H));
    expect(r.sent(A).at(-1)!.payload.status).toBe(CATCHUP_STATUS.PARTIAL);
    vi.advanceTimersByTime(10_000);
    r.req(B, minute(t0 + 1 * H));
    expect(r.sent(B).at(-1)!.payload.status).toBe(CATCHUP_STATUS.OK);
  });

  it('空でも END だけは返す', () => {
    r = rig();
    r.req(A, minute(t0));
    expect(r.sent(A).map(o => o.type)).toEqual([WireType.CATCHUP_END]);
  });

  it('★1 相手につき同時に 1 本: 進行中の要求は BUSY で断り、何も追加では送らない', () => {
    // 1 フレームで帯域を使い切る設定 (進行中のまま止まる)
    r = rig({ perPeerBytesPerSec: 1000, perPeerBurstBytes: MAX_CATCHUP_FRAME_BYTES });
    for (let i = 0; i < 12; i++) r.buffer.add(big(i + 1, t0 - (20 - i) * MIN));
    r.req(A, 0);
    expect(r.server.activeSessions).toBe(1);
    const before = r.sent(A).length;
    r.req(A, 0);
    const after = r.sent(A);
    expect(after.length).toBe(before + 1);
    expect(after.at(-1)).toEqual({ type: WireType.CATCHUP_END, payload: { status: CATCHUP_STATUS.BUSY, nextSince: minute(t0) } });
    expect(r.server.activeSessions).toBe(1);
    // 別の相手は独立に始められる
    r.req(B, 0);
    expect(r.server.activeSessions).toBe(2);
  });

  it('終わった直後の再要求も、最短間隔 (5 秒) の間は BUSY。過ぎれば受け付ける', () => {
    r = rig();
    r.buffer.add(makePacket([1], t0 - MIN));
    const since = minute(t0 - 5 * MIN);
    r.req(A, since);
    r.req(A, since);
    expect(r.sent(A).at(-1)!.payload.status).toBe(CATCHUP_STATUS.BUSY);
    vi.advanceTimersByTime(CATCHUP_SERVER_LIMITS.MIN_INTERVAL_MS + 1);
    r.req(A, since);
    expect(r.sent(A).at(-1)!.payload.status).toBe(CATCHUP_STATUS.OK);
  });

  it('★1 相手あたりの帯域を絞る: バーストを超えた分は待ってから送る (全部は一気に出ない)', () => {
    r = rig({ perPeerBytesPerSec: 4096, perPeerBurstBytes: MAX_CATCHUP_FRAME_BYTES });
    for (let i = 0; i < 12; i++) r.buffer.add(big(i + 1, t0 - (20 - i) * MIN));
    r.req(A, 0);
    const dataCount = () => r.sent(A).filter(o => o.type === WireType.CATCHUP_DATA).length;
    expect(dataCount()).toBe(1); // バーストで 1 フレームだけ
    vi.advanceTimersByTime(1000);
    expect(dataCount()).toBe(1); // 2 フレーム目 (約 8KB) の分のトークンがまだ足りない
    expect(r.sent(A).some(o => o.type === WireType.CATCHUP_END)).toBe(false);
    vi.advanceTimersByTime(1500); // 計 2.5 秒: 2 フレーム目 (約 8KB) の不足分 4KB/s × 2 秒を超える
    expect(dataCount()).toBe(2);
    expect(r.sent(A).at(-1)!.type).toBe(WireType.CATCHUP_END);
    expect(r.server.activeSessions).toBe(0);
  });

  it('全相手の合計も絞る (2 人が同時に頼んでも、合計の帯域を超えない)', () => {
    r = rig({ globalBytesPerSec: 8192, globalBurstBytes: MAX_CATCHUP_FRAME_BYTES });
    for (let i = 0; i < 12; i++) r.buffer.add(big(i + 1, t0 - (20 - i) * MIN));
    r.req(A, 0);
    r.req(B, 0);
    const frames = () => r.sent().filter(o => o.type === WireType.CATCHUP_DATA).length;
    expect(frames()).toBe(1); // 合計のバーストは 1 フレーム分
    vi.advanceTimersByTime(60_000);
    expect(frames()).toBe(4); // 2 人 × 2 フレーム
    expect(r.server.activeSessions).toBe(0);
  });

  it('既定の帯域は 1 相手 256KiB/秒・バースト 1MiB、全体 4MiB/秒', () => {
    expect(CATCHUP_SERVER_LIMITS.PER_PEER_BYTES_PER_SEC).toBe(256 * 1024);
    expect(CATCHUP_SERVER_LIMITS.PER_PEER_BURST_BYTES).toBe(1024 * 1024);
    expect(CATCHUP_SERVER_LIMITS.GLOBAL_BYTES_PER_SEC).toBe(4 * 1024 * 1024);
  });

  it('途中で切断されたら、その相手への送出は止まりタイマーも残らない', () => {
    r = rig({ perPeerBytesPerSec: 1000, perPeerBurstBytes: MAX_CATCHUP_FRAME_BYTES });
    for (let i = 0; i < 12; i++) r.buffer.add(big(i + 1, t0 - (20 - i) * MIN));
    r.req(A, 0);
    expect(vi.getTimerCount()).toBe(1);
    r.pm.peers.delete(A);
    r.pm.emit('peer:disconnect', A);
    expect(r.server.activeSessions).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
    const n = r.sent(A).length;
    vi.advanceTimersByTime(60_000);
    expect(r.sent(A).length).toBe(n);
  });

  it('不正な since・未検証の相手・未接続の相手には何も送らない', () => {
    r = rig();
    r.buffer.add(makePacket([1], t0));
    r.pm.peers.set('c'.repeat(32), { peerId: 'c'.repeat(32), isConnected: true, isVerified: false });
    r.pm.peers.set('d'.repeat(32), { peerId: 'd'.repeat(32), isConnected: false, isVerified: true });
    for (const since of [-1, 0x1000000, 1.5, NaN, '1' as any, undefined as any]) r.req(A, since);
    r.req('c'.repeat(32), 0);
    r.req('d'.repeat(32), 0);
    r.req('e'.repeat(32), 0); // 知らない相手
    expect(r.pm.sendMessage).not.toHaveBeenCalled();
  });

  it('destroy 後は要求に応えない', () => {
    r = rig();
    r.server.destroy();
    r.req(A, 0);
    expect(r.pm.sendMessage).not.toHaveBeenCalled();
  });
});

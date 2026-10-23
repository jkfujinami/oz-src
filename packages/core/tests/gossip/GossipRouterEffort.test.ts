import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest';
import { sodiumReady } from '../../src/crypto/sodium';
import { GossipRouter } from '../../src/network/gossip/GossipRouter';
import { DandelionRouter } from '../../src/network/gossip/DandelionRouter';
import { MessageDispatcher } from '../../src/network/MessageDispatcher';
import { WireType } from '../../src/network/wire/WireTypes';
import { RELAY_QUEUE } from '../../src/network/gossip/RelayQueue';
import { effortFromExp } from '../../src/crypto/PowPolicy';
import { makeCheapPacket } from '../helpers/cheapPow';

vi.mock('../../src/crypto/PowPolicy', async (orig) => (await import('../helpers/cheapPowMock')).cheapPowPolicyFactory(orig as any));

const ME = 'f'.repeat(32);
const A = 'a'.repeat(32);
const B = 'b'.repeat(32);

function setup() {
  const sent: Array<{ to: string; packet: any }> = [];
  const peers = new Map<string, any>([
    [A, { peerId: A, isConnected: true, isVerified: true }],
    [B, { peerId: B, isConnected: true, isVerified: true }],
  ]);
  const pm: any = {
    myPeerId: ME, myPosition: 0, peers, get degree() { return peers.size; },
    sendMessage: (to: string, _t: number, payload: any) => sent.push({ to, packet: payload.packet }),
    on: vi.fn(), off: vi.fn(),
  };
  const circuit: any = { onExit: vi.fn(), send: vi.fn().mockResolvedValue(true) };
  const dispatcher = new MessageDispatcher();
  const router = new GossipRouter(pm, dispatcher, new DandelionRouter(pm), circuit);
  const delivered: any[] = [];
  router.onMessage(p => delivered.push(p));
  let n = 0;
  // ペイロードごとに id が変わる。effort_exp は id に入らないので後から上書きできる
  const next = (exp = 0) => ({ ...makeCheapPacket([n++ & 255, n >> 8, 7, 7]), effort_exp: exp });
  const recv = (p: any) => dispatcher.dispatch(A, WireType.GOSSIP, { packet: p });
  return { router, sent, delivered, next, recv };
}

describe('GossipRouter: 推奨 effort と中継キュー (A3)', () => {
  beforeAll(async () => { await sodiumReady; });
  beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-15T00:00:00Z')); });
  afterEach(() => { vi.useRealTimers(); });

  it('平常時: 即座に中継され、推奨は最小', () => {
    const t = setup();
    const p = t.next();
    t.recv(p);
    expect(t.sent.map(s => s.to)).toEqual([B]); // 同じ呼び出しの中で出る
    expect(t.router.suggestedEffortPerCell()).toBe(1);
    t.router.destroy();
  });

  it('洪水: ローカル配信は遅れず、中継だけが予算で絞られ、推奨が上がる', () => {
    const t = setup();
    const total = 2000; // 10 秒 (予算の窓の下限 60 秒 × 20 = 1,200 セルを超える)
    for (let i = 0; i < total; i++) { t.recv(t.next(0)); vi.advanceTimersByTime(5); } // 200 セル/秒
    expect(t.delivered.length).toBe(total);               // UI へは全部すぐ
    expect(t.sent.length).toBeLessThan(total);            // 中継は予算に絞られる
    expect(t.router.relayQueueStats().queued).toBeGreaterThan(0);
    expect(t.router.suggestedEffortPerCell()).toBeGreaterThan(effortFromExp(0));
    expect(t.router.suggestedEffortFor(3)).toBeGreaterThanOrEqual(4);
    t.router.destroy();
  });

  it('洪水の中でも、高 effort の投稿は待ち行列を追い越して先に中継される', () => {
    const t = setup();
    for (let i = 0; i < RELAY_QUEUE.BURST_CELLS + 300; i++) t.recv(t.next(0)); // バーストを使い切って行列を作る
    const good = t.next(12);
    t.recv(good);
    const before = t.sent.length;
    vi.advanceTimersByTime(100); // 40 セル/秒 × 0.1 秒 ≒ 4 セル
    const out = t.sent.slice(before).map(s => s.packet.packet_id);
    expect(out[0]).toBe(good.packet_id);
    t.router.destroy();
  });

  it('自分の発信も数える (broadcast)、追いつきは数えない', async () => {
    const t = setup();
    await t.router.broadcast(t.next(0));
    expect((t.router as any).advisor.size()).toBe(1);
    t.router.deliverCatchup(t.next(0));
    expect((t.router as any).advisor.size()).toBe(1);
    t.router.destroy();
  });
});

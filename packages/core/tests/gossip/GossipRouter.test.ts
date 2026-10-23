import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest';
import { sodiumReady } from '../../src/crypto/sodium';
import { GossipRouter } from '../../src/network/gossip/GossipRouter';
import { RecentBuffer } from '../../src/network/history/RecentBuffer';
import { DandelionRouter } from '../../src/network/gossip/DandelionRouter';
import { MessageDispatcher } from '../../src/network/MessageDispatcher';
import { WireType } from '../../src/network/wire/WireTypes';
import { POW_POLICY } from '../../src/crypto/PowPolicy';
import type { GossipPacket } from '../../src/types';
import { makePacket } from '../helpers/onionNet';

const ME = 'f'.repeat(32);
const A = 'a'.repeat(32);
const B = 'b'.repeat(32);
const C = 'c'.repeat(32);
const D = 'd'.repeat(32);

interface Harness {
  router: GossipRouter;
  dispatcher: MessageDispatcher;
  dandelion: DandelionRouter;
  pm: any;
  circuit: any;
  buffer: RecentBuffer;
  delivered: GossipPacket[];
  sent: Array<{ to: string; type: number; payload: any }>;
  exit: (payload: any) => void;
}

function harness(opts: { circuitResult?: boolean } = {}): Harness {
  const peers = new Map<string, any>([
    [A, { peerId: A, isConnected: true, isVerified: true }],
    [B, { peerId: B, isConnected: true, isVerified: true }],
    // 未検証・切断済みの隣人には中継しない
    [C, { peerId: C, isConnected: true, isVerified: false }],
    [D, { peerId: D, isConnected: false, isVerified: true }],
  ]);
  const sent: Harness['sent'] = [];
  const pm: any = {
    myPeerId: ME,
    myPosition: 0,
    peers,
    get degree() { return peers.size; },
    sendMessage: vi.fn((to: string, type: number, payload: any) => sent.push({ to, type, payload })),
    on: vi.fn(),
    off: vi.fn(),
  };
  let exitHandler: ((payload: any, from: string) => void) | null = null;
  const circuit: any = {
    onExit: vi.fn((type: string, h: any) => {
      if (type === 'exit_fluff') exitHandler = h;
    }),
    send: vi.fn().mockResolvedValue(opts.circuitResult ?? true),
  };
  const buffer = RecentBuffer.forRole('client');
  const dispatcher = new MessageDispatcher();
  const dandelion = new DandelionRouter(pm);
  const router = new GossipRouter(pm, dispatcher, dandelion, circuit, buffer);
  const delivered: GossipPacket[] = [];
  router.onMessage(p => delivered.push(p));
  return {
    router, dispatcher, dandelion, pm, circuit, buffer, delivered, sent,
    exit: (payload: any) => exitHandler!(payload, A),
  };
}

const gossipFrom = (h: Harness, from: string, packet: any) =>
  h.dispatcher.dispatch(from, WireType.GOSSIP, { packet });

describe('GossipRouter: 受信と中継 (Broadcast Veil)', () => {
  let h: Harness;

  beforeAll(async () => {
    await sodiumReady;
  });
  beforeEach(() => {
    h = harness();
  });
  afterEach(() => {
    h.router.destroy();
    vi.useRealTimers();
  });

  it('正当な GOSSIP は送り主以外の「接続中かつ検証済み」の隣人全員へ中継される', () => {
    const p = makePacket([1, 2, 3]);
    gossipFrom(h, A, p);

    const targets = h.sent.filter(s => s.type === WireType.GOSSIP).map(s => s.to);
    expect(targets).toEqual([B]); // A (送り主), C (未検証), D (切断) には送らない
    expect(h.delivered.map(d => d.packet_id)).toEqual([p.packet_id]);
  });

  it('中継パケットは hop_count を持たない (出口の位置を漏らさない。フィールド自体が無い)', () => {
    const p = makePacket([9]);
    gossipFrom(h, A, p);

    const relayed = h.sent.find(s => s.type === WireType.GOSSIP)!;
    expect('hop_count' in relayed.payload.packet).toBe(false);
    // 他のフィールドは書き換えない (CHK が壊れない)
    expect(relayed.payload.packet.packet_id).toBe(p.packet_id);
    expect(relayed.payload.packet.payload).toEqual(p.payload);
  });

  it('同じパケットを複数の隣人から受けても、中継も UI 配信も 1 回だけ', () => {
    const p = makePacket([5, 5]);
    gossipFrom(h, A, p);
    gossipFrom(h, B, p);
    gossipFrom(h, A, p);

    expect(h.sent.filter(s => s.type === WireType.GOSSIP)).toHaveLength(1);
    expect(h.delivered).toHaveLength(1);
  });

  describe('検証に通らないパケットは中継もエコーもしない', () => {
    const cases: Array<[string, (p: GossipPacket) => any]> = [
      ['packet_id が CHK と一致しない', p => ({ ...p, packet_id: 'ab'.repeat(32) })],
      ['ヘッダの tag を改竄 (packet_id 破れ)', p => ({ ...p, tag: p.tag + 1 })],
      ['tag が 12 ビットに収まらない', p => ({ ...p, tag: 4096 })],
      ['age が 90 日を超える', p => ({ ...p, age: 91 })],
      ['effort の指数が範囲外', p => ({ ...p, effort_exp: 81 })],
      ['effort を高く名乗り直す (解は流用できない)', p => ({ ...p, effort_exp: 8 })],
      ['payload が空', p => ({ ...p, payload: new Uint8Array(0) })],
      ['payload が上限超え', p => ({ ...p, payload: new Uint8Array(POW_POLICY.MAX_PAYLOAD_SIZE + 1) })],
      ['Equi-X の解の長さが違う', p => ({ ...p, pow_solution: new Uint8Array(5) })],
      ['pow_nonce が負', p => ({ ...p, pow_nonce: -1 })],
      ['packet 自体が無い', () => undefined],
      ['packet が文字列', () => 'garbage'],
    ];
    for (const [name, mutate] of cases) {
      it(name, async () => {
        const p = makePacket([3, 1, 4]);
        const bad = mutate(p);
        const echo = h.dandelion.awaitEcho(p.packet_id, 10);
        expect(() => gossipFrom(h, A, bad)).not.toThrow();
        expect(h.sent).toHaveLength(0);
        expect(h.delivered).toHaveLength(0);
        expect(await echo).toBe(false);
      });
    }

    it('15 分より古いパケットは拒否する (リプレイの打ち切り)', () => {
      const p = makePacket([7, 7]);
      vi.useFakeTimers({ toFake: ['Date'] });
      vi.setSystemTime(Date.now() + POW_POLICY.MAX_TIME_DRIFT + 60_000);
      gossipFrom(h, A, p);
      expect(h.sent).toHaveLength(0);
      expect(h.delivered).toHaveLength(0);
    });

    it('15 分より先の未来日付のパケットは拒否する', () => {
      const p = makePacket([7, 8]);
      vi.useFakeTimers({ toFake: ['Date'] });
      // ★ パケットの時刻は分単位に切り捨てられ (最大 59.9 秒戻る)、さらに PoW の計算時間ぶん今より古い。
      //   余裕が 1 分だと、まれに 15 分の内側に入って受理された。2 分あける
      vi.setSystemTime(Date.now() - POW_POLICY.MAX_TIME_DRIFT - 2 * 60_000);
      gossipFrom(h, A, p);
      expect(h.sent).toHaveLength(0);
    });
  });

  it('正当な GOSSIP の到着は自分の発信のエコーとして通知される', async () => {
    const p = makePacket([2, 2]);
    const echo = h.dandelion.awaitEcho(p.packet_id, 10_000);
    gossipFrom(h, B, p);
    expect(await echo).toBe(true);
  });

  it('offMessage したリスナーには配信しない', () => {
    const extra: GossipPacket[] = [];
    const listener = (p: GossipPacket) => extra.push(p);
    h.router.onMessage(listener);
    h.router.offMessage(listener);
    gossipFrom(h, A, makePacket([6]));
    expect(extra).toHaveLength(0);
    expect(h.delivered).toHaveLength(1);
  });
});

describe('GossipRouter: 自己発信 (Fail-Closed)', () => {
  let h: Harness;

  beforeAll(async () => {
    await sodiumReady;
  });
  afterEach(() => h.router.destroy());

  it('broadcast は先に自分の UI へ渡し、回路に exit_fluff として載せる。平文は送らない', async () => {
    h = harness();
    const p = makePacket([1, 1]);

    expect(await h.router.broadcast(p)).toBe(true);

    expect(h.delivered.map(x => x.packet_id)).toEqual([p.packet_id]);
    expect(h.circuit.send).toHaveBeenCalledTimes(1);
    const [payload, echoId] = h.circuit.send.mock.calls[0];
    expect(payload).toEqual({ type: 'exit_fluff', packet: p });
    expect(echoId).toBe(p.packet_id);
    expect(h.pm.sendMessage).not.toHaveBeenCalled();
  });

  it('自分の発信は直近の入れ物にも入る (Guard の追いつきで他人に配れる)', async () => {
    h = harness();
    const p = makePacket([1, 8]);
    await h.router.broadcast(p);
    expect(h.buffer.has(p.packet_id)).toBe(true);
  });

  it('自分の UI には必ず見える', async () => {
    h = harness();
    const p = makePacket([1, 9]);
    await h.router.broadcast(p);
    expect(h.delivered).toHaveLength(1);
  });

  it('回路で届かなかったら false を返し、平文の GOSSIP には落ちない', async () => {
    h = harness({ circuitResult: false });
    const p = makePacket([2, 9]);
    expect(await h.router.broadcast(p)).toBe(false);
    expect(h.pm.sendMessage).not.toHaveBeenCalled();
  });

  it('自分の発信が網から戻ってきたとき、UI には二重に出さないが中継はする (小規模網の Stem ループ対策)', async () => {
    h = harness();
    const p = makePacket([3, 9]);
    await h.router.broadcast(p);
    expect(h.delivered).toHaveLength(1);

    gossipFrom(h, A, p);

    expect(h.delivered).toHaveLength(1);
    expect(h.sent.filter(s => s.type === WireType.GOSSIP).map(s => s.to)).toEqual([B]);
  });
});

describe('GossipRouter: 出口としての Fluff', () => {
  let h: Harness;

  beforeAll(async () => {
    await sodiumReady;
  });
  beforeEach(() => {
    h = harness();
  });
  afterEach(() => h.router.destroy());

  it('exit_fluff を受けた出口は、エコーを通知し、UI に渡し、全隣人へ Fluff する', async () => {
    const p = makePacket([4, 2]);
    const echo = h.dandelion.awaitEcho(p.packet_id, 10_000);
    h.exit({ type: 'exit_fluff', packet: p });

    expect(await echo).toBe(true);
    expect(h.delivered).toHaveLength(1);
    // 出口は送り主が居ないので、検証済みで接続中の隣人全員へ
    expect(h.sent.filter(s => s.type === WireType.GOSSIP).map(s => s.to).sort()).toEqual([A, B]);
  });

  it('出口に届いた不正なパケットは Fluff しない', () => {
    const p = makePacket([4, 3]);
    h.exit({ type: 'exit_fluff', packet: { ...p, timestamp: p.timestamp + 60_000 } });
    expect(h.sent).toHaveLength(0);
    expect(h.delivered).toHaveLength(0);
  });

  it('同じパケットが出口と GOSSIP の両方から来ても、Fluff は 1 回だけ', () => {
    const p = makePacket([4, 4]);
    h.exit({ type: 'exit_fluff', packet: p });
    gossipFrom(h, A, p);
    expect(h.sent.filter(s => s.type === WireType.GOSSIP)).toHaveLength(2); // A と B へ 1 回ずつ
    expect(h.delivered).toHaveLength(1);
  });
});

describe('GossipRouter: 後始末', () => {
  it('destroy() で重複排除キャッシュのタイマーが残らない', async () => {
    await sodiumReady;
    vi.useFakeTimers();
    try {
      const h = harness();
      expect(vi.getTimerCount()).toBeGreaterThan(0);
      h.router.destroy();
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('GossipRouter: 追いつき (deliverCatchup)', () => {
  let h: Harness;
  beforeAll(async () => {
    await sodiumReady;
  });
  beforeEach(() => {
    h = harness();
  });
  afterEach(() => h.router.destroy());

  it('★追いつきの投稿は読み手と保管候補へ渡すが、誰にも中継 (flood) しない', () => {
    const p = makePacket([5, 1]);
    const cands: Array<[string, string]> = [];
    h.router.onStoredCandidate((x, src) => cands.push([x.packet_id, src]));
    expect(h.router.deliverCatchup(p)).toBe(true);
    expect(h.delivered.map(d => d.packet_id)).toEqual([p.packet_id]);
    expect(cands).toEqual([[p.packet_id, 'catchup']]);
    expect(h.sent).toHaveLength(0);
    expect(h.circuit.send).not.toHaveBeenCalled();
    expect(h.buffer.has(p.packet_id)).toBe(true);
  });

  it('既に配った投稿 (live で受けた分) は重複として false。保管候補にも二重に出さない', () => {
    const p = makePacket([5, 2]);
    const cands: string[] = [];
    h.router.onStoredCandidate(x => cands.push(x.packet_id));
    gossipFrom(h, A, p);
    expect(h.router.deliverCatchup(p)).toBe(false);
    expect(h.delivered).toHaveLength(1);
    expect(cands).toEqual([p.packet_id]);
  });

  it('SeenCache が忘れた後でも、入れ物に残っている間は重複を弾く', () => {
    const p = makePacket([5, 3]);
    h.buffer.add(p);
    expect(h.router.deliverCatchup(p)).toBe(false);
  });

  it('追いつきで先に届いた投稿が、あとで live で届いても UI へは二重に出ない', () => {
    const p = makePacket([5, 4]);
    h.router.deliverCatchup(p);
    gossipFrom(h, A, p);
    expect(h.delivered).toHaveLength(1);
  });

  it('recentPackets は入れ物の中身を返す', () => {
    const p = makePacket([5, 5]);
    h.router.deliverCatchup(p);
    expect(h.router.recentPackets().map(x => x.packet_id)).toEqual([p.packet_id]);
  });
});

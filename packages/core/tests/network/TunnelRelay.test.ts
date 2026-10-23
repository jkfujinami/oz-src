import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest';
import { sodiumReady } from '../../src/crypto/sodium';
import { WireType } from '../../src/network/wire/WireTypes';
import { TUNNEL_ERROR_CODE } from '../../src/network/wire/WireCodec';
import { TunnelRelay, TUNNEL_LIMITS, type TunnelRelayOptions } from '../../src/network/tunnel/TunnelRelay';
import { FakeNetworkPeerManager, newDispatcher, pid } from '../helpers/fakeNetworkPeerManager';
import type { MessageDispatcher } from '../../src/network/MessageDispatcher';

beforeAll(async () => { await sodiumReady; });

/**
 * 中継の部品だけ (WireCodec・PeerManager は通さない) を、決定的なメッセージの束 (bus) でつないだ試験。
 * 配布は flush() で FIFO に流す。各ノードが受け取った (from, type, payload) を記録する。
 */
class Bus {
  nodes = new Map<string, Node>();
  queue: Array<() => void> = [];
  flush(): void {
    while (this.queue.length) this.queue.shift()!();
  }
}

class Node {
  readonly pm: FakeNetworkPeerManager;
  readonly dispatcher: MessageDispatcher = newDispatcher();
  readonly inbox: Array<{ from: string; type: number; payload: any }> = [];
  relay: TunnelRelay | null = null;

  constructor(readonly bus: Bus, readonly id: string) {
    this.pm = new FakeNetworkPeerManager(id);
    const send = this.pm.sendMessage.bind(this.pm);
    this.pm.sendMessage = (to, type, payload) => {
      send(to, type, payload);
      bus.queue.push(() => {
        const target = bus.nodes.get(to);
        if (!target || !this.pm.peers.get(to)?.isConnected) return;
        target.inbox.push({ from: id, type, payload });
        target.dispatcher.dispatch(id, type, payload);
      });
    };
    bus.nodes.set(id, this);
  }

  attach(opts: TunnelRelayOptions = {}): this {
    this.relay = new TunnelRelay(this.pm, this.dispatcher, opts);
    return this;
  }

  link(other: Node): void {
    this.pm.addPeer(other.id);
    other.pm.addPeer(this.id);
  }

  unlink(other: Node): void {
    this.pm._peers.delete(other.id);
    other.pm._peers.delete(this.id);
    this.pm.emit('peer:disconnect', other.id);
    other.pm.emit('peer:disconnect', this.id);
  }

  /** このノードから to へ、フレームを 1 つ送る */
  send(to: string, type: WireType, payload: any): void {
    this.pm.sendMessage(to, type, payload);
  }

  got(type: number, from?: string) {
    return this.inbox.filter(m => m.type === type && (from === undefined || m.from === from));
  }
}

const TID = new Uint8Array(8).fill(7);
const TID2 = new Uint8Array(8).fill(8);
const body = (n = 40, v = 1) => new Uint8Array(n).fill(v);

const R = pid(0xaa01);
const G1 = pid(0xbb01);
const G2 = pid(0xbb02);
const H = pid(0xcc01);

let bus: Bus;
const relays: TunnelRelay[] = [];
beforeEach(() => { bus = new Bus(); });
afterEach(() => { for (const r of relays.splice(0)) r.destroy(); });

function node(id: string, opts?: TunnelRelayOptions): Node {
  const n = new Node(bus, id);
  if (opts) { n.attach(opts); relays.push(n.relay!); }
  return n;
}

/** R ─ G1 ─ G2 ─ H (H が G2 の受け口に登録済み) */
function chain(opts: { g?: TunnelRelayOptions } = {}) {
  const r = node(R);
  const g1 = node(G1, { role: 'guard', isBackbone: (p) => p === G2, ...opts.g });
  const g2 = node(G2, { role: 'guard', isBackbone: (p) => p === G1, ...opts.g });
  const h = node(H);
  r.link(g1); g1.link(g2); g2.link(h);
  h.send(G2, WireType.TUNNEL_REGISTER, { tunnelId: TID });
  bus.flush();
  expect(h.got(WireType.TUNNEL_REGISTERED)[0].payload.ok).toBe(true);
  return { r, g1, g2, h };
}

const sendReq = (r: Node, to: string, gateway: string, reqId = 1234, b = body(), tunnelId = TID) => {
  r.send(to, WireType.TUNNEL_SEND, { reqId, gateway, tunnelId, body: b });
  bus.flush();
};

describe('TunnelRelay: 登録 (TUNNEL_REGISTER)', () => {
  it('★登録すると REGISTERED{ok}。同じ接続の再登録は冪等。切れたら消える', () => {
    const g = node(G1, { role: 'guard' });
    const h = node(H);
    h.link(g);
    h.send(G1, WireType.TUNNEL_REGISTER, { tunnelId: TID });
    bus.flush();
    expect(h.got(WireType.TUNNEL_REGISTERED).map(m => m.payload.ok)).toEqual([true]);
    expect(g.relay!.tunnelHolder(TID)).toBe(H);
    h.send(G1, WireType.TUNNEL_REGISTER, { tunnelId: TID });
    bus.flush();
    expect(h.got(WireType.TUNNEL_REGISTERED).map(m => m.payload.ok)).toEqual([true, true]);
    expect(g.relay!.tunnelCount).toBe(1);
    g.unlink(h);
    expect(g.relay!.tunnelCount).toBe(0);
    expect(g.relay!.tunnelHolder(TID)).toBeUndefined();
  });

  it('★1 つの接続が登録できる tunnelId は上限 (既定 4)。それ以上は ok=false。別の接続は影響を受けない', () => {
    expect(TUNNEL_LIMITS.MAX_TUNNELS_PER_PEER).toBe(4);
    let t = 100_000;
    const g = node(G1, { role: 'guard', now: () => t });
    const h = node(H);
    const h2 = node(pid(0xcc02));
    h.link(g); h2.link(g);
    for (let i = 0; i < 6; i++) {
      h.send(G1, WireType.TUNNEL_REGISTER, { tunnelId: new Uint8Array(8).fill(i + 1) });
      bus.flush();
      t += 3000; // 登録の頻度の枠 (0.5/秒) には掛からない間隔
    }
    expect(h.got(WireType.TUNNEL_REGISTERED).map(m => m.payload.ok)).toEqual([true, true, true, true, false, false]);
    h2.send(G1, WireType.TUNNEL_REGISTER, { tunnelId: new Uint8Array(8).fill(99) });
    bus.flush();
    expect(h2.got(WireType.TUNNEL_REGISTERED)[0].payload.ok).toBe(true);
    expect(g.relay!.tunnelCount).toBe(5);
  });

  it('★先着: 生きている別の接続が持つ tunnelId は奪えない。持ち主が切れれば登録できる', () => {
    const g = node(G1, { role: 'guard' });
    const h = node(H);
    const squatter = node(pid(0xdd01));
    h.link(g); squatter.link(g);
    h.send(G1, WireType.TUNNEL_REGISTER, { tunnelId: TID });
    bus.flush();
    squatter.send(G1, WireType.TUNNEL_REGISTER, { tunnelId: TID });
    bus.flush();
    expect(squatter.got(WireType.TUNNEL_REGISTERED)[0].payload.ok).toBe(false);
    expect(g.relay!.tunnelHolder(TID)).toBe(H);
    g.unlink(h);
    squatter.send(G1, WireType.TUNNEL_REGISTER, { tunnelId: TID });
    bus.flush();
    expect(squatter.got(WireType.TUNNEL_REGISTERED)[1].payload.ok).toBe(true);
  });

  it('登録の頻度は相手ごとに絞る (連打は捨てる)。不正な tunnelId の長さは無視する', () => {
    const g = node(G1, { role: 'guard' });
    const h = node(H);
    h.link(g);
    for (let i = 0; i < 20; i++) h.send(G1, WireType.TUNNEL_REGISTER, { tunnelId: TID });
    h.send(G1, WireType.TUNNEL_REGISTER, { tunnelId: new Uint8Array(3) });
    bus.flush();
    expect(h.got(WireType.TUNNEL_REGISTERED).length).toBe(TUNNEL_LIMITS.REGISTER.burst);
  });

  it('一般ノード (受け口の役) は登録の総数が少ない', () => {
    const c = node(G1, { role: 'client', limits: { maxTunnelsPerPeer: 100 } });
    const peers = Array.from({ length: 70 }, (_, i) => node(pid(0x1000 + i)));
    peers.forEach(p => p.link(c));
    peers.forEach(p => p.send(G1, WireType.TUNNEL_REGISTER, { tunnelId: new Uint8Array(8).fill(p.id.charCodeAt(31)) }));
    bus.flush();
    expect(c.relay!.tunnelCount).toBeLessThanOrEqual(TUNNEL_LIMITS.MAX_TUNNELS.client);
  });
});

describe('TunnelRelay: 要求と応答の経路 (R → G_R → G_h → H → G_h → G_R → R)', () => {
  it('★往復する。各ホップが振り直したタグで中継し、H が見る fromHop は H のすぐ前のホップ (G_h の相手 G_R) だけ。R の id は G_R より先へ出ない', () => {
    const { r, g1, g2, h } = chain();
    sendReq(r, G1, G2, 0x11111111);
    // 要求が H に届く: fromHop は G1 (R ではない)
    const d = h.got(WireType.TUNNEL_DELIVER)[0];
    expect(d.from).toBe(G2);
    expect(d.payload.fromHop).toBe(G1);
    expect(Array.from(d.payload.body)).toEqual(Array.from(body()));
    // G2 が見るのは G1 だけ。R の id (peerId・reqId) はどのフレームにも現れない
    expect(g2.inbox.every(m => m.from === G1 || m.from === H)).toBe(true);
    expect(JSON.stringify([...g2.inbox, ...h.inbox], (_k, v) => (v instanceof Uint8Array ? Array.from(v) : v))).not.toContain(R);
    const fwd = g2.got(WireType.TUNNEL_FWD)[0];
    expect(fwd.payload.returnTag).not.toBe(0x11111111); // G1 が振り直したタグ
    expect(d.payload.returnTag).not.toBe(fwd.payload.returnTag); // G2 も振り直した
    expect(g1.relay!.upstreamCount).toBe(1);
    expect(g2.relay!.downstreamCount).toBe(1);

    // 応答 3 片 (最後に final)
    for (let seq = 0; seq < 3; seq++) {
      h.send(G2, WireType.TUNNEL_REPLY, { returnTag: d.payload.returnTag, toHop: d.payload.fromHop, seq, final: seq === 2, body: body(30, seq + 1) });
    }
    bus.flush();
    const res = r.got(WireType.TUNNEL_RESULT);
    expect(res.map(m => m.payload.seq)).toEqual([0, 1, 2]);
    expect(res.map(m => m.payload.final)).toEqual([false, false, true]);
    expect(res.every(m => m.payload.reqId === 0x11111111 && m.from === G1)).toBe(true);
    expect(Array.from(res[1].payload.body)).toEqual(Array.from(body(30, 2)));
    // ★final で全部の状態が消える
    expect(g1.relay!.routeCount).toBe(0);
    expect(g2.relay!.routeCount).toBe(0);
  });

  it('★G_R が受け口そのもの (G_R = G_h) なら FWD / RET を経由せず直接つなぐ。H が見る fromHop は G 自身 (R の id は渡らない)', () => {
    const r = node(R);
    const g = node(G1, { role: 'guard' });
    const h = node(H);
    r.link(g); g.link(h);
    h.send(G1, WireType.TUNNEL_REGISTER, { tunnelId: TID });
    bus.flush();
    sendReq(r, G1, G1, 77);
    const d = h.got(WireType.TUNNEL_DELIVER)[0];
    expect(d.payload.fromHop).toBe(G1);
    expect(g.got(WireType.TUNNEL_FWD)).toHaveLength(0);
    h.send(G1, WireType.TUNNEL_REPLY, { returnTag: d.payload.returnTag, toHop: G1, seq: 0, final: true, body: body(20) });
    bus.flush();
    expect(r.got(WireType.TUNNEL_RESULT).map(m => [m.payload.reqId, m.payload.final])).toEqual([[77, true]]);
    expect(g.relay!.routeCount).toBe(0);
    expect(JSON.stringify(h.inbox.map(m => m.payload), (_k, v) => (v instanceof Uint8Array ? Array.from(v) : v))).not.toContain(R);
  });

  it('★本体 (body) は中継で一切変わらない (不透明)。同時に複数の要求が混ざらない', () => {
    const { r, h } = chain();
    const r2 = node(pid(0xaa02));
    r2.link(bus.nodes.get(G1)!);
    sendReq(r, G1, G2, 1, body(50, 0xa1));
    r2.send(G1, WireType.TUNNEL_SEND, { reqId: 1, gateway: G2, tunnelId: TID, body: body(60, 0xb2) }); // 同じ reqId でも別の要求
    bus.flush();
    const ds = h.got(WireType.TUNNEL_DELIVER);
    expect(ds).toHaveLength(2);
    for (const d of ds) h.send(G2, WireType.TUNNEL_REPLY, { returnTag: d.payload.returnTag, toHop: d.payload.fromHop, seq: 0, final: true, body: d.payload.body.slice(0, 5) });
    bus.flush();
    expect(Array.from(r.got(WireType.TUNNEL_RESULT)[0].payload.body)).toEqual([0xa1, 0xa1, 0xa1, 0xa1, 0xa1]);
    expect(Array.from(r2.got(WireType.TUNNEL_RESULT)[0].payload.body)).toEqual([0xb2, 0xb2, 0xb2, 0xb2, 0xb2]);
  });

  it('★登録されていない tunnelId・切れた保持者: NO_TUNNEL が R まで戻る。状態は残らない', () => {
    const { r, g1, g2, h } = chain();
    sendReq(r, G1, G2, 5, body(), TID2); // 未登録
    expect(r.got(WireType.TUNNEL_ERROR).map(m => [m.payload.id, m.payload.code])).toEqual([[5, TUNNEL_ERROR_CODE.NO_TUNNEL]]);
    expect(g1.relay!.routeCount + g2.relay!.routeCount).toBe(0);
    // 要求の途中で保持者が切れる
    sendReq(r, G1, G2, 6);
    expect(h.got(WireType.TUNNEL_DELIVER)).toHaveLength(1);
    g2.unlink(h);
    bus.flush();
    expect(r.got(WireType.TUNNEL_ERROR).at(-1)!.payload).toEqual({ id: 6, code: TUNNEL_ERROR_CODE.NO_TUNNEL });
    expect(g1.relay!.routeCount + g2.relay!.routeCount).toBe(0);
  });

  it('G_h との接続が切れたら NO_ROUTE が R へ戻る。R が切れたら状態を捨てる (返す先が無い)', () => {
    const { r, g1, g2 } = chain();
    sendReq(r, G1, G2, 8);
    g1.unlink(g2);
    bus.flush();
    expect(r.got(WireType.TUNNEL_ERROR).at(-1)!.payload).toEqual({ id: 8, code: TUNNEL_ERROR_CODE.NO_ROUTE });
    g1.link(g2);
    sendReq(r, G1, G2, 9);
    expect(g1.relay!.upstreamCount).toBe(1);
    g1.unlink(r);
    expect(g1.relay!.upstreamCount).toBe(0);
  });

  it('★保持者の ERROR (混雑・不正な要求) は R まで戻り、経路は消える', () => {
    const { r, g1, g2, h } = chain();
    sendReq(r, G1, G2, 3);
    const d = h.got(WireType.TUNNEL_DELIVER)[0];
    h.send(G2, WireType.TUNNEL_ERROR, { id: d.payload.returnTag, code: TUNNEL_ERROR_CODE.BUSY });
    bus.flush();
    expect(r.got(WireType.TUNNEL_ERROR).at(-1)!.payload).toEqual({ id: 3, code: TUNNEL_ERROR_CODE.BUSY });
    expect(g1.relay!.routeCount + g2.relay!.routeCount).toBe(0);
  });
});

describe('TunnelRelay: 偽の応答・重複を受け付けない', () => {
  it('★経路に紐づいた相手からだけ応答を受け付ける: 別の保持者の REPLY・toHop の食い違い・別の相手の RET は捨てる', () => {
    const { r, g1, g2, h } = chain();
    const evil = node(pid(0xee01));
    evil.link(g2);
    sendReq(r, G1, G2, 4);
    const d = h.got(WireType.TUNNEL_DELIVER)[0];
    const tag = d.payload.returnTag;
    evil.send(G2, WireType.TUNNEL_REPLY, { returnTag: tag, toHop: G1, seq: 0, final: true, body: body(10, 9) }); // 保持者ではない接続
    h.send(G2, WireType.TUNNEL_REPLY, { returnTag: tag, toHop: pid(0x1234), seq: 0, final: true, body: body(10, 9) }); // toHop が違う
    bus.flush();
    expect(r.got(WireType.TUNNEL_RESULT)).toHaveLength(0);
    expect(g2.relay!.stats.dropped.wrongPeer).toBe(2);
    // G1 が受け取る RET は、G2 (経路の相手) からだけ
    const evil2 = node(pid(0xee02));
    evil2.link(g1);
    const upTag = g2.got(WireType.TUNNEL_FWD)[0].payload.returnTag;
    evil2.send(G1, WireType.TUNNEL_RET, { returnTag: upTag, seq: 0, final: true, body: body(10, 7) });
    bus.flush();
    expect(r.got(WireType.TUNNEL_RESULT)).toHaveLength(0);
    expect(g1.relay!.stats.dropped.wrongPeer).toBe(1);
    // 本物は通る
    h.send(G2, WireType.TUNNEL_REPLY, { returnTag: tag, toHop: d.payload.fromHop, seq: 0, final: true, body: body(10, 1) });
    bus.flush();
    expect(r.got(WireType.TUNNEL_RESULT)).toHaveLength(1);
    // 知らないタグ・済んだ経路への再送は捨てる
    h.send(G2, WireType.TUNNEL_REPLY, { returnTag: tag, toHop: d.payload.fromHop, seq: 1, final: true, body: body(10, 1) });
    bus.flush();
    expect(r.got(WireType.TUNNEL_RESULT)).toHaveLength(1);
    expect(g2.relay!.stats.dropped.unknownRoute).toBe(1);
  });

  it('同じ前のホップの同じタグの FWD の再送 (リプレイ) は 2 度配らない', () => {
    const { h, g2 } = chain();
    const g1 = node(pid(0xbb09));
    g1.link(g2);
    for (let i = 0; i < 3; i++) g1.send(G2, WireType.TUNNEL_FWD, { returnTag: 555, tunnelId: TID, body: body() });
    bus.flush();
    expect(h.got(WireType.TUNNEL_DELIVER)).toHaveLength(1);
    expect(g2.relay!.stats.dropped.duplicate).toBe(2);
  });

  it('壊れたペイロード (型違い) は無視する', () => {
    const { r, g1 } = chain();
    r.send(G1, WireType.TUNNEL_SEND, { reqId: 'x', gateway: G2, tunnelId: TID, body: body() });
    r.send(G1, WireType.TUNNEL_SEND, { reqId: 1, gateway: G2, tunnelId: [1, 2], body: body() });
    r.send(G1, WireType.TUNNEL_SEND, { reqId: 1, gateway: G2, tunnelId: TID, body: null });
    bus.flush();
    expect(g1.relay!.routeCount).toBe(0);
    expect(r.got(WireType.TUNNEL_ERROR)).toHaveLength(0);
  });
});

describe('TunnelRelay: 状態は 60 秒で捨てる', () => {
  let t = 1_000_000;
  const now = () => t;
  beforeEach(() => { t = 1_000_000; });

  it('★無通信 60 秒の経路は sweep で消え、上流 (R・前のホップ) に TIMEOUT が戻る。通信があれば延びる', () => {
    const { r, g1, g2, h } = (() => {
      const r = node(R);
      const g1 = node(G1, { role: 'guard', isBackbone: (p) => p === G2, now });
      const g2 = node(G2, { role: 'guard', isBackbone: (p) => p === G1, now });
      const h = node(H);
      r.link(g1); g1.link(g2); g2.link(h);
      h.send(G2, WireType.TUNNEL_REGISTER, { tunnelId: TID });
      bus.flush();
      return { r, g1, g2, h };
    })();
    sendReq(r, G1, G2, 41);
    const d = h.got(WireType.TUNNEL_DELIVER)[0];
    expect(g1.relay!.routeCount + g2.relay!.routeCount).toBe(2);

    t += 59_000;
    h.send(G2, WireType.TUNNEL_REPLY, { returnTag: d.payload.returnTag, toHop: d.payload.fromHop, seq: 0, final: false, body: body(10) });
    bus.flush();
    t += 59_000; // 最後の片から 59 秒: まだ生きている
    expect(g1.relay!.sweep()).toBe(0);
    expect(g2.relay!.sweep()).toBe(0);
    t += 2_000; // 61 秒
    expect(g1.relay!.sweep()).toBe(1);
    expect(g2.relay!.sweep()).toBe(1);
    bus.flush();
    expect(g1.relay!.routeCount + g2.relay!.routeCount).toBe(0);
    expect(r.got(WireType.TUNNEL_ERROR).at(-1)!.payload).toEqual({ id: 41, code: TUNNEL_ERROR_CODE.TIMEOUT });
    // 遅れて来た応答は捨てる (状態が無い)
    h.send(G2, WireType.TUNNEL_REPLY, { returnTag: d.payload.returnTag, toHop: d.payload.fromHop, seq: 1, final: true, body: body(10) });
    bus.flush();
    expect(r.got(WireType.TUNNEL_RESULT)).toHaveLength(1);
  });

  it('掃除のタイマーが実際に回る (5 秒ごと)。ホップは終わった要求の状態を持ち越さない', () => {
    vi.useFakeTimers();
    try {
      const g = node(G1, { role: 'guard', now: () => Date.now() });
      const rr = node(R);
      const hh = node(H);
      rr.link(g); g.link(hh);
      hh.send(G1, WireType.TUNNEL_REGISTER, { tunnelId: TID });
      bus.flush();
      sendReq(rr, G1, G1, 1);
      expect(g.relay!.routeCount).toBe(2);
      vi.advanceTimersByTime(TUNNEL_LIMITS.ROUTE_IDLE_MS + TUNNEL_LIMITS.SWEEP_INTERVAL_MS + 100);
      expect(g.relay!.routeCount).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('TunnelRelay: 相手ごとの制限 (要求数・同時数・帯域・全体)', () => {
  it('★要求の頻度: 利用者 1 人は burst を超えると BUSY。時間が経てば戻る (C4: 利用者の上り枠 clientSend)', () => {
    let t = 5_000_000;
    const { r } = (() => {
      const r = node(R);
      const g = node(G1, { role: 'guard', now: () => t, limits: { clientSend: { reqPerSec: 2, reqBurst: 6, concurrent: 1000 } } });
      const h = node(H);
      r.link(g); g.link(h);
      h.send(G1, WireType.TUNNEL_REGISTER, { tunnelId: TID });
      bus.flush();
      return { r };
    })();
    for (let i = 0; i < 10; i++) r.send(G1, WireType.TUNNEL_SEND, { reqId: i + 1, gateway: G1, tunnelId: TID, body: body() });
    bus.flush();
    const busy = r.got(WireType.TUNNEL_ERROR).filter(m => m.payload.code === TUNNEL_ERROR_CODE.BUSY);
    expect(busy.map(m => m.payload.id)).toEqual([7, 8, 9, 10]);
    t += 1000; // 1 秒で 2 件回復
    for (let i = 20; i < 24; i++) r.send(G1, WireType.TUNNEL_SEND, { reqId: i, gateway: G1, tunnelId: TID, body: body() });
    bus.flush();
    const busy2 = r.got(WireType.TUNNEL_ERROR).filter(m => m.payload.code === TUNNEL_ERROR_CODE.BUSY).map(m => m.payload.id);
    expect(busy2).toEqual([7, 8, 9, 10, 22, 23]);
  });

  it('★同時数: 応答待ちの要求が上限 (利用者 32) に達したら新しい要求は BUSY。終われば入れる', () => {
    const { r, g1, g2, h } = chain({ g: { limits: { clientSend: { reqPerSec: 1000, reqBurst: 1000 } } } });
    const limit = TUNNEL_LIMITS.CLIENT_SEND.concurrent;
    for (let i = 0; i < limit + 2; i++) r.send(G1, WireType.TUNNEL_SEND, { reqId: 100 + i, gateway: G2, tunnelId: TID, body: body() });
    bus.flush();
    expect(h.got(WireType.TUNNEL_DELIVER)).toHaveLength(limit);
    expect(r.got(WireType.TUNNEL_ERROR).filter(m => m.payload.code === TUNNEL_ERROR_CODE.BUSY)).toHaveLength(2);
    expect(g1.relay!.stats.dropped.concurrent).toBe(2);
    // 1 件終える
    const d = h.got(WireType.TUNNEL_DELIVER)[0];
    h.send(G2, WireType.TUNNEL_REPLY, { returnTag: d.payload.returnTag, toHop: d.payload.fromHop, seq: 0, final: true, body: body(10) });
    bus.flush();
    sendReq(r, G1, G2, 999);
    expect(h.got(WireType.TUNNEL_DELIVER)).toHaveLength(limit + 1);
    expect(g2.relay!.downstreamCount).toBe(limit);
  });

  it('★バックボーンの相手 (信頼 Guard) には広い枠: G1 → G2 の同時数は 6 を超えて通る。バックボーンでない相手が同じことをすると BUSY', () => {
    const { r, h } = chain({ g: { limits: { peer: { reqPerSec: 1000, reqBurst: 1000 } } } });
    // 利用者の枠 (6) を超える数を、別々の利用者から G1 に頼む → G1 → G2 は 1 本の接続に束ねられる
    const clients = Array.from({ length: 12 }, (_, i) => node(pid(0xa000 + i)));
    clients.forEach(c => c.link(bus.nodes.get(G1)!));
    clients.forEach((c, i) => c.send(G1, WireType.TUNNEL_SEND, { reqId: i + 1, gateway: G2, tunnelId: TID, body: body() }));
    bus.flush();
    expect(h.got(WireType.TUNNEL_DELIVER)).toHaveLength(12);
    // 同じことを、バックボーンではない相手が G2 の受け口へ直接 FWD で頼む
    const stranger = node(pid(0xe001));
    stranger.link(bus.nodes.get(G2)!);
    for (let i = 0; i < 12; i++) stranger.send(G2, WireType.TUNNEL_FWD, { returnTag: 1000 + i, tunnelId: TID, body: body() });
    bus.flush();
    expect(stranger.got(WireType.TUNNEL_ERROR).filter(m => m.payload.code === TUNNEL_ERROR_CODE.BUSY).length).toBeGreaterThanOrEqual(6);
    void r;
  });

  it('★帯域: 利用者から受け取る本体のバイト数に枠 (C4: 1MiB/秒・バースト 64MiB)。使い切ると捨てる', () => {
    let t = 9_000_000;
    const r = node(R);
    const g = node(G1, { role: 'guard', now: () => t, limits: { clientSend: { reqPerSec: 1000, reqBurst: 1000, concurrent: 1000, bytesPerSec: 100_000, bytesBurst: 50_000 } } });
    const h = node(H);
    r.link(g); g.link(h);
    h.send(G1, WireType.TUNNEL_REGISTER, { tunnelId: TID });
    bus.flush();
    for (let i = 0; i < 8; i++) r.send(G1, WireType.TUNNEL_SEND, { reqId: i + 1, gateway: G1, tunnelId: TID, body: body(10_000) });
    bus.flush();
    expect(h.got(WireType.TUNNEL_DELIVER)).toHaveLength(5); // 50,000 / 10,000
    expect(g.relay!.stats.dropped.bytes).toBe(3);
    expect(r.got(WireType.TUNNEL_ERROR).filter(m => m.payload.code === TUNNEL_ERROR_CODE.BUSY)).toHaveLength(3);
    t += 500; // 50,000 バイト回復
    r.send(G1, WireType.TUNNEL_SEND, { reqId: 50, gateway: G1, tunnelId: TID, body: body(10_000) });
    bus.flush();
    expect(h.got(WireType.TUNNEL_DELIVER)).toHaveLength(6);
  });

  it('★C4 の既定: 帯域 1MiB/秒・バースト 64MiB・1 日 4GiB・件数 60/秒・同時 32', () => {
    expect(TUNNEL_LIMITS.CLIENT_SEND).toEqual({
      reqPerSec: 60, reqBurst: 120, concurrent: 32,
      bytesPerSec: 1024 * 1024, bytesBurst: 64 * 1024 * 1024, bytesPerDay: 4 * 1024 * 1024 * 1024,
    });
  });

  it('★1 日の上限: 超えた要求は BUSY。接続を切って張り直しても使用量は戻らない。翌日 (UTC) に戻る', () => {
    const DAY = 24 * 3600 * 1000;
    let t = 400 * DAY + 3600_000;
    const r = node(R);
    const g = node(G1, {
      role: 'guard', now: () => t,
      limits: { clientSend: { reqPerSec: 1000, reqBurst: 1000, concurrent: 1000, bytesPerSec: 1e9, bytesBurst: 1e9, bytesPerDay: 25_000 } },
    });
    const h = node(H);
    r.link(g); g.link(h);
    h.send(G1, WireType.TUNNEL_REGISTER, { tunnelId: TID });
    bus.flush();
    for (let i = 0; i < 4; i++) r.send(G1, WireType.TUNNEL_SEND, { reqId: i + 1, gateway: G1, tunnelId: TID, body: body(10_000) });
    bus.flush();
    expect(h.got(WireType.TUNNEL_DELIVER)).toHaveLength(2); // 25,000 / 10,000
    expect(g.relay!.stats.dropped.daily).toBe(2);
    // 切って張り直しても戻らない
    r.unlink(g);
    r.link(g);
    r.send(G1, WireType.TUNNEL_SEND, { reqId: 50, gateway: G1, tunnelId: TID, body: body(10_000) });
    bus.flush();
    expect(h.got(WireType.TUNNEL_DELIVER)).toHaveLength(2);
    expect(g.relay!.stats.dropped.daily).toBe(3);
    // 翌日 (UTC) には戻る
    t += DAY;
    r.send(G1, WireType.TUNNEL_SEND, { reqId: 60, gateway: G1, tunnelId: TID, body: body(10_000) });
    bus.flush();
    expect(h.got(WireType.TUNNEL_DELIVER)).toHaveLength(3);
  });

  it('★上り枠は利用者ごと: 1 人が使い切っても別の利用者は影響を受けない', () => {
    const r1 = node(R);
    const r2 = node(pid(0xaa02));
    const g = node(G1, { role: 'guard', limits: { clientSend: { reqPerSec: 1000, reqBurst: 1000, concurrent: 1000, bytesPerSec: 1, bytesBurst: 20_000 } } });
    const h = node(H);
    r1.link(g); r2.link(g); g.link(h);
    h.send(G1, WireType.TUNNEL_REGISTER, { tunnelId: TID });
    bus.flush();
    for (let i = 0; i < 4; i++) r1.send(G1, WireType.TUNNEL_SEND, { reqId: i + 1, gateway: G1, tunnelId: TID, body: body(10_000) });
    r2.send(G1, WireType.TUNNEL_SEND, { reqId: 1, gateway: G1, tunnelId: TID, body: body(10_000) });
    bus.flush();
    expect(r1.got(WireType.TUNNEL_ERROR).filter(m => m.payload.code === TUNNEL_ERROR_CODE.BUSY)).toHaveLength(2);
    expect(r2.got(WireType.TUNNEL_ERROR)).toHaveLength(0);
    expect(h.got(WireType.TUNNEL_DELIVER)).toHaveLength(3);
  });

  it('応答側の帯域: 保持者が枠を超えて REPLY を送り込むと、超えた片は R へ転送しない', () => {
    const r = node(R);
    const g = node(G1, { role: 'guard', limits: { peer: { reqPerSec: 1000, reqBurst: 1000, concurrent: 1000, bytesPerSec: 1, bytesBurst: 30_000 } } });
    const h = node(H);
    r.link(g); g.link(h);
    h.send(G1, WireType.TUNNEL_REGISTER, { tunnelId: TID });
    bus.flush();
    sendReq(r, G1, G1, 1, body(10)); // 要求 10 バイトぶんを使う
    const d = h.got(WireType.TUNNEL_DELIVER)[0];
    for (let seq = 0; seq < 5; seq++) h.send(G1, WireType.TUNNEL_REPLY, { returnTag: d.payload.returnTag, toHop: G1, seq, final: false, body: body(10_000) });
    bus.flush();
    // R と H は別のバケット (相手ごと): H は 30,000 まで
    expect(r.got(WireType.TUNNEL_RESULT)).toHaveLength(3);
  });

  it('★経路の総数 (全体) に上限: 満杯なら新しい要求は BUSY', () => {
    const r = node(R);
    const g = node(G1, { role: 'guard', limits: { maxRoutes: 4, peer: { reqPerSec: 1000, reqBurst: 1000, concurrent: 1000 } } });
    const h = node(H);
    r.link(g); g.link(h);
    h.send(G1, WireType.TUNNEL_REGISTER, { tunnelId: TID });
    bus.flush();
    for (let i = 0; i < 4; i++) r.send(G1, WireType.TUNNEL_SEND, { reqId: i + 1, gateway: G1, tunnelId: TID, body: body() });
    bus.flush();
    // 直接 (G_R = G_h) は上り・下りで 2 つ使う: 2 件で満杯
    expect(h.got(WireType.TUNNEL_DELIVER)).toHaveLength(2);
    expect(g.relay!.stats.dropped.full).toBe(2);
  });
});

describe('TunnelRelay: 受け口へ未接続のとき (オープンの網・バックボーン外)', () => {
  /** R ─ N (一般の隣人 = G_R)、G (受け口) ─ H。N と G はまだつながっていない */
  function openNet(over: TunnelRelayOptions = {}) {
    const dialed: string[] = [];
    const r = node(R);
    const n = node(pid(0x2001), { role: 'client', dial: (id) => { dialed.push(id); }, ...over });
    const g = node(G1, { role: 'client' });
    const h = node(H);
    r.link(n); g.link(h);
    h.send(G1, WireType.TUNNEL_REGISTER, { tunnelId: TID });
    bus.flush();
    return { r, n, g, h, dialed };
  }

  it('★G_R は受け口へ自分から張り (dial)、検証済みになったら溜めた要求を流す。応答は R まで戻る', () => {
    const { r, n, g, h, dialed } = openNet();
    sendReq(r, n.id, G1, 31);
    expect(dialed).toEqual([G1]);
    expect(n.relay!.pendingDialCount).toBe(1);
    expect(h.got(WireType.TUNNEL_DELIVER)).toHaveLength(0);
    // 同じ受け口への 2 件目は、張り直さずに待つ
    sendReq(r, n.id, G1, 32);
    expect(dialed).toEqual([G1]);
    // つながって検証が済んだ
    n.link(g);
    n.pm.emit('peer:verified', { peerId: G1 });
    bus.flush();
    expect(n.relay!.pendingDialCount).toBe(0);
    const ds = h.got(WireType.TUNNEL_DELIVER);
    expect(ds).toHaveLength(2);
    expect(ds.every(d => d.payload.fromHop === n.id)).toBe(true); // H が見るのは G_R (一般の隣人) だけ
    h.send(G1, WireType.TUNNEL_REPLY, { returnTag: ds[0].payload.returnTag, toHop: n.id, seq: 0, final: true, body: body(10) });
    bus.flush();
    expect(r.got(WireType.TUNNEL_RESULT)).toHaveLength(1);
  });

  it('★張れなかったら (時間切れ) NO_ROUTE。その受け口は 30 秒のあいだ張り直さず、すぐ NO_ROUTE を返す', () => {
    vi.useFakeTimers();
    try {
      let t = 3_000_000;
      const { r, n, dialed } = openNet({ now: () => t });
      sendReq(r, n.id, G1, 1);
      t += TUNNEL_LIMITS.DIAL.TIMEOUT_MS;
      vi.advanceTimersByTime(TUNNEL_LIMITS.DIAL.TIMEOUT_MS + 10);
      bus.flush();
      expect(r.got(WireType.TUNNEL_ERROR).at(-1)!.payload).toEqual({ id: 1, code: TUNNEL_ERROR_CODE.NO_ROUTE });
      expect(n.relay!.routeCount).toBe(0);
      sendReq(r, n.id, G1, 2);
      expect(dialed).toEqual([G1]); // 張り直していない
      expect(r.got(WireType.TUNNEL_ERROR).at(-1)!.payload).toEqual({ id: 2, code: TUNNEL_ERROR_CODE.NO_ROUTE });
      t += TUNNEL_LIMITS.DIAL.COOLDOWN_MS + 1000;
      n.relay!.sweep();
      sendReq(r, n.id, G1, 3);
      expect(dialed).toEqual([G1, G1]); // 冷却が明けた
    } finally {
      vi.useRealTimers();
    }
  });

  it('★張る頻度の制限: 利用者が出鱈目な受け口を次々に指しても、ダイヤルは burst (3) までで、残りは BUSY', () => {
    const dialed: string[] = [];
    const r = node(R);
    const n = node(pid(0x2001), { role: 'client', dial: (id) => { dialed.push(id); }, limits: { peer: { reqPerSec: 1000, reqBurst: 1000, concurrent: 1000 } } });
    r.link(n);
    for (let i = 0; i < 8; i++) r.send(n.id, WireType.TUNNEL_SEND, { reqId: i + 1, gateway: pid(0x7000 + i), tunnelId: TID, body: body() });
    bus.flush();
    expect(dialed).toHaveLength(TUNNEL_LIMITS.DIAL.burst);
    expect(r.got(WireType.TUNNEL_ERROR).filter(m => m.payload.code === TUNNEL_ERROR_CODE.BUSY)).toHaveLength(8 - TUNNEL_LIMITS.DIAL.burst);
  });

  it('1 つの受け口を待てる要求の数に上限 (16)', () => {
    const { r, n } = openNet({ limits: { peer: { reqPerSec: 1000, reqBurst: 1000, concurrent: 1000 } } });
    for (let i = 0; i < 20; i++) r.send(n.id, WireType.TUNNEL_SEND, { reqId: i + 1, gateway: G1, tunnelId: TID, body: body() });
    bus.flush();
    expect(r.got(WireType.TUNNEL_ERROR).filter(m => m.payload.code === TUNNEL_ERROR_CODE.BUSY)).toHaveLength(4);
    expect(n.relay!.upstreamCount).toBe(16);
  });

  it('待つ間に利用者が切れたら、つながったあとに流さない', () => {
    const { r, n, g, h } = openNet();
    sendReq(r, n.id, G1, 1);
    n.unlink(r);
    n.link(g);
    n.pm.emit('peer:verified', { peerId: G1 });
    bus.flush();
    expect(h.got(WireType.TUNNEL_DELIVER)).toHaveLength(0);
  });
});

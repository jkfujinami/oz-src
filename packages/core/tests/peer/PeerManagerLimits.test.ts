import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest';
import { sodiumReady } from '../../src/crypto/sodium';
import { NodeIdentity } from '../../src/crypto/NodeIdentity';
import { PeerManager, MAX_FRAME_BYTES } from '../../src/network/PeerManager';
import { MessageDispatcher } from '../../src/network/MessageDispatcher';
import { RateLimiter, RATE_LIMITS } from '../../src/network/RateLimiter';
import { WireType } from '../../src/network/wire/WireTypes';
import { WireCodec, MAX_SDP_BYTES, MAX_ICE_CANDIDATE_BYTES } from '../../src/network/wire/WireCodec';
import { WebRTCPeer } from '../../src/network/WebRTCPeer';
import { RING_MESH } from '../../src/constants';
import { installFakeWebRTC, resetFakeWebRTC } from '../helpers/webrtc';
import { LOGIC_FAKE_TIMERS } from '../helpers/logicHarness';

const FAST = { difficulty: 0, opsLimit: 1, memLimit: 8192 };
const hexId = (n: number) => n.toString(16).padStart(32, '0');

let identity: NodeIdentity;

function signalingMock() {
  return {
    connect: vi.fn().mockResolvedValue(undefined),
    disconnect: vi.fn(),
    sendRelay: vi.fn(),
    on: vi.fn(),
    isConnected: false,
  };
}

function manager(opts: { rateLimiter?: RateLimiter } = {}) {
  const dispatcher = new MessageDispatcher();
  const signaling = signalingMock();
  const pm = new PeerManager(identity, dispatcher, signaling as any, { powParams: FAST, ...opts });
  return { pm, dispatcher, signaling };
}

/** 検証済みとして振る舞う最小の接続 */
function verifiedPeer(pm: PeerManager, id: string) {
  const peer: any = {
    peerId: id, position: 0.3, rtt: 0, isConnected: true, isConnecting: false, isVerified: true,
    direction: 'inbound', verifiedAt: Date.now(), netGroup: 'unknown',
    send: vi.fn(), close: vi.fn(), signal: vi.fn(),
    dtlsFingerprints: () => ({ local: '', remote: '' }),
  };
  (pm as any)._peers.set(id, peer);
  return peer;
}

const feed = (pm: PeerManager, from: string, frame: Uint8Array) => (pm as any).handleData(from, frame);

/** 型ごとの、形式が正しい最小のフレーム。GOSSIP / STEM は中身 (packet / item) が読めなくてもフレームは成立する */
const frameFor = (t: WireType, i = 0): Uint8Array => {
  switch (t) {
    case WireType.HELLO: return WireCodec.encode(t, { challenge: new Uint8Array(32) });
    case WireType.JOIN: return WireCodec.encode(t, { pubkey: new Uint8Array(32), powCounter: 0, signature: new Uint8Array(64) });
    case WireType.PING:
    case WireType.PONG: return WireCodec.encode(t, { nonce: i });
    case WireType.PEX_REQUEST: return WireCodec.encode(t, {});
    case WireType.PEX_RESPONSE: return WireCodec.encode(t, { peers: [] });
    case WireType.SDP_RELAY: return WireCodec.encode(t, { targetPeerId: 'a'.repeat(32), senderId: 'b'.repeat(32), sdp: { type: 'offer', sdp: 'v=0' } });
    case WireType.ICE_RELAY: return WireCodec.encode(t, { targetPeerId: 'a'.repeat(32), senderId: 'b'.repeat(32), candidate: { candidate: 'candidate:x', sdpMid: null, sdpMLineIndex: null, usernameFragment: null } });
    case WireType.GOSSIP:
    case WireType.STEM:
    case WireType.ONION_STEM: return Uint8Array.of(t, i & 0xff, 1, 2);
    case WireType.CATCHUP_REQ: return WireCodec.encode(t, { since: i });
    case WireType.CATCHUP_DATA: return WireCodec.encode(t, { packets: [] });
    case WireType.CATCHUP_END: return WireCodec.encode(t, { status: 0, nextSince: i });
    case WireType.LEASESET: return WireCodec.encode(t, { leaseSet: new Uint8Array(145).fill(i & 0xff) });
    case WireType.LEASESET_SYNC_REQ: return WireCodec.encode(t, {});
    case WireType.LEASESET_SYNC: return WireCodec.encode(t, { leaseSets: [] });
    case WireType.TUNNEL_REGISTER: return WireCodec.encode(t, { tunnelId: new Uint8Array(8) });
    case WireType.TUNNEL_REGISTERED: return WireCodec.encode(t, { tunnelId: new Uint8Array(8), ok: true });
    case WireType.TUNNEL_SEND: return WireCodec.encode(t, { reqId: i, gateway: 'a'.repeat(32), tunnelId: new Uint8Array(8), body: Uint8Array.of(1) });
    case WireType.TUNNEL_FWD: return WireCodec.encode(t, { returnTag: i, tunnelId: new Uint8Array(8), body: Uint8Array.of(1) });
    case WireType.TUNNEL_DELIVER: return WireCodec.encode(t, { returnTag: i, fromHop: 'a'.repeat(32), body: Uint8Array.of(1) });
    case WireType.TUNNEL_REPLY: return WireCodec.encode(t, { returnTag: i, toHop: 'a'.repeat(32), seq: 0, final: true, body: Uint8Array.of(1) });
    case WireType.TUNNEL_RET:
    case WireType.TUNNEL_RESULT: return WireCodec.encode(t, t === WireType.TUNNEL_RET ? { returnTag: i, seq: 0, final: true, body: Uint8Array.of(1) } : { reqId: i, seq: 0, final: true, body: Uint8Array.of(1) });
    case WireType.TUNNEL_ERROR: return WireCodec.encode(t, { id: i, code: 1 });
    case WireType.OZZY_REPLY: return WireCodec.encode(t, { header: new Uint8Array(68).fill(i & 0xff), seq: 0, final: true, body: Uint8Array.of(1) });
    case WireType.OZZY_RESULT: return WireCodec.encode(t, { replyId: i, seq: 0, final: true, body: Uint8Array.of(1) });
    case WireType.OZZY_UP: return WireCodec.encode(t, { header: new Uint8Array(80).fill(i & 0xff), seq: 0, final: true, body: Uint8Array.of(1) });
    case WireType.OZZY_UP_FWD: return WireCodec.encode(t, { uploadId: new Uint8Array(16).fill(i & 0xff), seq: 0, final: true, body: Uint8Array.of(1) });
    case WireType.OZZY_WORKER_REQ: return WireCodec.encode(t, {});
    case WireType.OZZY_WORKER_ADS: return WireCodec.encode(t, { ads: [{ pubkey: new Uint8Array(32), powCounter: i, expiresMin: 1, url: 'https://a.b.workers.dev', signature: new Uint8Array(64) }] });
    default: throw new Error(`no sample for 0x${t.toString(16)}`);
  }
};

describe('PeerManager: フレーム長とレート制限', () => {
  const PEER = hexId(0xcafe);

  beforeAll(async () => {
    await sodiumReady;
    identity = await NodeIdentity.mine(FAST);
  });

  it('すべての WireType にレート制限のカテゴリがあり、1 件目は必ず通る (表の漏れ = 黙って全部捨てる、を防ぐ)', () => {
    const limiter = new RateLimiter();
    const { pm, dispatcher } = manager({ rateLimiter: limiter });
    verifiedPeer(pm, PEER);
    const types = Object.values(WireType).filter((v): v is WireType => typeof v === 'number' && v !== WireType.UNKNOWN);
    const seen = new Set<number>();
    for (const t of types) dispatcher.register(t, () => seen.add(t));
    for (const t of types) feed(pm, PEER, frameFor(t));

    expect(Array.from(seen).sort()).toEqual([...types].sort());
    expect(limiter.dropped.size).toBe(0);
  });

  it('カテゴリごとに予算が独立している: GOSSIP を使い切っても追いつき / 制御は通る', () => {
    const limiter = new RateLimiter(RATE_LIMITS, () => 0);
    const { pm, dispatcher } = manager({ rateLimiter: limiter });
    verifiedPeer(pm, PEER);
    const count = { gossip: 0, catchup: 0, ping: 0 };
    dispatcher.register(WireType.GOSSIP, () => count.gossip++);
    dispatcher.register(WireType.CATCHUP_REQ, () => count.catchup++);
    dispatcher.register(WireType.PING, () => count.ping++);

    for (let i = 0; i < 200; i++) feed(pm, PEER, frameFor(WireType.GOSSIP, i));
    feed(pm, PEER, frameFor(WireType.CATCHUP_REQ));
    feed(pm, PEER, WireCodec.encode(WireType.PING, { nonce: 1 }));

    expect(count.gossip).toBe(RATE_LIMITS.gossip.burst);
    expect(count.catchup).toBe(1);
    expect(count.ping).toBe(1);
  });

  it('同じカテゴリに属する WireType は予算を共有する (STEM で GOSSIP の枠を迂回できない)', () => {
    const limiter = new RateLimiter(RATE_LIMITS, () => 0);
    const { pm, dispatcher } = manager({ rateLimiter: limiter });
    verifiedPeer(pm, PEER);
    const n = { gossip: 0 };
    for (const t of [WireType.GOSSIP, WireType.STEM]) dispatcher.register(t, () => n.gossip++);
    for (let i = 0; i < 200; i++) {
      for (const t of [WireType.GOSSIP, WireType.STEM]) feed(pm, PEER, frameFor(t, i));
    }
    expect(n.gossip).toBe(RATE_LIMITS.gossip.burst);
  });

  it('追いつきを使い切っても GOSSIP の予算は減らない (追いつきの流れで live の投稿を飢えさせない)', () => {
    const limiter = new RateLimiter(RATE_LIMITS, () => 0);
    const { pm, dispatcher } = manager({ rateLimiter: limiter });
    verifiedPeer(pm, PEER);
    let gossip = 0;
    dispatcher.register(WireType.CATCHUP_DATA, () => {});
    dispatcher.register(WireType.GOSSIP, () => gossip++);
    for (let i = 0; i < 1000; i++) feed(pm, PEER, frameFor(WireType.CATCHUP_DATA));
    for (let i = 0; i < RATE_LIMITS.gossip.burst; i++) feed(pm, PEER, frameFor(WireType.GOSSIP, i));
    expect(gossip).toBe(RATE_LIMITS.gossip.burst);
  });

  it('既定の上限は、網全体のピーク 20 件/秒の投稿と、1 リンク 40 セル/秒のオニオンを通せる', () => {
    expect(RATE_LIMITS.gossip.ratePerSec).toBeGreaterThanOrEqual(20 * 2);
    // 追いつき: Guard が 1 相手に流す最大 16 フレーム/秒 (256KiB/秒 ÷ 16KiB) を通せる
    expect(RATE_LIMITS.catchup.ratePerSec).toBeGreaterThanOrEqual(16 * 2);
    expect(RATE_LIMITS.onion.ratePerSec).toBeGreaterThanOrEqual(40 * 2);
  });

  it('予算は隣人ごと: 1 人が使い切っても別の隣人の GOSSIP は通る', () => {
    const limiter = new RateLimiter(RATE_LIMITS, () => 0);
    const { pm, dispatcher } = manager({ rateLimiter: limiter });
    const OTHER = hexId(0xbeef);
    verifiedPeer(pm, PEER);
    verifiedPeer(pm, OTHER);
    const from: string[] = [];
    dispatcher.register(WireType.GOSSIP, (p) => from.push(p));
    for (let i = 0; i < 300; i++) feed(pm, PEER, frameFor(WireType.GOSSIP, i));
    feed(pm, OTHER, frameFor(WireType.GOSSIP, 0));
    expect(from.filter(p => p === OTHER)).toHaveLength(1);
  });

  it('時間が経てば定常レートぶん回復する', () => {
    let now = 0;
    const limiter = new RateLimiter(RATE_LIMITS, () => now);
    const { pm, dispatcher } = manager({ rateLimiter: limiter });
    verifiedPeer(pm, PEER);
    let n = 0;
    dispatcher.register(WireType.GOSSIP, () => n++);
    for (let i = 0; i < 300; i++) feed(pm, PEER, frameFor(WireType.GOSSIP, i));
    expect(n).toBe(RATE_LIMITS.gossip.burst);

    now += 1000; // 1 秒 = ratePerSec 件
    for (let i = 0; i < 300; i++) feed(pm, PEER, frameFor(WireType.GOSSIP, i));
    expect(n).toBe(RATE_LIMITS.gossip.burst + RATE_LIMITS.gossip.ratePerSec);
  });

  it('切断するとその隣人の予算は捨てられる (再接続で持ち越さない)', () => {
    const limiter = new RateLimiter(RATE_LIMITS, () => 0);
    const { pm } = manager({ rateLimiter: limiter });
    verifiedPeer(pm, PEER);
    for (let i = 0; i < 300; i++) feed(pm, PEER, frameFor(WireType.GOSSIP, i));
    expect(limiter.tokensFor(PEER, 'gossip')).toBeLessThan(1);
    pm.disconnect(PEER);
    expect(limiter.tokensFor(PEER, 'gossip')).toBe(RATE_LIMITS.gossip.burst);
  });

  it('レート超過は捨てるだけで、違反点も切断も無い', () => {
    const { pm } = manager({ rateLimiter: new RateLimiter(RATE_LIMITS, () => 0) });
    verifiedPeer(pm, PEER);
    for (let i = 0; i < 500; i++) feed(pm, PEER, frameFor(WireType.CATCHUP_REQ));
    expect(pm.misbehavior.getScore(PEER)).toBe(0);
    expect(pm.peers.has(PEER)).toBe(true);
  });

  describe('WireType ごとのフレーム長の上限 (デコード前に判定)', () => {
    const loose = () => new RateLimiter(Object.fromEntries(Object.keys(RATE_LIMITS).map(k => [k, { ratePerSec: 1e6, burst: 1e6 }])));
    const setup = (type: WireType) => {
      const { pm, dispatcher } = manager({ rateLimiter: loose() });
      verifiedPeer(pm, PEER);
      const n = { v: 0 };
      dispatcher.register(type, () => n.v++);
      return { pm, n };
    };
    const plusOne = (f: Uint8Array) => Uint8Array.from([...f, 0]);

    // 固定レイアウトの型: 上限 = 正規の長さ (1 + 本体)。1B 長いフレームは decode せずに捨てる
    const fixed: Array<[string, WireType, number]> = [
      ['HELLO', WireType.HELLO, 33],
      ['JOIN', WireType.JOIN, 101],
      ['PING', WireType.PING, 5],
      ['PONG', WireType.PONG, 5],
      ['PEX_REQUEST', WireType.PEX_REQUEST, 1],
      ['ONION_STEM', WireType.ONION_STEM, 1201],
    ];
    for (const [name, type, limit] of fixed) {
      it(`${name}: ${limit}B (正規の長さ) は通り、1B でも超えれば捨てる`, () => {
        const { pm, n } = setup(type);
        const ok = type === WireType.ONION_STEM ? Uint8Array.of(type, ...new Uint8Array(1200)) : frameFor(type);
        expect(ok.byteLength).toBe(limit);
        feed(pm, PEER, ok);
        expect(n.v).toBe(1);
        feed(pm, PEER, plusOne(ok));
        expect(n.v).toBe(1);
        expect(pm.misbehavior.getScore(PEER)).toBe(0);
        expect(pm.peers.has(PEER)).toBe(true); // 上限超えは捨てるだけ (切断しない)
      });
    }

    it('PEX_RESPONSE: 8 件 (290B) は通り、1B でも超えれば捨てる', () => {
      const { pm, n } = setup(WireType.PEX_RESPONSE);
      const ok = WireCodec.encode(WireType.PEX_RESPONSE, { peers: Array.from({ length: 8 }, () => ({ pubkey: new Uint8Array(32), powCounter: 1 })) });
      expect(ok.byteLength).toBe(290);
      feed(pm, PEER, ok);
      expect(n.v).toBe(1);
      feed(pm, PEER, plusOne(ok));
      expect(n.v).toBe(1);
      expect(pm.peers.has(PEER)).toBe(true);
    });

    it('GOSSIP: 3072B ちょうどは通り、1B でも超えれば捨てる', () => {
      const { pm, n } = setup(WireType.GOSSIP);
      feed(pm, PEER, Uint8Array.of(WireType.GOSSIP, ...new Uint8Array(3071)));
      expect(n.v).toBe(1);
      feed(pm, PEER, Uint8Array.of(WireType.GOSSIP, ...new Uint8Array(3072)));
      expect(n.v).toBe(1);
      expect(pm.peers.has(PEER)).toBe(true);
    });

    it('SDP_RELAY: 本文の上限いっぱいの正規フレームは通り、16KiB を超えれば捨てる', () => {
      const { pm, n } = setup(WireType.SDP_RELAY);
      const maxFrame = WireCodec.encode(WireType.SDP_RELAY, {
        targetPeerId: 'a'.repeat(32), senderId: 'b'.repeat(32), sdp: { type: 'offer', sdp: 'x'.repeat(MAX_SDP_BYTES) },
      });
      expect(maxFrame.byteLength).toBeLessThanOrEqual(16 * 1024);
      feed(pm, PEER, maxFrame);
      expect(n.v).toBe(1);
      feed(pm, PEER, Uint8Array.of(WireType.SDP_RELAY, ...new Uint8Array(16 * 1024)));
      expect(n.v).toBe(1);
      expect(pm.peers.has(PEER)).toBe(true);
    });

    it('ICE_RELAY: 最大の正規フレームは通り、上限を超えれば捨てる', () => {
      const { pm, n } = setup(WireType.ICE_RELAY);
      const maxFrame = WireCodec.encode(WireType.ICE_RELAY, {
        targetPeerId: 'a'.repeat(32), senderId: 'b'.repeat(32),
        candidate: { candidate: 'x'.repeat(MAX_ICE_CANDIDATE_BYTES), sdpMid: 'm'.repeat(254), sdpMLineIndex: 0, usernameFragment: 'u'.repeat(254) },
      });
      feed(pm, PEER, maxFrame);
      expect(n.v).toBe(1);
      feed(pm, PEER, Uint8Array.of(WireType.ICE_RELAY, ...new Uint8Array(maxFrame.byteLength)));
      expect(n.v).toBe(1);
      expect(pm.peers.has(PEER)).toBe(true);
    });

    it('CATCHUP_REQ / CATCHUP_END: 正規の長さ (4B / 5B) は通り、1B でも超えれば捨てる', () => {
      for (const t of [WireType.CATCHUP_REQ, WireType.CATCHUP_END]) {
        const { pm, n } = setup(t);
        const ok = frameFor(t);
        expect(ok.byteLength).toBe(t === WireType.CATCHUP_REQ ? 4 : 5);
        feed(pm, PEER, ok);
        expect(n.v).toBe(1);
        feed(pm, PEER, plusOne(ok));
        expect(n.v).toBe(1);
        expect(pm.peers.has(PEER)).toBe(true);
      }
    });

    it('CATCHUP_DATA: 16KiB ちょうどは通り、1B でも超えれば捨てる', () => {
      const { pm, n } = setup(WireType.CATCHUP_DATA);
      const pkt = new Uint8Array(2000).fill(1);
      // 1 + 2 + n × (2 + 2000) ≤ 16384 → n = 8 (16019B)
      const ok = WireCodec.encode(WireType.CATCHUP_DATA, { packets: Array.from({ length: 8 }, () => pkt) });
      expect(ok.byteLength).toBeLessThanOrEqual(16 * 1024);
      feed(pm, PEER, ok);
      expect(n.v).toBe(1);
      feed(pm, PEER, Uint8Array.of(WireType.CATCHUP_DATA, ...new Uint8Array(16 * 1024)));
      expect(n.v).toBe(1);
      expect(pm.peers.has(PEER)).toBe(true);
    });

    it('すべての WireType にフレーム長の上限がある (表の漏れ = 1MB まで通す、を防ぐ)', () => {
      for (const t of Object.values(WireType)) {
        if (typeof t !== 'number' || t === WireType.UNKNOWN) continue;
        expect(MAX_FRAME_BYTES[t], `0x${t.toString(16)}`).toBeDefined();
      }
    });
  });
});

describe('PeerManager: 保留中の接続とシグナルの上限', () => {
  beforeAll(async () => {
    await sodiumReady;
    identity = await NodeIdentity.mine(FAST);
    installFakeWebRTC();
  });
  beforeEach(() => resetFakeWebRTC());

  const offer = (sender: string) => ({ type: 'sdp-relay', targetPeerId: identity.peerId, senderId: sender, sdp: { type: 'offer', sdp: 'v=0\r\n' } });
  const ice = (sender: string) => ({ type: 'ice-relay', targetPeerId: identity.peerId, senderId: sender, candidate: { candidate: 'c' } });

  it('乱数 ID の offer がトラッカー経由で大量に来ても、未検証の接続は 8 本まで', () => {
    const { pm } = manager();
    for (let i = 1; i <= 50; i++) (pm as any).handleRelay(hexId(i), offer(hexId(i)));
    expect(pm.peers.size).toBe(8);
    pm.stop();
  });

  it('検証済みの接続は保留中の上限に数えない', () => {
    const { pm } = manager();
    for (let i = 1; i <= 12; i++) verifiedPeer(pm, hexId(0x1000 + i));
    for (let i = 1; i <= 20; i++) pm.connect(hexId(i), true);
    expect(pm.peers.size).toBe(12 + 8);
    pm.stop();
  });

  it('offer より先に届いた ICE は送信者 32 人 × 1 人 32 件までしか溜めない', () => {
    const { pm } = manager();
    for (let i = 1; i <= 100; i++) (pm as any).handleRelay(hexId(i), ice(hexId(i)));
    const pending = (pm as any).pendingSignals as Map<string, any[]>;
    expect(pending.size).toBe(32);
    // 古い送信者から押し出される
    expect(pending.has(hexId(1))).toBe(false);
    expect(pending.has(hexId(100))).toBe(true);

    for (let i = 0; i < 100; i++) (pm as any).handleRelay(hexId(100), ice(hexId(100)));
    expect(pending.get(hexId(100))!.length).toBe(32);
    pm.stop();
  });

  it('溜めておいた ICE は offer が届いた時点で新しい接続に流し込まれる', () => {
    const { pm } = manager();
    const signal = vi.spyOn(WebRTCPeer.prototype, 'signal');
    const S = hexId(0xabc);
    for (let i = 0; i < 3; i++) (pm as any).handleRelay(S, ice(S));
    expect(signal).not.toHaveBeenCalled();
    (pm as any).handleRelay(S, offer(S));
    expect(signal).toHaveBeenCalledTimes(4);
    expect(signal.mock.calls[0][0]).toMatchObject({ sdp: { type: 'offer' } });
    expect((pm as any).pendingSignals.has(S)).toBe(false);
    signal.mockRestore();
    pm.stop();
  });

  it('形式の壊れた peerId を名乗るシグナルは捨てる (接続もバッファもしない)', () => {
    const { pm } = manager();
    for (const bad of ['', 'XYZ', 'A'.repeat(32), 'a'.repeat(31), 'a'.repeat(33)]) {
      (pm as any).handleRelay(bad, offer(bad));
      (pm as any).handleRelay(bad, ice(bad));
    }
    expect(pm.peers.size).toBe(0);
    expect((pm as any).pendingSignals.size).toBe(0);
    expect(pm.connect('not-a-peer-id', true)).toBeUndefined();
    expect(pm.connect(identity.peerId, true)).toBeUndefined(); // 自分自身
  });

  it('未検証で死んだ接続に同じ ID の offer が来たら、古い接続を畳んで張り直す', () => {
    const { pm } = manager();
    const S = hexId(0xdead);
    const stale: any = { peerId: S, isVerified: false, isConnected: false, isConnecting: false, close: vi.fn(), signal: vi.fn() };
    (pm as any)._peers.set(S, stale);
    (pm as any).handleRelay(S, offer(S));
    expect(stale.close).toHaveBeenCalled();
    expect(pm.peers.get(S)).not.toBe(stale);
    expect(pm.peers.get(S)).toBeInstanceOf(WebRTCPeer);
    pm.stop();
  });

  it('トラッカーから来たピア一覧には MAX_DEGREE まで outbound で張り、壊れた要素は無視する', () => {
    const { pm } = manager();
    const connect = vi.spyOn(pm, 'connect').mockImplementation(() => undefined);
    (pm as any).handleTrackerPeers([null, { peerId: 5 }, { peerId: hexId(1) }, { peerId: hexId(2) }]);
    expect(connect.mock.calls.map(c => c[0])).toEqual([hexId(1), hexId(2)]);
    expect(connect.mock.calls.every(c => c[1] === true)).toBe(true);
    expect(() => (pm as any).handleTrackerPeers('garbage')).not.toThrow();
  });

  it('次数が MAX_DEGREE に達していればトラッカーのピアには張らない', () => {
    const { pm } = manager();
    for (let i = 1; i <= RING_MESH.MAX_DEGREE; i++) verifiedPeer(pm, hexId(0x2000 + i));
    const connect = vi.spyOn(pm, 'connect');
    (pm as any).handleTrackerPeers([{ peerId: hexId(1) }]);
    expect(connect).not.toHaveBeenCalled();
  });
});

describe('PeerManager: DataChannel 越しのシグナリング中継', () => {
  const X = hexId(0x111);
  const Y = hexId(0x222);

  beforeAll(async () => {
    await sodiumReady;
    identity = await NodeIdentity.mine(FAST);
    installFakeWebRTC();
  });

  it('自分宛てでなく、宛先が自分の隣人なら、そのまま転送する', () => {
    const { pm } = manager();
    verifiedPeer(pm, X);
    const y = verifiedPeer(pm, Y);
    const msg = { targetPeerId: Y, senderId: hexId(0x333), sdp: { type: 'offer', sdp: 'v=0' } };
    feed(pm, X, WireCodec.encode(WireType.SDP_RELAY, msg));
    expect(y.send).toHaveBeenCalledTimes(1);
    const fwd = WireCodec.decode(y.send.mock.calls[0][0]);
    expect(fwd.type).toBe(WireType.SDP_RELAY);
    expect(fwd.payload).toMatchObject(msg);
  });

  it('宛先が隣人に居なければ転送しない', () => {
    const { pm } = manager();
    const x = verifiedPeer(pm, X);
    feed(pm, X, WireCodec.encode(WireType.ICE_RELAY, { targetPeerId: Y, senderId: hexId(0x333), candidate: { candidate: 'candidate:x', sdpMid: null, sdpMLineIndex: null, usernameFragment: null } }));
    expect(x.send).not.toHaveBeenCalled();
    expect(pm.peers.size).toBe(1);
  });

  it('自分宛ての中継は、名乗られた senderId が正しい形式のときだけ受け付け、経路を記録する', () => {
    const { pm } = manager();
    verifiedPeer(pm, X);
    const relay = vi.spyOn(pm as any, 'handleRelay');
    // ★ 送り主は生の 16 バイトで運ぶので、形式違反の senderId はワイヤに載せられない (符号化できない)
    expect(() => WireCodec.encode(WireType.SDP_RELAY, { targetPeerId: identity.peerId, senderId: 'bogus', sdp: { type: 'offer', sdp: 'v=0' } })).toThrow(RangeError);
    expect(relay).not.toHaveBeenCalled();

    const S = hexId(0x444);
    feed(pm, X, WireCodec.encode(WireType.SDP_RELAY, { targetPeerId: identity.peerId, senderId: S, sdp: { type: 'offer', sdp: 'v=0' } }));
    expect(relay).toHaveBeenCalledWith(S, expect.anything(), X);
    expect((pm as any).pexRoutes.get(S)).toBe(X);
    pm.stop();
  });

  it('既存の検証済み接続の経路は、中継で名乗られた senderId では書き換わらない', () => {
    const { pm } = manager();
    verifiedPeer(pm, X);
    const live = verifiedPeer(pm, Y);
    feed(pm, X, WireCodec.encode(WireType.SDP_RELAY, { targetPeerId: identity.peerId, senderId: Y, sdp: { type: 'offer', sdp: 'v=0' } }));
    expect(pm.peers.get(Y)).toBe(live);
    expect(live.close).not.toHaveBeenCalled();
    expect((pm as any).pexRoutes.has(Y)).toBe(false);
  });
});

describe('PeerManager: トラッカーと stop()', () => {
  beforeAll(async () => {
    await sodiumReady;
    identity = await NodeIdentity.mine(FAST);
    installFakeWebRTC();
  });
  afterEach(() => vi.useRealTimers());

  it('トラッカーには購読ゾーンも座標も送らず、15 秒後に切り離す', async () => {
    vi.useFakeTimers(LOGIC_FAKE_TIMERS);
    const { pm, signaling } = manager();
    await pm.start();
    expect(signaling.connect).toHaveBeenCalledTimes(1);
    const arg = signaling.connect.mock.calls[0][0];
    for (const leaky of ['zones', 'subscribedZones', 'position']) {
      expect(arg).not.toHaveProperty(leaky);
      expect(arg.claim).not.toHaveProperty(leaky);
    }
    expect(Object.keys(arg.claim).sort()).toEqual(['peerId', 'powCounter', 'pubkey']);

    await vi.advanceTimersByTimeAsync(14_999);
    expect(signaling.disconnect).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(signaling.disconnect).toHaveBeenCalledTimes(1);
    pm.stop();
  });

  it('次数が 4 未満でトラッカーから離れていれば、30 秒ごとに再アナウンスする', async () => {
    vi.useFakeTimers(LOGIC_FAKE_TIMERS);
    const { pm, signaling } = manager();
    await pm.start();
    await vi.advanceTimersByTimeAsync(30_000);
    expect(signaling.connect).toHaveBeenCalledTimes(2);

    for (let i = 1; i <= 4; i++) verifiedPeer(pm, hexId(i));
    await vi.advanceTimersByTimeAsync(60_000);
    expect(signaling.connect).toHaveBeenCalledTimes(2);
    pm.stop();
  });

  it('最初のトラッカー接続に失敗しても、再アナウンスで再試行する', async () => {
    vi.useFakeTimers(LOGIC_FAKE_TIMERS);
    const { pm, signaling } = manager();
    signaling.connect.mockRejectedValueOnce(new Error('unreachable'));
    await expect(pm.start()).rejects.toThrow('unreachable');
    await vi.advanceTimersByTimeAsync(30_000);
    expect(signaling.connect).toHaveBeenCalledTimes(2);
    pm.stop();
  });

  it('stop() は全接続を切って peer:disconnect を出し、溜めていたシグナルも捨てる', () => {
    const { pm, signaling } = manager();
    const peers = [hexId(1), hexId(2), hexId(3)].map(id => verifiedPeer(pm, id));
    (pm as any).handleRelay(hexId(9), { type: 'ice-relay', candidate: {} });
    const gone: string[] = [];
    pm.on('peer:disconnect', (id: string) => gone.push(id));

    pm.stop();
    expect(pm.peers.size).toBe(0);
    expect(gone.sort()).toEqual([hexId(1), hexId(2), hexId(3)]);
    for (const p of peers) expect(p.close).toHaveBeenCalled();
    expect(signaling.disconnect).toHaveBeenCalled();
    expect((pm as any).pendingSignals.size).toBe(0);
  });

  it('stop() 後はシグナルもトラッカーのピア一覧も無視し、新規接続を作らない', async () => {
    const { pm, signaling } = manager();
    pm.stop();
    const before = signaling.connect.mock.calls.length;
    (pm as any).handleRelay(hexId(5), { type: 'sdp-relay', sdp: { type: 'offer', sdp: 'v=0' } });
    (pm as any).handleRelay(hexId(6), { type: 'ice-relay', candidate: {} });
    (pm as any).handleTrackerPeers([{ peerId: hexId(7) }]);
    await pm.reconnectTracker();
    expect(pm.peers.size).toBe(0);
    expect((pm as any).pendingSignals.size).toBe(0);
    expect(signaling.connect.mock.calls.length).toBe(before);
    expect(signaling.sendRelay).not.toHaveBeenCalled();
  });

  it('トラッカー接続の途中で stop() されたら、つながった直後に切断して切り離しタイマーも残さない', async () => {
    vi.useFakeTimers(LOGIC_FAKE_TIMERS);
    const { pm, signaling } = manager();
    let resolveConnect!: () => void;
    signaling.connect.mockImplementationOnce(() => new Promise<void>(r => { resolveConnect = r; }));
    const started = pm.start();
    pm.stop();
    const disconnectsAtStop = signaling.disconnect.mock.calls.length;
    resolveConnect();
    await started;
    expect(signaling.disconnect.mock.calls.length).toBe(disconnectsAtStop + 1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('stop() 後にディスパッチされた (届いてしまった) 中継も接続を作らない', () => {
    const { pm } = manager();
    const X = hexId(0x111);
    verifiedPeer(pm, X);
    pm.stop();
    (pm as any)._peers.set(X, { peerId: X, isVerified: true, isConnected: true, close: vi.fn(), send: vi.fn() });
    feed(pm, X, WireCodec.encode(WireType.SDP_RELAY, { targetPeerId: identity.peerId, senderId: hexId(0x555), sdp: { type: 'offer', sdp: 'v=0' } }));
    expect(pm.peers.has(hexId(0x555))).toBe(false);
  });
});

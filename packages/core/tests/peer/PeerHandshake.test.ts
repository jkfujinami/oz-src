import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest';
import { sodiumReady } from '../../src/crypto/sodium';
import { NodeIdentity, type JoinBinding, type NodeIdPowParams } from '../../src/crypto/NodeIdentity';
import { PeerManager } from '../../src/network/PeerManager';
import { MessageDispatcher } from '../../src/network/MessageDispatcher';
import { RateLimiter, RATE_LIMITS } from '../../src/network/RateLimiter';
import { WireType } from '../../src/network/wire/WireTypes';
import { WireCodec } from '../../src/network/wire/WireCodec';
import type { WebRTCPeer } from '../../src/network/WebRTCPeer';
import { installFakeWebRTC, resetFakeWebRTC } from '../helpers/webrtc';
import { SignalingHub, HubSignalingClient } from '../helpers/fakes';
import { waitFor, LOGIC_FAKE_TIMERS } from '../helpers/logicHarness';

const FAST: NodeIdPowParams = { difficulty: 0, opsLimit: 1, memLimit: 8192 };
const LOOSE = Object.fromEntries(Object.keys(RATE_LIMITS).map(k => [k, { ratePerSec: 1e6, burst: 1e6 }]));

interface Node {
  identity: NodeIdentity;
  dispatcher: MessageDispatcher;
  pm: PeerManager;
  verified: string[];
  sent: Array<{ to: string; type: number; payload: any }>;
}

let hub: SignalingHub;
let nodes: Node[] = [];
let alice: NodeIdentity;
let bob: NodeIdentity;
let carol: NodeIdentity;
let mallory: NodeIdentity;

function node(identity: NodeIdentity, opts: ConstructorParameters<typeof PeerManager>[3] = {}): Node {
  const dispatcher = new MessageDispatcher();
  const sig = new HubSignalingClient(hub, identity.peerId);
  const pm = new PeerManager(identity, dispatcher, sig, { powParams: FAST, ...opts });
  const verified: string[] = [];
  pm.on('peer:verified', (p: any) => verified.push(p.peerId));
  const sent: Node['sent'] = [];
  const orig = pm.sendMessage.bind(pm);
  pm.sendMessage = (to: string, type: WireType, payload: any) => {
    sent.push({ to, type, payload });
    orig(to, type, payload);
  };
  const n = { identity, dispatcher, pm, verified, sent };
  nodes.push(n);
  return n;
}

const joinsSent = (n: Node) => n.sent.filter(s => s.type === WireType.JOIN);
const inject = (to: Node, from: string, type: WireType, payload: any) =>
  (to.pm as any).handleData(from, WireCodec.encode(type, payload));
/** 符号化できない (壊れた) フレームを生のバイト列で差し込む */
const injectRaw = (to: Node, from: string, bytes: Uint8Array) => (to.pm as any).handleData(from, bytes);
/** [JOIN][pubkey 32][powCounter u32][signature 64] を直接組み立てる */
function joinFrame(pubkey: Uint8Array, signature: Uint8Array, powCounter = 0): Uint8Array {
  return Uint8Array.from([WireType.JOIN, ...pubkey, 0, 0, (powCounter >> 8) & 0xff, powCounter & 0xff, ...signature]);
}
/** 型ごとの、形式が正しい最小のフレーム (ハンドシェイク前の遮断を確かめる用) */
const minimalFrame = (t: WireType): Uint8Array => {
  switch (t) {
    case WireType.GOSSIP: return Uint8Array.of(t, 1, 2, 3); // 中身 (packet) が読めなくてもフレームは成立する
    case WireType.ONION_STEM: return Uint8Array.of(t, 1, 2, 3);
    case WireType.PEX_REQUEST: return Uint8Array.of(t);
    case WireType.PING: return WireCodec.encode(t, { nonce: 1 });
    case WireType.CATCHUP_REQ: return WireCodec.encode(t, { since: 1 });
    case WireType.SDP_RELAY: return WireCodec.encode(t, { targetPeerId: 'a'.repeat(32), senderId: 'b'.repeat(32), sdp: { type: 'offer', sdp: 'v=0' } });
    default: throw new Error('no sample');
  }
};

/**
 * A → B の接続を張るが、B は HELLO に JOIN を返さない。
 * A 側には「challenge を送ったが未検証の接続」が残るので、そこへ任意の JOIN を差し込める。
 */
async function pendingPair(aOpts: ConstructorParameters<typeof PeerManager>[3] = {}, bIdentity = bob) {
  const a = node(alice, { rateLimiter: new RateLimiter(LOOSE), ...aOpts });
  const b = node(bIdentity, { rateLimiter: new RateLimiter(LOOSE) });
  (b.pm as any).handleHello = () => {};
  a.pm.connect(bIdentity.peerId, true);
  await waitFor(() => {
    const p = a.pm.peers.get(bIdentity.peerId) as WebRTCPeer | undefined;
    return !!p?.isConnected && !!p?.challenge;
  });
  const peerOnA = a.pm.peers.get(bIdentity.peerId) as WebRTCPeer;
  const fp = peerOnA.dtlsFingerprints();
  // 署名者 (B) の視点: 自分の指紋 = A から見た remote、検証者の指紋 = A から見た local
  const binding: JoinBinding = { verifierId: alice.peerId, signerFingerprint: fp.remote, verifierFingerprint: fp.local };
  return { a, b, peerOnA, challenge: peerOnA.challenge!, binding, fp };
}

describe('PeerManager: HELLO / JOIN v4 ハンドシェイク', () => {
  beforeAll(async () => {
    await sodiumReady;
    installFakeWebRTC();
    [alice, bob, carol, mallory] = await Promise.all([1, 2, 3, 4].map(() => NodeIdentity.mine(FAST)));
  });

  beforeEach(() => {
    resetFakeWebRTC();
    hub = new SignalingHub();
    nodes = [];
  });

  afterEach(() => {
    for (const n of nodes) n.pm.stop();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  describe('正常系', () => {
    it('接続すると双方が相手を検証済みにし、公開鍵・PoW 解・接続の向きを記録する', async () => {
      const a = node(alice);
      const b = node(bob);
      a.pm.connect(bob.peerId, true);
      await waitFor(() => a.verified.includes(bob.peerId) && b.verified.includes(alice.peerId));

      const bOnA = a.pm.peers.get(bob.peerId) as WebRTCPeer;
      const aOnB = b.pm.peers.get(alice.peerId) as WebRTCPeer;
      expect(Array.from(bOnA.pubkey!)).toEqual(Array.from(bob.pubkey));
      expect(bOnA.powCounter).toBe(bob.powCounter);
      expect(bOnA.direction).toBe('outbound');
      expect(aOnB.direction).toBe('inbound');
      expect(bOnA.position).toBe(bob.position); // 座標は peerId から導出
      expect(a.pm.verifiedPeersWithKeys.map(p => p.peerId)).toEqual([bob.peerId]);
      expect(typeof bOnA.verifiedAt).toBe('number');
    });

    it('JOIN の署名は「この接続」(検証者 ID と両側の DTLS 指紋) に束縛されている', async () => {
      const a = node(alice);
      const b = node(bob);
      a.pm.connect(bob.peerId, true);
      await waitFor(() => a.verified.includes(bob.peerId));

      const join = joinsSent(b).find(s => s.to === alice.peerId)!.payload;
      const bOnA = a.pm.peers.get(bob.peerId) as WebRTCPeer;
      const fp = bOnA.dtlsFingerprints();
      expect(fp.local).toMatch(/^sha-256 /);
      expect(fp.remote).toMatch(/^sha-256 /);
      expect(fp.local).not.toBe(fp.remote);

      const binding = { verifierId: alice.peerId, signerFingerprint: fp.remote, verifierFingerprint: fp.local };
      expect(NodeIdentity.verifySignedClaim(join, bOnA.challenge!, binding, FAST)).toBe(true);
      expect(NodeIdentity.verifySignedClaim(join, bOnA.challenge!, { ...binding, signerFingerprint: fp.local, verifierFingerprint: fp.remote }, FAST)).toBe(false);
      expect(NodeIdentity.verifySignedClaim(join, bOnA.challenge!, { ...binding, verifierId: carol.peerId }, FAST)).toBe(false);
    });

    it('JOIN は接続ごとに一度だけ返し、challenge は接続ごとに異なる', async () => {
      const a = node(alice);
      const b = node(bob);
      const c = node(carol);
      a.pm.connect(bob.peerId, true);
      a.pm.connect(carol.peerId, true);
      await waitFor(() => a.verified.length === 2 && b.verified.length === 1 && c.verified.length === 1);

      expect(joinsSent(b)).toHaveLength(1);
      expect(joinsSent(c)).toHaveLength(1);
      const c1 = (a.pm.peers.get(bob.peerId) as WebRTCPeer).challenge!;
      const c2 = (a.pm.peers.get(carol.peerId) as WebRTCPeer).challenge!;
      expect(Buffer.from(c1).equals(Buffer.from(c2))).toBe(false);
    });

    it('検証が済む前の接続は degree には数えるが verifiedPeers には入れない', async () => {
      const { a } = await pendingPair();
      expect(a.pm.degree).toBe(1);
      expect(a.pm.verifiedPeers).toHaveLength(0);
      expect(a.pm.verifiedPeersWithKeys).toHaveLength(0);
    });
  });

  describe('JOIN の拒否 (切断するが、名乗られた ID は BAN しない)', () => {
    it('対照: 正しく束縛された JOIN は受理される', async () => {
      const { a, challenge, binding } = await pendingPair();
      inject(a, bob.peerId, WireType.JOIN, bob.signClaim(challenge, binding));
      expect(a.verified).toEqual([bob.peerId]);
      expect(a.pm.peers.get(bob.peerId)?.isVerified).toBe(true);
    });

    type Ctx = Awaited<ReturnType<typeof pendingPair>>;
    /** payload (WireCodec で符号化) か、生のフレームを返す */
    const rejectCases: Array<[string, (ctx: Ctx) => any]> = [
      ['自分が送ったのと違う challenge への署名', ({ binding }) => bob.signClaim(NodeIdentity.newChallenge(), binding)],
      ['B の公開鍵に、別人 (mallory) の秘密鍵で作った署名', ({ challenge, binding }) => ({
        ...bob.claim(), signature: mallory.signClaim(challenge, binding).signature,
      })],
      ['別の検証者 (carol) 向けに作られた署名', ({ challenge, binding }) => bob.signClaim(challenge, { ...binding, verifierId: carol.peerId })],
      ['別の接続の DTLS 指紋で作られた署名 (中継型 MITM)', ({ challenge, binding }) => bob.signClaim(challenge, { ...binding, signerFingerprint: 'sha-256 AA:BB:CC' })],
      ['検証者側の指紋を差し替えた署名', ({ challenge, binding }) => bob.signClaim(challenge, { ...binding, verifierFingerprint: 'sha-256 11:22:33' })],
      ['両側の指紋を入れ替えた署名', ({ challenge, binding }) => bob.signClaim(challenge, {
        ...binding, signerFingerprint: binding.verifierFingerprint, verifierFingerprint: binding.signerFingerprint,
      })],
      ['署名が 1 バイト壊れている', ({ challenge, binding }) => {
        const c = bob.signClaim(challenge, binding);
        const sig = c.signature.slice();
        sig[10] ^= 0x01;
        return { ...c, signature: sig };
      }],
      // ── 形式違反 (ワイヤで符号化できない形) ──
      ['署名が無い (フレームが 32+4 バイトで終わる)', () => joinFrame(bob.pubkey, new Uint8Array(0)),],
      ['署名が 1 バイト足りない', ({ challenge, binding }) => joinFrame(bob.pubkey, bob.signClaim(challenge, binding).signature.subarray(0, 63))],
      ['本体が空', () => Uint8Array.of(WireType.JOIN)],
      ['公開鍵の位置に msgpack の map を詰めた旧形式', () => Uint8Array.from([WireType.JOIN, 0x80, 0x81, 0xa1, 0x61, 0x01])],
    ];
    for (const [name, build] of rejectCases) {
      it(name, async () => {
        const ctx = await pendingPair();
        const built = build(ctx);
        const feed = () => (built instanceof Uint8Array ? injectRaw(ctx.a, bob.peerId, built) : inject(ctx.a, bob.peerId, WireType.JOIN, built));
        expect(feed).not.toThrow();
        expect(ctx.a.verified).toEqual([]);
        expect(ctx.a.pm.peers.has(bob.peerId)).toBe(false);
        expect(ctx.a.pm.misbehavior.isBanned(bob.peerId)).toBe(false);
        expect(ctx.a.pm.misbehavior.getScore(bob.peerId)).toBe(0);
      });
    }

    it('別人 (mallory) の完全に正当な JOIN をこの接続で名乗っても、どちらとしても登録しない', async () => {
      const { a, challenge, binding } = await pendingPair();
      inject(a, bob.peerId, WireType.JOIN, mallory.signClaim(challenge, binding));
      expect(a.pm.peers.has(bob.peerId)).toBe(false);
      expect(a.pm.peers.has(mallory.peerId)).toBe(false);
      expect(a.pm.misbehavior.isBanned(bob.peerId)).toBe(false);
      expect(a.pm.misbehavior.isBanned(mallory.peerId)).toBe(false);
    });

    it('傍受した JOIN を次の接続で再生 (replay) しても受理しない', async () => {
      const a1 = node(alice);
      const b1 = node(bob);
      a1.pm.connect(bob.peerId, true);
      await waitFor(() => a1.verified.includes(bob.peerId));
      const captured = joinsSent(b1).find(s => s.to === alice.peerId)!.payload;
      a1.pm.stop();
      b1.pm.stop();

      hub = new SignalingHub();
      const { a } = await pendingPair();
      inject(a, bob.peerId, WireType.JOIN, captured);
      expect(a.verified).toEqual([]);
      expect(a.pm.peers.has(bob.peerId)).toBe(false);
    });

    it('peerId を載せない JOIN: 署名が正しくても、pubkey から導かれる peerId が接続の相手と違えば受理しない (なりすまし)', async () => {
      // mallory の完全に正当な (pubkey, 署名) を、bob の名で張られた接続に送る。peerId はワイヤに無いので
      // 「名乗り」を偽ることはできず、導出される peerId (= mallory) が接続の peerId (= bob) と食い違う。
      const { a, challenge, binding } = await pendingPair();
      const join = mallory.signClaim(challenge, binding);
      expect(NodeIdentity.derivePeerId(join.pubkey)).not.toBe(bob.peerId);
      const spy = vi.spyOn(NodeIdentity, 'verifySignedClaim');
      inject(a, bob.peerId, WireType.JOIN, join);
      expect(spy).not.toHaveBeenCalled(); // 重い検証に入る前に弾く
      expect(a.verified).toEqual([]);
      expect(a.pm.peers.has(bob.peerId)).toBe(false);
      expect(a.pm.misbehavior.getScore(bob.peerId)).toBe(0);
    });

    it('JOIN の本体は 100 バイト (pubkey 32 + powCounter 4 + 署名 64)。peerId も challenge も運ばない', async () => {
      const { challenge, binding } = await pendingPair();
      const frame = WireCodec.encode(WireType.JOIN, bob.signClaim(challenge, binding));
      expect(frame.length).toBe(101);
      expect(Buffer.from(frame).includes(Buffer.from(bob.peerId, 'hex'))).toBe(false);
      expect(Buffer.from(frame).includes(Buffer.from(challenge))).toBe(false);
    });

    it('NodeId PoW を満たさない identity は、署名が正しくても受理しない', async () => {
      const POW8: NodeIdPowParams = { difficulty: 8, opsLimit: 1, memLimit: 8192 };
      let weak = await NodeIdentity.mine(FAST);
      while (NodeIdentity.verifyClaim(weak.claim(), POW8)) weak = await NodeIdentity.mine(FAST);

      const { a, challenge, binding } = await pendingPair({ powParams: POW8 }, weak);
      inject(a, weak.peerId, WireType.JOIN, weak.signClaim(challenge, { ...binding }));
      expect(a.verified).toEqual([]);
      expect(a.pm.peers.has(weak.peerId)).toBe(false);
    });

    it('HELLO を送る前 (challenge が無い) に届いた JOIN は無視し、接続も切らない', async () => {
      const a = node(alice, { rateLimiter: new RateLimiter(LOOSE) });
      a.pm.connect(carol.peerId, true); // carol はハブに居ないので接続は開かない
      const peer = a.pm.peers.get(carol.peerId) as WebRTCPeer;
      expect(peer.challenge).toBeNull();

      const fake = carol.signClaim(NodeIdentity.newChallenge(), { verifierId: alice.peerId, signerFingerprint: 'x', verifierFingerprint: 'y' });
      inject(a, carol.peerId, WireType.JOIN, fake);
      expect(a.pm.peers.get(carol.peerId)).toBe(peer);
      expect(peer.isVerified).toBe(false);
    });

    it('検証済みの接続に届いた JOIN の再送は、検証をやり直さずに無視する', async () => {
      const { a, challenge, binding } = await pendingPair();
      const join = bob.signClaim(challenge, binding);
      inject(a, bob.peerId, WireType.JOIN, join);
      expect(a.verified).toEqual([bob.peerId]);

      const spy = vi.spyOn(NodeIdentity, 'verifySignedClaim');
      inject(a, bob.peerId, WireType.JOIN, join);
      inject(a, bob.peerId, WireType.JOIN, mallory.signClaim(challenge, binding)); // 後から別人を名乗っても
      expect(spy).not.toHaveBeenCalled();
      expect(a.verified).toEqual([bob.peerId]);
      expect(a.pm.peers.get(bob.peerId)?.isVerified).toBe(true);
      expect(Array.from((a.pm.peers.get(bob.peerId) as WebRTCPeer).pubkey!)).toEqual(Array.from(bob.pubkey));
    });
  });

  describe('HELLO (署名を求められる側)', () => {
    it('長さの違う challenge には署名しない (署名オラクルにならない)', async () => {
      const { a, b } = await pendingPair();
      (b.pm as any).handleHello = (PeerManager.prototype as any).handleHello.bind(b.pm);
      const before = joinsSent(b).length;
      // ハンドラ単体 (ワイヤでは長さ違反のフレームは decode が先に落とす: WireCodec.test)
      for (const challenge of [new Uint8Array(0), new Uint8Array(5), new Uint8Array(33), 'abc', null]) {
        (b.pm as any).handleHello(alice.peerId, { challenge });
      }
      expect(joinsSent(b).length).toBe(before);

      // 正しい長さなら署名を返す (対照)
      inject(b, alice.peerId, WireType.HELLO, { challenge: NodeIdentity.newChallenge() });
      expect(joinsSent(b).length).toBe(before + 1);
      void a;
    });

    it('接続の無い相手からの HELLO には答えない', () => {
      const b = node(bob, { rateLimiter: new RateLimiter(LOOSE) });
      inject(b, carol.peerId, WireType.HELLO, { challenge: NodeIdentity.newChallenge() });
      expect(joinsSent(b)).toHaveLength(0);
    });
  });

  describe('DTLS 指紋が取れない環境 (fail-closed)', () => {
    function stripFingerprints(): () => void {
      const proto = (globalThis as any).RTCPeerConnection.prototype;
      const offer = proto.createOffer;
      const answer = proto.createAnswer;
      const strip = (d: any) => ({ ...d, sdp: d.sdp.replace(/a=fingerprint:[^\r\n]*\r\n/g, '') });
      proto.createOffer = async function () { return strip(await offer.call(this)); };
      proto.createAnswer = async function () { return strip(await answer.call(this)); };
      return () => {
        proto.createOffer = offer;
        proto.createAnswer = answer;
      };
    }

    it('既定では JOIN に署名せず、検証も成立せず、30 秒でハンドシェイク切れとして落とす', async () => {
      vi.useFakeTimers(LOGIC_FAKE_TIMERS);
      const restore = stripFingerprints();
      try {
        const a = node(alice);
        const b = node(bob);
        const helloA = vi.spyOn(a.pm as any, 'handleHello');
        const helloB = vi.spyOn(b.pm as any, 'handleHello');
        a.pm.connect(bob.peerId, true);
        await waitFor(() => helloA.mock.calls.length > 0 && helloB.mock.calls.length > 0);

        expect(joinsSent(a)).toHaveLength(0);
        expect(joinsSent(b)).toHaveLength(0);
        expect(a.pm.verifiedPeers).toHaveLength(0);
        expect(b.pm.verifiedPeers).toHaveLength(0);

        await vi.advanceTimersByTimeAsync(30_000);
        expect(a.pm.peers.size).toBe(0);
        expect(b.pm.peers.size).toBe(0);
      } finally {
        restore();
      }
    });

    it('相手が署名してきても、自分側で指紋が取れなければ受理しない', async () => {
      const restore = stripFingerprints();
      try {
        const { a, challenge } = await pendingPair();
        const join = bob.signClaim(challenge, { verifierId: alice.peerId, signerFingerprint: '', verifierFingerprint: '' });
        inject(a, bob.peerId, WireType.JOIN, join);
        expect(a.verified).toEqual([]);
        expect(a.pm.peers.has(bob.peerId)).toBe(false);
      } finally {
        restore();
      }
    });

    it('テスト用の allowMissingDtlsFingerprint を明示した場合だけ、束縛なしで検証が通る', async () => {
      const restore = stripFingerprints();
      try {
        const a = node(alice, { allowMissingDtlsFingerprint: true });
        const b = node(bob, { allowMissingDtlsFingerprint: true });
        a.pm.connect(bob.peerId, true);
        await waitFor(() => a.verified.includes(bob.peerId) && b.verified.includes(alice.peerId));
      } finally {
        restore();
      }
    });
  });

  describe('ハンドシェイク前の遮断とハンドシェイクのレート制限', () => {
    it('検証前の接続から届いた HELLO / JOIN 以外のメッセージはディスパッチしない (違反点も付けない)', async () => {
      const { a } = await pendingPair();
      const got: number[] = [];
      for (const t of [WireType.GOSSIP, WireType.PEX_REQUEST, WireType.CATCHUP_REQ, WireType.ONION_STEM, WireType.PING, WireType.SDP_RELAY]) {
        a.dispatcher.register(t, () => got.push(t));
        injectRaw(a, bob.peerId, minimalFrame(t));
      }
      expect(got).toEqual([]);
      expect(a.pm.peers.has(bob.peerId)).toBe(true);
      expect(a.pm.misbehavior.getScore(bob.peerId)).toBe(0);
    });

    it('検証が済めば同じメッセージが通る', async () => {
      const { a, challenge, binding } = await pendingPair();
      inject(a, bob.peerId, WireType.JOIN, bob.signClaim(challenge, binding));
      const got: number[] = [];
      a.dispatcher.register(WireType.PEX_REQUEST, () => got.push(1));
      inject(a, bob.peerId, WireType.PEX_REQUEST, {});
      expect(got).toEqual([1]);
    });

    it('HELLO / JOIN はまとめて 3 件までのバーストで、超えた JOIN は (正当でも) 捨てる。時間が経てば通る', async () => {
      let now = 1_000_000;
      const limiter = new RateLimiter(RATE_LIMITS, () => now);
      const { a, challenge, binding } = await pendingPair({ rateLimiter: limiter });
      // B は接続時に HELLO を 1 通送っている。残り 2 通を HELLO で使い切る
      const handshakeLeft = limiter.tokensFor(bob.peerId, 'handshake');
      expect(handshakeLeft).toBe(RATE_LIMITS.handshake.burst - 1);
      inject(a, bob.peerId, WireType.HELLO, { challenge: NodeIdentity.newChallenge() });
      inject(a, bob.peerId, WireType.HELLO, { challenge: NodeIdentity.newChallenge() });

      const join = bob.signClaim(challenge, binding);
      inject(a, bob.peerId, WireType.JOIN, join);
      expect(a.verified).toEqual([]);
      expect(a.pm.peers.has(bob.peerId)).toBe(true); // 捨てるだけで切断はしない

      now += 1000 / RATE_LIMITS.handshake.ratePerSec; // 1 トークン分
      inject(a, bob.peerId, WireType.JOIN, join);
      expect(a.verified).toEqual([bob.peerId]);
    });

    it('上限 (101B = 正規の JOIN の長さ) を超える JOIN はデコードせずに捨てる (切断も検証もしない)', async () => {
      const { a, challenge, binding } = await pendingPair();
      const join = bob.signClaim(challenge, binding);
      const spy = vi.spyOn(NodeIdentity, 'verifySignedClaim');
      injectRaw(a, bob.peerId, Uint8Array.from([...WireCodec.encode(WireType.JOIN, join), 0]));
      expect(spy).not.toHaveBeenCalled();
      expect(a.pm.peers.has(bob.peerId)).toBe(true);
      expect(a.verified).toEqual([]);

      inject(a, bob.peerId, WireType.JOIN, join);
      expect(a.verified).toEqual([bob.peerId]);
    });

    it('上限 (33B = 正規の HELLO の長さ) を超える HELLO には答えない', async () => {
      const { b } = await pendingPair();
      (b.pm as any).handleHello = (PeerManager.prototype as any).handleHello.bind(b.pm);
      const before = joinsSent(b).length;
      injectRaw(b, alice.peerId, Uint8Array.from([...WireCodec.encode(WireType.HELLO, { challenge: NodeIdentity.newChallenge() }), 0]));
      expect(joinsSent(b).length).toBe(before);
    });
  });
});

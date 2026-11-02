import { describe, it, expect, beforeEach, vi } from 'vitest';
import { PeerManager } from '../../src/network/PeerManager';
import { MessageDispatcher } from '../../src/network/MessageDispatcher';
import { NodeIdentity } from '../../src/crypto/NodeIdentity';
import { ViolationType } from '../../src/network/PeerMisbehaviorManager';
import { WireType } from '../../src/network/wire/WireTypes';
import { WireCodec } from '../../src/network/wire/WireCodec';

describe('PeerManager 要塞化 (Hardening Integration Tests)', () => {
  let identityA: NodeIdentity;
  let dispatcherA: MessageDispatcher;
  let mockSignaling: any;
  let peerManagerA: PeerManager;

  const BAD_PEER_ID = 'bad00000000000000000000000000001';

  beforeEach(async () => {
    identityA = await NodeIdentity.mine({ difficulty: 0, opsLimit: 1, memLimit: 8192 });
    dispatcherA = new MessageDispatcher();
    mockSignaling = {
      connect: vi.fn().mockResolvedValue(undefined),
      disconnect: vi.fn(),
      sendRelay: vi.fn(),
      on: vi.fn(),
      isConnected: false,
    };

    peerManagerA = new PeerManager(identityA, dispatcherA, mockSignaling, {
      powParams: { difficulty: 0, opsLimit: 1, memLimit: 8192 },
    });
  });

  it('検証済みピアが壊れたワイヤデータを送ったら即座にBANし切断する', () => {
    const verifiedPeer: any = { isVerified: true, isConnected: true, close: vi.fn() };
    (peerManagerA as any)._peers.set(BAD_PEER_ID, verifiedPeer);

    (peerManagerA as any).handleData(BAD_PEER_ID, new Uint8Array([0x99, 0xff, 0x00]));

    expect(peerManagerA.misbehavior.isBanned(BAD_PEER_ID)).toBe(true);
    expect(peerManagerA.peers.has(BAD_PEER_ID)).toBe(false);
  });

  it('未検証の接続が壊れたデータを送っても、名乗られた ID は BAN せず切断だけする', () => {
    const unverified: any = { isVerified: false, isConnected: true, close: vi.fn() };
    (peerManagerA as any)._peers.set(BAD_PEER_ID, unverified);

    (peerManagerA as any).handleData(BAD_PEER_ID, new Uint8Array([0x99, 0xff, 0x00]));

    expect(peerManagerA.misbehavior.isBanned(BAD_PEER_ID)).toBe(false);
    expect(peerManagerA.peers.has(BAD_PEER_ID)).toBe(false);
  });

  it('BANされたピアに対する新規接続の試行を拒絶する', () => {
    peerManagerA.misbehavior.banPeer(BAD_PEER_ID, 10000, 'Test pre-ban');
    expect(peerManagerA.misbehavior.isBanned(BAD_PEER_ID)).toBe(true);

    const peer = peerManagerA.connect(BAD_PEER_ID, true);
    expect(peer).toBeUndefined();
  });

  it('BANされたピアからのリレーメッセージをサイレントに無視する', () => {
    peerManagerA.misbehavior.banPeer(BAD_PEER_ID, 10000, 'Test ban');

    // handleRelay を呼んでも接続処理が走らないこと
    (peerManagerA as any).handleRelay(BAD_PEER_ID, {
      type: 'offer',
      sdp: { type: 'offer', sdp: 'fake-sdp' },
    });

    expect(peerManagerA.peers.has(BAD_PEER_ID)).toBe(false);
  });

  it('JOIN時に名乗りと接続IDが不一致なら切断するが、名乗られた ID は BAN しない', () => {
    const fakePeer: any = {
      isVerified: false,
      challenge: new Uint8Array(32),
      markVerified: vi.fn(),
      close: vi.fn(),
    };
    (peerManagerA as any)._peers.set(BAD_PEER_ID, fakePeer);

    (peerManagerA as any).handleJoin(BAD_PEER_ID, {
      peerId: 'spoofed0000000000000000000000002', // 詐称ID
      pubkey: new Uint8Array(32),
      powCounter: 0,
      challenge: new Uint8Array(32),
      signature: new Uint8Array(64),
    });

    expect(fakePeer.markVerified).not.toHaveBeenCalled();
    expect(peerManagerA.peers.has(BAD_PEER_ID)).toBe(false);
    // 接続の peerId はシグナリングで名乗られただけの値。第三者を陥れられないこと
    expect(peerManagerA.misbehavior.isBanned(BAD_PEER_ID)).toBe(false);
  });

  it('検証済みの生きた接続は、同じ ID を名乗る offer で置き換えられない', () => {
    const VICTIM = 'abc00000000000000000000000000001';
    const live: any = { peerId: VICTIM, isVerified: true, isConnected: true, close: vi.fn(), signal: vi.fn() };
    (peerManagerA as any)._peers.set(VICTIM, live);

    (peerManagerA as any).handleRelay(VICTIM, { type: 'sdp-relay', sdp: { type: 'offer', sdp: 'x' } });

    expect(live.close).not.toHaveBeenCalled();
    expect(peerManagerA.peers.get(VICTIM)).toBe(live);
  });

  it('ハンドシェイク未完了の接続数に上限があり、乱数 ID の offer で無制限に増えない', () => {
    (globalThis as any).RTCPeerConnection = class {
      createDataChannel() { return {}; }
      createOffer() { return new Promise(() => {}); }
      close() {}
    };
    for (let i = 0; i < 50; i++) {
      peerManagerA.connect(i.toString(16).padStart(32, '0'), true);
    }
    expect(peerManagerA.peers.size).toBeLessThanOrEqual(8);
    delete (globalThis as any).RTCPeerConnection;
  });

  describe('レート制限 (H2)', () => {
    const PEER = 'cafe0000000000000000000000000001';

    function attachVerified() {
      const peer: any = { peerId: PEER, isVerified: true, isConnected: true, close: vi.fn(), send: vi.fn() };
      (peerManagerA as any)._peers.set(PEER, peer);
      return peer;
    }

    it('以前は表から漏れていた PING や追いつき (CATCHUP_REQ) も制限され、超過しても BAN はしない', () => {
      attachVerified();
      const seen = { catchup: 0, ping: 0 };
      dispatcherA.register(WireType.CATCHUP_REQ, () => seen.catchup++);
      dispatcherA.register(WireType.PING, () => seen.ping++);

      for (let i = 0; i < 500; i++) {
        (peerManagerA as any).handleData(PEER, WireCodec.encode(WireType.CATCHUP_REQ, { since: 1 }));
        (peerManagerA as any).handleData(PEER, WireCodec.encode(WireType.PING, { nonce: i }));
      }
      expect(seen.catchup).toBeLessThan(500);
      expect(seen.ping).toBeLessThan(500);
      // 正直な隣人でも一時的に超えうるので、点は付けない (BAN の連鎖を起こさない)
      expect(peerManagerA.misbehavior.getScore(PEER)).toBe(0);
      expect(peerManagerA.peers.has(PEER)).toBe(true);
    });

    it('WireType ごとの上限を超える巨大フレームはデコードせずに捨てる', () => {
      attachVerified();
      let delivered = 0;
      dispatcherA.register(WireType.GOSSIP, () => delivered++);
      const huge = WireCodec.encode(WireType.GOSSIP, { packet: new Uint8Array(64 * 1024) });
      (peerManagerA as any).handleData(PEER, huge);
      expect(delivered).toBe(0);
    });
  });

  it('stop() 後はトラッカーへの再アナウンスも新規接続も行わない (H5)', async () => {
    vi.useFakeTimers();
    try {
      await peerManagerA.start();
      expect(mockSignaling.connect).toHaveBeenCalledTimes(1);

      peerManagerA.stop();
      await vi.advanceTimersByTimeAsync(5 * 60 * 1000);

      // 次数 0 のままでも、停止後は再アナウンスしない
      expect(mockSignaling.connect).toHaveBeenCalledTimes(1);
      expect(peerManagerA.connect('beef0000000000000000000000000001', true)).toBeUndefined();
    } finally {
      vi.useRealTimers();
    }
  });

  describe('握手の途中に届いたフレーム (相手が先にこちらを検証済みにした)', () => {
    const PEER = 'abc00000000000000000000000000077';
    const frame = () => WireCodec.encode(WireType.LEASESET_SYNC_REQ, {});
    const conn = (over: Record<string, any> = {}): any => ({ peerId: PEER, isVerified: false, isConnected: true, close: vi.fn(), send: vi.fn(), ...over });
    const verify = (c: any) => {
      c.isVerified = true;
      (peerManagerA as any).flushPreVerify(PEER);
    };

    it('★検証が済むまで処理せず、済んだら届いた順に処理する (要求や flood を捨てない)', () => {
      const got: string[] = [];
      dispatcherA.register(WireType.LEASESET_SYNC_REQ, () => got.push('sync'));
      dispatcherA.register(WireType.LEASESET_SYNC, () => got.push('data'));
      const c = conn();
      (peerManagerA as any)._peers.set(PEER, c);
      (peerManagerA as any).handleData(PEER, frame());
      (peerManagerA as any).handleData(PEER, WireCodec.encode(WireType.LEASESET_SYNC, { leaseSets: [] }));
      expect(got).toEqual([]);
      verify(c);
      expect(got).toEqual(['sync', 'data']);
      // 2 度は処理しない
      (peerManagerA as any).flushPreVerify(PEER);
      expect(got).toEqual(['sync', 'data']);
    });

    it('★握手が失敗した・切れたら捨てる。同じ ID を名乗った別の接続の分は、後で本物が検証されても処理しない', () => {
      const got: number[] = [];
      dispatcherA.register(WireType.LEASESET_SYNC_REQ, () => got.push(1));
      const impostor = conn();
      (peerManagerA as any)._peers.set(PEER, impostor);
      (peerManagerA as any).handleData(PEER, frame());
      peerManagerA.disconnect(PEER);
      const real = conn();
      (peerManagerA as any)._peers.set(PEER, real);
      verify(real);
      expect(got).toEqual([]);

      // 切断を経ずに接続が差し替わった場合も、検証したのと別の接続の分は処理しない
      const a = conn();
      (peerManagerA as any)._peers.set(PEER, a);
      (peerManagerA as any).handleData(PEER, frame());
      const b = conn();
      (peerManagerA as any)._peers.set(PEER, b);
      verify(b);
      expect(got).toEqual([]);
    });

    it('取っておくのは上限まで (件数)。超えた分は捨てて数える', () => {
      let n = 0;
      dispatcherA.register(WireType.LEASESET_SYNC_REQ, () => n++);
      const c = conn();
      (peerManagerA as any)._peers.set(PEER, c);
      for (let i = 0; i < 40; i++) (peerManagerA as any).handleData(PEER, frame());
      verify(c);
      expect(n).toBeLessThan(40);
      expect(n).toBeGreaterThan(0);
      expect(peerManagerA.preVerifyDropped).toBe(40 - n);
    });
  });
});

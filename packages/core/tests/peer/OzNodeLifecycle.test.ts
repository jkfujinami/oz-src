import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest';
import 'fake-indexeddb/auto';
import { sodiumReady } from '../../src/crypto/sodium';
import { OzNode } from '../../src/node/OzNode';
import { IndexedDBStore, WrongPassphraseError } from '../../src/storage/IndexedDBStore';
import { VAULT_PARAMS_FAST } from '../../src/storage/SecretVault';
import { NodeIdentity } from '../../src/crypto/NodeIdentity';
import { NodeIdentityStore } from '../../src/crypto/NodeIdentityStore';
import { WireType } from '../../src/network/wire/WireTypes';
import { WireCodec } from '../../src/network/wire/WireCodec';
import { LOGIC_FAKE_TIMERS } from '../helpers/logicHarness';

const FAST = { difficulty: 0, opsLimit: 1, memLimit: 8192 };
const PASS = 'lifecycle-pass';

let seq = 0;
const freshName = () => `lifecycle_${Date.now()}_${seq++}`;

function signalingMock() {
  return {
    connect: vi.fn().mockResolvedValue(undefined),
    disconnect: vi.fn(),
    sendRelay: vi.fn(),
    on: vi.fn(),
    isConnected: false,
  };
}

async function makeNode(opts: { name?: string; db?: IndexedDBStore; passphrase?: string; signaling?: any; autoStart?: boolean } = {}) {
  const signaling = opts.signaling ?? signalingMock();
  const db = opts.db ?? new IndexedDBStore(opts.name ?? freshName());
  const node = await OzNode.create({
    db,
    signalingClient: signaling,
    autoStart: opts.autoStart ?? false,
    passphrase: opts.passphrase ?? PASS,
    vaultParams: VAULT_PARAMS_FAST,
    circuit: { coverIntervalMs: 50, relayDelayMs: 1, echoTimeoutMs: 1000 },
    // ★ 枠の PoW (本番は 1 枠 約 2 秒) を裏で解くと、全体のテストで CPU が混んだときに stop() の検査が
    //   5 秒を超えて落ちた。ここで見たいのはタイマーと送信の後始末なので、PoW は軽くする
    storage: { slotEffort: 1, chunkEffort: 1 },
  });
  return { node, signaling, db };
}

/** 検証済みの隣人として振る舞う最小の接続 (送信を記録する) */
function attachPeer(node: OzNode, n: number) {
  const id = n.toString(16).padStart(32, '0');
  const peer: any = {
    peerId: id, position: (n * 0.137) % 1, rtt: 0, isConnected: true, isConnecting: false, isVerified: true,
    direction: 'outbound', verifiedAt: Date.now(), netGroup: 'unknown', pubkey: new Uint8Array(32), powCounter: 0,
    send: vi.fn(), close: vi.fn(),
  };
  (node.peerManager as any)._peers.set(id, peer);
  return peer;
}

describe('OzNode のライフサイクル', () => {
  beforeAll(async () => {
    await sodiumReady;
  });

  beforeEach(() => {
    // 既定の NodeId PoW (数秒) を避ける。識別子の性質はここでは問わない
    vi.spyOn(NodeIdentityStore, 'mineEphemeral').mockImplementation(() => NodeIdentity.mine(FAST));
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('create → start → stop。stop は終端で、再開・設定変更はできない', async () => {
    const { node, signaling } = await makeNode();
    expect(node.running).toBe(false);
    expect(node.db.isUnlocked).toBe(true);
    expect(signaling.connect).not.toHaveBeenCalled(); // autoStart:false なら網に出ない

    await node.start();
    expect(node.running).toBe(true);
    expect(signaling.connect).toHaveBeenCalledTimes(1);

    await node.start(); // 二重起動しない
    expect(signaling.connect).toHaveBeenCalledTimes(1);

    await node.stop();
    expect(node.running).toBe(false);
    expect(node.db.isUnlocked).toBe(false); // メモリ上のデータ鍵を消す
    expect(signaling.disconnect).toHaveBeenCalled();

    await expect(node.start()).rejects.toThrow(/cannot be restarted/);
    await expect(node.setTrackerUrl(null)).rejects.toThrow(/stopped/);
    await expect(node.stop()).resolves.toBeUndefined(); // 二重停止は何もしない
  });

  it('autoStart:true なら生成と同時に網へ参加する', async () => {
    const { node, signaling } = await makeNode({ autoStart: true });
    expect(node.running).toBe(true);
    expect(signaling.connect).toHaveBeenCalledTimes(1);
    await node.stop();
  });

  it('トラッカーに届かなくても start() は失敗せず、起動状態になる', async () => {
    const signaling = signalingMock();
    signaling.connect.mockRejectedValue(new Error('unreachable'));
    const { node } = await makeNode({ signaling });
    await expect(node.start()).resolves.toBeUndefined();
    expect(node.running).toBe(true);
    await node.stop();
  });

  it('stop() は全タイマーを解放し、以後は網へ何も送らない (トラッカー・隣人とも)', async () => {
    vi.useFakeTimers(LOGIC_FAKE_TIMERS);
    const { node, signaling } = await makeNode();
    const peers = [1, 2, 3].map(n => attachPeer(node, n));
    await node.start();

    // 対照: 動いている間は heartbeat などで隣人へ送信がある
    await vi.advanceTimersByTimeAsync(20_000);
    const sentWhileRunning = peers.reduce((a, p) => a + p.send.mock.calls.length, 0);
    expect(sentWhileRunning).toBeGreaterThan(0);

    await node.stop();
    for (const p of peers) expect(p.close).toHaveBeenCalled();
    expect(node.peerManager.peers.size).toBe(0);
    expect(vi.getTimerCount()).toBe(0);

    const sends = peers.map(p => p.send.mock.calls.length);
    const tracker = { connect: signaling.connect.mock.calls.length, relay: signaling.sendRelay.mock.calls.length };
    await vi.advanceTimersByTimeAsync(60 * 60 * 1000);
    expect(peers.map(p => p.send.mock.calls.length)).toEqual(sends);
    expect(signaling.connect.mock.calls.length).toBe(tracker.connect);
    expect(signaling.sendRelay.mock.calls.length).toBe(tracker.relay);
  });

  it('stop() 後に届いたデータ・シグナル・トラッカーのピア一覧には反応しない', async () => {
    const { node, signaling } = await makeNode();
    await node.start();
    await node.stop();

    const pm = node.peerManager as any;
    pm.handleRelay('a'.repeat(32), { type: 'sdp-relay', sdp: { type: 'offer', sdp: 'v=0' } });
    pm.handleTrackerPeers([{ peerId: 'b'.repeat(32) }]);
    pm.handleData('c'.repeat(32), WireCodec.encode(WireType.PING, { nonce: 1 }));
    expect(node.peerManager.peers.size).toBe(0);
    expect(node.peerManager.connect('d'.repeat(32), true)).toBeUndefined();
    expect(signaling.sendRelay).not.toHaveBeenCalled();
  });

  it('stop() は板・スレッドの購読も外す (停止後に届いたパケットを処理しない)', async () => {
    const { node } = await makeNode();
    const key = new Uint8Array(32).fill(7);
    await node.boardOrchestrator.activate('vip', key);
    await node.stop();
    expect(node.boardOrchestrator.getThreads()).toEqual([]);
    expect((node.boardOrchestrator as any).isListening).toBe(false);
    expect((node.threadOrchestrator as any).isListening).toBe(false);
  });

  describe('パスワード', () => {
    it('同じ DB を違うパスワードで開こうとすると WrongPassphraseError になり、ロックされたまま', async () => {
      const name = freshName();
      const first = await makeNode({ name });
      await first.node.db.saveBoard('vip', new Uint8Array([1, 2, 3]));
      await first.node.stop();

      const db = new IndexedDBStore(name);
      await expect(makeNode({ db, passphrase: 'wrong-pass' })).rejects.toBeInstanceOf(WrongPassphraseError);
      expect(db.isUnlocked).toBe(false);

      const again = await makeNode({ db, passphrase: PASS });
      expect(await again.node.db.getBoardKey('vip')).toEqual(new Uint8Array([1, 2, 3]));
      await again.node.stop();
    });

    it('停止したノードの DB インスタンスを使い回しても、パスワードの照合は省略されない', async () => {
      const { node, db } = await makeNode();
      await node.stop();
      await expect(makeNode({ db, passphrase: 'not-the-password' })).rejects.toBeInstanceOf(WrongPassphraseError);
    });

    it('空のパスワードでは作れない (DB には鍵の封印も作らない)', async () => {
      const db = new IndexedDBStore(freshName());
      await expect(makeNode({ db, passphrase: '' })).rejects.toBeInstanceOf(RangeError);
      expect(await db.hasVault()).toBe(false);
    });

    it('不正なトラッカー URL は、鍵の導出や DB の解錠より前に拒否する', async () => {
      const db = new IndexedDBStore(freshName());
      await expect(OzNode.create({ db, trackerUrl: 'http://tracker.example/ws', passphrase: PASS, vaultParams: VAULT_PARAMS_FAST }))
        .rejects.toThrow(/invalid tracker URL/);
      expect(await db.hasVault()).toBe(false);
      expect(db.isUnlocked).toBe(false);
    });

    it('起動の途中で失敗したら、データ鍵をメモリに残さない', async () => {
      vi.mocked(NodeIdentityStore.mineEphemeral).mockRejectedValueOnce(new Error('mining failed'));
      const db = new IndexedDBStore(freshName());
      await expect(makeNode({ db })).rejects.toThrow('mining failed');
      expect(db.isUnlocked).toBe(false);
    });

    it('トリップはパスワードで封印され、次の起動で同じパスワードなら復元される', async () => {
      const name = freshName();
      const first = await makeNode({ name });
      const display = await first.node.identity.generateTrip(first.node.db);
      await first.node.stop();

      const second = await makeNode({ name });
      expect(second.node.identity.hasTrip).toBe(true);
      expect(second.node.identity.tripDisplay).toBe(display);
      await second.node.stop();
    });

    it('既定 (ephemeral) ではノード鍵を保存せず、起動ごとに採掘し直す', async () => {
      const loadOrMine = vi.spyOn(NodeIdentityStore, 'loadOrMine');
      const name = freshName();
      const a = await makeNode({ name });
      const idA = a.node.peerId;
      await a.node.stop();
      const b = await makeNode({ name });
      expect(NodeIdentityStore.mineEphemeral).toHaveBeenCalledTimes(2);
      expect(loadOrMine).not.toHaveBeenCalled();
      expect(await b.node.db.getSealed('node')).toBeUndefined();
      expect(b.node.peerId).not.toBe(idA);
      expect(b.node.peerId).toMatch(/^[0-9a-f]{32}$/);
      await b.node.stop();
    });
  });

  describe('パニックワイプ', () => {
    it('通信を止め、DB を丸ごと消す。同じ名前で開き直しても何も残っていない', async () => {
      const name = freshName();
      const { node, signaling } = await makeNode({ name });
      await node.start();
      await node.db.saveBoard('vip', new Uint8Array([9, 9, 9]));
      await node.db.save({ boardId: 'vip', threadId: 't', payload: new Uint8Array([1]) });

      await node.panicWipe();
      expect(node.running).toBe(false);
      expect(signaling.disconnect).toHaveBeenCalled();
      await expect(node.start()).rejects.toThrow();

      const reopened = new IndexedDBStore(name);
      expect(await reopened.hasVault()).toBe(false);
      // 別のパスワードでも「新規」として開ける = 古い鍵の封印は残っていない
      await reopened.unlock('brand-new-pass', VAULT_PARAMS_FAST);
      expect(await reopened.listBoards()).toEqual([]);
      expect(await reopened.getPosts('vip', 't')).toEqual([]);
    });

    it('起動前のノードでもパニックワイプできる', async () => {
      const name = freshName();
      const { node } = await makeNode({ name });
      await node.panicWipe();
      expect(await new IndexedDBStore(name).hasVault()).toBe(false);
    });
  });
});

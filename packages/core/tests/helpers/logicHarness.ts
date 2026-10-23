import { vi } from 'vitest';
import 'fake-indexeddb/auto';
import sodium from '../../src/crypto/sodium';
import { IndexedDBStore } from '../../src/storage/IndexedDBStore';
import { VAULT_PARAMS_FAST } from '../../src/storage/SecretVault';
import { CryptoEngine } from '../../src/crypto/CryptoEngine';
import { KeyManager } from '../../src/crypto/KeyManager';
import { PacketBuilder } from '../../src/crypto/PacketBuilder';
import { encodePacket } from '../../src/crypto/PacketCodec';
import { fakePowEngine, realPowEngine } from './postFixtures';
import type { GossipPacket, IIdentity } from '../../src/types';
import { GossipRouter } from '../../src/network/gossip/GossipRouter';

/**
 * オーケストレータ (BoardOrchestrator / ThreadOrchestrator) の単体テスト用の部品。
 * ネットワーク側 (PeerManager / GossipRouter) は最小の代役にし、
 * 暗号・パケット・永続化 (暗号化 IndexedDB) は本物を使う。
 */

export const keyMgr = {
  deriveThreadKey: KeyManager.deriveThreadKey,
};

/**
 * オーケストレータの投稿 (submitReply / submitThread) に渡す PoW。解かない代役 (fakePowEngine)。
 * FakeRouter を通る単体テストでは検証 (PacketValidator) を通らないので、解く必要が無く速い。
 * 検証を通すパケットは buildReplyPacket / buildThreadMetaPacket (既定は本物の Equi-X) で作る。
 */
export const syncPow = fakePowEngine;

export const PASS = 'logic-test-passphrase';

let dbSeq = 0;
export async function unlockedStore(name = `logic_${Date.now()}_${dbSeq++}`, pass = PASS): Promise<IndexedDBStore> {
  const db = new IndexedDBStore(name);
  await db.init();
  await db.unlock(pass, VAULT_PARAMS_FAST);
  return db;
}

export class FakePeerManager {
  public peers = new Map<string, any>();
  public myPeerId = 'f'.repeat(32);
  public myPosition = 0.5;
  public degreeOverride: number | null = null;
  private handlers = new Map<string, Set<(...a: any[]) => void>>();
  public sendMessage = vi.fn();
  public connect = vi.fn();
  public disconnect = vi.fn();

  get degree(): number {
    return this.degreeOverride ?? this.peers.size;
  }
  on(ev: string, h: (...a: any[]) => void) {
    if (!this.handlers.has(ev)) this.handlers.set(ev, new Set());
    this.handlers.get(ev)!.add(h);
  }
  off(ev: string, h: (...a: any[]) => void) {
    this.handlers.get(ev)?.delete(h);
  }
  listenerCount(ev: string): number {
    return this.handlers.get(ev)?.size ?? 0;
  }
  emit(ev: string, ...args: any[]) {
    for (const h of Array.from(this.handlers.get(ev) ?? [])) h(...args);
  }
  /** 隣人を 1 人足して peer:connect を出す */
  addPeer(id = (this.peers.size + 1).toString(16).padStart(32, '0')) {
    const peer = { peerId: id, isConnected: true, isVerified: true, position: 0.1 };
    this.peers.set(id, peer);
    this.emit('peer:connect', peer);
    return peer;
  }
}

export class FakeRouter {
  public listeners = new Set<(p: any) => any>();
  public broadcast = vi.fn(async (_packet: GossipPacket) => true);
  /** 直近に見た投稿 (GossipRouter.recentPackets の代役)。テストが直接入れる */
  public recent: GossipPacket[] = [];
  recentPackets(): GossipPacket[] { return this.recent; }
  onMessage(h: (p: any) => any) { this.listeners.add(h); }
  offMessage(h: (p: any) => any) { this.listeners.delete(h); }
  /** 網から GOSSIP が届いたことにする (リスナーの完了まで待つ) */
  async deliver(packet: any) {
    await Promise.all(Array.from(this.listeners).map(l => l(packet)));
  }
}

/** 追いつきの進み具合の代役 (CatchupProgress)。active を切り替えて通知する */
export class FakeCatchup {
  public active = false;
  private cbs = new Set<() => void>();
  onChange(cb: () => void) { this.cbs.add(cb); return () => { this.cbs.delete(cb); }; }
  set(active: boolean) { this.active = active; this.cbs.forEach(cb => cb()); }
}

/** 任意のトリップ鍵・署名を持たせられる署名者 (なりすましの再現用) */
export function customSigner(opts: {
  trip?: { publicKey: Uint8Array; privateKey: Uint8Array } | null;
  forgeTripSig?: boolean;
  tripPubkeyOnly?: Uint8Array;
} = {}): IIdentity {
  const session = sodium.crypto_sign_keypair();
  return {
    // ★ 署名ブロックの形 (トリップ有りはトリップだけ) は hasTrip で決まる。
    //   偽造の再現 (他人の公開鍵 + 偽の署名) では、trip を持たせずに tripPubkeyOnly を指定する
    hasTrip: !!(opts.trip || opts.tripPubkeyOnly),
    sign: (data: Uint8Array) => ({
      sessionPubkey: session.publicKey,
      sessionSignature: sodium.crypto_sign_detached(data, session.privateKey),
      tripPubkey: opts.tripPubkeyOnly ?? opts.trip?.publicKey ?? null,
      tripSignature: opts.forgeTripSig
        ? new Uint8Array(64)
        : opts.trip
          ? sodium.crypto_sign_detached(data, opts.trip.privateKey)
          : null,
    }),
  };
}

/**
 * 板のスレッド作成パケット (post_type=1) を作る。boardKey で暗号化される。
 * PoW は既定で解かない (FakeRouter は検証を通さない)。PacketValidator を通すなら pow: 'real'
 */
export async function buildThreadMetaPacket(
  boardKey: Uint8Array,
  boardId: string,
  threadId: string,
  title: string,
  signer: IIdentity,
  _depth = 0,
  opts: { pow?: 'real' | 'fake'; now?: number } = {},
): Promise<GossipPacket> {
  return PacketBuilder.build({
    content: title, key: boardKey, identity: signer, cryptoEngine: new CryptoEngine(),
    powEngine: opts.pow === 'real' ? realPowEngine : fakePowEngine,
    boardId, threadId, postType: 1, now: opts.now,
  });
}

/** スレッドへの返信パケット (post_type=0) を作る。threadKey で暗号化される。PoW は既定で解かない (pow: 'real' で本物) */
export async function buildReplyPacket(
  threadKey: Uint8Array,
  boardId: string,
  threadId: string,
  text: string,
  signer: IIdentity,
  dag: { parents?: string[]; postType?: number; depth?: number; pow?: 'real' | 'fake'; now?: number } = {},
): Promise<GossipPacket> {
  return PacketBuilder.build({
    content: text, key: threadKey, identity: signer, cryptoEngine: new CryptoEngine(),
    powEngine: dag.pow === 'real' ? realPowEngine : fakePowEngine,
    boardId, threadId, postType: dag.postType ?? 0, parents: dag.parents ?? [], now: dag.now,
  });
}

/** Slot 本体と同じ形 (PacketCodec のコンパクト形式) にする */
export function encodeBody(packet: any): Uint8Array {
  return encodePacket(packet);
}

/**
 * 条件が満たされるまで待つ。固定 sleep は使わない。
 * setTimeout / Date を偽装しているテストでも動くよう、setImmediate と performance.now で回す。
 */
export async function waitFor(cond: () => boolean, timeoutMs = 3000): Promise<void> {
  const deadline = performance.now() + timeoutMs;
  while (!cond()) {
    if (performance.now() > deadline) throw new Error('waitFor: condition not met in time');
    await new Promise(r => setImmediate(r));
  }
}

/** IndexedDB を止めずに偽装するタイマー (fake-indexeddb は setImmediate で動く) */
export const LOGIC_FAKE_TIMERS = { toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date'] as any };

/** 未処理のマイクロタスク / IndexedDB のコールバックを流す */
export async function flush(rounds = 5): Promise<void> {
  for (let i = 0; i < rounds; i++) await new Promise(r => setImmediate(r));
}

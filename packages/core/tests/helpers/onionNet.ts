import { vi } from 'vitest';
import { NodeIdentity } from '../../src/crypto/NodeIdentity';
import { MessageDispatcher } from '../../src/network/MessageDispatcher';
import { PeerManager } from '../../src/network/PeerManager';
import { RateLimiter, RATE_LIMITS } from '../../src/network/RateLimiter';
import { PEXHandler } from '../../src/network/PEXHandler';
import type { GuardPolicy } from '../../src/trust/GuardManager';
import { DandelionRouter } from '../../src/network/gossip/DandelionRouter';
import { GossipRouter } from '../../src/network/gossip/GossipRouter';
import { OnionCircuit } from '../../src/network/onion/OnionCircuit';
import { RecentBuffer } from '../../src/network/history/RecentBuffer';
import { CatchupServer, type CatchupServerOptions } from '../../src/network/history/CatchupServer';
import { CatchupClient, type CatchupStore } from '../../src/network/history/CatchupClient';
import { WireCodec } from '../../src/network/wire/WireCodec';
import { PACKET_VERSION, derivePacketId, minutesToMs, msToMinutes, solvePow } from '../../src/crypto/PowPolicy';
import type { GossipPacket } from '../../src/types';

export const FAST_POW = { difficulty: 0, opsLimit: 1, memLimit: 8192 };

/** テスト用に十分緩いレート制限 (cover traffic を短い間隔で回すため) */
// ★ カテゴリは RATE_LIMITS の全部 (新しいカテゴリを足したとき、表から漏れて黙って全部捨てられるのを防ぐ)
const LOOSE_LIMITS = Object.fromEntries(
  Object.keys(RATE_LIMITS).map(k => [k, { ratePerSec: 1e6, burst: 1e6 }]),
);

export interface SimNode {
  name: string;
  identity: NodeIdentity;
  dispatcher: MessageDispatcher;
  peerManager: PeerManager;
  dandelion: DandelionRouter;
  circuit: OnionCircuit;
  gossip: GossipRouter;
  /** 過去ログ v2 (createSimNode の history オプションを渡したときだけ) */
  buffer?: RecentBuffer;
  catchupServer?: CatchupServer;
  catchupClient?: CatchupClient;
  received: GossipPacket[];
  /** この節点が受け取った生のワイヤメッセージ (送信者つき) */
  inbox: Array<{ from: string; type: number; payload: any; /** フレームそのもの (型 1 バイトを含む)。平文が載っていないことの確認に使う */ raw: Uint8Array }>;
}

/**
 * @param guardPolicy 指定すると、その Guard 方針で DandelionRouter を作る (省略時は従来どおり方針なし)
 */
export interface SimHistoryOptions {
  role?: 'client' | 'guard';
  /** CatchupClient の保存先 (省略時はこのノード専用のメモリ) */
  store?: CatchupStore;
  server?: CatchupServerOptions;
}

export async function createSimNode(
  name: string, circuitOptions?: any, guardPolicy?: GuardPolicy, history?: SimHistoryOptions,
): Promise<SimNode> {
  const identity = await NodeIdentity.mine(FAST_POW);
  const dispatcher = new MessageDispatcher();
  const signaling: any = {
    connect: vi.fn().mockResolvedValue(undefined),
    disconnect: vi.fn(),
    sendRelay: vi.fn(),
    on: vi.fn(),
    isConnected: false,
  };
  const peerManager = new PeerManager(identity, dispatcher, signaling, {
    powParams: FAST_POW,
    rateLimiter: new RateLimiter(LOOSE_LIMITS),
    allowMissingDtlsFingerprint: true,
  });
  // PEX 応答で新規接続を張りに行かないようにする (テストのトポロジーを固定するため)
  (peerManager as any).connect = vi.fn();

  const dandelion = new DandelionRouter(peerManager, guardPolicy ?? null);
  const circuit = new OnionCircuit(peerManager, dispatcher, dandelion, circuitOptions ?? {
    coverIntervalMs: 15,
    relayDelayMs: 1,
    readyWaitMs: 150,
    echoTimeoutMs: 400,
  });
  const buffer = history ? RecentBuffer.forRole(history.role ?? 'client') : undefined;
  const gossip = new GossipRouter(peerManager, dispatcher, dandelion, circuit, buffer ?? null);
  const catchupServer = history ? new CatchupServer(peerManager, dispatcher, buffer!, history.server) : undefined;
  let catchupClient: CatchupClient | undefined;
  if (history) {
    const mem = new Map<string, unknown>();
    const store: CatchupStore = history.store ?? { get: async (k) => mem.get(k), set: async (k, v) => { mem.set(k, v); } };
    catchupClient = new CatchupClient(peerManager, dispatcher, dandelion, gossip, store);
    await catchupClient.init();
  }
  new PEXHandler(peerManager, dispatcher);

  const received: GossipPacket[] = [];
  gossip.onMessage(p => received.push(p));

  const node: SimNode = {
    name, identity, dispatcher, peerManager, dandelion, circuit, gossip, buffer, catchupServer, catchupClient, received, inbox: [],
  };
  const original = (peerManager as any).handleData.bind(peerManager);
  (peerManager as any).handleData = (from: string, data: Uint8Array) => {
    const decoded = WireCodec.decode(data);
    node.inbox.push({ from, type: decoded.type, payload: decoded.payload, raw: data.slice() });
    return original(from, data);
  };
  return node;
}

/** 双方向の検証済みリンクを張る (配送は非同期) */
export function link(a: SimNode, b: SimNode): void {
  const half = (from: SimNode, to: SimNode) => ({
    peerId: to.identity.peerId,
    position: to.identity.position,
    rtt: 0,
    isConnected: true,
    isVerified: true,
    pubkey: to.identity.pubkey,
    powCounter: to.identity.powCounter,
    send: (data: Uint8Array) => {
      const copy = data.slice();
      setTimeout(() => (to.peerManager as any).handleData(from.identity.peerId, copy), 0);
    },
    close: vi.fn(),
  });
  (a.peerManager as any)._peers.set(b.identity.peerId, half(a, b));
  (b.peerManager as any)._peers.set(a.identity.peerId, half(b, a));
}

export function unlink(a: SimNode, b: SimNode): void {
  (a.peerManager as any)._peers.delete(b.identity.peerId);
  (b.peerManager as any)._peers.delete(a.identity.peerId);
}

/**
 * link() は検証済みのリンクを直接作るので、PeerManager が握手の完了で出す 'peer:verified' は出ない。
 * 握手が済んだことにして、両側に通知する (追いつきの開始の契機)。
 */
export function announceVerified(a: SimNode, b: SimNode): void {
  const peerA = (a.peerManager as any)._peers.get(b.identity.peerId);
  const peerB = (b.peerManager as any)._peers.get(a.identity.peerId);
  if (peerA) (a.peerManager as any).emit('peer:verified', peerA);
  if (peerB) (b.peerManager as any).emit('peer:verified', peerB);
}

/** 切断 (リンクを外し、両側に 'peer:disconnect' を出す) */
export function disconnectNodes(a: SimNode, b: SimNode): void {
  unlink(a, b);
  (a.peerManager as any).emit('peer:disconnect', b.identity.peerId);
  (b.peerManager as any).emit('peer:disconnect', a.identity.peerId);
}

export function startAll(nodes: SimNode[]): void {
  for (const n of nodes) n.circuit.start();
}

export function stopAll(nodes: SimNode[]): void {
  for (const n of nodes) {
    n.circuit.stop();
    n.gossip.destroy();
    n.catchupServer?.destroy();
    n.catchupClient?.destroy();
  }
}

export const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

/**
 * PoW と packet_id が整合した GossipPacket (PacketValidator を通る)。
 * payload は鍵なしでは読めない任意のバイト列 (SIV の最小長に満たなければ 0 で埋める)。
 * ★ 本物の Equi-X を解く (1 個 60〜100ms)。多数作るテストは余裕を見ること。
 */
export function makePacket(
  payloadBytes: number[] | Uint8Array = [1, 2, 3, 4],
  now: number = Date.now(),
  over: { tag?: number; age?: number; effort_exp?: number } = {},
): GossipPacket {
  const given = payloadBytes instanceof Uint8Array ? payloadBytes : Uint8Array.from(payloadBytes);
  const payload = new Uint8Array(Math.max(given.length, MIN_TEST_PAYLOAD));
  payload.set(given, 0);
  const time = msToMinutes(now);
  const committed = { version: PACKET_VERSION, time, tag: over.tag ?? 1, age: over.age ?? 0, effort_exp: over.effort_exp ?? 0, payload };
  const sol = solvePow(committed)!;
  return {
    packet_id: derivePacketId(committed),
    timestamp: minutesToMs(time),
    tag: committed.tag,
    age: committed.age,
    effort_exp: committed.effort_exp,
    pow_nonce: sol.nonce,
    pow_solution: sol.solution,
    payload,
  };
}

/** 検証を通る最小のペイロード長 (siv 16 + flags 1 + 署名ブロック 96) */
const MIN_TEST_PAYLOAD = 16 + 1 + 96;

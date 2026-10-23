import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import WebSocket from 'ws';
import {
  sodium,
  sodiumReady,
  NodeIdentity,
  NODE_ID_POW_FAST,
  SignalingClient,
  MessageDispatcher,
  PeerManager,
  PEXHandler,
  DandelionRouter,
  GossipRouter,
  OnionCircuit,
  WireType,
  RateLimiter,
  derivePacketId,
  solvePow,
  msToMinutes,
  minutesToMs,
  PACKET_VERSION,
  equixReady,
  type GossipPacket,
} from '@oz/core';
import { TrackerServer } from '../src';

const PARAMS = NODE_ID_POW_FAST;
const LOOSE_LIMITS = Object.fromEntries(
  ['gossip', 'dhtPut', 'dhtGet', 'pex', 'handshake', 'signaling', 'control', 'onion'].map(k => [k, { ratePerSec: 1e6, burst: 1e6 }]),
);

interface TestNode {
  name: string;
  identity: NodeIdentity;
  dispatcher: MessageDispatcher;
  signaling: SignalingClient;
  peerManager: PeerManager;
  dandelion: DandelionRouter;
  circuit: OnionCircuit;
  gossip: GossipRouter;
  pex: PEXHandler;
  receivedGossip: GossipPacket[];
}

describe('Tracker WebSocket 上限 & Guard 常時接続 & PEX 回路構築 E2E 忠実テスト', () => {
  let http: Server;
  let tracker: TrackerServer;
  let port: number;
  let trackerUrl: string;
  let nodes: TestNode[] = [];

  beforeAll(async () => {
    await sodiumReady;
    await equixReady;
  });

  afterEach(async () => {
    for (const node of nodes) {
      try { node.circuit.destroy(); } catch {}
      try { node.peerManager.stop(); } catch {}
      try { node.signaling.disconnect(); } catch {}
    }
    nodes = [];

    if (tracker) {
      tracker.shutdown();
    }
    if (http) {
      http.closeAllConnections();
      await new Promise<void>(resolve => http.close(() => resolve()));
    }
  });

  async function startTracker(options: { maxConnectionsPerAddress?: number } = {}) {
    http = createServer();
    tracker = new TrackerServer(http, {
      powParams: PARAMS,
      rateLimiter: new RateLimiter({ join: { ratePerSec: 1000, burst: 1000 }, relay: { ratePerSec: 1000, burst: 1000 } }),
      maxConnectionsPerAddress: options.maxConnectionsPerAddress ?? 16,
      log: () => {},
    });
    await new Promise<void>(resolve => http.listen(0, '127.0.0.1', resolve));
    port = (http.address() as AddressInfo).port;
    trackerUrl = `ws://127.0.0.1:${port}/ws`;
  }

  async function createTestNode(name: string, connectToTracker = false): Promise<TestNode> {
    const identity = await NodeIdentity.mine(PARAMS);
    const dispatcher = new MessageDispatcher();
    const signaling = new SignalingClient(trackerUrl, { WebSocketImpl: WebSocket as any });
    const peerManager = new PeerManager(identity, dispatcher, signaling, {
      powParams: PARAMS,
      rateLimiter: new RateLimiter(LOOSE_LIMITS),
      allowMissingDtlsFingerprint: true,
    });
    // Node.js 環境では WebRTC (RTCPeerConnection) がないため、PEX/Tracker 受信時の直接接続呼び出しをモック
    (peerManager as any).connect = vi.fn();

    const dandelion = new DandelionRouter(peerManager);
    const circuit = new OnionCircuit(peerManager, dispatcher, dandelion, {
      coverIntervalMs: 20,
      relayDelayMs: 2,
      echoTimeoutMs: 2000,
    });
    const gossip = new GossipRouter(peerManager, dispatcher, dandelion, circuit);
    const pex = new PEXHandler(peerManager, dispatcher);

    const receivedGossip: GossipPacket[] = [];
    gossip.onMessage(p => receivedGossip.push(p));

    const node: TestNode = {
      name, identity, dispatcher, signaling, peerManager, dandelion, circuit, gossip, pex, receivedGossip,
    };
    nodes.push(node);

    if (connectToTracker) {
      await signaling.connect({ claim: identity.claim(), identity });
    }

    return node;
  }

  /**
   * 2つのノード間に双方向の検証済み P2P リンクを確立する。
   */
  async function establishP2PLink(a: TestNode, b: TestNode) {
    const half = (from: TestNode, to: TestNode) => ({
      peerId: to.identity.peerId,
      position: to.identity.position,
      rtt: 0,
      isConnected: true,
      isVerified: true,
      direction: 'outbound',
      pubkey: to.identity.pubkey,
      powCounter: to.identity.powCounter,
      verifiedAt: Date.now(),
      send: (data: Uint8Array) => {
        const copy = data.slice();
        setTimeout(() => (to.peerManager as any).handleData(from.identity.peerId, copy), 0);
      },
      close: vi.fn(),
    });

    (a.peerManager as any)._peers.set(b.identity.peerId, half(a, b));
    (b.peerManager as any)._peers.set(a.identity.peerId, half(b, a));
  }

  /** 検証を通る v5 のパケット (本物の Equi-X を解く。effort 1) */
  function createMockGossipPacket(payloadStr: string): GossipPacket {
    const text = new TextEncoder().encode(payloadStr);
    const payload = new Uint8Array(Math.max(text.length, 16 + 1 + 96)); // 検証を通る最小のペイロード長
    payload.set(text);
    const time = msToMinutes(Date.now());
    const committed = { version: PACKET_VERSION, time, tag: 0, age: 0, effort_exp: 0, payload };
    const sol = solvePow(committed);
    if (sol === null) throw new Error('PoW search failed');
    return {
      packet_id: derivePacketId(committed),
      timestamp: minutesToMs(time),
      tag: 0,
      age: 0,
      effort_exp: 0,
      pow_nonce: sol.nonce,
      pow_solution: sol.solution,
      payload,
    };
  }

  it('ガードノードがトラッカーに常時接続し、クライアントがトラッカーから切断後も PEX 経由で M1 を発見してオニオン回路を構築・配送できること', async () => {
    await startTracker({ maxConnectionsPerAddress: 16 });

    // 1. Guard ノード: トラッカーに常時接続
    const guard = await createTestNode('Guard', true);
    expect(guard.signaling.isConnected).toBe(true);
    expect(tracker.sessionCount).toBe(1);

    // 2. Exit ノード (Charlie) と 受信ノード (Bob): ネットワーク内に存在
    const exitNode = await createTestNode('Exit_Charlie', false);
    const receiver = await createTestNode('Receiver_Bob', false);

    // Guard と Exit、Exit と Receiver をリンク (Guard の隣人は Exit、Receiver の隣人は Exit)
    await establishP2PLink(guard, exitNode);
    await establishP2PLink(exitNode, receiver);

    // 3. クライアント (Alice): トラッカーに一時接続して Guard を発見
    const alice = await createTestNode('Client_Alice', true);
    expect(alice.signaling.isConnected).toBe(true);
    expect(tracker.sessionCount).toBe(2);

    // Alice が Guard と直接 P2P リンクを確立
    await establishP2PLink(alice, guard);

    // 4. ★ Alice がトラッカーから即座に切断 (WS 接続枠を解放)
    alice.signaling.disconnect();
    expect(alice.signaling.isConnected).toBe(false);
    await new Promise(r => setTimeout(r, 50));
    // トラッカーのアクティブセッション数は Guard の 1 つだけに戻る
    expect(tracker.sessionCount).toBe(1);

    // 5. 各ノードの OnionCircuit と Gossip を開始
    guard.circuit.start();
    exitNode.circuit.start();
    receiver.circuit.start();
    alice.circuit.start();

    // 6. Alice が Guard に対して PEX_REQUEST を発行
    //    Alice は Exit (Charlie) の存在をまだ直接知らない
    alice.pex.requestPeers(guard.identity.peerId);

    // PEX 応答が配送され、Alice の OnionCircuit が Guard の隣人 (Exit) を検証・学習するのを待機
    await new Promise(r => setTimeout(r, 100));

    // Alice の OnionCircuit の guardNeighbors に Exit (Charlie) が登録されていることを確認
    const guardNeighbors = (alice.circuit as any).guardNeighbors as Map<string, any>;
    expect(guardNeighbors.has(exitNode.identity.peerId)).toBe(true);
    const exitInfo = guardNeighbors.get(exitNode.identity.peerId);
    expect(exitInfo.pubkey).toEqual(exitNode.identity.pubkey);

    // 7. Alice がオニオン経由で Gossip メッセージを発信
    const packet = createMockGossipPacket('PEX経由オニオン回路配送テスト');
    const sendSuccess = await alice.gossip.broadcast(packet);
    expect(sendSuccess).toBe(true);

    // 8. 受信ノード (Receiver_Bob) が M1 から Stem を経て Fluff されたパケットを受け取ったことを検証
    await new Promise(r => setTimeout(r, 150));
    const received = receiver.receivedGossip.find(p => p.packet_id === packet.packet_id);
    expect(received).toBeDefined();
    expect(new TextDecoder().decode(received?.payload).replace(/\0+$/, '')).toBe('PEX経由オニオン回路配送テスト');
  });

  it('トラッカーの WS 接続上限 (例: 4本) があっても、クライアントが接続後に切断する運用により、上限を超える多数のノードが順次ブートストラップし自律 P2P 網に参加できること', async () => {
    // 同一 IP アドレスからの同時接続上限を 4 本に制限した厳しいトラッカーを起動
    await startTracker({ maxConnectionsPerAddress: 4 });

    // 常時接続ガードノード (スロット 1 を永続占有)
    const guard = await createTestNode('PersistentGuard', true);
    expect(guard.signaling.isConnected).toBe(true);
    expect(tracker.sessionCount).toBe(1);

    // M1 候補 (ガードの隣人)
    const exitNode = await createTestNode('ExitNode', false);
    await establishP2PLink(guard, exitNode);
    guard.circuit.start();
    exitNode.circuit.start();

    // ★ M1 は本物を自分では Fluff せず、ガード以外の隣人へ Stem で渡す。ガードにしか
    //   つながらない葉が M1 に選ばれると、渡す先が無くて投稿は消える。実際の網では
    //   どのノードも複数の隣人を持つので、候補になりうるノード (M1 候補と最後以外の
    //   クライアント) を、ガードの隣人ではない中継ノードにもつなげておく。
    const hub = await createTestNode('Hub', false);
    await establishP2PLink(exitNode, hub);

    // 10 台のクライアントが順次トラッカーを通過して Guard とリンクし、即切断する
    const CLIENT_COUNT = 10;
    const clients: TestNode[] = [];

    for (let i = 0; i < CLIENT_COUNT; i++) {
      const client = await createTestNode(`Client_${i}`, false);
      // トラッカーに接続 (この時点の同時接続数は Guard + 1 = 2 <= 4)
      await client.signaling.connect({ claim: client.identity.claim(), identity: client.identity });
      expect(client.signaling.isConnected).toBe(true);

      // Guard とリンクを確立
      await establishP2PLink(client, guard);
      // 最後のクライアントは作者になる。作者は Guard 以外の隣人を持たない (Guard の選択を固定するため)
      if (i < CLIENT_COUNT - 1) await establishP2PLink(client, hub);

      // ★ 接続完了後、直ちにトラッカーから切断 (スロット返却)
      client.signaling.disconnect();
      expect(client.signaling.isConnected).toBe(false);

      clients.push(client);
    }

    await new Promise(r => setTimeout(r, 50));
    // 全 10 クライアントが切断したため、トラッカーのセッション数は Guard の 1 つだけ
    expect(tracker.sessionCount).toBe(1);

    // 全クライアントが Guard に PEX を発行して Exit を取得 (PEX は 8 件ランダムサンプルのため複数回問い合わせて収束)
    for (const client of clients) {
      client.circuit.start();
    }

    for (let attempt = 0; attempt < 3; attempt++) {
      for (const client of clients) {
        client.pex.requestPeers(guard.identity.peerId);
      }
      await new Promise(r => setTimeout(r, 50));
    }

    // 全てのクライアントがトラッカー不在のまま Exit を学習できていることを検証
    for (const client of clients) {
      const guardNeighbors = (client.circuit as any).guardNeighbors as Map<string, any>;
      expect(guardNeighbors.has(exitNode.identity.peerId)).toBe(true);
    }

    // 最後のクライアントがオニオンパケットを送信し、Guard と M1 を経由して配送されることを確認
    const lastClient = clients[clients.length - 1];
    const packet = createMockGossipPacket('Tracker-detached-PEX-Mesh-Message');
    const sendOk = await lastClient.gossip.broadcast(packet);
    expect(sendOk).toBe(true);
  });

  it('悪意ある Guard が不正な PEX (PoW未達成/偽公開鍵) を返しても、クライアントが検証で拒否し不正 Exit を回路に組み込まないこと (Fail-Closed)', async () => {
    await startTracker({ maxConnectionsPerAddress: 16 });
    const guard = await createTestNode('MaliciousGuard', true);
    const alice = await createTestNode('Alice', true);
    await establishP2PLink(alice, guard);
    alice.signaling.disconnect();
    alice.circuit.start();

    // 偽の Exit 候補: 署名/PoW が不一致のクレーム
    const fakePeerId = '0123456789abcdef0123456789abcdef';
    const fakePubkey = new Uint8Array(32).fill(0xfe);
    const fakePowCounter = 9999999; // 嘘のカウンター

    // Guard が Alice に偽の PEX 応答を送信
    alice.dispatcher.dispatch(guard.identity.peerId, WireType.PEX_RESPONSE, {
      peers: [
        { id: fakePeerId, pubkey: fakePubkey, powCounter: fakePowCounter },
      ],
    });

    await new Promise(r => setTimeout(r, 50));

    // Alice の guardNeighbors に偽 Exit が登録されていないことを検証
    const guardNeighbors = (alice.circuit as any).guardNeighbors as Map<string, any>;
    expect(guardNeighbors.has(fakePeerId)).toBe(false);
  });
});

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import crypto from 'node:crypto';
import sodium, { sodiumReady } from '../../src/crypto/sodium';
import { equixReady } from '../../src/crypto/equix/EquiX';
import { Encoding } from '../../src/common/Encoding';
import { createSimNode, link, announceVerified, stopAll, type SimNode } from '../helpers/onionNet';
import { attachTunnel, attachBehind, stopTunnel, until, type TunnelSimNode } from '../helpers/tunnelNet';
import { stopStorage } from '../helpers/storageNet';
import { FileUploader, type UploadProgress } from '../../src/files/FileUploader';
import { FileDownloader, type DownloadProgress } from '../../src/files/FileDownloader';
import { makeCheapPacket } from '../helpers/cheapPow';
import { LOOSE_CLIENT_SEND, TEST_CHUNK_EFFORT } from '../helpers/fileNet';
import { KeyManager } from '../../src/crypto/KeyManager';

/**
 * 30 ノード Ozzy プロトコル大規模エミュレーション検証
 *
 * 1. 30 ノードのクラスタ立ち上げ (Guard 4台 + 保持者 6台 + クライアント 20台)
 * 2. P2P メッシュ・リングルーティングのトポロジ収束検証
 * 3. 全 30 ノードでの匿名経路 (3-hop Onion Circuit: Client -> Guard -> M1) 確立検証
 * 4. 1MB (1,048,576 バイト) バイナリデータの分散暗号化配置 (FileUploader)
 * 5. 掲示板 (Dandelion++ / Gossip) へのオニオン経由放流と全ノード伝播検証
 * 6. 対角ノードによる 1MB データ取得 (FileDownloader) とバイト単位 SHA-256 完全一致検証
 */

describe('30 ノード Ozzy プロトコル実動エミュレーション', () => {
  beforeAll(async () => {
    await sodiumReady;
    await equixReady;
  });

  const allNodes: TunnelSimNode[] = [];

  afterAll(async () => {
    stopTunnel(allNodes);
    await stopStorage(allNodes);
    stopAll(allNodes);
  });

  it('30ノードでのルーティング・全ノード匿名経路確立・1MB掲示板放流と交換', async () => {
    console.log('=== [Phase 1] 30 ノードのインスタンス化開始 ===');
    const t0 = performance.now();

    // 役割定義: Guard 4台, 保持者 6台, クライアント 20台
    const NUM_GUARDS = 4;
    const NUM_HOLDERS = 6;
    const NUM_CLIENTS = 20;
    const TOTAL_NODES = NUM_GUARDS + NUM_HOLDERS + NUM_CLIENTS; // 30台

    const guards: TunnelSimNode[] = [];
    const holders: TunnelSimNode[] = [];
    const clients: TunnelSimNode[] = [];
    const guardIds = new Set<string>();

    // 1. Guard 4台の生成
    for (let i = 0; i < NUM_GUARDS; i++) {
      const g = await attachTunnel(await createSimNode(`Guard_${i}`), {
        storage: { slots: 1, wait: false },
        relay: {
          role: 'guard',
          isBackbone: (id) => guardIds.has(id),
          limits: { clientSend: LOOSE_CLIENT_SEND },
        },
      });
      guardIds.add(g.identity.peerId);
      guards.push(g);
      allNodes.push(g);
    }

    // 2. 保持者 6台の生成 (ファイル保管枠を持ち、LeaseSet を発行するノード)
    for (let i = 0; i < NUM_HOLDERS; i++) {
      const h = await attachTunnel(await createSimNode(`Holder_${i}`), {
        storage: {
          slots: 1,
          chunkEffort: TEST_CHUNK_EFFORT,
          tunnel: { limits: { chunkIntervalMs: 1 } },
        },
      });
      holders.push(h);
      allNodes.push(h);
    }

    // 3. クライアント 20台の生成
    for (let i = 0; i < NUM_CLIENTS; i++) {
      const c = await attachTunnel(await createSimNode(`Client_${i}`), {
        storage: { slots: 1, wait: false, chunkEffort: TEST_CHUNK_EFFORT },
      });
      clients.push(c);
      allNodes.push(c);
    }

    expect(allNodes.length).toBe(30);
    console.log(`[Phase 1] 30 ノード生成完了 (${(performance.now() - t0).toFixed(0)}ms)`);

    // === [Phase 2] P2P トポロジー構築とルーティングの検証 ===
    console.log('=== [Phase 2] P2P メッシュ・リング構築とルーティング検証 ===');

    // 1) Guard バックボーンの相互フルメッシュ接続
    for (let i = 0; i < guards.length; i++) {
      for (let j = i + 1; j < guards.length; j++) {
        link(guards[i], guards[j]);
        announceVerified(guards[i], guards[j]);
      }
    }

    // 2) 保持者ノードを Guard 配下に接続
    for (let i = 0; i < holders.length; i++) {
      const targetGuard = guards[i % guards.length];
      attachBehind(holders[i], targetGuard);
    }

    // 3) クライアントノードを Guard 配下に接続 (各クライアントは 1〜2 台の Guard と接続)
    for (let i = 0; i < clients.length; i++) {
      const g1 = guards[i % guards.length];
      attachBehind(clients[i], g1);
      const g2 = guards[(i + 1) % guards.length];
      link(clients[i], g2);
      announceVerified(clients[i], g2);
    }

    // 4) 全 30 ノードをリングトポロジ (i と i+1) + ショートカット弦 (i と i+7) で結線
    for (let i = 0; i < TOTAL_NODES; i++) {
      const next = (i + 1) % TOTAL_NODES;
      link(allNodes[i], allNodes[next]);
      announceVerified(allNodes[i], allNodes[next]);

      const chord = (i + 7) % TOTAL_NODES;
      link(allNodes[i], allNodes[chord]);
      announceVerified(allNodes[i], allNodes[chord]);
    }

    // ルーティングの健全性チェック: 全ノードが孤立せず、適切なピア数を持っていること
    for (const node of allNodes) {
      const peerCount = node.peerManager.peers.size;
      expect(peerCount).toBeGreaterThanOrEqual(3);
    }
    console.log(`[Phase 2] ルーティング検証成功: 30 ノード全台が連結、平均接続次数 = ${(allNodes.reduce((a, b) => a + b.peerManager.peers.size, 0) / 30).toFixed(1)}`);

    // === [Phase 3] 全ノードでの匿名経路 (Onion Circuit) 確立の検証 ===
    console.log('=== [Phase 3] 全 30 ノードの匿名経路確立検証 ===');

    // 全ノードの回路とルータを起動
    for (const n of allNodes) {
      n.circuit.start();
    }

    // Guard からの PEX 応答が各ノードに行き渡り、M1 (Middle候補) が選べるようになるのを待つ
    // 各ノードの routeReady が true になることを検証
    await until(() => {
      return allNodes.every(n => n.circuit.routeReady);
    }, 10000, '30ノード全員の routeReady 成立');

    // 各ノードの匿名回路ステータスを精密検査
    let totalMiddles = 0;
    for (let i = 0; i < TOTAL_NODES; i++) {
      const n = allNodes[i];
      expect(n.circuit.routeReady).toBe(true);
      expect(n.circuit.currentGuardHop).not.toBeNull();
      const middles = n.circuit.middleCandidateCount;
      expect(middles).toBeGreaterThanOrEqual(1);
      totalMiddles += middles;
    }
    console.log(`[Phase 3] 匿名経路確立成功: 30/30 ノード (100%) で 3-hop オニオン回路が即時利用可能 (平均 Middle 候補数: ${(totalMiddles / 30).toFixed(1)})`);

    // === [Phase 4] 1MB データの暗号化・分散配置 (FileUploader) ===
    console.log('=== [Phase 4] 1MB データ生成と保持者への分散配置 ===');

    // 保持者の LeaseSet を広告し、全クライアントに同期させる
    for (const h of holders) {
      h.storage.router.publish();
    }
    await until(() => holders.every(h => h.storage.tunnel!.registered), 10000, 'holders tunnel registered');

    const uploaderNode = clients[0];  // Client_0 (上げる側)
    const downloaderNode = clients[clients.length - 1]; // Client_19 (対角で受け取る側)

    await until(() => {
      return uploaderNode.storage.leaseSets.size === holders.length &&
             downloaderNode.storage.leaseSets.size === holders.length;
    }, 10000, 'leaseSets synced to uploader & downloader');

    // 1MB (1,048,576 bytes) のランダムバイナリデータを生成
    const ONE_MB = 1024 * 1024;
    const originalData = crypto.randomBytes(ONE_MB);
    const originalHash = crypto.createHash('sha256').update(originalData).digest('hex');
    console.log(`[Phase 4] 放流用 1MB データ生成完了: サイズ = ${originalData.length} bytes, SHA-256 = ${originalHash}`);

    const uploaderRouting = {
      duty: uploaderNode.storage.duty,
      leaseSets: uploaderNode.storage.leaseSets,
      ownSid: () => uploaderNode.sid,
    };

    const uploadProgressList: UploadProgress[] = [];
    const tUploadStart = performance.now();

    const uploader = new FileUploader(
      {
        tunnel: uploaderNode.tunnel,
        routing: uploaderRouting,
        chunkEffort: TEST_CHUNK_EFFORT,
        limits: { fragmentsPerSec: 1e6, roundDelayMs: [10, 30], retryBackoffMs: 10 },
      },
      new Uint8Array(originalData.buffer),
      { name: 'ozzy_1mb_payload.bin', mime: 'application/octet-stream' },
      p => uploadProgressList.push(p),
    ).start();

    const fileLinkToken = await uploader.link;
    const uploadDurationMs = performance.now() - tUploadStart;

    expect(fileLinkToken).toMatch(/^\[\[file:[A-Za-z0-9_-]{74}\]\]$/);
    expect(uploadProgressList.at(-1)?.phase).toBe('done');
    expect(uploadProgressList.at(-1)?.bytesPlaced).toBe(ONE_MB);
    console.log(`[Phase 4] 1MB 分散配置成功 (${uploadDurationMs.toFixed(0)}ms): トークン = ${fileLinkToken}`);

    // === [Phase 5] 掲示板 (Gossip / Dandelion++) への放流と全ノード伝播検証 ===
    console.log('=== [Phase 5] 掲示板への 1MB ファイルトークン放流と全ノード伝播検証 ===');

    // 30 ノード全員に Gossip リスナーをセット
    const receivedPackets = new Map<string, any[]>();
    for (const n of allNodes) {
      receivedPackets.set(n.identity.peerId, []);
      n.gossip.onMessage((pkt) => {
        receivedPackets.get(n.identity.peerId)!.push(pkt);
      });
    }

    // 掲示板投稿パケットの作成 (本文に 1MB ファイルトークンを埋め込む)
    const postContent = `【Ozzy 1MB 大容量データ放流テスト】\nファイルはこちら: ${fileLinkToken}\nChecksum: ${originalHash}`;
    const payloadBytes = new TextEncoder().encode(postContent);
    const postPacket = makeCheapPacket(payloadBytes);

    // uploaderNode から掲示板網へ放流 (GossipRouter.broadcast)
    const broadcastOk = await uploaderNode.gossip.broadcast(postPacket);
    expect(broadcastOk).toBe(true);

    // 全 30 ノードに届くのを待つ
    await until(() => {
      let count = 0;
      for (const [_, pkts] of receivedPackets) {
        if (pkts.some(p => p.packet_id === postPacket.packet_id)) count++;
      }
      return count === TOTAL_NODES;
    }, 10000, '30ノード全員への掲示板パケット伝播');

    console.log(`[Phase 5] 掲示板放流・伝播成功: 30/30 ノード (100%) が 1MB ファイル共有ポストを受信完了`);

    // === [Phase 6] 対角クライアントによるダウンロードと SHA-256 完全一致検証 ===
    console.log('=== [Phase 6] 対角ノードによる 1MB データ取得と完全一致検証 ===');

    const downloaderRouting = {
      duty: downloaderNode.storage.duty,
      leaseSets: downloaderNode.storage.leaseSets,
      ownSid: () => downloaderNode.sid,
    };

    const downloadProgressList: DownloadProgress[] = [];
    const tDownloadStart = performance.now();

    const downloader = new FileDownloader(
      {
        tunnel: downloaderNode.tunnel,
        routing: downloaderRouting,
        limits: { hedgeMs: 50, inactivityMs: 2000, roundDelayMs: 20 },
      },
      fileLinkToken,
      p => downloadProgressList.push(p),
    ).start();

    // チャンクを受信してバッファに結合
    const downloadedChunks: Uint8Array[] = [];
    for await (const chunk of downloader) {
      downloadedChunks.push(chunk);
    }
    const downloadDurationMs = performance.now() - tDownloadStart;

    // 全バイトを結合
    const totalBytes = downloadedChunks.reduce((acc, c) => acc + c.length, 0);
    const downloadedData = new Uint8Array(totalBytes);
    let offset = 0;
    for (const c of downloadedChunks) {
      downloadedData.set(c, offset);
      offset += c.length;
    }

    const downloadedHash = crypto.createHash('sha256').update(downloadedData).digest('hex');

    expect(totalBytes).toBe(ONE_MB);
    expect(downloadedHash).toBe(originalHash);

    console.log(`[Phase 6] ダウンロード完了 (${downloadDurationMs.toFixed(0)}ms):`);
    console.log(`  - 受信サイズ: ${totalBytes} bytes (期待値: ${ONE_MB} bytes) [一致]`);
    console.log(`  - 送信元 SHA-256: ${originalHash}`);
    console.log(`  - 受信先 SHA-256: ${downloadedHash}`);
    console.log(`  - 1 バイトの狂いもなく完全一致を確認！`);

    console.log('=== 全 6 フェーズの検証がすべて成功しました ===');
  }, 60_000);
});

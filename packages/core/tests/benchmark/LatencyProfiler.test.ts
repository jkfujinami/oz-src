import 'fake-indexeddb/auto';
import { describe, it, expect } from 'vitest';
import sodium, { sodiumReady } from '../../src/crypto/sodium';
import { CIRCUIT_CONFIG } from '../../src/network/onion/OnionCircuit';
import { WireType } from '../../src/network/wire/WireTypes';
import { KeyManager } from '../../src/crypto/KeyManager';
import { CryptoEngine } from '../../src/crypto/CryptoEngine';
import { PoWEngine } from '../../src/crypto/PoWEngine';
import { Identity } from '../../src/crypto/Identity';
import { PacketBuilder } from '../../src/crypto/PacketBuilder';
import { POW_POLICY } from '../../src/crypto/PowPolicy';
import {
  createSimNode,
  link,
  startAll,
  stopAll,
  sleep,
  type SimNode,
} from '../helpers/onionNet';

describe('10-Node E2E Latency Profiler', () => {
  it('profiles exact delay of each stage in 10-node network', async () => {
    await sodiumReady;

    console.log('\n================================================================================');
    console.log('⏱️  OZ 10ノード仮想ネットワーク E2E レイテンシ プロファイリング開始');
    console.log('================================================================================');

    const NODE_COUNT = 10;
    const baseNodes: SimNode[] = [];
    const appNodes: SimNode[] = baseNodes;

    // 本番実運用の既定オニオンパラメータ
    const prodCircuitOptions = {
      coverIntervalMs: CIRCUIT_CONFIG.COVER_INTERVAL_MS, // 2000ms
      relayDelayMs: CIRCUIT_CONFIG.RELAY_DELAY_MS,       // 40ms
      echoTimeoutMs: CIRCUIT_CONFIG.ECHO_TIMEOUT_MS,     // 45000ms
    };

    // 1. ノード 10 台を生成 (本番の遅延パラメータを注入)
    for (let i = 0; i < NODE_COUNT; i++) {
      const base = await createSimNode(`node_${i}`, prodCircuitOptions);
      baseNodes.push(base);
    }

    // 2. 10ノードをメッシュ結合 (リング + クロスリンク)
    for (let i = 0; i < NODE_COUNT; i++) {
      link(baseNodes[i], baseNodes[(i + 1) % NODE_COUNT]);
      link(baseNodes[i], baseNodes[(i + 3) % NODE_COUNT]);
      link(baseNodes[i], baseNodes[(i + 5) % NODE_COUNT]);
    }

    // 全ノード起動
    startAll(baseNodes);

    // Guard の隣人表 (PEX) が届くまで待機
    console.log('⏳ P2P トポロジー構築 & Guard PEX 伝播待機中 (500ms)...');
    await sleep(500);

    // 3. 計測プローブ
    const timestamps: Record<string, number> = {};
    const record = (stage: string) => {
      const now = performance.now();
      if (!timestamps[stage]) {
        timestamps[stage] = now;
      }
    };

    const sender = appNodes[0];
    const receiver = appNodes[9];

    const boardKey = sodium.randombytes_buf(32);
    const boardId = 'vip';
    const threadId = 'test_thread_01';
    const threadKey = KeyManager.deriveThreadKey(boardKey, threadId);

    const normalPeer = appNodes[8]; // 一般ノード

    // 4. メッセージ投稿シーケンス
    record('T0_Start');

    const cryptoEng = new CryptoEngine();
    const powEng: any = { compute: (h: any) => PoWEngine.compute(h) };
    const identityObj = new Identity();

    console.log('🔨 ステップ 1: パケット構築 & PoW 計算開始');
    const packet = await PacketBuilder.build({
      content: '速度測定テストメッセージ', key: threadKey, identity: identityObj, cryptoEngine: cryptoEng, powEngine: powEng,
      boardId, threadId,
    });
    record('T1_PacketBuilt');

    // 受信側ノードの GOSSIP 直接受信を監視 (Layer 1 会話プレーン)
    const gossipReceivedPromise = new Promise<void>((resolve) => {
      normalPeer.gossip.onMessage((receivedPacket) => {
        if (receivedPacket.packet_id === packet.packet_id) {
          record('T_GossipDirectReceived');
          resolve();
        }
      });
    });

    // 送信ノードが Guard にセルを送った瞬間
    const origSend = (sender.peerManager as any).sendMessage.bind(sender.peerManager);
    (sender.peerManager as any).sendMessage = (target: string, type: number, payload: any) => {
      if (type === WireType.ONION_STEM) {
        record('T3_CoverSlotAcquired_SentToGuard');
      }
      return origSend(target, type, payload);
    };

    // Exit ノードで最内層が解かれ Fluff (GOSSIP) が始まった瞬間
    for (const n of appNodes) {
      const origDispatch = n.dispatcher.dispatch.bind(n.dispatcher);
      n.dispatcher.dispatch = (peerId: string, type: number, payload: any) => {
        if (type === WireType.GOSSIP && !timestamps['T4_ExitFloodStarted']) {
          record('T4_ExitFloodStarted');
        }
        return origDispatch(peerId, type, payload);
      };
    }

    console.log('🧅 ステップ 3: Layer 1 単一オニオン回路によるブロードキャスト開始 (Cover待機 + Stem の歩き)');
    const delivered = await sender.gossip.broadcast(packet);
    record('T5_EchoConfirmed_BroadcastReturned');

    expect(delivered).toBe(true);
    console.log('📡 ステップ 4: エコー確認完了。受信側での即時 Gossip 到着待機...');

    await gossipReceivedPromise;
    record('T_Layer1Complete');

    // 5. 結果集計
    const t0 = timestamps['T0_Start'];
    const layer1TotalMs = timestamps['T_Layer1Complete'] - t0;

    const diff = (from: string, to: string) => {
      if (!timestamps[from] || !timestamps[to]) return 0;
      return Math.max(0, timestamps[to] - timestamps[from]);
    };

    console.log('\n================================================================================');
    console.log('📊 【測定結果】OZ アーキテクチャ E2E レイテンシ');
    console.log('================================================================================');

    const p1 = diff('T0_Start', 'T1_PacketBuilt');
    const p3 = diff('T1_PacketBuilt', 'T3_CoverSlotAcquired_SentToGuard');
    const p4 = diff('T3_CoverSlotAcquired_SentToGuard', 'T4_ExitFloodStarted');
    const p5 = diff('T4_ExitFloodStarted', 'T5_EchoConfirmed_BroadcastReturned');
    const pDirect = diff('T5_EchoConfirmed_BroadcastReturned', 'T_GossipDirectReceived');

    const rows = [
      { phase: '1. PoW & 暗号化パケット生成', timeMs: p1 },
      { phase: '3. Cover Traffic 空きスロット待ち', timeMs: p3 },
      { phase: '4. Guard中継 + M1 + Stem の歩き', timeMs: p4 },
      { phase: '5. Exit本体フラッド & 送信者エコー確認', timeMs: p5 },
      { phase: '6. 受信者ピアへの Gossip 直送・即時反映', timeMs: pDirect },
    ];

    console.table(
      rows.map(r => ({
        'フェーズ': r.phase,
        '所要時間 (ms)': Math.round(r.timeMs),
        '割合 (%)': `${((r.timeMs / layer1TotalMs) * 100).toFixed(1)}%`,
      }))
    );

    console.log(`--------------------------------------------------------------------------------`);
    console.log(`⚡ 【Layer 1: 会話プレーン E2E 反映時間】: ${(layer1TotalMs / 1000).toFixed(2)} 秒 (${Math.round(layer1TotalMs)} ms)`);
    console.log('================================================================================\n');

    stopAll(baseNodes);
  }, 120_000);
});

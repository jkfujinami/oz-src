import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import sodium from 'libsodium-wrappers-sumo';
import 'fake-indexeddb/auto';

import { OzNode } from '../src/node/OzNode';
import { IndexedDBStore } from '../src/storage/IndexedDBStore';
import { VAULT_PARAMS_FAST } from '../src/storage/SecretVault';
import { KeyManager } from '../src/crypto/KeyManager';
import { installFakeWebRTC, resetFakeWebRTC } from './helpers/webrtc';
import { SignalingHub, HubSignalingClient } from './helpers/fakes';

describe('OzNode Multi-Node End-to-End P2P Integration', () => {
  let hub: SignalingHub;

  beforeAll(async () => {
    await sodium.ready;
    installFakeWebRTC();
  });

  beforeEach(() => {
    resetFakeWebRTC();
    hub = new SignalingHub();
  });

  /** ハブ経由のシグナリングを差し込んだノードを作る */
  async function makeNode(name: string): Promise<OzNode> {
    const db = new IndexedDBStore(`${name}DB_` + Date.now());
    await db.init();
    const node = await OzNode.create({
      storage: { slotEffort: 1, chunkEffort: 1 }, // ★ 保管の PoW は軽く (CPU を食って他のテストの時間を乱さないように)
      db,
      autoStart: false,
      passphrase: `${name}-passphrase`,
      vaultParams: VAULT_PARAMS_FAST,
      // テスト用に cover traffic と中継遅延を縮める (既定は数秒単位)
      circuit: { coverIntervalMs: 20, relayDelayMs: 1, readyWaitMs: 2000, echoTimeoutMs: 3000 },
      // 小さな網 (隣人 1 人) でも Guard を選べるよう、選択待ちを無効にする。
      // 本番の既定 (4 人以上・20 秒待ち) は GuardSelection.test.ts で検証している。
      guardOptions: { minOpenCandidates: 1, openSelectionDelayMs: 0 },
    });
    const sig = new HubSignalingClient(hub, node.peerId);
    (node.peerManager as any).signaling = sig;
    sig.on('relay', (sender: string, payload: any) => (node.peerManager as any).handleRelay(sender, payload));
    return node;
  }

  it('3 ノード (Alice - Bob - Carol) で、スレッドがオニオン回路経由で配送される', async () => {
    const alice = await makeNode('Alice');
    const bob = await makeNode('Bob');
    const carol = await makeNode('Carol');
    expect(new Set([alice.peerId, bob.peerId, carol.peerId]).size).toBe(3);

    // Alice の隣人は Bob だけ。Bob の背後の Carol が M1 になる
    alice.peerManager.connect(bob.peerId, true);
    bob.peerManager.connect(carol.peerId, true);
    await new Promise((r) => setTimeout(r, 300));

    // DTLS 指紋に束縛された JOIN (v4) で相互に本人確認が済んでいること
    expect(alice.peerManager.peers.get(bob.peerId)?.isVerified).toBe(true);
    expect(bob.peerManager.peers.get(alice.peerId)?.isVerified).toBe(true);
    expect(bob.peerManager.peers.get(carol.peerId)?.isVerified).toBe(true);

    for (const n of [alice, bob, carol]) await n.start();
    // Guard の隣人表 (PEX) が届くまで待つ
    await new Promise((r) => setTimeout(r, 300));

    const boardId = 'vip';
    const boardKey = KeyManager.cryptoHash(new TextEncoder().encode('OZ_LITE_VIP_DEFAULT_SEED')).slice(0, 32);
    for (const n of [alice, bob, carol]) n.boardOrchestrator.activate(boardId, boardKey);

    const threadTitle = 'OZ P2P 統合テストスレッド (Alice発信)';
    const threadId = await alice.boardOrchestrator.submitThread(boardId, boardKey, threadTitle);
    expect(threadId).toBeTruthy();

    // cover の空き待ち + Stem の歩き + 伝播を待つ
    const deadline = Date.now() + 5000;
    const seen = (n: OzNode) => n.boardOrchestrator.getThreads().some((t) => t.content === threadTitle);
    while (Date.now() < deadline && !(seen(bob) && seen(carol))) {
      await new Promise((r) => setTimeout(r, 50));
    }
    expect(seen(bob)).toBe(true);
    expect(seen(carol)).toBe(true);

    for (const n of [alice, bob, carol]) await n.stop();
  }, 30_000);
});

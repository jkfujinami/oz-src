import 'fake-indexeddb/auto';
import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import sodium, { sodiumReady } from '../../src/crypto/sodium';
import { createSimNode, link, startAll, stopAll, sleep, type SimNode } from '../helpers/onionNet';
import { KeyManager } from '../../src/crypto/KeyManager';
import { ThreadOrchestrator } from '../../src/logic/ThreadOrchestrator';
import { BoardOrchestrator } from '../../src/logic/BoardOrchestrator';
import { CryptoEngine } from '../../src/crypto/CryptoEngine';
import { PoWEngine } from '../../src/crypto/PoWEngine';
import { Identity } from '../../src/crypto/Identity';
import { IndexedDBStore } from '../../src/storage/IndexedDBStore';
import { CIRCUIT_CONFIG } from '../../src/network/onion/OnionCircuit';

describe('高速 Gossip 配信 統合テスト (オニオン → Stem → Fluff)', () => {
  let nodes: SimNode[] = [];
  const cleanups: Array<() => void> = [];
  const syncPow: any = { compute: (h: any) => PoWEngine.compute(h) };
  const keyMgr: any = {
    deriveThreadKey: KeyManager.deriveThreadKey,
  };

  beforeAll(async () => {
    await sodiumReady;
  });

  afterEach(async () => {
    for (const c of cleanups) {
      try { c(); } catch {}
    }
    cleanups.length = 0;
    stopAll(nodes);
    nodes = [];
    await sleep(50);
  });

  async function createAppContext(node: SimNode, dbName: string) {
    const db = new IndexedDBStore(dbName);
    await db.init();
    await db.unlock('test_password_123');
    return { db };
  }

  it('CIRCUIT_CONFIG の高速化定数が仕様値 (COVER 500ms, ECHO 5000ms, Stem Fluff 確率 0.25) に設定されていること', () => {
    expect(CIRCUIT_CONFIG.COVER_INTERVAL_MS).toBe(500);
    expect(CIRCUIT_CONFIG.STEM_FLUFF_PROBABILITY).toBe(0.25);
    expect(CIRCUIT_CONFIG.READY_WAIT_MS).toBe(60_000);
    // 出口の混合遅延は撤去した (Stem の歩きが置き換える)
    expect(CIRCUIT_CONFIG).not.toHaveProperty('EXIT_DELAY_MS');
    expect(CIRCUIT_CONFIG).not.toHaveProperty('EXIT_DELAY_MAX_MS');
    expect(CIRCUIT_CONFIG.ECHO_TIMEOUT_MS).toBe(5000);
  });

  it('会話パケットはオニオン M1 から Stem を歩いた末に Fluff され即時に受信側 DAG に到達する', async () => {
    // 4ノード網: 送信者 (0) -> Guard (1) -> M1 (2 または 3) -> Stem -> Fluff
    const n0 = await createSimNode('n0');
    const n1 = await createSimNode('n1');
    const n2 = await createSimNode('n2');
    const n3 = await createSimNode('n3');
    nodes = [n0, n1, n2, n3];

    link(n0, n1);
    link(n1, n2);
    link(n2, n3);
    link(n1, n3);

    startAll(nodes);
    // Guard の隣人表 (PEX) が伝播するまで待機
    await sleep(100);

    const boardKey = sodium.randombytes_buf(32);
    const boardId = 'news';
    const threadId = 'thread_fast_01';

    const ctx0 = await createAppContext(n0, 'fast_db_0');
    const ctx3 = await createAppContext(n3, 'fast_db_3');

    const cryptoEngine = new CryptoEngine();
    const senderIdentity = new Identity();
    const receiverIdentity = new Identity();

    const senderOrch = new ThreadOrchestrator(
      n0.peerManager,
      ctx0.db,
      n0.gossip,
      cryptoEngine,
      syncPow,
      senderIdentity,
      keyMgr,
    );

    const receiverOrch = new ThreadOrchestrator(
      n3.peerManager,
      ctx3.db,
      n3.gossip,
      cryptoEngine,
      syncPow,
      receiverIdentity,
      keyMgr,
    );

    await receiverOrch.activate(boardId, threadId, boardKey);
    await senderOrch.activate(boardId, threadId, boardKey);

    const receivedPromise = new Promise<string>((resolve) => {
      const unsub = receiverOrch.subscribe(() => {
        const posts = receiverOrch.getPosts();
        const found = posts.find(p => p.content === '爆速テストメッセージ');
        if (found) {
          unsub();
          resolve(found.content);
        }
      });
    });

    const startTime = performance.now();

    // 送信実行
    await senderOrch.submitReply('爆速テストメッセージ');
    const sendDuration = performance.now() - startTime;

    // 1. 送信処理自体がブロックされず即時完了したか
    expect(sendDuration).toBeLessThan(2000);

    // 2. 受信側への到達 (Gossip 直接配信経由) を待機。
    //    上限は 1 回目の試行が失敗してもやり直しが間に合う長さ (エコー待ち 5 秒 + 余裕)
    const receivedContent = await Promise.race([
      receivedPromise,
      new Promise<null>((_, reject) => setTimeout(() => reject(new Error('Timeout waiting for gossip post')), 15_000)),
    ]);

    expect(receivedContent).toBe('爆速テストメッセージ');

    senderOrch.clear();
    receiverOrch.clear();
  }, 25_000);

  it('BoardOrchestrator においても、スレッド作成パケットが即時伝播する', async () => {
    const n0 = await createSimNode('n0');
    const n1 = await createSimNode('n1');
    const n2 = await createSimNode('n2');
    const n3 = await createSimNode('n3');
    nodes = [n0, n1, n2, n3];

    link(n0, n1);
    link(n1, n2);
    link(n2, n3);
    link(n1, n3);

    startAll(nodes);
    await sleep(100);

    const boardKey = sodium.randombytes_buf(32);
    const boardId = 'vip';

    const ctx0 = await createAppContext(n0, 'fast_board_db_0');
    const ctx3 = await createAppContext(n3, 'fast_board_db_3');

    const cryptoEngine = new CryptoEngine();
    const senderIdentity = new Identity();
    const receiverIdentity = new Identity();

    const senderBoard = new BoardOrchestrator(
      n0.peerManager,
      ctx0.db,
      n0.gossip,
      cryptoEngine,
      syncPow,
      senderIdentity,
    );

    const receiverBoard = new BoardOrchestrator(
      n3.peerManager,
      ctx3.db,
      n3.gossip,
      cryptoEngine,
      syncPow,
      receiverIdentity,
    );

    await receiverBoard.activate(boardId, boardKey);
    await senderBoard.activate(boardId, boardKey);

    const receivedThreadPromise = new Promise<string>((resolve) => {
      const unsub = receiverBoard.subscribe(() => {
        const threads = receiverBoard.getThreads();
        const found = threads.find(t => t.content === '新板テストスレ');
        if (found) {
          unsub();
          resolve(found.content);
        }
      });
    });

    const startTime = performance.now();

    const createdThreadId = await senderBoard.submitThread(boardId, boardKey, '新板テストスレ');
    const sendDuration = performance.now() - startTime;

    expect(createdThreadId).toBeDefined();
    expect(sendDuration).toBeLessThan(2000);

    const title = await Promise.race([
      receivedThreadPromise,
      new Promise<null>((_, reject) => setTimeout(() => reject(new Error('Timeout waiting for board thread')), 15_000)),
    ]);

    expect(title).toBe('新板テストスレ');

    senderBoard.clear();
    receiverBoard.clear();
  }, 25_000);
});

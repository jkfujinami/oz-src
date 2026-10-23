import { describe, it, expect, vi, beforeEach } from 'vitest';
import { OzNode } from '../src/node/OzNode';
import { IndexedDBStore } from '../src/storage/IndexedDBStore';
import { VAULT_PARAMS_FAST } from '../src/storage/SecretVault';
import 'fake-indexeddb/auto';

describe('OzNode Facade', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('OzNode インスタンスが全サブシステムを自動配線して生成される', async () => {
    const db = new IndexedDBStore();
    await db.init();

    const node = await OzNode.create({
      storage: { slotEffort: 1, chunkEffort: 1 }, // ★ 保管の PoW は軽く (CPU を食って他のテストの時間を乱さないように)
      db,
      trackerUrl: 'ws://localhost:9999/ws',
      autoStart: false,
      passphrase: 'test-passphrase',
      vaultParams: VAULT_PARAMS_FAST,
    });

    expect(node).toBeDefined();
    expect(typeof node.peerId).toBe('string');
    expect(node.peerId.length).toBe(32); // Hex 32 文字 (16 バイト PeerId)
    expect(node.degree).toBe(0);
    expect(node.running).toBe(false);

    // 主要サブシステムが注入されているか
    expect(node.boardOrchestrator).toBeDefined();
    expect(node.threadOrchestrator).toBeDefined();
    expect(node.catchupClient).toBeDefined();
    expect(node.catchupServer).toBeDefined();
    expect(node.dandelion).toBeDefined();
    expect(node.peerManager).toBeDefined();

    // 停止処理の呼び出し確認
    await node.stop();
    expect(node.running).toBe(false);
    // 停止の後は署名に使う鍵 (identity) が消えている: 停止後に投稿の署名は起きない
    expect(() => node.identity.sign(new Uint8Array(1))).toThrow(/disposed/);
  });

  it('パスワード無しでは起動しない (ローカルデータは必ず暗号化する)', async () => {
    const db = new IndexedDBStore('NoPassDB_' + Date.now());
    await expect(OzNode.create({ db, autoStart: false })).rejects.toThrow(RangeError);
  });
});

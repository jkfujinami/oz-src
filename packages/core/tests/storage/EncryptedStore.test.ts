import { describe, it, expect, beforeAll } from 'vitest';
import 'fake-indexeddb/auto';
import { openDB } from 'idb';
import { sodiumReady } from '../../src/crypto/sodium';
import { IndexedDBStore } from '../../src/storage/IndexedDBStore';
import { WrongPassphraseError } from '../../src/storage/DataVault';
import { SecretVault, VAULT_PARAMS_FAST } from '../../src/storage/SecretVault';

const PASS = 'correct horse battery staple';
const BOARD = 'secret-board-xyz';
const THREAD = 'thread-abc-123';

let seq = 0;
const freshName = () => `enc_${Date.now()}_${seq++}`;

/** IndexedDB の中身を、鍵を使わずに丸ごと文字列化する (押収者の視点) */
async function rawDump(name: string): Promise<string> {
  const db = await openDB(name);
  const out: string[] = [];
  for (const store of Array.from(db.objectStoreNames)) {
    const keys = await db.getAllKeys(store);
    const values = await db.getAll(store);
    out.push(JSON.stringify(keys), JSON.stringify(values, (_k, v) =>
      v instanceof Uint8Array ? Buffer.from(v).toString('latin1') : v));
  }
  db.close();
  return out.join('\n');
}

async function unlocked(name: string, pass = PASS): Promise<IndexedDBStore> {
  const store = new IndexedDBStore(name);
  await store.init();
  await store.unlock(pass, VAULT_PARAMS_FAST);
  return store;
}

describe('端末データの暗号化 (パスワード必須)', () => {
  beforeAll(async () => {
    await sodiumReady;
  });

  it('板 ID・スレッド ID・板の鍵が平文で残らない', async () => {
    const name = freshName();
    const store = await unlocked(name);
    const boardKey = new TextEncoder().encode('BOARD-KEY-MARKER-0123456789abcdef');

    await store.saveBoard(BOARD, boardKey);
    await store.save({
      boardId: BOARD,
      threadId: THREAD,
      payload: new TextEncoder().encode('POST-BODY-MARKER'),
      dag: { parents: [], cumulative_pow: 12, thread_root: THREAD, created_at: Date.now() },
    });
    await store.setSetting('guard-history', { note: 'SETTING-MARKER' });

    const dump = await rawDump(name);
    for (const marker of [BOARD, THREAD, 'BOARD-KEY-MARKER', 'POST-BODY-MARKER', 'SETTING-MARKER']) {
      expect(dump).not.toContain(marker);
    }

    // 正しいパスワードなら読める
    expect(Array.from((await store.getBoardKey(BOARD))!)).toEqual(Array.from(boardKey));
    expect((await store.getPosts(BOARD, THREAD)).map(p => new TextDecoder().decode(p.payload))).toEqual(['POST-BODY-MARKER']);
    expect((await store.getThreads(BOARD)).map(t => t.threadId)).toEqual([THREAD]);
    expect((await store.listBoards()).map(b => b.boardId)).toEqual([BOARD]);
  });

  it('違うパスワードではロックを解除できない', async () => {
    const name = freshName();
    const store = await unlocked(name);
    store.lock();

    const other = new IndexedDBStore(name);
    await other.init();
    await expect(other.unlock('wrong passphrase', VAULT_PARAMS_FAST)).rejects.toBeInstanceOf(WrongPassphraseError);
    expect(other.isUnlocked).toBe(false);
  });

  it('空のパスワードは受け付けない', async () => {
    const store = new IndexedDBStore(freshName());
    await store.init();
    await expect(store.unlock('', VAULT_PARAMS_FAST)).rejects.toThrow(RangeError);
  });

  it('ロック中はデータを読み書きできない (fail-closed)', async () => {
    const name = freshName();
    const store = await unlocked(name);
    store.lock();
    await expect(store.save({ boardId: BOARD, threadId: THREAD, payload: new Uint8Array(1) })).rejects.toThrow(/locked/);
    await expect(store.getBoardKey(BOARD)).rejects.toThrow(/locked/);
  });

  it('パスワードを変えても、データを再暗号化せずに読める', async () => {
    const name = freshName();
    const store = await unlocked(name);
    await store.saveBoard(BOARD, new Uint8Array([1, 2, 3]));
    await store.changePassphrase(PASS, 'new passphrase', VAULT_PARAMS_FAST);
    store.lock();

    const again = new IndexedDBStore(name);
    await again.init();
    await expect(again.unlock(PASS, VAULT_PARAMS_FAST)).rejects.toBeInstanceOf(WrongPassphraseError);
    await again.unlock('new passphrase', VAULT_PARAMS_FAST);
    expect(Array.from((await again.getBoardKey(BOARD))!)).toEqual([1, 2, 3]);
  });

  it('緊急消去 (wipeAll) の後は何も残らず、新しいパスワードで作り直せる', async () => {
    const name = freshName();
    const store = await unlocked(name);
    await store.saveBoard(BOARD, new Uint8Array([9]));
    await store.wipeAll();

    const fresh = new IndexedDBStore(name);
    expect(await fresh.hasVault()).toBe(false);
    await fresh.unlock('another passphrase', VAULT_PARAMS_FAST);
    expect(await fresh.listBoards()).toEqual([]);
  });

  it('v6 の平文データは初回のロック解除で暗号化して移し、平文側は消す', async () => {
    const name = freshName();
    // v6 の形の DB を直接作る
    const legacy = await openDB(name, 6, {
      upgrade(db) {
        db.createObjectStore('mailbox', { keyPath: 'topicHash' }).createIndex('lastUpdated', 'lastUpdated');
        const posts = db.createObjectStore('posts', { keyPath: 'id', autoIncrement: true });
        posts.createIndex('board_thread', ['boardId', 'threadId']);
        posts.createIndex('timestamp', 'timestamp');
        db.createObjectStore('identity', { keyPath: 'key' });
        db.createObjectStore('threads', { keyPath: 'threadId' }).createIndex('boardId', 'boardId');
      },
    });
    await legacy.add('posts', { boardId: BOARD, threadId: THREAD, payload: new Uint8Array([1]), timestamp: 1 });
    await legacy.put('threads', { threadId: THREAD, boardId: BOARD, max_pow: 3, created_at: 1, last_updated: 1 });
    await legacy.put('identity', { key: 'trip', sealed: SecretVault.seal(new Uint8Array(96), '', VAULT_PARAMS_FAST) });
    legacy.close();

    const store = await unlocked(name);
    expect(await store.getPosts(BOARD, THREAD)).toHaveLength(1);
    expect((await store.getThreads(BOARD))[0].max_pow).toBe(3);
    // 保護なしで封印されていたトリップは、DEK 配下の新形式に移される
    expect(await store.getSealed('trip')).toBeUndefined();
    expect((await store.getSecret('trip'))!.secret).toHaveLength(96);

    const dump = await rawDump(name);
    expect(dump).not.toContain(BOARD);
    expect(dump).not.toContain(THREAD);
  });
});

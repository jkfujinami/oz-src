/**
 * IndexedDBStore の、EncryptedStore.test.ts で扱っていない性質:
 *   - ロック前・初期化前の挙動 (fail-closed)
 *   - DEK スロットの予約
 *   - 封印済み鍵の meta の暗号化
 *   - レコードのすり替え・改竄の検出 (AD による置き場所の束縛)
 *   - 平文で残るフィールドの最小化 (日単位の保管日だけ)
 *   - Mailbox の重複排除・期限切れ削除・使用量
 */
import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest';
import 'fake-indexeddb/auto';
import { openDB } from 'idb';
import { sodiumReady } from '../../src/crypto/sodium';
import { IndexedDBStore, WrongPassphraseError } from '../../src/storage/IndexedDBStore';
import { SecretVault, VAULT_PARAMS_FAST } from '../../src/storage/SecretVault';
import { setSink } from '../../src/common/Logger';

const PASS = 'hardening passphrase';
const DAY = 24 * 60 * 60 * 1000;
const enc = (s: string) => new TextEncoder().encode(s);

let seq = 0;
const freshName = () => `idbh_${process.pid}_${seq++}`;

async function unlocked(name: string, pass = PASS): Promise<IndexedDBStore> {
  const store = new IndexedDBStore(name);
  await store.init();
  await store.unlock(pass, VAULT_PARAMS_FAST);
  return store;
}

/** 鍵を使わずに DB の生の行を読む (押収者の視点) */
async function rawRows(name: string, storeName: string): Promise<any[]> {
  const db = await openDB(name);
  try {
    return await db.getAll(storeName);
  } finally {
    db.close();
  }
}

async function rawDump(name: string): Promise<string> {
  const db = await openDB(name);
  const out: string[] = [];
  for (const store of Array.from(db.objectStoreNames)) {
    out.push(JSON.stringify(await db.getAllKeys(store)));
    out.push(JSON.stringify(await db.getAll(store), (_k, v) => (v instanceof Uint8Array ? Buffer.from(v).toString('latin1') : v)));
  }
  db.close();
  return out.join('\n');
}

/** 生の行を書き換える */
async function rawMutate(name: string, storeName: string, fn: (rows: any[]) => any[]): Promise<void> {
  const db = await openDB(name);
  try {
    const rows = await db.getAll(storeName);
    const next = fn(rows);
    await db.clear(storeName);
    for (const r of next) await db.put(storeName, r);
  } finally {
    db.close();
  }
}

beforeAll(async () => {
  await sodiumReady;
  setSink({ error() {}, warn() {}, info() {}, log() {}, debug() {} });
});

afterEach(() => {
  vi.useRealTimers();
});

describe('IndexedDBStore: 初期化前・ロック中 (fail-closed)', () => {
  it('init 前の読み書きは何もしない (例外も平文書き込みも無い)', async () => {
    const store = new IndexedDBStore(freshName());
    await expect(store.save({ boardId: 'b', threadId: 't', payload: new Uint8Array(1) })).resolves.toBeUndefined();
    expect(await store.getThreads('b')).toEqual([]);
    expect(await store.getPosts('b', 't')).toEqual([]);
    expect(await store.getSecret('trip')).toBeUndefined();
    await expect(store.saveSecret('trip', new Uint8Array(1))).resolves.toBeUndefined();
    await expect(store.deleteSecret('trip')).resolves.toBeUndefined();
    expect(store.isUnlocked).toBe(false);
  });

  it('ロック中はすべてのデータ操作が locked で失敗する', async () => {
    const store = await unlocked(freshName());
    store.lock();
    expect(store.isUnlocked).toBe(false);
    const ops: Array<() => Promise<unknown>> = [
      () => store.getThreads('b'),
      () => store.getPosts('b', 't'),
      () => store.saveBoard('b', new Uint8Array(32)),
      () => store.listBoards(),
      () => store.removeBoard('b'),
      () => store.getSetting('x'),
      () => store.setSetting('x', 1),
      () => store.saveSecret('node', new Uint8Array(1), { peerId: 'x' }),
    ];
    for (const op of ops) await expect(op()).rejects.toThrow(/locked/);
  });

  it('hasVault はロック解除前でも分かり、別インスタンスにも引き継がれる', async () => {
    const name = freshName();
    const a = new IndexedDBStore(name);
    expect(await a.hasVault()).toBe(false);
    await a.unlock(PASS, VAULT_PARAMS_FAST);
    expect(await a.hasVault()).toBe(true);
    const b = new IndexedDBStore(name);
    expect(await b.hasVault()).toBe(true);
    expect(b.isUnlocked).toBe(false);
  });

  it('違うパスワードで失敗しても DEK の封印は作り直されない', async () => {
    const name = freshName();
    const first = await unlocked(name);
    await first.setSetting('k', 'v');
    first.lock();
    const before = (await rawRows(name, 'identity')).find((r) => r.key === '__dek__');

    const other = new IndexedDBStore(name);
    await expect(other.unlock('wrong', VAULT_PARAMS_FAST)).rejects.toBeInstanceOf(WrongPassphraseError);
    const after = (await rawRows(name, 'identity')).find((r) => r.key === '__dek__');
    expect(Buffer.from(after.sealed.ciphertext).equals(Buffer.from(before.sealed.ciphertext))).toBe(true);

    await other.unlock(PASS, VAULT_PARAMS_FAST);
    expect(await other.getSetting('k')).toBe('v');
  });

  it('lock 後に正しいパスワードで unlock し直せば読める', async () => {
    const store = await unlocked(freshName());
    await store.setSetting('k', { n: 1 });
    store.lock();
    await store.unlock(PASS, VAULT_PARAMS_FAST);
    expect(await store.getSetting('k')).toEqual({ n: 1 });
  });

  it('changePassphrase: 旧パスワード違いは WrongPassphraseError で、元のパスワードは生きている', async () => {
    const name = freshName();
    const store = await unlocked(name);
    await expect(store.changePassphrase('wrong', 'new', VAULT_PARAMS_FAST)).rejects.toBeInstanceOf(WrongPassphraseError);
    await expect(store.changePassphrase(PASS, '', VAULT_PARAMS_FAST)).rejects.toThrow(RangeError);
    store.lock();
    await store.unlock(PASS, VAULT_PARAMS_FAST);
    expect(store.isUnlocked).toBe(true);
  });

  it('changePassphrase: 金庫が無ければ失敗する', async () => {
    const store = new IndexedDBStore(freshName());
    await expect(store.changePassphrase('a', 'b', VAULT_PARAMS_FAST)).rejects.toThrow(/no vault/);
  });

  it('wipeAll はロック解除なしで実行でき、DEK の封印ごと消えてロック状態になる', async () => {
    const name = freshName();
    const store = await unlocked(name);
    await store.setSetting('k', 'v');
    await store.wipeAll();
    expect(store.isUnlocked).toBe(false);

    const locked = new IndexedDBStore(name);
    await locked.init();
    await locked.wipeAll();
    const again = new IndexedDBStore(name);
    expect(await again.hasVault()).toBe(false);
  });
});

describe('IndexedDBStore: 封印済み鍵 (identity ストア)', () => {
  it('DEK のスロットは予約済みで、読めず・上書きできず・消せない', async () => {
    const name = freshName();
    const store = await unlocked(name);
    expect(await store.getSecret('__dek__')).toBeUndefined();
    expect(await store.getSealed('__dek__')).toBeUndefined();
    await expect(store.saveSecret('__dek__', new Uint8Array(32))).rejects.toThrow(RangeError);
    await expect(store.saveSealed('__dek__', SecretVault.seal(new Uint8Array(32), 'x', VAULT_PARAMS_FAST))).rejects.toThrow(RangeError);
    await store.deleteSecret('__dek__');
    expect(await store.hasVault()).toBe(true);
    store.lock();
    await store.unlock(PASS, VAULT_PARAMS_FAST);
    expect(store.isUnlocked).toBe(true);
  });

  it('meta は DEK で暗号化して保存され、平文で残らない', async () => {
    const name = freshName();
    const store = await unlocked(name);
    await store.saveSecret('node', new Uint8Array(96), { peerId: 'PEERID-MARKER-0123', powCounter: 77 });
    expect(await rawDump(name)).not.toContain('PEERID-MARKER-0123');
    const row = (await rawRows(name, 'identity')).find((r) => r.key === 'node');
    expect(row.meta).toBeUndefined();
    expect(row.sealed).toBeUndefined(); // 行全体が DEK で封印されている
    expect(row.e).toBeInstanceOf(Uint8Array);

    const got = await store.getSecret('node');
    expect(got!.meta).toEqual({ peerId: 'PEERID-MARKER-0123', powCounter: 77 });
    expect(got!.secret).toHaveLength(96);
  });

  it('meta が無くても行は封印され、ロック中は保存も読み出しもできない', async () => {
    const name = freshName();
    const store = await unlocked(name);
    await store.saveSecret('trip', new Uint8Array(96));
    const got = await store.getSecret('trip');
    expect(got!.meta).toBeUndefined();
    store.lock();
    await expect(store.saveSecret('trip', new Uint8Array(96))).rejects.toThrow(/locked/);
    await expect(store.getSecret('trip')).rejects.toThrow(/locked/);
  });

  it('暗号化された meta を別のスロットへ移しても読めない (スロットへの束縛)', async () => {
    const name = freshName();
    const store = await unlocked(name);
    await store.saveSecret('node', new Uint8Array(96), { powCounter: 5 });
    await store.saveSecret('trip', new Uint8Array(96));
    await rawMutate(name, 'identity', (rows) => {
      const node = rows.find((r) => r.key === 'node');
      const trip = rows.find((r) => r.key === 'trip');
      trip.e = node.e;
      return rows;
    });
    expect(await store.getSecret('trip')).toBeUndefined();
    expect((await store.getSecret('node'))!.meta).toEqual({ powCounter: 5 });
  });

  it('行を改竄すると undefined になる (例外は投げない)', async () => {
    const name = freshName();
    const store = await unlocked(name);
    await store.saveSecret('node', new Uint8Array(96), { powCounter: 5 });
    await rawMutate(name, 'identity', (rows) => {
      const node = rows.find((r) => r.key === 'node');
      node.e[node.e.length - 1] ^= 1;
      return rows;
    });
    expect(await store.getSecret('node')).toBeUndefined();
  });

  it('暗号化された meta はロック中には読めない', async () => {
    const store = await unlocked(freshName());
    await store.saveSecret('node', new Uint8Array(96), { powCounter: 5 });
    store.lock();
    await expect(store.getSecret('node')).rejects.toThrow(/locked/);
  });

  it('v6 の保護なしノード鍵は、平文 meta ごと DEK 配下の新形式に移される', async () => {
    const name = freshName();
    const legacy = await openDB(name, 6, {
      upgrade(db) {
        db.createObjectStore('identity', { keyPath: 'key' });
      },
    });
    const secret = new Uint8Array(96).fill(5);
    await legacy.put('identity', {
      key: 'node',
      sealed: SecretVault.seal(secret, '', VAULT_PARAMS_FAST),
      meta: { powCounter: 3, peerId: 'LEGACY-PEER-MARKER' },
    });
    legacy.close();

    const store = await unlocked(name);
    const got = await store.getSecret('node');
    expect(got!.meta).toEqual({ powCounter: 3, peerId: 'LEGACY-PEER-MARKER' });
    expect(Array.from(got!.secret)).toEqual(Array.from(secret));
    expect(await store.getSealed('node')).toBeUndefined();
    expect(await rawDump(name)).not.toContain('LEGACY-PEER-MARKER');
  });

  it('v6 の壊れた行は移行時に飛ばし、正常な行だけを移す', async () => {
    const name = freshName();
    const legacy = await openDB(name, 6, {
      upgrade(db) {
        db.createObjectStore('mailbox', { keyPath: 'topicHash' });
        db.createObjectStore('posts', { keyPath: 'id', autoIncrement: true });
        db.createObjectStore('threads', { keyPath: 'threadId' });
        db.createObjectStore('identity', { keyPath: 'key' });
      },
    });
    await legacy.put('mailbox', { topicHash: 'ok-topic', entries: [new Uint8Array([1])], lastUpdated: 1 });
    await legacy.add('posts', { boardId: 'B', threadId: 'T', payload: new Uint8Array([1]), timestamp: 1 });
    await legacy.add('posts', { boardId: 42, threadId: 'T', payload: new Uint8Array([2]), timestamp: 2 });
    await legacy.put('threads', { threadId: 'T', boardId: 'B', max_pow: 1 });
    await legacy.put('threads', { threadId: 'T2' });
    // 保護なしだが中身が壊れている (開けない) 封印
    await legacy.put('identity', { key: 'trip', sealed: { v: 1, protected: false } });
    legacy.close();

    const store = await unlocked(name);
    expect(await store.getPosts('B', 'T')).toHaveLength(1);
    expect((await store.getThreads('B')).map((t) => t.threadId)).toEqual(['T']);
    expect((await store.getSealed('trip'))!.sealed.protected).toBe(false);
    // 平文ストアは空になる
    // 旧 Mailbox ストアは v8 で捨てられている (移行しない)
    expect(await rawRows(name, 'posts')).toEqual([]);
    expect(await rawRows(name, 'threads')).toEqual([]);
  });
});

describe('IndexedDBStore: すり替え・改竄の検出', () => {
  it('板の鍵の行を入れ替えると、どちらの鍵も返さない', async () => {
    const name = freshName();
    const store = await unlocked(name);
    await store.saveBoard('board-A', new Uint8Array(32).fill(0xa));
    await store.saveBoard('board-B', new Uint8Array(32).fill(0xb));
    await rawMutate(name, 'boards', (rows) => {
      const [a, b] = rows;
      [a.blob, b.blob] = [b.blob, a.blob];
      return rows;
    });
    expect(await store.getBoardKey('board-A')).toBeNull();
    expect(await store.getBoardKey('board-B')).toBeNull();
    expect(await store.listBoards()).toEqual([]);
  });

  it('設定値の暗号文を別のキーへコピーしても読めない', async () => {
    const name = freshName();
    const store = await unlocked(name);
    await store.setSetting('public', 'harmless');
    await store.setSetting('secret', 'SENSITIVE');
    const vault = (store as any).vault;
    const pubK = vault.index('kv', 'public');
    const secK = vault.index('kv', 'secret');
    await rawMutate(name, 'kv', (rows) => {
      const secretBlob = rows.find((r) => r.k === secK).blob;
      return rows.map((r) => (r.k === pubK ? { ...r, blob: secretBlob } : r));
    });
    expect(await store.getSetting('public')).toBeUndefined();
    expect(await store.getSetting('secret')).toBe('SENSITIVE');
  });

  it('暗号文を 1 バイト改竄した設定値は undefined (例外は投げない)', async () => {
    const name = freshName();
    const store = await unlocked(name);
    await store.setSetting('x', { a: 1 });
    await rawMutate(name, 'kv', (rows) => rows.map((r) => { r.blob[30] ^= 1; return r; }));
    expect(await store.getSetting('x')).toBeUndefined();
  });

  it('暗号文が Uint8Array でない行 (型の改竄) も undefined', async () => {
    const name = freshName();
    const store = await unlocked(name);
    await store.setSetting('x', 1);
    await rawMutate(name, 'kv', (rows) => rows.map((r) => ({ ...r, blob: 'garbage' })));
    expect(await store.getSetting('x')).toBeUndefined();
  });

  it('投稿を別スレッドの索引へ移しても、そのスレッドの投稿としては返らない', async () => {
    const name = freshName();
    const store = await unlocked(name);
    await store.save({ boardId: 'B', threadId: 'T1', payload: enc('in T1') });
    await store.save({ boardId: 'B', threadId: 'T2', payload: enc('in T2') });
    await rawMutate(name, 'eposts', (rows) => {
      const t2bt = rows[1].bt;
      return rows.map((r) => ({ ...r, bt: t2bt }));
    });
    const t2 = await store.getPosts('B', 'T2');
    expect(t2.map((p) => new TextDecoder().decode(p.payload))).toEqual(['in T2']);
    expect(await store.getPosts('B', 'T1')).toEqual([]);
  });

  it('スレッド統計の板索引を書き換えても、別の板のスレッドとして返らない', async () => {
    const name = freshName();
    const store = await unlocked(name);
    await store.save({ boardId: 'A', threadId: 'TA', payload: enc('x'), dag: { thread_root: 'TA', cumulative_pow: 1, created_at: 1 } });
    await store.save({ boardId: 'B', threadId: 'TB', payload: enc('y'), dag: { thread_root: 'TB', cumulative_pow: 1, created_at: 1 } });
    const bIdx = (store as any).vault.index('board', 'B');
    await rawMutate(name, 'ethreads', (rows) => rows.map((r) => ({ ...r, b: bIdx })));
    // 板 A のスレッドの行も B の索引で引けるようになったが、中身の boardId で弾く
    expect((await openDB(name).then(async (db) => { const n = (await db.getAllFromIndex('ethreads', 'b', bIdx)).length; db.close(); return n; }))).toBe(2);
    expect((await store.getThreads('B')).map((t) => t.threadId)).toEqual(['TB']);
  });
});

describe('IndexedDBStore: 平文で残るもの', () => {
  it('各ストアの行には索引 (鍵付きハッシュ)・暗号文しか無い', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    const t = Date.UTC(2026, 0, 15, 13, 37, 42, 123);
    vi.setSystemTime(t);
    const name = freshName();
    const store = await unlocked(name);
    await store.save({ boardId: 'B', threadId: 'T', payload: enc('p'), dag: { thread_root: 'T', cumulative_pow: 3, created_at: t } });
    await store.saveBoard('B', new Uint8Array(32));
    await store.setSetting('s', 1);

    const keysOf = async (s: string) => (await rawRows(name, s)).map((r) => Object.keys(r).sort());
    expect(await keysOf('eposts')).toEqual([['blob', 'bt', 'id']]);
    expect(await keysOf('ethreads')).toEqual([['b', 'blob', 'k']]);
    expect(await keysOf('boards')).toEqual([['blob', 'k']]);
    expect(await keysOf('kv')).toEqual([['blob', 'k']]);

    for (const s of ['ethreads', 'boards', 'kv']) {
      for (const r of await rawRows(name, s)) expect(r.k).toMatch(/^[0-9a-f]{32}$/);
    }
    // ミリ秒単位の時刻は平文に残らない
    const dump = await rawDump(name);
    const dekRow = (await rawRows(name, 'identity')).find((r) => r.key === '__dek__');
    expect(dump.replace(String(dekRow.updatedAt), '')).not.toContain(String(t));
  });

  it('同じ板 ID でも用途 (板の鍵・スレッドの板索引) ごとに別の索引になる', async () => {
    const name = freshName();
    const store = await unlocked(name);
    await store.saveBoard('B', new Uint8Array(32));
    await store.save({ boardId: 'B', threadId: 'T', payload: enc('p'), dag: { thread_root: 'T' } });
    const boardRowK = (await rawRows(name, 'boards'))[0].k;
    const threadRowB = (await rawRows(name, 'ethreads'))[0].b;
    expect(boardRowK).not.toBe(threadRowB);
  });

  it('別のパスワード (別の DEK) で作った DB では、同じ板 ID でも索引が一致しない', async () => {
    const n1 = freshName();
    const n2 = freshName();
    await (await unlocked(n1)).saveBoard('same-board', new Uint8Array(32));
    await (await unlocked(n2)).saveBoard('same-board', new Uint8Array(32));
    expect((await rawRows(n1, 'boards'))[0].k).not.toBe((await rawRows(n2, 'boards'))[0].k);
  });
});

describe('IndexedDBStore: 旧 Mailbox ストアの撤去 (v8)', () => {
  it('v7 以前の DB を開くと、暗号化済みの emailbox も平文の mailbox も捨てられ、投稿などは残る', async () => {
    const name = freshName();
    const legacy = await openDB(name, 7, {
      upgrade(db) {
        db.createObjectStore('identity', { keyPath: 'key' });
        db.createObjectStore('eposts', { keyPath: 'id', autoIncrement: true }).createIndex('bt', 'bt');
        db.createObjectStore('ethreads', { keyPath: 'k' }).createIndex('b', 'b');
        db.createObjectStore('emailbox', { keyPath: 'k' }).createIndex('day', 'day');
        db.createObjectStore('mailbox', { keyPath: 'topicHash' });
        db.createObjectStore('boards', { keyPath: 'k' });
        db.createObjectStore('kv', { keyPath: 'k' });
      },
    });
    await legacy.put('emailbox', { k: 'abc', day: 1, blob: new Uint8Array([1, 2, 3]) });
    await legacy.put('mailbox', { topicHash: 't', entries: [], lastUpdated: 1 });
    legacy.close();

    const store = await unlocked(name);
    const db = await openDB(name);
    const names = Array.from(db.objectStoreNames);
    db.close();
    expect(names).not.toContain('emailbox');
    expect(names).not.toContain('mailbox');
    expect(names).toEqual(expect.arrayContaining(['eposts', 'ethreads', 'boards', 'kv', 'identity']));
    await store.setSetting('x', 1);
    expect(await store.getSetting('x')).toBe(1);
  });
});

describe('IndexedDBStore: 投稿・スレッド・板', () => {
  it('投稿は板・スレッドごとに分かれ、日付順 (同じ日は保存順) に並ぶ', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    const store = await unlocked(freshName());
    vi.setSystemTime(3 * DAY);
    await store.save({ boardId: 'B', threadId: 'T', payload: enc('third') });
    vi.setSystemTime(1 * DAY);
    await store.save({ boardId: 'B', threadId: 'T', payload: enc('first') });
    vi.setSystemTime(2 * DAY + 5000);
    await store.save({ boardId: 'B', threadId: 'T', payload: enc('second-a') });
    vi.setSystemTime(2 * DAY + 9000);
    await store.save({ boardId: 'B', threadId: 'T', payload: enc('second-b') });
    await store.save({ boardId: 'B', threadId: 'U', payload: enc('other thread') });
    await store.save({ boardId: 'C', threadId: 'T', payload: enc('other board') });
    const posts = await store.getPosts('B', 'T');
    expect(posts.map((p) => new TextDecoder().decode(p.payload))).toEqual(['first', 'second-a', 'second-b', 'third']);
    expect(posts.every((p) => typeof p.id === 'number')).toBe(true);
  });

  it('板 ID とスレッド ID の境界をずらした組み合わせは混ざらない', async () => {
    const store = await unlocked(freshName());
    await store.save({ boardId: 'ab', threadId: 'c', payload: enc('1') });
    await store.save({ boardId: 'a', threadId: 'bc', payload: enc('2') });
    expect((await store.getPosts('ab', 'c')).map((p) => new TextDecoder().decode(p.payload))).toEqual(['1']);
    expect((await store.getPosts('a', 'bc')).map((p) => new TextDecoder().decode(p.payload))).toEqual(['2']);
  });

  it('スレッド統計: max_pow は最大値を保ち、created_at は最初の有効値を保つ', async () => {
    const store = await unlocked(freshName());
    await store.save({ boardId: 'B', threadId: 'T', payload: enc('1'), dag: { thread_root: 'R', cumulative_pow: 5, created_at: 1000 } });
    await store.save({ boardId: 'B', threadId: 'T', payload: enc('2'), dag: { thread_root: 'R', cumulative_pow: 3, created_at: 999 } });
    await store.save({ boardId: 'B', threadId: 'T', payload: enc('3'), dag: { thread_root: 'R', cumulative_pow: 9, created_at: 5000 } });
    const [stats] = await store.getThreads('B');
    expect(stats.threadId).toBe('R');
    expect(stats.max_pow).toBe(9);
    expect(stats.created_at).toBe(1000);
  });

  it('スレッド統計: 不正な created_at は採用しない', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(777 * DAY + 12345);
    const store = await unlocked(freshName());
    await store.save({ boardId: 'B', threadId: 'T', payload: enc('1'), dag: { thread_root: 'T', created_at: NaN } });
    expect((await store.getThreads('B'))[0].created_at).toBe(777 * DAY);
    await store.save({ boardId: 'B', threadId: 'T2', payload: enc('1'), dag: { thread_root: 'T2', created_at: -5 } });
    expect((await store.getThreads('B')).find((t) => t.threadId === 'T2')!.created_at).toBe(777 * DAY);
  });

  it('板の鍵の上書き・削除・一覧 (追加順)', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    const store = await unlocked(freshName());
    vi.setSystemTime(1);
    await store.saveBoard('B1', new Uint8Array([1]));
    vi.setSystemTime(2);
    await store.saveBoard('B2', new Uint8Array([2]));
    vi.setSystemTime(3);
    await store.saveBoard('B1', new Uint8Array([3]));
    expect(Array.from((await store.getBoardKey('B1'))!)).toEqual([3]);
    expect((await store.listBoards()).map((b) => b.boardId)).toEqual(['B2', 'B1']);
    await store.removeBoard('B1');
    expect(await store.getBoardKey('B1')).toBeNull();
    expect(await store.getBoardKey('never')).toBeNull();
    expect((await store.listBoards()).map((b) => b.boardId)).toEqual(['B2']);
  });

  it('設定値は任意の構造を往復し、未設定は undefined', async () => {
    const store = await unlocked(freshName());
    expect(await store.getSetting('missing')).toBeUndefined();
    const v = { list: [1, 'two', null], bytes: new Uint8Array([9, 8]), nested: { ok: true } };
    await store.setSetting('cfg', v);
    expect(await store.getSetting('cfg')).toEqual(v);
  });
});

describe('IndexedDBStore.unlock: 解除済みでもパスワードを照合する (回帰テスト)', () => {
  it('解除済みのインスタンスに違うパスワードで unlock すると WrongPassphraseError', async () => {
    const store = await unlocked(freshName());
    await expect(store.unlock('Bad-Pass-Marker-9', VAULT_PARAMS_FAST)).rejects.toBeInstanceOf(WrongPassphraseError);
    await expect(store.unlock('', VAULT_PARAMS_FAST)).rejects.toThrow(RangeError);
  });

  it('正しいパスワードでの再 unlock は成功し、状態もデータも変わらない', async () => {
    const name = freshName();
    const store = await unlocked(name);
    await store.setSetting('k', 'v');
    const dekBefore = (await rawRows(name, 'identity')).find((r) => r.key === '__dek__');
    await store.unlock(PASS, VAULT_PARAMS_FAST);
    expect(store.isUnlocked).toBe(true);
    expect(await store.getSetting('k')).toBe('v');
    const dekAfter = (await rawRows(name, 'identity')).find((r) => r.key === '__dek__');
    expect(Buffer.from(dekAfter.sealed.ciphertext).equals(Buffer.from(dekBefore.sealed.ciphertext))).toBe(true);
  });

  it('照合に失敗しても既に開いている金庫は使え続け、ロックされたことにもならない', async () => {
    const store = await unlocked(freshName());
    await store.setSetting('k', 1);
    await expect(store.unlock('wrong', VAULT_PARAMS_FAST)).rejects.toBeInstanceOf(WrongPassphraseError);
    expect(store.isUnlocked).toBe(true);
    expect(await store.getSetting('k')).toBe(1);
  });

  it('パスワード変更後は、解除済みのインスタンスでも新しいパスワードでだけ照合が通る', async () => {
    const store = await unlocked(freshName());
    await store.changePassphrase(PASS, 'new pass', VAULT_PARAMS_FAST);
    await expect(store.unlock(PASS, VAULT_PARAMS_FAST)).rejects.toBeInstanceOf(WrongPassphraseError);
    await expect(store.unlock('new pass', VAULT_PARAMS_FAST)).resolves.toBeUndefined();
  });

  it('解除済みのまま DEK の封印が消えていれば (どのパスワードでも) 照合に失敗する', async () => {
    const name = freshName();
    const store = await unlocked(name);
    await rawMutate(name, 'identity', (rows) => rows.filter((r) => r.key !== '__dek__'));
    await expect(store.unlock(PASS, VAULT_PARAMS_FAST)).rejects.toBeInstanceOf(WrongPassphraseError);
  });
});

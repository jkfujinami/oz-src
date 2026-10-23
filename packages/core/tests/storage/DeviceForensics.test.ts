/**
 * 端末の押収・フォレンジックを想定した性質:
 *   - パスワード変更で DEK が入れ替わり、旧い封印のコピーでは現在のデータを読めない
 *   - 保存する時刻は日単位に丸めてある (封印の中でも)
 *   - identity の行は平文の時刻・保護フラグを持たない
 *   - 旧い KDF パラメータの封印は、ロック解除のたびに今の強度へ引き上げる
 *   - trip / node 鍵は DEK 配下 (アンロックの Argon2 は 1 回)
 */
import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest';
import 'fake-indexeddb/auto';
import { openDB } from 'idb';
import { sodiumReady } from '../../src/crypto/sodium';
import { IndexedDBStore } from '../../src/storage/IndexedDBStore';
import { DataVault, WrongPassphraseError } from '../../src/storage/DataVault';
import { SecretVault, VAULT_PARAMS, VAULT_PARAMS_FAST, isWeakerThan } from '../../src/storage/SecretVault';

const PASS = 'forensics passphrase one';
const PASS2 = 'forensics passphrase two';
const DAY = 24 * 60 * 60 * 1000;
const enc = (s: string) => new TextEncoder().encode(s);

let seq = 0;
const freshName = () => `forensics_${process.pid}_${seq++}`;

async function unlocked(name: string, pass = PASS, params = VAULT_PARAMS_FAST): Promise<IndexedDBStore> {
  const store = new IndexedDBStore(name);
  await store.init();
  await store.unlock(pass, params);
  return store;
}

async function rawRows(name: string, storeName: string): Promise<any[]> {
  const db = await openDB(name);
  try {
    return await db.getAll(storeName);
  } finally {
    db.close();
  }
}

/** 押収者が保存済みの DEK の封印をパスワードで開き、レコードを復号しようとする */
function vaultFromRow(row: any, pass: string): DataVault {
  return DataVault.open({ ...row.sealed, protected: true }, pass);
}

afterEach(() => vi.useRealTimers());
beforeAll(async () => { await sodiumReady; });

describe('パスワード変更で DEK を入れ替える (H1)', () => {
  it('旧い封印のコピーから旧 DEK を取り出しても、変更後のデータは読めない', async () => {
    const name = freshName();
    const store = await unlocked(name);
    await store.saveBoard('B1', new Uint8Array([1, 2, 3]));
    await store.save({ boardId: 'B1', threadId: 'T1', payload: enc('hello'), dag: { thread_root: 'T1', cumulative_pow: 3, created_at: 5 * DAY } });
    await store.setSetting('s', { a: 1 });
    const oldDekRow = (await rawRows(name, 'identity')).find((r) => r.key === '__dek__');

    await store.changePassphrase(PASS, PASS2, VAULT_PARAMS_FAST);

    // 新しいパスワードで、データはそのまま読める (検索キーも作り直されている)
    expect(Array.from((await store.getBoardKey('B1'))!)).toEqual([1, 2, 3]);
    expect((await store.getPosts('B1', 'T1')).map((p) => new TextDecoder().decode(p.payload))).toEqual(['hello']);
    expect((await store.getThreads('B1')).map((t) => t.threadId)).toEqual(['T1']);
    expect(await store.getSetting('s')).toEqual({ a: 1 });
    store.lock();
    const again = await unlocked(name, PASS2);
    expect((await again.listBoards()).map((b) => b.boardId)).toEqual(['B1']);

    // 旧い封印 (旧パスワードで開ける) は DB から消え、新しい DEK の封印に置き換わっている
    const newDekRow = (await rawRows(name, 'identity')).find((r) => r.key === '__dek__');
    expect(Buffer.from(newDekRow.sealed.ciphertext).equals(Buffer.from(oldDekRow.sealed.ciphertext))).toBe(false);
    expect(() => vaultFromRow(newDekRow, PASS)).toThrow();

    // 旧い封印のコピーを開いて得た旧 DEK では、DB 上のどのレコードも復号できない
    const oldVault = vaultFromRow(oldDekRow, PASS);
    for (const [storeName, prefix] of [['eposts', 'eposts:'], ['ethreads', 'ethreads:'], ['boards', 'boards:'], ['kv', 'kv:']] as const) {
      const rows = await rawRows(name, storeName);
      expect(rows.length).toBeGreaterThan(0);
      for (const row of rows) {
        expect(oldVault.open(row.blob, `${prefix}${row.bt ?? row.k}`)).toBeNull();
      }
    }
    // 現在の DEK なら開ける (対照)
    const cur = vaultFromRow(newDekRow, PASS2);
    const board = (await rawRows(name, 'boards'))[0];
    expect(cur.open(board.blob, `boards:${board.k}`)).not.toBeNull();
  });

  it('トリップ / ノード鍵は新しい DEK で包み直され、新しいパスワードで開け、旧パスワードでは開けない', async () => {
    const name = freshName();
    const store = await unlocked(name);
    const secret = new Uint8Array(96).fill(7);
    await store.saveSecret('trip', secret, { n: 1 });
    await store.saveSecret('node', secret, { peerId: 'p' });
    await store.changePassphrase(PASS, PASS2, VAULT_PARAMS_FAST);
    const got = await store.getSecret('trip');
    expect(got!.meta).toEqual({ n: 1 });
    expect(Array.from(got!.secret)).toEqual(Array.from(secret));
    store.lock();
    await expect(unlocked(name, PASS)).rejects.toBeInstanceOf(WrongPassphraseError);
    const again = await unlocked(name, PASS2);
    expect(Array.from((await again.getSecret('node'))!.secret)).toEqual(Array.from(secret));
  });

  it('旧形式 (独自の KDF で封印) の行が残っていても、変更後は新形式で新しい DEK 配下に移る', async () => {
    const name = freshName();
    const store = await unlocked(name);
    const secret = new Uint8Array(96).fill(5);
    await store.saveSealed('trip', SecretVault.seal(secret, PASS, VAULT_PARAMS_FAST), { n: 2 });
    await store.changePassphrase(PASS, PASS2, VAULT_PARAMS_FAST);
    expect(await store.getSealed('trip')).toBeUndefined();
    const got = await store.getSecret('trip');
    expect(got!.meta).toEqual({ n: 2 });
    expect(Array.from(got!.secret)).toEqual(Array.from(secret));
  });

  it('投稿の挿入順 (id) は変更後も保たれる', async () => {
    const name = freshName();
    const store = await unlocked(name);
    for (const t of ['a', 'b', 'c']) await store.save({ boardId: 'B', threadId: 'T', payload: enc(t) });
    const before = (await store.getPosts('B', 'T')).map((p) => p.id);
    await store.changePassphrase(PASS, PASS2, VAULT_PARAMS_FAST);
    const after = await store.getPosts('B', 'T');
    expect(after.map((p) => p.id)).toEqual(before);
    expect(after.map((p) => new TextDecoder().decode(p.payload))).toEqual(['a', 'b', 'c']);
  });

  it('ロック中に変更しても、ロックのまま (鍵をメモリに持ち込まない)', async () => {
    const name = freshName();
    const store = await unlocked(name);
    store.lock();
    await store.changePassphrase(PASS, PASS2, VAULT_PARAMS_FAST);
    expect(store.isUnlocked).toBe(false);
    await expect(unlocked(name, PASS2)).resolves.toBeDefined();
  });
});

describe('時刻は日単位に丸める (M2)', () => {
  it('投稿・スレッド統計・板の封印の中に、日の途中の時刻が残らない', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(100 * DAY + 12 * 3600_000 + 34_567);
    const name = freshName();
    const store = await unlocked(name);
    await store.save({ boardId: 'B', threadId: 'T', payload: enc('x'), dag: { thread_root: 'T', cumulative_pow: 1, created_at: NaN } });
    await store.touchThread('B', 'T', 100 * DAY + 5 * 3600_000); // last_post_at は呼び出し側の値 (公開済みの投稿時刻)
    await store.saveBoard('B', new Uint8Array([1]));

    const dekRow = (await rawRows(name, 'identity')).find((r) => r.key === '__dek__');
    const vault = vaultFromRow(dekRow, PASS);
    const post = vault.open<any>((await rawRows(name, 'eposts'))[0].blob, `eposts:${(await rawRows(name, 'eposts'))[0].bt}`)!;
    expect(post.timestamp).toBe(100 * DAY);
    const th = (await rawRows(name, 'ethreads'))[0];
    const stats = vault.open<any>(th.blob, `ethreads:${th.k}`)!;
    expect(stats.last_updated).toBe(100 * DAY);
    expect(stats.created_at).toBe(100 * DAY);
    expect(stats.last_post_at).toBe(100 * DAY + 5 * 3600_000);
    const bd = (await rawRows(name, 'boards'))[0];
    expect(vault.open<any>(bd.blob, `boards:${bd.k}`)!.addedAt).toBe(100 * DAY);
  });
});

describe('identity の行に平文の時刻・保護フラグを置かない (M1)', () => {
  it('trip / node 行は {key, e} だけ、DEK 行は {key, sealed} だけで、sealed に protected が無い', async () => {
    const name = freshName();
    const store = await unlocked(name);
    await store.saveSecret('trip', new Uint8Array(96));
    await store.saveSecret('node', new Uint8Array(96), { peerId: 'p' });
    const rows = await rawRows(name, 'identity');
    expect(rows.map((r) => r.key).sort()).toEqual(['__dek__', 'node', 'trip']);
    for (const r of rows) {
      expect(JSON.stringify(Object.keys(r).sort())).toBe(r.key === '__dek__' ? '["key","sealed"]' : '["e","key"]');
      expect(r).not.toHaveProperty('updatedAt');
      if (r.sealed) expect(r.sealed).not.toHaveProperty('protected');
    }
    // 行の中に SecretVault の封印 (protected / salt 等) は無い
    expect(await store.getSealed('trip')).toBeUndefined();
    expect((await store.getSecret('trip'))!.secret).toHaveLength(96);
  });

  it('旧形式 (updatedAt / protected 付きの DEK 行) は、ロック解除で落とされる', async () => {
    const name = freshName();
    const store = await unlocked(name);
    store.lock();
    const db = await openDB(name);
    const row = await db.get('identity', '__dek__');
    await db.put('identity', { ...row, updatedAt: 123456789, sealed: { ...row.sealed, protected: true } });
    db.close();
    await unlocked(name);
    const after = (await rawRows(name, 'identity')).find((r) => r.key === '__dek__');
    expect(after).not.toHaveProperty('updatedAt');
    expect(after.sealed).not.toHaveProperty('protected');
  });
});

describe('KDF パラメータの引き上げ (H2)', () => {
  it('既定は libsodium MODERATE (ops 3 / 256 MiB)', () => {
    expect(VAULT_PARAMS).toEqual({ opsLimit: 3, memLimit: 256 * 1024 * 1024 });
    expect(isWeakerThan(VAULT_PARAMS_FAST, VAULT_PARAMS)).toBe(true);
    expect(isWeakerThan(VAULT_PARAMS, VAULT_PARAMS)).toBe(false);
  });

  it('旧い (弱い) DEK の封印は、ロック解除に成功すると今のパラメータで包み直され、trip/node は無傷', async () => {
    const name = freshName();
    const store = await unlocked(name); // FAST で作成
    const secret = new Uint8Array(96).fill(9);
    await store.saveSecret('trip', secret, { m: 1 });
    await store.setSetting('keep', 'me');
    const before = (await rawRows(name, 'identity')).find((r) => r.key === '__dek__');
    expect(before.sealed.memLimit).toBe(VAULT_PARAMS_FAST.memLimit);
    store.lock();

    const stronger = { opsLimit: 2, memLimit: 32 * 1024 };
    const again = await unlocked(name, PASS, stronger);

    const after = (await rawRows(name, 'identity')).find((r) => r.key === '__dek__');
    expect(after.sealed.opsLimit).toBe(2);
    expect(after.sealed.memLimit).toBe(32 * 1024);
    // 同じパスワードで開け、データは無傷 (DEK は同じ)
    expect(await again.getSetting('keep')).toBe('me');
    const trip = (await again.getSecret('trip'))!;
    expect(trip.meta).toEqual({ m: 1 });
    expect(Array.from(trip.secret)).toEqual(Array.from(secret));

    // 以後の解除では包み直さない (封印がそのまま)
    again.lock();
    await unlocked(name, PASS, stronger);
    const third = (await rawRows(name, 'identity')).find((r) => r.key === '__dek__');
    expect(Buffer.from(third.sealed.ciphertext).equals(Buffer.from(after.sealed.ciphertext))).toBe(true);
  });
});

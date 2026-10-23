import { createHash, timingSafeEqual } from 'node:crypto';
import { chmod, mkdir, open, readFile, rename, rm, stat } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { deserialize, serialize } from 'node:v8';
import { createLogger } from '@oz/core';

const log = createLogger('guard.snapshot');

/**
 * 暗号化 DB (fake-indexeddb) のスナップショット。
 *
 * core の IndexedDBStore は idb 越しに IndexedDB を使う。Node には IndexedDB が無いので fake-indexeddb
 * (メモリ上の実装) を差し込み、その中身を定期的にファイルへ書き出し、起動時に戻す。
 *
 * ★ 中身は IndexedDBStore が封印したレコードだけ (DEK はパスフレーズで包まれている)。
 *   スナップショットを盗まれても、パスフレーズ無しでは何も読めない。それでもファイルは 0600、
 *   ディレクトリは 0700 にする (深層防御)。
 * ★ 書き込みは「一時ファイルに書く → fsync → rename」。途中で落ちても、古い完全なスナップショットか
 *   新しい完全なスナップショットのどちらかが残る。
 * ★ 壊れたスナップショットは **黙って捨てない**。捨てて空から始めると新しい身元 (peerId) を採掘してしまい、
 *   署名済みの Guard リストに載っている peerId を失う。起動を止めて運用者に知らせる。
 */

const MAGIC = Buffer.from('AGSNAP\x01\n', 'latin1');
const DIGEST_BYTES = 32;
export const SNAPSHOT_FILE = 'db.snapshot';

interface IndexSnap { name: string; keyPath: string | string[]; unique: boolean; multiEntry: boolean }
interface StoreSnap {
  name: string;
  keyPath: string | string[] | null;
  autoIncrement: boolean;
  indexes: IndexSnap[];
  /** [主キー, 値]。インラインキーのストアでも主キーを持つ (復元時は値から決まるので使わない) */
  records: Array<[IDBValidKey, unknown]>;
}
export interface DbSnapshot { name: string; version: number; stores: StoreSnap[] }

export class SnapshotCorruptError extends Error {}

const wait = <T>(req: IDBRequest<T>): Promise<T> =>
  new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });

const txDone = (tx: IDBTransaction): Promise<void> =>
  new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error ?? new Error('transaction aborted'));
  });

/** DB が (その名前で) 存在するか */
async function exists(factory: IDBFactory, name: string): Promise<boolean> {
  const dbs = await factory.databases();
  return dbs.some((d) => d.name === name);
}

/** DB の全内容を取り出す。1 つの読み取りトランザクションなので、ストア間で一貫した時点の像になる */
export async function dumpDatabase(factory: IDBFactory, name: string): Promise<DbSnapshot | null> {
  if (!(await exists(factory, name))) return null;
  const db = await wait(factory.open(name));
  try {
    const names = Array.from(db.objectStoreNames);
    const stores: StoreSnap[] = [];
    if (names.length > 0) {
      const tx = db.transaction(names, 'readonly');
      for (const storeName of names) {
        const os = tx.objectStore(storeName);
        const [keys, values] = await Promise.all([wait(os.getAllKeys()), wait(os.getAll())]);
        stores.push({
          name: storeName,
          keyPath: os.keyPath,
          autoIncrement: os.autoIncrement,
          indexes: Array.from(os.indexNames).map((n) => {
            const ix = os.index(n);
            return { name: n, keyPath: ix.keyPath, unique: ix.unique, multiEntry: ix.multiEntry };
          }),
          records: keys.map((k, i): [IDBValidKey, unknown] => [k, values[i]]),
        });
      }
      await txDone(tx);
    }
    return { name, version: db.version, stores };
  } finally {
    db.close();
  }
}

/** スナップショットから DB を作り直す (同じ名前の DB が既にあれば失敗する: 空の factory に対して呼ぶ) */
export async function restoreDatabase(factory: IDBFactory, snap: DbSnapshot): Promise<void> {
  const req = factory.open(snap.name, snap.version);
  req.onupgradeneeded = () => {
    const db = req.result;
    for (const s of snap.stores) {
      const os = db.createObjectStore(s.name, {
        ...(s.keyPath !== null ? { keyPath: s.keyPath } : {}),
        autoIncrement: s.autoIncrement,
      });
      for (const ix of s.indexes) os.createIndex(ix.name, ix.keyPath, { unique: ix.unique, multiEntry: ix.multiEntry });
    }
  };
  const db = await wait(req);
  try {
    if (snap.stores.length > 0) {
      const tx = db.transaction(snap.stores.map((s) => s.name), 'readwrite');
      for (const s of snap.stores) {
        const os = tx.objectStore(s.name);
        for (const [key, value] of s.records) {
          // インラインキーのストアは値の中のキーが使われる。外部キーのストアは明示する
          if (s.keyPath === null) os.put(value, key);
          else os.put(value);
        }
      }
      await txDone(tx);
    }
  } finally {
    db.close();
  }
}

export function encodeSnapshot(snap: DbSnapshot): Buffer {
  const body = serialize(snap);
  const digest = createHash('sha256').update(body).digest();
  return Buffer.concat([MAGIC, body, digest]);
}

export function decodeSnapshot(buf: Buffer): DbSnapshot {
  if (buf.length < MAGIC.length + DIGEST_BYTES || !buf.subarray(0, MAGIC.length).equals(MAGIC)) {
    throw new SnapshotCorruptError('スナップショットの形式が違います');
  }
  const body = buf.subarray(MAGIC.length, buf.length - DIGEST_BYTES);
  const digest = buf.subarray(buf.length - DIGEST_BYTES);
  if (!timingSafeEqual(createHash('sha256').update(body).digest(), digest)) {
    throw new SnapshotCorruptError('スナップショットのチェックサムが合いません');
  }
  const snap = deserialize(body) as DbSnapshot;
  if (typeof snap?.name !== 'string' || !Number.isInteger(snap.version) || !Array.isArray(snap.stores)) {
    throw new SnapshotCorruptError('スナップショットの中身が不正です');
  }
  return snap;
}

/** ディレクトリを 0700 で用意する。既にあれば権限を締める */
export async function ensurePrivateDir(dir: string): Promise<void> {
  await mkdir(dir, { recursive: true, mode: 0o700 });
  if (process.platform === 'win32') return;
  const st = await stat(dir);
  if ((st.mode & 0o077) !== 0) {
    try {
      await chmod(dir, 0o700);
      log.warn(() => 'data directory was accessible to other users; permissions tightened to 0700');
    } catch {
      throw new Error('データディレクトリの権限を 0700 にできません。所有者を確認してください');
    }
  }
}

/**
 * ファイルをアトミックに置き換える (0600)。
 * ★ 一時ファイルは `wx` で新規に作り、最初から 0600 で存在させる (作ってから chmod だと一瞬だけ広い権限になり得る)。
 */
export async function writeFileAtomic(path: string, data: Uint8Array): Promise<void> {
  const tmp = `${path}.tmp`;
  await rm(tmp, { force: true });
  const fh = await open(tmp, 'wx', 0o600);
  try {
    await fh.writeFile(data);
    await fh.sync();
  } finally {
    await fh.close();
  }
  await rename(tmp, path);
  // ディレクトリの fsync (rename の永続化)。取れない環境 (Windows) は諦める
  try {
    const dh = await open(dirname(path), 'r');
    try {
      await dh.sync();
    } finally {
      await dh.close();
    }
  } catch {
    // noop
  }
}

/** 1 つの DB をディレクトリへ保存・復元する */
export class SnapshotStore {
  private readonly file: string;
  private queue: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly dir: string,
    private readonly factory: IDBFactory,
    private readonly dbName: string,
  ) {
    this.file = join(dir, SNAPSHOT_FILE);
  }

  /** ディレクトリを用意し、あればスナップショットを factory へ戻す。戻したら true */
  async restore(): Promise<boolean> {
    await ensurePrivateDir(this.dir);
    // 前回、書き込み中に落ちたときの残骸
    await rm(`${this.file}.tmp`, { force: true });
    let buf: Buffer;
    try {
      buf = await readFile(this.file);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return false;
      throw err;
    }
    const snap = decodeSnapshot(buf);
    if (snap.name !== this.dbName) throw new SnapshotCorruptError('スナップショットが別の DB のものです');
    await restoreDatabase(this.factory, snap);
    return true;
  }

  /** 現在の DB をファイルへ書く。呼び出しは順番に実行される (重ならない)。DB がまだ無ければ何もしない */
  save(): Promise<boolean> {
    const run = async (): Promise<boolean> => {
      const snap = await dumpDatabase(this.factory, this.dbName);
      if (!snap) return false;
      await writeFileAtomic(this.file, encodeSnapshot(snap));
      return true;
    };
    const next = this.queue.then(run, run);
    this.queue = next.catch(() => undefined);
    return next;
  }
}

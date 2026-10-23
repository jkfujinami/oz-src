import { existsSync, mkdtempSync, readdirSync, rmSync, statSync, writeFileSync, readFileSync, chmodSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createIndexedDbFactory } from '../src/env';
import {
  SNAPSHOT_FILE, SnapshotCorruptError, SnapshotStore, decodeSnapshot, dumpDatabase, encodeSnapshot, writeFileAtomic,
} from '../src/snapshot';

const NAME = 'TestDB';
const mode = (p: string) => statSync(p).mode & 0o777;
const posix = process.platform !== 'win32';

function open(factory: IDBFactory, upgrade: boolean): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = factory.open(NAME, 3);
    req.onupgradeneeded = () => {
      if (!upgrade) return;
      const db = req.result;
      const a = db.createObjectStore('inline', { keyPath: 'id', autoIncrement: true });
      a.createIndex('by_tag', 'tag', { unique: false });
      db.createObjectStore('outline');
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function put(db: IDBDatabase, store: string, value: unknown, key?: IDBValidKey): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readwrite');
    tx.objectStore(store).put(value, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function fill(factory: IDBFactory): Promise<void> {
  const db = await open(factory, true);
  await put(db, 'inline', { tag: 'a', payload: new Uint8Array([1, 2, 3, 250]) });
  await put(db, 'inline', { tag: 'b', payload: new Uint8Array([9]) });
  await put(db, 'outline', { n: 1, bytes: new Uint8Array(1000).fill(7) }, 'k1');
  db.close();
}

describe('snapshot', () => {
  let dir: string;
  beforeEach(() => {
    dir = join(mkdtempSync(join(tmpdir(), 'oz-guard-snap-')), 'data');
  });
  afterEach(() => rmSync(join(dir, '..'), { recursive: true, force: true }));

  it('往復: ストア・索引・バイナリ・外部キーが戻る', async () => {
    const f1 = createIndexedDbFactory();
    await fill(f1);
    const store = new SnapshotStore(dir, f1, NAME);
    expect(await store.restore()).toBe(false); // 初回は何も無い
    expect(await store.save()).toBe(true);

    const f2 = createIndexedDbFactory();
    expect(await new SnapshotStore(dir, f2, NAME).restore()).toBe(true);
    const a = await dumpDatabase(f1, NAME);
    const b = await dumpDatabase(f2, NAME);
    expect(b).toEqual(a);
    expect(b?.version).toBe(3);
    expect(b?.stores.find((s) => s.name === 'inline')?.indexes[0]).toMatchObject({ name: 'by_tag', keyPath: 'tag' });
    expect(b?.stores.find((s) => s.name === 'outline')?.records[0][0]).toBe('k1');

    // 索引も使える (復元後の autoIncrement も続きから)
    const db = await open(f2, false);
    const hit = await new Promise<unknown[]>((resolve) => {
      const r = db.transaction('inline').objectStore('inline').index('by_tag').getAll('b');
      r.onsuccess = () => resolve(r.result);
    });
    expect(hit).toHaveLength(1);
    db.close();
  });

  it('DB がまだ無ければ書かない', async () => {
    const store = new SnapshotStore(dir, createIndexedDbFactory(), NAME);
    await store.restore();
    expect(await store.save()).toBe(false);
    expect(existsSync(join(dir, SNAPSHOT_FILE))).toBe(false);
  });

  it.skipIf(!posix)('ファイルは 0600・ディレクトリは 0700。広いディレクトリは締める', async () => {
    const f = createIndexedDbFactory();
    await fill(f);
    mkdirSync(dir, { recursive: true, mode: 0o755 });
    chmodSync(dir, 0o755);
    const store = new SnapshotStore(dir, f, NAME);
    await store.restore();
    expect(mode(dir)).toBe(0o700);
    await store.save();
    expect(mode(join(dir, SNAPSHOT_FILE))).toBe(0o600);
    await store.save(); // 上書きしても 0600 のまま
    expect(mode(join(dir, SNAPSHOT_FILE))).toBe(0o600);
  });

  it('アトミック書き込み: 一時ファイルは残らず、置き換わる。前回の残骸は無視して消す', async () => {
    mkdirSync(dir, { recursive: true });
    const p = join(dir, 'x.bin');
    await writeFileAtomic(p, Buffer.from('one'));
    await writeFileAtomic(p, Buffer.from('two'));
    expect(readFileSync(p, 'utf8')).toBe('two');
    expect(readdirSync(dir)).toEqual(['x.bin']);

    // 書き込み途中で落ちた残骸 (.tmp) があっても、完全なスナップショットが読まれる
    const f = createIndexedDbFactory();
    await fill(f);
    const store = new SnapshotStore(dir, f, NAME);
    await store.save();
    writeFileSync(join(dir, `${SNAPSHOT_FILE}.tmp`), 'half-written garbage');
    const f2 = createIndexedDbFactory();
    expect(await new SnapshotStore(dir, f2, NAME).restore()).toBe(true);
    expect(existsSync(join(dir, `${SNAPSHOT_FILE}.tmp`))).toBe(false);
  });

  it('書き込みが失敗しても、前の完全なスナップショットは壊れない', async () => {
    const f = createIndexedDbFactory();
    await fill(f);
    const store = new SnapshotStore(dir, f, NAME);
    await store.restore();
    await store.save();
    const before = readFileSync(join(dir, SNAPSHOT_FILE));
    // 一時ファイルの場所をディレクトリで塞ぐ → rm は消すので、代わりに書き込み先ディレクトリを読み取り専用にする
    if (posix && process.getuid?.() !== 0) {
      chmodSync(dir, 0o500);
      await expect(store.save()).rejects.toBeTruthy();
      chmodSync(dir, 0o700);
      expect(readFileSync(join(dir, SNAPSHOT_FILE)).equals(before)).toBe(true);
    }
  });

  it('壊れたスナップショットは黙って捨てず、復元を拒否する', async () => {
    const f = createIndexedDbFactory();
    await fill(f);
    const store = new SnapshotStore(dir, f, NAME);
    await store.restore();
    await store.save();
    const file = join(dir, SNAPSHOT_FILE);
    const buf = readFileSync(file);
    buf[buf.length >> 1] ^= 0xff;
    writeFileSync(file, buf);
    await expect(new SnapshotStore(dir, createIndexedDbFactory(), NAME).restore()).rejects.toThrow(SnapshotCorruptError);
    // 別の DB のもの
    await expect(new SnapshotStore(dir, createIndexedDbFactory(), 'Other').restore()).rejects.toThrow();
    expect(() => decodeSnapshot(Buffer.from('nope'))).toThrow(SnapshotCorruptError);
    expect(() => decodeSnapshot(encodeSnapshot({ name: NAME, version: 1, stores: [] }))).not.toThrow();
  });

  it('save を同時に呼んでも順番に処理される', async () => {
    const f = createIndexedDbFactory();
    await fill(f);
    const store = new SnapshotStore(dir, f, NAME);
    await store.restore();
    await Promise.all([store.save(), store.save(), store.save()]);
    expect(readdirSync(dir)).toEqual([SNAPSHOT_FILE]);
  });
});

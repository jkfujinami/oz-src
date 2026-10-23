import { describe, it, expect, beforeAll } from 'vitest';
import 'fake-indexeddb/auto';
import { sodiumReady } from '../../src/crypto/sodium';
import { Identity } from '../../src/crypto/Identity';
import { IndexedDBStore } from '../../src/storage/IndexedDBStore';
import { openDB } from 'idb';

beforeAll(async () => { await sodiumReady; });
const data = new TextEncoder().encode('x');
const pk = (id: Identity, boardId: string, threadId: string, day: number) =>
  Buffer.from(id.sign(data, { boardId, threadId, day }).sessionPubkey).toString('hex');

describe('セッション鍵は (板, スレ, 日) ごとに導出される', () => {
  it('同じ文脈なら同じ公開鍵、スレ・日・板が違えば別', () => {
    const id = new Identity();
    const a = pk(id, 'B', 'T1', 100);
    expect(pk(id, 'B', 'T1', 100)).toBe(a);
    expect(pk(id, 'B', 'T2', 100)).not.toBe(a);
    expect(pk(id, 'B', 'T1', 101)).not.toBe(a);
    expect(pk(id, 'C', 'T1', 100)).not.toBe(a);
    expect(pk(new Identity(), 'B', 'T1', 100)).not.toBe(a);
  });

  it('署名は検証でき、キャッシュを溢れさせても同じ鍵に戻る', () => {
    const id = new Identity();
    const ctx = { boardId: 'B', threadId: 'T', day: 1 };
    const sig = id.sign(data, ctx);
    expect(Identity.verify(data, sig.sessionPubkey, sig.sessionSignature)).toBe(true);
    const first = pk(id, 'B', 'T', 1);
    for (let i = 0; i < 20; i++) pk(id, 'B', `X${i}`, 1);
    expect(pk(id, 'B', 'T', 1)).toBe(first);
  });

  it('dispose 後は署名できない', () => {
    const id = new Identity();
    id.dispose();
    expect(() => id.sign(data, { boardId: 'B', threadId: 'T', day: 1 })).toThrow();
  });

  it('master は IndexedDB にも localStorage にも現れない', async () => {
    const id = new Identity();
    const master: Uint8Array = (id as any).master;
    const hex = Buffer.from(master).toString('hex');
    const b64 = Buffer.from(master).toString('base64');
    const name = `sk_${process.pid}`;
    const store = new IndexedDBStore(name);
    await store.init();
    await store.unlock('pass phrase long enough', (await import('../../src/storage/SecretVault')).VAULT_PARAMS_FAST);
    pk(id, 'B', 'T', 1);
    await store.setSetting('s', { a: 1 });
    const db = await openDB(name);
    let dump = '';
    for (const n of Array.from(db.objectStoreNames)) dump += JSON.stringify(await db.getAll(n), (_k, v) => v instanceof Uint8Array ? Buffer.from(v).toString('hex') : v);
    db.close();
    dump += JSON.stringify(Object.entries((globalThis as any).localStorage ?? {}));
    expect(dump.includes(hex)).toBe(false);
    expect(dump.includes(b64)).toBe(false);
  });
});

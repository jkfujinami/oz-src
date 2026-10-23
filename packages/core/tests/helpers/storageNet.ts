import 'fake-indexeddb/auto';
import { vi } from 'vitest';
import sodium from '../../src/crypto/sodium';
import { Encoding } from '../../src/common/Encoding';
import { IndexedDBStore } from '../../src/storage/IndexedDBStore';
import { StorageService, type StorageServiceParts } from '../../src/network/storage/StorageService';
import { decodeLeaseSet, signLeaseSet, type LeaseSet } from '../../src/network/storage/LeaseSet';
import { msToMinutes } from '../../src/crypto/PowPolicy';
import { unlockedStore } from './logicHarness';
import type { SimNode } from './onionNet';

/** 保管担当をつけたシミュレーション用ノード */
export interface StorageSimNode extends SimNode {
  storage: StorageService;
  db: IndexedDBStore;
  dbName: string;
}

let seq = 0;

/**
 * SimNode に StorageService (本物の暗号化 DB + HolderStore) をつなぐ。
 * 枠の PoW は effort 1 (約 65ms/枠)。gateway は誰でも可 (open の網)。
 */
export async function attachStorage(
  node: SimNode,
  over: Partial<StorageServiceParts> & { slots?: number; wait?: boolean } = {},
): Promise<StorageSimNode> {
  const dbName = `storage_${node.name}_${Date.now()}_${seq++}`;
  const db = await unlockedStore(dbName);
  const storage = await StorageService.create({
    peerManager: node.peerManager,
    dispatcher: node.dispatcher,
    dandelion: node.dandelion,
    gossipRouter: node.gossip,
    settings: { get: (n) => db.getSetting(n), set: (n, v) => db.setSetting(n, v) },
    holderDb: await db.openHolderDb(),
    gatewayAllowed: () => true,
    defaultSlots: over.slots ?? 1,
    slotEffort: 1,
    duty: { minRebuildMs: 0 },
    router: { syncMinIntervalMs: 0, syncFrameIntervalMs: 1 },
    ...over,
  });
  if (over.wait !== false) await storage.identity.ensureSlots(storage.capacitySlots);
  return Object.assign(node, { storage, db, dbName });
}

export async function stopStorage(nodes: StorageSimNode[]): Promise<void> {
  for (const n of nodes) {
    await n.storage.stop();
    n.db.lock();
  }
}

/** 署名は検証しない合成 leaseSet (担当の計算・容量の試験用)。SID は seed から決まる */
export function fakeLeaseSet(
  seed: number, slotCount = 1, over: { expiresMin?: number; gateway?: string } = {},
): LeaseSet {
  const sid = new Uint8Array(32);
  new DataView(sid.buffer).setUint32(0, seed, false);
  sid[31] = 0xfa;
  const slots = Array.from({ length: slotCount }, (_, i) => {
    const solution = sodium.crypto_generichash(16, Uint8Array.of(...sid, i, 0x55), null);
    return { nonce: seed ^ i, solution };
  });
  const bytes = signLeaseSet(
    {
      sid,
      slots,
      gateway: over.gateway ?? 'cd'.repeat(16),
      tunnelId: new Uint8Array(8).fill(seed & 0xff),
      expiresMin: over.expiresMin ?? msToMinutes(Date.now()) + 300,
    },
    () => new Uint8Array(64),
  );
  return decodeLeaseSet(bytes)!;
}

/** 生の IndexedDB を全部読み、全ての文字列・バイト列を 1 本の latin1 文字列にして返す (平文の探索用) */
export async function rawDump(dbName: string): Promise<string> {
  const db: IDBDatabase = await new Promise((resolve, reject) => {
    const req = indexedDB.open(dbName);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  const parts: string[] = [];
  const walk = (v: unknown): void => {
    if (v === null || v === undefined) return;
    if (typeof v === 'string') parts.push(v);
    else if (typeof v === 'number') parts.push(String(v));
    else if (Object.prototype.toString.call(v) === '[object Uint8Array]') parts.push(Buffer.from(v as Uint8Array).toString('latin1')); // ★大きな配列を spread で渡すと引数の上限を超える
    else if (Array.isArray(v)) v.forEach(walk);
    else if (typeof v === 'object') for (const [k, x] of Object.entries(v as object)) { parts.push(k); walk(x); }
  };
  for (const name of Array.from(db.objectStoreNames)) {
    const tx = db.transaction(name, 'readonly');
    const store = tx.objectStore(name);
    await new Promise<void>((resolve, reject) => {
      const cur = store.openCursor();
      cur.onsuccess = () => {
        const c = cur.result;
        if (!c) return resolve();
        walk(c.key);
        walk(c.value);
        c.continue();
      };
      cur.onerror = () => reject(cur.error);
    });
  }
  db.close();
  return parts.join('\u0001');
}

export const latin1 = (b: Uint8Array): string => Buffer.from(b).toString('latin1');
export const hexOf = Encoding.toHex;
export const spyDate = (ms: number) => vi.setSystemTime(ms);

import sodium from '../../src/crypto/sodium';
import { Encoding } from '../../src/common/Encoding';
import { createSimNode, link, announceVerified } from './onionNet';
import { attachTunnel, attachBehind, until, type TunnelSimNode } from './tunnelNet';
import type { TunnelRelayOptions } from '../../src/network/tunnel/TunnelRelay';
import type { TunnelHolderOptions } from '../../src/network/storage/TunnelHolder';
import type { FileUploaderParts } from '../../src/files/FileUploader';
import type { FileDownloaderParts } from '../../src/files/FileDownloader';
import { callTunnel, type TunnelTarget } from '../../src/network/tunnel/TunnelCall';
import { TUNNEL_KIND } from '../../src/network/tunnel/TunnelCrypto';
import { solveChunkPowSync } from '../../src/network/storage/ChunkPow';
import { FRAG_DATA_BYTES, decodeStatusResponse, encodePutFragment, fragmentCountFor, type ChunkStatus } from '../../src/network/storage/ChunkProtocol';
import { equixReady } from '../../src/crypto/equix/EquiX';
import { idOf } from '../../src/files/FileFormat';

/** テストの保存の PoW (effort 1 = 1 チャンク 約 65ms)。本番は CHUNK_EFFORT = 5 */
export const TEST_CHUNK_EFFORT = 1;

/** 利用者の上り枠をほぼ無制限にする (枠そのものの試験以外は、枠で時間がかからないように) */
export const LOOSE_CLIENT_SEND = {
  reqPerSec: 1e6, reqBurst: 1e6, concurrent: 32, bytesPerSec: 1e12, bytesBurst: 1e12, bytesPerDay: 1e15,
};

export interface FileNet {
  g1: TunnelSimNode;
  g2: TunnelSimNode;
  /** g1 の後ろに 4 台、g2 の後ろに 4 台 */
  holders: TunnelSimNode[];
  /** g1 の後ろ (上げる側) と g2 の後ろ (取る側)。保持者ではない (leaseSet を出さない) */
  u: TunnelSimNode;
  d: TunnelSimNode;
  all: TunnelSimNode[];
  uploaderParts(over?: Partial<FileUploaderParts>): FileUploaderParts;
  downloaderParts(over?: Partial<FileDownloaderParts>): FileDownloaderParts;
}

export interface BuildOptions {
  holders?: number;
  guardRelay?: TunnelRelayOptions;
  holderTunnel?: TunnelHolderOptions;
}

/**
 *      u ─┐                    ┌─ d
 *   h1a-d ┤ g1 ═══(backbone)═══ g2 ├ h2a-d     (保持者は 8 台、leaseSet を出して受け口に登録済み)
 */
export async function buildFileNet(opts: BuildOptions = {}): Promise<FileNet> {
  const perSide = Math.floor((opts.holders ?? 8) / 2);
  const guardIds = new Set<string>();
  const mkGuard = async (name: string) => attachTunnel(await createSimNode(name), {
    storage: { slots: 1, wait: false },
    relay: {
      role: 'guard', isBackbone: (id) => guardIds.has(id),
      ...opts.guardRelay,
      limits: { clientSend: LOOSE_CLIENT_SEND, ...opts.guardRelay?.limits },
    },
  });
  const g1 = await mkGuard('g1');
  const g2 = await mkGuard('g2');
  guardIds.add(g1.identity.peerId);
  guardIds.add(g2.identity.peerId);
  link(g1, g2);
  announceVerified(g1, g2);

  const holders: TunnelSimNode[] = [];
  const mkHolder = async (name: string, guard: TunnelSimNode) => {
    const n = await attachTunnel(await createSimNode(name), {
      storage: {
        slots: 1, chunkEffort: TEST_CHUNK_EFFORT,
        tunnel: { ...opts.holderTunnel, limits: { chunkIntervalMs: 1, ...opts.holderTunnel?.limits } },
      },
    });
    attachBehind(n, guard);
    holders.push(n);
    return n;
  };
  for (let i = 0; i < perSide; i++) await mkHolder(`h1${i}`, g1);
  for (let i = 0; i < perSide; i++) await mkHolder(`h2${i}`, g2);
  const mkClient = async (name: string, guard: TunnelSimNode) => {
    const n = await attachTunnel(await createSimNode(name), { storage: { slots: 1, wait: false, chunkEffort: TEST_CHUNK_EFFORT } });
    attachBehind(n, guard);
    return n;
  };
  const u = await mkClient('u', g1);
  const d = await mkClient('d', g2);

  for (const h of holders) h.storage.router.publish();
  await until(() => holders.every(h => h.storage.tunnel!.registered), 8000, 'holders registered');
  await until(() => [u, d].every(c => c.storage.leaseSets.size === holders.length), 8000, 'leaseSets');

  const routing = (n: TunnelSimNode) => ({ duty: n.storage.duty, leaseSets: n.storage.leaseSets, ownSid: () => n.sid });
  return {
    g1, g2, holders, u, d, all: [g1, g2, ...holders, u, d],
    uploaderParts: (over = {}) => ({
      tunnel: u.tunnel, routing: routing(u), chunkEffort: TEST_CHUNK_EFFORT,
      limits: { fragmentsPerSec: 1e6, roundDelayMs: [50, 100], retryBackoffMs: 20, ...over.limits },
      ...over,
    }),
    downloaderParts: (over = {}) => ({
      tunnel: d.tunnel, routing: routing(d),
      limits: { hedgeMs: 200, inactivityMs: 3000, roundDelayMs: 50, ...over.limits },
      ...over,
    }),
  };
}

export const targetOf = (from: TunnelSimNode, holder: TunnelSimNode): TunnelTarget => {
  const ls = from.storage.leaseSets.get(holder.sid)!;
  return { sidBytes: ls.sid, gateway: ls.gateway, tunnelId: ls.tunnelId };
};

/** 手書きの PUT (全断片を順に送り、各断片の status を返す)。PoW は effort 1 で解く。pow を渡せば不正な解も送れる */
export async function rawPut(
  from: TunnelSimNode, holder: TunnelSimNode, chunkId: Uint8Array, data: Uint8Array,
  pow?: { nonce: number; solution: Uint8Array },
): Promise<Array<ChunkStatus | null>> {
  await equixReady;
  const sol = pow ?? solveChunkPowSync(chunkId, TEST_CHUNK_EFFORT)!;
  const count = fragmentCountFor(data.length);
  const out: Array<ChunkStatus | null> = [];
  for (let i = 0; i < count; i++) {
    const payload = encodePutFragment({
      chunkId, powNonce: sol.nonce, powSolution: sol.solution, fragIndex: i, fragCount: count,
      data: data.subarray(i * FRAG_DATA_BYTES, Math.min(data.length, (i + 1) * FRAG_DATA_BYTES)),
    });
    const r = await callTunnel(from.tunnel, targetOf(from, holder), TUNNEL_KIND.PUT_CHUNK, payload, {
      inactivityMs: 3000, maxBytes: 16, maxPieces: 2,
    });
    out.push(r.data ? decodeStatusResponse(r.data) : null);
  }
  return out;
}

export const randBytes = (n: number): Uint8Array => {
  const out = new Uint8Array(n);
  for (let o = 0; o < n; o += 65536) out.set(sodium.randombytes_buf(Math.min(65536, n - o)), o);
  return out;
};

export const concatBytes = (parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((a, p) => a + p.length, 0));
  let o = 0;
  for (const p of parts) (out.set(p, o), (o += p.length));
  return out;
};

/** 生の IndexedDB の各ストアの行数 (何も書かれていないことの確認用) */
export async function rowCounts(dbName: string): Promise<Record<string, number>> {
  const db: IDBDatabase = await new Promise((resolve, reject) => {
    const req = indexedDB.open(dbName);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  const out: Record<string, number> = {};
  for (const name of Array.from(db.objectStoreNames)) {
    out[name] = await new Promise<number>((resolve, reject) => {
      const r = db.transaction(name, 'readonly').objectStore(name).count();
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error);
    });
  }
  db.close();
  return out;
}

export const peerIdRaw = (id: string): Uint8Array => Encoding.fromHex(id);

export const hasSubarray = (hay: Uint8Array, needle: Uint8Array): boolean => Buffer.from(hay).includes(Buffer.from(needle));

/**
 * 保持者 h が担当になるランダムなチャンク (大きさ n バイト)。8 台の環でも、複製の位置に近い 3 枠に必ず入るとは限らない
 * (15 の席に 8 台) ので、担当になるまで引き直す。
 */
export function dutyChunk(h: TunnelSimNode, n: number): { data: Uint8Array; id: Uint8Array } {
  for (;;) {
    const data = randBytes(n);
    const id = idOf(data);
    if (h.storage.duty.shouldStoreChunk(id)) return { data, id };
  }
}

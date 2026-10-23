import type { IDBPDatabase } from 'idb';
import { ByteReader, ByteWriter } from '../common/ByteIO';
import { createLogger } from '../common/Logger';

const log = createLogger('storage.chunk');

/** チャンクの保存先 (IndexedDB のオブジェクトストア名)。IndexedDBStore の upgrade が作る */
export const HOLD_CHUNK_STORE = 'hold_chunk';
export const HOLD_CHUNK_META_STORE = 'hold_cmeta';

/** HolderDB の封印の道具 (専用の鍵 HK から派生した鍵)。ここは使うだけで、鍵そのものは持たない */
export interface HolderSealer {
  seal(plain: Uint8Array, ad: string): Uint8Array;
  open(blob: unknown, ad: string): Uint8Array | null;
  index(label: string, value: string): string;
}

/**
 * チャンク 1 つの控え (封印して hold_cmeta に置く)。
 * ★ 時刻は**日の単位**にしか持たない (フォレンジック): 押収された端末で「このチャンクがいつ取られたか」を
 *   分・秒まで読めると、読み手の行動の時刻が漏れる。追い出しの順と 90 日の保持には日で足りる。
 */
export interface ChunkMeta {
  /** 預かった日 (UNIX 日番号) */
  storedDay: number;
  /** 最後に取られた日 (UNIX 日番号)。0 = 一度も取られていない */
  fetchDay: number;
  /** 封印後のバイト数 */
  bytes: number;
}

function encodeMeta(m: ChunkMeta): Uint8Array {
  return new ByteWriter().u8(1).u48(m.storedDay).u48(m.fetchDay).u48(m.bytes).finish();
}

function decodeMeta(b: Uint8Array): ChunkMeta | null {
  try {
    const r = new ByteReader(b);
    if (r.u8() !== 1) return null;
    const storedDay = r.u48();
    const fetchDay = r.u48();
    const bytes = r.u48();
    r.end();
    return { storedDay, fetchDay, bytes };
  } catch {
    return null;
  }
}

/**
 * ChunkDB — 大容量ファイルのチャンクの IndexedDB 層 (hold_chunk / hold_cmeta)。投稿のバケット (HolderDB の
 * hold_meta / hold_data) とは**別のストア**にして、容量の勘定と追い出しを混ぜない。
 *
 *   hold_chunk  { k, blob }   k = 鍵付きハッシュ(チャンク ID)。blob = 封印したチャンクの暗号文
 *   hold_cmeta  { k, blob }   blob = 封印した ChunkMeta (預かった日・最後に取られた日・大きさ)
 *
 * ★ 平文で残るのは「行の数と大きさ」と鍵付きハッシュの索引だけ。チャンク ID も、何日に取られたかも、
 *   パスワード無しでは読めない。保持者は元々、中身もファイル名も知らない (チャンクはファイルごとの鍵 K_f の暗号文)。
 * ★ 控えを別のストアにしたのは、起動時に全控えを読むため (追い出しの順を決める)。データと同じ行に置くと、
 *   数 GiB の本体まで読むことになる。
 * ★ 行の入れ替えを防ぐため、封印の AD に「ストア名:k」を入れる (別の k の行へ貼り替えても開けない)。
 */
export class ChunkDB {
  constructor(private readonly db: IDBPDatabase, private readonly sealer: HolderSealer) {}

  public chunkKey(chunkId: Uint8Array): string {
    let hex = '';
    for (const b of chunkId) hex += b.toString(16).padStart(2, '0');
    return this.sealer.index('chunk', hex);
  }

  /** 全チャンクの控えを読む (起動時に 1 回)。読めない控え・控えの無いデータは捨てる (別の鍵で書かれた残骸) */
  public async loadMeta(): Promise<Map<string, ChunkMeta>> {
    const out = new Map<string, ChunkMeta>();
    const orphan = new Set<string>();
    for (const row of await this.db.getAll(HOLD_CHUNK_META_STORE)) {
      const plain = this.sealer.open(row.blob, `${HOLD_CHUNK_META_STORE}:${row.k}`);
      const meta = plain ? decodeMeta(plain) : null;
      if (meta) out.set(row.k, meta);
      else orphan.add(row.k);
    }
    // 控えが無いまま残ったデータ (書き込み途中の中断) も片付ける
    for (const k of await this.db.getAllKeys(HOLD_CHUNK_STORE)) {
      if (!out.has(k as string)) orphan.add(k as string);
    }
    for (const k of orphan) await this.delete(k);
    if (orphan.size > 0) log.warn(`dropped ${orphan.size} unreadable chunk(s)`);
    return out;
  }

  /** チャンクを 1 つ足す (データと控えを 1 トランザクションで)。封印後のバイト数を返す */
  public async put(k: string, data: Uint8Array, meta: Omit<ChunkMeta, 'bytes'>): Promise<ChunkMeta> {
    const blob = this.sealer.seal(data, `${HOLD_CHUNK_STORE}:${k}`);
    const full: ChunkMeta = { ...meta, bytes: blob.length };
    const tx = this.db.transaction([HOLD_CHUNK_STORE, HOLD_CHUNK_META_STORE], 'readwrite');
    await tx.objectStore(HOLD_CHUNK_STORE).put({ k, blob });
    await tx.objectStore(HOLD_CHUNK_META_STORE).put({ k, blob: this.sealer.seal(encodeMeta(full), `${HOLD_CHUNK_META_STORE}:${k}`) });
    await tx.done;
    return full;
  }

  /** データを読む。無い・開けないは null */
  public async get(k: string): Promise<Uint8Array | null> {
    const row = await this.db.get(HOLD_CHUNK_STORE, k);
    return row ? this.sealer.open(row.blob, `${HOLD_CHUNK_STORE}:${k}`) : null;
  }

  /** 控えだけを書き換える (最後に取られた日の更新) */
  public async putMeta(k: string, meta: ChunkMeta): Promise<void> {
    await this.db.put(HOLD_CHUNK_META_STORE, { k, blob: this.sealer.seal(encodeMeta(meta), `${HOLD_CHUNK_META_STORE}:${k}`) });
  }

  public async delete(k: string): Promise<void> {
    const tx = this.db.transaction([HOLD_CHUNK_STORE, HOLD_CHUNK_META_STORE], 'readwrite');
    await tx.objectStore(HOLD_CHUNK_STORE).delete(k);
    await tx.objectStore(HOLD_CHUNK_META_STORE).delete(k);
    await tx.done;
  }
}

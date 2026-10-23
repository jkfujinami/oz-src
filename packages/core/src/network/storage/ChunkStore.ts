import { DAY_MS } from '../../crypto/PowPolicy';
import { createLogger } from '../../common/Logger';
import type { ChunkDB, ChunkMeta } from '../../storage/ChunkDB';

const log = createLogger('net.storage.chunks');

/** 保持日数。最後に預かった / 取られた日からこれだけ経ったら捨てる (取られるたびに延びる) */
export const CHUNK_RETENTION_DAYS = 90;
/**
 * 書き込み待ち (メモリ上のチャンク) の上限。1 つが最大 256KiB なので 32 件 = 8MiB。
 * ★ 超えたら FULL で断る (PUT を受ける側がメモリを食われないように)。
 */
const MAX_PENDING_PUTS = 32;

export interface ChunkStoreOptions {
  /** 容量の上限 (封印後のバイト数)。呼ぶたびに最新の枠の数で計算する。★ 投稿のバケットとは別枠 (StorageService) */
  quotaBytes: () => number;
  now?: () => number;
}

export type ChunkPutResult = 'stored' | 'exists' | 'full';

/**
 * ChunkStore — 保持者として預かる大容量ファイルのチャンク (docs/design/file-sharing.md §5)。
 *
 * ★ 預かる前の検査 (ハッシュ・PoW・担当) は呼び出し側 (TunnelHolder) が済ませる。ここは預かるだけ。
 * ★ **容量は投稿のバケットと別枠**。大容量が過去ログを押し出さない (設計 §6-3)。投稿は枠の 25% まで、チャンクは残り (StorageService)。
 * ★ 追い出しの順: **一度も取られていないものが先** (預かった日が古い順)、次に取られたもの (最後に取られた日が古い順、
 *   同じ日なら預かった日が古い順)。ゴミは誰にも取られないので先に落ちる。人気のあるチャンクは押し流されにくい。
 *   同じ日の中の順は、手元で預かった順 (Map の挿入順) で決まる。
 * ★ 保持 90 日: 最後に預かった日 / 取られた日から数える。取られるたびに延びる。
 * ★ 時刻は日の単位でしか持たない (ChunkDB の ★)。取られた日の更新は、その日の最初の 1 回だけ書く (ディスクへの書き込みを減らす)。
 * ★ 書き込みは 1 本の列に並べる (控えの更新と追い出しが競合しない)。
 */
export class ChunkStore {
  private meta = new Map<string, ChunkMeta>();
  private total = 0;
  private chain: Promise<unknown> = Promise.resolve();
  private pending = 0;
  private closed = false;
  private readonly now: () => number;

  private constructor(private readonly db: ChunkDB, private readonly opts: ChunkStoreOptions) {
    this.now = opts.now ?? Date.now;
  }

  public static async open(db: ChunkDB, opts: ChunkStoreOptions): Promise<ChunkStore> {
    const store = new ChunkStore(db, opts);
    store.meta = await db.loadMeta();
    for (const m of store.meta.values()) store.total += m.bytes;
    return store;
  }

  public get totalBytes(): number {
    return this.total;
  }

  public get count(): number {
    return this.meta.size;
  }

  /** いまの容量の上限 (封印後のバイト数) */
  public get quota(): number {
    return this.opts.quotaBytes();
  }

  private today(): number {
    return Math.floor(this.now() / DAY_MS);
  }

  public has(chunkId: Uint8Array): boolean {
    return !this.closed && this.meta.has(this.db.chunkKey(chunkId));
  }

  /** 診断・テスト用: 控え (日の単位の時刻と大きさ)。無ければ undefined */
  public metaOf(chunkId: Uint8Array): ChunkMeta | undefined {
    return this.meta.get(this.db.chunkKey(chunkId));
  }

  private enqueue<T>(job: () => Promise<T>): Promise<T> {
    const run = this.chain.then(job, job);
    this.chain = run.catch(() => undefined);
    return run;
  }

  /**
   * チャンクを預かる。既にあれば 'exists' (預かった日だけ更新する)。容量に入らない・待ちが満杯なら 'full'。
   * 容量を超える分は、追い出しの順に捨てて空ける (入れるチャンク自身は捨てない)。
   */
  public put(chunkId: Uint8Array, data: Uint8Array): Promise<ChunkPutResult> {
    if (this.closed) return Promise.resolve('full');
    if (this.pending >= MAX_PENDING_PUTS) return Promise.resolve('full');
    this.pending++;
    return this.enqueue(async (): Promise<ChunkPutResult> => {
      try {
        if (this.closed) return 'full';
        const k = this.db.chunkKey(chunkId);
        const cur = this.meta.get(k);
        if (cur) {
          // 置き直しは預かった日を延ばす (保持の起点)
          if (cur.storedDay !== this.today()) {
            const next = { ...cur, storedDay: this.today() };
            await this.db.putMeta(k, next);
            this.meta.set(k, next);
          }
          return 'exists';
        }
        const quota = this.opts.quotaBytes();
        // 封印で 40 バイト (nonce 24 + タグ 16) 増える
        const sealed = data.length + 40;
        if (sealed > quota) return 'full';
        await this.evictFor(sealed, quota);
        const meta = await this.db.put(k, data, { storedDay: this.today(), fetchDay: 0 });
        this.meta.set(k, meta);
        this.total += meta.bytes;
        return 'stored';
      } catch (e) {
        log.warn('could not store a chunk', e);
        return 'full';
      } finally {
        this.pending--;
      }
    });
  }

  /** データを返し、最後に取られた日を今日にする。無い・期限切れ・開けないは null */
  public get(chunkId: Uint8Array): Promise<Uint8Array | null> {
    return this.enqueue(async () => {
      if (this.closed) return null;
      const k = this.db.chunkKey(chunkId);
      const m = this.meta.get(k);
      if (!m) return null;
      if (this.expired(m)) {
        await this.dropChunk(k, m);
        return null;
      }
      const data = await this.db.get(k);
      if (!data) {
        await this.dropChunk(k, m); // 控えだけ残った・開けない: 持っていないことにする
        return null;
      }
      const today = this.today();
      if (m.fetchDay !== today) {
        const next = { ...m, fetchDay: today };
        try {
          await this.db.putMeta(k, next);
          this.meta.set(k, next);
        } catch (e) {
          log.warn('could not record a fetch', e);
        }
      }
      return data;
    });
  }

  private expired(m: ChunkMeta): boolean {
    return this.today() - Math.max(m.storedDay, m.fetchDay) > CHUNK_RETENTION_DAYS;
  }

  /** 保持期間を過ぎたチャンクを捨てる。捨てた数 */
  public prune(): Promise<number> {
    return this.enqueue(async () => {
      let n = 0;
      for (const [k, m] of Array.from(this.meta)) {
        if (!this.expired(m)) continue;
        await this.dropChunk(k, m);
        n++;
      }
      if (n > 0) log.debug(() => `retention dropped ${n} chunk(s)`);
      return n;
    });
  }

  /** `need` バイトを足しても quota に収まるまで、追い出しの順に捨てる (列の中だけで呼ぶ) */
  private async evictFor(need: number, quota: number): Promise<number> {
    if (this.total + need <= quota) return 0;
    // 一度も取られていない (fetchDay = 0) が先頭、次に最後に取られた日が古い順、同じ日は預かった日が古い順。
    // 同順位は Map の挿入順 (Array.sort は安定)。
    const order = Array.from(this.meta.entries()).sort(
      (a, b) => a[1].fetchDay - b[1].fetchDay || a[1].storedDay - b[1].storedDay,
    );
    let n = 0;
    for (const [k, m] of order) {
      if (this.total + need <= quota) break;
      await this.dropChunk(k, m);
      n++;
    }
    if (n > 0) log.debug(() => `quota evicted ${n} chunk(s)`);
    return n;
  }

  /** 容量の設定を下げた直後などに、今すぐ収める */
  public enforceQuota(): Promise<number> {
    return this.enqueue(() => this.evictFor(0, this.opts.quotaBytes()));
  }

  private async dropChunk(k: string, m: ChunkMeta): Promise<void> {
    await this.db.delete(k);
    this.meta.delete(k);
    this.total -= m.bytes;
  }

  public flush(): Promise<void> {
    return this.enqueue(async () => undefined);
  }

  public async close(): Promise<void> {
    await this.flush();
    this.closed = true;
    await this.flush();
  }
}

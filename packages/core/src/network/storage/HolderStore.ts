import { DAY_MS } from '../../crypto/PowPolicy';
import { encodePacket } from '../../crypto/PacketCodec';
import { createLogger } from '../../common/Logger';
import type { GossipPacket } from '../../types';
import type { BucketMeta, HolderDB } from '../../storage/HolderDB';
import { birthDayOf } from './Duty';

const log = createLogger('net.storage.holder');

/** 保持日数。バケットの birthDay からこれだけ経ったら丸ごと捨てる */
export const HOLD_RETENTION_DAYS = 90;
/** 保存待ちの上限。追いつきで一気に届いても溢れないよう余裕を見る。超えたら新しい方を捨てる (次の追いつきで取り直せる) */
const MAX_PENDING = 20_000;
/** パケットの時刻 (OZ_EPOCH からの分) は encodePacket の先頭 [1..3] */
export function timeMinOf(bytes: Uint8Array): number {
  return (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
}

export interface HolderStoreOptions {
  /** 容量の上限 (バイト)。枠の数 × 256MiB。呼ぶたびに最新の枠の数で計算する */
  quotaBytes: () => number;
  now?: () => number;
}

/**
 * HolderStore — 保管担当として預かるバケット (history v2 §4.3)。
 *
 * ★ 保存するかどうか (担当か) は呼び出し側 (StorageService → Duty) が決める。ここは預かるだけ。
 * ★ 重複排除: パケット ID (主キー) ごとに 1 件。同じ投稿が live・追いつき・自分の発信で何度届いても 1 件。
 * ★ 保持: バケットの birthDay + 90 日を過ぎたら丸ごと削除。容量を超えたら birthDay が古いバケットから丸ごと削除。
 *   (パケット単位で捨てると、バケットが歯抜けになり、読み手が「全部ある」と信じてしまう。)
 * ★ 書き込みは 1 本の列に並べる (控えの更新が競合しない)。
 */
export class HolderStore {
  private meta = new Map<string, BucketMeta>();
  private total = 0;
  private chain: Promise<unknown> = Promise.resolve();
  private pending = 0;
  private closed = false;
  private readonly now: () => number;

  private constructor(private readonly db: HolderDB, private readonly opts: HolderStoreOptions) {
    this.now = opts.now ?? Date.now;
  }

  public static async open(db: HolderDB, opts: HolderStoreOptions): Promise<HolderStore> {
    const store = new HolderStore(db, opts);
    store.meta = await db.loadMeta();
    for (const m of store.meta.values()) store.total += m.bytes;
    return store;
  }

  /** 預かっている総量 (封印後のバイト数) */
  public get totalBytes(): number {
    return this.total;
  }

  /** いまの容量の上限 (封印後のバイト数。枠の容量のうち投稿の分) */
  public get quota(): number {
    return this.opts.quotaBytes();
  }

  public get bucketCount(): number {
    return this.meta.size;
  }

  public hasBucket(birthDay: number, tag: number): boolean {
    if (this.closed) return false;
    return this.meta.has(this.db.bucketKey(birthDay, tag));
  }

  private enqueue<T>(job: () => Promise<T>): Promise<T> {
    const run = this.chain.then(job, job);
    this.chain = run.catch(() => undefined);
    return run;
  }

  /**
   * パケットを預かる。保持期間を過ぎたものは預からない。
   * @returns 新しく保存したら true (重複・期間外・停止後・待ち行列が満杯は false)
   */
  public put(packet: GossipPacket): Promise<boolean> {
    if (this.closed) return Promise.resolve(false);
    const birthDay = birthDayOf(packet.timestamp, packet.age);
    if (this.expired(birthDay, this.now())) return Promise.resolve(false);
    if (this.pending >= MAX_PENDING) {
      log.warn('holder queue is full; dropping a packet (it can be fetched again later)');
      return Promise.resolve(false);
    }
    let bytes: Uint8Array;
    try {
      bytes = encodePacket(packet);
    } catch {
      return Promise.resolve(false);
    }
    this.pending++;
    return this.enqueue(async () => {
      try {
        if (this.closed) return false;
        const bk = this.db.bucketKey(birthDay, packet.tag);
        const cur = this.meta.get(bk) ?? null;
        const res = await this.db.putPacket(bk, packet.packet_id, bytes, cur, { birthDay, tag: packet.tag });
        if (!res.stored) return false;
        this.total += res.sealedBytes;
        this.meta.set(bk, res.meta);
        await this.evictOverQuota();
        return true;
      } catch (e) {
        log.warn('could not store a packet', e);
        return false;
      } finally {
        this.pending--;
      }
    });
  }

  /**
   * バケットのパケット (encodePacket のバイト列)。time ≥ sinceMinute (OZ_EPOCH からの分) のものを古い順に。
   * 預かっていなければ空。
   */
  public getBucket(birthDay: number, tag: number, sinceMinute: number = 0): Promise<Uint8Array[]> {
    // 書き込みの列に並べる: 直前に put したものが読めるように
    return this.enqueue(async () => {
      if (this.closed) return [];
      const bk = this.db.bucketKey(birthDay, tag);
      if (!this.meta.has(bk)) return [];
      const all = await this.db.getPackets(bk);
      return all
        .filter(b => b.length >= 4 && timeMinOf(b) >= sinceMinute)
        .sort((a, b) => timeMinOf(a) - timeMinOf(b));
    });
  }

  private expired(birthDay: number, nowMs: number): boolean {
    return nowMs > (birthDay + HOLD_RETENTION_DAYS) * DAY_MS;
  }

  /** 保持期間を過ぎたバケットを捨てる。捨てた数 */
  public prune(): Promise<number> {
    return this.enqueue(async () => {
      const now = this.now();
      let n = 0;
      for (const [bk, m] of Array.from(this.meta)) {
        if (!this.expired(m.birthDay, now)) continue;
        await this.dropBucket(bk, m);
        n++;
      }
      if (n > 0) log.debug(() => `retention dropped ${n} bucket(s)`);
      return n;
    });
  }

  /** 容量を超えていれば、birthDay の古いバケットから捨てる (呼ぶのは列の中だけ) */
  private async evictOverQuota(): Promise<number> {
    const quota = this.opts.quotaBytes();
    if (this.total <= quota) return 0;
    const order = Array.from(this.meta.entries()).sort(
      (a, b) => a[1].birthDay - b[1].birthDay || a[1].tag - b[1].tag,
    );
    let n = 0;
    for (const [bk, m] of order) {
      if (this.total <= quota) break;
      await this.dropBucket(bk, m);
      n++;
    }
    if (n > 0) log.debug(() => `quota evicted ${n} bucket(s)`);
    return n;
  }

  /** 容量の設定を下げた直後などに、今すぐ収める */
  public enforceQuota(): Promise<number> {
    return this.enqueue(() => this.evictOverQuota());
  }

  private async dropBucket(bk: string, m: BucketMeta): Promise<void> {
    await this.db.deleteBucket(bk);
    this.meta.delete(bk);
    this.total -= m.bytes;
  }

  /** 書き込み待ちが空になるまで待つ */
  public flush(): Promise<void> {
    return this.enqueue(async () => undefined);
  }

  /** 以後の書き込みを受け付けず、待ちを流してから鍵を消す */
  public async close(): Promise<void> {
    await this.flush();
    this.closed = true;
    await this.flush();
    this.db.lock();
  }
}

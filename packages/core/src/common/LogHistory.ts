import { onLogRecord, type LogRecord } from './Logger';

/** 画面のログ表示が持つ行数の既定 */
export const LOG_HISTORY_CAPACITY = 5000;

/**
 * LogHistory — 出たログの直近 N 行をメモリに持つ (画面の「状態とログ」用)。
 *
 * ★ 端末には書かない。ロックで clear する (画面側)。上限を超えたら古い行から捨てる。
 * ★ 購読者への通知は行ごとに呼ぶ。描画の間引きは受け手 (画面) が行う。
 */
export class LogHistory {
  private buf: LogRecord[] = [];
  private head = 0;
  private unsub: (() => void) | null = null;
  private listeners = new Set<() => void>();
  /** 上限で捨てた行の数 */
  public dropped = 0;

  constructor(public readonly capacity: number = LOG_HISTORY_CAPACITY) {}

  public start(): void {
    if (this.unsub) return;
    this.unsub = onLogRecord((r) => this.push(r));
  }

  public stop(): void {
    this.unsub?.();
    this.unsub = null;
  }

  public push(r: LogRecord): void {
    if (this.buf.length < this.capacity) {
      this.buf.push(r);
    } else {
      this.buf[this.head] = r;
      this.head = (this.head + 1) % this.capacity;
      this.dropped++;
    }
    for (const l of this.listeners) l();
  }

  /** 古い順の全行 (呼ぶたびに新しい配列) */
  public snapshot(): LogRecord[] {
    return this.head === 0 ? this.buf.slice() : this.buf.slice(this.head).concat(this.buf.slice(0, this.head));
  }

  public get size(): number {
    return this.buf.length;
  }

  public clear(): void {
    this.buf = [];
    this.head = 0;
    this.dropped = 0;
    for (const l of this.listeners) l();
  }

  public subscribe(fn: () => void): () => void {
    this.listeners.add(fn);
    return () => { this.listeners.delete(fn); };
  }
}

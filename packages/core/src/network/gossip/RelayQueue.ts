import type { GossipPacket, PeerId } from '../../types';
import { toBytes } from '../../crypto/PowPolicy';
import { packetCells, packetEffortPerCell } from './EffortAdvisor';

/**
 * RelayQueue — 中継の優先度キュー。
 *
 * ★ 全ノードが「自分が中継してよい量」に予算を持つ (トークンバケット、単位はセル)。
 *   予算の内側なら**待たせず即座に**流す (平常時に遅延を足さない)。予算を超えたら、待たせて
 *   e_c (1 セルあたりの effort) の高い順に流し、同じなら古い順。溢れたら e_c の低いものから捨てる。
 *   → 低 effort の洪水が網を埋めても、推奨 effort (EffortAdvisor) に従った正直な投稿が先に流れる。
 * ★ ローカル配信 (UI へ渡す) はこのキューを通らない。検証は安く、手元の表示まで遅らせる理由が無い。
 *   このキューが絞るのは「隣人への転送」だけ。隣人ごとの受信レート制限 (RateLimiter) は従来どおり別に働く。
 * ★ ワイヤには何も足さない (新しいメッセージ無し)。各ノードが自分の手元で順序を決めるだけ。
 * ★ 有界: 件数とバイト数の上限 (メモリの天井)。満杯で新しい投稿が来たら、キューの最低 e_c と比べて
 *   低い方を捨てる。同じ e_c なら新しい方を捨てる (先に待っていた方を優先 = FIFO と同じ)。
 *   最大/最小の両端を取るので、遅延削除つきの二つのヒープで持つ。
 */
export const RELAY_QUEUE = {
  /** 予算 (セル/秒)。想定の平均負荷 (1〜2 投稿/秒) と、ピーク (10〜20 投稿/秒) に十分な余裕を持たせた値 */
  RELAY_CELLS_PER_SEC: 40,
  /** バースト (セル)。この分は予算を超えても即座に流す (ピークの数秒を吸収する) */
  BURST_CELLS: 200,
  /** 待たせてよい投稿数・バイト数の上限 */
  MAX_PACKETS: 2000,
  MAX_BYTES: 4 * 1024 * 1024,
  /**
   * 待たせてよい最長 (ms)。これを超えたものは捨てる。
   * ★ 受け手は 15 分より古い時刻を拒否する (MAX_TIME_DRIFT)。そのうえ洪水が続くなら、この古さまで
   *   待った投稿はもう勝ち目がない。
   */
  MAX_WAIT_MS: 5 * 60 * 1000,
} as const;

export interface RelayQueueOptions {
  cellsPerSec?: number;
  burstCells?: number;
  maxPackets?: number;
  maxBytes?: number;
  maxWaitMs?: number;
  now?: () => number;
  /** テスト用: タイマー。戻り値は clear に渡す */
  setTimer?: (fn: () => void, ms: number) => unknown;
  clearTimer?: (handle: unknown) => void;
}

interface Entry {
  packet: GossipPacket;
  exclude: PeerId | null;
  cells: number;
  ec: number;
  bytes: number;
  seq: number;
  at: number;
  dead: boolean;
}

/** a の方が先に流す価値が高い (e_c が高い。同じなら古い) */
function better(a: Entry, b: Entry): boolean {
  return a.ec !== b.ec ? a.ec > b.ec : a.seq < b.seq;
}

/** 比較関数つきの二分ヒープ (先頭 = lt が最も真になる要素) */
class Heap {
  private a: Entry[] = [];
  constructor(private lt: (x: Entry, y: Entry) => boolean) {}
  get length(): number { return this.a.length; }
  peek(): Entry | undefined { return this.a[0]; }
  clear(): void { this.a = []; }
  items(): Entry[] { return this.a; }
  push(e: Entry): void {
    const a = this.a;
    a.push(e);
    let i = a.length - 1;
    while (i > 0) {
      const p = (i - 1) >> 1;
      if (!this.lt(a[i], a[p])) break;
      [a[i], a[p]] = [a[p], a[i]];
      i = p;
    }
  }
  pop(): Entry | undefined {
    const a = this.a;
    if (a.length === 0) return undefined;
    const top = a[0];
    const last = a.pop()!;
    if (a.length > 0) {
      a[0] = last;
      let i = 0;
      for (;;) {
        const l = 2 * i + 1, r = l + 1;
        let m = i;
        if (l < a.length && this.lt(a[l], a[m])) m = l;
        if (r < a.length && this.lt(a[r], a[m])) m = r;
        if (m === i) break;
        [a[i], a[m]] = [a[m], a[i]];
        i = m;
      }
    }
    return top;
  }
}

export class RelayQueue {
  private readonly rate: number;
  private readonly burst: number;
  private readonly maxPackets: number;
  private readonly maxBytes: number;
  private readonly maxWaitMs: number;
  private readonly now: () => number;
  private readonly setTimer: (fn: () => void, ms: number) => unknown;
  private readonly clearTimer: (h: unknown) => void;

  private tokens: number;
  private lastRefill: number;
  private best = new Heap(better);                  // 先頭 = 次に流すもの
  private worst = new Heap((x, y) => better(y, x)); // 先頭 = 最初に捨てるもの
  private live = 0;
  private bytes = 0;
  private seq = 0;
  private timer: unknown = null;
  private destroyed = false;

  /** 捨てた数 (診断・テスト用) */
  public dropped = 0;

  constructor(
    /** 実際の転送。exclude は送ってきた隣人 (返さない) */
    private send: (packet: GossipPacket, exclude: PeerId | null) => void,
    opts: RelayQueueOptions = {},
  ) {
    this.rate = opts.cellsPerSec ?? RELAY_QUEUE.RELAY_CELLS_PER_SEC;
    this.burst = opts.burstCells ?? RELAY_QUEUE.BURST_CELLS;
    this.maxPackets = opts.maxPackets ?? RELAY_QUEUE.MAX_PACKETS;
    this.maxBytes = opts.maxBytes ?? RELAY_QUEUE.MAX_BYTES;
    this.maxWaitMs = opts.maxWaitMs ?? RELAY_QUEUE.MAX_WAIT_MS;
    this.now = opts.now ?? Date.now;
    this.setTimer = opts.setTimer ?? ((fn, ms) => {
      const t = setTimeout(fn, ms);
      (t as any)?.unref?.(); // Node のプロセスをこのタイマーで引き留めない
      return t;
    });
    this.clearTimer = opts.clearTimer ?? ((h) => clearTimeout(h as ReturnType<typeof setTimeout>));
    this.tokens = this.burst;
    this.lastRefill = this.now();
  }

  /** 待っている投稿数 */
  public get size(): number { return this.live; }
  /** 待っているバイト数 */
  public get queuedBytes(): number { return this.bytes; }

  /**
   * 転送したい投稿を渡す。予算内で待ち行列が空なら、その場で send する。
   * ★ 待ち行列が空でないときは、予算があっても割り込ませない (優先度の高いものが先に流れる)。
   */
  public offer(packet: GossipPacket, exclude: PeerId | null = null): void {
    if (this.destroyed) return;
    const now = this.now();
    this.refill(now);
    const cells = packetCells(packet);
    if (this.live === 0 && this.tokens >= cells) {
      this.tokens -= cells;
      this.send(packet, exclude);
      return;
    }

    const e: Entry = {
      packet, exclude, cells, ec: packetEffortPerCell(packet),
      bytes: toBytes(packet.payload).length + 64, seq: this.seq++, at: now, dead: false,
    };
    // 満杯なら、最低優先のものと比べて低い方を捨てる (同じ e_c なら新しい方 = 今来たもの)
    while (this.live > 0 && (this.live + 1 > this.maxPackets || this.bytes + e.bytes > this.maxBytes)) {
      const w = this.peekLive(this.worst);
      if (!w || !better(e, w)) { this.dropped++; return; }
      this.kill(w);
      this.dropped++;
    }
    if (e.bytes > this.maxBytes) { this.dropped++; return; }
    this.best.push(e);
    this.worst.push(e);
    this.live++;
    this.bytes += e.bytes;
    this.drain(now);
  }

  public destroy(): void {
    this.destroyed = true;
    if (this.timer !== null) this.clearTimer(this.timer);
    this.timer = null;
    this.best.clear();
    this.worst.clear();
    this.live = 0;
    this.bytes = 0;
  }

  private refill(now: number): void {
    const dt = now - this.lastRefill;
    if (dt > 0) {
      this.tokens = Math.min(this.burst, this.tokens + (dt / 1000) * this.rate);
      this.lastRefill = now;
    }
  }

  private peekLive(h: Heap): Entry | undefined {
    for (let e = h.peek(); e; e = h.peek()) {
      if (!e.dead) return e;
      h.pop();
    }
    return undefined;
  }

  private kill(e: Entry): void {
    e.dead = true;
    this.live--;
    this.bytes -= e.bytes;
    // 遅延削除の残骸 (相手のヒープに残った死んだ要素) が溜まらないよう、膨らんだら作り直す
    if (this.best.length + this.worst.length > 4 * this.live + 128) this.compact();
  }

  private compact(): void {
    const alive = this.best.items().filter(x => !x.dead);
    this.best.clear();
    this.worst.clear();
    for (const x of alive) { this.best.push(x); this.worst.push(x); }
  }

  /** 予算の許す限り、優先度の高い順に流す。残りがあれば、次に払える時刻にタイマーを張る */
  private drain(now: number): void {
    this.refill(now);
    for (;;) {
      const top = this.peekLive(this.best);
      if (!top) break;
      if (now - top.at > this.maxWaitMs) { this.best.pop(); this.kill(top); this.dropped++; continue; }
      if (this.tokens < top.cells) break;
      this.best.pop();
      this.kill(top);
      this.tokens -= top.cells;
      this.send(top.packet, top.exclude);
    }
    if (this.timer !== null) { this.clearTimer(this.timer); this.timer = null; }
    const next = this.peekLive(this.best);
    if (next && !this.destroyed) {
      const waitMs = Math.max(1, Math.ceil(((next.cells - this.tokens) / this.rate) * 1000));
      this.timer = this.setTimer(() => { this.timer = null; this.drain(this.now()); }, waitMs);
    }
  }
}

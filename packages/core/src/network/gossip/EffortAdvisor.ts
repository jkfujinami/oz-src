import type { GossipPacket } from '../../types';
import { POW_POLICY, cellsFor, effortFromExp, toBytes } from '../../crypto/PowPolicy';

/**
 * EffortAdvisor — 推奨 effort (Tor の hs PoW v1 の "suggested effort" を、放送網に移したもの)。
 *
 * ★ 権限者がいない。推奨値は「全員が同じ flood を見て、手元で同じ式で計算する」。投稿券も、Guard が
 *   決める値も無い。同じ flood を見た者は (量子化のおかげで) ほぼ同じ値になり、端末ごとの差は指紋にならない。
 * ★ 申告ではない。この値に満たない投稿も網は受理する (強制するのは最低 effort だけ)。ただし混雑時、中継は
 *   effort の高い順に流す (RelayQueue) ので、推奨に満たない投稿は後回し・最悪は捨てられる。
 *   だから正直な作者は自分の利益のために推奨に従い、攻撃者は推奨を超える仕事を払い続けるしかない。
 *
 * 仕組み:
 *   - 受理した live の投稿を、直近 W (10 分) だけ「(時刻, セル数, 1 セルあたりの effort e_c)」で覚える。
 *     e_c = effort / セル数。長い投稿は、枚数分の仕事を払うので 1 セル当たりで公平に比べる。
 *   - 窓の中のセルが網の予算 (CAPACITY_CELLS_PER_SEC × 窓の長さ) 以内なら、推奨は最小 (1 / セル)。
 *   - 超えたら、e_c の高い順に並べて予算ちょうどの順位にある投稿の e_c を取り、1 段 (×2^(1/4)) 上げる。
 *     新しい正直な投稿が、予算の内側に入るための値。
 *   - 上限は MAX_SUGGESTED_EXP (1024 / セル ≒ 40 秒)。洪水が止まれば、古い投稿が窓から出て自然に下がる
 *     (滑らかな減衰。専用の減衰処理は持たない)。
 *
 * ★ 並べ替えはしない。e_c を指数 (2^(i/4), i = 0..MAX_EFFORT_EXP+) の目盛りで数える度数表 (ヒストグラム)
 *   にして、上から累積するだけ。1 投稿 O(1)・推奨の計算 O(目盛り数) で、洪水中でも軽い。
 *   度数表の目盛りがそのまま量子化になるので、全員が同じ値に揃う。
 */
export const EFFORT_ADVISOR = {
  /**
   * 網が捌くセル数の予算 (1 秒あたり)。
   * ★ 想定する平均負荷の約 10 倍。設計の想定は平均 1〜2 投稿/秒、ピークで 10〜20 投稿/秒
   *   (1 投稿はおおむね 1 セル)。平均の 10 倍を予算にしておけば、通常のピークでは予算を超えず推奨は
   *   最小のまま (正直な利用者は PoW でほぼ待たない)。それを超える持続的な洪水だけが推奨を押し上げる。
   */
  CAPACITY_CELLS_PER_SEC: 20,
  /** 窓の長さ (ms) */
  WINDOW_MS: 10 * 60 * 1000,
  /**
   * 予算を計る窓の長さの下限 (ms)。
   * ★ 窓がまだ溜まっていない間 (起動直後・洪水の始まり) に、予算 = 20 × 600 = 12,000 セルが溜まるまで
   *   10 分待つと、洪水の最初の分が丸ごと無防備になる。実際に観測できた長さ (最古の投稿から今まで) を窓として
   *   予算を比例させる。ただし短すぎるとただの揺らぎに反応するので、60 秒を下限にする
   *   (= 60 秒で 1,200 セル、20 セル/秒を持続して超えたときだけ反応する)。
   */
  MIN_SPAN_MS: 60 * 1000,
  /**
   * 推奨の上限の指数 (1 セルあたり 2^(40/4) = 1024)。Equi-X で約 40 秒 (PowPolicy.EQUIX_MS_PER_EFFORT)。
   * ★ 上限が無いと、攻撃者が高 effort の投稿を少量混ぜるだけで、正直な利用者の待ち時間を際限なく
   *   伸ばせてしまう。
   */
  MAX_SUGGESTED_EXP: 40,
  /** 覚える投稿数の上限 (超えたら古い順に忘れる)。メモリの天井 */
  MAX_ENTRIES: 200_000,
} as const;

/** パケットのセル数 (ヘッダ込みの長さ / 1000 の切り上げ) */
export function packetCells(packet: Pick<GossipPacket, 'payload'>): number {
  return cellsFor(POW_POLICY.HEADER_BYTES + toBytes(packet.payload).length);
}

/** パケットの優先度 e_c = effort / セル数 (RelayQueue も同じ値で並べる) */
export function packetEffortPerCell(packet: Pick<GossipPacket, 'payload' | 'effort_exp'>): number {
  return effortFromExp(packet.effort_exp) / packetCells(packet);
}

/** e_c を度数表の目盛り (指数) に切り上げる。e_c ≤ 2^(b/4) を満たす最小の b */
function bucketOf(effortPerCell: number): number {
  // 浮動小数の誤差で 2^(k/4) ちょうどが k+1 に出ないよう、わずかに引いてから切り上げる
  return Math.max(0, Math.ceil(4 * Math.log2(Math.max(1, effortPerCell)) - 1e-9));
}

export interface EffortAdvisorOptions {
  capacityCellsPerSec?: number;
  windowMs?: number;
  minSpanMs?: number;
  maxSuggestedExp?: number;
  maxEntries?: number;
  now?: () => number;
}

export class EffortAdvisor {
  private readonly capacity: number;
  private readonly windowMs: number;
  private readonly minSpanMs: number;
  private readonly maxExp: number;
  private readonly maxEntries: number;
  private readonly now: () => number;

  // 窓の中の投稿。3 本の並列配列 (head 以降が有効)。オブジェクトを作らないのは洪水中の GC を避けるため
  private times: number[] = [];
  private cells: number[] = [];
  private buckets: number[] = [];
  private head = 0;
  /** 度数表: 目盛り b → 窓の中でその e_c の投稿が占めるセルの合計 */
  private hist: number[] = new Array(POW_POLICY.MAX_EFFORT_EXP + 1).fill(0);
  private totalCells = 0;

  constructor(opts: EffortAdvisorOptions = {}) {
    this.capacity = opts.capacityCellsPerSec ?? EFFORT_ADVISOR.CAPACITY_CELLS_PER_SEC;
    this.windowMs = opts.windowMs ?? EFFORT_ADVISOR.WINDOW_MS;
    this.minSpanMs = opts.minSpanMs ?? EFFORT_ADVISOR.MIN_SPAN_MS;
    this.maxExp = opts.maxSuggestedExp ?? EFFORT_ADVISOR.MAX_SUGGESTED_EXP;
    this.maxEntries = opts.maxEntries ?? EFFORT_ADVISOR.MAX_ENTRIES;
    this.now = opts.now ?? Date.now;
  }

  /**
   * 受理した live の投稿を 1 件数える (検証済み・初見のものだけ。重複と追いつきは呼ばない)。
   * ★ 時刻は端末の現在時刻 (ヘッダの時刻は分単位で、遅れて届いた投稿も混ざるため)。
   */
  public observe(packet: Pick<GossipPacket, 'payload' | 'effort_exp'>, now: number = this.now()): void {
    const cells = packetCells(packet);
    const b = Math.min(bucketOf(packetEffortPerCell(packet)), this.hist.length - 1);
    this.times.push(now);
    this.cells.push(cells);
    this.buckets.push(b);
    this.hist[b] += cells;
    this.totalCells += cells;
    this.prune(now);
    while (this.size() > this.maxEntries) this.dropOldest();
  }

  /** 窓の中の投稿数 (テスト・診断用) */
  public size(): number {
    return this.times.length - this.head;
  }

  /** 窓の中のセル数の合計 (テスト・診断用) */
  public windowCells(now: number = this.now()): number {
    this.prune(now);
    return this.totalCells;
  }

  /**
   * 1 セルあたりの推奨 effort。最小は 1。量子化済み (2^(i/4))。
   * 全員が同じ flood から同じ式で計算する。権限者の指示ではない。
   */
  public suggestedPerCell(now: number = this.now()): number {
    this.prune(now);
    if (this.size() === 0) return 1;
    const span = Math.min(this.windowMs, Math.max(this.minSpanMs, now - this.times[this.head]));
    const budget = this.capacity * (span / 1000);
    if (this.totalCells <= budget) return 1;

    // e_c の高い順に累積し、予算ちょうどに達する目盛りを探す
    let cum = 0;
    let rank = 0;
    for (let b = this.hist.length - 1; b >= 0; b--) {
      cum += this.hist[b];
      if (cum >= budget) { rank = b; break; }
    }
    // 1 段 (×2^(1/4)) 上げる。新しい投稿が、予算の内側に入るため
    return Math.pow(2, Math.min(rank + 1, this.maxExp) / 4);
  }

  /** セル数 cells の投稿に勧める effort (パケット全体。effortFor / PacketBuilder へ渡す値) */
  public suggestedFor(cells: number, now: number = this.now()): number {
    return Math.ceil(this.suggestedPerCell(now) * Math.max(1, cells) - 1e-9);
  }

  private prune(now: number): void {
    const limit = now - this.windowMs;
    while (this.head < this.times.length && this.times[this.head] < limit) this.dropOldest();
  }

  private dropOldest(): void {
    if (this.head >= this.times.length) return;
    const c = this.cells[this.head];
    this.hist[this.buckets[this.head]] -= c;
    this.totalCells -= c;
    this.head++;
    // 前半が使用済みになったら詰める (償却 O(1))
    if (this.head > 4096 && this.head * 2 > this.times.length) {
      this.times = this.times.slice(this.head);
      this.cells = this.cells.slice(this.head);
      this.buckets = this.buckets.slice(this.head);
      this.head = 0;
    }
  }
}

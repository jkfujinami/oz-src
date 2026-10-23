/**
 * RateLimiter — 隣人ごとのトークンバケット。
 *
 * 本家 OZ 18.11.3 の結論:
 *
 *   「PoW は主役ではない。ゴシップ網の本来の防御は暗号ではなく、
 *     隣人ごとのレート制限である。」
 *
 *   次数 d=16、隣人 1 人あたり R 件/秒に制限すると、受信レートの上限が
 *   d×R に構造的に頭打ちになる。攻撃者の資源 (ハッシュ能力・ASIC) が
 *   いくらあっても、注入口がコネクション数で決まるようになる。
 *
 * 旧実装にはこれが 1 箇所も無かった。GOSSIP も PEX も、
 * 1 人の隣人が無制限に送り込めた。
 *
 * バケットはピア単位・カテゴリ単位で独立している。追いつきを撃ち込まれても
 * GOSSIP の予算は減らない (逆も同様)。
 */

export interface RateLimitConfig {
  /** 定常レート (件/秒) */
  ratePerSec: number;
  /** バースト許容量 (トークン上限)。瞬間的な同期などを通すため rate より大きく取る */
  burst: number;
}

/**
 * カテゴリ別の既定値。
 * 「正常な運用で到達しないが、フラッドは確実に頭打ちになる」水準に置く。
 */
export const RATE_LIMITS = {
  /**
   * ゴシップ中継 (GOSSIP / STEM)。
   * フラッドは新しいパケットを全リンクで 1 回ずつ運ぶので、1 リンクあたりの流量 = 網全体の
   * 投稿レートになる (隣人が増えても下がらない)。運用の想定は網全体のピーク 10〜20 件/秒。
   * 旧値 20 件/秒はこのピークだけで使い切り、正直な隣人からの投稿が落ちた。
   * ピーク 20 の 2.5 倍の 50 件/秒を定常、3 秒ぶんの 150 をバーストにする。
   * 上限を上げても注入口はコネクション数 × この値で頭打ちのまま (PoW が別途かかる)。
   */
  gossip: { ratePerSec: 50, burst: 150 },
  /**
   * 追いつき (CATCHUP_REQ / DATA / END)。★ GOSSIP と別バケット: 同じバケットだと、Guard からの
   * 追いつきの流れ (1 フレーム最大 16KiB。サーバ側は 1 相手あたり 256KiB/秒 = 約 16 フレーム/秒) が
   * 「その Guard からの枠」を使い切り、いま流れている投稿が落ちる。
   * 必要量は 16 フレーム/秒 + REQ/END。余裕を見て 40/秒、バースト 120 (3 秒)。
   * 受け手がフレームを捨てても追いつきは「取り逃した分」が残るだけで、次の再接続で取り直せる。
   */
  catchup: { ratePerSec: 40, burst: 120 },
  /**
   * leaseSet (LEASESET / SYNC_REQ / SYNC)。★ GOSSIP と別バケット。
   * flood の流量は 3 万人 × 2 時間ごとの更新 ≒ 網全体で約 4 件/秒。新参者への一括送信 (SYNC) は
   * 送り手が 16 フレーム/秒に絞る (LeaseSetRouter) ので、受け手の枠は 40 件/秒・バースト 200 で足りる。
   */
  leaseset: { ratePerSec: 40, burst: 200 },
  /**
   * トンネル (TUNNEL_*)。★ GOSSIP と別バケット。要求は 1 隣人あたり多くて数件/秒だが、応答は 16KiB のフレームの列
   * (最大 4MiB = 約 270 フレーム) で来る。保持者は 10ms 間隔 (100 フレーム/秒 = 約 1.6MiB/秒) で送るので、
   * 200/秒・バースト 600 (3 秒) に収まる。これは入口の粗い枠で、要求数・帯域・同時数の細かい制限は TunnelRelay が持つ。
   */
  tunnel: { ratePerSec: 200, burst: 600 },
  /**
   * Ozzy の代理取得の応答 (OZZY_REPLY: M1 → Guard / OZZY_RESULT: Guard → 読み手。ozzy/MeshRange)。
   * ★ GOSSIP・トンネル・オニオンと別バケット。応答は 4KiB 以下のフレームの列 (1 チャンク 4MiB = 約 1,050 フレーム)。
   * 送り手 (M1・Guard) は 1 相手あたり 2,500 フレーム/秒 (約 10MiB/秒) までに送出を絞るので、3,000/秒・
   * バースト 6,000 (2 秒) に収まる。フレームは小さく、処理は表引きとコピーだけ。
   */
  ozzy: { ratePerSec: 3000, burst: 6000 },
  /** PEX 要求。RingMaintainer は 10 秒に 1 回しか投げない */
  pex: { ratePerSec: 1, burst: 5 },
  /** ハンドシェイク。NodeId PoW の検証は 3.4ms と重いので特に絞る */
  handshake: { ratePerSec: 0.2, burst: 3 },
  /** シグナリング中継 (SDP/ICE) */
  signaling: { ratePerSec: 10, burst: 40 },
  /**
   * オニオンセル。cover traffic は 1 隣人あたり平均 0.5 件/秒だが、
   * Guard は多数の利用者のセルを同じ中継へ束ねて流す。想定: 利用者 300 人 × 2 セル/秒 を
   * 約 15 の中継に散らすと 1 リンクあたり約 40 セル/秒 (自分が出口のときも同様)。旧値 20 件/秒では
   * 正規のセル (cover を含む) が落ち、cover が落ちること自体が観測の手がかりにもなる。
   * 2 倍の余裕で 80 件/秒、バースト 240 (3 秒)。セルは 1.2KB なので、最悪でも 1 リンク約 100KB/秒、
   * 隣人 16 本で約 1.5MB/秒が受信の上限 (WebRTC の通常の帯域に収まる)。
   */
  onion: { ratePerSec: 80, burst: 240 },
  /** 生存確認などの制御メッセージ。Heartbeat は 15 秒に 1 回 */
  control: { ratePerSec: 2, burst: 10 },
} as const satisfies Record<string, RateLimitConfig>;

interface Bucket {
  tokens: number;
  lastRefill: number;
}

export class RateLimiter {
  private buckets = new Map<string, Bucket>();
  private readonly configs: Record<string, RateLimitConfig>;
  /** テスト用の時刻フック */
  private readonly clock: () => number;

  /** 直近で拒否した件数 (カテゴリ別)。運用時の観測用 */
  public readonly dropped = new Map<string, number>();

  constructor(
    configs: Record<string, RateLimitConfig> = RATE_LIMITS,
    clock: () => number = Date.now,
  ) {
    this.configs = configs;
    this.clock = clock;
  }

  /**
   * 1 件分の予算を消費する。予算が無ければ false (=そのメッセージを捨てる)。
   */
  public allow(peerId: string, category: string): boolean {
    // 自前のキーだけを見る ("constructor" 等で Object.prototype のメンバーを設定として拾わない)
    const config = Object.prototype.hasOwnProperty.call(this.configs, category) ? this.configs[category] : undefined;
    // ★ 未定義カテゴリは拒否する (fail-closed)。
    //   旧実装は素通しにしていたため、カテゴリ表から漏れた WireType
    //   (HINT / PING など) が無制限に受け付けられていた。
    if (!config) {
      this.dropped.set(category, (this.dropped.get(category) ?? 0) + 1);
      return false;
    }

    const key = `${category}\u0000${peerId}`;
    const now = this.clock();
    let bucket = this.buckets.get(key);

    if (!bucket) {
      bucket = { tokens: config.burst, lastRefill: now };
      this.buckets.set(key, bucket);
    } else {
      const elapsedSec = Math.max(0, now - bucket.lastRefill) / 1000;
      bucket.tokens = Math.min(config.burst, bucket.tokens + elapsedSec * config.ratePerSec);
      bucket.lastRefill = now;
    }

    if (bucket.tokens < 1) {
      this.dropped.set(category, (this.dropped.get(category) ?? 0) + 1);
      return false;
    }

    bucket.tokens -= 1;
    return true;
  }

  /** ピア切断時に状態を捨てる */
  public forget(peerId: string): void {
    for (const key of this.buckets.keys()) {
      if (key.endsWith(`\u0000${peerId}`)) this.buckets.delete(key);
    }
  }

  /** 現在の残トークン (テスト・診断用) */
  public tokensFor(peerId: string, category: string): number {
    return this.buckets.get(`${category}\u0000${peerId}`)?.tokens ?? this.configs[category]?.burst ?? Infinity;
  }

  public reset(): void {
    this.buckets.clear();
    this.dropped.clear();
  }
}

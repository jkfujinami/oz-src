import type { HistoryFetcher } from '../network/history/HistoryClient';
import { createLogger } from '../common/Logger';

const log = createLogger('logic.history');

/** 取りに行く 1 つのバケット */
export interface HistoryJob {
  birthDay: number;
  tag: number;
  /** OZ_EPOCH からの分。0 なら全部 */
  since: number;
}

/**
 * HistorySession — 画面 (板・スレ) を開いたときの過去ログの取得 1 回分 (history v2 §4.5)。
 *
 *   start(plan) で取得を始める (画面は待たない)。plan は取得の直前に呼んで、手元の DB の最新の状態から
 *   since を決める (再接続のとき、前回より先へ進んでいる)。複数のバケットは concurrency 本ずつ、先頭 (新しい方) から。
 *
 * ★ いつ取るか: **開いたとき 1 回**と、**1 ホップ目が (再) 接続したとき**だけ。定期的には取らない
 *   (保持者への問い合わせは、頻度そのものが 1 ホップ目と保持者の Guard に見える)。取得の最中の再接続は、
 *   その取得 (1 ホップ目の準備を待っている) がそのまま使うので重ねない。
 * ★ 届いた投稿は HistoryClient が GossipRouter.deliverFetched で手元へ配る。画面は live と同じ経路 (onMessage →
 *   handlePacketObject) で受け取るので、ここは件数と状態の管理だけ。
 */
export class HistorySession {
  private ctl: AbortController | null = null;
  private plan: (() => HistoryJob[]) | null = null;
  private concurrency = 1;
  private unsubReady: (() => void) | null = null;
  private runId = 0;
  private jobsTotal = 0;
  private jobsDone = 0;
  private count = 0;
  private stopped = false;

  constructor(
    private readonly history: HistoryFetcher | null,
    /** 状態が変わったとき (進み具合・終了) */
    private readonly onChange: () => void,
  ) {}

  /** 取得の最中か (UI は「過去ログを取得中」を出す) */
  public get active(): boolean {
    return this.ctl !== null;
  }

  /** これまでに受け取った投稿の数 */
  public get received(): number {
    return this.count;
  }

  /** 画面に出す文言。バケットが複数なら進み具合 (k/n) も添える */
  public message(): string {
    const parts: string[] = [];
    if (this.jobsTotal > 1) parts.push(`${Math.min(this.jobsDone + 1, this.jobsTotal)}/${this.jobsTotal}`);
    if (this.count > 0) parts.push(`${this.count}件`);
    return parts.length > 0 ? `過去ログを取得中... (${parts.join('・')})` : '過去ログを取得中...';
  }

  /** 取得を始める。取得の途中なら何もしない (その取得が結果を運ぶ) */
  public start(plan: () => HistoryJob[], concurrency: number = 1): void {
    if (!this.history || this.stopped) return;
    this.plan = plan;
    this.concurrency = Math.max(1, concurrency);
    if (!this.unsubReady) {
      // 1 ホップ目が (再) 接続したら、もう一度。取得中なら重ねない
      this.unsubReady = this.history.onReady(() => {
        if (!this.active && !this.stopped) this.run();
      });
    }
    if (!this.active) this.run();
  }

  private run(): void {
    const history = this.history;
    const plan = this.plan;
    if (!history || !plan) return;
    let jobs: HistoryJob[];
    try {
      jobs = plan();
    } catch (e) {
      log.warn('history plan failed', e);
      return;
    }
    if (jobs.length === 0) return;
    const ctl = new AbortController();
    const id = ++this.runId;
    this.ctl = ctl;
    this.jobsTotal = jobs.length;
    this.jobsDone = 0;
    this.count = 0;
    this.onChange();

    let next = 0;
    const worker = async (): Promise<void> => {
      while (!ctl.signal.aborted) {
        const i = next++;
        if (i >= jobs.length) return;
        const job = jobs[i];
        let last = 0;
        try {
          await history.fetchBucket(job.birthDay, job.tag, {
            since: job.since,
            signal: ctl.signal,
            onProgress: (n) => {
              this.count += n - last;
              last = n;
              if (this.runId === id) this.onChange();
            },
          });
        } catch (e) {
          log.warn('history fetch failed', e);
        }
        this.jobsDone++;
        if (this.runId === id && !ctl.signal.aborted) this.onChange();
      }
    };
    void Promise.all(Array.from({ length: Math.min(this.concurrency, jobs.length) }, () => worker())).finally(() => {
      if (this.runId !== id) return; // 止められた / 取り直された
      this.ctl = null;
      this.onChange();
    });
  }

  /** 取得を止める (画面を閉じた・別のスレに移った)。購読も外す */
  public stop(): void {
    this.stopped = true;
    this.runId++;
    this.ctl?.abort();
    this.ctl = null;
    this.unsubReady?.();
    this.unsubReady = null;
    this.plan = null;
    this.jobsTotal = 0;
    this.jobsDone = 0;
    this.count = 0;
  }

  /** stop のあと、同じ画面で別の対象に切り替えて使い直す */
  public reset(): void {
    this.stop();
    this.stopped = false;
  }
}

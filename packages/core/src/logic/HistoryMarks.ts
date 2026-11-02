import { msToMinutes } from '../crypto/PowPolicy';
import { createLogger } from '../common/Logger';

const log = createLogger('logic.history');

/** 取り切った時刻から、さらに遡って頼む分 (保持者へ遅れて届いた投稿・時計のずれ) */
export const HISTORY_MARK_MARGIN_MIN = 5;
/**
 * 記録の名前 (暗号化された端末 DB の設定)。板とスレで分ける。
 * ★ v2: 1 台の「全部です」で完了としていた版の記録は、欠けた答えで付いたかもしれないので使わない (名前を変えて読み捨てる)。
 *   完了は 2 台の答えを合わせたとき (HistoryClient の REQUIRED_OK)
 */
export const HISTORY_MARKS_BOARD = 'history.marks.v2.board';
export const HISTORY_MARKS_THREAD = 'history.marks.v2.thread';
/** 1 つの記録に覚える区分の数の上限。超えたら古く記録したものから忘れる (忘れた区分は次に全部取り直すだけ) */
const MAX_MARKS = 512;

/**
 * HistoryMarks — 過去ログの区分 (バケット = 生まれた日 + tag) ごとに、「保持者から最後まで取り切った時刻」を覚える。
 * 次に同じ区分を取るときは、その時刻 − HISTORY_MARK_MARGIN_MIN から後だけを頼む。記録が無ければ全部 (since = 0)。
 *
 * ★ 手元にある最新の投稿の時刻を since にしてはいけない。最新の投稿は追いつき (1 ホップ目が持つ直近の投稿) や
 *   ふつうの配信で先に届くことがあり、それを基準にすると、それより前の投稿を二度と取りに行かない
 *   (実網で、スレの最新のレスだけが出て、前日までのレスが抜けていた)。ここに記録するのは、取得が完了したときだけ。
 * ★ 置き場所は暗号化された端末 DB (設定)。網には出ない。
 */
export class HistoryMarks {
  private marks = new Map<string, number>();
  private scope: string | null = null;

  constructor(
    private readonly db: { getSetting<T>(name: string): Promise<T | undefined>; setSetting(name: string, value: unknown): Promise<void> } | null,
    /** 設定の名前の頭 (板とスレで分ける: 同じ設定を別々に書き戻して互いに消し合わない) */
    private readonly prefix: string,
  ) {}

  /** 板ごとの記録を読み込む (取得を始める前に呼ぶ) */
  public async load(boardId: string): Promise<void> {
    this.scope = boardId;
    const next = new Map<string, number>();
    try {
      const saved = await this.db?.getSetting<Record<string, number>>(this.keyOf(boardId));
      if (saved && typeof saved === 'object') {
        for (const [k, v] of Object.entries(saved)) if (typeof v === 'number' && Number.isFinite(v) && v > 0) next.set(k, v);
      }
    } catch (e) {
      log.debug(() => `history marks could not be read: ${e}`);
    }
    if (this.scope === boardId) this.marks = next;
  }

  /** この区分で頼む since (分)。取り切った記録が無ければ 0 (全部) */
  public since(birthDay: number, tag: number): number {
    const m = this.marks.get(bucketKey(birthDay, tag));
    return m === undefined ? 0 : Math.max(0, m - HISTORY_MARK_MARGIN_MIN);
  }

  /** 区分を最後まで取り切った。startedAtMs = その取得を始めた時刻 (それより前に保持者が持っていた分は取れた) */
  public async complete(boardId: string, birthDay: number, tag: number, startedAtMs: number): Promise<void> {
    if (this.scope !== boardId) return; // 別の板に移った
    let min: number;
    try {
      min = msToMinutes(startedAtMs);
    } catch {
      return;
    }
    const key = bucketKey(birthDay, tag);
    if ((this.marks.get(key) ?? 0) >= min) return;
    this.marks.delete(key);
    this.marks.set(key, min);
    while (this.marks.size > MAX_MARKS) {
      const oldest = this.marks.keys().next().value;
      if (oldest === undefined) break;
      this.marks.delete(oldest);
    }
    try {
      await this.db?.setSetting(this.keyOf(boardId), Object.fromEntries(this.marks));
    } catch (e) {
      log.debug(() => `history marks could not be saved: ${e}`);
    }
  }

  public clear(): void {
    this.scope = null;
    this.marks = new Map();
  }

  private keyOf(boardId: string): string {
    return `${this.prefix}.${boardId}`;
  }
}

function bucketKey(birthDay: number, tag: number): string {
  return `${birthDay}:${tag}`;
}

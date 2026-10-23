import { createLogger } from '../common/Logger';
import { POW_POLICY } from '../crypto/PowPolicy';
import { THREAD_LIMITS, threadExpiresAt } from './ThreadLimits';

const log = createLogger('logic.dag');

// DAGMetadata is not used here directly as an object, so removing unused import

/**
 * DAGPost
 * 投稿データに DAG のメタデータを付与した内部管理構造
 */
export interface DAGPost {
  packet_id: string;
  content: string;
  post_number: number;
  created_at: number;
  board_id: string;
  thread_id: string;
  parents: string[];
  // 表示用の追加メタデータ
  trip_pubkey?: Uint8Array | null;
  /** トリップ有りの投稿には無い (セッション鍵を載せない) */
  session_pubkey?: Uint8Array | null;
}

/** 表示されない理由 (内部の符号) */
const H_OVER = 1;
const H_CLOSE = 2;
const H_EXPIRE = 3;

export type ThreadCloseReason = 'posts' | 'bytes';
export type ThreadPreviewReason = 'closed' | 'expired' | 'full-posts' | 'full-bytes';

export interface ThreadState {
  /** 表示されるレスの数 */
  visibleCount: number;
  /** 上限・猶予・寿命のどれかで表示されないレスの数 */
  hiddenCount: number;
  /** 表示されるレスの本文の合計 (UTF-8 バイト) */
  contentBytes: number;
  closed: boolean;
  closeReason?: ThreadCloseReason;
  closedAt?: number;
  birthAt: number | null;
  /** 表示されるレスの実効時刻の最大。無ければ null */
  lastPostAt: number | null;
  /** 落ちる時刻。スレ立ての時刻が分からなければ null */
  expiresAt: number | null;
  expired: boolean;
}

export interface NewPostPreview {
  parents: string[];
  /** この親で書いた場合のそのレスの n (祖先 + 1) */
  number: number;
  /** 同じく b (祖先と自分の本文の合計バイト) */
  bytes: number;
  allowed: boolean;
  reason?: ThreadPreviewReason;
}

/** 1 回の解析結果。addPost / setBirth で捨てる */
interface Analysis {
  /** 表示順 (隠れる投稿を含む全体。Kahn で置けたものだけ) */
  order: DAGPost[];
  index: Map<string, number>;
  eff: number[];
  n: number[];
  b: number[];
  hidden: Uint8Array;
  /** 祖先の集合。order の添字をビット位置にした固定長ビット列を並べたもの */
  anc: Uint32Array;
  words: number;
  /** 表示される投稿の order 上の添字 (表示順) */
  visible: number[];
  closedAt: number | null;
  closeReason: ThreadCloseReason | null;
  birth: number | null;
  lastPostAt: number | null;
  expiresAt: number | null;
  contentBytes: number;
}

const encoder = new TextEncoder();

function popcount(x: number): number {
  x = x - ((x >>> 1) & 0x55555555);
  x = (x & 0x33333333) + ((x >>> 2) & 0x33333333);
  return (((x + (x >>> 4)) & 0x0f0f0f0f) * 0x01010101) >>> 24;
}

/** (eff, packet_id) の昇順で取り出す二分ヒープ */
class ReadyHeap {
  private a: number[] = [];
  constructor(private less: (x: number, y: number) => boolean) {}
  get size() { return this.a.length; }
  push(v: number) {
    const a = this.a;
    a.push(v);
    let i = a.length - 1;
    while (i > 0) {
      const p = (i - 1) >> 1;
      if (!this.less(a[i], a[p])) break;
      [a[i], a[p]] = [a[p], a[i]];
      i = p;
    }
  }
  pop(): number {
    const a = this.a;
    const top = a[0];
    const last = a.pop()!;
    if (a.length > 0) {
      a[0] = last;
      let i = 0;
      for (;;) {
        const l = 2 * i + 1, r = l + 1;
        let m = i;
        if (l < a.length && this.less(a[l], a[m])) m = l;
        if (r < a.length && this.less(a[r], a[m])) m = r;
        if (m === i) break;
        [a[i], a[m]] = [a[m], a[i]];
        i = m;
      }
    }
    return top;
  }
}

/**
 * ThreadDAGManager
 * スレッド内のパケット間の因果関係(DAG)を管理し、決定論的な表示順序を算出する。
 *
 * ★ 上限 (レス数・容量) と寿命は、投稿ごとに「祖先だけ」で判定する (ThreadLimits 参照)。
 *   並び順の先頭から数えると、古い親を指定して割り込む投稿が末尾の正規の投稿を押し出せる。
 *   祖先は packet_id に固定されているので、投稿ごとの数は後から変わらない。
 */
export class ThreadDAGManager {
  private nodes: Map<string, DAGPost> = new Map();
  private threadId: string;
  private birthAt: number | null = null;
  private cache: Analysis | null = null;

  constructor(threadId: string) {
    this.threadId = threadId;
  }

  /**
   * 新しいパケットを DAG に追加する
   */
  public addPost(post: DAGPost): boolean {
    if (this.nodes.has(post.packet_id)) return false;

    // スレッドIDの一致確認
    if (post.thread_id !== this.threadId) {
      log.warn(`Thread ID mismatch: ${post.thread_id} !== ${this.threadId}`);
      return false;
    }

    this.nodes.set(post.packet_id, post);
    this.cache = null;
    return true;
  }

  /** スレ立ての時刻 (板のメタの時刻)。分からなければ null (最も古い投稿の実効時刻で代用する) */
  public setBirth(ms: number | null): void {
    if (this.birthAt === ms) return;
    this.birthAt = ms;
    this.cache = null;
  }

  /**
   * 解析 (遅延評価・キャッシュ)。
   *
   * 1 回の Kahn で、表示順・実効時刻・祖先のビット列を一緒に作る。
   * 実効時刻は親が全部取り出された時点 (= 準備完了) で決まるので、優先度に使える。
   */
  private analyze(): Analysis {
    if (this.cache) return this.cache;

    const all = Array.from(this.nodes.values());
    const total = all.length;
    const pos = new Map<string, number>(); // all 上の添字
    all.forEach((p, i) => pos.set(p.packet_id, i));

    const parentIdx: number[][] = all.map(p => {
      const set = new Set<number>();
      for (const q of p.parents) {
        const j = pos.get(q);
        if (j !== undefined && q !== p.packet_id) set.add(j);
      }
      return Array.from(set);
    });
    const children: number[][] = all.map(() => []);
    const inDegree = new Int32Array(total);
    parentIdx.forEach((ps, i) => {
      inDegree[i] = ps.length;
      for (const j of ps) children[j].push(i);
    });

    const words = Math.max(1, Math.ceil(total / 32));
    const anc = new Uint32Array(total * words);
    const effAll = new Array<number>(total).fill(0);
    const rank = new Int32Array(total).fill(-1); // all 上の添字 -> 表示順の添字

    const heap = new ReadyHeap((x, y) =>
      effAll[x] !== effAll[y] ? effAll[x] < effAll[y] : all[x].packet_id < all[y].packet_id
    );
    // 準備完了になった時点で、実効時刻と祖先 (親の祖先 + 親自身) を確定させる
    // ビット位置は表示順の添字。親は必ず先に取り出されているので、その添字が使える
    const makeReady = (i: number) => {
      let eff = all[i].created_at;
      for (const j of parentIdx[i]) {
        if (effAll[j] > eff) eff = effAll[j];
        const dst = i * words, src = j * words;
        for (let w = 0; w < words; w++) anc[dst + w] |= anc[src + w];
        const r = rank[j];
        anc[dst + (r >>> 5)] |= (1 << (r & 31)) >>> 0;
      }
      effAll[i] = eff;
      heap.push(i);
    };
    for (let i = 0; i < total; i++) if (inDegree[i] === 0) makeReady(i);

    const orderAll: number[] = [];
    while (heap.size > 0) {
      const i = heap.pop();
      rank[i] = orderAll.length;
      orderAll.push(i);
      for (const c of children[i]) {
        if (--inDegree[c] === 0) makeReady(c);
      }
    }
    if (orderAll.length < total) {
      // packet_id が親を含むので循環は作れないはずだが、万一のときは置けない投稿を除いて続ける
      log.warn(`DAG: ${total - orderAll.length} post(s) could not be ordered (cycle?) -> excluded`);
    }

    // all 上の添字を表示順の添字に直す (anc のビット位置は既に表示順なので、行だけ並べ替える)
    const m = orderAll.length;
    const order = orderAll.map(i => all[i]);
    const eff = orderAll.map(i => effAll[i]);
    const ancOrdered = new Uint32Array(m * words);
    orderAll.forEach((i, r) => ancOrdered.set(anc.subarray(i * words, (i + 1) * words), r * words));
    const index = new Map<string, number>();
    order.forEach((p, r) => index.set(p.packet_id, r));

    // 投稿ごとの n と b
    const own = order.map(p => encoder.encode(p.content || '').length);
    const nArr = new Array<number>(m);
    const bArr = new Array<number>(m);
    for (let r = 0; r < m; r++) {
      let cnt = 0;
      let bytes = own[r];
      const base = r * words;
      for (let w = 0; w < words; w++) {
        let x = ancOrdered[base + w];
        if (x === 0) continue;
        cnt += popcount(x);
        while (x !== 0) {
          const low = x & -x;
          bytes += own[(w << 5) + (31 - Math.clz32(low))];
          x ^= low;
        }
      }
      nArr[r] = cnt + 1;
      bArr[r] = bytes;
    }

    // 埋まった時刻: 上限に達した投稿 (超えたものも含む) の実効時刻の最小
    const { MAX_POSTS, MAX_CONTENT_BYTES, CLOSE_GRACE_MS } = THREAD_LIMITS;
    let closedAt: number | null = null;
    for (let r = 0; r < m; r++) {
      if ((nArr[r] >= MAX_POSTS || bArr[r] >= MAX_CONTENT_BYTES) && (closedAt === null || eff[r] < closedAt)) closedAt = eff[r];
    }
    let closeReason: ThreadCloseReason | null = null;
    if (closedAt !== null) {
      closeReason = 'bytes';
      for (let r = 0; r < m; r++) {
        if (eff[r] === closedAt && nArr[r] >= MAX_POSTS) { closeReason = 'posts'; break; }
      }
    }

    const hidden = new Uint8Array(m);
    const candidates: number[] = [];
    for (let r = 0; r < m; r++) {
      if (nArr[r] > MAX_POSTS || bArr[r] > MAX_CONTENT_BYTES) hidden[r] = H_OVER;
      else if (closedAt !== null && eff[r] > closedAt + CLOSE_GRACE_MS) hidden[r] = H_CLOSE;
      else candidates.push(r);
    }

    // 寿命: 表示順に歩き、最後の表示レスから 30 日 / 立てて 90 日を超えた所から先を隠す
    let birth = this.birthAt;
    if (birth === null && m > 0) birth = Math.min(...eff);
    const visible: number[] = [];
    let last: number | null = null;
    let expired = false;
    for (const r of candidates) {
      if (!expired && birth !== null && eff[r] > threadExpiresAt(birth, last)) expired = true;
      if (expired) { hidden[r] = H_EXPIRE; continue; }
      last = last === null ? eff[r] : Math.max(last, eff[r]);
      visible.push(r);
    }
    let contentBytes = 0;
    for (const r of visible) contentBytes += own[r];

    this.cache = {
      order, index, eff, n: nArr, b: bArr, hidden, anc: ancOrdered, words, visible,
      closedAt, closeReason, birth, lastPostAt: last,
      expiresAt: birth === null ? null : threadExpiresAt(birth, last),
      contentBytes,
    };
    return this.cache;
  }

  /**
   * 表示される投稿を、決定論的な順序で取得する (隠れる投稿は含まない)。
   * ルール:
   * 1. 依存関係の維持 (親が先) — Kahn のアルゴリズム
   * 2. 準備のできた投稿のうち、実効時刻 (親より前へは遡らない時刻) が早い方を先に
   * 3. 同じなら packet_id の辞書順
   *
   * ★ 並べ替えは created_at ではなく実効時刻。古い親を指す投稿を古い投稿の隣へ
   *   引き寄せず、書かれた時刻の位置に置く。
   */
  public getSortedPosts(): DAGPost[] {
    const a = this.analyze();
    return a.visible.map(r => a.order[r]);
  }

  public getThreadState(now: number = Date.now()): ThreadState {
    const a = this.analyze();
    const state: ThreadState = {
      visibleCount: a.visible.length,
      hiddenCount: a.order.length - a.visible.length,
      contentBytes: a.contentBytes,
      closed: a.closedAt !== null,
      birthAt: a.birth,
      lastPostAt: a.lastPostAt,
      expiresAt: a.expiresAt,
      expired: a.expiresAt !== null && now > a.expiresAt,
    };
    if (a.closedAt !== null) {
      state.closeReason = a.closeReason!;
      state.closedAt = a.closedAt;
    }
    return state;
  }

  /**
   * いま新しいレスを書いたらどうなるかを、親を決めたうえで見積もる。
   * 送信前 (PoW の前) の判定と、実際に作るパケットの親を一致させるために使う。
   */
  public previewNewPost(
    contentBytes: number,
    now: number = Date.now(),
    parents: string[] = this.getTips(),
  ): NewPostPreview {
    const a = this.analyze();
    const set = new Uint32Array(a.words);
    const own = new Set<number>();
    for (const id of parents) {
      const r = a.index.get(id);
      if (r === undefined) continue;
      own.add(r);
      for (let w = 0; w < a.words; w++) set[w] |= a.anc[r * a.words + w];
      set[r >>> 5] |= (1 << (r & 31)) >>> 0;
    }
    let count = 0;
    let bytes = contentBytes;
    for (let w = 0; w < a.words; w++) {
      let x = set[w];
      while (x !== 0) {
        const low = x & -x;
        const r = (w << 5) + (31 - Math.clz32(low));
        bytes += encoder.encode(a.order[r].content || '').length;
        count++;
        x ^= low;
      }
    }
    const number = count + 1;

    let reason: ThreadPreviewReason | undefined;
    if (a.closedAt !== null) reason = 'closed';
    else if (a.expiresAt !== null && now > a.expiresAt) reason = 'expired';
    else if (number > THREAD_LIMITS.MAX_POSTS) reason = 'full-posts';
    else if (bytes > THREAD_LIMITS.MAX_CONTENT_BYTES) reason = 'full-bytes';
    return { parents: [...parents], number, bytes, allowed: reason === undefined, ...(reason ? { reason } : {}) };
  }

  /**
   * `>>n` が指す投稿を解決する。from の祖先だけを表示順に並べた n 番目 (1 始まり)。
   *
   * ★ 書き手が画面で見ていたのは、ほぼ from の祖先 (親を辿って届く範囲) だけ。
   *   祖先で閉じた部分集合では、その中だけで Kahn を回した順序が、全体の順序から
   *   その部分集合だけを抜き出した順序と一致する。だから、後から (同時に書かれた)
   *   投稿が全体の番号をずらしても、`>>n` は書き手が見ていたレスを指し続ける。
   *
   * 未知の投稿・範囲外は null。
   */
  public resolveAnchor(fromPacketId: string, n: number): string | null {
    const a = this.analyze();
    const from = a.index.get(fromPacketId);
    if (from === undefined || !Number.isInteger(n) || n < 1) return null;
    let k = 0;
    const base = from * a.words;
    for (const r of a.visible) {
      if ((a.anc[base + (r >>> 5)] >>> (r & 31)) & 1) {
        if (++k === n) return a.order[r].packet_id;
      }
    }
    return null;
  }

  /**
   * 現在の DAG の「先端 (Tips)」を取得する。
   * 新しいレスを書く際の親パケット候補。
   *
   * ★ 親は最大 max (= POW_POLICY.MAX_PARENTS = 2) 個に絞る。同時書き込みで先端が増えても、
   *   固定長セルに収まらなくなるのを防ぐため (親 1 つにつき 16 バイト)。
   *
   * ★ 絞り方: 「最も重い先端」1 つ + 「最も古い先端」1 つ。
   *   - 最も重い (祖先の数 n(p) が大きく、同じなら新しい) 先端につなぐので、本流が伸びる。
   *   - 残りの先端のうち最も古いものを毎回拾うので、取り残された枝は、書き込みが続く限り
   *     先端が増える速さより速く (1 投稿に 1 本ずつ) 本流へ合流する。
   *   重い順に 2 つだけを選ぶと、軽い枝が永久に取り残されて DAG が分断されたままになる。
   *   同点は packet_id の辞書順で決めるので、同じ DAG を見ている端末は同じ親を選ぶ。
   *
   * ★ 表示される投稿の中だけで数える。隠れる投稿 (上限超過・猶予後) を親に選ぶと、
   *   新しいレスも一緒に隠れてしまう。
   */
  public getTips(max: number = POW_POLICY.MAX_PARENTS): string[] {
    const a = this.analyze();
    if (a.visible.length === 0) return [];

    const hasChildren = new Set<string>();
    for (const r of a.visible) {
      a.order[r].parents.forEach(p => hasChildren.add(p));
    }

    // 子を持たないノードを抽出
    const tips = a.visible.map(r => a.order[r].packet_id).filter(id => !hasChildren.has(id));

    // ★ 「重さ」はワイヤの値ではなく、手元で数えた祖先の数 n(p) (= 祖先 + 自分)。
    //   旧形式は作者が累積 PoW を申告して載せていたが、申告は偽れる (重い先端を名乗って本流を奪える)。
    //   祖先は packet_id に固定されているので、n(p) は同じ DAG を見ている端末で同じ値になる。
    const weight = (id: string) => a.n[a.index.get(id)!];
    const byWeight = (x: string, y: string) => {
      const nodeA = this.nodes.get(x)!;
      const nodeB = this.nodes.get(y)!;
      return weight(y) - weight(x) || nodeB.created_at - nodeA.created_at || (x < y ? -1 : x > y ? 1 : 0);
    };
    tips.sort(byWeight);
    if (tips.length <= max) return tips;
    if (max <= 1) return tips.slice(0, max);

    // 最も重い先端 + 残りのうち最も古い先端 (max が 3 以上なら、古い順に続けて拾う)
    const oldestFirst = tips.slice(1).sort((x, y) => {
      const nodeA = this.nodes.get(x)!;
      const nodeB = this.nodes.get(y)!;
      return nodeA.created_at - nodeB.created_at || (x < y ? -1 : x > y ? 1 : 0);
    });
    return [tips[0], ...oldestFirst.slice(0, max - 1)];
  }

  /**
   * 投稿の n(p) = 祖先の数 + 1 (そのレスのレス番号相当)。未知なら null。
   * 隠れる投稿も数える (解析が全体を持つ)。
   */
  public getAncestorCount(id: string): number | null {
    const a = this.analyze();
    const r = a.index.get(id);
    return r === undefined ? null : a.n[r];
  }

  public getCount(): number {
    return this.nodes.size;
  }

  public getById(id: string): DAGPost | undefined {
    return this.nodes.get(id);
  }
}

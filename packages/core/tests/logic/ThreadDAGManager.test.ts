import { describe, it, expect } from 'vitest';
import { ThreadDAGManager, type DAGPost } from '../../src/logic/ThreadDAGManager';
import { THREAD_LIMITS } from '../../src/logic/ThreadLimits';

const T = 'thread0001';

function post(id: string, opts: Partial<DAGPost> = {}): DAGPost {
  return {
    packet_id: id,
    content: `content ${id}`,
    post_number: 0,
    created_at: 1_700_000_000_000,
    board_id: 'b',
    thread_id: T,
    parents: [],
    ...opts,
  };
}

const ids = (posts: DAGPost[]) => posts.map(p => p.packet_id);

/** 全ての辺で親が子より先に来ているか */
function respectsCausality(sorted: DAGPost[]): boolean {
  const index = new Map(sorted.map((p, i) => [p.packet_id, i]));
  return sorted.every(p => p.parents.every(parent => !index.has(parent) || index.get(parent)! < index.get(p.packet_id)!));
}

describe('ThreadDAGManager: 追加', () => {
  it('新しい投稿は true、同じ packet_id の再追加は false', () => {
    const dag = new ThreadDAGManager(T);
    expect(dag.addPost(post('a'))).toBe(true);
    expect(dag.addPost(post('a', { content: '改竄' }))).toBe(false);
    expect(dag.getCount()).toBe(1);
    expect(dag.getById('a')!.content).toBe('content a'); // 先着を保つ
  });

  it('別スレッドの投稿は受け付けない', () => {
    const dag = new ThreadDAGManager(T);
    expect(dag.addPost(post('x', { thread_id: 'other' }))).toBe(false);
    expect(dag.getCount()).toBe(0);
    expect(dag.getById('x')).toBeUndefined();
  });

  it('空の DAG は空のリスト・空の先端', () => {
    const dag = new ThreadDAGManager(T);
    expect(dag.getSortedPosts()).toEqual([]);
    expect(dag.getTips()).toEqual([]);
    expect(dag.getAncestorCount('nothing')).toBeNull();
  });
});

describe('ThreadDAGManager: 決定論的な表示順序', () => {
  it('親は子より先に並ぶ (子の方が時刻が早くても)', () => {
    const dag = new ThreadDAGManager(T);
    dag.addPost(post('child', { parents: ['parent'], created_at: 1000 }));
    dag.addPost(post('parent', { created_at: 5000 }));
    expect(ids(dag.getSortedPosts())).toEqual(['parent', 'child']);
  });

  it('依存関係が無ければ時刻順、同時刻なら packet_id の辞書順', () => {
    const dag = new ThreadDAGManager(T);
    dag.addPost(post('c', { created_at: 2000 }));
    dag.addPost(post('b', { created_at: 1000 }));
    dag.addPost(post('a', { created_at: 2000 }));
    expect(ids(dag.getSortedPosts())).toEqual(['b', 'a', 'c']);
  });

  it('時刻の桁数が違っても数値として正しく比較する', () => {
    const dag = new ThreadDAGManager(T);
    dag.addPost(post('late', { created_at: 10_000 }));
    dag.addPost(post('early', { created_at: 9_999 }));
    expect(ids(dag.getSortedPosts())).toEqual(['early', 'late']);
  });

  it('到着順に依存しない (どの順で追加しても同じ並び)', () => {
    const all = [
      post('root', { created_at: 100 }),
      post('r1', { parents: ['root'], created_at: 300 }),
      post('r2', { parents: ['root'], created_at: 200 }),
      post('merge', { parents: ['r1', 'r2'], created_at: 150 }),
      post('solo', { created_at: 250 }),
    ];
    const orders = [
      [0, 1, 2, 3, 4], [4, 3, 2, 1, 0], [3, 0, 4, 2, 1], [2, 4, 0, 3, 1],
    ];
    const results = orders.map(order => {
      const dag = new ThreadDAGManager(T);
      for (const i of order) dag.addPost(all[i]);
      return ids(dag.getSortedPosts());
    });
    for (const r of results) expect(r).toEqual(results[0]);
    expect(results[0]).toEqual(['root', 'r2', 'solo', 'r1', 'merge']);
  });

  it('菱形 (合流) の DAG で、合流点は両方の親の後に来る', () => {
    const dag = new ThreadDAGManager(T);
    dag.addPost(post('root', { created_at: 1 }));
    dag.addPost(post('left', { parents: ['root'], created_at: 50 }));
    dag.addPost(post('right', { parents: ['root'], created_at: 10 }));
    dag.addPost(post('join', { parents: ['left', 'right'], created_at: 5 }));
    const sorted = dag.getSortedPosts();
    expect(ids(sorted)).toEqual(['root', 'right', 'left', 'join']);
    expect(respectsCausality(sorted)).toBe(true);
  });

  it('まだ届いていない親を持つ投稿は根として扱い、表示から落とさない', () => {
    const dag = new ThreadDAGManager(T);
    dag.addPost(post('orphan', { parents: ['missing'], created_at: 10 }));
    dag.addPost(post('a', { created_at: 20 }));
    expect(ids(dag.getSortedPosts())).toEqual(['orphan', 'a']);

    // 後から親が届けば、親が先に来る
    dag.addPost(post('missing', { created_at: 30 }));
    expect(ids(dag.getSortedPosts())).toEqual(['a', 'missing', 'orphan']);
  });

  it('同じ親を重複して指していても、子は 1 回だけ現れる', () => {
    const dag = new ThreadDAGManager(T);
    dag.addPost(post('p'));
    dag.addPost(post('c', { parents: ['p', 'p'] }));
    expect(ids(dag.getSortedPosts())).toEqual(['p', 'c']);
  });

  it('長い鎖 (200 件) でも因果順を保ち、全件が並ぶ', () => {
    const dag = new ThreadDAGManager(T);
    // 逆順・時刻も逆向きに追加する
    for (let i = 199; i >= 0; i--) {
      dag.addPost(post(`p${String(i).padStart(3, '0')}`, {
        parents: i === 0 ? [] : [`p${String(i - 1).padStart(3, '0')}`],
        created_at: 1_000_000 - i,
      }));
    }
    const sorted = dag.getSortedPosts();
    expect(sorted).toHaveLength(200);
    expect(respectsCausality(sorted)).toBe(true);
    expect(sorted[0].packet_id).toBe('p000');
    expect(sorted[199].packet_id).toBe('p199');
  });
});

/** id を末尾とする、n 個の投稿の鎖 (祖先 n-1 個 + id)。先端 id の重み n(p) = n にする */
function deep(dag: ThreadDAGManager, id: string, n: number, created_at: number) {
  let prev: string | null = null;
  for (let i = 0; i < n - 1; i++) {
    const a = `${id}~${i}`;
    dag.addPost(post(a, { parents: prev ? [prev] : [], created_at }));
    prev = a;
  }
  dag.addPost(post(id, { parents: prev ? [prev] : [], created_at }));
}

describe('ThreadDAGManager: 先端 (Tips) と重み n(p) (祖先の数 + 1。ワイヤの累積 PoW ではない)', () => {
  it('子を持たない投稿だけが先端になる', () => {
    const dag = new ThreadDAGManager(T);
    dag.addPost(post('a'));
    dag.addPost(post('b', { parents: ['a'] }));
    expect(dag.getTips()).toEqual(['b']);
  });

  it('getAncestorCount は n(p) = 祖先 + 自分 (合流は重複して数えない)。隠れる投稿も数え、未知は null', () => {
    const dag = new ThreadDAGManager(T);
    dag.addPost(post('a'));
    dag.addPost(post('b', { parents: ['a'] }));
    dag.addPost(post('c', { parents: ['a'] }));
    dag.addPost(post('d', { parents: ['b', 'c'] }));
    expect([dag.getAncestorCount('a'), dag.getAncestorCount('b'), dag.getAncestorCount('c'), dag.getAncestorCount('d')]).toEqual([1, 2, 2, 4]);
    expect(dag.getAncestorCount('zzz')).toBeNull();
  });

  it('先端は最大 2 つ: 最も重い (n(p) が大きい) 先端 + 残りのうち最も古い先端 (固定長セルに収めるため)', () => {
    const dag = new ThreadDAGManager(T);
    deep(dag, 'light', 2, 999);
    deep(dag, 'heavy', 7, 1);
    deep(dag, 'mid-old', 4, 100);
    deep(dag, 'mid-new', 4, 200);
    expect(dag.getTips()).toEqual(['heavy', 'mid-old']);
  });

  it('★重さは作者の申告ではなく、手元の祖先から数える (軽い枝に重い値を名乗らせる手がない)', () => {
    const dag = new ThreadDAGManager(T);
    // DAGPost に申告用の重みのフィールドは無い。祖先の数だけが効く
    deep(dag, 'long', 5, 100);
    dag.addPost(post('lone', { created_at: 9999 }));
    expect(dag.getTips(1)).toEqual(['long']);
  });

  it('先端が 2 つ以下ならそのまま (重い順、同じなら新しい順)', () => {
    const dag = new ThreadDAGManager(T);
    dag.addPost(post('a', { created_at: 100 }));
    dag.addPost(post('b', { created_at: 200 }));
    expect(dag.getTips()).toEqual(['b', 'a']);
  });

  it('★先端が何本あっても親は POW_POLICY.MAX_PARENTS 個まで', () => {
    const dag = new ThreadDAGManager(T);
    for (let i = 0; i < 20; i++) dag.addPost(post(`t${i}`, { created_at: 1000 + i }));
    expect(dag.getTips()).toHaveLength(2);
    expect(dag.getTips(1)).toEqual(['t19']);
  });

  it('★取り残された枝は、書き込みが続けば 1 投稿に 1 本ずつ本流へ合流する (DAG が分断されたままにならない)', () => {
    const dag = new ThreadDAGManager(T);
    // 同時書き込みで 6 本の先端ができた状態
    for (let i = 0; i < 6; i++) dag.addPost(post(`s${i}`, { created_at: 100 + i }));
    let n = 0;
    while (dag.getTips(99).length > 1 && n < 10) {
      const tips = dag.getTips();
      dag.addPost(post(`m${n}`, { parents: tips, created_at: 1000 + n }));
      n++;
    }
    // 各投稿が 2 本を 1 本に畳むので、先端 6 本は 5 投稿で 1 本になる
    expect(dag.getTips(99)).toHaveLength(1);
    expect(n).toBe(5);
    // 最も古い先端 (s0) も、どこかの投稿の親として拾われている
    const referenced = new Set(dag.getSortedPosts().flatMap(p => p.parents));
    expect(referenced.has('s0')).toBe(true);
  });

  it('同点は packet_id の辞書順で決まる (同じ DAG を見る端末は同じ親を選ぶ)', () => {
    const a = new ThreadDAGManager(T);
    const b = new ThreadDAGManager(T);
    for (const id of ['x', 'y', 'z']) a.addPost(post(id, { created_at: 5 }));
    for (const id of ['z', 'x', 'y']) b.addPost(post(id, { created_at: 5 }));
    expect(a.getTips()).toEqual(b.getTips());
  });

  it('存在しない親を指していても、その投稿自身は先端になれる', () => {
    const dag = new ThreadDAGManager(T);
    dag.addPost(post('x', { parents: ['ghost'] }));
    expect(dag.getTips()).toEqual(['x']);
  });
});


// ---------------------------------------------------------------------------
// スレッドの上限と寿命 (ThreadLimits)
// ---------------------------------------------------------------------------
const { MAX_POSTS, MAX_CONTENT_BYTES, CLOSE_GRACE_MS, IDLE_EXPIRY_MS, MAX_LIFETIME_MS } = THREAD_LIMITS;
const T0 = 1_700_000_000_000;
const MIN = 60_000;
const DAY = 24 * 60 * MIN;
const NOW_FAR = T0 + 10 * 365 * DAY; // 寿命の判定に影響させたくないテスト用 (setBirth と組み合わせる)

/** 1 本の鎖 (p0 <- p1 <- ...)。時刻は 1 分ずつ進む */
function chain(dag: ThreadDAGManager, count: number, prefix = 'p', startAt = T0, content = 'x') {
  for (let i = 0; i < count; i++) {
    dag.addPost(post(`${prefix}${String(i).padStart(5, '0')}`, {
      parents: i === 0 ? [] : [`${prefix}${String(i - 1).padStart(5, '0')}`],
      created_at: startAt + i * MIN,
      content,
    }));
  }
}
const pid = (i: number, prefix = 'p') => `${prefix}${String(i).padStart(5, '0')}`;

describe('ThreadDAGManager: レス数の上限', () => {
  it('1000 レスの鎖は全部表示され、スレは埋まる (posts)。1001 件目の子は表示しない', () => {
    const dag = new ThreadDAGManager(T);
    chain(dag, MAX_POSTS);
    let st = dag.getThreadState(T0);
    expect(st).toMatchObject({ visibleCount: MAX_POSTS, hiddenCount: 0, closed: true, closeReason: 'posts' });
    expect(st.closedAt).toBe(T0 + (MAX_POSTS - 1) * MIN);

    dag.addPost(post('over', { parents: [pid(MAX_POSTS - 1)], created_at: T0 + MAX_POSTS * MIN }));
    st = dag.getThreadState(T0);
    expect(st.visibleCount).toBe(MAX_POSTS);
    expect(st.hiddenCount).toBe(1);
    expect(ids(dag.getSortedPosts())).not.toContain('over');
  });

  it('祖先が 999 件ずつの同時の 2 件は、どちらも表示される', () => {
    const dag = new ThreadDAGManager(T);
    chain(dag, MAX_POSTS - 1);
    const tail = pid(MAX_POSTS - 2);
    dag.addPost(post('x1', { parents: [tail], created_at: T0 + 2_000 * MIN }));
    dag.addPost(post('x2', { parents: [tail], created_at: T0 + 2_000 * MIN }));
    const st = dag.getThreadState(T0);
    expect(st.visibleCount).toBe(MAX_POSTS + 1);
    expect(st.hiddenCount).toBe(0);
    expect(st.closed).toBe(true);
  });

  it('押し出し攻撃: 古い親を指す投稿を、猶予内の時刻で足しても、既に見えているレスは隠れない', () => {
    const dag = new ThreadDAGManager(T);
    chain(dag, MAX_POSTS);
    const before = ids(dag.getSortedPosts());
    const closedAt = dag.getThreadState(T0).closedAt!;
    dag.addPost(post('evil', { parents: [pid(4)], created_at: closedAt - 14 * MIN }));
    const after = new Set(ids(dag.getSortedPosts()));
    for (const id of before) expect(after.has(id)).toBe(true);
  });

  it('同じ攻撃を猶予を超えた (現在の) 時刻で行うと、攻撃者の投稿だけが猶予後として隠れる', () => {
    const dag = new ThreadDAGManager(T);
    chain(dag, MAX_POSTS);
    const before = ids(dag.getSortedPosts());
    const closedAt = dag.getThreadState(T0).closedAt!;
    dag.addPost(post('evil', { parents: [pid(4)], created_at: closedAt + CLOSE_GRACE_MS + MIN }));
    const visible = ids(dag.getSortedPosts());
    expect(visible).toEqual(before);
    expect(dag.getThreadState(T0).hiddenCount).toBe(1);
  });
});

describe('ThreadDAGManager: 容量の上限', () => {
  it('2048 バイトのレスは 256 件まで表示され、257 件目は隠れる (bytes)', () => {
    const dag = new ThreadDAGManager(T);
    const body = 'a'.repeat(2048);
    chain(dag, 257, 'p', T0, body);
    const st = dag.getThreadState(T0);
    expect(st.visibleCount).toBe(256);
    expect(st.hiddenCount).toBe(1);
    expect(st.contentBytes).toBe(MAX_CONTENT_BYTES);
    expect(st.closed).toBe(true);
    expect(st.closeReason).toBe('bytes');
  });

  it('容量は本文の UTF-8 バイトで数える (日本語は 3 バイト)', () => {
    const dag = new ThreadDAGManager(T);
    dag.addPost(post('a', { content: 'あい' }));
    expect(dag.getThreadState(T0).contentBytes).toBe(6);
  });
});

describe('ThreadDAGManager: 実効時刻', () => {
  it('親より前の時刻を名乗った子は、親の実効時刻に引き上げられ、時刻の位置に並ぶ', () => {
    const dag = new ThreadDAGManager(T);
    dag.addPost(post('parent', { created_at: T0 + 10 * MIN }));
    dag.addPost(post('child', { parents: ['parent'], created_at: T0 }));
    dag.addPost(post('other', { created_at: T0 + 5 * MIN }));
    // child は eff = parent の時刻なので、other (5 分) より後ろ
    expect(ids(dag.getSortedPosts())).toEqual(['other', 'parent', 'child']);
    expect(dag.getThreadState(T0).lastPostAt).toBe(T0 + 10 * MIN);
  });

  it('古い親を指す新しい投稿は、古い投稿の隣へ引き寄せられない', () => {
    const dag = new ThreadDAGManager(T);
    dag.addPost(post('old', { created_at: T0 }));
    dag.addPost(post('mid', { created_at: T0 + 10 * MIN }));
    dag.addPost(post('stale', { parents: ['old'], created_at: T0 + 20 * MIN }));
    expect(ids(dag.getSortedPosts())).toEqual(['old', 'mid', 'stale']);
  });
});

describe('ThreadDAGManager: 寿命', () => {
  it('過疎: 最後の書き込みから 30 日あくと、そこから先は落ちる', () => {
    const dag = new ThreadDAGManager(T);
    dag.addPost(post('a', { created_at: T0 }));
    dag.addPost(post('b', { parents: ['a'], created_at: T0 + 10 * DAY }));
    dag.addPost(post('c', { parents: ['b'], created_at: T0 + 41 * DAY }));
    dag.addPost(post('d', { parents: ['c'], created_at: T0 + 42 * DAY }));
    expect(ids(dag.getSortedPosts())).toEqual(['a', 'b']);
    const st = dag.getThreadState(T0 + DAY);
    expect(st.hiddenCount).toBe(2);
    expect(st.expiresAt).toBe(T0 + 10 * DAY + IDLE_EXPIRY_MS);
    expect(st.expiresAt).toBe(T0 + 40 * DAY);
    expect(st.expired).toBe(false);
    expect(dag.getThreadState(T0 + 40 * DAY + 1).expired).toBe(true);
  });

  it('寿命の上限: 書き込みが続いていても、スレ立てから 90 日で落ちる', () => {
    const dag = new ThreadDAGManager(T);
    dag.setBirth(T0);
    let prev = '';
    for (let day = 0; day <= 91; day += 10) {
      const id = `d${day}`;
      dag.addPost(post(id, { parents: prev ? [prev] : [], created_at: T0 + day * DAY }));
      prev = id;
    }
    dag.addPost(post('late', { parents: [prev], created_at: T0 + 91 * DAY }));
    const visible = ids(dag.getSortedPosts());
    expect(visible).not.toContain('late');
    expect(visible).toContain('d90');
    const st = dag.getThreadState(T0);
    expect(st.expiresAt).toBe(T0 + MAX_LIFETIME_MS);
    expect(st.birthAt).toBe(T0);
  });

  it('スレ立ての時刻が分からなければ、最も古い投稿の実効時刻を使う。空で未知なら null', () => {
    const dag = new ThreadDAGManager(T);
    expect(dag.getThreadState(T0)).toMatchObject({ birthAt: null, expiresAt: null, expired: false, lastPostAt: null });
    dag.addPost(post('a', { created_at: T0 }));
    expect(dag.getThreadState(T0).birthAt).toBe(T0);
    dag.setBirth(T0 - DAY);
    expect(dag.getThreadState(T0).birthAt).toBe(T0 - DAY);
  });

  it('投稿が無くても、スレ立てが分かれば 30 日で落ちる', () => {
    const dag = new ThreadDAGManager(T);
    dag.setBirth(T0);
    const st = dag.getThreadState(T0 + 31 * DAY);
    expect(st.expiresAt).toBe(T0 + 30 * DAY);
    expect(st.expired).toBe(true);
  });
});

describe('ThreadDAGManager.previewNewPost', () => {
  it('親を指定しなければ先端を使い、n と b を返す', () => {
    const dag = new ThreadDAGManager(T);
    chain(dag, 3);
    const pv = dag.previewNewPost(10, T0);
    expect(pv).toMatchObject({ parents: [pid(2)], number: 4, bytes: 3 + 10, allowed: true });
    expect(pv.reason).toBeUndefined();
  });

  it('親を指定したときは、その祖先だけで数える', () => {
    const dag = new ThreadDAGManager(T);
    chain(dag, 5);
    const pv = dag.previewNewPost(1, T0, [pid(1)]);
    expect(pv).toMatchObject({ parents: [pid(1)], number: 3, bytes: 3 });
  });

  it('埋まったスレは closed、落ちたスレは expired', () => {
    const full = new ThreadDAGManager(T);
    chain(full, MAX_POSTS);
    expect(full.previewNewPost(1, T0)).toMatchObject({ allowed: false, reason: 'closed', number: MAX_POSTS + 1 });

    const old = new ThreadDAGManager(T);
    chain(old, 2);
    expect(old.previewNewPost(1, T0 + 100 * DAY)).toMatchObject({ allowed: false, reason: 'expired' });
  });

  it('埋まる直前: 古い親を指すと上限内、最後の 1 件はその書き込みで上限に達するが許される', () => {
    const dag = new ThreadDAGManager(T);
    chain(dag, MAX_POSTS - 1);
    expect(dag.previewNewPost(1, T0)).toMatchObject({ allowed: true, number: MAX_POSTS });
  });

  it('容量: 超える書き込みは full-bytes、レス数: 超える親の取り方は full-posts', () => {
    const dag = new ThreadDAGManager(T);
    chain(dag, 2, 'p', T0, 'a'.repeat(2048));
    expect(dag.previewNewPost(MAX_CONTENT_BYTES, T0)).toMatchObject({ allowed: false, reason: 'full-bytes' });
    expect(dag.previewNewPost(MAX_CONTENT_BYTES - 4096, T0).allowed).toBe(true);

    const many = new ThreadDAGManager(T);
    chain(many, MAX_POSTS - 1);
    expect(many.previewNewPost(1, T0, [pid(MAX_POSTS - 2), 'unknown']).allowed).toBe(true);
  });
});

describe('ThreadDAGManager.resolveAnchor', () => {
  it('同時の投稿が全体の番号をずらしても、書き手の見ていたレスを指し続ける', () => {
    const dag = new ThreadDAGManager(T);
    dag.addPost(post('A1', { created_at: T0 }));
    dag.addPost(post('A2', { parents: ['A1'], created_at: T0 + 2 * MIN }));
    dag.addPost(post('A3', { parents: ['A2'], created_at: T0 + 3 * MIN }));
    dag.addPost(post('A4', { parents: ['A3'], created_at: T0 + 4 * MIN }));
    expect(dag.resolveAnchor('A4', 3)).toBe('A3');
    // 同時に書かれた (A4 の祖先ではない) 投稿が、全体の 2 番目に割り込む
    dag.addPost(post('B', { parents: ['A1'], created_at: T0 + MIN }));
    expect(ids(dag.getSortedPosts()).indexOf('A3') + 1).toBe(4);
    expect(dag.resolveAnchor('A4', 3)).toBe('A3');
    expect(dag.resolveAnchor('A4', 1)).toBe('A1');
  });

  it('未知の投稿・範囲外・不正な番号は null', () => {
    const dag = new ThreadDAGManager(T);
    chain(dag, 3);
    expect(dag.resolveAnchor('nope', 1)).toBeNull();
    expect(dag.resolveAnchor(pid(2), 3)).toBeNull(); // 祖先は 2 件だけ
    expect(dag.resolveAnchor(pid(2), 0)).toBeNull();
    expect(dag.resolveAnchor(pid(0), 1)).toBeNull();
  });
});

describe('ThreadDAGManager: 性質', () => {
  /** 決定論的な乱数 (mulberry32) */
  function rng(seed: number) {
    return () => {
      seed |= 0; seed = (seed + 0x6D2B79F5) | 0;
      let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  function ancestors(dag: ThreadDAGManager, id: string, acc = new Set<string>()): Set<string> {
    for (const p of dag.getById(id)!.parents) {
      if (dag.getById(p) && !acc.has(p)) { acc.add(p); ancestors(dag, p, acc); }
    }
    return acc;
  }

  it('ランダムな DAG でも、表示される投稿の祖先は全て表示される (限界を超える形・古い親・遡った時刻を含む)', () => {
    for (let seed = 1; seed <= 6; seed++) {
      const rand = rng(seed);
      const dag = new ThreadDAGManager(T);
      dag.setBirth(T0);
      const made: string[] = [];
      const count = 1200;
      for (let i = 0; i < count; i++) {
        const id = `r${String(i).padStart(5, '0')}`;
        const parents: string[] = [];
        const k = made.length === 0 ? 0 : 1 + Math.floor(rand() * 2);
        for (let j = 0; j < k; j++) {
          // 直近寄り 70%、古い親 30%
          const idx = rand() < 0.7 ? Math.max(0, made.length - 1 - Math.floor(rand() * 3)) : Math.floor(rand() * made.length);
          parents.push(made[idx]);
        }
        // 時刻: 進む、ときどき 15 分まで遡る、ときどき大きく跳ぶ
        const jitter = rand() < 0.2 ? -Math.floor(rand() * 15) * MIN : 0;
        const jump = i > 0 && rand() < 0.002 ? 40 * DAY : 0;
        dag.addPost(post(id, { parents: [...new Set(parents)], created_at: T0 + i * MIN + jitter + jump, content: 'y'.repeat(1 + Math.floor(rand() * 900)) }));
        made.push(id);
      }
      const visible = new Set(ids(dag.getSortedPosts()));
      expect(visible.size).toBeGreaterThan(0);
      for (const id of visible) {
        for (const a of ancestors(dag, id)) expect(visible.has(a)).toBe(true);
      }
      expect(respectsCausality(dag.getSortedPosts())).toBe(true);
    }
  });

  it('3000 件の鎖と枝を、十分速く解析できる', () => {
    const dag = new ThreadDAGManager(T);
    dag.setBirth(T0);
    chain(dag, 2000);
    for (let i = 0; i < 1000; i++) {
      dag.addPost(post(`s${String(i).padStart(5, '0')}`, { parents: [pid(i)], created_at: T0 + i * MIN + 1 }));
    }
    const t = performance.now();
    const st = dag.getThreadState(T0);
    dag.getSortedPosts();
    dag.getTips();
    expect(st.visibleCount + st.hiddenCount).toBe(3000);
    expect(performance.now() - t).toBeLessThan(3000);
    // 2 回目はキャッシュ
    const t2 = performance.now();
    dag.getThreadState(T0);
    expect(performance.now() - t2).toBeLessThan(50);
  });

  it('未知の親は、分かっている祖先だけで数え、投稿は表示する', () => {
    const dag = new ThreadDAGManager(T);
    dag.addPost(post('a', { parents: ['missing'], created_at: T0 }));
    dag.addPost(post('b', { parents: ['a', 'missing2'], created_at: T0 + MIN }));
    expect(ids(dag.getSortedPosts())).toEqual(['a', 'b']);
    expect(dag.previewNewPost(1, T0, ['b'])).toMatchObject({ number: 3 });
    expect(dag.resolveAnchor('b', 1)).toBe('a');
  });

  it('getTips は表示される投稿の中から選ぶ (隠れた投稿を親にしない)', () => {
    const dag = new ThreadDAGManager(T);
    chain(dag, MAX_POSTS);
    dag.addPost(post('over', { parents: [pid(MAX_POSTS - 1)], created_at: T0 + MAX_POSTS * MIN }));
    expect(dag.getTips()).toEqual([pid(MAX_POSTS - 1)]);
  });

  it('addPost / setBirth でキャッシュが更新される', () => {
    const dag = new ThreadDAGManager(T);
    dag.addPost(post('a', { created_at: T0 }));
    expect(dag.getThreadState(T0).visibleCount).toBe(1);
    dag.addPost(post('b', { parents: ['a'], created_at: T0 + 100 * DAY }));
    expect(dag.getThreadState(T0).hiddenCount).toBe(1);
    dag.setBirth(T0 + 99 * DAY);
    expect(dag.getThreadState(T0).hiddenCount).toBe(0);
  });
});

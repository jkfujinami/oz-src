import { describe, it, expect } from 'vitest';

/**
 * 在線パターンの交差攻撃 (Presence Intersection) — 数理モデル。
 *
 * ★ このファイルはプロトコルのコードを一切実行しない。
 *   「同じ偽名で何度も投稿する人は、投稿時刻に在線だった利用者の集合を交差されると絞り込まれる」
 *   という、経路の匿名化とは無関係に残る性質を、人口モデルの上で数えるだけである。
 *   オニオン経路・Guard・cover traffic がどれだけ堅くても、この攻撃は効く。
 *   (監視ノードは隣人の IP と接続・切断の時刻を見られる。そこから「誰がいつ在線か」を作れる。)
 *
 * 攻撃者の手順:
 *   1. 偽名 X の投稿 k 回それぞれについて、投稿時刻に在線だった利用者の集合 S_k を観測する。
 *   2. 候補 = S_1 ∩ S_2 ∩ … ∩ S_k。標的は毎回在線なので必ず残る。
 *   3. 候補が標的 1 人になった時点で終了 (= 「標的が唯一の候補」になるまでの投稿数を測る)。
 *
 * 比較する 2 つの在線モデル:
 *   独立: 各投稿時刻に、各利用者が確率 p で独立に在線。
 *   相関: 利用者ごとに「好みの時間帯」(朝型 / 夜型 / ばらつき) があり、毎日そのあたりに
 *         p × 24 時間ぶんのセッションを開く (開始は日ごとに ±1 時間ゆらぎ、15% の日は不在)。
 *         標的は自分のセッションの中で投稿する。標的と時間帯が近い利用者は一緒に在線になりやすく、
 *         交差で落ちにくい。現実の人間はこちらに近い。
 *
 * 結果の読み方:
 *   - 独立モデルの中央値は log(N)/log(1/p) の理論値に近い (p が小さいほど少ない投稿で割れる)。
 *   - 相関モデルは同じ p でも多くの投稿を要する (似た生活リズムの人が候補に残る) が、
 *     p=0.3 でも 30 回前後で割れる。同じ偽名を使い続けること自体が危険。
 *   - 常時在線の利用者 (常駐デスクトップ) がいると、その人数が候補集合の下限になり、「唯一の候補」にはならない。
 *     ただし常時在線の利用者が 1 人 (標的だけ) なら、むしろ即座に割れる。
 *
 * これらは製品判断 (常駐デスクトップモード / 投稿の遅延 / 偽名の使い捨て) の材料である。
 * 検査は「結果が理論値の範囲にある」程度の健全性確認のみ。
 *
 * 実行: RUN_SIM=1 npx vitest run tests/simulation/PresenceIntersection.sim.test.ts
 * (vitest.config.ts が tests/simulation を RUN_SIM=1 のときだけ対象にする。)
 */

const N = 30_000;
const MAX_POSTS = 2000;
const TRIALS = 101;
const DAY_H = 24;

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** (a, b, c) から [0,1) の一様乱数を決定的に作る (日ごと・利用者ごとのゆらぎ用) */
function hash01(a: number, b: number, c: number): number {
  let h = (Math.imul(a ^ 0x9e3779b9, 0x85ebca6b) ^ Math.imul(b + 0x7f4a7c15, 0xc2b2ae35) ^ Math.imul(c + 0x165667b1, 0x27d4eb2f)) >>> 0;
  h = Math.imul(h ^ (h >>> 15), 0x2c1b3c6d) >>> 0;
  h = Math.imul(h ^ (h >>> 12), 0x297a2d39) >>> 0;
  h ^= h >>> 15;
  return (h >>> 0) / 4294967296;
}

/** 近似的な標準正規乱数 (一様 4 つの和) */
function gauss(r: () => number): number {
  return (r() + r() + r() + r() - 2) / Math.sqrt(4 / 12);
}

/** 一日の中の好みの時間帯 (時刻 0-24) を人口分布から引く: 夜型 60% / 朝型 25% / ばらつき 15% */
function drawPreferredHour(r: () => number): number {
  const x = r();
  const h = x < 0.6 ? 21 + 2.5 * gauss(r) : x < 0.85 ? 8 + 2 * gauss(r) : r() * DAY_H;
  return ((h % DAY_H) + DAY_H) % DAY_H;
}

const circDist = (a: number, b: number) => {
  const d = Math.abs(a - b) % DAY_H;
  return Math.min(d, DAY_H - d);
};

interface Population {
  /** 常時在線か */
  always: Uint8Array;
  center: Float64Array;
  /** セッション長 (時間) */
  length: Float64Array;
}

const SKIP_DAY = 0.15;
const JITTER_H = 1.0;

function makePopulation(r: () => number, p: number, alwaysCount: number): Population {
  const always = new Uint8Array(N);
  const center = new Float64Array(N);
  const length = new Float64Array(N);
  for (let u = 0; u < N; u++) {
    center[u] = drawPreferredHour(r);
    // 欠席の日があるぶん、在線の日は長めに開いて、全体の在線率を p に合わせる
    length[u] = Math.min(DAY_H, (p * DAY_H) / (1 - SKIP_DAY));
  }
  // 常時在線は先頭の alwaysCount 人 (標的は別枠で扱う)
  for (let u = 0; u < alwaysCount; u++) always[u] = 1;
  return { always, center, length };
}

/** 利用者 u が (day, hour) に在線か (相関モデル)。同じ引数なら常に同じ答え */
function onlineCorrelated(pop: Population, seed: number, u: number, day: number, hour: number): boolean {
  if (pop.always[u]) return true;
  if (hash01(seed, u, day * 3 + 1) < SKIP_DAY) return false;
  // その日のセッション開始のゆらぎ (±1 時間, 近似正規)
  const g = (hash01(seed, u, day * 3 + 2) + hash01(seed + 1, u, day * 3 + 2) + hash01(seed + 2, u, day * 3 + 2) + hash01(seed + 3, u, day * 3 + 2) - 2) * Math.sqrt(3);
  const mid = pop.center[u] + g * JITTER_H;
  return circDist(hour, ((mid % DAY_H) + DAY_H) % DAY_H) <= pop.length[u] / 2;
}

interface Outcome {
  /** 唯一の候補になった投稿数。MAX_POSTS 内に絞り切れなければ null */
  posts: number | null;
  /** 最後に残った候補の数 (標的を含む) */
  finalSize: number;
}

/** 独立モデル: 投稿ごとに各利用者が確率 p で在線 (常時在線の alwaysCount 人は常に在線)。標的は毎回必ず在線 */
function runIndependent(seed: number, p: number, alwaysCount: number): Outcome {
  const r = mulberry32(seed);
  // 候補 = 標的以外の利用者 (標的は必ず残るので数えない)。常時在線は先頭 alwaysCount 人
  let cands: number[] = Array.from({ length: N - 1 }, (_, i) => i);
  let k = 0;
  while (cands.length > alwaysCount && k < MAX_POSTS) {
    k++;
    cands = cands.filter(u => u < alwaysCount || r() < p);
  }
  const done = cands.length <= alwaysCount;
  return { posts: done ? k : null, finalSize: cands.length + 1 };
}

/**
 * 相関モデル: 標的は毎日、自分のセッション内の一様な時刻に 1 回投稿する。
 * 標的が常時在線のときは、毎回 24 時間のどこでも投稿でき、時刻は一様に選ぶ。
 */
function runCorrelated(seed: number, p: number, alwaysCount: number, targetAlways: boolean): Outcome {
  const r = mulberry32(seed);
  const pop = makePopulation(r, p, alwaysCount);
  const targetCenter = drawPreferredHour(r);
  const targetLen = pop.length[0]; // 標的の長さも人口と同じ (p で決まる)
  let cands: number[] = [];
  for (let u = 0; u < N - 1; u++) cands.push(u);
  let day = 0;
  let k = 0;
  while (cands.length > alwaysCount && k < MAX_POSTS) {
    // 標的が不在の日は投稿しない (在線のときだけ投稿する)
    day++;
    if (!targetAlways && hash01(seed, 0x7a97, day) < SKIP_DAY) continue;
    const jitter = gauss(r) * JITTER_H;
    const hour = targetAlways
      ? r() * DAY_H
      : (((targetCenter + jitter + (r() - 0.5) * targetLen) % DAY_H) + DAY_H) % DAY_H;
    k++;
    cands = cands.filter(u => onlineCorrelated(pop, seed, u, day, hour));
  }
  const done = cands.length <= alwaysCount;
  return { posts: done ? k : null, finalSize: cands.length + 1 };
}

function median(xs: number[]): number {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.floor(s.length / 2)];
}

function summarize(outcomes: Outcome[]) {
  const reached = outcomes.filter(o => o.posts !== null).map(o => o.posts!);
  return {
    median: reached.length > outcomes.length / 2 ? median(reached) : null,
    p90: reached.length >= Math.ceil(outcomes.length * 0.9) ? [...reached].sort((a, b) => a - b)[Math.floor(outcomes.length * 0.9) - 1] : null,
    reachedRate: reached.length / outcomes.length,
    finalSize: median(outcomes.map(o => o.finalSize)),
  };
}

const fmt = (x: number | null) => (x === null ? 'なし' : String(x)).padStart(6);

describe('在線パターンの交差攻撃 (数理モデル, N=30,000)', () => {
  const table: string[] = [];

  it('通常の利用者 (在線率 p): 標的が唯一の候補になるまでの投稿数 (中央値 / 90 パーセンタイル)', () => {
    const rows: string[] = [];
    for (const p of [0.05, 0.1, 0.3]) {
      const ind = summarize(Array.from({ length: TRIALS }, (_, i) => runIndependent(10_000 + i, p, 0)));
      const cor = summarize(Array.from({ length: TRIALS }, (_, i) => runCorrelated(20_000 + i, p, 0, false)));
      rows.push(`  p=${p.toFixed(2)}   ${fmt(ind.median)} ${fmt(ind.p90)}      ${fmt(cor.median)} ${fmt(cor.p90)}`);

      // 健全性: 独立モデルは理論値 log(N)/log(1/p) に近い (最大値の期待値は +0.58/ln(1/p) 程度上乗せ)。
      const theory = Math.log(N) / Math.log(1 / p) + 1;
      expect(ind.reachedRate).toBe(1);
      expect(Math.abs(ind.median! - theory)).toBeLessThan(2.5);
      // 相関モデルでも、標的は毎回在線なので有限回で割れる
      expect(cor.reachedRate).toBeGreaterThan(0.9);
      // 相関のほうが落ちにくい (似た生活リズムの人が残る)。厳密な定理ではないが、このモデルでは大差で成り立つ
      expect(cor.median!).toBeGreaterThanOrEqual(ind.median!);
    }
    table.push('通常の利用者: 標的が唯一の候補になるまでの投稿数');
    table.push('                  独立モデル           相関モデル');
    table.push('            中央値   p90       中央値   p90');
    table.push(...rows);
  }, 600_000);

  it('常時在線の利用者 (常駐デスクトップ): 一緒に常時在線の人数が候補集合の下限になる', () => {
    const p = 0.1;
    const rows: string[] = [];
    for (const others of [0, 30, 300]) {
      // 標的も常時在線。他に常時在線が others 人いる (人口の 0 / 0.1% / 1%)
      const ind = summarize(Array.from({ length: 31 }, (_, i) => runIndependent(30_000 + i, p, others)));
      const cor = summarize(Array.from({ length: 31 }, (_, i) => runCorrelated(40_000 + i, p, others, true)));
      rows.push(
        `  他の常時在線=${String(others).padStart(3)} 人   残る候補=${String(ind.finalSize).padStart(3)} 人 ` +
        `(独立: ${fmt(ind.median)} 回で下限到達 / 相関: ${fmt(cor.median)} 回)`,
      );
      // 常時在線の人数が下限: 絞り込みはそこで止まる
      expect(ind.finalSize).toBe(others + 1);
      expect(cor.finalSize).toBe(others + 1);
    }
    table.push('');
    table.push(`標的が常時在線 (他の利用者は p=${p}): 候補が下限に張り付くまでの投稿数`);
    table.push(...rows);
    table.push('  → 常時在線の仲間が 1 人もいなければ、むしろ数回で標的 1 人に絞られる。仲間の人数が匿名集合の大きさそのもの。');
  }, 600_000);

  it('結果の一覧', () => {
    console.log(`[在線パターンの交差攻撃 (数理モデル)] N=${N}, 試行=${TRIALS}, 1 日 1 投稿 (標的の在線中のみ)\n${table.join('\n')}`);
    expect(table.length).toBeGreaterThan(0);
  });
});

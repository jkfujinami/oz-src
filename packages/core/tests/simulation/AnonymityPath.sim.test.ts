import { describe, it, expect, vi, afterAll } from 'vitest';
import { writeFileSync } from 'node:fs';
import { CIRCUIT_CONFIG } from '../../src/network/onion/OnionCircuit';
import { runMany, f1, f3, type SimParams, type Summary } from './anonymitySimHarness';

// ★ 検証を通すためだけの安い PoW (本番のコードにこの分岐は無い。cheapPow.ts 参照)。経路の振る舞いには関係しない
vi.mock('../../src/crypto/PowPolicy', async (orig) => (await import('../helpers/cheapPowMock')).cheapPowPolicyFactory(orig as any));

/**
 * 匿名性シミュレーション D1 (重い版)。実コードの網をメモリ内で回し、
 * 監視ノード (法執行機関型) が作者の IP をどこまで知れるかを数える。説明と結果は docs/design/anonymity-sim.md。
 *
 *   author --onion--> Guard --onion--> M1 --stem--> W1 --> ... --> F が flood
 *
 * 実行: RUN_SIM=1 npx vitest run tests/simulation/AnonymityPath.sim.test.ts
 *   SIM_OUT=/path/out.json  … 結果を JSON でも保存
 *   SIM_WORLDS=3            … 設定ごとに作り直す網の数 (既定 3)
 *   SIM_POSTS=500           … 網 1 つあたりの投稿数 (既定 500)
 *   SIM_ONLY=main|nocover|fluff … 一部だけ実行
 *
 * ★ 数値は「モデル時間」。実測した時間に縮尺 (scale = 5) を掛けて戻してある (cover 0.5 秒 / 中継 40ms / リンク 20-60ms)。
 */

const WORLDS = Number(process.env.SIM_WORLDS ?? 3);
const POSTS = Number(process.env.SIM_POSTS ?? 500);
const ONLY = process.env.SIM_ONLY ?? 'all';
const out: Record<string, Summary> = {};

const base: SimParams = {
  n: 60, degree: 8, advFraction: 0.1, mode: 'open', trustedCount: 6, trustedPerClient: 3,
  posts: POSTS, authors: 45, postGapMs: 60, scale: 5, cover: true, seed: 20261015,
};

function row(s: Summary): string {
  const h = s.heuristicStemOrGossip;
  return [
    s.label,
    f3(s.pGuardAdv), f3(s.pM1Adv), f3(s.qStrictGivenGuardAdv),
    f3(s.pLearnK[1]), f3(s.pLearnK[10]), f3(s.pLearnK[50]),
    f3(h.pAuthor), f3(h.pGuard), f3(h.pM1), f3(h.pFluffer), f3(s.baseline),
  ].join(' | ');
}

function report(s: Summary, wallMs: number): void {
  out[s.label] = s;
  console.log(`[${s.label}] posts=${s.posts} (echo ${s.postsEchoed}) wall=${(wallMs / 1000).toFixed(0)}s cpuLag=${f1(s.cpuLagMs)}ms(real)`);
  console.log('  ' + row(s));
  if (s.timing) {
    const t = s.timing;
    console.log(`  timing: n=${t.instances} acc=${f3(t.accuracy)} base=${f3(t.baseline)} top3=${f3(t.top3)} set=${f1(t.meanCandidateSet)} | global acc=${f3(t.global.accuracy)} random=${f3(t.global.randomBaseline)} ub=${f3(t.global.upperBound)} top10%prec=${f3(t.global.precisionTop10pct)}`);
  }
  console.log(`  walk mean=${f1(s.walk.mean)} p50=${s.walk.p50} p95=${s.walk.p95} | delivery full p50=${f1(s.delivery.p50)} p95=${f1(s.delivery.p95)} ms | 95% reach p50=${f1(s.delivery.p50Reach95)} | first flood p50=${f1(s.delivery.tFirstFlood.p50)} p95=${f1(s.delivery.tFirstFlood.p95)}`);
  console.log(`  dist author->fluffer=${f1(s.distance.authorToFluffer)} random pair=${f1(s.distance.randomPair)} P(neighbor)=${f3(s.distance.pFlufferIsNeighborOfAuthor)} m1Repeat=${f3(s.m1Repeat)} anonSet|advM1=${f1(s.anonSetGivenAdvM1)} guardClients=${f1(s.guardClients)}`);
  console.log(`  inv: ${JSON.stringify(s.invariants)}`);
}

afterAll(() => {
  if (process.env.SIM_OUT) writeFileSync(process.env.SIM_OUT, JSON.stringify(out, null, 1));
});

describe.skipIf(!(ONLY === 'all' || ONLY === 'main'))('D1 主実験: 信頼 Guard (A) と開放モード (B)', () => {
  for (const mode of ['trusted', 'open'] as const) {
    for (const f of [0.05, 0.1, 0.2]) {
      it(`${mode} f=${f}`, async () => {
        const { summary, wallMs } = await runMany({ ...base, mode, advFraction: f }, `${mode === 'trusted' ? 'A' : 'B'} f=${f}`, WORLDS);
        report(summary, wallMs);
        expect(summary.invariants.authorFirstGossip).toBe(0);
        expect(summary.invariants.m1ToGuard).toBe(0);
        if (mode === 'trusted') expect(summary.pGuardAdv).toBe(0);
      }, 900_000);
    }
  }
});

describe.skipIf(!(ONLY === 'all' || ONLY === 'nocover'))('D1 対照: cover なし (B)', () => {
  for (const f of [0.1, 0.2]) {
    it(`open no-cover f=${f}`, async () => {
      // 投稿は重ならないよう間隔を空ける (cover が無いので 1 枚のセルがそのまま見える)
      const { summary, wallMs } = await runMany(
        { ...base, mode: 'open', advFraction: f, cover: false, posts: Math.min(POSTS, 300), postGapMs: 160 },
        `B-nocover f=${f}`, WORLDS,
      );
      report(summary, wallMs);
    }, 900_000);
  }
});

describe.skipIf(!(ONLY === 'all' || ONLY === 'fluff'))('D1 感度: STEM_FLUFF_PROBABILITY', () => {
  // CIRCUIT_CONFIG は実行時に読まれる定数。テストの中でだけ差し替えて戻す (ソースは編集しない)
  for (const p of [0.1, 0.5]) {
    it(`open f=0.1 fluff=${p}`, async () => {
      const orig = CIRCUIT_CONFIG.STEM_FLUFF_PROBABILITY;
      (CIRCUIT_CONFIG as any).STEM_FLUFF_PROBABILITY = p;
      try {
        const { summary, wallMs } = await runMany({ ...base, mode: 'open', advFraction: 0.1 }, `B f=0.1 fluff=${p}`, 2);
        summary.walk.expectedMean = 1 / p;
        report(summary, wallMs);
      } finally {
        (CIRCUIT_CONFIG as any).STEM_FLUFF_PROBABILITY = orig;
      }
    }, 900_000);
  }
});

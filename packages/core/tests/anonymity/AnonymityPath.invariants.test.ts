import { describe, it, expect, vi } from 'vitest';
import { runConfig, type SimParams } from '../simulation/anonymitySimHarness';

// ★ 検証を通すためだけの安い PoW (cheapPow.ts 参照)
vi.mock('../../src/crypto/PowPolicy', async (orig) => (await import('../helpers/cheapPowMock')).cheapPowPolicyFactory(orig as any));

/**
 * 匿名性シミュレーションの軽い版 (不変条件のみ。約 10〜20 秒)。
 * 重い版 (AnonymityPath.sim.test.ts) と同じ道具で、小さな網 (30 ノード) を回す。
 *
 * ★ 通常のテストで毎回走らせるため tests/anonymity に置く (tests/simulation は RUN_SIM=1 のときだけ走る)。
 *   道具は tests/simulation/anonymitySimHarness.ts を共有する。
 */
const small: SimParams = {
  n: 30, degree: 6, advFraction: 0.2, mode: 'open', trustedCount: 4, trustedPerClient: 3,
  posts: 100, authors: 20, postGapMs: 40, scale: 5, cover: true, seed: 424242,
};

describe('経路の不変条件 (小さな網)', () => {
  for (const mode of ['open', 'trusted'] as const) {
    it(`${mode}: 作者は最初の flood をしない / M1 は Guard に返さない / 作者が先に平文を出さない`, async () => {
      const { summary: s } = await runConfig({ ...small, mode }, mode);
      expect(s.posts).toBeGreaterThanOrEqual(95);
      // ほぼ全投稿が網に現れた (fail-closed で落ちていない)。★ 全体のテストで CPU が混むと、エコー待ちの
      //   時間切れでまれに 1〜2 件落ちる。安全性の不変条件 (下の 0 件の検査) は緩めず、届いた率だけ少し許す
      expect(s.postsEchoed).toBeGreaterThanOrEqual(Math.floor(s.posts * 0.97));
      // 作者が最初の broadcaster になった投稿は 1 件も無い
      expect(s.invariants.authorFirstGossip).toBe(0);
      // M1 は自分の Guard に Stem を返さない
      expect(s.invariants.m1ToGuard).toBe(0);
      // 作者は、歩きが始まる前に平文 (STEM) を出さない
      expect(s.invariants.authorStemBeforeFirstStemRecv).toBe(0);
      // Guard は onion の外側 1 層しか剥がせず、作者の平文は見ない。
      // ★ ただし歩きが作者に戻ってきたとき、作者は (自分の Guard を除外せずに) 平文の STEM を渡しうる。
      //   既知の小さな漏れ (docs/design/anonymity-sim.md 参照)。この割合が膨らんだら退行
      // 歩きが作者に戻っても、作者は自分の Guard に平文の Stem を渡さない (OnionCircuit.authorGuards)
      expect(s.invariants.guardSawClearFromAuthor).toBe(0);
      // 歩数の平均は理論値 (1 / 0.25 = 4) の近く
      expect(s.walk.mean).toBeGreaterThan(2.5);
      expect(s.walk.mean).toBeLessThan(6.5);
      // 全員に届く
      expect(s.delivery.meanReachFraction).toBeGreaterThan(0.97);
      if (mode === 'trusted') expect(s.pGuardAdv).toBe(0);
    }, 120_000);
  }

  it('open + cover: Guard のタイミング攻撃は無作為な当てずっぽうとほぼ変わらない', async () => {
    const { summary: s } = await runConfig({ ...small, mode: 'open', posts: 160, seed: 31337 }, 'timing');
    const t = s.timing;
    expect(t).not.toBeNull();
    // 全投稿を対象に、攻撃者の Guard の利用者の中から 1 人を選ぶ攻撃。cover があれば、利用者数の逆数 (無作為) を
    // 大きく超えない (標本が小さいので、絶対差 0.08 までを許す)
    expect(t!.global.accuracy).toBeLessThanOrEqual(Math.max(3 * t!.global.randomBaseline, t!.global.randomBaseline + 0.08));
    // 作者の Guard が攻撃者のときに作者を当てる率も、Guard の利用者が少ない (≒1.5 人) ぶんの基準線を大きく超えない
    if (t!.instances >= 5) expect(t!.accuracy).toBeLessThanOrEqual(Math.min(1, t!.baseline + 0.3));
  }, 120_000);
});

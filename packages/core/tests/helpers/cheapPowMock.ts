/**
 * 大量のパケットが要るテスト (件数上限・洪水・保留の上限) 向けの「安い PoW」。
 *
 * 本物の Equi-X は 1 個 60〜100ms かかるので、数百個のパケットを作るテストが秒単位で遅くなる。
 * テストファイルの中だけ
 *   vi.mock('../../src/crypto/PowPolicy', async (orig) => (await import('../helpers/cheapPowMock')).cheapPowPolicyFactory(orig))
 * で verifyPow を差し替え、印 (CHEAP_SOLUTION = 0xaa * 16) の付いた解も受け入れる。
 *
 * ★ 本番のコードにこの分岐は無い。PowPolicy.ts にも PacketValidator.ts にも「テストなら通す」という経路を
 *   入れていない (入れると攻撃面になる)。差し替えは vitest のモジュールモックだけ。印の無い解は本物の検証に回る
 *   ので、PoW の検証そのものを試すテストは、このモックを使わないファイルで行う。
 */
// ★ vi.mock のファクトリから動的 import される。PowPolicy を import しない (モック対象との循環を避ける)
export const CHEAP_SOLUTION = new Uint8Array(16).fill(0xaa);

const isCheap = (s: Uint8Array) => s.length === 16 && s.every(b => b === 0xaa);

export async function cheapPowPolicyFactory(importOriginal: () => Promise<any>) {
  const real = await importOriginal();
  return {
    ...real,
    verifyPow: (h: any, sol: { nonce: number; solution: Uint8Array }) =>
      (isCheap(sol.solution) && Number.isInteger(h.effort_exp) && h.effort_exp >= 0 && h.effort_exp <= real.POW_POLICY.MAX_EFFORT_EXP) ||
      real.verifyPow(h, sol),
  };
}


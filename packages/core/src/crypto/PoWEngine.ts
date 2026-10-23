import { WorkerBridge } from '../worker/WorkerBridge';
import { equixReady } from './equix/EquiX';
import sodium from './sodium';
import {
  POW_POLICY,
  solvePow,
  verifyPow,
  type PowCommitted,
  type PowSolution,
} from './PowPolicy';

/**
 * PoWEngine — Gossip パケットの PoW (Tor 式の Equi-X。構成は PowPolicy を参照)。
 *
 * 構成:
 *   - 検証 (verify)  : メインスレッドで同期実行。Equi-X の検証は約 20µs。
 *   - 探索 (compute) : Worker に委譲 (1 試行約 60ms)。ここだけが重い。
 *
 * ★ 検証を Worker に投げない。受信パケット 1 通ごとに postMessage の往復が発生し、
 *   単一 Worker が直列化点になって、ゴミパケットを流すだけで正当なパケットの処理を
 *   詰まらせられる (head-of-line blocking)。実際の負荷上限を決めるのは PoW ではなく
 *   隣人ごとのレート制限 ({@link ../network/RateLimiter}) である、という本家 18.11.3 の結論も併せて実装してある。
 */
export class PoWEngine {
  /**
   * PoW 探索を Worker に委譲する。
   *
   * @returns 見つかった nonce と Equi-X の解
   */
  static async compute(header: PowCommitted): Promise<PowSolution> {
    if (!Number.isInteger(header.effort_exp) || header.effort_exp < 0 || header.effort_exp > POW_POLICY.MAX_EFFORT_EXP) {
      throw new RangeError(`PoWEngine.compute: effort exponent ${header.effort_exp} out of range`);
    }
    await equixReady;
    await sodium.ready;

    // Worker が使えない環境 (SSR / Node / テスト) では同期版にフォールバックする。
    if (typeof Worker === 'undefined') {
      return PoWEngine.computeSync(header);
    }

    const r = await WorkerBridge.request<{ nonce: number; solution: Uint8Array }>('compute', {
      header: serializeHeader(header),
    });
    return { nonce: r.nonce, solution: new Uint8Array(r.solution) };
  }

  /** メインスレッドで探索する。Worker が無い環境と単体テスト用。equixReady を済ませておくこと。 */
  static computeSync(header: PowCommitted): PowSolution {
    const sol = solvePow(header);
    if (sol === null) throw new Error('PoWEngine: PoW search exhausted');
    return sol;
  }

  /** 検証。同期。effort の上限・解の長さ・Equi-X・effort の判定を {@link verifyPow} が行う。 */
  static verify(header: PowCommitted, sol: PowSolution): boolean {
    return verifyPow(header, sol);
  }
}

/** Worker へ渡すために構造化複製可能な形へ落とす */
function serializeHeader(h: PowCommitted) {
  return {
    version: h.version,
    time: h.time,
    tag: h.tag,
    age: h.age,
    effort_exp: h.effort_exp,
    payload: h.payload,
  };
}

import sodium from '../../crypto/sodium';
import { equixSolve, equixVerify, EQUIX_SOLUTION_BYTES } from '../../crypto/equix/EquiX';
import { positionOf } from '../../common/Ring';
import { concat, u32be } from '../../crypto/PowPolicy';

/**
 * SlotPow — 保管担当の「枠」の位置と、その PoW (history v2 §4.1)。
 *
 *   seed        = BLAKE2b-256("oz/v5/slot-pow" ‖ SID_pub ‖ u8 i)
 *   challenge   = seed ‖ u32be(nonce)                       … Equi-X の challenge
 *   解 s が有効 ⇔ equixVerify(challenge, s) かつ u32be(BLAKE2b-256(seed ‖ nonce ‖ s)[0..4]) * SLOT_EFFORT ≤ 0xFFFFFFFF
 *   枠 i の位置 = u64(BLAKE2b("oz/v5/slot" ‖ SID_pub ‖ u8 i ‖ s)[0..8])   (Ring.positionOf)
 *
 * ★ なぜ PoW を払わせるのか: 位置がハッシュで決まるだけだと、好きなバケットの隣に居座る SID を
 *   いくらでも作れる (検閲・狙い撃ち)。枠ごとに「解く」費用を要求すると、狙った位置の近くに
 *   枠を置く費用が (枠の数 × 位置を掘る試行回数) に跳ね上がる。解 s は位置の入力にも入る
 *   (同じ nonce でも解が違えば位置が違う = 1 つの SID で位置を選べる自由度は解の個数分あるが、
 *   1 つ選ぶのに 1 回の解き直しが要る)。
 * ★ 検証は 1 枠あたり約 21µs (Equi-X) + BLAKE2b 1 回。leaseSet を全員が検証するので軽さが要る。
 * ★ SLOT_EFFORT は網の定数。全ノードで同じでなければならない (テストだけが引数で下げる)。
 */

/**
 * 枠の PoW の effort。実測 (Node 20 + 埋め込み wasm、80 回): 1 枠 平均 2.06 秒・中央値 1.1 秒・p90 5.7 秒
 * (幾何分布なので裾が長い)。1 試行 約 60ms で解は平均 1.47 個、effort 48 なら約 33 試行 ≒ 2 秒。
 * 検証は 1 枠 約 24〜49µs (Equi-X 検証 + BLAKE2b 1 回)。
 */
export const SLOT_EFFORT = 48;

/** 1 枠 = 256MiB 相当 */
export const SLOT_BYTES = 256 * 1024 * 1024;
/** 1 つの SID が持てる枠の最大数 (leaseSet の slotCount の上限) */
export const MAX_SLOTS = 16;

const enc = new TextEncoder();
const SLOT_POW_DOMAIN = enc.encode('oz/v5/slot-pow');
export const SLOT_POSITION_DOMAIN = 'oz/v5/slot';

export interface SlotSolution {
  nonce: number;
  /** Equi-X の解 (16 バイト) */
  solution: Uint8Array;
}

function seedOf(sid: Uint8Array, index: number): Uint8Array {
  return sodium.crypto_generichash(32, concat([SLOT_POW_DOMAIN, sid, Uint8Array.of(index)]), null);
}

function meetsEffort(seed: Uint8Array, nonce: number, solution: Uint8Array, effort: number): boolean {
  const r = sodium.crypto_generichash(32, concat([seed, u32be(nonce), solution]), null);
  const v = ((r[0] << 24) | (r[1] << 16) | (r[2] << 8) | r[3]) >>> 0;
  return v * effort <= 0xffffffff;
}

/** 枠 index の解を検証する。同期 (equixReady を済ませておくこと) */
export function verifySlotSolution(
  sid: Uint8Array, index: number, sol: SlotSolution, effort: number = SLOT_EFFORT,
): boolean {
  if (sid.length !== 32) return false;
  if (!Number.isInteger(index) || index < 0 || index >= MAX_SLOTS) return false;
  if (!Number.isInteger(sol.nonce) || sol.nonce < 0 || sol.nonce > 0xffffffff) return false;
  if (!(sol.solution instanceof Uint8Array) || sol.solution.length !== EQUIX_SOLUTION_BYTES) return false;
  const seed = seedOf(sid, index);
  if (!equixVerify(concat([seed, u32be(sol.nonce)]), sol.solution)) return false;
  return meetsEffort(seed, sol.nonce, sol.solution, effort);
}

/** 枠 index のリング上の位置。解の検証は呼び出し側 (verifySlotSolution) が済ませていること */
export function slotPosition(sid: Uint8Array, index: number, solution: Uint8Array): bigint {
  return positionOf(SLOT_POSITION_DOMAIN, sid, Uint8Array.of(index), solution);
}

const yieldToLoop = () => new Promise<void>(resolve => setTimeout(resolve, 0));

/**
 * 枠 index の解を探す。nonce を 0, 1, 2, … と試す (1 試行 約 60ms の同期 wasm)。
 * ★ 1 試行ごとにイベントループへ戻る。解くのに数秒かかるので、画面とネットワークを止めない。
 * @param shouldStop true を返すと null で打ち切る (停止・容量の縮小)
 */
export async function solveSlot(
  sid: Uint8Array, index: number, opts: { effort?: number; shouldStop?: () => boolean } = {},
): Promise<SlotSolution | null> {
  const effort = opts.effort ?? SLOT_EFFORT;
  const seed = seedOf(sid, index);
  for (let nonce = 0; nonce <= 0xffffffff; nonce++) {
    if (opts.shouldStop?.()) return null;
    for (const solution of equixSolve(concat([seed, u32be(nonce)]))) {
      if (meetsEffort(seed, nonce, solution, effort)) return { nonce, solution };
    }
    await yieldToLoop();
  }
  return null;
}

import sodium from '../../crypto/sodium';
import { equixSolve, equixVerify, EQUIX_SOLUTION_BYTES } from '../../crypto/equix/EquiX';
import { concat, u32be } from '../../crypto/PowPolicy';

/**
 * ChunkPow — チャンクを預けるときの保存の PoW (docs/design/file-sharing.md §3・§6)。
 *
 *   seed      = BLAKE2b-256("oz/v5/chunk-pow" ‖ chunkId)
 *   challenge = seed ‖ u32be(nonce)                         … Equi-X の challenge
 *   解 s が有効 ⇔ equixVerify(challenge, s) かつ u32be(BLAKE2b-256(seed ‖ u32be(nonce) ‖ s)[0..4]) * effort ≤ 0xFFFFFFFF
 *
 * ★ 主役ではなく**減速帯**。押し流しの本当の防御は Guard での IP ごとの上り制限・取られていない順の追い出し・
 *   投稿用と大容量の容量の分離 (設計 §6)。PoW は「1 台が毎秒数千チャンクを PUT する」ことを止める程度に軽く、
 *   正直な利用者が 2GiB (8,192 チャンク) を上げても PoW だけで 30 分を超えない程度に収める。
 * ★ 解は**チャンク ID だけ**に結び付く (置き先の保持者・複製の番号を含めない)。複製先が変わっても (別の保持者へ回す・
 *   5 か所へ置く) 1 回の解で済む。代わりに、同じチャンクを別の人が再生してもらえるが、チャンク ID は中身のハッシュなので
 *   「そのチャンクを置く」以外のことには使えない。
 * ★ CHUNK_EFFORT は網の定数 (全ノードで同じ)。テストだけが構築時の引数で下げる (本番に迂回の経路は無い)。
 *   Equi-X は 1 試行 約 60ms で解が平均 1.47 個 → effort E の期待時間は約 41ms × E。5 なら約 0.2 秒 (幾何分布なので裾は長い)。
 */
export const CHUNK_EFFORT = 5;

const CHUNK_POW_DOMAIN = new TextEncoder().encode('oz/v5/chunk-pow');

export interface ChunkPowSolution {
  nonce: number;
  /** Equi-X の解 (16 バイト) */
  solution: Uint8Array;
}

function seedOf(chunkId: Uint8Array): Uint8Array {
  return sodium.crypto_generichash(32, concat([CHUNK_POW_DOMAIN, chunkId]), null);
}

function meetsEffort(seed: Uint8Array, nonce: number, solution: Uint8Array, effort: number): boolean {
  const r = sodium.crypto_generichash(32, concat([seed, u32be(nonce), solution]), null);
  const v = ((r[0] << 24) | (r[1] << 16) | (r[2] << 8) | r[3]) >>> 0;
  return v * effort <= 0xffffffff;
}

/** 解を検証する。同期 (equixReady と sodiumReady を済ませておくこと)。約 25µs */
export function verifyChunkPow(chunkId: Uint8Array, sol: ChunkPowSolution, effort: number = CHUNK_EFFORT): boolean {
  if (chunkId.length !== 16) return false;
  if (!Number.isInteger(sol.nonce) || sol.nonce < 0 || sol.nonce > 0xffffffff) return false;
  if (!(sol.solution instanceof Uint8Array) || sol.solution.length !== EQUIX_SOLUTION_BYTES) return false;
  const seed = seedOf(chunkId);
  if (!equixVerify(concat([seed, u32be(sol.nonce)]), sol.solution)) return false;
  return meetsEffort(seed, sol.nonce, sol.solution, effort);
}

const yieldToLoop = () => new Promise<void>(resolve => setTimeout(resolve, 0));

/**
 * 解を探す。nonce を 0, 1, 2, … と試す (1 試行 約 60ms の同期 wasm)。
 * ★ 1 試行ごとにイベントループへ戻る (Worker が無い環境のフォールバックでも、画面とネットワークを止めない)。
 *   Worker では {@link solveChunkPowSync} を使う (そちらは戻らず、メインスレッドの外で回る)。
 * @param shouldStop true を返すと null で打ち切る (中止)
 */
export async function solveChunkPow(
  chunkId: Uint8Array, opts: { effort?: number; shouldStop?: () => boolean } = {},
): Promise<ChunkPowSolution | null> {
  const effort = opts.effort ?? CHUNK_EFFORT;
  const seed = seedOf(chunkId);
  for (let nonce = 0; nonce <= 0xffffffff; nonce++) {
    if (opts.shouldStop?.()) return null;
    for (const solution of equixSolve(concat([seed, u32be(nonce)]))) {
      if (meetsEffort(seed, nonce, solution, effort)) return { nonce, solution };
    }
    await yieldToLoop();
  }
  return null;
}

/** 戻らずに探す (Worker の中で使う) */
export function solveChunkPowSync(chunkId: Uint8Array, effort: number = CHUNK_EFFORT): ChunkPowSolution | null {
  const seed = seedOf(chunkId);
  for (let nonce = 0; nonce <= 0xffffffff; nonce++) {
    for (const solution of equixSolve(concat([seed, u32be(nonce)]))) {
      if (meetsEffort(seed, nonce, solution, effort)) return { nonce, solution };
    }
  }
  return null;
}

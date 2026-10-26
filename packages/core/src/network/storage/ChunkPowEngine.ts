import sodium from '../../crypto/sodium';
import { equixReady } from '../../crypto/equix/EquiX';
import { WorkerBridge } from '../../worker/WorkerBridge';
import { CHUNK_EFFORT, solveChunkPow, type ChunkPowSolution } from './ChunkPow';

/**
 * ★ Worker の中 (pow.worker.ts) は ChunkPow だけを読み込み、このファイル (WorkerBridge を読み込む) は読み込まない。
 *   Worker が自分自身を Worker として起動するコードを抱えると、バンドラが循環して Worker を作り続けてしまう。
 */
/**
 * 解を探す入口。Worker があれば Worker で (画面を止めない。上げる端末は 1 チャンクごとに呼ぶ)、無ければ (Node・テスト) 同じスレッドで。
 * ★ Worker 版は途中で止められない (1 チャンク 約 0.2 秒なので、中止は次のチャンクから効けば足りる)。
 */
export async function computeChunkPow(
  chunkId: Uint8Array, opts: { effort?: number; shouldStop?: () => boolean } = {},
): Promise<ChunkPowSolution | null> {
  await equixReady;
  await sodium.ready;
  const effort = opts.effort ?? CHUNK_EFFORT;
  if (typeof Worker === 'undefined') return solveChunkPow(chunkId, { effort, shouldStop: opts.shouldStop });
  try {
    const r = await WorkerBridge.request<{ nonce: number; solution: Uint8Array }>('chunk-pow', { chunkId, effort });
    return { nonce: r.nonce, solution: new Uint8Array(r.solution) };
  } catch {
    return solveChunkPow(chunkId, { effort, shouldStop: opts.shouldStop });
  }
}

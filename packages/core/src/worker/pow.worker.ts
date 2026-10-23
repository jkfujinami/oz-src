import sodium from '../crypto/sodium';
import { equixReady } from '../crypto/equix/EquiX';
import { solvePow, toBytes, type PowCommitted } from '../crypto/PowPolicy';
import { solveChunkPowSync } from '../network/storage/ChunkPow';

/**
 * PoW Web Worker
 *
 * PoW の *探索* (Equi-X。1 試行約 60ms) だけをこのスレッドで行う。検証はメインスレッドで
 * 同期実行する ({@link ../crypto/PoWEngine})。Wasm はこの Worker でも別に読み込む (equixReady)。
 */

/** ★ チャンクの保存の PoW (network/storage/ChunkPow)。パケットの PoW とは別の問題で、同じ Worker を使い回す */
interface ChunkPowRequest {
  id: string;
  type: 'chunk-pow';
  chunkId: Uint8Array;
  effort: number;
}

interface ComputeRequest {
  id: string;
  type: 'compute';
  header: {
    version: number;
    time: number;
    tag: number;
    age: number;
    effort_exp: number;
    payload: unknown;
  };
}

self.onmessage = async (e: MessageEvent<ComputeRequest | ChunkPowRequest>) => {
  const { id, type } = e.data ?? ({} as ComputeRequest);

  try {
    await sodium.ready;
    await equixReady;

    if (type === 'chunk-pow') {
      const req = e.data as ChunkPowRequest;
      const sol = solveChunkPowSync(new Uint8Array(req.chunkId), req.effort);
      if (sol === null) throw new Error('PoW search exhausted');
      self.postMessage({ id, type: 'result', result: { nonce: sol.nonce, solution: sol.solution } });
      return;
    }

    const { header } = e.data as ComputeRequest;
    if (type !== 'compute') {
      throw new Error(`unsupported request type: ${String(type)}`);
    }

    const committed: PowCommitted = {
      version: header.version,
      time: header.time,
      tag: header.tag,
      age: header.age,
      effort_exp: header.effort_exp,
      payload: toBytes(header.payload),
    };

    const sol = solvePow(committed);
    if (sol === null) throw new Error('PoW search exhausted');

    self.postMessage({ id, type: 'result', result: { nonce: sol.nonce, solution: sol.solution } });
  } catch (err: any) {
    self.postMessage({ id, type: 'error', error: err?.message ?? String(err) });
  }
};

import { createLogger } from '../common/Logger';
import { equixReady } from '../crypto/equix/EquiX';

const log = createLogger('worker.bridge');

/**
 * WorkerBridge
 * Web Worker とメインスレッドを Promise で繋ぐ架け橋。
 *
 * 旧実装は pendingRequests に登録した Promise を回収する経路が
 * 「Worker からの応答」しかなく、Worker がクラッシュしたり応答を落とすと
 * Promise が永久に解決されずメモリに残り続けた。タイムアウトと
 * onerror での一括 reject を追加してある。
 */
export class WorkerBridge {
  private static worker: Worker | null = null;
  private static pending = new Map<
    string,
    { resolve: (val: any) => void; reject: (err: any) => void; timer: ReturnType<typeof setTimeout> }
  >();

  /** 1 リクエストの上限。Equi-X の探索は effort が低いうちは 1 試行 60ms 前後で終わる想定 */
  private static readonly REQUEST_TIMEOUT_MS = 120_000;

  static getWorker(): Worker {
    if (!this.worker) {
      let workerUrl: URL;
      try {
        if (typeof import.meta !== 'undefined' && import.meta?.url) {
          workerUrl = new URL('./pow.worker.js', import.meta.url);
        } else {
          const base = typeof location !== 'undefined' ? location.href : 'http://localhost/';
          workerUrl = new URL('./pow.worker.js', base);
        }
      } catch {
        const base = typeof location !== 'undefined' ? location.href : 'http://localhost/';
        workerUrl = new URL('./pow.worker.js', base);
      }
      this.worker = new Worker(workerUrl, { type: 'module' });
      this.worker.onmessage = (e) => this.handleMessage(e);
      this.worker.onerror = (err) => {
        log.error('Worker error:', err);
        this.rejectAll(new Error(`PoW worker error: ${err.message ?? 'unknown'}`));
        // 壊れた Worker は捨てて次回作り直す
        this.worker?.terminate();
        this.worker = null;
      };
    }
    return this.worker;
  }

  static async request<T = any>(type: string, data: Record<string, unknown>): Promise<T> {
    // ★ メインスレッド側の Wasm も読み込み済みにしてから投げる (結果の検証・フォールバックで使う)。
    //   Worker 自身は pow.worker.ts で自分の分を待つ。
    await equixReady;
    const worker = this.getWorker();
    const id = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;

    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`PoW worker timeout after ${this.REQUEST_TIMEOUT_MS}ms (type=${type})`));
      }, this.REQUEST_TIMEOUT_MS);

      this.pending.set(id, { resolve, reject, timer });
      worker.postMessage({ id, type, ...data });
    });
  }

  private static handleMessage(e: MessageEvent) {
    const { id, type, result, error } = e.data ?? {};
    const entry = this.pending.get(id);
    if (!entry) return;

    clearTimeout(entry.timer);
    this.pending.delete(id);

    if (type === 'result') entry.resolve(result);
    else entry.reject(new Error(error ?? 'unknown worker error'));
  }

  private static rejectAll(err: Error) {
    for (const [, entry] of this.pending) {
      clearTimeout(entry.timer);
      entry.reject(err);
    }
    this.pending.clear();
  }

  /** テスト・アンマウント用 */
  static destroy() {
    this.rejectAll(new Error('WorkerBridge destroyed'));
    this.worker?.terminate();
    this.worker = null;
  }
}

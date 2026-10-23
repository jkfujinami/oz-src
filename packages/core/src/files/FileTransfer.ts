import type { PeerId } from '../types';

/**
 * FileTransfer — FileUploader / FileDownloader / ChunkReader が共有する小さな部品。
 *
 * ★ ここは**メモリだけ**で動く。アップロード・ダウンロードの途中経過 (どのチャンクまで済んだか・どのファイルか) も、
 *   平文・暗号文のチャンクも、ディスク (IndexedDB・OPFS) には一切書かない。アプリが閉じたら全部失われる。
 *   押収された端末に「このファイルを上げていた / 取っていた」痕跡を残さないため (docs/design/file-sharing.md の脅威モデル)。
 */

export type FileTransferErrorCode =
  | 'cancelled'
  | 'no-first-hop'
  | 'no-holders'
  | 'insufficient-replicas'
  | 'unavailable'
  | 'bad-link'
  | 'bad-manifest';

export class FileTransferError extends Error {
  constructor(public readonly code: FileTransferErrorCode, message?: string) {
    super(message ?? code);
    this.name = 'FileTransferError';
  }
}

/** 中止を待ち時間に反映する sleep。中止されたら (例外でなく) すぐ戻る */
export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal?.aborted) return resolve();
    const t = setTimeout(done, ms);
    function done() {
      clearTimeout(t);
      signal?.removeEventListener('abort', done);
      resolve();
    }
    signal?.addEventListener('abort', done, { once: true });
  });
}

/**
 * 送る間隔の調整。perSec 回/秒を超えないよう、呼ぶたびに次の枠の時刻まで待たせる (バーストは許さない)。
 * ★ Guard の上り枠 (TUNNEL_LIMITS.CLIENT_SEND) より手前で自分で絞る: Guard に断られてからでなく、断られない速さで送る。
 */
export class Pacer {
  private next = 0;

  constructor(private readonly perSec: number) {}

  public async wait(signal?: AbortSignal): Promise<void> {
    const now = Date.now();
    const at = Math.max(now, this.next);
    this.next = at + 1000 / this.perSec;
    if (at > now) await sleep(at - now, signal);
  }
}

/** 同時数の上限。acquire は中止されたら false (枠は取れていない) */
export class Semaphore {
  private waiters: Array<() => void> = [];
  private used = 0;

  constructor(private readonly max: number) {}

  public async acquire(signal?: AbortSignal): Promise<boolean> {
    while (this.used >= this.max) {
      if (signal?.aborted) return false;
      await new Promise<void>((resolve) => {
        const wake = () => {
          signal?.removeEventListener('abort', wake);
          // ★ 中止で起きたときは待ち行列から外す。残すと、次の release が死んだ待ち手を起こして、生きている待ち手が起きない
          const i = this.waiters.indexOf(wake);
          if (i >= 0) this.waiters.splice(i, 1);
          resolve();
        };
        this.waiters.push(wake);
        signal?.addEventListener('abort', wake, { once: true });
      });
    }
    if (signal?.aborted) return false;
    this.used++;
    return true;
  }

  public release(): void {
    this.used--;
    this.waiters.shift()?.();
  }
}

/** 一時停止の門。pause 中は wait が解けない。中止されたら解ける */
export class PauseGate {
  private paused = false;
  private waiters: Array<() => void> = [];

  public get isPaused(): boolean {
    return this.paused;
  }

  public pause(): void {
    this.paused = true;
  }

  public resume(): void {
    this.paused = false;
    for (const w of this.waiters.splice(0)) w();
  }

  public async wait(signal?: AbortSignal): Promise<void> {
    while (this.paused && !signal?.aborted) {
      await new Promise<void>((resolve) => {
        const wake = () => {
          signal?.removeEventListener('abort', wake);
          const i = this.waiters.indexOf(wake);
          if (i >= 0) this.waiters.splice(i, 1);
          resolve();
        };
        this.waiters.push(wake);
        signal?.addEventListener('abort', wake, { once: true });
      });
    }
  }
}

/** 1 ホップ目が使えるようになるのを待つ (使えれば true)。中止・時間切れで false */
export async function waitForFirstHop(
  tunnel: { readonly firstHop: PeerId | null }, timeoutMs: number, signal?: AbortSignal, pollMs = 200,
): Promise<boolean> {
  const end = Date.now() + timeoutMs;
  while (!tunnel.firstHop) {
    if (signal?.aborted || Date.now() >= end) return false;
    await sleep(pollMs, signal);
  }
  return true;
}

/**
 * 親の signal が中止されたら中止される、子の AbortController。
 * ★ 子が先に終わったら、親に付けた監視を外す (外さないと、長いアップロードで要求のたびに監視が溜まる)。
 */
export function linkedController(parent?: AbortSignal): AbortController {
  const ac = new AbortController();
  if (parent) {
    if (parent.aborted) {
      ac.abort();
    } else {
      const onParent = () => ac.abort();
      parent.addEventListener('abort', onParent, { once: true });
      ac.signal.addEventListener('abort', () => parent.removeEventListener('abort', onParent), { once: true });
    }
  }
  return ac;
}

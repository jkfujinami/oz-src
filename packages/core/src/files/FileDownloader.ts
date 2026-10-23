import { sodiumReady } from '../crypto/sodium';
import { equixReady } from '../crypto/equix/EquiX';
import { createLogger } from '../common/Logger';
import { ChunkReader, type ChunkReaderParts } from './ChunkReader';
import { FileAssembler, decryptManifest } from './FileCodec';
import { chunkPlainLength, type FileManifest } from './FileFormat';
import { decodeFileLinkBody, parseFileLinks, type FileLink } from './FileLink';
import { FileTransferError, waitForFirstHop } from './FileTransfer';

const log = createLogger('files.download');

export const DOWNLOAD_LIMITS = {
  /** 同時に取るチャンクの数 */
  CONCURRENCY: 6,
  /**
   * 受け取り側がまだ読み出していない (手元に溜めている) チャンクの数の上限。256KiB × 24 = 6MiB。
   * ★ 受け取り側 (保存先への書き込み) が遅いときに、取り続けてメモリを膨らませない。
   */
  WINDOW: 24,
  /** 1 ホップ目がつながるのを待つ上限 */
  READY_WAIT_MS: 60_000,
} as const;

export interface DownloadProgress {
  /** manifest: Manifest を取っている / chunks: チャンクを取っている / done: 全部取れた (読み出しはこれから) */
  phase: 'manifest' | 'chunks' | 'done';
  /** 検証を通った (取り終えた) 平文の合計 */
  bytesDone: number;
  /** ファイルの大きさ (リンクにある) */
  totalBytes: number;
  chunksDone: number;
  chunkCount: number;
}

export interface FileDownloaderParts extends ChunkReaderParts {
  /** ★ テスト専用 */
  downloadLimits?: Partial<{ concurrency: number; window: number; readyWaitMs: number }>;
}

/** リンクの文字列 (`[[file:...]]` でも本体の base64url だけでもよい) を読む。不正なら null */
export function parseLinkToken(token: string): FileLink | null {
  const t = token.trim();
  return parseFileLinks(t)[0]?.link ?? decodeFileLinkBody(t);
}

/**
 * FileDownload — 取得中のファイル。`for await` で**平文を番号順に**受け取る (保存先 = Blob / OPFS / ファイルは呼び出し側が決める)。
 *
 *   const dl = node.downloadFile(token, onProgress);
 *   const info = await dl.manifest;          // 名前・MIME・大きさ (画面のカード用)
 *   for await (const piece of dl) write(piece);
 *   dl.cancel();                              // いつでも中止できる
 */
export interface FileDownload extends AsyncIterable<Uint8Array> {
  /** 復号した Manifest。取れなければ拒否される */
  readonly manifest: Promise<FileManifest>;
  cancel(): void;
}

/**
 * FileDownloader — リンクからファイルを取る (docs/design/file-sharing.md §4)。
 *
 *   リンク → Manifest (そのチャンク ID の位置から GET_CHUNK) → decryptManifest (ID とリンクの突き合わせ → 復号)
 *   → チャンクを CONCURRENCY (6) 本ずつ (ChunkReader: 速い保持者から・遅ければ別の複製へ) → FileAssembler で検証して復号
 *   → 番号順に平文を出す。
 *
 * ★ 検証の順: ハッシュ (暗号文の SHA-256 の先頭 16 バイト = チャンク ID) → 復号 (AEAD) → 長さ。偽物を返した保持者は
 *   後回しにして、別の保持者から取り直す (ChunkReader)。
 * ★ **ディスクに何も書かない**: 部分的に取ったチャンク・どこまで取ったかをメモリの外へ出さない。中断したら最初からやり直す
 *   (取りかけの記録は「何を取っていたか」の痕跡になる。設計 §4 の「取りかけを暗号化 DB に置く」は、この版では採らない)。
 * ★ 保持者ごとの速さはメモリだけ (ChunkReader)。
 */
export class FileDownloader implements FileDownload {
  public readonly manifest: Promise<FileManifest>;

  private readonly ac = new AbortController();
  private readonly reader: ChunkReader;
  private readonly lim: { concurrency: number; window: number; readyWaitMs: number };
  private readonly link: FileLink | null;
  private resolveManifest!: (m: FileManifest) => void;
  private rejectManifest!: (e: unknown) => void;

  /** 取り終えて番号順に並んだ、まだ読み出されていない平文 */
  private queue: Uint8Array[] = [];
  private consumed = 0;
  private wake: (() => void) | null = null;
  private finished = false;
  private error: unknown = null;
  private started = false;
  private iterated = false;
  private progress: DownloadProgress;

  constructor(
    private readonly parts: FileDownloaderParts,
    token: string,
    private readonly onProgress?: (p: DownloadProgress) => void,
  ) {
    const l = parts.downloadLimits ?? {};
    this.lim = {
      concurrency: l.concurrency ?? DOWNLOAD_LIMITS.CONCURRENCY,
      window: l.window ?? DOWNLOAD_LIMITS.WINDOW,
      readyWaitMs: l.readyWaitMs ?? DOWNLOAD_LIMITS.READY_WAIT_MS,
    };
    this.reader = new ChunkReader(parts);
    this.link = parseLinkToken(token);
    this.progress = { phase: 'manifest', bytesDone: 0, totalBytes: this.link?.size ?? 0, chunksDone: 0, chunkCount: 0 };
    this.manifest = new Promise<FileManifest>((resolve, reject) => {
      this.resolveManifest = resolve;
      this.rejectManifest = reject;
    });
    this.manifest.catch(() => undefined);
  }

  /** 診断・テスト用 */
  public get readerStats() {
    return this.reader.stats;
  }
  public speedOf(sid: string): number | undefined {
    return this.reader.speedOf(sid);
  }

  /** 取り始める (一度だけ。iterate すると自動で始まる) */
  public start(): this {
    if (this.started) return this;
    this.started = true;
    void this.run().catch((e) => this.fail(e));
    return this;
  }

  public cancel(): void {
    this.ac.abort();
    this.fail(new FileTransferError('cancelled'));
  }

  private emit(): void {
    try {
      this.onProgress?.({ ...this.progress });
    } catch (e) {
      log.warn('progress listener failed', e);
    }
  }

  private fail(e: unknown): void {
    if (this.finished) return;
    this.finished = true;
    this.error = e;
    this.queue.length = 0; // 失敗・中止したら、溜めていた平文は渡さない
    this.ac.abort();
    this.rejectManifest(e);
    this.wakeUp();
  }

  private wakeUp(): void {
    const w = this.wake;
    this.wake = null;
    w?.();
  }

  private async run(): Promise<void> {
    await sodiumReady;
    await equixReady;
    if (!this.link) throw new FileTransferError('bad-link');
    const link = this.link;
    if (!(await waitForFirstHop(this.parts.tunnel, this.lim.readyWaitMs, this.ac.signal))) {
      throw this.ac.signal.aborted ? new FileTransferError('cancelled') : new FileTransferError('no-first-hop');
    }

    // ── Manifest ──
    let manifest: FileManifest | null = null;
    const m = await this.reader.read(link.manifestId, async (data) => {
      // ★ ID を突き合わせてから復号する (decryptManifest が内側で行う)。偽の Manifest を返す保持者はここで弾かれる
      const dec = await decryptManifest(data, link);
      if (!dec) return false;
      manifest = dec;
      return true;
    }, this.ac.signal);
    if (!m.ok || !manifest) {
      throw m.ok === false && m.reason === 'aborted' ? new FileTransferError('cancelled') : new FileTransferError('unavailable', 'manifest');
    }
    const mf: FileManifest = manifest;
    this.resolveManifest(mf);
    const asm = new FileAssembler(mf, link.key);
    this.progress = { phase: 'chunks', bytesDone: 0, totalBytes: mf.size, chunksDone: 0, chunkCount: mf.chunkIds.length };
    this.emit();

    // ── チャンク ──
    const n = mf.chunkIds.length;
    let nextIndex = 0;
    let active = 0;
    let completed = 0;
    await new Promise<void>((resolve, reject) => {
      const pump = () => {
        if (this.finished) return resolve();
        while (active < this.lim.concurrency && nextIndex < n && nextIndex - this.consumed < this.lim.window) {
          const index = nextIndex++;
          active++;
          void this.fetchOne(asm, mf, index).then(() => {
            active--;
            completed++;
            this.progress.chunksDone = completed;
            this.progress.bytesDone += chunkPlainLength(mf.size, index);
            this.emit();
            // 取れた分のうち、先頭から連続している分を番号順に出す
            for (const piece of asm.drain()) this.queue.push(piece.plaintext);
            this.wakeUp();
            if (completed === n) return resolve();
            pump();
          }, reject);
        }
      };
      this.onConsumed = pump;
      pump();
    });
    if (this.finished) return;
    this.progress.phase = 'done';
    this.emit();
    this.finished = true; // 正常終了: 残りの平文は queue に残っていて、読み出し側が空にするまで返す
    this.wakeUp();
  }

  private onConsumed: () => void = () => undefined;

  /** チャンク 1 つを取って検証する。取れなければ例外 (全体が失敗する) */
  private async fetchOne(asm: FileAssembler, mf: FileManifest, index: number): Promise<void> {
    const id = mf.chunkIds[index];
    const r = await this.reader.read(id, async (data) => {
      const res = await asm.accept(index, data);
      return res.ok || res.reason === 'duplicate';
    }, this.ac.signal);
    if (!r.ok) {
      throw r.reason === 'aborted' ? new FileTransferError('cancelled') : new FileTransferError('unavailable', `chunk ${index}`);
    }
  }

  public [Symbol.asyncIterator](): AsyncIterator<Uint8Array> {
    if (this.iterated) throw new Error('FileDownload can be iterated only once');
    this.iterated = true;
    this.start();
    return {
      next: async (): Promise<IteratorResult<Uint8Array>> => {
        for (;;) {
          const piece = this.queue.shift();
          if (piece) {
            this.consumed++;
            this.onConsumed(); // 窓が空いたので次のチャンクを取り始める
            return { value: piece, done: false };
          }
          if (this.error) throw this.error;
          if (this.finished) return { value: undefined, done: true };
          await new Promise<void>((resolve) => { this.wake = resolve; });
        }
      },
      return: async (): Promise<IteratorResult<Uint8Array>> => {
        this.cancel();
        return { value: undefined, done: true };
      },
    };
  }
}

/**
 * OzzyStream — ファイル全体をメモリに載せずに、ストライプ (最大約 64 MiB) 単位で読み・書きする部品。
 *
 *   上げる: OrderedSourceReader が File / Blob を先頭から 1 ストライプずつ切り出し、全体のハッシュを順に積み上げる。
 *   取る:   writeStripesInOrder が復元できたストライプを番号順に書き出し先 (OzzyByteSink) へ流し、ハッシュを確かめる。
 *           ブラウザでは File System Access API の FileSystemWritableFileStream (write / close / abort) をそのまま渡せる。
 *
 * ★ 同時に持つストライプの数は並列数 + 1 まで。GB 級のファイルでもメモリは数百 MiB で頭打ちになる。
 * ★ 全体のハッシュが合わなければ、書き出し先を abort する (FileSystemWritableFileStream は abort で書きかけを捨てる)。
 *   ストライプごとの中身は K_enc の認証と Manifest のハッシュで既に確かめてあるので、書いた分が改ざんされていることはない。
 */
import sodium, { sodiumReady } from '../crypto/sodium';
import { bytesEqual } from '../files/FileFormat';

/** アップロードの元。Uint8Array・Blob (File)・任意の範囲読み出し */
export type OzzyUploadSource =
  | Uint8Array
  | Blob
  | { readonly size: number; read(start: number, end: number): Promise<Uint8Array> };

export function sourceSize(src: OzzyUploadSource): number {
  if (src instanceof Uint8Array) return src.byteLength;
  return src.size;
}

/** [start, end) を読む */
export async function readSource(src: OzzyUploadSource, start: number, end: number): Promise<Uint8Array> {
  if (src instanceof Uint8Array) return src.subarray(start, end);
  if (typeof Blob !== 'undefined' && src instanceof Blob) return new Uint8Array(await src.slice(start, end).arrayBuffer());
  return (src as { read(start: number, end: number): Promise<Uint8Array> }).read(start, end);
}

/** 書き出し先。FileSystemWritableFileStream と同じ形 (write / close / abort) */
export interface OzzyByteSink {
  write(chunk: Uint8Array): Promise<void> | void;
  close?(): Promise<void> | void;
  abort?(reason?: unknown): Promise<void> | void;
}

/** メモリに集める書き出し先 (テスト・小さいファイル用) */
export function memorySink(): OzzyByteSink & { result(): Uint8Array } {
  const parts: Uint8Array[] = [];
  let total = 0;
  return {
    write(chunk) {
      parts.push(chunk);
      total += chunk.length;
    },
    result() {
      const out = new Uint8Array(total);
      let o = 0;
      for (const p of parts) {
        out.set(p, o);
        o += p.length;
      }
      return out;
    },
  };
}

/** 全体のハッシュ (BLAKE2b-256) を少しずつ積み上げる */
export class StreamingFileHash {
  private state: unknown;

  constructor() {
    this.state = sodium.crypto_generichash_init(null, 32);
  }

  update(chunk: Uint8Array): void {
    sodium.crypto_generichash_update(this.state as never, chunk);
  }

  digest(): Uint8Array {
    return sodium.crypto_generichash_final(this.state as never, 32);
  }
}

/**
 * アップロードの元を先頭から sliceBytes ずつ順に切り出す。読むのは 1 つずつ (順番どおり) で、全体のハッシュも順に積む。
 * 並列にアップロードするワーカーが next() を呼び合っても、読み出しとハッシュの順は崩れない。
 */
export class OrderedSourceReader {
  readonly size: number;
  readonly count: number;
  private index = 0;
  private chain: Promise<unknown> = Promise.resolve();
  private readonly hash = new StreamingFileHash();

  constructor(private readonly src: OzzyUploadSource, private readonly sliceBytes: number) {
    this.size = sourceSize(src);
    this.count = Math.max(1, Math.ceil(this.size / sliceBytes));
  }

  /** 次のスライス。無ければ null */
  next(): Promise<{ index: number; data: Uint8Array } | null> {
    const run = this.chain.then(async () => {
      if (this.index >= this.count) return null;
      const index = this.index++;
      const start = index * this.sliceBytes;
      const data = await readSource(this.src, start, Math.min(this.size, start + this.sliceBytes));
      this.hash.update(data);
      return { index, data };
    });
    this.chain = run.catch(() => undefined);
    return run;
  }

  /** 全部読み終えた後の全体のハッシュ */
  digest(): Uint8Array {
    if (this.index < this.count) throw new Error('OrderedSourceReader: not fully read');
    return this.hash.digest();
  }
}

export type StripeWriteResult = 'ok' | 'failed' | 'aborted' | 'size-mismatch' | 'hash-mismatch';

/**
 * ストライプを並列に取り、番号順に書き出し先へ流す。全体の大きさとハッシュを確かめ、合わなければ abort する。
 * ★ 先に終わったストライプは、前のストライプが書けるまで待つ。待っている数が並列数を超えないよう、先へ進みすぎない。
 */
export async function writeStripesInOrder(p: {
  stripeCount: number;
  concurrency: number;
  fetchStripe: (index: number, signal: AbortSignal) => Promise<Uint8Array | null>;
  sink: OzzyByteSink;
  expectedSize: number;
  expectedHash: Uint8Array;
  onStripe?: (done: number, total: number) => void;
  signal?: AbortSignal;
}): Promise<StripeWriteResult> {
  await sodiumReady;
  const ac = new AbortController();
  const onAbort = () => ac.abort();
  p.signal?.addEventListener('abort', onAbort, { once: true });
  if (p.signal?.aborted) ac.abort();

  const hash = new StreamingFileHash();
  const ready = new Map<number, Uint8Array>();
  let nextToWrite = 0;
  let nextToFetch = 0;
  let written = 0;
  let failed = false;
  let writing: Promise<void> = Promise.resolve();
  const window = Math.max(1, p.concurrency) + 1;
  let wake: (() => void) | null = null;
  const notify = () => {
    const w = wake;
    wake = null;
    w?.();
  };

  const flush = () => {
    writing = writing.then(async () => {
      while (!failed && ready.has(nextToWrite)) {
        const data = ready.get(nextToWrite)!;
        ready.delete(nextToWrite);
        hash.update(data);
        written += data.length;
        await p.sink.write(data);
        nextToWrite++;
        p.onStripe?.(nextToWrite, p.stripeCount);
        notify();
      }
    });
    return writing;
  };

  try {
    const workers = Array.from({ length: Math.min(Math.max(1, p.concurrency), p.stripeCount) }, async () => {
      while (!failed && !ac.signal.aborted && nextToFetch < p.stripeCount) {
        // 書けていないストライプが溜まりすぎないよう、先へ進みすぎたら待つ
        while (!failed && !ac.signal.aborted && nextToFetch - nextToWrite >= window) {
          await new Promise<void>((r) => { wake = r; setTimeout(r, 200); });
        }
        if (failed || ac.signal.aborted || nextToFetch >= p.stripeCount) return;
        const index = nextToFetch++;
        let data: Uint8Array | null = null;
        try {
          data = await p.fetchStripe(index, ac.signal);
        } catch {
          data = null;
        }
        if (!data) {
          failed = true;
          ac.abort();
          notify();
          return;
        }
        ready.set(index, data);
        await flush();
      }
    });
    await Promise.all(workers);
    await writing;
  } catch {
    failed = true;
  } finally {
    p.signal?.removeEventListener('abort', onAbort);
  }

  const abortSink = async (reason: string) => {
    try {
      await p.sink.abort?.(new Error(reason));
    } catch {
      // 書き出し先が既に閉じている
    }
  };
  if (failed || nextToWrite < p.stripeCount) {
    await abortSink('ozzy download failed');
    return p.signal?.aborted ? 'aborted' : 'failed';
  }
  if (written !== p.expectedSize) {
    await abortSink('ozzy size mismatch');
    return 'size-mismatch';
  }
  if (!bytesEqual(hash.digest(), p.expectedHash)) {
    await abortSink('ozzy hash mismatch');
    return 'hash-mismatch';
  }
  await p.sink.close?.();
  return 'ok';
}

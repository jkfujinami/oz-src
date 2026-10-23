/**
 * FileCodec — ファイルの暗号化 (送り側) と組み立て (取り側)。ストリーム処理でメモリは数チャンク分だけ。
 *
 * ★ DOM に依存しない (Worker で動く)。入力は Uint8Array / Blob 風 (slice().arrayBuffer()) /
 *   AsyncIterable<Uint8Array> のどれでもよい。
 */
import { sodiumReady } from '../crypto/sodium';
import { positionOf } from '../common/Ring';
import {
  CHUNK_ID_BYTES,
  CHUNK_SIZE,
  MAX_FILE_BYTES,
  bytesEqual,
  chunkCountFor,
  chunkPlainLength,
  decryptChunk,
  decryptManifestRaw,
  encryptChunk,
  encryptManifest,
  idOf,
  newFileKey,
  type FileManifest,
} from './FileFormat';
import { formatFileLink, type FileLink } from './FileLink';

export interface BlobLike {
  readonly size: number;
  slice(start?: number, end?: number): { arrayBuffer(): Promise<ArrayBuffer> };
}

export type FileSource = Uint8Array | BlobLike | AsyncIterable<Uint8Array>;

export interface EncodeOptions {
  name: string;
  mime: string;
  /** テスト用。通常は省略 (毎回乱数) */
  key?: Uint8Array;
}

export type EncodeEvent =
  | { kind: 'chunk'; index: number; id: Uint8Array; ciphertext: Uint8Array }
  | { kind: 'manifest'; id: Uint8Array; ciphertext: Uint8Array; link: FileLink; token: string };

/** 入力を高々 CHUNK_SIZE ごとの平文に切り出す。手元に持つのは 1 チャンク分の作業バッファ */
async function* plainChunks(source: FileSource): AsyncGenerator<Uint8Array> {
  if (source instanceof Uint8Array) {
    for (let o = 0; o < source.length; o += CHUNK_SIZE) yield source.subarray(o, Math.min(o + CHUNK_SIZE, source.length));
    return;
  }
  if (typeof (source as BlobLike).slice === 'function' && typeof (source as BlobLike).size === 'number') {
    const blob = source as BlobLike;
    for (let o = 0; o < blob.size; o += CHUNK_SIZE) {
      yield new Uint8Array(await blob.slice(o, Math.min(o + CHUNK_SIZE, blob.size)).arrayBuffer());
    }
    return;
  }
  let buf = new Uint8Array(CHUNK_SIZE);
  let fill = 0;
  for await (const piece of source as AsyncIterable<Uint8Array>) {
    let o = 0;
    while (o < piece.length) {
      const n = Math.min(CHUNK_SIZE - fill, piece.length - o);
      buf.set(piece.subarray(o, o + n), fill);
      fill += n;
      o += n;
      if (fill === CHUNK_SIZE) {
        yield buf;
        buf = new Uint8Array(CHUNK_SIZE); // yield 先が保持していても壊れないよう新しく取る
        fill = 0;
      }
    }
  }
  if (fill > 0) yield buf.subarray(0, fill);
}

/**
 * ファイルを暗号化してチャンクを 1 つずつ出し、最後に Manifest を出す。
 * ★ 全チャンクを置き終えてから投稿する (設計 §3) ので、Manifest は最後でよい。
 * 不正な入力 (空・2GiB 超) は例外。
 */
export async function* encodeFile(source: FileSource, opts: EncodeOptions): AsyncGenerator<EncodeEvent> {
  await sodiumReady;
  const key = opts.key ?? newFileKey();
  const ids: Uint8Array[] = [];
  let size = 0;
  let index = 0;
  for await (const plain of plainChunks(source)) {
    size += plain.length;
    if (size > MAX_FILE_BYTES) throw new RangeError('file too large');
    const { id, ciphertext } = await encryptChunk(plain, index, key);
    ids.push(id);
    yield { kind: 'chunk', index, id, ciphertext };
    index++;
  }
  if (size === 0) throw new RangeError('empty file');
  const m = await encryptManifest({ size, mime: opts.mime, name: opts.name, chunkIds: ids }, key);
  const link: FileLink = { manifestId: m.id, key, size };
  yield { kind: 'manifest', id: m.id, ciphertext: m.ciphertext, link, token: formatFileLink(link) };
}

/**
 * Manifest を復号する。★ 復号の前に ID (暗号文のハッシュ) をリンクと突き合わせる。
 * 保持者が偽の Manifest を返しても、ここで弾かれる。不正なら null。
 */
export async function decryptManifest(manifestCiphertext: Uint8Array, link: FileLink): Promise<FileManifest | null> {
  await sodiumReady;
  if (!bytesEqual(idOf(manifestCiphertext), link.manifestId)) return null;
  const m = await decryptManifestRaw(manifestCiphertext, link.key);
  if (!m || m.size !== link.size) return null;
  return m;
}

export type AcceptResult = { ok: true } | { ok: false; reason: 'range' | 'duplicate' | 'id' | 'decrypt' | 'length' };

/**
 * 取り側。チャンクを 1 つずつ検証・復号し、番号順に平文を出す。
 * ★ 状態は「欠け」「保持中 (未出力)」「出力済み」の 3 つ。出力済みの番号は保存先 (ディスク) に
 *   書かれたものとして覚えるので、`completed` を渡せば途中から再開できる。
 */
export class FileAssembler {
  private state: Uint8Array; // 0 欠け / 1 保持中 / 2 出力済み
  private held = new Map<number, Uint8Array>();
  private cursor = 0;

  constructor(
    readonly manifest: FileManifest,
    private readonly key: Uint8Array,
    completed: Iterable<number> = [],
  ) {
    this.state = new Uint8Array(manifest.chunkIds.length);
    for (const i of completed) if (Number.isInteger(i) && i >= 0 && i < this.state.length) this.state[i] = 2;
  }

  get chunkCount(): number {
    return this.state.length;
  }

  async accept(index: number, ciphertext: Uint8Array): Promise<AcceptResult> {
    await sodiumReady;
    if (!Number.isInteger(index) || index < 0 || index >= this.state.length) return { ok: false, reason: 'range' };
    if (this.state[index] !== 0) return { ok: false, reason: 'duplicate' };
    // ★ 暗号文のハッシュを先に確かめる (偽物に復号の計算を使わない)
      if (!bytesEqual(idOf(ciphertext), this.manifest.chunkIds[index])) return { ok: false, reason: 'id' };
    const plain = await decryptChunk(ciphertext, index, this.key);
    if (!plain) return { ok: false, reason: 'decrypt' };
    if (plain.length !== chunkPlainLength(this.manifest.size, index)) return { ok: false, reason: 'length' };
    this.state[index] = 1;
    this.held.set(index, plain);
    return { ok: true };
  }

  /** 先頭から連続している分の平文を番号順に出し、保持を解放する */
  *drain(): Generator<{ index: number; plaintext: Uint8Array }> {
    while (this.cursor < this.state.length && this.state[this.cursor] === 2) this.cursor++;
    while (this.cursor < this.state.length && this.state[this.cursor] === 1) {
      const index = this.cursor++;
      const plaintext = this.held.get(index)!;
      this.held.delete(index);
      this.state[index] = 2;
      yield { index, plaintext };
      while (this.cursor < this.state.length && this.state[this.cursor] === 2) this.cursor++;
    }
  }

  /** 受け取り済み (保持中 + 出力済み) の番号 */
  doneIndices(): number[] {
    const out: number[] = [];
    for (let i = 0; i < this.state.length; i++) if (this.state[i] !== 0) out.push(i);
    return out;
  }

  /** まだ受け取っていない番号 */
  missing(): number[] {
    const out: number[] = [];
    for (let i = 0; i < this.state.length; i++) if (this.state[i] === 0) out.push(i);
    return out;
  }

  get isComplete(): boolean {
    return this.state.every(s => s !== 0);
  }

  get isFullyDrained(): boolean {
    return this.state.every(s => s === 2);
  }
}

/**
 * チャンク ID の置き場所 (複製ごとの位置)。j = 0..replicas-1。同じ位置は 1 つにまとめる。
 * ★ 呼ぶ前に sodiumReady を await しておくこと (encodeFile / decryptManifest を通っていれば済んでいる)。
 * ★ 位置は ID からだけ決まるので、置く側と取る側が同じ結果になる。
 */
export function chunkPositions(chunkId: Uint8Array, replicas: number): bigint[] {
  if (!Number.isInteger(replicas) || replicas < 1 || replicas > 255) throw new RangeError('bad replicas');
  if (chunkId.length !== CHUNK_ID_BYTES) throw new RangeError('bad chunk id');
  const seen = new Set<bigint>();
  const out: bigint[] = [];
  for (let j = 0; j < replicas; j++) {
    const p = positionOf('oz/v5/chunk', chunkId, Uint8Array.of(j));
    if (!seen.has(p)) {
      seen.add(p);
      out.push(p);
    }
  }
  return out;
}

export { chunkCountFor };

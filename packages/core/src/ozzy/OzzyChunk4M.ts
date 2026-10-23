/**
 * OzzyChunk4M — 均一 4 MiB 暗号化チャンクの生成・パリティ符号化・復元エンジン。
 *
 * 設計仕様 (docs/design/03_storage_format.md §3.1 - §3.2):
 *   - すべてのチャンクは厳密に 4 MiB (4,194,304 bytes = 0x400000 bytes) 均一サイズ。
 *   - 構造: [ tag (16 B) | body (4,194,288 B) ]
 *   - データチャンク (shareIndex 0..15):
 *       body = XChaCha20-Poly1305(key = K_enc, nonce = stripeIndex || shareIndex, aad = tag, paddedPlaintext)
 *       paddedPlaintext 長 = 4,194,272 B (4 MiB - 32 B)
 *   - パリティチャンク (shareIndex 16..31):
 *       body = ReedSolomon_GF256(dataBodies[0..15])[shareIndex - 16]
 *   - ファイルの切れ目 (サイズ端数) はチャンク内部で暗号論的乱数パディングにより完全に消去される。
 */
import sodium, { sodiumReady } from '../crypto/sodium';
import { bytesEqual } from '../files/FileFormat';
import { OZZY_KEY_BYTES, OZZY_TAG_BYTES, computeChunkTag, type OzzyFileKeys } from './OzzyKdf';
import { OZZY_RS_K, OZZY_RS_N, encodeRsParity, reconstructRsData, type RsShareInput } from './ReedSolomon';

/** 本番の均一チャンクサイズ: 厳密に 4 MiB (4,194,304 bytes) */
export const OZZY_CHUNK_BYTES = 4 * 1024 * 1024; // 4,194,304
export const OZZY_MAC_BYTES = 16; // Poly1305 タグ長
export const OZZY_LEN_HEADER_BYTES = 4; // 各チャンク内部の有効平文長ヘッダ (u32le)

/** チャンクサイズ (既定 4 MiB) から内部パラメータを計算するヘルパ */
export function chunkLayoutFor(chunkBytes: number = OZZY_CHUNK_BYTES) {
  const bodyBytes = chunkBytes - OZZY_TAG_BYTES;
  const cipherPayloadBytes = bodyBytes - OZZY_MAC_BYTES;
  const maxPlainSliceBytes = cipherPayloadBytes - OZZY_LEN_HEADER_BYTES;
  const maxStripePlainBytes = maxPlainSliceBytes * OZZY_RS_K;
  return {
    chunkBytes,
    bodyBytes,
    cipherPayloadBytes,
    maxPlainSliceBytes,
    maxStripePlainBytes,
  };
}

export const DEFAULT_CHUNK_LAYOUT = chunkLayoutFor(OZZY_CHUNK_BYTES);

export interface OzzyChunk {
  readonly stripeIndex: number;
  readonly shareIndex: number; // 0..31
  readonly tag: Uint8Array; // 16 B
  /** 厳密に chunkBytes (4,194,304 B) の完全なチャンクバイナリ (tag 16B + body) */
  readonly rawChunk: Uint8Array;
}

function makeChunkNonce(stripeIndex: number, shareIndex: number): Uint8Array {
  const nonce = new Uint8Array(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES); // 24 B
  const dv = new DataView(nonce.buffer);
  dv.setUint32(0, stripeIndex >>> 0, true);
  dv.setUint32(4, shareIndex >>> 0, true);
  return nonce;
}

/**
 * 平文スライス (0 .. maxPlainSliceBytes) を先頭 4B 長さヘッダ + 平文 + パディングで
 * 厳密に cipherPayloadBytes に揃える (直後に XChaCha20-Poly1305 で暗号化されるため、
 * 出力される 4 MiB チャンクはパディング領域を含め全域が真性乱数と識別不能になる)。
 */
function padPlainSlice(plainSlice: Uint8Array, cipherPayloadBytes: number): Uint8Array {
  const maxPlain = cipherPayloadBytes - OZZY_LEN_HEADER_BYTES;
  if (plainSlice.length > maxPlain) {
    throw new RangeError(`Plain slice length ${plainSlice.length} exceeds max ${maxPlain}`);
  }
  const padded = new Uint8Array(cipherPayloadBytes);
  new DataView(padded.buffer).setUint32(0, plainSlice.length, true);
  padded.set(plainSlice, OZZY_LEN_HEADER_BYTES);
  return padded;
}

function unpadPlainSlice(padded: Uint8Array, cipherPayloadBytes: number): Uint8Array | null {
  if (padded.length !== cipherPayloadBytes) return null;
  const maxPlain = cipherPayloadBytes - OZZY_LEN_HEADER_BYTES;
  const actualLen = new DataView(padded.buffer, padded.byteOffset, 4).getUint32(0, true);
  if (actualLen > maxPlain) return null;
  return padded.subarray(OZZY_LEN_HEADER_BYTES, OZZY_LEN_HEADER_BYTES + actualLen);
}

/**
 * 1 ストライプ分の平文 (最大約 64 MiB) を 16 個の均一 4 MiB 暗号化データチャンク (shareIndex 0..15) に変換する。
 */
export async function encryptStripeDataChunks(
  stripePlaintext: Uint8Array,
  stripeIndex: number,
  keys: OzzyFileKeys,
  chunkBytes: number = OZZY_CHUNK_BYTES,
): Promise<OzzyChunk[]> {
  await sodiumReady;
  const layout = chunkLayoutFor(chunkBytes);
  if (stripePlaintext.length > layout.maxStripePlainBytes) {
    throw new RangeError(
      `Stripe plaintext length ${stripePlaintext.length} exceeds max ${layout.maxStripePlainBytes}`,
    );
  }

  const dataChunks: OzzyChunk[] = [];
  for (let shareIndex = 0; shareIndex < OZZY_RS_K; shareIndex++) {
    const start = shareIndex * layout.maxPlainSliceBytes;
    const end = Math.min(start + layout.maxPlainSliceBytes, stripePlaintext.length);
    const slice = start < stripePlaintext.length ? stripePlaintext.subarray(start, end) : new Uint8Array(0);

    const paddedPlain = padPlainSlice(slice, layout.cipherPayloadBytes);
    const tag = computeChunkTag(keys.kTag, stripeIndex, shareIndex);
    const nonce = makeChunkNonce(stripeIndex, shareIndex);
    const body = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(paddedPlain, tag, null, nonce, keys.kEnc);

    if (body.length !== layout.bodyBytes) {
      throw new Error(`Unexpected encrypted body length: ${body.length}`);
    }

    const rawChunk = new Uint8Array(layout.chunkBytes);
    rawChunk.set(tag, 0);
    rawChunk.set(body, OZZY_TAG_BYTES);

    dataChunks.push({
      stripeIndex,
      shareIndex,
      tag,
      rawChunk,
    });
  }

  return dataChunks;
}

/**
 * 16 個の暗号化済みデータチャンク (shareIndex 0..15) から、16 個のパリティチャンク (shareIndex 16..31) を生成する。
 * ★ 復号鍵 K_enc を必要としないため、Uploader 本人だけでなく P2P 上の `parity-helper` ノードでも実行できる。
 */
export function generateStripeParityChunks(
  dataChunks: readonly OzzyChunk[],
  stripeIndex: number,
  kTag: Uint8Array,
): OzzyChunk[] {
  if (dataChunks.length !== OZZY_RS_K) {
    throw new RangeError(`Expected ${OZZY_RS_K} data chunks, got ${dataChunks.length}`);
  }
  const chunkBytes = dataChunks[0].rawChunk.length;
  const dataBodies = dataChunks.map(c => c.rawChunk.subarray(OZZY_TAG_BYTES));
  const parityBodies = encodeRsParity(dataBodies);

  const parityChunks: OzzyChunk[] = [];
  for (let p = 0; p < parityBodies.length; p++) {
    const shareIndex = OZZY_RS_K + p;
    const tag = computeChunkTag(kTag, stripeIndex, shareIndex);
    const rawChunk = new Uint8Array(chunkBytes);
    rawChunk.set(tag, 0);
    rawChunk.set(parityBodies[p], OZZY_TAG_BYTES);
    parityChunks.push({
      stripeIndex,
      shareIndex,
      tag,
      rawChunk,
    });
  }
  return parityChunks;
}

/**
 * 1 ストライプ分の平文から、データ 16 個 + パリティ 16 個 = 計 32 個の 4 MiB チャンクを一括生成する。
 */
export async function encodeFullStripe(
  stripePlaintext: Uint8Array,
  stripeIndex: number,
  keys: OzzyFileKeys,
  chunkBytes: number = OZZY_CHUNK_BYTES,
): Promise<OzzyChunk[]> {
  const dataChunks = await encryptStripeDataChunks(stripePlaintext, stripeIndex, keys, chunkBytes);
  const parityChunks = generateStripeParityChunks(dataChunks, stripeIndex, keys.kTag);
  return [...dataChunks, ...parityChunks];
}

/** シェア (4 MiB チャンク) ごとのハッシュの長さ。Manifest にストライプごと 32 個 (512 B) 載せる */
export const OZZY_SHARE_DIGEST_BYTES = 16;

let shareDigestKey: Uint8Array | null = null;

/**
 * シェア 1 つ (tag 込みのチャンク全体) のハッシュ。BLAKE2b-128 (key = 固定のドメイン鍵)。
 * ★ パリティのシェアは K_enc で認証されていないので、取得役やロッカーが tag だけ正しいゴミを返すと
 *   RS 復元が壊れる (どのシェアが悪いか分からない)。Manifest にハッシュを載せておき、使う前に 1 つずつ確かめる。
 */
export function computeShareDigest(rawChunk: Uint8Array): Uint8Array {
  shareDigestKey ??= sodium.crypto_generichash(32, new TextEncoder().encode('ozzy-share-digest-v3'), null);
  return sodium.crypto_generichash(OZZY_SHARE_DIGEST_BYTES, rawChunk, shareDigestKey);
}

/** 32 個のシェアのハッシュを shareIndex 順に連結する (Manifest の stripe 記述子に入れる 512 B) */
export function computeStripeShareDigests(chunks: readonly OzzyChunk[]): Uint8Array {
  const out = new Uint8Array(OZZY_RS_N * OZZY_SHARE_DIGEST_BYTES);
  for (const c of chunks) {
    if (c.shareIndex < 0 || c.shareIndex >= OZZY_RS_N) throw new RangeError('bad shareIndex');
    out.set(computeShareDigest(c.rawChunk), c.shareIndex * OZZY_SHARE_DIGEST_BYTES);
  }
  return out;
}

/** shareDigests (512 B) と照らして、このシェアが正しいか */
export function shareMatchesDigest(shareDigests: Uint8Array, shareIndex: number, rawChunk: Uint8Array): boolean {
  if (shareDigests.length !== OZZY_RS_N * OZZY_SHARE_DIGEST_BYTES || shareIndex < 0 || shareIndex >= OZZY_RS_N) return false;
  const want = shareDigests.subarray(shareIndex * OZZY_SHARE_DIGEST_BYTES, (shareIndex + 1) * OZZY_SHARE_DIGEST_BYTES);
  return bytesEqual(computeShareDigest(rawChunk), want);
}

/** データシェア 1 つ (shareIndex < 16) を K_enc で認証復号し、パディングを外した平文を返す。改ざんなら null */
export function openDataShareBody(
  body: Uint8Array, stripeIndex: number, shareIndex: number, keys: OzzyFileKeys, chunkBytes: number = OZZY_CHUNK_BYTES,
): Uint8Array | null {
  const layout = chunkLayoutFor(chunkBytes);
  try {
    const tag = computeChunkTag(keys.kTag, stripeIndex, shareIndex);
    const nonce = makeChunkNonce(stripeIndex, shareIndex);
    const padded = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, body, tag, nonce, keys.kEnc);
    return unpadPlainSlice(padded, layout.cipherPayloadBytes);
  } catch {
    return null;
  }
}

export interface StripeDecodeOptions {
  /** Manifest に記録されたシェアごとのハッシュ (32 × 16 B)。あれば一致しないシェアは最初に捨てる */
  readonly shareDigests?: Uint8Array;
  /**
   * ハッシュが無いとき (Manifest 自身のストライプ) に、パリティの組み合わせを試す回数の上限 (既定 16)。
   * データシェアは K_enc で 1 つずつ確かめられるが、パリティは復元結果を復号してみるまで良し悪しが分からない。
   */
  readonly maxParityTrials?: number;
  readonly random?: () => number;
}

/**
 * 任意の 16 個以上のチャンク (0..31 の順不同部分集合) から元のストライプ平文を検証・復元する。
 *
 *   1. 大きさ・先頭 16 B の tag・(あれば) Manifest のハッシュが合わないシェアを捨てる。
 *   2. データシェア (0..15) は K_enc で 1 つずつ認証復号する (改ざんされたものは捨てる)。
 *   3. 欠けたデータシェアをパリティから RS 復元し、復元したものも認証復号で確かめる。
 *      ★ 通らなければ (悪いパリティが混ざっている)、別のパリティの組み合わせで試し直す。旧実装は先頭 16 個に
 *        固定していたので、悪いシェアが 1 つ混ざるだけで、良いシェアが余っていても復元できなかった。
 * 有効なシェアが足りない・どの組み合わせも通らなければ null。
 */
export async function decodeStripeFromChunks(
  chunks: readonly { shareIndex: number; rawChunk: Uint8Array }[],
  stripeIndex: number,
  keys: OzzyFileKeys,
  chunkBytes: number = OZZY_CHUNK_BYTES,
  options: StripeDecodeOptions = {},
): Promise<Uint8Array | null> {
  await sodiumReady;
  const layout = chunkLayoutFor(chunkBytes);
  const random = options.random ?? Math.random;

  const plain = new Map<number, Uint8Array>();
  const dataBodies = new Map<number, Uint8Array>();
  const parity: RsShareInput[] = [];
  const seen = new Set<number>();
  for (const item of chunks) {
    if (!Number.isInteger(item.shareIndex) || item.shareIndex < 0 || item.shareIndex >= OZZY_RS_N) continue;
    if (seen.has(item.shareIndex)) continue;
    if (item.rawChunk.length !== layout.chunkBytes) continue;
    const expectedTag = computeChunkTag(keys.kTag, stripeIndex, item.shareIndex);
    if (!bytesEqual(item.rawChunk.subarray(0, OZZY_TAG_BYTES), expectedTag)) continue;
    if (options.shareDigests && !shareMatchesDigest(options.shareDigests, item.shareIndex, item.rawChunk)) continue;
    const body = item.rawChunk.subarray(OZZY_TAG_BYTES);
    if (item.shareIndex < OZZY_RS_K) {
      const opened = openDataShareBody(body, stripeIndex, item.shareIndex, keys, chunkBytes);
      if (!opened) continue; // 改ざんされたデータシェアは捨て、パリティでの復元に回す
      plain.set(item.shareIndex, opened);
      dataBodies.set(item.shareIndex, body);
    } else {
      parity.push({ shareIndex: item.shareIndex, body });
    }
    seen.add(item.shareIndex);
  }

  const missing: number[] = [];
  for (let d = 0; d < OZZY_RS_K; d++) if (!plain.has(d)) missing.push(d);
  if (missing.length > parity.length) return null;

  if (missing.length > 0) {
    parity.sort((a, b) => a.shareIndex - b.shareIndex);
    const maxTrials = options.shareDigests ? 2 : Math.max(1, options.maxParityTrials ?? 16);
    const tried = new Set<string>();
    let recovered = false;
    for (let trial = 0; trial < maxTrials && !recovered; trial++) {
      // 1 回目は番号の小さい順、以降は乱数で選び直す
      let pick: RsShareInput[];
      if (trial === 0) {
        pick = parity.slice(0, missing.length);
      } else {
        const pool = [...parity];
        for (let i = pool.length - 1; i > 0; i--) {
          const j = Math.floor(random() * (i + 1));
          [pool[i], pool[j]] = [pool[j], pool[i]];
        }
        pick = pool.slice(0, missing.length);
      }
      const key = pick.map(p => p.shareIndex).sort((a, b) => a - b).join(',');
      if (tried.has(key)) {
        if (tried.size >= binomialCap(parity.length, missing.length)) break;
        continue;
      }
      tried.add(key);
      try {
        const shares: RsShareInput[] = [
          ...Array.from(dataBodies, ([shareIndex, body]) => ({ shareIndex, body })),
          ...pick,
        ];
        const rebuilt = reconstructRsData(shares);
        const opened = new Map<number, Uint8Array>();
        let ok = true;
        for (const d of missing) {
          const o = openDataShareBody(rebuilt[d], stripeIndex, d, keys, chunkBytes);
          if (!o) {
            ok = false;
            break;
          }
          opened.set(d, o);
        }
        if (ok) {
          for (const [d, o] of opened) plain.set(d, o);
          recovered = true;
        }
      } catch {
        // 行列が特異など。次の組み合わせへ
      }
    }
    if (!recovered) return null;
  }

  let totalLen = 0;
  for (let d = 0; d < OZZY_RS_K; d++) totalLen += plain.get(d)!.length;
  const out = new Uint8Array(totalLen);
  let offset = 0;
  for (let d = 0; d < OZZY_RS_K; d++) {
    const s = plain.get(d)!;
    out.set(s, offset);
    offset += s.length;
  }
  return out;
}

/**
 * データシェアの先頭から順に開け、平文が途中で終わったシェアまで揃っていれば、RS 復元なしでストライプの平文を返す。
 *
 * ★ データシェアは平文を先頭から詰めていくので、あるシェアの平文が最大より短ければ、それより後のデータシェアは空。
 *   小さいファイル (と Manifest) は 64 MiB のストライプの先頭の数シェアにしか中身が無い。旧版は毎回 16 シェア
 *   (4 MiB × 16 = 64 MiB) を取っていた。ここで先に終わりが分かれば、残りを取りに行かなくてよい。
 * opened は開けた結果の置き場 (同じシェアを何度も復号しない)。揃っていなければ null。
 */
export function decodeSystematicPrefix(
  chunks: readonly { shareIndex: number; rawChunk: Uint8Array }[],
  stripeIndex: number,
  keys: OzzyFileKeys,
  chunkBytes: number = OZZY_CHUNK_BYTES,
  opened: Map<number, Uint8Array | null> = new Map(),
  shareDigests?: Uint8Array,
): Uint8Array | null {
  const layout = chunkLayoutFor(chunkBytes);
  const byIndex = new Map<number, Uint8Array>();
  for (const c of chunks) if (c.shareIndex < OZZY_RS_K && !byIndex.has(c.shareIndex)) byIndex.set(c.shareIndex, c.rawChunk);
  const slices: Uint8Array[] = [];
  for (let d = 0; d < OZZY_RS_K; d++) {
    let slice = opened.get(d);
    if (slice === undefined) {
      const raw = byIndex.get(d);
      if (!raw) return null;
      const tagOk = raw.length === layout.chunkBytes && bytesEqual(raw.subarray(0, OZZY_TAG_BYTES), computeChunkTag(keys.kTag, stripeIndex, d));
      const digestOk = !shareDigests || shareMatchesDigest(shareDigests, d, raw);
      slice = tagOk && digestOk ? openDataShareBody(raw.subarray(OZZY_TAG_BYTES), stripeIndex, d, keys, chunkBytes) : null;
      opened.set(d, slice);
    }
    if (!slice) return null;
    slices.push(slice);
    if (slice.length < layout.maxPlainSliceBytes) break; // ここで平文が終わっている: 後ろのデータシェアは空
  }
  let total = 0;
  for (const x of slices) total += x.length;
  const out = new Uint8Array(total);
  let o = 0;
  for (const x of slices) {
    out.set(x, o);
    o += x.length;
  }
  return out;
}

/** n 個から k 個を選ぶ組み合わせの数 (上限付き。試す回数の打ち切りに使う) */
function binomialCap(n: number, k: number): number {
  let r = 1;
  for (let i = 1; i <= k; i++) {
    r = (r * (n - k + i)) / i;
    if (r > 1e6) return 1e6;
  }
  return Math.round(r);
}

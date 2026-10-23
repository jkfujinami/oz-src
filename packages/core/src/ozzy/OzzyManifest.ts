/**
 * OzzyManifest — 大規模ファイル用 Manifest v2 ("OZM2") とリンク表記 `[[ozzy:v2:...]]`。
 *
 * 設計仕様 (docs/design/03_storage_format.md §3.5 - §3.6):
 *   - Manifest 自体も 1 つのストライプ (stripeIndex = 0xFFFFFFFF) として 4 MiB 均一チャンクに暗号化・RS 符号化され、
 *     Tier 1 バケットの先頭 10% (スロット 0..229) の Manifest 専用保護プールへ配置される。
 *   - Manifest の平文は 1 ストライプ (約 64 MiB) まで。ストライプ 1 つの記述は 563 B なので約 11 万ストライプ (約 7 TiB)。
 *   - リンク表記: `[[ozzy:v2:<base64url(S_manifest(32B) || totalFileSize(u48) || flags(u8))>]]`
 *     flags はチャンクの大きさ (bit0-3) と置き場所の種類 (bit4)。受け取った側が設定を合わせなくても取れるようにする。
 *
 * ★ v3: ストライプごとに 32 個のシェアのハッシュ (shareDigests, 512 B) を載せる。メッシュの取得役やロッカーが
 *   tag だけ正しいゴミ (特にパリティ) を返しても、使う前に 1 つずつ見分けて別の取得役から取り直せる。
 */
import sodium, { sodiumReady } from '../crypto/sodium';
import { ByteReader, ByteWriter } from '../common/ByteIO';
import { Encoding } from '../common/Encoding';
import { bytesEqual, sanitizeFileName, sanitizeMime } from '../files/FileFormat';
import { decodeFileLinkBody, formatFileLink } from '../files/FileLink';
import { OZZY_SEED_BYTES, deriveOzzyKeys } from './OzzyKdf';
import {
  OZZY_CHUNK_BYTES,
  OZZY_SHARE_DIGEST_BYTES,
  decodeStripeFromChunks,
  encodeFullStripe,
  type OzzyChunk,
} from './OzzyChunk4M';
import { OZZY_RS_N } from './ReedSolomon';

export const OZZY_MANIFEST_MAGIC = new Uint8Array([0x4f, 0x5a, 0x4d, 0x33]); // "OZM3"
export const OZZY_MANIFEST_VERSION = 3;
export const OZZY_MANIFEST_STRIPE_INDEX = 0xffffffff;

export const enum OzzyTierMode {
  Tier1Ring = 0x01,
  Tier2Slab = 0x02,
  Hybrid = 0x03,
}

export interface OzzyStripeDescriptor {
  readonly stripeSeed: Uint8Array; // 32 B
  readonly tierMode: OzzyTierMode;
  readonly leaseSetId: Uint8Array; // 16 B (Tier 1 のみの場合は 0 埋め)
  readonly slabStartChunkIdx: number; // u16
  /** 32 個のシェアのハッシュ (shareIndex 順、各 16 B = 512 B)。OzzyChunk4M.computeStripeShareDigests */
  readonly shareDigests: Uint8Array;
}

export interface OzzyManifestV2 {
  readonly version: number;
  readonly flags: number;
  readonly totalFileSize: number; // Safe integer up to 2^48 - 1 (~256 TiB)
  readonly createdAtDay: number; // u32 (UTC epoch days)
  readonly fileHash: Uint8Array; // 32 B BLAKE2b-256
  readonly fileName: string;
  readonly mimeType: string;
  readonly stripes: OzzyStripeDescriptor[];
}

export interface OzzyLinkV2 {
  readonly manifestSeed: Uint8Array; // 32 B
  readonly totalFileSize: number; // u48
  readonly flags: number; // u8
}

const LINK_RAW_BYTES = OZZY_SEED_BYTES + 6 + 1; // 39 bytes -> 52 chars in base64url
const STRIPE_DIGESTS_BYTES = OZZY_RS_N * OZZY_SHARE_DIGEST_BYTES; // 512

/**
 * リンクの flags (u8):
 *   bit0-3  チャンクの大きさ: 4 MiB >> n (n = 0..12。0 = 4 MiB、6 = 64 KiB)。受け取った側が設定を合わせなくても取れる
 *   bit4    Tier 1 (R2 Gatekeeper のリング) に置いた。0 なら Tier 2 (ロッカーの Slab)
 *   その他  0 (知らないビットが立っていれば拒否)
 */
export const OZZY_LINK_FLAG_TIER1 = 0x10;
const OZZY_LINK_CHUNK_SHIFT_MASK = 0x0f;
const OZZY_LINK_MAX_CHUNK_SHIFT = 12; // 1 KiB
const OZZY_LINK_KNOWN_FLAGS = OZZY_LINK_FLAG_TIER1 | OZZY_LINK_CHUNK_SHIFT_MASK;
/** 試験用の小さいチャンク (ブラウザでの即時検証) */
export const OZZY_DEMO_CHUNK_BYTES = 64 * 1024;

/** 上げたときのチャンクの大きさと置き場所から、リンクの flags を作る。大きさは 4 MiB を 2 の累乗で割った値に限る */
export function ozzyLinkFlagsFor(chunkBytes: number, tier1: boolean): number {
  let shift = 0;
  while (shift <= OZZY_LINK_MAX_CHUNK_SHIFT && OZZY_CHUNK_BYTES / 2 ** shift !== chunkBytes) shift++;
  if (shift > OZZY_LINK_MAX_CHUNK_SHIFT) throw new RangeError(`unsupported chunk size ${chunkBytes}`);
  return shift | (tier1 ? OZZY_LINK_FLAG_TIER1 : 0);
}

/** リンクの flags から、チャンクの大きさを読む */
export function ozzyChunkBytesOf(link: Pick<OzzyLinkV2, 'flags'>): number {
  return OZZY_CHUNK_BYTES / 2 ** (link.flags & OZZY_LINK_CHUNK_SHIFT_MASK);
}

/** リンクの flags から、Tier 1 (R2 Gatekeeper) に置いたものか */
export function ozzyIsTier1(link: Pick<OzzyLinkV2, 'flags'>): boolean {
  return (link.flags & OZZY_LINK_FLAG_TIER1) !== 0;
}

/** OzzyManifestV2 をバイナリにシリアライズする */
export function serializeOzzyManifest(m: OzzyManifestV2): Uint8Array {
  if (m.fileHash.length !== 32) throw new RangeError('fileHash must be 32 bytes');
  const safeName = new TextEncoder().encode(sanitizeFileName(m.fileName));
  const safeMime = new TextEncoder().encode(sanitizeMime(m.mimeType));

  const w = new ByteWriter();
  w.raw(OZZY_MANIFEST_MAGIC);
  w.u8(OZZY_MANIFEST_VERSION);
  w.u8(m.flags & 0xff);
  w.u48(m.totalFileSize);
  w.u16((m.createdAtDay >>> 16) & 0xffff).u16(m.createdAtDay & 0xffff);
  w.raw(m.fileHash);
  w.u8(safeName.length).raw(safeName);
  w.u8(safeMime.length).raw(safeMime);
  w.varint(m.stripes.length);

  for (const s of m.stripes) {
    if (s.stripeSeed.length !== OZZY_SEED_BYTES) throw new RangeError('stripeSeed must be 32 bytes');
    if (s.leaseSetId.length !== 16) throw new RangeError('leaseSetId must be 16 bytes');
    if (s.shareDigests.length !== STRIPE_DIGESTS_BYTES) throw new RangeError('shareDigests must be 512 bytes');
    w.raw(s.stripeSeed);
    w.u8(s.tierMode);
    w.raw(s.leaseSetId);
    w.u16(s.slabStartChunkIdx & 0xffff);
    w.raw(s.shareDigests);
  }
  return w.finish();
}

/** バイナリから OzzyManifestV2 を厳格にデシリアライズする (不正時は null) */
export function deserializeOzzyManifest(bytes: Uint8Array): OzzyManifestV2 | null {
  try {
    const r = new ByteReader(bytes);
    const magic = r.bytes(4);
    if (!bytesEqual(magic, OZZY_MANIFEST_MAGIC)) return null;
    const version = r.u8();
    if (version !== OZZY_MANIFEST_VERSION) return null;
    const flags = r.u8();
    const totalFileSize = r.u48();
    if (totalFileSize < 1) return null;
    const createdAtDay = ((r.u16() << 16) | r.u16()) >>> 0;
    const fileHash = r.bytes(32).slice();

    const dec = new TextDecoder('utf-8', { fatal: true });
    const nameLen = r.u8();
    if (nameLen < 1) return null;
    const fileName = dec.decode(r.bytes(nameLen));
    if (sanitizeFileName(fileName) !== fileName) return null;

    const mimeLen = r.u8();
    if (mimeLen < 1) return null;
    const mimeType = dec.decode(r.bytes(mimeLen));
    if (sanitizeMime(mimeType) !== mimeType) return null;

    const stripeCount = r.varint();
    if (stripeCount < 1 || stripeCount > 200000) return null;

    const stripes: OzzyStripeDescriptor[] = [];
    for (let i = 0; i < stripeCount; i++) {
      const stripeSeed = r.bytes(OZZY_SEED_BYTES).slice();
      const tierMode = r.u8() as OzzyTierMode;
      if (
        tierMode !== OzzyTierMode.Tier1Ring &&
        tierMode !== OzzyTierMode.Tier2Slab &&
        tierMode !== OzzyTierMode.Hybrid
      ) {
        return null;
      }
      const leaseSetId = r.bytes(16).slice();
      const slabStartChunkIdx = r.u16();
      const shareDigests = r.bytes(STRIPE_DIGESTS_BYTES).slice();
      stripes.push({ stripeSeed, tierMode, leaseSetId, slabStartChunkIdx, shareDigests });
    }
    r.end();
    return {
      version,
      flags,
      totalFileSize,
      createdAtDay,
      fileHash,
      fileName,
      mimeType,
      stripes,
    };
  } catch {
    return null;
  }
}

/**
 * OzzyManifestV2 を暗号化・RS(16, 32) 符号化して 32 個の均一 4 MiB チャンクに変換する。
 */
export async function encodeManifestToStripeChunks(
  manifest: OzzyManifestV2,
  manifestSeed: Uint8Array,
  chunkBytes: number = OZZY_CHUNK_BYTES,
): Promise<OzzyChunk[]> {
  await sodiumReady;
  const plain = serializeOzzyManifest(manifest);
  const keys = await deriveOzzyKeys(manifestSeed);
  return encodeFullStripe(plain, OZZY_MANIFEST_STRIPE_INDEX, keys, chunkBytes);
}

/**
 * 任意の 16 個以上の Manifest チャンクから OzzyManifestV2 を復元する。
 */
export async function decodeManifestFromStripeChunks(
  chunks: readonly { shareIndex: number; rawChunk: Uint8Array }[],
  manifestSeed: Uint8Array,
  chunkBytes: number = OZZY_CHUNK_BYTES,
): Promise<OzzyManifestV2 | null> {
  await sodiumReady;
  const keys = await deriveOzzyKeys(manifestSeed);
  const plain = await decodeStripeFromChunks(chunks, OZZY_MANIFEST_STRIPE_INDEX, keys, chunkBytes);
  if (!plain) return null;
  return deserializeOzzyManifest(plain);
}

/** リンク `[[ozzy:v2:<base64url>]]` をフォーマットする */
export function formatOzzyLink(link: OzzyLinkV2): string {
  if (link.manifestSeed.length !== OZZY_SEED_BYTES) throw new RangeError('Invalid manifestSeed');
  if (!Number.isSafeInteger(link.totalFileSize) || link.totalFileSize < 1) {
    throw new RangeError('Invalid totalFileSize');
  }
  const raw = new ByteWriter()
    .raw(link.manifestSeed)
    .u48(link.totalFileSize)
    .u8(link.flags & 0xff)
    .finish();
  return `[[ozzy:v2:${Encoding.toBase64(raw)}]]`;
}

/** リンク文字列 `[[ozzy:v2:...]]` または本体文字列をパースする */
export function parseOzzyLink(input: string): OzzyLinkV2 | null {
  const trimmed = input.trim();
  const match = /^\[\[ozzy:v2:([A-Za-z0-9_-]+)\]\]$/.exec(trimmed);
  const body = match ? match[1] : trimmed;
  if (!/^[A-Za-z0-9_-]+$/.test(body)) return null;
  try {
    const raw = Encoding.fromBase64(body);
    if (raw.length !== LINK_RAW_BYTES) return null;
    if (Encoding.toBase64(raw) !== body) return null;
    const r = new ByteReader(raw);
    const manifestSeed = r.bytes(OZZY_SEED_BYTES).slice();
    const totalFileSize = r.u48();
    const flags = r.u8();
    r.end();
    if (totalFileSize < 1) return null;
    if ((flags & ~OZZY_LINK_KNOWN_FLAGS) !== 0 || (flags & OZZY_LINK_CHUNK_SHIFT_MASK) > OZZY_LINK_MAX_CHUNK_SHIFT) return null;
    return { manifestSeed, totalFileSize, flags };
  } catch {
    return null;
  }
}

/** テキスト本文中に埋め込まれたすべての `[[ozzy:v2:...]]` リンクを抽出する */
export function extractOzzyLinksFromText(text: string): { link: OzzyLinkV2; start: number; end: number }[] {
  const out: { link: OzzyLinkV2; start: number; end: number }[] = [];
  const re = /\[\[ozzy:v2:([A-Za-z0-9_-]+)\]\]/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const link = parseOzzyLink(m[0]);
    if (link) {
      out.push({ link, start: m.index, end: m.index + m[0].length });
    }
  }
  return out;
}

// ───────────────────────── v4: 置き場所入りの Manifest を P2P に置く ─────────────────────────
//
// ★ 置き場所の表 (どのストライプのどのシェアが、どのロッカーの URL の何チャンク目か) を Manifest の中に入れ、Manifest は
//   WebLite の P2P のファイル保管 (保持者の端末に複製して置く。network/storage/ChunkStore) に置く。リンクはその
//   ファイルのリンク (`[[file:...]]` の本体 74 文字) を包んだもの: `[[ozzy:v3:<本体>]]`。
//   → 置き場所を引くための共通の場所 (旧: 共通 Worker のリース一覧) が要らない。リース一覧の公開・取得の通信も無い
//     (旧版は告発者と読み手が自分の IP で共通 Worker に識別子を送っていた)。
//   → Manifest をロッカーに置かない (旧版は Manifest のために 4 MiB × 32 のストライプを丸ごと上げていた)。
// ★ 置き場所は一度決めたら変わらない (Manifest は書き換えられない)。移し替えるなら上げ直してリンクを出し直す。
//
//   OZM4 ‖ ver u8 (4) ‖ chunkShift u8 (4 MiB >> n) ‖ totalFileSize u48 ‖ createdAtDay u32 ‖ fileHash 32 ‖ lp8(name) ‖ lp8(mime)
//   ‖ varint(stripes) ‖ { stripeSeed 32 ‖ shareDigests 512 ‖ u8 locs ‖ { lp8(lockerId) ‖ lp16(url) ‖ u8 slabChunks
//                         ‖ u8 maps ‖ { share u8 ‖ slot u8 } × maps } × locs } × stripes

export const OZZY_MANIFEST_V4_MAGIC = new Uint8Array([0x4f, 0x5a, 0x4d, 0x34]); // "OZM4"
export const OZZY_MANIFEST_V4_VERSION = 4;

export interface OzzySlabLocation {
  /** ロッカーの種類 (OverseasLockerId) */
  readonly lockerId: string;
  /** Slab の URL (誰でも読める公開ロッカーの URL。資格情報は入れない) */
  readonly url: string;
  /** Slab に入っているチャンクの数 */
  readonly slabChunks: number;
  /** Slab の中の [シェア番号 ↔ 何チャンク目] */
  readonly chunkMap: readonly { readonly shareIndex: number; readonly slotOffsetIndex: number }[];
}

export interface OzzyStripeV4 {
  readonly stripeSeed: Uint8Array;
  readonly shareDigests: Uint8Array;
  readonly locations: readonly OzzySlabLocation[];
}

export interface OzzyManifestV4 {
  readonly version: 4;
  /** チャンクの大きさ (4 MiB を 2 の累乗で割った値) */
  readonly chunkBytes: number;
  readonly totalFileSize: number;
  readonly createdAtDay: number;
  readonly fileHash: Uint8Array;
  readonly fileName: string;
  readonly mimeType: string;
  readonly stripes: readonly OzzyStripeV4[];
}

const LOCKER_ID_V4_RE = /^[a-z0-9][a-z0-9.-]{0,31}$/;

function chunkShiftOf(chunkBytes: number): number {
  let shift = 0;
  while (shift <= 12 && OZZY_CHUNK_BYTES / 2 ** shift !== chunkBytes) shift++;
  if (shift > 12) throw new RangeError(`unsupported chunk size ${chunkBytes}`);
  return shift;
}

export function serializeOzzyManifestV4(m: OzzyManifestV4): Uint8Array {
  if (m.fileHash.length !== 32) throw new RangeError('fileHash must be 32 bytes');
  const utf8 = new TextEncoder();
  const name = utf8.encode(sanitizeFileName(m.fileName));
  const mime = utf8.encode(sanitizeMime(m.mimeType));
  const w = new ByteWriter()
    .raw(OZZY_MANIFEST_V4_MAGIC)
    .u8(OZZY_MANIFEST_V4_VERSION)
    .u8(chunkShiftOf(m.chunkBytes))
    .u48(m.totalFileSize)
    .u16((m.createdAtDay >>> 16) & 0xffff).u16(m.createdAtDay & 0xffff)
    .raw(m.fileHash)
    .u8(name.length).raw(name)
    .u8(mime.length).raw(mime)
    .varint(m.stripes.length);
  for (const s of m.stripes) {
    if (s.stripeSeed.length !== OZZY_SEED_BYTES) throw new RangeError('stripeSeed must be 32 bytes');
    if (s.shareDigests.length !== STRIPE_DIGESTS_BYTES) throw new RangeError('shareDigests must be 512 bytes');
    if (s.locations.length > 255) throw new RangeError('too many locations');
    w.raw(s.stripeSeed).raw(s.shareDigests).u8(s.locations.length);
    for (const loc of s.locations) {
      const id = utf8.encode(loc.lockerId);
      const url = utf8.encode(loc.url);
      if (!LOCKER_ID_V4_RE.test(loc.lockerId) || url.length < 1 || url.length > 2048) throw new RangeError('bad location');
      if (loc.slabChunks < 1 || loc.slabChunks > 255 || loc.chunkMap.length > 255) throw new RangeError('bad slab');
      w.u8(id.length).raw(id).u16(url.length).raw(url).u8(loc.slabChunks).u8(loc.chunkMap.length);
      for (const c of loc.chunkMap) w.u8(c.shareIndex).u8(c.slotOffsetIndex);
    }
  }
  return w.finish();
}

/** 厳格に読む。置き場所の URL は公開の HTTPS だけ、シェア・位置は範囲内だけ。不正なら null */
export function deserializeOzzyManifestV4(bytes: Uint8Array): OzzyManifestV4 | null {
  try {
    const r = new ByteReader(bytes);
    if (!bytesEqual(r.bytes(4), OZZY_MANIFEST_V4_MAGIC)) return null;
    if (r.u8() !== OZZY_MANIFEST_V4_VERSION) return null;
    const shift = r.u8();
    if (shift > 12) return null;
    const chunkBytes = OZZY_CHUNK_BYTES / 2 ** shift;
    const totalFileSize = r.u48();
    if (totalFileSize < 1) return null;
    const createdAtDay = ((r.u16() << 16) | r.u16()) >>> 0;
    const fileHash = r.bytes(32).slice();
    const dec = new TextDecoder('utf-8', { fatal: true });
    const nameLen = r.u8();
    if (nameLen < 1) return null;
    const fileName = dec.decode(r.bytes(nameLen));
    if (sanitizeFileName(fileName) !== fileName) return null;
    const mimeLen = r.u8();
    if (mimeLen < 1) return null;
    const mimeType = dec.decode(r.bytes(mimeLen));
    if (sanitizeMime(mimeType) !== mimeType) return null;
    const stripeCount = r.varint();
    if (stripeCount < 1 || stripeCount > 200000) return null;
    const stripes: OzzyStripeV4[] = [];
    for (let i = 0; i < stripeCount; i++) {
      const stripeSeed = r.bytes(OZZY_SEED_BYTES).slice();
      const shareDigests = r.bytes(STRIPE_DIGESTS_BYTES).slice();
      const locCount = r.u8();
      const locations: OzzySlabLocation[] = [];
      for (let j = 0; j < locCount; j++) {
        const lockerId = dec.decode(r.bytes(r.u8()));
        const url = dec.decode(r.bytes(r.u16()));
        const slabChunks = r.u8();
        const maps = r.u8();
        const chunkMap: { shareIndex: number; slotOffsetIndex: number }[] = [];
        for (let k = 0; k < maps; k++) {
          const shareIndex = r.u8();
          const slotOffsetIndex = r.u8();
          if (shareIndex >= OZZY_RS_N || slotOffsetIndex >= slabChunks) return null;
          chunkMap.push({ shareIndex, slotOffsetIndex });
        }
        if (!LOCKER_ID_V4_RE.test(lockerId) || slabChunks < 1 || !isPublicHttpsUrl(url)) return null;
        locations.push({ lockerId, url, slabChunks, chunkMap });
      }
      stripes.push({ stripeSeed, shareDigests, locations });
    }
    r.end();
    return { version: 4, chunkBytes, totalFileSize, createdAtDay, fileHash, fileName, mimeType, stripes };
  } catch {
    return null;
  }
}

/** 置き場所の URL として受け付けるもの (HTTPS・資格情報なし・ローカル/プライベートでない) */
function isPublicHttpsUrl(raw: string): boolean {
  try {
    const u = new URL(raw);
    if (u.protocol !== 'https:' || u.username || u.password) return false;
    const h = u.hostname.toLowerCase();
    if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || !h.includes('.')) return false;
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(h) || h.startsWith('[')) return false; // IP 直書きは拒否
    return raw.length <= 2048;
  } catch {
    return false;
  }
}

/**
 * Manifest の置き場所 (P2P)。アプリでは WebLite の P2P のファイル保管 (OzNode.ozzyManifestStore)。
 * ★ put が返すのは WebLite のファイルリンクの本体 (74 文字)。鍵を含むので、リンクを持つ人だけが Manifest を開ける。
 */
export interface OzzyManifestStore {
  put(bytes: Uint8Array, signal?: AbortSignal): Promise<string>;
  get(linkBody: string, signal?: AbortSignal): Promise<Uint8Array | null>;
}

/** メモリだけの Manifest の置き場所 (テスト・試験モード用)。本体は形の正しい WebLite のファイルリンク */
export function memoryManifestStore(): OzzyManifestStore & { readonly size: number } {
  const m = new Map<string, Uint8Array>();
  return {
    get size() {
      return m.size;
    },
    async put(bytes) {
      await sodiumReady;
      const token = formatFileLink({ manifestId: sodium.randombytes_buf(16), key: sodium.randombytes_buf(32), size: Math.max(1, bytes.length) });
      const body = token.slice('[[file:'.length, -2);
      m.set(body, bytes.slice());
      return body;
    },
    async get(body) {
      return m.get(body)?.slice() ?? null;
    },
  };
}

const OZZY_V3_RE = /\[\[ozzy:v3:([A-Za-z0-9_-]{74})\]\]/g;

/** P2P に置いた Manifest のリンク `[[ozzy:v3:<WebLite のファイルリンクの本体>]]` */
export function formatOzzyLinkV3(fileLinkBody: string): string {
  if (!decodeFileLinkBody(fileLinkBody)) throw new RangeError('bad file link body');
  return `[[ozzy:v3:${fileLinkBody}]]`;
}

/** `[[ozzy:v3:...]]` (または本体だけ) を読む。不正なら null */
export function parseOzzyLinkV3(input: string): string | null {
  const t = input.trim();
  const m = /^\[\[ozzy:v3:([A-Za-z0-9_-]+)\]\]$/.exec(t);
  const body = m ? m[1] : t;
  return decodeFileLinkBody(body) ? body : null;
}

/** 本文に埋め込まれた `[[ozzy:v3:...]]` を全部取り出す */
export function extractOzzyV3LinksFromText(text: string): { body: string; start: number; end: number }[] {
  const out: { body: string; start: number; end: number }[] = [];
  OZZY_V3_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = OZZY_V3_RE.exec(text)) !== null) {
    if (decodeFileLinkBody(m[1])) out.push({ body: m[1], start: m.index, end: m.index + m[0].length });
  }
  return out;
}

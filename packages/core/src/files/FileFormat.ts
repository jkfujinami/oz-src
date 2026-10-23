/**
 * FileFormat — 大容量ファイルのチャンク・Manifest の形式 (docs/design/file-sharing.md §2)。
 *
 * ★ 収束暗号 (中身のハッシュから鍵を作る方式) は使わない。使うと同じファイルは必ず同じ暗号文・
 *   同じチャンク ID になり、警察が「既知のファイル」のチャンク ID を手元で計算して、
 *   保持者に「これを持っているか」を確かめられる (Winny の摘発と同じ穴)。
 *   鍵 K_f はファイルごとの乱数なので、同じファイルでも上げるたびに全チャンク ID が変わる。
 * ★ K_f がファイルごとに一意なので、nonce は「チャンク番号」だけで足りる (同じ鍵・同じ nonce が
 *   2 回使われることがない)。AAD にも番号を入れ、暗号文を別の番号へ差し替えても通らないようにする。
 *
 * チャンク暗号文 = XChaCha20-Poly1305(平文, AAD = "oz/v5/chunk" ‖ u32be(i), nonce = u32be(i) ‖ 0×20, K_f)
 * チャンク ID   = SHA-256(暗号文) の先頭 16 バイト
 *
 * Manifest (平文):
 *   version u8 (=1) ‖ size u48 ‖ chunkSizeLog2 u8 (=18) ‖ mimeLen u8 ‖ mime ‖ nameLen u8 ‖ name (UTF-8)
 *   ‖ chunkCount u32 ‖ chunkId 16B × chunkCount
 * Manifest 暗号文 = 同じ AEAD、index = 0xFFFFFFFF、AAD = "oz/v5/manifest" ‖ u32be(0xFFFFFFFF)
 * Manifest ID    = SHA-256(Manifest 暗号文) の先頭 16 バイト
 */
import sodium, { sodiumReady } from '../crypto/sodium';
import { ByteReader, ByteWriter } from '../common/ByteIO';

export const CHUNK_SIZE = 256 * 1024;
export const CHUNK_SIZE_LOG2 = 18;
export const MAX_FILE_BYTES = 2 * 1024 ** 3;
export const MAX_CHUNKS = Math.ceil(MAX_FILE_BYTES / CHUNK_SIZE); // 8192
export const CHUNK_ID_BYTES = 16;
export const KEY_BYTES = 32;
export const TAG_BYTES = 16;
export const MANIFEST_VERSION = 1;
export const MANIFEST_INDEX = 0xffffffff;
export const MAX_MIME_BYTES = 100;
export const MAX_NAME_BYTES = 255;
export const DEFAULT_MIME = 'application/octet-stream';
export const DEFAULT_NAME = 'file';

const CHUNK_AAD_PREFIX = new TextEncoder().encode('oz/v5/chunk');
const MANIFEST_AAD_PREFIX = new TextEncoder().encode('oz/v5/manifest');

export interface FileManifest {
  version: number;
  size: number;
  chunkSizeLog2: number;
  mime: string;
  name: string;
  chunkIds: Uint8Array[];
}

export function chunkCountFor(size: number): number {
  return Math.ceil(size / CHUNK_SIZE);
}

/** index 番目のチャンクの平文の長さ (最後だけ短い) */
export function chunkPlainLength(size: number, index: number): number {
  const n = chunkCountFor(size);
  if (index < 0 || index >= n) return -1;
  return index === n - 1 ? size - (n - 1) * CHUNK_SIZE : CHUNK_SIZE;
}

function u32be(n: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, false);
  return out;
}

function aad(prefix: Uint8Array, index: number): Uint8Array {
  const out = new Uint8Array(prefix.length + 4);
  out.set(prefix, 0);
  out.set(u32be(index), prefix.length);
  return out;
}

/** ★ nonce = u32be(index) ‖ 0 × 20。K_f が一意なので番号だけで衝突しない */
function nonce(index: number): Uint8Array {
  const out = new Uint8Array(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  out.set(u32be(index), 0);
  return out;
}

export function newFileKey(): Uint8Array {
  return sodium.randombytes_buf(KEY_BYTES);
}

export function idOf(ciphertext: Uint8Array): Uint8Array {
  return sodium.crypto_hash_sha256(ciphertext).slice(0, CHUNK_ID_BYTES);
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

export async function encryptChunk(plaintext: Uint8Array, index: number, key: Uint8Array): Promise<{ id: Uint8Array; ciphertext: Uint8Array }> {
  await sodiumReady;
  if (!Number.isInteger(index) || index < 0 || index >= MAX_CHUNKS) throw new RangeError('chunk index out of range');
  if (plaintext.length < 1 || plaintext.length > CHUNK_SIZE) throw new RangeError('chunk length out of range');
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad(CHUNK_AAD_PREFIX, index), null, nonce(index), key);
  return { id: idOf(ciphertext), ciphertext };
}

/** 復号に失敗したら null (例外は出さない) */
export async function decryptChunk(ciphertext: Uint8Array, index: number, key: Uint8Array): Promise<Uint8Array | null> {
  await sodiumReady;
  if (!Number.isInteger(index) || index < 0 || index >= MAX_CHUNKS) return null;
  if (key.length !== KEY_BYTES) return null;
  if (ciphertext.length <= TAG_BYTES || ciphertext.length > CHUNK_SIZE + TAG_BYTES) return null;
  try {
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, aad(CHUNK_AAD_PREFIX, index), nonce(index), key);
  } catch {
    return null;
  }
}

// --- 名前・MIME ---

/**
 * ファイル名の無害化。
 * ★ 保存時にパスとして解釈されると、任意の場所へ書かれる (../../x)。区切り文字・制御文字・
 *   双方向制御文字 (拡張子の偽装: "gpj.exe" を "exe.jpg" に見せる) を取り除く。
 *   結果は 255 バイト以内 (コードポイントの途中で切らない)。冪等。
 */
export function sanitizeFileName(raw: string): string {
  // eslint-disable-next-line no-control-regex
  let s = raw.normalize('NFC').replace(/[\\/:*?"<>|\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩﻿�]/g, '');
  s = s.trim();
  const enc = new TextEncoder();
  if (enc.encode(s).length > MAX_NAME_BYTES) {
    let out = '';
    let bytes = 0;
    for (const ch of s) {
      const n = enc.encode(ch).length;
      if (bytes + n > MAX_NAME_BYTES) break;
      out += ch;
      bytes += n;
    }
    s = out.trim();
  }
  // 先頭のドットだけ・"." ".." は空として扱う
  if (/^\.*$/.test(s)) return DEFAULT_NAME;
  return s;
}

export function sanitizeMime(raw: string): string {
  const s = raw.trim().toLowerCase();
  return /^[\x21-\x7e]{1,100}$/.test(s) ? s : DEFAULT_MIME;
}

// --- Manifest ---

export function encodeManifest(m: Omit<FileManifest, 'version' | 'chunkSizeLog2'> & Partial<Pick<FileManifest, 'version' | 'chunkSizeLog2'>>): Uint8Array {
  const version = m.version ?? MANIFEST_VERSION;
  const log2 = m.chunkSizeLog2 ?? CHUNK_SIZE_LOG2;
  if (version !== MANIFEST_VERSION || log2 !== CHUNK_SIZE_LOG2) throw new RangeError('unsupported manifest parameters');
  if (!Number.isSafeInteger(m.size) || m.size < 1 || m.size > MAX_FILE_BYTES) throw new RangeError('file size out of range');
  if (m.chunkIds.length !== chunkCountFor(m.size)) throw new RangeError('chunk count mismatch');
  const mime = new TextEncoder().encode(sanitizeMime(m.mime));
  const name = new TextEncoder().encode(sanitizeFileName(m.name));
  const w = new ByteWriter().u8(version).u48(m.size).u8(log2).u8(mime.length).raw(mime).u8(name.length).raw(name);
  w.raw(u32be(m.chunkIds.length));
  for (const id of m.chunkIds) {
    if (id.length !== CHUNK_ID_BYTES) throw new RangeError('bad chunk id');
    w.raw(id);
  }
  return w.finish();
}

/** 厳格な復号。不正なら null (例外は出さない) */
export function decodeManifest(b: Uint8Array): FileManifest | null {
  try {
    const r = new ByteReader(b);
    const version = r.u8();
    if (version !== MANIFEST_VERSION) return null;
    const size = r.u48();
    if (size < 1 || size > MAX_FILE_BYTES) return null;
    const chunkSizeLog2 = r.u8();
    if (chunkSizeLog2 !== CHUNK_SIZE_LOG2) return null;
    const dec = new TextDecoder('utf-8', { fatal: true });
    const mimeLen = r.u8();
    if (mimeLen < 1 || mimeLen > MAX_MIME_BYTES) return null;
    const mime = dec.decode(r.bytes(mimeLen));
    if (sanitizeMime(mime) !== mime) return null;
    const nameLen = r.u8();
    if (nameLen < 1 || nameLen > MAX_NAME_BYTES) return null;
    const name = dec.decode(r.bytes(nameLen));
    // ★ 無害化済みの名前だけを受け付ける (送り手が無害化を飛ばしても受け手で弾く)
    if (sanitizeFileName(name) !== name) return null;
    const count = new DataView(r.bytes(4).slice().buffer).getUint32(0, false);
    if (count !== chunkCountFor(size) || count > MAX_CHUNKS) return null;
    const chunkIds: Uint8Array[] = [];
    for (let i = 0; i < count; i++) chunkIds.push(r.bytes(CHUNK_ID_BYTES).slice());
    r.end();
    return { version, size, chunkSizeLog2, mime, name, chunkIds };
  } catch {
    return null;
  }
}

/** Manifest を暗号化して置ける形にする。★ 1 チャンクに収まらなければ拒否 */
export async function encryptManifest(m: Parameters<typeof encodeManifest>[0], key: Uint8Array): Promise<{ id: Uint8Array; ciphertext: Uint8Array }> {
  await sodiumReady;
  const plain = encodeManifest(m);
  if (plain.length > CHUNK_SIZE) throw new RangeError('manifest exceeds one chunk');
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plain, aad(MANIFEST_AAD_PREFIX, MANIFEST_INDEX), null, nonce(MANIFEST_INDEX), key);
  return { id: idOf(ciphertext), ciphertext };
}

export async function decryptManifestRaw(ciphertext: Uint8Array, key: Uint8Array): Promise<FileManifest | null> {
  await sodiumReady;
  if (key.length !== KEY_BYTES) return null;
  if (ciphertext.length <= TAG_BYTES || ciphertext.length > CHUNK_SIZE + TAG_BYTES) return null;
  try {
    const plain = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, aad(MANIFEST_AAD_PREFIX, MANIFEST_INDEX), nonce(MANIFEST_INDEX), key);
    return decodeManifest(plain);
  } catch {
    return null;
  }
}

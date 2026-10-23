/**
 * FileLink — 投稿本文に埋め込む添付トークン。
 *
 *   [[file:<base64url(version u8 (=1) ‖ manifestId 16B ‖ K_f 32B ‖ size u48)>]]   (55 バイト → 74 文字、パディングなし)
 *
 * ★ 鍵 K_f は本文の中にある。つまり「投稿を読めた人だけがファイルを開ける」。置き場所 (保持者) は
 *   ID しか知らず、中身も名前も分からない。投稿の外 (コピー&ペースト) でも渡せる。
 * ★ 形式の合わないトークンは黙って無視する (本文はただの文字列として表示される)。
 *   1 投稿 4 件まで: 添付のたびに Manifest 取得が走るので、本文の中のトークンで取得を水増しされないようにする。
 */
import { Encoding } from '../common/Encoding';
import { ByteReader, ByteWriter } from '../common/ByteIO';
import { CHUNK_ID_BYTES, KEY_BYTES, MAX_FILE_BYTES } from './FileFormat';

export const FILE_LINK_VERSION = 1;
export const MAX_LINKS_PER_POST = 4;
const RAW_BYTES = 1 + CHUNK_ID_BYTES + KEY_BYTES + 6;
const ENCODED_CHARS = Math.ceil((RAW_BYTES * 8) / 6); // 74

export interface FileLink {
  manifestId: Uint8Array;
  key: Uint8Array;
  size: number;
}

export interface ParsedFileLink {
  link: FileLink;
  /** 本文中の [[file:...]] の開始位置と終了位置 (end は含まない) */
  start: number;
  end: number;
}

export function formatFileLink(link: FileLink): string {
  if (link.manifestId.length !== CHUNK_ID_BYTES || link.key.length !== KEY_BYTES) throw new RangeError('bad link fields');
  if (!Number.isSafeInteger(link.size) || link.size < 1 || link.size > MAX_FILE_BYTES) throw new RangeError('bad link size');
  const raw = new ByteWriter().u8(FILE_LINK_VERSION).raw(link.manifestId).raw(link.key).u48(link.size).finish();
  return `[[file:${Encoding.toBase64(raw)}]]`;
}

/** トークン本体 (base64url) を厳格に復号。不正なら null */
export function decodeFileLinkBody(body: string): FileLink | null {
  if (body.length !== ENCODED_CHARS || !/^[A-Za-z0-9_-]+$/.test(body)) return null;
  try {
    const raw = Encoding.fromBase64(body);
    // ★ 末尾の余りビットが 0 でない表現 (同じ値の別表記) は拒否
    if (Encoding.toBase64(raw) !== body) return null;
    const r = new ByteReader(raw);
    if (r.u8() !== FILE_LINK_VERSION) return null;
    const manifestId = r.bytes(CHUNK_ID_BYTES).slice();
    const key = r.bytes(KEY_BYTES).slice();
    const size = r.u48();
    r.end();
    if (size < 1 || size > MAX_FILE_BYTES) return null;
    return { manifestId, key, size };
  } catch {
    return null;
  }
}

export function parseFileLinks(text: string): ParsedFileLink[] {
  const out: ParsedFileLink[] = [];
  const re = /\[\[file:([^\]\s]*)\]\]/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const link = decodeFileLinkBody(m[1]);
    if (!link) continue;
    out.push({ link, start: m.index, end: m.index + m[0].length });
    if (out.length >= MAX_LINKS_PER_POST) break;
  }
  return out;
}

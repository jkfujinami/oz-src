import { ByteReader, ByteWriter } from '../common/ByteIO';
import { Encoding } from '../common/Encoding';
import { POW_POLICY } from './PowPolicy';

/**
 * PostCodec — SIV の内側 (暗号化層) と署名対象 (署名層) の形式 v5。
 *
 * 暗号化層の平文 (CryptoEngine が SIV で包む。先頭に magic は付けない):
 *   flags     u8   bit0 = スレ立て (post_type 1) / bit1 = トリップ有り / bit2-3 = 親の数 (0..2) / bit4-7 は 0
 *   [スレ立てのみ] thread_id  u8 長 + UTF-8 (≤ 32)
 *   parents   16 バイト × 親の数 (packet_id の生バイト)
 *   署名ブロック  トリップ無し: session_pubkey 32 ‖ session_sig 64
 *                 トリップ有り: trip_pubkey 32 ‖ trip_sig 64 (セッション鍵は載せない)
 *   content   残り全部 (UTF-8, ≤ 2048 バイト)
 *
 * 署名対象 (ワイヤには載らず、両端が同じ手順で組み立てる):
 *   "OZ/v5/post" ‖ lp(board_id) ‖ lp(thread_id) ‖ AAD ‖ flags ‖ [スレ立ての thread_id (lp)] ‖ parents ‖ content
 *   (lp = u8 の長さ前置き。AAD = 外側ヘッダの先頭 7 バイト: version ‖ time ‖ tag ‖ age)
 *
 * ★ board_id と thread_id は署名に入るが、ワイヤには載せない。読み手は板 / スレの鍵で復号するので、
 *   どの板・どのスレとして読んでいるか (文脈) を知っている。署名を文脈に縛るので、別の板・別のスレへ
 *   そのままコピーして出しても検証が通らない (鍵が違えば復号もできない)。
 * ★ AAD (time / tag / age) を署名にも入れるのは、ヘッダを書き換えた複製を作れないようにするため。
 *   (SIV も AAD を認証するので二重だが、署名は鍵を持つ他人が改竄したものを弾く側に効く)
 * ★ 署名の対象に長さを持つ可変部 (content) は最後に置く。「境界を動かした別の入力が同じバイト列になる」曖昧さが出ない。
 * ★ 累積 PoW・reply_to・post_number はワイヤに載せない。重さは読み手が祖先の数 n(p) から自分で数える。
 *   トリップ有りの投稿はトリップの署名だけを載せる (セッション鍵と組にすると、トリップの利用者を
 *   セッションごとに結び付ける材料が増える)。
 */
export const POST_SIGNED_DOMAIN = new TextEncoder().encode('OZ/v5/post');

export const FLAG_THREAD_META = 0x01;
export const FLAG_TRIP = 0x02;
/** 親の数は bit2-3 */
export const FLAG_PARENTS_SHIFT = 2;
const FLAG_PARENTS_MASK = 0x03 << FLAG_PARENTS_SHIFT;
const FLAGS_KNOWN = FLAG_THREAD_META | FLAG_TRIP | FLAG_PARENTS_MASK;

/** 署名ブロックのバイト数 (公開鍵 32 + 署名 64) */
export const SIGNER_BLOCK_BYTES = 32 + 64;

export interface PostFields {
  /** 0 = 返信, 1 = スレ立て */
  postType: number;
  /** 文脈 (ワイヤには載らない)。署名に入る */
  boardId: string;
  /**
   * 返信: 文脈のスレッド ID (ワイヤには載らない)。
   * スレ立て: 新しいスレッドの ID (平文に載る)。
   */
  threadId: string;
  /** hex 32 文字 (packet_id) */
  parents: string[];
  content: string;
}

/** 署名ブロックの中身。トリップ有りなら isTrip で、pubkey / signature はトリップのもの */
export interface PostSigner {
  isTrip: boolean;
  pubkey: Uint8Array;
  signature: Uint8Array;
}

const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: true });

export function utf8Length(s: string): number {
  return enc.encode(s).length;
}

/** 送る前の検査。違反は RangeError (メッセージは UI にそのまま見せてよい文面) */
export function assertPostLimits(f: PostFields): void {
  const contentBytes = utf8Length(f.content);
  if (contentBytes > POW_POLICY.MAX_CONTENT_BYTES) {
    throw new RangeError(
      `投稿が長すぎます (${contentBytes} バイト / 上限 ${POW_POLICY.MAX_CONTENT_BYTES} バイト, UTF-8)`,
    );
  }
  if (f.postType !== 0 && f.postType !== 1) throw new RangeError('post_type must be 0 or 1');
  for (const [name, v] of [['board_id', f.boardId], ['thread_id', f.threadId]] as const) {
    if (utf8Length(v) > POW_POLICY.MAX_ID_BYTES) throw new RangeError(`${name} too long (max ${POW_POLICY.MAX_ID_BYTES} bytes)`);
  }
  if (f.parents.length > POW_POLICY.MAX_PARENTS) {
    throw new RangeError(`too many DAG parents (${f.parents.length} > ${POW_POLICY.MAX_PARENTS})`);
  }
  for (const p of f.parents) {
    if (!/^[0-9a-f]{32}$/.test(p)) throw new RangeError('DAG parent must be a 32-char lowercase hex packet id');
  }
}

function lp(w: ByteWriter, s: string): void {
  const b = enc.encode(s);
  w.u8(b.length).raw(b);
}

export function flagsOf(f: Pick<PostFields, 'postType' | 'parents'>, isTrip: boolean): number {
  let flags = f.parents.length << FLAG_PARENTS_SHIFT;
  if (f.postType === 1) flags |= FLAG_THREAD_META;
  if (isTrip) flags |= FLAG_TRIP;
  return flags;
}

/** 署名対象。aad は外側ヘッダの先頭 7 バイト */
export function postSignedBytes(f: PostFields, aad: Uint8Array, isTrip: boolean): Uint8Array {
  const w = new ByteWriter().raw(POST_SIGNED_DOMAIN);
  lp(w, f.boardId);
  lp(w, f.threadId);
  w.raw(aad).u8(flagsOf(f, isTrip));
  if (f.postType === 1) lp(w, f.threadId);
  for (const p of f.parents) w.raw(Encoding.fromHex(p));
  w.raw(enc.encode(f.content));
  return w.finish();
}

export function encodePostPlain(f: PostFields, signer: PostSigner): Uint8Array {
  assertPostLimits(f);
  if (signer.pubkey.length !== 32 || signer.signature.length !== 64) throw new RangeError('bad signer block');
  const w = new ByteWriter().u8(flagsOf(f, signer.isTrip));
  if (f.postType === 1) lp(w, f.threadId);
  for (const p of f.parents) w.raw(Encoding.fromHex(p));
  w.raw(signer.pubkey).raw(signer.signature);
  w.raw(enc.encode(f.content));
  return w.finish();
}

export interface DecodedPost {
  postType: number;
  /** スレ立てのときだけ。返信では null (文脈から補う) */
  metaThreadId: string | null;
  parents: string[];
  signer: PostSigner;
  content: string;
}

/** 失敗 (形式違反・切り詰め) は null */
export function decodePostPlain(bytes: Uint8Array): DecodedPost | null {
  try {
    const r = new ByteReader(bytes);
    const flags = r.u8();
    if ((flags & ~FLAGS_KNOWN) !== 0) return null;
    const postType = (flags & FLAG_THREAD_META) !== 0 ? 1 : 0;
    let metaThreadId: string | null = null;
    if (postType === 1) {
      const n = r.u8();
      if (n > POW_POLICY.MAX_ID_BYTES) return null;
      metaThreadId = dec.decode(r.bytes(n));
    }
    const np = (flags & FLAG_PARENTS_MASK) >> FLAG_PARENTS_SHIFT;
    if (np > POW_POLICY.MAX_PARENTS) return null;
    const parents: string[] = [];
    for (let i = 0; i < np; i++) parents.push(Encoding.toHex(r.bytes(POW_POLICY.PACKET_ID_BYTES)));
    const pubkey = r.bytes(32).slice();
    const signature = r.bytes(64).slice();
    const rest = r.rest();
    if (rest.length > POW_POLICY.MAX_CONTENT_BYTES) return null;
    const content = dec.decode(rest);
    return { postType, metaThreadId, parents, signer: { isTrip: (flags & FLAG_TRIP) !== 0, pubkey, signature }, content };
  } catch {
    return null;
  }
}

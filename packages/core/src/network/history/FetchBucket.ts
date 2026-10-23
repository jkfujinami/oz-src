import { ByteReader, ByteWriter } from '../../common/ByteIO';

/**
 * FETCH_BUCKET — 保持者にバケット (birthDay, tag) の投稿を頼む要求と、その応答の符号化 (history v2 §4.4)。
 * 要求・応答とも TunnelCrypto で端から端まで暗号化される (ここは暗号化する前 / した後の中身の形式)。
 *
 *   要求   birthDay u16 (UNIX 日番号) ‖ tag u16 (12 ビット) ‖ since u24 (OZ_EPOCH からの分)    7 バイト
 *   応答   status u8 ‖ nextSince u24 ‖ { len u16 ‖ パケット (PacketCodec) } × n
 *
 *   status  OK (0)        since 以降を全部送った (0 件でもよい。「持っているが新しいものは無い」)
 *           MORE (1)      上限 (FETCH_MAX_RESPONSE_BYTES) で打ち切った。続きは since = nextSince で頼む
 *           NOT_HELD (2)  このバケットを持っていない (担当でも、まだ何も受け取っていない・捨てた)。読み手は別の保持者へ
 *
 * ★ birthDay は u16 (UNIX 日番号は 2026 年で約 2.1 万、65535 は 2149 年)。u24 にしても 1 バイト増えるだけで得が無い。
 * ★ 保持者はどのスレのバケットかを知らない (tag は 12 ビットで他のスレと衝突する)。要求の since 以降をバケットごとに返す。
 */

export const FETCH_REQUEST_BYTES = 2 + 2 + 3;
/** 応答 1 回の本体の上限 (パケットの長さの前置きを含む。4MiB)。超える分は MORE で続きを頼ませる */
export const FETCH_MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
/** 読み手が受け付ける応答の上限 (上限 + 余裕)。これを超えたら捨てる */
export const FETCH_MAX_ACCEPT_BYTES = FETCH_MAX_RESPONSE_BYTES + 64 * 1024;

export const FETCH_STATUS = { OK: 0, MORE: 1, NOT_HELD: 2 } as const;
export type FetchStatus = (typeof FETCH_STATUS)[keyof typeof FETCH_STATUS];

const MAX_U24 = 0xffffff;

export interface FetchRequest {
  birthDay: number;
  tag: number;
  since: number;
}

export function encodeFetchRequest(r: FetchRequest): Uint8Array {
  if (!Number.isInteger(r.birthDay) || r.birthDay < 0 || r.birthDay > 0xffff) throw new RangeError('birthDay out of range');
  if (!Number.isInteger(r.tag) || r.tag < 0 || r.tag > 0xfff) throw new RangeError('tag out of range');
  if (!Number.isInteger(r.since) || r.since < 0 || r.since > MAX_U24) throw new RangeError('since out of range');
  return new ByteWriter().u16(r.birthDay).u16(r.tag).u8(r.since >>> 16).u8((r.since >>> 8) & 0xff).u8(r.since & 0xff).finish();
}

export function decodeFetchRequest(b: Uint8Array): FetchRequest | null {
  if (b.length !== FETCH_REQUEST_BYTES) return null;
  try {
    const r = new ByteReader(b);
    const birthDay = r.u16();
    const tag = r.u16();
    const since = (r.u8() << 16) | (r.u8() << 8) | r.u8();
    r.end();
    if (tag > 0xfff) return null;
    return { birthDay, tag, since };
  } catch {
    return null;
  }
}

export interface FetchResponse {
  status: FetchStatus;
  nextSince: number;
  packets: Uint8Array[];
}

/** 応答を作る (パケットは時刻の古い順)。status は呼び出し側 (HolderResponder) が決める */
export function encodeFetchResponse(res: FetchResponse): Uint8Array {
  const w = new ByteWriter().u8(res.status);
  const n = res.nextSince;
  if (!Number.isInteger(n) || n < 0 || n > MAX_U24) throw new RangeError('nextSince out of range');
  w.u8(n >>> 16).u8((n >>> 8) & 0xff).u8(n & 0xff);
  for (const p of res.packets) {
    if (p.length === 0 || p.length > 0xffff) throw new RangeError('bad packet size');
    w.u16(p.length).raw(p);
  }
  return w.finish();
}

/** 壊れていれば null。パケットの中身 (PoW・id) はここでは見ない */
export function decodeFetchResponse(b: Uint8Array): FetchResponse | null {
  try {
    const r = new ByteReader(b);
    const status = r.u8();
    if (status !== FETCH_STATUS.OK && status !== FETCH_STATUS.MORE && status !== FETCH_STATUS.NOT_HELD) return null;
    const nextSince = (r.u8() << 16) | (r.u8() << 8) | r.u8();
    const packets: Uint8Array[] = [];
    while (r.remaining > 0) {
      const len = r.u16();
      if (len === 0) return null;
      packets.push(r.bytes(len).slice());
    }
    if (status === FETCH_STATUS.NOT_HELD && packets.length > 0) return null;
    return { status, nextSince, packets };
  } catch {
    return null;
  }
}

/**
 * 保持者が返す内容を、上限 (FETCH_MAX_RESPONSE_BYTES) に収めて作る。
 * @param packets 時刻の古い順の encodePacket のバイト列
 * @param timeMinOf パケットの時刻 (OZ_EPOCH からの分)
 * @param since 要求の since
 */
export function buildFetchResponse(
  packets: readonly Uint8Array[], timeMinOf: (p: Uint8Array) => number, since: number,
  maxBytes: number = FETCH_MAX_RESPONSE_BYTES,
): FetchResponse {
  let used = 0;
  const out: Uint8Array[] = [];
  let i = 0;
  for (; i < packets.length; i++) {
    const cost = 2 + packets[i].length;
    if (used + cost > maxBytes) break;
    used += cost;
    out.push(packets[i]);
  }
  if (i >= packets.length) return { status: FETCH_STATUS.OK, nextSince: 0, packets: out };
  // 続きの since: 最後に入れたパケットの時刻 (≥ なので同じ分の続きも取れる。重複は読み手が落とす)。
  // 進まない (1 分に上限以上の投稿が重なる) ときは 1 分進めて、無限に同じ所を頼ませない。
  const last = out.length > 0 ? timeMinOf(out[out.length - 1]) : since;
  return { status: FETCH_STATUS.MORE, nextSince: Math.min(MAX_U24, last > since ? last : since + 1), packets: out };
}

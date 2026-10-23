import { ByteReader, ByteWriter } from '../../common/ByteIO';
import { CHUNK_ID_BYTES, CHUNK_SIZE, TAG_BYTES } from '../../files/FileFormat';
import { EQUIX_SOLUTION_BYTES } from '../../crypto/equix/EquiX';

/**
 * チャンクの PUT / GET の要求と応答の符号化 (docs/design/file-sharing.md §3・§4)。
 * 要求・応答とも TunnelCrypto で端から端まで暗号化される (ここは暗号化する前 / した後の中身の形式)。
 * トンネルの要求の種別 (kind) は TUNNEL_KIND.PUT_CHUNK / GET_CHUNK。
 *
 *   PUT_CHUNK 要求  chunkId 16 ‖ powNonce u32 ‖ powSolution 16 ‖ fragIndex u8 ‖ fragCount u8 ‖ data
 *   PUT_CHUNK 応答  status u8
 *   GET_CHUNK 要求  chunkId 16
 *   GET_CHUNK 応答  status u8 ‖ data      (data は status = OK のときだけ。暗号文そのもの)
 *
 * ★ **PUT は断片に分けて送る**: トンネルの 1 フレームは 16KiB まで (TunnelRelay・MAX_TUNNEL_FRAME_BYTES) で、
 *   チャンクの暗号文は最大 256KiB + 16。要求を 1 つの封印に収められないので、`data` を 15KiB ずつの断片にして
 *   それぞれを独立した要求 (別の封印・別の respKey) として送る。保持者はチャンク ID ごとに断片を集め、揃った時点で
 *   ハッシュ・PoW・担当・容量を確かめて預かる。
 *   - 断片は全部に chunkId・PoW を載せる (24 バイトの重複)。最初に届いた断片で PoW と担当を確かめ、
 *     不正ならバッファを取らずに断る (ゴミでメモリを埋められない)。
 *   - 最後の断片以外は**ちょうど** FRAG_DATA_BYTES。位置は fragIndex × FRAG_DATA_BYTES で決まる (順序が入れ替わってよい)。
 *   - 揃えた断片で STORED を返すのは、揃えた 1 通だけ。他は OK (まだ途中)。保存済みのチャンクへの再送は STORED を返す (冪等)。
 * ★ GET の応答は TUNNEL_CHUNK_DATA_BYTES (15KiB) ごとの片に分かれて返る (TunnelHolder の既存の仕組み。最大 18 片)。
 */

/** 複製の数 R_FILE と、置き終えたと認める最低数 R_MIN_OK */
export const R_FILE = 5;
export const R_MIN_OK = 3;

/** 保持者が PUT を受け付ける範囲: 複製の位置のどれかに近い 3 枠のうちに、自分の枠があること */
export const CHUNK_DUTY_SLOTS = 3;
/** 取りに行く側が、1 つの複製の位置につき試す枠の数 (担当の 3 枠 + 次に近い枠 3 つ) */
export const CHUNK_READ_SLOTS = 6;

/** 断片 1 つに載せるデータ。封印後 = 48 + 1 + 32 + 38 + 15360 でフレーム (16KiB) に収まる */
export const FRAG_DATA_BYTES = 15 * 1024;
/** 預かるデータの最大 (チャンクの暗号文。Manifest のチャンクも同じ上限) */
export const CHUNK_MAX_CIPHER_BYTES = CHUNK_SIZE + TAG_BYTES;
/** 断片の最大数 = ceil((256KiB + 16) / 15KiB) */
export const MAX_FRAGMENTS = Math.ceil(CHUNK_MAX_CIPHER_BYTES / FRAG_DATA_BYTES);

export const PUT_HEADER_BYTES = CHUNK_ID_BYTES + 4 + EQUIX_SOLUTION_BYTES + 1 + 1;

export const CHUNK_STATUS = {
  /** GET: データを返した。PUT: 断片を受け取った (まだ全部は揃っていない) */
  OK: 0,
  /** PUT: 預かった (または既に預かっている) */
  STORED: 1,
  /** GET: 持っていない */
  NOT_HELD: 2,
  /** PUT: 保存の PoW が不正 */
  BAD_POW: 3,
  /** PUT: 自分の担当ではない (複製の位置に近い 3 枠に自分の枠が無い) */
  NOT_DUTY: 4,
  /** PUT: 揃ったデータのハッシュが chunkId と合わない */
  BAD_ID: 5,
  /** 形式の不正 (長さ・断片の番号・大きさ) */
  BAD_REQUEST: 6,
  /** PUT: 容量に入らない・書き込みの待ちが満杯・集めている最中の数が上限 */
  FULL: 7,
} as const;
export type ChunkStatus = (typeof CHUNK_STATUS)[keyof typeof CHUNK_STATUS];

export interface PutFragment {
  chunkId: Uint8Array;
  powNonce: number;
  powSolution: Uint8Array;
  fragIndex: number;
  fragCount: number;
  data: Uint8Array;
}

/** 断片の数 (データ n バイトを FRAG_DATA_BYTES ずつ) */
export function fragmentCountFor(dataBytes: number): number {
  return Math.max(1, Math.ceil(dataBytes / FRAG_DATA_BYTES));
}

export function encodePutFragment(f: PutFragment): Uint8Array {
  if (f.chunkId.length !== CHUNK_ID_BYTES) throw new RangeError('bad chunk id');
  if (f.powSolution.length !== EQUIX_SOLUTION_BYTES) throw new RangeError('bad pow solution');
  if (!Number.isInteger(f.fragCount) || f.fragCount < 1 || f.fragCount > MAX_FRAGMENTS) throw new RangeError('bad fragCount');
  if (!Number.isInteger(f.fragIndex) || f.fragIndex < 0 || f.fragIndex >= f.fragCount) throw new RangeError('bad fragIndex');
  if (f.data.length < 1 || f.data.length > FRAG_DATA_BYTES) throw new RangeError('bad fragment size');
  if (f.fragIndex < f.fragCount - 1 && f.data.length !== FRAG_DATA_BYTES) throw new RangeError('non-final fragment must be full');
  const w = new ByteWriter().raw(f.chunkId);
  w.u8((f.powNonce >>> 24) & 0xff).u8((f.powNonce >>> 16) & 0xff).u8((f.powNonce >>> 8) & 0xff).u8(f.powNonce & 0xff);
  return w.raw(f.powSolution).u8(f.fragIndex).u8(f.fragCount).raw(f.data).finish();
}

/** 厳格な復号。形式の不正は null (大きさ・断片の数の検査を含む) */
export function decodePutFragment(b: Uint8Array): PutFragment | null {
  try {
    if (b.length <= PUT_HEADER_BYTES || b.length > PUT_HEADER_BYTES + FRAG_DATA_BYTES) return null;
    const r = new ByteReader(b);
    const chunkId = r.bytes(CHUNK_ID_BYTES).slice();
    const nb = r.bytes(4);
    const powNonce = ((nb[0] << 24) | (nb[1] << 16) | (nb[2] << 8) | nb[3]) >>> 0;
    const powSolution = r.bytes(EQUIX_SOLUTION_BYTES).slice();
    const fragIndex = r.u8();
    const fragCount = r.u8();
    if (fragCount < 1 || fragCount > MAX_FRAGMENTS || fragIndex >= fragCount) return null;
    const data = b.slice(PUT_HEADER_BYTES);
    if (fragIndex < fragCount - 1 && data.length !== FRAG_DATA_BYTES) return null;
    return { chunkId, powNonce, powSolution, fragIndex, fragCount, data };
  } catch {
    return null;
  }
}

export function encodeGetRequest(chunkId: Uint8Array): Uint8Array {
  if (chunkId.length !== CHUNK_ID_BYTES) throw new RangeError('bad chunk id');
  return chunkId.slice();
}

export function decodeGetRequest(b: Uint8Array): Uint8Array | null {
  return b.length === CHUNK_ID_BYTES ? b.slice() : null;
}

export function encodeStatusResponse(status: ChunkStatus): Uint8Array {
  return Uint8Array.of(status);
}

export function decodeStatusResponse(b: Uint8Array): ChunkStatus | null {
  return b.length === 1 && b[0] <= CHUNK_STATUS.FULL ? (b[0] as ChunkStatus) : null;
}

export function encodeGetResponse(status: ChunkStatus, data?: Uint8Array): Uint8Array {
  if (status !== CHUNK_STATUS.OK) return Uint8Array.of(status);
  const d = data ?? new Uint8Array(0);
  const out = new Uint8Array(1 + d.length);
  out[0] = status;
  out.set(d, 1);
  return out;
}

/** 応答を読む。status = OK のときは data つき。不正は null */
export function decodeGetResponse(b: Uint8Array): { status: ChunkStatus; data: Uint8Array } | null {
  if (b.length < 1 || b[0] > CHUNK_STATUS.FULL) return null;
  const status = b[0] as ChunkStatus;
  if (status !== CHUNK_STATUS.OK) return b.length === 1 ? { status, data: new Uint8Array(0) } : null;
  if (b.length - 1 > CHUNK_MAX_CIPHER_BYTES) return null;
  return { status, data: b.slice(1) };
}

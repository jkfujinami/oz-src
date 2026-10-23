/**
 * MeshRange — Ozzy のチャンクを、オニオン回路 (Tor と同じ多段ホップ) の先のノードに代わりに取ってきてもらう。
 *
 *   要求   読み手 R ─ONION_STEM (cover と同じ送出枠)→ R の Guard G ─ONION_STEM→ M1 ─HTTP Range GET→ ロッカー
 *   応答   M1 ─OZZY_REPLY→ G ─OZZY_RESULT→ R   (4KiB 以下の片の列。片ごとに R の要求ごとの鍵で暗号化)
 *   1 チャンクごとに要求を 1 つ出す。回路は 3 枠ごとに M1 を替えるので、要求は多くの M1 に散って並列に取れる。
 *
 * ★ 誰に何が見えるか:
 *   - G (R の隣人): R の IP と、どの M1 から応答が来たか・量。URL・範囲は M1 宛ての封印の中で見えない。中身も見えない。
 *   - M1: URL と範囲、手前の G。R は分からない (返送先は G 宛ての封印の中)。中身は暗号文のまま (K_enc を持たない)。
 *   - ロッカー (または中継 Worker): M1 の IP。R の IP は届かない。
 *   G と M1 が結託すれば R と URL が揃う (Tor の 2 ホップと同じ限界)。
 * ★ M1 はどんな URL にも行くわけではない。許可された公開ロッカーのホストだけ (攻撃者のサーバーに取りに行かせて M1 の IP を
 *   暴く・LAN を覗く穴を塞ぐ)。範囲は 1 チャンク (4 MiB) まで。認証情報 (削除トークン等) は要求に載せない。
 * ★ 旧実装 (P2PFetcher: OZZY_FETCH_REQ / STREAM) は隣人 1 人に IP と URL を両方見せ、レート制限のカテゴリも無く
 *   本物の PeerManager では全フレームが捨てられていた。作り直した。
 *
 *   要求の本体   v u8 (1) ‖ lp8(lockerId) ‖ lp16(url) ‖ start u48 ‖ length u32 ‖ expectedTag 16
 *   応答 (片を繋いだもの)   status u8 ‖ data (OK のときだけ。ちょうど length バイト)
 */
import { ByteReader, ByteWriter } from '../common/ByteIO';
import { Encoding } from '../common/Encoding';
import sodium from '../crypto/sodium';
import { bytesEqual } from '../files/FileFormat';
import { sleep } from '../files/FileTransfer';
import type { IMessageDispatcher, IPeerManager, PeerId } from '../types';
import { WireType } from '../network/wire/WireTypes';
import {
  MAX_OZZY_FRAME_BYTES, OZZY_REPLY_FIXED_BYTES, OZZY_REPLY_HEADER_BYTES, OZZY_UP_FIXED_BYTES, OZZY_UP_HEADER_BYTES, OZZY_UPLOAD_ID_BYTES,
} from '../network/wire/WireCodec';
import { decryptChunk, encryptChunk } from '../network/tunnel/TunnelCrypto';
import { isSafeExternalHttpsUrl } from './CloudLeaseSet';
import { OZZY_CHUNK_BYTES } from './OzzyChunk4M';
import { OZZY_TAG_BYTES } from './OzzyKdf';

const MESH_RANGE_VERSION = 1;
/** 1 回の要求で取れる最大の範囲 (= 1 チャンク) */
export const OZZY_MESH_MAX_RANGE_BYTES = OZZY_CHUNK_BYTES;
/** URL の最大 (UTF-8)。要求を 1 フレーム (MAX_OZZY_REQ_FRAME_BYTES) に収める */
export const OZZY_MESH_MAX_URL_BYTES = 1024;

export const OZZY_MESH_STATUS = {
  OK: 0,
  /** ロッカーに無い (404 など) */
  NOT_FOUND: 1,
  /** 取れたが中身が違う・通信の失敗・時間切れ */
  FETCH_ERROR: 2,
  /** 許可されていない宛先・壊れた要求 */
  REFUSED: 3,
  /** 同時数の上限 */
  BUSY: 4,
} as const;
export type OzzyMeshStatus = (typeof OZZY_MESH_STATUS)[keyof typeof OZZY_MESH_STATUS];

export interface OzzyRangeRequest {
  /** ロッカーの種類 (OverseasLockerId)。H がロッカーごとの取り方 (Gofile のセッション等) を選ぶのに使う */
  readonly lockerId: string;
  readonly url: string;
  readonly start: number;
  readonly length: number;
  /** チャンク先頭 16 バイトの tag。隣人は一致しないものを返さない (ゴミを流さない) */
  readonly expectedTag: Uint8Array;
}

const utf8 = new TextEncoder();
const utf8Strict = new TextDecoder('utf-8', { fatal: true });
const LOCKER_ID_RE = /^[a-z0-9][a-z0-9.-]{0,31}$/;

export function encodeRangeRequest(req: OzzyRangeRequest): Uint8Array {
  if (!LOCKER_ID_RE.test(req.lockerId)) throw new RangeError('bad lockerId');
  const url = utf8.encode(req.url);
  if (url.length < 1 || url.length > OZZY_MESH_MAX_URL_BYTES) throw new RangeError('bad url length');
  if (!Number.isSafeInteger(req.length) || req.length < 1 || req.length > OZZY_MESH_MAX_RANGE_BYTES) {
    throw new RangeError('bad range length');
  }
  if (req.expectedTag.length !== OZZY_TAG_BYTES) throw new RangeError('bad tag');
  const id = utf8.encode(req.lockerId);
  return new ByteWriter()
    .u8(MESH_RANGE_VERSION)
    .u8(id.length).raw(id)
    .u16(url.length).raw(url)
    .u48(req.start)
    .raw(Uint8Array.of(req.length >>> 24, (req.length >>> 16) & 0xff, (req.length >>> 8) & 0xff, req.length & 0xff))
    .raw(req.expectedTag)
    .finish();
}

export function decodeRangeRequest(bytes: Uint8Array): OzzyRangeRequest | null {
  try {
    const r = new ByteReader(bytes);
    if (r.u8() !== MESH_RANGE_VERSION) return null;
    const lockerId = utf8Strict.decode(r.bytes(r.u8()));
    const urlLen = r.u16();
    if (urlLen < 1 || urlLen > OZZY_MESH_MAX_URL_BYTES) return null;
    const url = utf8Strict.decode(r.bytes(urlLen));
    const start = r.u48();
    const lb = r.bytes(4);
    const length = ((lb[0] << 24) | (lb[1] << 16) | (lb[2] << 8) | lb[3]) >>> 0;
    const expectedTag = r.bytes(OZZY_TAG_BYTES).slice();
    r.end();
    if (!LOCKER_ID_RE.test(lockerId)) return null;
    if (length < 1 || length > OZZY_MESH_MAX_RANGE_BYTES) return null;
    if (!Number.isSafeInteger(start + length)) return null;
    return { lockerId, url, start, length, expectedTag };
  } catch {
    return null;
  }
}

export function encodeRangeResponse(status: OzzyMeshStatus, data?: Uint8Array): Uint8Array {
  if (status !== OZZY_MESH_STATUS.OK || !data) return Uint8Array.of(status);
  const out = new Uint8Array(1 + data.length);
  out[0] = status;
  out.set(data, 1);
  return out;
}

export function decodeRangeResponse(bytes: Uint8Array): { status: number; data: Uint8Array } | null {
  if (bytes.length < 1) return null;
  const status = bytes[0];
  if (status === OZZY_MESH_STATUS.OK) {
    if (bytes.length < 2) return null;
    return { status, data: bytes.subarray(1) };
  }
  if (bytes.length !== 1 || status > OZZY_MESH_STATUS.BUSY) return null;
  return { status, data: new Uint8Array(0) };
}

// ── 頼まれる側 (M1) の取り方 ──

/**
 * 取得役が取りに行ってよいロッカーのホスト。どれも「誰でもアップロードでき、URL を知っていれば誰でも読める」公開ロッカー。
 * ★ 攻撃者が自分で用意したホストは入れない: 入れると、要求を投げるだけで取得役の IP を集められ、LAN の中も覗ける。
 *   取得役が中継 Worker を挟めば、ロッカーに見えるのは Cloudflare の IP になる。
 */
export const OZZY_FETCH_ALLOWED_HOSTS: readonly string[] = [
  'archive.org',
  'files.catbox.moe',
  'litter.catbox.moe',
  '0x0.st',
  'x0.at',
  'd.uguu.se',
  'pomf2.lain.la',
  'qu.ax',
  'pixeldrain.com',
];
/** サブドメインまで許すもの (IA のダウンロードは ia*.us.archive.org へ、Gofile は store*.gofile.io へ振り分けられる) */
export const OZZY_FETCH_ALLOWED_SUFFIXES: readonly string[] = ['.archive.org', '.gofile.io'];

export function isAllowedOzzyFetchUrl(rawUrl: string, extraHosts: readonly string[] = []): boolean {
  if (!isSafeExternalHttpsUrl(rawUrl)) return false;
  let u: URL;
  try {
    u = new URL(rawUrl);
  } catch {
    return false;
  }
  if (u.port !== '') return false;
  const host = u.hostname.toLowerCase();
  if (OZZY_FETCH_ALLOWED_HOSTS.includes(host)) return true;
  if (OZZY_FETCH_ALLOWED_SUFFIXES.some(s => host.endsWith(s))) return true;
  return extraHosts.some(h => h.toLowerCase() === host);
}

/** 取得役が実際にロッカーから範囲を取る関数。end は含む。取れなければ null。404 は 'not-found' */
export type OzzyRangeFetchFn = (
  lockerId: string, url: string, start: number, endInclusive: number, signal: AbortSignal,
) => Promise<Uint8Array | null | 'not-found'>;

export interface OzzyRangeServerOptions {
  fetchRange: OzzyRangeFetchFn;
  /** 既定の許可リストに足すホスト (自分たちの中継 Worker など)。完全一致 */
  extraAllowedHosts?: readonly string[];
  /** 同時に取りに行く数 (既定 4)。超えたら BUSY */
  maxConcurrent?: number;
  /** 1 回の取得の上限時間 (既定 30 秒) */
  timeoutMs?: number;
}

/**
 * OzzyRangeServer — 要求 1 つを検証してロッカーから取り、応答 (status ‖ data) を作る。送るのは OzzyOnionExit。
 * ★ 取った中身はメモリだけ。応答を送り終えたら捨てる。URL はログに出さない。
 */
export class OzzyRangeServer {
  private active = 0;
  private readonly maxConcurrent: number;
  private readonly timeoutMs: number;
  private readonly extraHosts: readonly string[];
  private destroyed = false;
  private readonly controllers = new Set<AbortController>();

  /** 診断・テスト用 */
  public readonly stats = { served: 0, refused: 0, busy: 0, notFound: 0, failed: 0 };

  constructor(private readonly opts: OzzyRangeServerOptions) {
    this.maxConcurrent = opts.maxConcurrent ?? 4;
    this.timeoutMs = opts.timeoutMs ?? 30_000;
    this.extraHosts = opts.extraAllowedHosts ?? [];
  }

  public async serve(payload: Uint8Array): Promise<Uint8Array> {
    const req = decodeRangeRequest(payload);
    if (this.destroyed || !req || !isAllowedOzzyFetchUrl(req.url, this.extraHosts)) {
      this.stats.refused++;
      return encodeRangeResponse(OZZY_MESH_STATUS.REFUSED);
    }
    if (this.active >= this.maxConcurrent) {
      this.stats.busy++;
      return encodeRangeResponse(OZZY_MESH_STATUS.BUSY);
    }
    this.active++;
    const ac = new AbortController();
    this.controllers.add(ac);
    const timer = setTimeout(() => ac.abort(), this.timeoutMs);
    try {
      const got = await this.opts.fetchRange(req.lockerId, req.url, req.start, req.start + req.length - 1, ac.signal);
      if (got === 'not-found') {
        this.stats.notFound++;
        return encodeRangeResponse(OZZY_MESH_STATUS.NOT_FOUND);
      }
      // ★ 長さと tag が合わないものは返さない (ロッカーの差し替え・途中で切れた応答を流さない)
      if (!got || got.length !== req.length || !bytesEqual(got.subarray(0, OZZY_TAG_BYTES), req.expectedTag)) {
        this.stats.failed++;
        return encodeRangeResponse(OZZY_MESH_STATUS.FETCH_ERROR);
      }
      this.stats.served++;
      return encodeRangeResponse(OZZY_MESH_STATUS.OK, got);
    } catch {
      this.stats.failed++;
      return encodeRangeResponse(OZZY_MESH_STATUS.FETCH_ERROR);
    } finally {
      clearTimeout(timer);
      this.controllers.delete(ac);
      this.active--;
    }
  }

  public destroy(): void {
    this.destroyed = true;
    for (const ac of this.controllers) ac.abort();
    this.controllers.clear();
  }
}

/**
 * 既定の取得: HTTP Range GET (Content-Range の範囲を確かめる)。ブラウザでは CORS を返さないロッカーが多いので、
 * 呼び出し側は中継 Worker のトランスポート (createWorkerCorsProxyTransport) を渡すこと。
 */
export function createHttpRangeFetch(
  transport: (req: Request) => Promise<Response> = (req) => fetch(req, { cache: 'no-store', redirect: 'follow' }),
): OzzyRangeFetchFn {
  return async (_lockerId, url, start, end, signal) => {
    const res = await transport(new Request(url, { method: 'GET', headers: { Range: `bytes=${start}-${end}` }, signal }));
    if (res.status === 404 || res.status === 410) return 'not-found';
    const want = end - start + 1;
    if (res.status === 206) {
      const buf = new Uint8Array(await res.arrayBuffer());
      return buf.length === want ? buf : null;
    }
    if (res.status === 200) {
      // Range を無視したサーバー。全体が小さいときだけ切り出す (巨大な全体を読み込まない)
      const len = Number(res.headers.get('Content-Length') ?? NaN);
      if (!Number.isFinite(len) || len > end + 1 + OZZY_MESH_MAX_RANGE_BYTES * 4) return null;
      const full = new Uint8Array(await res.arrayBuffer());
      return end < full.length ? full.slice(start, end + 1) : null;
    }
    return null;
  };
}

// ── オニオン回路に載せる形 ──

/**
 * オニオンの出口 (M1) で「Ozzy の代理取得」を表す種別 (組み立てた item の先頭 1 バイト)。ExitItem の 1 (fluff) と重ならない。
 *   item = OZZY_ONION_KIND ‖ replyHeader 68 ‖ respKey 32 ‖ 要求の本体 (encodeRangeRequest)
 */
export const OZZY_ONION_KIND = 0x4f;
/** 応答の片の暗号化 (TunnelCrypto.encryptChunk) の AAD に入れる種別 (別の用途の片に差し替えられない) */
const OZZY_REPLY_AEAD_KIND = 0x4f;
const RESP_KEY_BYTES = 32;
/** 応答の 1 片に載せる平文の最大: フレーム 4KiB - OZZY_REPLY の固定部 - (final 1 + AEAD 16) */
export const OZZY_REPLY_PIECE_BYTES = MAX_OZZY_FRAME_BYTES - OZZY_REPLY_FIXED_BYTES - 17;

/** 返送先 (Guard が開ける): 読み手の peerId 16 ‖ replyId u32 を Guard の X25519 鍵へ封印 */
export function sealReplyHeader(guardEd25519Pub: Uint8Array, readerPeerId: PeerId, replyId: number): Uint8Array {
  const plain = new Uint8Array(20);
  plain.set(Encoding.fromHex(readerPeerId), 0);
  new DataView(plain.buffer).setUint32(16, replyId >>> 0, false);
  return sodium.crypto_box_seal(plain, sodium.crypto_sign_ed25519_pk_to_curve25519(guardEd25519Pub));
}

function openReplyHeader(header: Uint8Array, keys: { pk: Uint8Array; sk: Uint8Array }): { reader: PeerId; replyId: number } | null {
  try {
    const plain = sodium.crypto_box_seal_open(header, keys.pk, keys.sk);
    if (plain.length !== 20) return null;
    return { reader: Encoding.toHex(plain.subarray(0, 16)), replyId: new DataView(plain.buffer, plain.byteOffset).getUint32(16, false) };
  } catch {
    return null;
  }
}

// ── ロッカーへの作業 (アップロード・削除) を M1 に頼む形 ──
//
//   回路の要求 (M1 へ)   OZZY_ONION_JOB_KIND ‖ replyHeader 68 ‖ respKey 32 ‖ upKey 32 ‖ uploadId 16 ‖ 作業 (encodeLockerJob)
//   本体 (Slab)          告発者 ─OZZY_UP (宛先は Guard 宛ての封印: M1 ‖ uploadId)→ Guard ─OZZY_UP_FWD→ M1
//                        片ごとに upKey で暗号化 (Guard には中身が見えない)
//   結果 (受け取り票)     M1 → Guard → 告発者 (OZZY_REPLY / RESULT。取得の応答と同じ道)
// ★ M1 に見えるのは Guard と、置き先のロッカー・Slab (暗号文)。告発者は分からない。Guard に見えるのは告発者・M1・量だけ。
// ★ M1 はロッカーへ、交換で集めた他人の中継 Worker を通して行く。ロッカーにも Worker にも告発者の IP は届かない。

/** M1 で「ロッカーへの作業」を表す種別 (組み立てた item の先頭 1 バイト) */
export const OZZY_ONION_JOB_KIND = 0x50;
const OZZY_UP_AEAD_KIND = 0x50;
/** 本体の 1 片に載せる平文の最大: フレーム 4KiB - OZZY_UP の固定部 - (final 1 + AEAD 16) */
export const OZZY_UP_PIECE_BYTES = MAX_OZZY_FRAME_BYTES - OZZY_UP_FIXED_BYTES - 17;
/** 1 つの作業で運べる本体の上限 (Slab 1 本) */
export const OZZY_JOB_MAX_BYTES = 64 * 1024 * 1024;
/** M1 が作業を引き受けるロッカー (資格情報なしで置ける公開ロッカーだけ。IA はアカウントの鍵を M1 に渡すことになるので不可) */
export const OZZY_JOB_LOCKERS: readonly string[] = ['catbox', 'litterbox', '0x0.st', 'pomf-lain', 'pomf-quax', 'pomf-uguu', 'gofile', 'pixeldrain'];

export type OzzyLockerJob =
  | { readonly op: 'upload'; readonly lockerId: string; readonly filename: string }
  | { readonly op: 'delete'; readonly lockerId: string; readonly receipt: string };

/** M1 で作業を実行する関数 (ロッカーのアダプタを中継 Worker 経由で動かす)。結果のバイト列 (JSON) を返す */
export type OzzyLockerJobRunner = (job: OzzyLockerJob, body: Uint8Array, signal: AbortSignal) => Promise<Uint8Array>;

const SLAB_FILENAME_RE = /^[A-Za-z0-9._-]{1,64}$/;
/** 削除に渡す受け取り票の上限 (要求全体が回路の 1 item = 3 セル ≒ 3.2KB に収まるように) */
export const OZZY_JOB_RECEIPT_MAX_BYTES = 2800;

export function encodeLockerJob(job: OzzyLockerJob, totalBytes: number): Uint8Array {
  const id = utf8.encode(job.lockerId);
  if (!OZZY_JOB_LOCKERS.includes(job.lockerId)) throw new RangeError('locker not allowed for jobs');
  if (!Number.isSafeInteger(totalBytes) || totalBytes < 0 || totalBytes > OZZY_JOB_MAX_BYTES) throw new RangeError('bad job size');
  const w = new ByteWriter().u8(job.op === 'upload' ? 1 : 2).u8(id.length).raw(id);
  if (job.op === 'upload') {
    if (!SLAB_FILENAME_RE.test(job.filename)) throw new RangeError('bad filename');
    const fn = utf8.encode(job.filename);
    w.u8(fn.length).raw(fn);
  } else {
    const rc = utf8.encode(job.receipt);
    if (rc.length > OZZY_JOB_RECEIPT_MAX_BYTES) throw new RangeError('receipt too large');
    w.u16(rc.length).raw(rc);
  }
  return w.raw(Uint8Array.of(totalBytes >>> 24, (totalBytes >>> 16) & 0xff, (totalBytes >>> 8) & 0xff, totalBytes & 0xff)).finish();
}

export function decodeLockerJob(bytes: Uint8Array): { job: OzzyLockerJob; totalBytes: number } | null {
  try {
    const r = new ByteReader(bytes);
    const op = r.u8();
    const lockerId = utf8Strict.decode(r.bytes(r.u8()));
    if (!OZZY_JOB_LOCKERS.includes(lockerId)) return null;
    let job: OzzyLockerJob;
    if (op === 1) {
      const filename = utf8Strict.decode(r.bytes(r.u8()));
      if (!SLAB_FILENAME_RE.test(filename)) return null;
      job = { op: 'upload', lockerId, filename };
    } else if (op === 2) {
      const len = r.u16();
      if (len > OZZY_JOB_RECEIPT_MAX_BYTES) return null;
      const receipt = utf8Strict.decode(r.bytes(len));
      job = { op: 'delete', lockerId, receipt };
    } else {
      return null;
    }
    const b = r.bytes(4);
    const totalBytes = ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
    r.end();
    if (totalBytes > OZZY_JOB_MAX_BYTES || (job.op === 'delete' && totalBytes !== 0)) return null;
    return { job, totalBytes };
  } catch {
    return null;
  }
}

/** 本体の宛先 (Guard が開ける): M1 の peerId 16 ‖ uploadId 16 を Guard の X25519 鍵へ封印 */
export function sealUpHeader(guardEd25519Pub: Uint8Array, middlePeerId: PeerId, uploadId: Uint8Array): Uint8Array {
  const plain = new Uint8Array(16 + OZZY_UPLOAD_ID_BYTES);
  plain.set(Encoding.fromHex(middlePeerId), 0);
  plain.set(uploadId, 16);
  return sodium.crypto_box_seal(plain, sodium.crypto_sign_ed25519_pk_to_curve25519(guardEd25519Pub));
}

function openUpHeader(header: Uint8Array, keys: { pk: Uint8Array; sk: Uint8Array }): { middle: PeerId; uploadId: Uint8Array } | null {
  try {
    const plain = sodium.crypto_box_seal_open(header, keys.pk, keys.sk);
    if (plain.length !== 16 + OZZY_UPLOAD_ID_BYTES) return null;
    return { middle: Encoding.toHex(plain.subarray(0, 16)), uploadId: plain.slice(16) };
  } catch {
    return null;
  }
}

/** 送出の上限 (片/秒)。受け手の RateLimiter.ozzy (3,000/秒) に収める */
export const OZZY_ONION_PACING = {
  /** 1 つの応答 (要求 1 つ) の送出 (片/秒)。600 × 約 4KiB ≒ 2.3MiB/秒。読み手の同時要求 4 本で Guard → 読み手の上限に収まる */
  PER_STREAM_FRAMES_PER_SEC: 600,
  /** 1 つの相手 (M1 → Guard、Guard → 読み手) への送出の合計 (片/秒)。約 10MiB/秒 */
  PER_LINK_FRAMES_PER_SEC: 2500,
  /** DataChannel の送信待ちがこれを超えていたら、減るまで待つ (送り過ぎると Chromium が DataChannel を閉じる) */
  MAX_BUFFERED_BYTES: 1024 * 1024,
  /** 送出の間隔 (ms) */
  PUMP_INTERVAL_MS: 4,
} as const;

type FrameSink = (peerId: PeerId, frame: { seq: number; final: boolean; body: Uint8Array }) => void;

interface PacedStream {
  /** 片の列を作る関数 (seq 番目)。最後なら final */
  piece(seq: number): { body: Uint8Array; final: boolean };
  next: number;
  credit: number;
  send: FrameSink;
  done: () => void;
  /** true を返したら残りを送らずに終える (相手が先に失敗を返したアップロードなど) */
  cancelled?: () => boolean;
}

/**
 * 相手 (隣人) ごとの送出のポンプ。応答ごとに PER_STREAM、相手ごとに PER_LINK の速さを超えないよう、DataChannel の溜まりを
 * 見ながら片を流す。複数の応答は順番に。
 */
class LinkPacer {
  private links = new Map<PeerId, { streams: PacedStream[]; timer: ReturnType<typeof setTimeout> | null; last: number; credit: number }>();
  private destroyed = false;

  constructor(
    private readonly bufferedAmountOf: (peerId: PeerId) => number,
    private readonly now: () => number,
    private readonly perStream: number = OZZY_ONION_PACING.PER_STREAM_FRAMES_PER_SEC,
    private readonly perLink: number = OZZY_ONION_PACING.PER_LINK_FRAMES_PER_SEC,
  ) {}

  public queuedStreams(peerId: PeerId): number {
    return this.links.get(peerId)?.streams.length ?? 0;
  }

  public add(peerId: PeerId, stream: PacedStream): void {
    if (this.destroyed) return stream.done();
    let link = this.links.get(peerId);
    if (!link) {
      link = { streams: [], timer: null, last: this.now(), credit: 0 };
      this.links.set(peerId, link);
    }
    link.streams.push(stream);
    this.pump(peerId);
  }

  private pump(peerId: PeerId): void {
    const link = this.links.get(peerId);
    if (!link || link.timer || link.streams.length === 0 || this.destroyed) return;
    link.timer = setTimeout(() => {
      link.timer = null;
      if (this.destroyed) return;
      const t = this.now();
      const dt = Math.min(250, Math.max(0, t - link.last));
      link.last = t;
      link.credit = Math.min(this.perLink / 4, link.credit + (this.perLink * dt) / 1000);
      for (const s of link.streams) s.credit = Math.min(this.perStream / 4, s.credit + (this.perStream * dt) / 1000);
      if (this.bufferedAmountOf(peerId) <= OZZY_ONION_PACING.MAX_BUFFERED_BYTES) {
        let progressed = true;
        while (link.credit >= 1 && progressed) {
          progressed = false;
          for (const s of [...link.streams]) {
            if (link.credit < 1) break;
            if (s.cancelled?.()) {
              link.streams.splice(link.streams.indexOf(s), 1);
              s.done();
              continue;
            }
            if (s.credit < 1) continue;
            const seq = s.next++;
            const p = s.piece(seq);
            s.send(peerId, { seq, final: p.final, body: p.body });
            s.credit -= 1;
            link.credit -= 1;
            progressed = true;
            if (p.final) {
              link.streams.splice(link.streams.indexOf(s), 1);
              s.done();
            }
          }
        }
      }
      if (link.streams.length === 0) this.links.delete(peerId);
      else this.pump(peerId);
    }, OZZY_ONION_PACING.PUMP_INTERVAL_MS);
  }

  /** その相手への送出を全部やめる (切断) */
  public drop(peerId: PeerId): void {
    const link = this.links.get(peerId);
    if (!link) return;
    if (link.timer) clearTimeout(link.timer);
    for (const s of link.streams) s.done();
    this.links.delete(peerId);
  }

  public destroy(): void {
    this.destroyed = true;
    for (const id of Array.from(this.links.keys())) this.drop(id);
  }
}

type PeerManagerLike = Pick<IPeerManager, 'peers' | 'sendMessage' | 'on' | 'off' | 'myPeerId'> & {
  bufferedAmountOf?(peerId: PeerId): number;
};
type DispatcherLike = IMessageDispatcher & { unregister?(type: number, handler: (peerId: PeerId, payload: any) => void): void };

// ── 出口 (M1): 回路の先で要求を受け、ロッカーから取って Guard へ返す ──

export const ONION_EXIT_LIMITS = {
  /** 1 つの Guard (= その利用者たちの束) から受け付ける要求の頻度・同時数 */
  PER_GUARD_REQ_PER_SEC: 16,
  PER_GUARD_REQ_BURST: 32,
  PER_GUARD_CONCURRENT: 16,
  /** ロッカーへの作業 (Slab 1 本 = 最大 64 MiB をメモリに持つ) の同時数: Guard ごと / 全体 */
  JOBS_PER_GUARD: 2,
  JOBS_TOTAL: 4,
  /** 作業の本体が途切れたまま待つ上限 */
  JOB_INACTIVITY_MS: 60_000,
  /** 作業 (ロッカーへの PUT) にかけてよい時間 */
  JOB_RUN_MS: 180_000,
  /**
   * 要求 (回路のセル) より先に届いた本体の片を溜めておく上限: Guard ごと・全体のバイト数と時間。
   * ★ 告発者は要求を送り出してから本体を流すので、追い越すのは最初の数片だけ。大きくすると、隣人が
   *   宛先の無い片を送りつけてメモリを使わせられる
   */
  EARLY_BYTES_PER_GUARD: 4 * 1024 * 1024,
  EARLY_BYTES_TOTAL: 16 * 1024 * 1024,
  EARLY_TTL_MS: 15_000,
} as const;

interface ExitJob {
  key: string;
  guardId: PeerId;
  job: OzzyLockerJob;
  totalBytes: number;
  header: Uint8Array;
  respKey: Uint8Array;
  upKey: Uint8Array;
  parts: Map<number, Uint8Array>;
  bytes: number;
  finalSeq: number;
  bad: number;
  timer: ReturnType<typeof setTimeout> | null;
  running: boolean;
}

/**
 * OzzyOnionExit — 全ノードが持つ M1 の役。オニオン回路で届いた Ozzy の取得要求に答える。
 *
 * ★ 見えるのは「送ってきた Guard」と URL・範囲だけ。読み手の peerId は返送先 (Guard 宛ての封印) の中で、開けられない。
 * ★ 応答は片ごとに読み手の鍵 (respKey) で暗号化してから Guard へ返す。Guard には中身が見えない。
 * ★ 取った中身・鍵はメモリだけ。送り終えたらゼロで埋めて捨てる。
 */
export class OzzyOnionExit {
  private pacer: LinkPacer;
  private buckets = new Map<PeerId, { tokens: number; last: number }>();
  private active = new Map<PeerId, number>();
  private jobs = new Map<string, ExitJob>();
  private jobsPerGuard = new Map<PeerId, number>();
  private early = new Map<string, { guardId: PeerId; frames: Array<{ seq: number; final: boolean; body: Uint8Array }>; bytes: number; at: number }>();
  private destroyed = false;
  private readonly now: () => number;
  private readonly dispatcher: DispatcherLike | null;
  private jobRunner: OzzyLockerJobRunner | null;
  private readonly onDisconnect = (peerId: PeerId) => {
    this.pacer.drop(peerId);
    for (const j of Array.from(this.jobs.values())) if (j.guardId === peerId) this.dropJob(j);
  };
  private readonly onUpFwd = (from: PeerId, msg: any) => this.handleUpFwd(from, msg);

  /** 診断・テスト用 */
  public readonly stats = { requests: 0, rejected: 0, framesSent: 0, jobs: 0, jobsDone: 0, guardsSeen: new Set<PeerId>() };

  constructor(
    private readonly peerManager: PeerManagerLike,
    circuit: { onDirectExit(kind: number, handler: (body: Uint8Array, guardId: PeerId) => void): void },
    /** null なら取得役を止めている (REFUSED を返す)。後から setServer で替えられる */
    private server: OzzyRangeServer | null,
    opts: { now?: () => number; dispatcher?: DispatcherLike; jobRunner?: OzzyLockerJobRunner | null } = {},
  ) {
    this.now = opts.now ?? Date.now;
    this.dispatcher = opts.dispatcher ?? null;
    this.jobRunner = opts.jobRunner ?? null;
    this.pacer = new LinkPacer((id) => peerManager.bufferedAmountOf?.(id) ?? 0, this.now);
    circuit.onDirectExit(OZZY_ONION_KIND, (body, guardId) => this.handle(body, guardId));
    circuit.onDirectExit(OZZY_ONION_JOB_KIND, (body, guardId) => this.handleJob(body, guardId));
    this.dispatcher?.register(WireType.OZZY_UP_FWD, this.onUpFwd);
    peerManager.on('peer:disconnect', this.onDisconnect);
  }

  /**
   * 取得役を始める・止める (null で止める。Ozzy の中継 Worker を設定するまでは止めておく)。
   * jobRunner はロッカーへの作業 (アップロード・削除) を引き受ける関数 (省略なら今のまま)。
   */
  public setServer(server: OzzyRangeServer | null, jobRunner?: OzzyLockerJobRunner | null): void {
    if (this.server && this.server !== server) this.server.destroy();
    this.server = server;
    if (jobRunner !== undefined) this.jobRunner = jobRunner;
  }

  /** 取得役として動いているか */
  public get serving(): boolean {
    return this.server !== null;
  }

  private take(guardId: PeerId): boolean {
    const t = this.now();
    let b = this.buckets.get(guardId);
    if (!b) {
      b = { tokens: ONION_EXIT_LIMITS.PER_GUARD_REQ_BURST, last: t };
      this.buckets.set(guardId, b);
      if (this.buckets.size > 4096) this.buckets.delete(this.buckets.keys().next().value!);
    }
    b.tokens = Math.min(ONION_EXIT_LIMITS.PER_GUARD_REQ_BURST, b.tokens + (Math.max(0, t - b.last) / 1000) * ONION_EXIT_LIMITS.PER_GUARD_REQ_PER_SEC);
    b.last = t;
    if (b.tokens < 1) return false;
    b.tokens -= 1;
    return true;
  }

  private handle(body: Uint8Array, guardId: PeerId): void {
    if (this.destroyed) return;
    if (body.length <= OZZY_REPLY_HEADER_BYTES + RESP_KEY_BYTES) return;
    this.stats.requests++;
    if (this.stats.guardsSeen.size < 64) this.stats.guardsSeen.add(guardId);
    const header = body.slice(0, OZZY_REPLY_HEADER_BYTES);
    const respKey = body.slice(OZZY_REPLY_HEADER_BYTES, OZZY_REPLY_HEADER_BYTES + RESP_KEY_BYTES);
    const request = body.subarray(OZZY_REPLY_HEADER_BYTES + RESP_KEY_BYTES);

    const reply = (payload: Uint8Array) => this.stream(guardId, header, respKey, payload);
    if (!this.server) {
      this.stats.rejected++;
      return reply(encodeRangeResponse(OZZY_MESH_STATUS.REFUSED));
    }
    if (!this.take(guardId) || (this.active.get(guardId) ?? 0) >= ONION_EXIT_LIMITS.PER_GUARD_CONCURRENT) {
      this.stats.rejected++;
      return reply(encodeRangeResponse(OZZY_MESH_STATUS.BUSY));
    }
    this.active.set(guardId, (this.active.get(guardId) ?? 0) + 1);
    void this.server.serve(request).then(
      (payload) => this.stream(guardId, header, respKey, payload, () => this.release(guardId)),
      () => {
        this.release(guardId);
        respKey.fill(0);
      },
    );
  }

  // ── ロッカーへの作業 (アップロード・削除) ──

  private jobKey(guardId: PeerId, uploadId: Uint8Array): string {
    return `${guardId}:${Encoding.toHex(uploadId)}`;
  }

  private handleJob(body: Uint8Array, guardId: PeerId): void {
    if (this.destroyed) return;
    const fixed = OZZY_REPLY_HEADER_BYTES + RESP_KEY_BYTES + RESP_KEY_BYTES + OZZY_UPLOAD_ID_BYTES;
    if (body.length <= fixed) return;
    this.stats.requests++;
    const header = body.slice(0, OZZY_REPLY_HEADER_BYTES);
    const respKey = body.slice(OZZY_REPLY_HEADER_BYTES, OZZY_REPLY_HEADER_BYTES + RESP_KEY_BYTES);
    const upKey = body.slice(OZZY_REPLY_HEADER_BYTES + RESP_KEY_BYTES, OZZY_REPLY_HEADER_BYTES + 2 * RESP_KEY_BYTES);
    const uploadId = body.slice(OZZY_REPLY_HEADER_BYTES + 2 * RESP_KEY_BYTES, fixed);
    const decoded = decodeLockerJob(body.subarray(fixed));
    const reply = (status: OzzyMeshStatus) => {
      upKey.fill(0);
      this.stream(guardId, header, respKey, encodeRangeResponse(status));
    };
    if (!this.jobRunner || !this.server) {
      this.stats.rejected++;
      return reply(OZZY_MESH_STATUS.REFUSED);
    }
    if (!decoded) {
      this.stats.rejected++;
      return reply(OZZY_MESH_STATUS.REFUSED);
    }
    const key = this.jobKey(guardId, uploadId);
    if (
      this.jobs.has(key) || !this.take(guardId) ||
      (this.jobsPerGuard.get(guardId) ?? 0) >= ONION_EXIT_LIMITS.JOBS_PER_GUARD || this.jobs.size >= ONION_EXIT_LIMITS.JOBS_TOTAL
    ) {
      this.stats.rejected++;
      return reply(OZZY_MESH_STATUS.BUSY);
    }
    this.stats.jobs++;
    const job: ExitJob = {
      key, guardId, job: decoded.job, totalBytes: decoded.totalBytes, header, respKey, upKey,
      parts: new Map(), bytes: 0, finalSeq: -1, bad: 0, timer: null, running: false,
    };
    this.jobs.set(key, job);
    this.jobsPerGuard.set(guardId, (this.jobsPerGuard.get(guardId) ?? 0) + 1);
    this.armJob(job);
    if (decoded.totalBytes === 0) return void this.runJob(job, new Uint8Array(0));
    // 要求より先に届いていた本体の片を取り込む
    const early = this.early.get(key);
    if (early) {
      this.early.delete(key);
      for (const f of early.frames) this.acceptPiece(job, f.seq, f.final, f.body);
    }
  }

  private armJob(job: ExitJob): void {
    if (job.timer) clearTimeout(job.timer);
    job.timer = setTimeout(() => this.failJob(job), ONION_EXIT_LIMITS.JOB_INACTIVITY_MS);
  }

  private handleUpFwd(from: PeerId, msg: any): void {
    if (this.destroyed) return;
    const { uploadId, seq, final, body } = msg ?? {};
    if (!(uploadId instanceof Uint8Array) || !(body instanceof Uint8Array) || !Number.isInteger(seq)) return;
    const key = this.jobKey(from, uploadId);
    const job = this.jobs.get(key);
    if (job) return this.acceptPiece(job, seq, final === true, body);
    // 要求 (オニオンのセル) より先に本体が届くことがある: Guard ごとの上限内で少しだけ溜める
    const t = this.now();
    for (const [k, e] of this.early) if (t - e.at > ONION_EXIT_LIMITS.EARLY_TTL_MS) this.early.delete(k);
    let used = 0;
    let total = 0;
    for (const e of this.early.values()) {
      total += e.bytes;
      if (e.guardId === from) used += e.bytes;
    }
    if (used + body.length > ONION_EXIT_LIMITS.EARLY_BYTES_PER_GUARD || total + body.length > ONION_EXIT_LIMITS.EARLY_BYTES_TOTAL) return;
    const e = this.early.get(key) ?? { guardId: from, frames: [], bytes: 0, at: t };
    e.frames.push({ seq, final: final === true, body });
    e.bytes += body.length;
    this.early.set(key, e);
  }

  private acceptPiece(job: ExitJob, seq: number, _final: boolean, body: Uint8Array): void {
    if (job.running) return;
    const dec = decryptChunk(job.upKey, OZZY_UP_AEAD_KIND, seq, body);
    if (!dec) {
      if (++job.bad >= 3) this.failJob(job);
      return;
    }
    if (job.parts.has(seq)) return;
    const maxPieces = Math.max(1, Math.ceil(job.totalBytes / OZZY_UP_PIECE_BYTES));
    // ★ 最後の印は暗号文の中の値を使う。片の数・大きさが宣言を超えたら打ち切る (際限なく送りつけてメモリを使わせない)
    if ((job.finalSeq >= 0 && seq > job.finalSeq) || seq >= maxPieces) return this.failJob(job);
    if (dec.final) {
      if ([...job.parts.keys()].some(s => s > seq)) return this.failJob(job);
      job.finalSeq = seq;
    }
    job.parts.set(seq, dec.data);
    job.bytes += dec.data.length;
    if (job.bytes > job.totalBytes) return this.failJob(job);
    this.armJob(job);
    if (job.finalSeq >= 0 && job.parts.size === job.finalSeq + 1) {
      if (job.bytes !== job.totalBytes) return this.failJob(job);
      const data = new Uint8Array(job.bytes);
      let o = 0;
      for (let i = 0; i <= job.finalSeq; i++) {
        const part = job.parts.get(i)!;
        data.set(part, o);
        o += part.length;
        part.fill(0);
      }
      job.parts.clear();
      void this.runJob(job, data);
    }
  }

  private async runJob(job: ExitJob, data: Uint8Array): Promise<void> {
    job.running = true;
    if (job.timer) clearTimeout(job.timer);
    job.timer = null;
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), ONION_EXIT_LIMITS.JOB_RUN_MS);
    let result: Uint8Array | null = null;
    try {
      result = this.jobRunner ? await this.jobRunner(job.job, data, ac.signal) : null;
    } catch {
      result = null;
    } finally {
      clearTimeout(timer);
      data.fill(0);
    }
    if (this.destroyed) return this.dropJob(job);
    this.stats.jobsDone++;
    const payload = result ? encodeRangeResponse(OZZY_MESH_STATUS.OK, result) : encodeRangeResponse(OZZY_MESH_STATUS.FETCH_ERROR);
    const { guardId, header, respKey } = job;
    this.dropJob(job, false);
    this.stream(guardId, header, respKey, payload);
  }

  private failJob(job: ExitJob): void {
    if (!this.jobs.has(job.key)) return;
    const { guardId, header, respKey } = job;
    this.dropJob(job, false);
    this.stream(guardId, header, respKey, encodeRangeResponse(OZZY_MESH_STATUS.FETCH_ERROR));
  }

  /** 作業の状態を捨てる (鍵・溜めた片はゼロで埋める)。zeroResp = 応答の鍵も消す (応答を返さないとき) */
  private dropJob(job: ExitJob, zeroResp = true): void {
    if (!this.jobs.delete(job.key)) return;
    if (job.timer) clearTimeout(job.timer);
    for (const p of job.parts.values()) p.fill(0);
    job.parts.clear();
    job.upKey.fill(0);
    if (zeroResp) job.respKey.fill(0);
    const n = (this.jobsPerGuard.get(job.guardId) ?? 1) - 1;
    if (n <= 0) this.jobsPerGuard.delete(job.guardId);
    else this.jobsPerGuard.set(job.guardId, n);
  }

  private release(guardId: PeerId): void {
    const n = (this.active.get(guardId) ?? 1) - 1;
    if (n <= 0) this.active.delete(guardId);
    else this.active.set(guardId, n);
  }

  private stream(guardId: PeerId, header: Uint8Array, respKey: Uint8Array, payload: Uint8Array, onDone?: () => void): void {
    if (this.destroyed) {
      respKey.fill(0);
      return onDone?.();
    }
    const pieces = Math.max(1, Math.ceil(payload.length / OZZY_REPLY_PIECE_BYTES));
    this.pacer.add(guardId, {
      next: 0,
      credit: 0,
      piece: (seq) => {
        const final = seq === pieces - 1;
        const data = payload.subarray(seq * OZZY_REPLY_PIECE_BYTES, Math.min(payload.length, (seq + 1) * OZZY_REPLY_PIECE_BYTES));
        return { final, body: encryptChunk(respKey, OZZY_REPLY_AEAD_KIND, seq, final, data) };
      },
      send: (to, f) => {
        this.stats.framesSent++;
        this.peerManager.sendMessage(to, WireType.OZZY_REPLY, { header, seq: f.seq, final: f.final, body: f.body });
      },
      done: () => {
        payload.fill(0);
        respKey.fill(0);
        onDone?.();
      },
    });
  }

  public destroy(): void {
    this.destroyed = true;
    this.server?.destroy();
    for (const j of Array.from(this.jobs.values())) this.dropJob(j);
    this.early.clear();
    this.pacer.destroy();
    this.peerManager.off('peer:disconnect', this.onDisconnect);
    this.dispatcher?.unregister?.(WireType.OZZY_UP_FWD, this.onUpFwd);
  }
}

// ── Guard: M1 からの応答を、返送先 (封印) を開けて読み手へ流す ──

export const ONION_RELAY_LIMITS = {
  /** 開けた返送先の覚えておく数と時間 (同じ応答の片ごとに封印を開け直さない) */
  ROUTE_CACHE: 4096,
  ROUTE_TTL_MS: 120_000,
  /** 開けられなかった返送先を覚えておく数 (同じゴミで何度も CPU を使わせない) */
  BAD_CACHE: 1024,
  /** 1 人の読み手宛てに溜めておく片の数の上限 (約 16MiB)。超えた片は捨てる (その要求は読み手側で失敗・やり直し) */
  MAX_QUEUED_PER_READER: 4096,
  /** アップロードの中継で、1 人の送り手から 1 つの M1 宛てに溜めておく片の数の上限 (約 4MiB) */
  MAX_QUEUED_PER_UPLOADER: 1024,
} as const;

/** 送り出した直後に呼ぶ関数を、送る msg に隠して持たせる (WireCodec は知らないキーを無視する) */
const SENT_HOOK = Symbol('ozzySent');

/**
 * OzzyOnionReplyRelay — 全ノードが持つ Guard の役。M1 から届いた OZZY_REPLY の返送先を自分の鍵で開け、
 * 読み手 (自分の隣人) へ OZZY_RESULT として流す。
 *
 * ★ Guard に分かるのは「この隣人宛ての応答がこの M1 から来た」ことと量だけ。中身は読み手の鍵で暗号化されている。
 *   URL・範囲は M1 宛ての封印の中で、Guard は回路の要求を開けられない。
 * ★ 読み手宛ての送出は読み手ごとに絞る (受け手の RateLimiter.ozzy を超えると片が捨てられ、取得ごと失敗する)。
 */
export class OzzyOnionReplyRelay {
  private routes = new Map<string, { reader: PeerId; replyId: number; at: number }>();
  private upRoutes = new Map<string, { middle: PeerId; uploadId: Uint8Array; at: number }>();
  private bad = new Set<string>();
  private queues = new Map<PeerId, { frames: Array<{ type: WireType; msg: object }>; timer: ReturnType<typeof setTimeout> | null; last: number; credit: number }>();
  /** アップロードの中継: 送り手 → M1 ごとの溜まり具合 (1 人の送り手が M1 宛ての枠を食い尽くさない) */
  private upQueued = new Map<string, number>();
  private curveKeys: { pk: Uint8Array; sk: Uint8Array } | null = null;
  private destroyed = false;
  private readonly onReply = (from: PeerId, msg: any) => this.handleReply(from, msg);
  private readonly onUp = (from: PeerId, msg: any) => this.handleUp(from, msg);
  private readonly onDisconnect = (peerId: PeerId) => {
    const q = this.queues.get(peerId);
    if (q?.timer) clearTimeout(q.timer);
    this.queues.delete(peerId);
  };

  /** 診断・テスト用 */
  public readonly stats = { forwarded: 0, upForwarded: 0, dropped: { badHeader: 0, noReader: 0, full: 0 } };

  constructor(
    private readonly peerManager: PeerManagerLike,
    private readonly dispatcher: DispatcherLike,
    /** 自分の Ed25519 鍵 (返送先は X25519 に変換した鍵で開ける) */
    private readonly identity: { readonly pubkey: Uint8Array; exportSecret(): { pubkey: Uint8Array; privkey: Uint8Array } },
    private readonly now: () => number = Date.now,
  ) {
    dispatcher.register(WireType.OZZY_REPLY, this.onReply);
    dispatcher.register(WireType.OZZY_UP, this.onUp);
    peerManager.on('peer:disconnect', this.onDisconnect);
  }

  private keys(): { pk: Uint8Array; sk: Uint8Array } {
    if (!this.curveKeys) {
      const secret = this.identity.exportSecret();
      this.curveKeys = {
        pk: sodium.crypto_sign_ed25519_pk_to_curve25519(secret.pubkey),
        sk: sodium.crypto_sign_ed25519_sk_to_curve25519(secret.privkey),
      };
    }
    return this.curveKeys;
  }

  private route(header: Uint8Array): { reader: PeerId; replyId: number } | null {
    const key = Encoding.toHex(header);
    const t = this.now();
    const hit = this.routes.get(key);
    if (hit && t - hit.at < ONION_RELAY_LIMITS.ROUTE_TTL_MS) return hit;
    if (this.bad.has(key)) return null;
    const opened = openReplyHeader(header, this.keys());
    if (!opened) {
      this.bad.add(key);
      if (this.bad.size > ONION_RELAY_LIMITS.BAD_CACHE) this.bad.delete(this.bad.values().next().value!);
      return null;
    }
    this.routes.set(key, { ...opened, at: t });
    if (this.routes.size > ONION_RELAY_LIMITS.ROUTE_CACHE) this.routes.delete(this.routes.keys().next().value!);
    return opened;
  }

  private handleReply(from: PeerId, msg: any): void {
    if (this.destroyed) return;
    const { header, seq, final, body } = msg ?? {};
    if (!(header instanceof Uint8Array) || !(body instanceof Uint8Array) || !Number.isInteger(seq)) return;
    const r = this.route(header);
    if (!r) {
      this.stats.dropped.badHeader++;
      return;
    }
    // 読み手は自分の検証済みの隣人で、応答を送ってきた M1 本人ではないこと (反射させない)
    const peer = this.peerManager.peers.get(r.reader);
    if (r.reader === from || !peer || !peer.isConnected || !peer.isVerified) {
      this.stats.dropped.noReader++;
      return;
    }
    if (!this.enqueue(r.reader, WireType.OZZY_RESULT, { replyId: r.replyId, seq, final: final === true, body })) {
      this.stats.dropped.full++;
    }
  }

  private upRoute(header: Uint8Array): { middle: PeerId; uploadId: Uint8Array } | null {
    const key = Encoding.toHex(header);
    const t = this.now();
    const hit = this.upRoutes.get(key);
    if (hit && t - hit.at < ONION_RELAY_LIMITS.ROUTE_TTL_MS) {
      hit.at = t;
      return hit;
    }
    if (this.bad.has(key)) return null;
    const opened = openUpHeader(header, this.keys());
    if (!opened) {
      this.bad.add(key);
      if (this.bad.size > ONION_RELAY_LIMITS.BAD_CACHE) this.bad.delete(this.bad.values().next().value!);
      return null;
    }
    this.upRoutes.set(key, { ...opened, at: t });
    if (this.upRoutes.size > ONION_RELAY_LIMITS.ROUTE_CACHE) this.upRoutes.delete(this.upRoutes.keys().next().value!);
    return opened;
  }

  /**
   * 回路の利用者 (自分の隣人) から M1 宛ての本体の片。宛先 (自分宛ての封印) を開け、M1 へ OZZY_UP_FWD として流す。
   * ★ Guard に分かるのは「この隣人がこの M1 へこれだけ送った」ことだけ。片は告発者と M1 の鍵で暗号化されている。
   */
  private handleUp(from: PeerId, msg: any): void {
    if (this.destroyed) return;
    const { header, seq, final, body } = msg ?? {};
    if (!(header instanceof Uint8Array) || !(body instanceof Uint8Array) || !Number.isInteger(seq)) return;
    const sender = this.peerManager.peers.get(from);
    if (!sender?.isConnected || !sender.isVerified) return;
    const r = this.upRoute(header);
    if (!r) {
      this.stats.dropped.badHeader++;
      return;
    }
    const peer = this.peerManager.peers.get(r.middle);
    if (r.middle === from || r.middle === this.peerManager.myPeerId || !peer || !peer.isConnected || !peer.isVerified) {
      this.stats.dropped.noReader++;
      return;
    }
    const pair = `${from}>${r.middle}`;
    const queued = this.upQueued.get(pair) ?? 0;
    if (queued >= ONION_RELAY_LIMITS.MAX_QUEUED_PER_UPLOADER) {
      this.stats.dropped.full++;
      return;
    }
    const ok = this.enqueue(r.middle, WireType.OZZY_UP_FWD, { uploadId: r.uploadId, seq, final: final === true, body }, () => {
      const n = (this.upQueued.get(pair) ?? 1) - 1;
      if (n <= 0) this.upQueued.delete(pair);
      else this.upQueued.set(pair, n);
    });
    if (!ok) {
      this.stats.dropped.full++;
      return;
    }
    this.upQueued.set(pair, queued + 1);
  }

  private enqueue(to: PeerId, type: WireType, msg: object, onSent?: () => void): boolean {
    let q = this.queues.get(to);
    if (!q) {
      q = { frames: [], timer: null, last: this.now(), credit: 0 };
      this.queues.set(to, q);
    }
    if (q.frames.length >= ONION_RELAY_LIMITS.MAX_QUEUED_PER_READER) return false;
    q.frames.push({ type, msg: onSent ? Object.assign(msg, { [SENT_HOOK]: onSent }) : msg });
    this.pump(to);
    return true;
  }

  private pump(reader: PeerId): void {
    const q = this.queues.get(reader);
    if (!q || q.timer || q.frames.length === 0 || this.destroyed) return;
    // ★ 送り先ごとに 1 本の列 (応答の片と本体の片が同じ隣人宛てなら同じ枠を分け合う)
    q.timer = setTimeout(() => {
      q.timer = null;
      if (this.destroyed) return;
      const t = this.now();
      const dt = Math.min(250, Math.max(0, t - q.last));
      q.last = t;
      q.credit = Math.min(OZZY_ONION_PACING.PER_LINK_FRAMES_PER_SEC / 4, q.credit + (OZZY_ONION_PACING.PER_LINK_FRAMES_PER_SEC * dt) / 1000);
      if ((this.peerManager.bufferedAmountOf?.(reader) ?? 0) <= OZZY_ONION_PACING.MAX_BUFFERED_BYTES) {
        while (q.credit >= 1 && q.frames.length > 0) {
          const f = q.frames.shift()!;
          const hook = (f.msg as any)[SENT_HOOK] as (() => void) | undefined;
          this.peerManager.sendMessage(reader, f.type, f.msg);
          hook?.();
          if (f.type === WireType.OZZY_UP_FWD) this.stats.upForwarded++;
          else this.stats.forwarded++;
          q.credit -= 1;
        }
      }
      if (q.frames.length === 0) this.queues.delete(reader);
      else this.pump(reader);
    }, OZZY_ONION_PACING.PUMP_INTERVAL_MS);
  }

  public destroy(): void {
    this.destroyed = true;
    for (const q of this.queues.values()) if (q.timer) clearTimeout(q.timer);
    this.queues.clear();
    this.routes.clear();
    this.upRoutes.clear();
    this.upQueued.clear();
    this.curveKeys?.sk.fill(0);
    this.curveKeys = null;
    this.peerManager.off('peer:disconnect', this.onDisconnect);
    this.dispatcher.unregister?.(WireType.OZZY_REPLY, this.onReply);
    this.dispatcher.unregister?.(WireType.OZZY_UP, this.onUp);
  }
}

// ── 読み手 (R) の側 ──

export const MESH_FETCH_LIMITS = {
  /** 1 本目を送ってから、まだ終わらなければ別の M1 へも頼むまで */
  HEDGE_MS: 10_000,
  /** 送り出してから応答の片が 1 つも届かないまま待つ上限 (M1 がロッカーから取り終えるまで最初の片は来ない) */
  INACTIVITY_MS: 30_000,
  /** 1 つの範囲に同時に頼む本数 (保険を含む) */
  MAX_PARALLEL: 2,
  /** 1 つの範囲で頼む回数の上限 */
  MAX_ATTEMPTS: 5,
  /** この数の M1 が「無い (NOT_FOUND)」と言ったら、そのロッカーには無いと見なして諦める */
  NOT_FOUND_QUORUM: 2,
  /** 偽物・失敗を返した M1 を避けておく時間 (回路の M1 選びから外す) */
  AVOID_MS: 10 * 60_000,
} as const;

export interface MeshFetcherParts {
  circuit: {
    readonly routeReady: boolean;
    readonly middleCandidateCount: number;
    readonly currentGuardHop: { peerId: PeerId; pubkey: Uint8Array } | null;
    sendDirect(kind: number, body: Uint8Array, exclude?: ReadonlySet<PeerId>): Promise<{ ok: true; guardId: PeerId; middleId: PeerId } | { ok: false }>;
  };
  peerManager: Pick<IPeerManager, 'myPeerId' | 'on' | 'off' | 'sendMessage'> & { bufferedAmountOf?(peerId: PeerId): number };
  dispatcher: DispatcherLike;
  now?: () => number;
  /** ★ テスト専用 */
  limits?: Partial<{ hedgeMs: number; inactivityMs: number; maxParallel: number; maxAttempts: number; notFoundQuorum: number }>;
}

export type MeshFetchResult =
  | { ok: true; data: Uint8Array }
  | { ok: false; reason: 'aborted' | 'no-fetchers' | 'not-found' | 'unavailable' };

export type MeshJobResult =
  | { ok: true; result: Uint8Array; middle: PeerId }
  | { ok: false; reason: 'aborted' | 'no-fetchers' | 'failed' };

/** 作業の結果 (受け取り票の JSON) の上限 */
const OZZY_JOB_RESULT_MAX_BYTES = 16 * 1024;
/** 本体を送り終えてから結果を待つ上限 (M1 がロッカーへ PUT する時間 + 余裕) */
const OZZY_JOB_WAIT_MS = ONION_EXIT_LIMITS.JOB_RUN_MS + 30_000;

type AttemptOutcome =
  | { kind: 'ok'; data: Uint8Array; middle: PeerId }
  | { kind: 'not-found' | 'busy' | 'failed' | 'unsupported'; middle?: PeerId };

interface PendingReply {
  guardId: PeerId;
  respKey: Uint8Array;
  maxBytes: number;
  maxPieces: number;
  parts: Map<number, Uint8Array>;
  bytes: number;
  finalSeq: number;
  bad: number;
  timer: ReturnType<typeof setTimeout> | null;
  /** 応答の片を待つ上限 (省略なら inactivityMs) */
  waitMs?: number;
  done: (payload: Uint8Array | null) => void;
}

/**
 * OzzyMeshFetcher — 読み手の側。1 つの範囲 (= 1 チャンク) を、オニオン回路 (自分 → Guard → M1) の M1 に取ってもらう。
 *
 *   要求: 自分の Guard 宛てに返送先 (自分の peerId ‖ replyId) を封印し、要求ごとの鍵 respKey と一緒に回路で M1 へ送る
 *         (cover traffic と同じ送出枠。Guard には cover と区別が付かない)
 *   応答: M1 → Guard (OZZY_REPLY) → 自分 (OZZY_RESULT)。片ごとに respKey で復号し、最後の片の印 (暗号文の中) まで揃えて組み立てる
 *
 * ★ 回路は 3 枠ごとに M1 を替えるので、続けて出す要求は自然に多くの M1 に散る (並列)。遅ければ別の M1 へ保険の要求を出す。
 * ★ M1 に見えるのは Guard と URL・範囲だけ。Guard に見えるのは自分と M1 と量だけ (URL は M1 宛ての封印の中)。
 *   Guard と M1 が結託すれば分かる (Tor の 2 ホップと同じ限界)。
 * ★ 取ったデータの検証は呼び出し側の accept (長さ・tag・Manifest のハッシュ)。通らなければ、その M1 をしばらく避けて取り直す。
 * ★ 記録はメモリだけ。ディスクには何も書かない。
 */
export class OzzyMeshFetcher {
  private readonly now: () => number;
  private readonly lim: { hedgeMs: number; inactivityMs: number; maxParallel: number; maxAttempts: number; notFoundQuorum: number };
  private pending = new Map<number, PendingReply>();
  private avoid = new Map<PeerId, number>();
  private readonly upPacer: LinkPacer;
  private destroyed = false;
  private readonly onResult = (from: PeerId, msg: any) => this.handleResult(from, msg);
  private readonly onDisconnect = (peerId: PeerId) => {
    for (const [id, p] of Array.from(this.pending)) if (p.guardId === peerId) this.finishPending(id, null);
  };

  /** 診断・テスト用 */
  public readonly stats = {
    ranges: 0, attempts: 0, hedges: 0, notFound: 0, rejected: 0, busy: 0, failed: 0, ok: 0, jobs: 0, jobsOk: 0, upFrames: 0,
    middlesUsed: new Set<PeerId>(),
  };

  constructor(private readonly parts: MeshFetcherParts) {
    this.now = parts.now ?? Date.now;
    this.upPacer = new LinkPacer((id) => parts.peerManager.bufferedAmountOf?.(id) ?? 0, this.now);
    const l = parts.limits ?? {};
    this.lim = {
      hedgeMs: l.hedgeMs ?? MESH_FETCH_LIMITS.HEDGE_MS,
      inactivityMs: l.inactivityMs ?? MESH_FETCH_LIMITS.INACTIVITY_MS,
      maxParallel: l.maxParallel ?? MESH_FETCH_LIMITS.MAX_PARALLEL,
      maxAttempts: l.maxAttempts ?? MESH_FETCH_LIMITS.MAX_ATTEMPTS,
      notFoundQuorum: l.notFoundQuorum ?? MESH_FETCH_LIMITS.NOT_FOUND_QUORUM,
    };
    parts.dispatcher.register(WireType.OZZY_RESULT, this.onResult);
    parts.peerManager.on('peer:disconnect', this.onDisconnect);
  }

  /** 回路が組めるか (Guard と M1 の候補がいる) */
  public get ready(): boolean {
    return this.parts.circuit.routeReady;
  }

  /** 頼める M1 の候補の数 (Guard の隣人) */
  public get fetcherCount(): number {
    return this.parts.circuit.middleCandidateCount;
  }

  private avoided(): Set<PeerId> {
    const t = this.now();
    const out = new Set<PeerId>();
    for (const [id, until] of this.avoid) {
      if (until > t) out.add(id);
      else this.avoid.delete(id);
    }
    return out;
  }

  /**
   * 範囲を取る。`accept(data)` が true を返したら完了 (呼び出し側がその data を使う)。
   * 回路が組めなければ 'no-fetchers'、NOT_FOUND_QUORUM 本が「無い」と言えば 'not-found'。
   */
  public fetchRange(
    req: OzzyRangeRequest, accept: (data: Uint8Array) => boolean | Promise<boolean>, signal?: AbortSignal,
  ): Promise<MeshFetchResult> {
    this.stats.ranges++;
    let payload: Uint8Array;
    try {
      payload = encodeRangeRequest(req);
    } catch {
      return Promise.resolve({ ok: false, reason: 'unavailable' });
    }
    if (!this.ready) return Promise.resolve({ ok: false, reason: 'no-fetchers' });

    return new Promise<MeshFetchResult>((resolve) => {
      let active = 0;
      let attempts = 0;
      let notFound = 0;
      let done = false;
      let hedge: ReturnType<typeof setTimeout> | null = null;
      const usedMiddles = new Set<PeerId>();
      const ac = new AbortController();

      const finish = (res: MeshFetchResult) => {
        if (done) return;
        done = true;
        if (hedge) clearTimeout(hedge);
        signal?.removeEventListener('abort', onAbort);
        ac.abort();
        resolve(res);
      };
      const onAbort = () => finish({ ok: false, reason: 'aborted' });
      signal?.addEventListener('abort', onAbort, { once: true });
      if (signal?.aborted) return finish({ ok: false, reason: 'aborted' });

      const canLaunch = () => attempts < this.lim.maxAttempts;
      const launch = (): void => {
        if (done || !canLaunch()) return;
        attempts++;
        active++;
        this.stats.attempts++;
        const exclude = new Set([...usedMiddles, ...this.avoided()]);
        void this.attempt(payload, req, accept, exclude, ac.signal, () => done, (m) => usedMiddles.add(m)).then((outcome) => {
          active--;
          if (done) return;
          if (outcome.kind === 'ok') {
            this.stats.ok++;
            return finish({ ok: true, data: outcome.data });
          }
          if (outcome.kind === 'not-found' && ++notFound >= this.lim.notFoundQuorum) {
            return finish({ ok: false, reason: 'not-found' });
          }
          if (active < 1 && canLaunch()) return launch();
          if (active === 0) {
            this.stats.failed++;
            finish({ ok: false, reason: notFound > 0 ? 'not-found' : 'unavailable' });
          }
        });
      };
      const armHedge = () => {
        hedge = setTimeout(() => {
          hedge = null;
          if (done) return;
          if (active < this.lim.maxParallel && canLaunch()) {
            this.stats.hedges++;
            launch();
          }
          if (canLaunch()) armHedge();
        }, this.lim.hedgeMs);
      };
      launch();
      armHedge();
    });
  }

  private newReplyId(): number {
    for (let i = 0; i < 16; i++) {
      const id = sodium.randombytes_random() >>> 0;
      if (id !== 0 && !this.pending.has(id)) return id;
    }
    return 0;
  }

  private async attempt(
    payload: Uint8Array, req: OzzyRangeRequest, accept: (data: Uint8Array) => boolean | Promise<boolean>,
    exclude: ReadonlySet<PeerId>, signal: AbortSignal, isDone: () => boolean, onMiddle: (m: PeerId) => void,
  ): Promise<AttemptOutcome> {
    const guard = this.parts.circuit.currentGuardHop;
    const replyId = this.newReplyId();
    if (!guard || replyId === 0 || this.destroyed) return { kind: 'failed' };
    const respKey = sodium.randombytes_buf(RESP_KEY_BYTES);
    const header = sealReplyHeader(guard.pubkey, this.parts.peerManager.myPeerId, replyId);
    const body = new Uint8Array(header.length + RESP_KEY_BYTES + payload.length);
    body.set(header, 0);
    body.set(respKey, header.length);
    body.set(payload, header.length + RESP_KEY_BYTES);

    // 応答を受ける準備を先にしてから送る (送り出しの直後に片が届いても取りこぼさない)
    const maxBytes = 1 + req.length;
    const result = new Promise<Uint8Array | null>((resolve) => {
      const p: PendingReply = {
        guardId: guard.peerId, respKey, maxBytes, maxPieces: Math.ceil(maxBytes / OZZY_REPLY_PIECE_BYTES) + 1,
        parts: new Map(), bytes: 0, finalSeq: -1, bad: 0, timer: null,
        done: (res) => {
          signal.removeEventListener('abort', onAbort);
          resolve(res);
        },
      };
      const onAbort = () => this.finishPending(replyId, null);
      signal.addEventListener('abort', onAbort, { once: true });
      this.pending.set(replyId, p);
    });

    const sent = await this.parts.circuit.sendDirect(OZZY_ONION_KIND, body, exclude);
    body.fill(0);
    if (!sent.ok || sent.guardId !== guard.peerId || signal.aborted) {
      this.finishPending(replyId, null);
      await result;
      return { kind: 'failed' };
    }
    const middle = sent.middleId;
    onMiddle(middle);
    this.stats.middlesUsed.add(middle);
    const p = this.pending.get(replyId);
    if (p) this.arm(replyId, p); // 送り出した時点から応答を待つ (送出枠の順番待ちを数えない)

    const raw = await result;
    if (signal.aborted || isDone()) return { kind: 'failed', middle };
    const dec = raw ? decodeRangeResponse(raw) : null;
    if (!dec) {
      this.avoid.set(middle, this.now() + MESH_FETCH_LIMITS.AVOID_MS);
      return { kind: 'failed', middle };
    }
    switch (dec.status) {
      case OZZY_MESH_STATUS.OK:
        break;
      case OZZY_MESH_STATUS.NOT_FOUND:
        this.stats.notFound++;
        return { kind: 'not-found', middle };
      case OZZY_MESH_STATUS.BUSY:
        this.stats.busy++;
        return { kind: 'busy', middle };
      case OZZY_MESH_STATUS.REFUSED:
        // 取得役を止めている M1。しばらく回路の M1 選びから外す
        this.avoid.set(middle, this.now() + MESH_FETCH_LIMITS.AVOID_MS);
        return { kind: 'unsupported', middle };
      default:
        return { kind: 'failed', middle };
    }
    const data = dec.data.slice();
    if (data.length !== req.length || !bytesEqual(data.subarray(0, OZZY_TAG_BYTES), req.expectedTag) || !(await accept(data))) {
      // ★ 長さ・tag・ハッシュが合わない: 偽物を返した M1。しばらく避けて別の M1 から取り直す
      this.stats.rejected++;
      this.avoid.set(middle, this.now() + MESH_FETCH_LIMITS.AVOID_MS);
      return { kind: 'failed', middle };
    }
    return { kind: 'ok', data, middle };
  }

  private arm(replyId: number, p: PendingReply): void {
    if (p.timer) clearTimeout(p.timer);
    p.timer = setTimeout(() => this.finishPending(replyId, null), p.waitMs ?? this.lim.inactivityMs);
  }

  /**
   * ロッカーへの作業 (Slab のアップロード・削除) を回路の M1 に頼み、結果 (受け取り票の JSON) を返す。
   *
   *   要求   自分 ─ONION_STEM→ Guard ─ONION_STEM→ M1      (取得の要求と同じ。Guard には cover と区別が付かない)
   *   本体   自分 ─OZZY_UP→ Guard ─OZZY_UP_FWD→ M1          (片ごとに upKey で暗号化。宛先の M1 は Guard 宛ての封印の中)
   *   結果   M1 ─OZZY_REPLY→ Guard ─OZZY_RESULT→ 自分
   *
   * ★ ロッカーに届くのは M1 が選んだ中継 Worker の IP。自分の IP はロッカーにも Worker にも M1 にも届かない。
   * ★ Guard には「自分が M1 へこれだけ送った」ことが見える (量は隠せない)。
   * 断られた・失敗した M1 は避けて、別の M1 で attempts 回まで (本体は呼び出し側が持ち続ける。ここでは消さない)。
   */
  public async runJob(
    job: OzzyLockerJob, body: Uint8Array, opts: { signal?: AbortSignal; exclude?: ReadonlySet<PeerId>; attempts?: number } = {},
  ): Promise<MeshJobResult> {
    this.stats.jobs++;
    let jobBytes: Uint8Array;
    try {
      jobBytes = encodeLockerJob(job, body.length);
    } catch {
      return { ok: false, reason: 'failed' };
    }
    if (!this.ready) return { ok: false, reason: 'no-fetchers' };
    const used = new Set<PeerId>(opts.exclude ?? []);
    const attempts = Math.max(1, opts.attempts ?? 3);
    for (let i = 0; i < attempts; i++) {
      if (opts.signal?.aborted || this.destroyed) return { ok: false, reason: 'aborted' };
      const out = await this.jobAttempt(jobBytes, body, new Set([...used, ...this.avoided()]), opts.signal);
      if (out.middle) used.add(out.middle);
      if (out.kind === 'ok') {
        this.stats.jobsOk++;
        return { ok: true, result: out.data, middle: out.middle! };
      }
      if (out.kind === 'unsupported' && out.middle) this.avoid.set(out.middle, this.now() + MESH_FETCH_LIMITS.AVOID_MS);
      if (!this.ready) return { ok: false, reason: 'no-fetchers' };
    }
    return { ok: false, reason: opts.signal?.aborted ? 'aborted' : 'failed' };
  }

  private async jobAttempt(
    jobBytes: Uint8Array, body: Uint8Array, exclude: ReadonlySet<PeerId>, signal?: AbortSignal,
  ): Promise<AttemptOutcome> {
    const guard = this.parts.circuit.currentGuardHop;
    const replyId = this.newReplyId();
    if (!guard || replyId === 0 || this.destroyed) return { kind: 'failed' };
    const respKey = sodium.randombytes_buf(RESP_KEY_BYTES);
    const upKey = sodium.randombytes_buf(RESP_KEY_BYTES);
    const uploadId = sodium.randombytes_buf(OZZY_UPLOAD_ID_BYTES);
    const header = sealReplyHeader(guard.pubkey, this.parts.peerManager.myPeerId, replyId);
    const req = new ByteWriter().raw(header).raw(respKey).raw(upKey).raw(uploadId).raw(jobBytes).finish();

    let settled = false;
    const result = new Promise<Uint8Array | null>((resolve) => {
      const onAbort = () => this.finishPending(replyId, null);
      this.pending.set(replyId, {
        guardId: guard.peerId, respKey, maxBytes: 1 + OZZY_JOB_RESULT_MAX_BYTES,
        maxPieces: Math.ceil((1 + OZZY_JOB_RESULT_MAX_BYTES) / OZZY_REPLY_PIECE_BYTES) + 1,
        parts: new Map(), bytes: 0, finalSeq: -1, bad: 0, timer: null, waitMs: OZZY_JOB_WAIT_MS,
        done: (res) => {
          settled = true;
          signal?.removeEventListener('abort', onAbort);
          resolve(res);
        },
      });
      signal?.addEventListener('abort', onAbort, { once: true });
    });

    const sent = await this.parts.circuit.sendDirect(OZZY_ONION_JOB_KIND, req, exclude);
    req.fill(0);
    if (!sent.ok || sent.guardId !== guard.peerId || signal?.aborted) {
      upKey.fill(0);
      this.finishPending(replyId, null);
      await result;
      return { kind: 'failed' };
    }
    const middle = sent.middleId;
    this.stats.middlesUsed.add(middle);

    // 本体を Guard へ流す (Guard が M1 へ回す)。M1 が先に結果 (断り・失敗) を返したら残りは送らない
    if (body.length > 0) {
      const upHeader = sealUpHeader(guard.pubkey, middle, uploadId);
      const pieces = Math.ceil(body.length / OZZY_UP_PIECE_BYTES);
      this.upPacer.add(guard.peerId, {
        next: 0,
        credit: 0,
        cancelled: () => settled || this.destroyed,
        piece: (seq) => {
          const final = seq === pieces - 1;
          const data = body.subarray(seq * OZZY_UP_PIECE_BYTES, Math.min(body.length, (seq + 1) * OZZY_UP_PIECE_BYTES));
          return { final, body: encryptChunk(upKey, OZZY_UP_AEAD_KIND, seq, final, data) };
        },
        send: (to, f) => {
          this.stats.upFrames++;
          this.parts.peerManager.sendMessage(to, WireType.OZZY_UP, { header: upHeader, seq: f.seq, final: f.final, body: f.body });
        },
        done: () => {
          upKey.fill(0);
          // 送り終えた時点から結果を待つ (M1 がロッカーへ PUT する時間)
          const p = this.pending.get(replyId);
          if (p) this.arm(replyId, p);
        },
      });
    } else {
      upKey.fill(0);
      const p = this.pending.get(replyId);
      if (p) this.arm(replyId, p);
    }

    const raw = await result;
    if (signal?.aborted) return { kind: 'failed', middle };
    const dec = raw ? decodeRangeResponse(raw) : null;
    if (!dec) return { kind: 'failed', middle };
    switch (dec.status) {
      case OZZY_MESH_STATUS.OK:
        return { kind: 'ok', data: dec.data.slice(), middle };
      case OZZY_MESH_STATUS.BUSY:
        this.stats.busy++;
        return { kind: 'busy', middle };
      case OZZY_MESH_STATUS.REFUSED:
        return { kind: 'unsupported', middle };
      default:
        return { kind: 'failed', middle };
    }
  }

  private finishPending(replyId: number, res: Uint8Array | null): void {
    const p = this.pending.get(replyId);
    if (!p) return;
    this.pending.delete(replyId);
    if (p.timer) clearTimeout(p.timer);
    p.parts.clear();
    p.respKey.fill(0);
    p.done(res);
  }

  /** Guard からの応答の片。頼んだ Guard からの、知っている replyId だけ。復号できない片が続けば失敗 */
  private handleResult(from: PeerId, msg: any): void {
    const replyId = msg?.replyId;
    const p = this.pending.get(replyId);
    if (!p || p.guardId !== from) return;
    const { seq, body } = msg;
    if (!Number.isInteger(seq) || !(body instanceof Uint8Array)) return;
    const dec = decryptChunk(p.respKey, OZZY_REPLY_AEAD_KIND, seq, body);
    if (!dec) {
      if (++p.bad >= 3) this.finishPending(replyId, null);
      return;
    }
    if (p.parts.has(seq)) return;
    // ★ 最後の印は暗号文の中の値を使う (途中の片を黙って落とされても、完結と見なさない)
    if ((p.finalSeq >= 0 && seq > p.finalSeq) || p.parts.size >= p.maxPieces) return this.finishPending(replyId, null);
    if (dec.final) {
      if ([...p.parts.keys()].some(s => s > seq)) return this.finishPending(replyId, null);
      p.finalSeq = seq;
    }
    p.parts.set(seq, dec.data);
    p.bytes += dec.data.length;
    if (p.bytes > p.maxBytes) return this.finishPending(replyId, null);
    this.arm(replyId, p);
    if (p.finalSeq >= 0 && p.parts.size === p.finalSeq + 1) {
      const out = new Uint8Array(p.bytes);
      let o = 0;
      for (let i = 0; i <= p.finalSeq; i++) {
        const part = p.parts.get(i);
        if (!part) return this.finishPending(replyId, null);
        out.set(part, o);
        o += part.length;
      }
      this.finishPending(replyId, out);
    }
  }

  /** 回路が組めるまで待つ (最大 waitMs)。中止されたら false */
  public async waitReady(waitMs: number, signal?: AbortSignal): Promise<boolean> {
    const end = this.now() + waitMs;
    while (!this.ready) {
      if (signal?.aborted || this.now() >= end) return this.ready;
      await sleep(200, signal);
    }
    return true;
  }

  public destroy(): void {
    this.destroyed = true;
    for (const id of Array.from(this.pending.keys())) this.finishPending(id, null);
    this.upPacer.destroy();
    this.parts.peerManager.off('peer:disconnect', this.onDisconnect);
    this.parts.dispatcher.unregister?.(WireType.OZZY_RESULT, this.onResult);
  }
}

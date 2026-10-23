/**
 * OnionLockers — ロッカーへのアップロード・削除を、オニオン回路の先の M1 に代わりにやってもらう。
 *
 *   告発者 ─(回路の要求 + OZZY_UP の本体)→ Guard → M1 ─(M1 が選んだ他人の中継 Worker)→ ロッカー
 *   受け取り票 (URL・削除トークン) は M1 → Guard → 告発者 (告発者の鍵で暗号化)
 *
 * ★ ロッカーに見えるのは Cloudflare (中継 Worker) の IP。Worker の持ち主に見えるのは M1 の IP。M1 に見えるのは Guard。
 *   告発者の IP は、隣人の Guard にしか届かない (Guard には中身も置き先も見えない。量だけ)。
 * ★ M1 は受け取り票を偽れる (置いていないのに置いたと言う・別の URL を言う)。告発者は
 *   - 受け取り票の形・ロッカーのホスト・大きさを確かめ (parseJobReceipt)、
 *   - 置いた直後に別の M1 から Slab の最後のチャンクの tag を取って確かめる (コーディネータの verifyUploads)。
 *   通らなければ別の M1・別のロッカーで置き直す。
 * ★ Internet Archive は使わない: IA のアカウントの鍵を M1 に渡すことになり、アカウントが告発者を名指しする。
 */
import type { PeerId } from '../types';
import {
  OZZY_JOB_LOCKERS,
  OZZY_JOB_MAX_BYTES,
  isAllowedOzzyFetchUrl,
  type OzzyLockerJob,
  type OzzyLockerJobRunner,
  type OzzyMeshFetcher,
} from './MeshRange';
import {
  CatboxLockerAdapter,
  GofileLockerAdapter,
  LitterboxLockerAdapter,
  PixeldrainLockerAdapter,
  PomfLockerAdapter,
  ZeroXZeroLockerAdapter,
  type HttpTransportFn,
  type OverseasLockerAdapter,
  type OverseasLockerId,
  type UploadedLockerSlabReceipt,
} from './OverseasLockers';

const utf8 = new TextEncoder();
const utf8Strict = new TextDecoder('utf-8', { fatal: true });

/** 受け取り票の文字列の上限 (削除トークン・ID) */
const RECEIPT_FIELD_MAX = 1024;

/**
 * 受け取り票 (JSON) を厳格に読む。ロッカーが違う・URL が許可されたロッカーのホストでない・大きさが違うものは null。
 * expectBytes を渡せばその大きさと一致すること。
 */
export function parseJobReceipt(
  bytes: Uint8Array, lockerId: string, expectBytes?: number,
): UploadedLockerSlabReceipt | null {
  try {
    const o = JSON.parse(utf8Strict.decode(bytes));
    if (!o || typeof o !== 'object' || Array.isArray(o)) return null;
    const { slabId, downloadUrl, deleteToken, byteLength, expiresAtSec } = o;
    if (o.lockerId !== lockerId || !OZZY_JOB_LOCKERS.includes(lockerId)) return null;
    if (typeof slabId !== 'string' || slabId.length > RECEIPT_FIELD_MAX) return null;
    if (typeof deleteToken !== 'string' || deleteToken.length > RECEIPT_FIELD_MAX) return null;
    if (typeof downloadUrl !== 'string' || !isAllowedOzzyFetchUrl(downloadUrl)) return null;
    if (!Number.isSafeInteger(byteLength) || byteLength < 0 || byteLength > OZZY_JOB_MAX_BYTES) return null;
    if (expectBytes !== undefined && byteLength !== expectBytes) return null;
    if (expiresAtSec !== undefined && (!Number.isSafeInteger(expiresAtSec) || expiresAtSec < 0)) return null;
    return {
      lockerId: lockerId as OverseasLockerId, slabId, downloadUrl, deleteToken, byteLength,
      ...(expiresAtSec !== undefined ? { expiresAtSec } : {}),
    };
  } catch {
    return null;
  }
}

function encodeReceipt(r: UploadedLockerSlabReceipt): Uint8Array {
  return utf8.encode(JSON.stringify({
    lockerId: r.lockerId, slabId: r.slabId, downloadUrl: r.downloadUrl, deleteToken: r.deleteToken, byteLength: r.byteLength,
    ...(r.expiresAtSec !== undefined ? { expiresAtSec: r.expiresAtSec } : {}),
  }));
}

/** M1 が他人の作業に使うロッカーのアダプタ (資格情報なし)。transport は他人の中継 Worker 経由のもの */
export function createJobLockerAdapters(transport: HttpTransportFn): Map<string, OverseasLockerAdapter> {
  const list: OverseasLockerAdapter[] = [
    new CatboxLockerAdapter(transport),
    new LitterboxLockerAdapter(transport, { expiryTime: '72h' }),
    new ZeroXZeroLockerAdapter(transport),
    new PomfLockerAdapter(transport, { variant: 'pomf-lain' }),
    new PomfLockerAdapter(transport, { variant: 'pomf-quax' }),
    new PomfLockerAdapter(transport, { variant: 'pomf-uguu' }),
    // 他人の要求でゲスト ID を作るので、5 秒に 1 つまで
    new GofileLockerAdapter(transport, { minMintIntervalMs: 5_000 }),
    new PixeldrainLockerAdapter(transport),
  ];
  return new Map(list.map(a => [a.lockerId, a]));
}

/**
 * M1 の側: 頼まれた作業をロッカーのアダプタで実行し、受け取り票 (JSON) を返す。
 * ★ アップロードの結果の URL が許可されたロッカーのホストでなければ失敗にする (告発者の側でも確かめる)。
 * ★ 削除は受け取り票の URL が許可されたホストのときだけ (0x0.st は URL へ POST するので、任意の URL へ行かせない)。
 */
export function createLockerJobRunner(
  transport: HttpTransportFn, adapters: Map<string, OverseasLockerAdapter> = createJobLockerAdapters(transport),
): OzzyLockerJobRunner {
  return async (job: OzzyLockerJob, body: Uint8Array, signal: AbortSignal): Promise<Uint8Array> => {
    const adapter = adapters.get(job.lockerId);
    if (!adapter || signal.aborted) throw new Error('locker unavailable');
    if (job.op === 'upload') {
      if (body.length < 1 || body.length > Math.min(adapter.maxSlabBytes, OZZY_JOB_MAX_BYTES)) throw new RangeError('bad slab size');
      const receipt = await abortable(adapter.uploadSlab(body, job.filename), signal);
      if (receipt.lockerId !== job.lockerId || !isAllowedOzzyFetchUrl(receipt.downloadUrl)) throw new Error('unexpected receipt');
      return encodeReceipt({ ...receipt, byteLength: body.length });
    }
    const receipt = parseJobReceipt(utf8.encode(job.receipt), job.lockerId);
    if (!receipt) throw new Error('bad receipt');
    const ok = await abortable(adapter.deleteSlab(receipt), signal);
    return utf8.encode(JSON.stringify({ deleted: ok === true }));
  };
}

function abortable<T>(p: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(new Error('aborted'));
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(new Error('aborted'));
    signal.addEventListener('abort', onAbort, { once: true });
    p.then(
      (v) => {
        signal.removeEventListener('abort', onAbort);
        resolve(v);
      },
      (e) => {
        signal.removeEventListener('abort', onAbort);
        reject(e);
      },
    );
  });
}

export type OnionJobMesh = Pick<OzzyMeshFetcher, 'runJob' | 'ready'>;

/**
 * 告発者の側: ロッカーへの PUT / DELETE をオニオン回路の M1 に頼むアダプタ。
 * 読み出し (fetchSlabRange) はしない (読むのはメッシュの取得役。SlabReader の mesh)。
 */
export class OnionLockerAdapter implements OverseasLockerAdapter {
  readonly supportsExplicitDelete: boolean;
  readonly maxSlabBytes: number;
  /** 最後に頼んだ M1 (診断・テスト用) */
  public lastMiddle: PeerId | null = null;
  private readonly attempts: number;

  constructor(
    readonly lockerId: OverseasLockerId,
    private readonly mesh: OnionJobMesh,
    opts: { maxSlabBytes?: number; attempts?: number } = {},
  ) {
    if (!OZZY_JOB_LOCKERS.includes(lockerId)) throw new RangeError(`${lockerId} cannot be used over the onion`);
    // 匿名の Catbox / Litterbox / Pomf は消せない (削除トークンを返さない)
    this.supportsExplicitDelete = lockerId === '0x0.st' || lockerId === 'gofile' || lockerId === 'pixeldrain';
    this.maxSlabBytes = Math.min(opts.maxSlabBytes ?? OZZY_JOB_MAX_BYTES, OZZY_JOB_MAX_BYTES);
    this.attempts = opts.attempts ?? 3;
  }

  async uploadSlab(slabBinary: Uint8Array, slabFilename: string): Promise<UploadedLockerSlabReceipt> {
    if (slabBinary.byteLength > this.maxSlabBytes) throw new RangeError(`${this.lockerId} max Slab size is ${this.maxSlabBytes} bytes`);
    const res = await this.mesh.runJob({ op: 'upload', lockerId: this.lockerId, filename: slabFilename }, slabBinary, { attempts: this.attempts });
    if (!res.ok) throw new Error(`onion upload to ${this.lockerId} failed: ${res.reason}`);
    this.lastMiddle = res.middle;
    const receipt = parseJobReceipt(res.result, this.lockerId, slabBinary.byteLength);
    if (!receipt) throw new Error(`onion upload to ${this.lockerId}: bad receipt`);
    return receipt;
  }

  async fetchSlabRange(): Promise<Uint8Array | null> {
    return null;
  }

  async deleteSlab(receipt: UploadedLockerSlabReceipt): Promise<boolean> {
    if (receipt.lockerId !== this.lockerId || !receipt.deleteToken) return false;
    const res = await this.mesh.runJob(
      { op: 'delete', lockerId: this.lockerId, receipt: new TextDecoder().decode(encodeReceipt(receipt)) }, new Uint8Array(0),
      { attempts: this.attempts },
    );
    if (!res.ok) return false;
    try {
      return JSON.parse(utf8Strict.decode(res.result))?.deleted === true;
    } catch {
      return false;
    }
  }
}

/** 回路で置けるロッカーごとの OnionLockerAdapter */
export function createOnionLockerAdapters(
  mesh: OnionJobMesh, lockerIds: readonly string[] = OZZY_JOB_LOCKERS,
): OnionLockerAdapter[] {
  return lockerIds.filter(id => OZZY_JOB_LOCKERS.includes(id)).map(id => new OnionLockerAdapter(id as OverseasLockerId, mesh));
}

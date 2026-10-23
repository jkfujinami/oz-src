/**
 * OverseasLockers — Internet Archive 以外の海外無記名・クレカ不要大容量ロッカー各社に対応した
 * プロトコルアダプタ群・異種混合マルチロッカー RAM ミキサー・ヤドカリ自動移設エンジン。
 *
 * 実装対象モジュール (すべて HTTP Range: bytes=start-end `206 Partial Content` 対応):
 *   1. `CatboxLockerAdapter`      (`catbox.moe` — 200 MiB/Slab, multipart `reqtype=fileupload` / `deletefiles`)
 *   2. `LitterboxLockerAdapter`   (`litterbox.catbox.moe` — 1 GiB/Slab, 1h/12h/24h/72h 時限自動消去)
 *   3. `ZeroXZeroLockerAdapter`   (`0x0.st` — 512 MiB/Slab, multipart `file` + `X-Token` 物理削除トークン)
 *   4. `PomfLockerAdapter`        (`pomf2.lain.la` / `qu.ax` — Pomf 互換 JSON API `files[]`)
 *   5. `GofileLockerAdapter`      (`gofile.io` — サーバ自動選択 `/servers` + `/contents/uploadfile` + Bearer DELETE)
 *   6. `PixeldrainLockerAdapter`  (`pixeldrain.com` — `PUT /api/file/` + `GET /api/file/:id` Range + `DELETE`)
 *   7. `InternetArchiveLockerAdapter` (`archive.org` IAS3 API の共通インターフェースラッパー)
 */
import sodium, { sodiumReady } from '../crypto/sodium';
import { Encoding } from '../common/Encoding';
import {
  OZZY_CHUNK_BYTES,
  computeStripeShareDigests,
  encryptStripeDataChunks,
  generateStripeParityChunks,
  type OzzyChunk,
} from './OzzyChunk4M';
import {
  OZZY_TAG_BYTES,
  computeChunkTag,
  deriveOzzyKeys,
  deriveStripeSeed,
  generateOzzySeed,
} from './OzzyKdf';
import { OZZY_RS_K } from './ReedSolomon';
import { bytesEqual } from '../files/FileFormat';
import {
  formatOzzyLinkV3,
  serializeOzzyManifestV4,
  type OzzyManifestStore,
  type OzzyManifestV4,
  type OzzySlabLocation,
  type OzzyStripeV4,
} from './OzzyManifest';
import { RamChunkArena, blindedEpochDay, maxStripePlainBytes } from './ParallelPipeline';
import { createHttpRangeFetch, type OzzyMeshFetcher, type OzzyRangeFetchFn } from './MeshRange';
import { OzzySlabReader, type OzzyFetchRoute, type SlabReadFailure, type SlabReadProgress } from './SlabReader';
import { OrderedSourceReader, type OzzyByteSink, type OzzyUploadSource } from './OzzyStream';
import {
  IA_DOWNLOAD_ENDPOINT,
  IA_S3_ENDPOINT,
  buildIaS3DeleteHeaders,
  buildIaS3PutHeaders,
  type FlushReason,
  type IaS3Credentials,
} from './InternetArchiveSlab';

export type OverseasLockerId =
  | 'internet-archive-s3'
  | 'catbox'
  | 'litterbox'
  | '0x0.st'
  | 'pomf-lain'
  | 'pomf-quax'
  | 'pomf-uguu'
  | 'gofile'
  | 'pixeldrain';

export interface UploadedLockerSlabReceipt {
  readonly lockerId: OverseasLockerId;
  readonly slabId: string;
  readonly downloadUrl: string;
  readonly deleteToken: string;
  readonly byteLength: number;
  readonly expiresAtSec?: number;
}

export interface OverseasLockerAdapter {
  readonly lockerId: OverseasLockerId;
  readonly maxSlabBytes: number;
  readonly supportsExplicitDelete: boolean;
  uploadSlab(slabBinary: Uint8Array, slabFilename: string): Promise<UploadedLockerSlabReceipt>;
  /** 範囲を取る (end は含む)。読み出しに資格情報は渡さない (Lease に入っていない)。取れなければ null */
  fetchSlabRange(downloadUrl: string, startByte: number, endByte: number, authToken?: string, signal?: AbortSignal): Promise<Uint8Array | null>;
  deleteSlab(receipt: UploadedLockerSlabReceipt): Promise<boolean>;
}

export type HttpTransportFn = (request: Request) => Promise<Response>;

/**
 * ブラウザ環境で海外ロッカー (`catbox.moe`, `litterbox.catbox.moe`, `0x0.st`, `pomf2.lain.la`, `gofile.io`, `pixeldrain.com`)
 * の CORS 制約を回避するため、Cloudflare Worker (`/ozzy/v2/locker-proxy`) 経由でリクエストを中継するトランスポートを生成する。
 */
export interface WorkerCorsProxyOptions {
  /**
   * 厳格匿名モード (デフォルト `false` = Fail-Closed):
   * `false` の場合、Cloudflare Worker リレーが失敗してもクライアントの生 IP から海外ロッカーへ直接通信することは絶対にしない。
   * 生 IP がロッカーに見えてもよいと分かっていて、直接通信を許可する場合のみ `true` を指定する。
   */
  readonly allowDirectIpFallback?: boolean;
}

const STRIPPED_CLIENT_HEADERS = new Set([
  'referer',
  'origin',
  'x-forwarded-for',
  'cf-connecting-ip',
  'true-client-ip',
  'x-real-ip',
  'forwarded',
  'via',
]);

export function createWorkerCorsProxyTransport(
  workerBaseUrl: string,
  innerFetch: (req: Request) => Promise<Response> = req => fetch(req, { cache: 'no-store' }),
  opts?: WorkerCorsProxyOptions,
): HttpTransportFn {
  const base = workerBaseUrl.replace(/\/+$/, '');
  const allowDirectFallback = opts?.allowDirectIpFallback ?? false;

  return async (request: Request): Promise<Response> => {
    const reqUrl = new URL(request.url);
    // 既に同一 Worker 宛てのリクエストであればそのまま直接送信
    if (request.url.startsWith(base)) {
      return innerFetch(request);
    }
    const headerObj: Record<string, string> = {};
    request.headers.forEach((v, k) => {
      if (!STRIPPED_CLIENT_HEADERS.has(k.toLowerCase())) {
        headerObj[k] = v;
      }
    });
    const hasBody = request.method !== 'GET' && request.method !== 'HEAD';
    const bodyBuf = hasBody ? await request.arrayBuffer() : undefined;
    const proxyReq = new Request(`${base}/ozzy/v2/locker-proxy`, {
      method: 'POST',
      signal: request.signal,
      headers: {
        'X-Ozzy-Target-Url': reqUrl.toString(),
        'X-Ozzy-Target-Method': request.method,
        'X-Ozzy-Target-Headers': JSON.stringify(headerObj),
      },
      body: hasBody && bodyBuf && bodyBuf.byteLength > 0 ? bodyBuf.slice(0) : undefined,
    });
    const proxyRes = await innerFetch(proxyReq);
    // Fail-Closed: allowDirectFallback が明示的に true の場合のみ直接通信フォールバックを許可
    if (!proxyRes.ok && allowDirectFallback) {
      try {
        const directReq = new Request(reqUrl.toString(), {
          method: request.method,
          headers: headerObj,
          body: hasBody && bodyBuf && bodyBuf.byteLength > 0 ? bodyBuf.slice(0) : undefined,
        });
        const directRes = await innerFetch(directReq);
        if (directRes.ok) return directRes;
      } catch {
        return proxyRes;
      }
    }
    return proxyRes;
  };
}

/**
 * 参加者の中継 Worker のプール (ozzy/WorkerPool) から、要求ごとに Worker を選んで中継させるトランスポート。
 * ★ 自分の通信は他人の Worker を通る (自分の Cloudflare アカウントに自分のロッカー通信が残らない)。要求ごとに選び直すので、
 *   1 人の持ち主に通信が集まらない。中継として応えない Worker (Ozzy の中継でない・落ちている) は報告して別の Worker で再試行する。
 * ★ 中継が見つからなければ例外 (生 IP で直接ロッカーへは行かない)。
 */
export function createPooledRelayTransport(
  pickRelay: () => string | null,
  reportFailure: (url: string) => void = () => undefined,
  innerFetch: (req: Request) => Promise<Response> = (req) => fetch(req, { cache: 'no-store' }),
  attempts = 3,
): HttpTransportFn {
  return async (request: Request): Promise<Response> => {
    let lastErr: unknown = new Error('no ozzy relay worker available');
    for (let i = 0; i < attempts; i++) {
      const base = pickRelay(); // 失敗を報告した Worker はプールがしばらく選ばない
      if (!base) break;
      const relay = createWorkerCorsProxyTransport(base, innerFetch);
      try {
        const res = await relay(request.clone());
        // 中継した応答には X-Ozzy-Proxied-Status が付く。ロッカーに届かなかった (502) も中継自体は働いている
        if (res.headers.get('X-Ozzy-Proxied-Status') !== null || res.status === 502) return res;
        reportFailure(base);
        lastErr = new Error(`relay ${base} did not act as an Ozzy relay (HTTP ${res.status})`);
      } catch (e) {
        if (request.signal?.aborted) throw e;
        reportFailure(base);
        lastErr = e;
      }
    }
    throw lastErr;
  };
}

function buildRangeHeaders(startByte: number, endByte: number, extra?: Record<string, string>): Record<string, string> {
  return {
    ...extra,
    Range: `bytes=${startByte}-${endByte}`,
  };
}

async function executeRangeFetch(
  transport: HttpTransportFn,
  downloadUrl: string,
  startByte: number,
  endByte: number,
  extraHeaders?: Record<string, string>,
  signal?: AbortSignal,
): Promise<Uint8Array | null> {
  const expectedLen = endByte - startByte + 1;
  try {
    const req = new Request(downloadUrl, {
      method: 'GET',
      headers: buildRangeHeaders(startByte, endByte, extraHeaders),
      signal,
    });
    const res = await transport(req);
    if (res.status === 206) {
      const buf = new Uint8Array(await res.arrayBuffer());
      return buf.byteLength === expectedLen ? buf : null;
    }
    if (res.status === 200) {
      // ★ Range を無視したサーバー: 全体が小さいときだけ読み込んで切り出す (1 GiB の Slab 全体をメモリに載せない)
      const len = Number(res.headers.get('Content-Length') ?? NaN);
      if (!Number.isFinite(len) || len > endByte + 1 + 16 * 1024 * 1024) return null;
      const full = new Uint8Array(await res.arrayBuffer());
      if (endByte < full.byteLength) {
        return full.slice(startByte, endByte + 1);
      }
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * RFC 7578 準拠の軽量 `multipart/form-data` バイナリボディ構築ヘルパ。
 * Node / Browser / Cloudflare Workers 間で FormData の実装差異に左右されず、
 * 4 MiB〜数百 MiB の Slab バイナリをゼロコピーに近い形で正確にカプセル化する。
 */
export function buildMultipartFormData(
  fields: readonly { name: string; value: string }[],
  fileField?: { fieldName: string; fileName: string; data: Uint8Array },
): { contentType: string; body: Uint8Array; boundary: string } {
  const boundary = `----OzzySlabBoundary${Encoding.toHex(sodium.randombytes_buf(8))}`;
  const encoder = new TextEncoder();
  const parts: Uint8Array[] = [];

  for (const f of fields) {
    const header = `--${boundary}\r\nContent-Disposition: form-data; name="${f.name}"\r\n\r\n${f.value}\r\n`;
    parts.push(encoder.encode(header));
  }

  if (fileField) {
    const fileHeader =
      `--${boundary}\r\n` +
      `Content-Disposition: form-data; name="${fileField.fieldName}"; filename="${fileField.fileName}"\r\n` +
      `Content-Type: application/octet-stream\r\n\r\n`;
    parts.push(encoder.encode(fileHeader));
    parts.push(fileField.data);
    parts.push(encoder.encode('\r\n'));
  }

  parts.push(encoder.encode(`--${boundary}--\r\n`));

  let totalLen = 0;
  for (const p of parts) totalLen += p.byteLength;
  const merged = new Uint8Array(totalLen);
  let offset = 0;
  for (const p of parts) {
    merged.set(p, offset);
    offset += p.byteLength;
  }

  return {
    contentType: `multipart/form-data; boundary=${boundary}`,
    body: merged,
    boundary,
  };
}

// ============================================================================
// 1. Catbox.moe アダプタ (`https://catbox.moe/user/api.php`)
//    - クレカ・アカウント登録不要 (上限 200 MiB / 1 Slab)
//    - userhash を指定した場合は `reqtype=deletefiles` による物理削除にも対応
// ============================================================================
export class CatboxLockerAdapter implements OverseasLockerAdapter {
  readonly lockerId: OverseasLockerId = 'catbox';
  readonly maxSlabBytes = 200 * 1024 * 1024; // 200 MiB
  readonly supportsExplicitDelete: boolean;
  private readonly apiEndpoint: string;
  private readonly userhash: string;

  constructor(
    private readonly transport: HttpTransportFn,
    opts?: { apiEndpoint?: string; userhash?: string },
  ) {
    this.apiEndpoint = opts?.apiEndpoint ?? 'https://catbox.moe/user/api.php';
    this.userhash = opts?.userhash ?? '';
    this.supportsExplicitDelete = Boolean(this.userhash);
  }

  async uploadSlab(slabBinary: Uint8Array, slabFilename: string): Promise<UploadedLockerSlabReceipt> {
    if (slabBinary.byteLength > this.maxSlabBytes) {
      throw new RangeError(`Catbox max Slab size is ${this.maxSlabBytes} bytes`);
    }
    const fields = [{ name: 'reqtype', value: 'fileupload' }];
    if (this.userhash) {
      fields.push({ name: 'userhash', value: this.userhash });
    }
    const mp = buildMultipartFormData(fields, {
      fieldName: 'fileToUpload',
      fileName: slabFilename,
      data: slabBinary,
    });

    const req = new Request(this.apiEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': mp.contentType },
      body: mp.body as Uint8Array<ArrayBuffer>,
    });
    const res = await this.transport(req);
    if (!res.ok) {
      throw new Error(`Catbox upload failed with HTTP ${res.status}`);
    }
    const downloadUrl = (await res.text()).trim();
    if (!downloadUrl.startsWith('https://')) {
      throw new Error(`Catbox returned invalid URL: ${downloadUrl}`);
    }
    const urlParts = downloadUrl.split('/');
    const slabId = urlParts[urlParts.length - 1];

    return {
      lockerId: 'catbox',
      slabId,
      downloadUrl,
      deleteToken: this.userhash,
      byteLength: slabBinary.byteLength,
    };
  }

  async fetchSlabRange(
    downloadUrl: string, startByte: number, endByte: number, _authToken?: string, signal?: AbortSignal,
  ): Promise<Uint8Array | null> {
    return executeRangeFetch(this.transport, downloadUrl, startByte, endByte, undefined, signal);
  }

  async deleteSlab(receipt: UploadedLockerSlabReceipt): Promise<boolean> {
    if (!receipt.deleteToken) return true;
    const mp = buildMultipartFormData([
      { name: 'reqtype', value: 'deletefiles' },
      { name: 'userhash', value: receipt.deleteToken },
      { name: 'files', value: receipt.slabId },
    ]);
    const req = new Request(this.apiEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': mp.contentType },
      body: mp.body as Uint8Array<ArrayBuffer>,
    });
    const res = await this.transport(req);
    return res.ok;
  }
}

// ============================================================================
// 2. Litterbox (`https://litterbox.catbox.moe/resources/internals/api.php`)
//    - 完全無記名・最大 1 GiB/Slab・指定時間 (1h / 12h / 24h / 72h) 後にサーバ側で自動物理消去
// ============================================================================
export type LitterboxExpiryTime = '1h' | '12h' | '24h' | '72h';

export class LitterboxLockerAdapter implements OverseasLockerAdapter {
  readonly lockerId: OverseasLockerId = 'litterbox';
  readonly maxSlabBytes = 1024 * 1024 * 1024; // 1 GiB
  readonly supportsExplicitDelete = false; // 時限自動消去型
  private readonly apiEndpoint: string;
  private readonly expiryTime: LitterboxExpiryTime;

  constructor(
    private readonly transport: HttpTransportFn,
    opts?: { apiEndpoint?: string; expiryTime?: LitterboxExpiryTime },
  ) {
    this.apiEndpoint = opts?.apiEndpoint ?? 'https://litterbox.catbox.moe/resources/internals/api.php';
    this.expiryTime = opts?.expiryTime ?? '72h';
  }

  async uploadSlab(slabBinary: Uint8Array, slabFilename: string): Promise<UploadedLockerSlabReceipt> {
    if (slabBinary.byteLength > this.maxSlabBytes) {
      throw new RangeError(`Litterbox max Slab size is ${this.maxSlabBytes} bytes`);
    }
    const mp = buildMultipartFormData(
      [
        { name: 'reqtype', value: 'fileupload' },
        { name: 'time', value: this.expiryTime },
      ],
      {
        fieldName: 'fileToUpload',
        fileName: slabFilename,
        data: slabBinary,
      },
    );

    const req = new Request(this.apiEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': mp.contentType },
      body: mp.body as Uint8Array<ArrayBuffer>,
    });
    const res = await this.transport(req);
    if (!res.ok) {
      throw new Error(`Litterbox upload failed with HTTP ${res.status}`);
    }
    const downloadUrl = (await res.text()).trim();
    if (!downloadUrl.startsWith('https://')) {
      throw new Error(`Litterbox returned invalid URL: ${downloadUrl}`);
    }
    const parts = downloadUrl.split('/');
    const slabId = parts[parts.length - 1];
    const hours = parseInt(this.expiryTime.replace('h', ''), 10);

    return {
      lockerId: 'litterbox',
      slabId,
      downloadUrl,
      deleteToken: '',
      byteLength: slabBinary.byteLength,
      expiresAtSec: Math.floor(Date.now() / 1000) + hours * 3600,
    };
  }

  async fetchSlabRange(
    downloadUrl: string, startByte: number, endByte: number, _authToken?: string, signal?: AbortSignal,
  ): Promise<Uint8Array | null> {
    return executeRangeFetch(this.transport, downloadUrl, startByte, endByte, undefined, signal);
  }

  async deleteSlab(_receipt: UploadedLockerSlabReceipt): Promise<boolean> {
    // Litterbox はサーバ側タイマーで自動ワイプされる
    return true;
  }
}

// ============================================================================
// 3. 0x0.st / x0.at (`https://0x0.st` / `https://x0.at` — The Null Pointer ラッパー)
//    - 完全無記名・最大 512 MiB/Slab
//    - 本家 `0x0.st` が 503 等でアップロード停止中の場合、同一プロトコルの `https://x0.at` へ自動フェイルオーバー!
//    - `x0.at` の拡張子フィルタを透過するため `.txt` 名でバイナリ投入し、`206 Partial Content` で切り出す
// ============================================================================
export class ZeroXZeroLockerAdapter implements OverseasLockerAdapter {
  readonly lockerId: OverseasLockerId = '0x0.st';
  readonly maxSlabBytes = 512 * 1024 * 1024; // 512 MiB
  readonly supportsExplicitDelete = true;
  private readonly endpoints: readonly string[];
  private readonly expiresHours: number;

  constructor(
    private readonly transport: HttpTransportFn,
    opts?: { endpoint?: string; fallbackEndpoints?: readonly string[]; expiresHours?: number },
  ) {
    const primary = opts?.endpoint ?? 'https://0x0.st';
    const fallbacks = opts?.fallbackEndpoints ?? ['https://x0.at'];
    this.endpoints = [primary, ...fallbacks.filter(e => e !== primary)];
    this.expiresHours = opts?.expiresHours ?? 720; // 30 days
  }

  async uploadSlab(slabBinary: Uint8Array, slabFilename: string): Promise<UploadedLockerSlabReceipt> {
    if (slabBinary.byteLength > this.maxSlabBytes) {
      throw new RangeError(`0x0.st max Slab size is ${this.maxSlabBytes} bytes`);
    }

    let lastStatus = 0;
    for (const ep of this.endpoints) {
      // x0.at 等の nullpointer 派生サーバは `.bin` 拡張子を拒否するため `.txt` を付与して生バイナリを格納する
      const normalizedName =
        ep.includes('x0.at') && !slabFilename.endsWith('.txt') ? `${slabFilename}.txt` : slabFilename;
      const mp = buildMultipartFormData(
        [
          { name: 'expires', value: this.expiresHours.toString() },
          { name: 'secret', value: '' },
        ],
        {
          fieldName: 'file',
          fileName: normalizedName,
          data: slabBinary,
        },
      );

      try {
        const req = new Request(ep, {
          method: 'POST',
          headers: {
            'Content-Type': mp.contentType,
            'User-Agent': 'ozzy-slab-client/2.0',
          },
          body: mp.body as Uint8Array<ArrayBuffer>,
        });
        const res = await this.transport(req);
        lastStatus = res.status;
        if (!res.ok) continue;

        const downloadUrl = (await res.text()).trim();
        if (!downloadUrl.startsWith('https://')) continue;
        const deleteToken = res.headers.get('X-Token') ?? '';
        const parts = downloadUrl.split('/');
        const slabId = parts[parts.length - 1];

        return {
          lockerId: '0x0.st',
          slabId,
          downloadUrl,
          deleteToken,
          byteLength: slabBinary.byteLength,
          expiresAtSec: Math.floor(Date.now() / 1000) + this.expiresHours * 3600,
        };
      } catch {
        continue;
      }
    }

    throw new Error(`0x0.st / x0.at upload failed (last HTTP ${lastStatus})`);
  }

  async fetchSlabRange(
    downloadUrl: string, startByte: number, endByte: number, _authToken?: string, signal?: AbortSignal,
  ): Promise<Uint8Array | null> {
    return executeRangeFetch(this.transport, downloadUrl, startByte, endByte, {
      'User-Agent': 'ozzy-slab-client/2.0',
    }, signal);
  }

  async deleteSlab(receipt: UploadedLockerSlabReceipt): Promise<boolean> {
    // x0.at など X-Token を返さないミラーの場合は時限自動消去に委ねる
    if (!receipt.deleteToken) return true;
    const mp = buildMultipartFormData([
      { name: 'token', value: receipt.deleteToken },
      { name: 'delete', value: '' },
    ]);
    const req = new Request(receipt.downloadUrl, {
      method: 'POST',
      headers: {
        'Content-Type': mp.contentType,
        'User-Agent': 'ozzy-slab-client/2.0',
      },
      body: mp.body as Uint8Array<ArrayBuffer>,
    });
    const res = await this.transport(req);
    return res.ok;
  }
}

// ============================================================================
// 4. Pomf クローン系アダプタ (`https://uguu.se/upload` / `https://pomf2.lain.la/upload.php` / `https://qu.ax/upload.php`)
//    - `files[]` マルチパートフィールドで POST し、JSON `{ success: true, files: [{ url, name, size }] }` を返す
//    - `lain.la` 到達不能時や `qu.ax` の拡張子制限時には、実稼働中の `https://uguu.se/upload` (`d.uguu.se`) へ自動フェイルオーバー!
// ============================================================================
export class PomfLockerAdapter implements OverseasLockerAdapter {
  readonly lockerId: OverseasLockerId;
  readonly maxSlabBytes: number;
  readonly supportsExplicitDelete = true;
  private readonly uploadUrls: readonly string[];

  constructor(
    private readonly transport: HttpTransportFn,
    opts?: {
      variant?: 'pomf-lain' | 'pomf-quax' | 'pomf-uguu';
      uploadUrl?: string;
      fallbackUploadUrls?: readonly string[];
      maxSlabBytes?: number;
    },
  ) {
    this.lockerId = opts?.variant ?? 'pomf-lain';
    const primary =
      opts?.uploadUrl ??
      (this.lockerId === 'pomf-uguu'
        ? 'https://uguu.se/upload'
        : this.lockerId === 'pomf-quax'
          ? 'https://qu.ax/upload.php'
          : 'https://pomf2.lain.la/upload.php');
    const fallbacks = opts?.fallbackUploadUrls ?? ['https://uguu.se/upload'];
    this.uploadUrls = [primary, ...fallbacks.filter(u => u !== primary)];
    this.maxSlabBytes = opts?.maxSlabBytes ?? 128 * 1024 * 1024;
  }

  async uploadSlab(slabBinary: Uint8Array, slabFilename: string): Promise<UploadedLockerSlabReceipt> {
    if (slabBinary.byteLength > this.maxSlabBytes) {
      throw new RangeError(`${this.lockerId} max Slab size is ${this.maxSlabBytes} bytes`);
    }
    const mp = buildMultipartFormData([], {
      fieldName: 'files[]',
      fileName: slabFilename,
      data: slabBinary,
    });

    let lastErr = '';
    for (const targetUrl of this.uploadUrls) {
      try {
        const req = new Request(targetUrl, {
          method: 'POST',
          headers: { 'Content-Type': mp.contentType },
          body: mp.body as Uint8Array<ArrayBuffer>,
        });
        const res = await this.transport(req);
        if (!res.ok) {
          lastErr = `HTTP ${res.status}`;
          continue;
        }
        const json = (await res.json()) as {
          success: boolean;
          files?: { url: string; filename?: string; name?: string; size?: number; deleteToken?: string }[];
        };
        if (!json.success || !json.files || json.files.length === 0) {
          lastErr = 'unsuccessful JSON payload';
          continue;
        }
        const f = json.files[0];
        const parts = f.url.split('/');
        const slabId = parts[parts.length - 1];

        return {
          lockerId: this.lockerId,
          slabId,
          downloadUrl: f.url,
          deleteToken: f.deleteToken ?? '',
          byteLength: slabBinary.byteLength,
        };
      } catch (e) {
        lastErr = e instanceof Error ? e.message : String(e);
        continue;
      }
    }

    throw new Error(`${this.lockerId} upload failed across all Pomf endpoints (${lastErr})`);
  }

  async fetchSlabRange(
    downloadUrl: string, startByte: number, endByte: number, _authToken?: string, signal?: AbortSignal,
  ): Promise<Uint8Array | null> {
    return executeRangeFetch(this.transport, downloadUrl, startByte, endByte, undefined, signal);
  }

  async deleteSlab(receipt: UploadedLockerSlabReceipt): Promise<boolean> {
    // Uguu.se など deleteToken を発行しない時限消去型 Pomf サーバの場合は true を返す
    if (!receipt.deleteToken && receipt.downloadUrl.includes('uguu.se')) {
      return true;
    }
    const req = new Request(receipt.downloadUrl, {
      method: 'DELETE',
      headers: receipt.deleteToken ? { 'X-Delete-Token': receipt.deleteToken } : {},
    });
    const res = await this.transport(req);
    return res.status === 200 || res.status === 204;
  }
}

// ============================================================================
// 5. Gofile.io リバースエンジニアリング・ラッパー (`ltsdw/gofile-downloader` 準拠)
//    - 動的 `X-Website-Token` 生成アルゴリズム:
//      `SHA256("${UserAgent}::en-US::${accountToken}::${Math.floor(unixSec / 14400)}::12af056dacea0b")`
//    - `POST /accounts` による無記名ゲストトークン自動発行 + `GET /contents/{folderCode}?wt={wt}` による
//      エッジストレージ (`store-*.gofile.io`) セッション有効化により、別端末からでも確実に `206 Partial Content` を取得!
// ============================================================================
export const GOFILE_DEFAULT_USER_AGENT =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

export const ANONYMOUS_USER_AGENT_POOL: readonly string[] = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
];

function pickAnonymousUserAgent(): string {
  const idx = sodium.randombytes_uniform(ANONYMOUS_USER_AGENT_POOL.length);
  return ANONYMOUS_USER_AGENT_POOL[idx];
}

export async function generateGofileWebsiteToken(
  userAgent: string,
  accountToken: string,
  unixSec: number = Math.floor(Date.now() / 1000),
): Promise<string> {
  const timeSlot = Math.floor(unixSec / 14400);
  const raw = `${userAgent}::en-US::${accountToken}::${timeSlot}::12af056dacea0b`;
  const bytes = new TextEncoder().encode(raw);
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return Encoding.toHex(new Uint8Array(digest));
}

export class GofileLockerAdapter implements OverseasLockerAdapter {
  readonly lockerId: OverseasLockerId = 'gofile';
  readonly maxSlabBytes = 2 * 1024 * 1024 * 1024; // 2 GiB
  readonly supportsExplicitDelete = true;
  private readonly apiBaseUrl: string;
  private readonly uploadHostTemplate: string;
  private readonly fixedUserAgent?: string;
  // 1-Slab 1-Identity 分離: セッション横断の単一トークン使い回しを廃止し、folderCode 単位の使い捨て ID のみ保持
  private readonly folderIdentityMap = new Map<string, { token: string; userAgent: string; activated: boolean }>();
  /** 覚えておく ID の数 (超えたら古いものから捨てる) */
  private static readonly MAX_IDENTITIES = 64;
  /**
   * ゲスト ID を新しく作る間隔の下限。メッシュの取得役として他人の要求で取りに行くとき、URL のフラグメントを
   * 変えるだけで無限に Gofile のアカウントを作らせられる (取得役・中継 Worker の IP が Gofile に締め出される) のを防ぐ。
   */
  private readonly minMintIntervalMs: number;
  private lastMint: { at: number; identity: { token: string; userAgent: string } } | null = null;

  constructor(
    private readonly transport: HttpTransportFn,
    opts?: { apiBaseUrl?: string; uploadHostTemplate?: string; userAgent?: string; minMintIntervalMs?: number },
  ) {
    this.apiBaseUrl = (opts?.apiBaseUrl ?? 'https://api.gofile.io').replace(/\/+$/, '');
    this.uploadHostTemplate = opts?.uploadHostTemplate ?? 'https://{server}.gofile.io';
    this.fixedUserAgent = opts?.userAgent;
    this.minMintIntervalMs = opts?.minMintIntervalMs ?? 0;
  }

  /** 読み出し用の ID を作る (minMintIntervalMs より短い間隔なら、直前に作った ID を使い回す) */
  private async mintForRead(): Promise<{ token: string; userAgent: string }> {
    const now = Date.now();
    if (this.lastMint && now - this.lastMint.at < this.minMintIntervalMs) return this.lastMint.identity;
    const identity = await this.mintDisposableGuestIdentity();
    this.lastMint = { at: now, identity };
    return identity;
  }

  private rememberIdentity(key: string, identity: { token: string; userAgent: string; activated: boolean }): void {
    this.folderIdentityMap.delete(key);
    this.folderIdentityMap.set(key, identity);
    while (this.folderIdentityMap.size > GofileLockerAdapter.MAX_IDENTITIES) {
      const oldest = this.folderIdentityMap.keys().next().value;
      if (oldest === undefined) break;
      this.folderIdentityMap.delete(oldest);
    }
  }

  /**
   * 1-Slab 1-Identity (Unlinkability):
   * 複数の Slab や異なるファイル間で同一の `accountToken` や `User-Agent` が名寄せされないよう、
   * 呼び出しごとに独立した使い捨てゲストアカウント (`POST /accounts`) とランダム化 `User-Agent` を新規発行する。
   */
  async mintDisposableGuestIdentity(): Promise<{ token: string; userAgent: string }> {
    await sodiumReady;
    const userAgent = this.fixedUserAgent ?? pickAnonymousUserAgent();
    try {
      const res = await this.transport(
        new Request(`${this.apiBaseUrl}/accounts`, {
          method: 'POST',
          headers: { 'User-Agent': userAgent },
        }),
      );
      if (res.ok) {
        const json = (await res.json()) as { status?: string; data?: { token?: string } };
        if (json.status === 'ok' && json.data?.token) {
          return { token: json.data.token, userAgent };
        }
      }
    } catch {
      // フォールバック
    }
    return { token: '', userAgent };
  }

  /**
   * GoFile のエッジサーバ (`store-*.gofile.io`) が `Cookie: accountToken=...` での直接 `Range (206)` 取得を
   * 許可するように、`GET /contents/{folderCode}?wt={wt}` (`X-Website-Token`) を1回叩いてセッションを有効化する。
   */
  private async activateFolderSession(
    folderCode: string,
    identity: { token: string; userAgent: string; activated: boolean },
  ): Promise<void> {
    if (!folderCode || !identity.token || identity.activated) return;

    try {
      const wt = await generateGofileWebsiteToken(identity.userAgent, identity.token);
      const res = await this.transport(
        new Request(`${this.apiBaseUrl}/contents/${encodeURIComponent(folderCode)}?wt=${wt}`, {
          method: 'GET',
          headers: {
            'User-Agent': identity.userAgent,
            Authorization: `Bearer ${identity.token}`,
            'X-Website-Token': wt,
            'X-BL': 'en-US',
            Cookie: `accountToken=${identity.token}`,
          },
        }),
      );
      if (res.ok) {
        identity.activated = true;
      }
    } catch {
      // エミュレータ環境等では無視して続行
    }
  }

  async uploadSlab(slabBinary: Uint8Array, slabFilename: string): Promise<UploadedLockerSlabReceipt> {
    await sodiumReady;
    const slabUserAgent = this.fixedUserAgent ?? pickAnonymousUserAgent();
    // Step 1: 最適なエッジサーバを問い合わせ
    let serverName = 'store1';
    try {
      const srvRes = await this.transport(
        new Request(`${this.apiBaseUrl}/servers`, {
          method: 'GET',
          headers: { 'User-Agent': slabUserAgent },
        }),
      );
      if (srvRes.ok) {
        const srvJson = (await srvRes.json()) as {
          status: string;
          data?: { servers?: { name: string }[] };
        };
        serverName = srvJson.data?.servers?.[0]?.name ?? 'store1';
      }
    } catch {
      // フォールバック
    }
    const uploadBase = this.uploadHostTemplate.replace('{server}', serverName).replace(/\/+$/, '');

    // Step 2: Slab バイナリをマルチパート投入 (Slab ごとに独立した無記名セッション)
    const mp = buildMultipartFormData([], {
      fieldName: 'file',
      fileName: slabFilename,
      data: slabBinary,
    });
    const upRes = await this.transport(
      new Request(`${uploadBase}/contents/uploadfile`, {
        method: 'POST',
        headers: {
          'Content-Type': mp.contentType,
          'User-Agent': slabUserAgent,
        },
        body: mp.body as Uint8Array<ArrayBuffer>,
      }),
    );
    if (!upRes.ok) {
      throw new Error(`Gofile uploadfile failed with HTTP ${upRes.status}`);
    }
    const upJson = (await upRes.json()) as {
      status: string;
      data?: {
        id: string;
        name?: string;
        code?: string;
        parentFolder?: string;
        parentFolderCode?: string;
        servers?: string[];
        guestToken?: string;
        directLink?: string;
      };
    };
    if (upJson.status !== 'ok' || !upJson.data) {
      throw new Error('Gofile upload returned non-ok status');
    }

    const contentId = upJson.data.id;
    const parentFolder = upJson.data.parentFolder ?? contentId;
    const folderCode = upJson.data.parentFolderCode ?? upJson.data.code ?? '';
    const guestToken = upJson.data.guestToken ?? '';
    const actualFileName = upJson.data.name ?? slabFilename;
    const edgeServer = upJson.data.servers?.[0];
    const edgeBase = edgeServer
      ? this.uploadHostTemplate.replace('{server}', edgeServer).replace(/\/+$/, '')
      : uploadBase;

    const rawDirectUrl = upJson.data.directLink ?? `${edgeBase}/download/web/${contentId}/${actualFileName}`;
    // 別端末が `/contents/{folderCode}?wt={wt}` でセッションを有効化できるよう、URL フラグメントに folder メタデータを付与
    const downloadUrl = folderCode
      ? `${rawDirectUrl}#folder=${encodeURIComponent(folderCode)}&folderId=${encodeURIComponent(parentFolder)}`
      : rawDirectUrl;

    return {
      lockerId: 'gofile',
      slabId: parentFolder,
      downloadUrl,
      deleteToken: guestToken,
      byteLength: slabBinary.byteLength,
    };
  }

  async fetchSlabRange(
    downloadUrl: string,
    startByte: number,
    endByte: number,
    authToken?: string,
    signal?: AbortSignal,
  ): Promise<Uint8Array | null> {
    await sodiumReady;
    const hashIdx = downloadUrl.indexOf('#');
    const cleanUrl = hashIdx >= 0 ? downloadUrl.slice(0, hashIdx) : downloadUrl;
    const hashStr = hashIdx >= 0 ? downloadUrl.slice(hashIdx + 1) : '';
    const hashParams = new URLSearchParams(hashStr);
    const folderCode = hashParams.get('folder') ?? '';
    const identityScopeKey = folderCode || cleanUrl;

    let identity = this.folderIdentityMap.get(identityScopeKey);
    if (!identity) {
      if (authToken) {
        identity = {
          token: authToken,
          userAgent: this.fixedUserAgent ?? pickAnonymousUserAgent(),
          activated: false,
        };
      } else {
        const minted = await this.mintForRead();
        identity = { ...minted, activated: false };
      }
      this.rememberIdentity(identityScopeKey, identity);
    }

    if (folderCode && identity.token) {
      await this.activateFolderSession(folderCode, identity);
    }

    const extra: Record<string, string> = { 'User-Agent': identity.userAgent };
    if (identity.token) {
      extra.Authorization = `Bearer ${identity.token}`;
      extra.Cookie = `accountToken=${identity.token}`;
    }

    const firstAttempt = await executeRangeFetch(this.transport, cleanUrl, startByte, endByte, extra, signal);
    if (firstAttempt) return firstAttempt;

    // 別端末・別 IP 等でアップロード時の guestToken が弾かれた場合、この Slab 専用の使い捨てゲスト ID を新規発行して再試行
    const freshMinted = await this.mintForRead();
    if (freshMinted.token && freshMinted.token !== identity.token) {
      const freshIdentity = { ...freshMinted, activated: false };
      this.rememberIdentity(identityScopeKey, freshIdentity);
      if (folderCode) {
        await this.activateFolderSession(folderCode, freshIdentity);
      }
      return executeRangeFetch(this.transport, cleanUrl, startByte, endByte, {
        'User-Agent': freshIdentity.userAgent,
        Authorization: `Bearer ${freshIdentity.token}`,
        Cookie: `accountToken=${freshIdentity.token}`,
      }, signal);
    }

    return null;
  }

  async deleteSlab(receipt: UploadedLockerSlabReceipt): Promise<boolean> {
    if (!receipt.deleteToken) return false;
    await sodiumReady;
    const hashIdx = receipt.downloadUrl.indexOf('#');
    const hashParams = new URLSearchParams(hashIdx >= 0 ? receipt.downloadUrl.slice(hashIdx + 1) : '');
    const contentsId = hashParams.get('folderId') ?? receipt.slabId;
    const folderCode = hashParams.get('folder') ?? '';
    if (folderCode) {
      this.folderIdentityMap.delete(folderCode);
    }

    const req = new Request(`${this.apiBaseUrl}/contents`, {
      method: 'DELETE',
      headers: {
        'User-Agent': this.fixedUserAgent ?? pickAnonymousUserAgent(),
        Authorization: `Bearer ${receipt.deleteToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ contentsId }),
    });
    const res = await this.transport(req);
    return res.ok;
  }
}

// ============================================================================
// 6. Pixeldrain アダプタ (`https://pixeldrain.com/api/file/{name}`)
//    - シンプルな REST `PUT /api/file/{name}` -> `{ id }`
//    - `GET /api/file/{id}` (HTTP Range 206 完全対応) + `DELETE /api/file/{id}`
// ============================================================================
export class PixeldrainLockerAdapter implements OverseasLockerAdapter {
  readonly lockerId: OverseasLockerId = 'pixeldrain';
  readonly maxSlabBytes = 1024 * 1024 * 1024; // 1 GiB
  readonly supportsExplicitDelete = true;
  private readonly apiBaseUrl: string;
  private readonly apiKey: string;

  constructor(
    private readonly transport: HttpTransportFn,
    opts?: { apiBaseUrl?: string; apiKey?: string },
  ) {
    this.apiBaseUrl = (opts?.apiBaseUrl ?? 'https://pixeldrain.com/api').replace(/\/+$/, '');
    this.apiKey = opts?.apiKey ?? '';
  }

  private authHeaders(): Record<string, string> {
    if (!this.apiKey) return {};
    return {
      Authorization: `Basic ${btoa(`:${this.apiKey}`)}`,
    };
  }

  async uploadSlab(slabBinary: Uint8Array, slabFilename: string): Promise<UploadedLockerSlabReceipt> {
    const req = new Request(`${this.apiBaseUrl}/file/${encodeURIComponent(slabFilename)}`, {
      method: 'PUT',
      headers: {
        ...this.authHeaders(),
        'Content-Type': 'application/octet-stream',
      },
      body: slabBinary as Uint8Array<ArrayBuffer>,
    });
    const res = await this.transport(req);
    if (!res.ok) {
      throw new Error(`Pixeldrain PUT failed with HTTP ${res.status}`);
    }
    const json = (await res.json()) as { success?: boolean; id?: string };
    if (!json.id) {
      throw new Error('Pixeldrain did not return file id');
    }
    const downloadUrl = `${this.apiBaseUrl}/file/${json.id}`;
    return {
      lockerId: 'pixeldrain',
      slabId: json.id,
      downloadUrl,
      deleteToken: this.apiKey || 'anonymous-delete-token',
      byteLength: slabBinary.byteLength,
    };
  }

  async fetchSlabRange(
    downloadUrl: string, startByte: number, endByte: number, _authToken?: string, signal?: AbortSignal,
  ): Promise<Uint8Array | null> {
    return executeRangeFetch(this.transport, downloadUrl, startByte, endByte, this.authHeaders(), signal);
  }

  async deleteSlab(receipt: UploadedLockerSlabReceipt): Promise<boolean> {
    const req = new Request(receipt.downloadUrl, {
      method: 'DELETE',
      headers: this.authHeaders(),
    });
    const res = await this.transport(req);
    return res.ok;
  }
}

// ============================================================================
// 7. Internet Archive (IAS3) 共通アダプタラッパー
// ============================================================================
export class InternetArchiveLockerAdapter implements OverseasLockerAdapter {
  readonly lockerId: OverseasLockerId = 'internet-archive-s3';
  readonly maxSlabBytes = 10 * 1024 * 1024 * 1024;
  readonly supportsExplicitDelete = true;

  constructor(
    private readonly transport: HttpTransportFn,
    private readonly creds: IaS3Credentials,
  ) {}

  async uploadSlab(slabBinary: Uint8Array, slabFilename: string): Promise<UploadedLockerSlabReceipt> {
    const s3Base = (this.creds.s3Endpoint ?? IA_S3_ENDPOINT).replace(/\/+$/, '');
    const dlBase = (this.creds.downloadEndpoint ?? IA_DOWNLOAD_ENDPOINT).replace(/\/+$/, '');
    const slabKey = `${this.creds.itemIdentifier}/${slabFilename}`;
    const putUrl = `${s3Base}/${slabKey}`;
    const downloadUrl = `${dlBase}/${slabKey}`;

    const req = new Request(putUrl, {
      method: 'PUT',
      headers: buildIaS3PutHeaders(this.creds),
      body: slabBinary as Uint8Array<ArrayBuffer>,
    });
    const res = await this.transport(req);
    if (!res.ok) {
      throw new Error(`Internet Archive IAS3 PUT failed with HTTP ${res.status}`);
    }
    return {
      lockerId: 'internet-archive-s3',
      slabId: slabKey,
      downloadUrl,
      deleteToken: `${this.creds.accessKey}:${this.creds.secretKey}`,
      byteLength: slabBinary.byteLength,
    };
  }

  async fetchSlabRange(
    downloadUrl: string, startByte: number, endByte: number, _authToken?: string, signal?: AbortSignal,
  ): Promise<Uint8Array | null> {
    return executeRangeFetch(this.transport, downloadUrl, startByte, endByte, undefined, signal);
  }

  async deleteSlab(receipt: UploadedLockerSlabReceipt): Promise<boolean> {
    const s3Base = (this.creds.s3Endpoint ?? IA_S3_ENDPOINT).replace(/\/+$/, '');
    const req = new Request(`${s3Base}/${receipt.slabId}`, {
      method: 'DELETE',
      headers: buildIaS3DeleteHeaders(this.creds),
    });
    const res = await this.transport(req);
    return res.status === 200 || res.status === 204;
  }
}

// ============================================================================
// 8. テスト & ローカル検証用の海外ロッカー 6 社プロトコル忠実エミュレータクラスタ
//    (`Catbox`, `Litterbox`, `0x0.st`, `Pomf`, `Gofile`, `Pixeldrain` + `IAS3` 全対応)
// ============================================================================
function extractBinaryFromMultipart(rawBody: Uint8Array, contentType: string): Uint8Array | null {
  const m = /boundary=([^\s;]+)/i.exec(contentType);
  if (!m) return null;
  const boundary = m[1];
  const marker = new TextEncoder().encode('\r\n\r\n');
  const closingBoundary = new TextEncoder().encode(`\r\n--${boundary}`);

  // 最後のパートまたは filename= を含むパートの本文を切り出す
  const fnToken = new TextEncoder().encode('filename="');
  let searchPos = 0;
  while (searchPos < rawBody.byteLength) {
    let fnIdx = -1;
    for (let i = searchPos; i <= rawBody.byteLength - fnToken.byteLength; i++) {
      let ok = true;
      for (let j = 0; j < fnToken.byteLength; j++) {
        if (rawBody[i + j] !== fnToken[j]) {
          ok = false;
          break;
        }
      }
      if (ok) {
        fnIdx = i;
        break;
      }
    }
    if (fnIdx === -1) break;

    // fnIdx 以降の最初の \r\n\r\n を探す
    let dataStart = -1;
    for (let i = fnIdx; i <= rawBody.byteLength - marker.byteLength; i++) {
      if (
        rawBody[i] === 13 &&
        rawBody[i + 1] === 10 &&
        rawBody[i + 2] === 13 &&
        rawBody[i + 3] === 10
      ) {
        dataStart = i + 4;
        break;
      }
    }
    if (dataStart === -1) break;

    // dataStart 以降の \r\n--boundary を探す
    for (let i = dataStart; i <= rawBody.byteLength - closingBoundary.byteLength; i++) {
      let match = true;
      for (let j = 0; j < closingBoundary.byteLength; j++) {
        if (rawBody[i + j] !== closingBoundary[j]) {
          match = false;
          break;
        }
      }
      if (match) {
        return rawBody.slice(dataStart, i);
      }
    }
    break;
  }
  return null;
}

export class MemoryOverseasLockerCluster {
  private readonly files = new Map<
    string,
    {
      data: Uint8Array;
      deleteToken: string;
      lockerHost: string;
      expiresAtMs: number;
    }
  >();
  private readonly disabledHosts = new Set<string>();
  private seq = 0;

  /** カオステスト用: 特定の海外ロッカーホスト (例: `catbox.moe`, `0x0.st`) をダウン状態にする */
  setHostOffline(hostname: string, offline: boolean): void {
    if (offline) {
      this.disabledHosts.add(hostname.toLowerCase());
    } else {
      this.disabledHosts.delete(hostname.toLowerCase());
    }
  }

  get storedFileCount(): number {
    return this.files.size;
  }

  async handleFetch(request: Request, nowMs: number = Date.now()): Promise<Response> {
    const url = new URL(request.url);
    const host = url.hostname.toLowerCase();
    if (this.disabledHosts.has(host)) {
      return new Response('Service Unavailable (Simulated Outage)', { status: 503 });
    }

    // 1. Gofile サーバ検出 (`GET https://api.gofile.io/servers`) & ゲストアカウント発行 (`POST https://api.gofile.io/accounts`)
    if (host === 'api.gofile.io' && url.pathname === '/servers' && request.method === 'GET') {
      return new Response(
        JSON.stringify({
          status: 'ok',
          data: { servers: [{ name: 'store1' }] },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    }
    if (host === 'api.gofile.io' && url.pathname === '/accounts' && request.method === 'POST') {
      const tok = `gftok_guest_${++this.seq}`;
      return new Response(
        JSON.stringify({
          status: 'ok',
          data: { id: `acc_${this.seq}`, tier: 'guest', token: tok },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    }
    if (host === 'api.gofile.io' && url.pathname.startsWith('/contents/') && request.method === 'GET') {
      const wt = request.headers.get('X-Website-Token') ?? url.searchParams.get('wt') ?? '';
      if (!wt || wt.length !== 64) {
        return new Response(JSON.stringify({ status: 'error-notAuthorized' }), { status: 401 });
      }
      return new Response(JSON.stringify({ status: 'ok', data: { children: {} } }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // 2. Gofile DELETE (`DELETE https://api.gofile.io/contents`)
    if (host === 'api.gofile.io' && url.pathname === '/contents' && request.method === 'DELETE') {
      const auth = request.headers.get('Authorization') ?? '';
      if (!auth.startsWith('Bearer ')) return new Response('Unauthorized', { status: 401 });
      const body = (await request.json()) as { contentsId?: string };
      const id = body.contentsId ?? '';
      for (const [dlUrl] of this.files.entries()) {
        if (dlUrl.includes(`/${id}/`)) {
          this.files.delete(dlUrl);
          return new Response(JSON.stringify({ status: 'ok' }), { status: 200 });
        }
      }
      return new Response('Not Found', { status: 404 });
    }

    // 3. Gofile Upload (`POST https://store1.gofile.io/contents/uploadfile` or `https://upload.gofile.io/uploadfile`)
    if (
      host.endsWith('.gofile.io') &&
      (url.pathname === '/contents/uploadfile' || url.pathname === '/uploadfile') &&
      request.method === 'POST'
    ) {
      const ct = request.headers.get('Content-Type') ?? '';
      const raw = new Uint8Array(await request.arrayBuffer());
      const bin = extractBinaryFromMultipart(raw, ct);
      if (!bin) return new Response('Bad Multipart', { status: 400 });
      const contentId = `gf_${++this.seq}`;
      const folderCode = `gfcode_${this.seq}`;
      const guestToken = `gftok_${this.seq}`;
      const edgeHost = host === 'upload.gofile.io' ? 'store1.gofile.io' : host;
      const directLink = `https://${edgeHost}/download/web/${contentId}/slab.bin`;
      this.files.set(directLink, {
        data: bin,
        deleteToken: guestToken,
        lockerHost: edgeHost,
        expiresAtMs: nowMs + 86_400_000 * 10,
      });
      return new Response(
        JSON.stringify({
          status: 'ok',
          data: {
            id: contentId,
            name: 'slab.bin',
            code: folderCode,
            parentFolder: contentId,
            parentFolderCode: folderCode,
            servers: [edgeHost.replace('.gofile.io', '')],
            guestToken,
            directLink,
          },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    }

    // 4. Catbox Upload & Delete (`POST https://catbox.moe/user/api.php`)
    if (host === 'catbox.moe' && url.pathname === '/user/api.php' && request.method === 'POST') {
      const ct = request.headers.get('Content-Type') ?? '';
      const raw = new Uint8Array(await request.arrayBuffer());
      const textView = new TextDecoder().decode(raw.subarray(0, Math.min(raw.byteLength, 1024)));
      if (textView.includes('deletefiles')) {
        const m = /name="files"\r\n\r\n([^\r\n]+)/.exec(textView);
        const fileId = m?.[1]?.trim() ?? '';
        const targetUrl = `https://files.catbox.moe/${fileId}`;
        if (!this.files.has(targetUrl)) return new Response('File not found', { status: 404 });
        this.files.delete(targetUrl);
        return new Response('Files successfully deleted.', { status: 200 });
      }
      const bin = extractBinaryFromMultipart(raw, ct);
      if (!bin) return new Response('Bad Multipart', { status: 400 });
      const fileId = `cb${++this.seq}.bin`;
      const dlUrl = `https://files.catbox.moe/${fileId}`;
      this.files.set(dlUrl, {
        data: bin,
        deleteToken: 'ozzy_ephemeral_userhash',
        lockerHost: 'files.catbox.moe',
        expiresAtMs: nowMs + 86_400_000 * 90,
      });
      return new Response(dlUrl, { status: 200 });
    }

    // 5. Litterbox Upload (`POST https://litterbox.catbox.moe/resources/internals/api.php`)
    if (host === 'litterbox.catbox.moe' && request.method === 'POST') {
      const ct = request.headers.get('Content-Type') ?? '';
      const raw = new Uint8Array(await request.arrayBuffer());
      const bin = extractBinaryFromMultipart(raw, ct);
      if (!bin) return new Response('Bad Multipart', { status: 400 });
      const fileId = `lt${++this.seq}.bin`;
      const dlUrl = `https://litter.catbox.moe/${fileId}`;
      this.files.set(dlUrl, {
        data: bin,
        deleteToken: '',
        lockerHost: 'litter.catbox.moe',
        expiresAtMs: nowMs + 72 * 3600_000,
      });
      return new Response(dlUrl, { status: 200 });
    }

    // 6. 0x0.st & x0.at Upload & Token Delete (`POST https://0x0.st` / `POST https://x0.at`)
    if ((host === '0x0.st' || host === 'x0.at') && request.method === 'POST') {
      const ua = request.headers.get('User-Agent') ?? '';
      if (!ua) return new Response('Missing User-Agent', { status: 403 });
      const ct = request.headers.get('Content-Type') ?? '';
      const raw = new Uint8Array(await request.arrayBuffer());
      if (url.pathname !== '/' && url.pathname !== '') {
        const text = new TextDecoder().decode(raw);
        const existing = this.files.get(request.url);
        if (!existing || !text.includes(existing.deleteToken)) {
          return new Response('Invalid token or file', { status: 403 });
        }
        this.files.delete(request.url);
        return new Response('Deleted', { status: 200 });
      }
      const bin = extractBinaryFromMultipart(raw, ct);
      if (!bin) return new Response('Bad Multipart', { status: 400 });
      const ext = host === 'x0.at' ? 'txt' : 'bin';
      const fileId = `zx${++this.seq}.${ext}`;
      const dlUrl = `https://${host}/${fileId}`;
      const token = `0x0_secret_tok_${this.seq}`;
      this.files.set(dlUrl, {
        data: bin,
        deleteToken: token,
        lockerHost: host,
        expiresAtMs: nowMs + 30 * 86_400_000,
      });
      return new Response(`${dlUrl}\n`, {
        status: 200,
        headers: { 'X-Token': token },
      });
    }

    // 7. Pomf Clone Upload (`POST https://pomf2.lain.la/upload.php`, `https://qu.ax/upload.php`, or `https://uguu.se/upload`)
    if (
      ((host === 'pomf2.lain.la' || host === 'qu.ax') && url.pathname === '/upload.php' && request.method === 'POST') ||
      (host === 'uguu.se' && url.pathname === '/upload' && request.method === 'POST')
    ) {
      const ct = request.headers.get('Content-Type') ?? '';
      const raw = new Uint8Array(await request.arrayBuffer());
      const bin = extractBinaryFromMultipart(raw, ct);
      if (!bin) return new Response('Bad Multipart', { status: 400 });
      const fileId = `pf${++this.seq}.bin`;
      const dlHost = host === 'uguu.se' ? 'd.uguu.se' : host;
      const dlUrl = host === 'uguu.se' ? `https://d.uguu.se/${fileId}` : `https://${host}/f/${fileId}`;
      const delTok = host === 'uguu.se' ? '' : `pomf_del_${this.seq}`;
      this.files.set(dlUrl, {
        data: bin,
        deleteToken: delTok,
        lockerHost: dlHost,
        expiresAtMs: nowMs + 60 * 86_400_000,
      });
      return new Response(
        JSON.stringify({
          success: true,
          files: [{ name: fileId, filename: fileId, url: dlUrl, size: bin.byteLength, deleteToken: delTok }],
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    }

    // 8. Pixeldrain Upload (`PUT https://pixeldrain.com/api/file/:name`) & Delete (`DELETE https://pixeldrain.com/api/file/:id`)
    if (host === 'pixeldrain.com' && url.pathname.startsWith('/api/file/')) {
      if (request.method === 'PUT') {
        const bin = new Uint8Array(await request.arrayBuffer());
        const fileId = `pd_${++this.seq}`;
        const dlUrl = `https://pixeldrain.com/api/file/${fileId}`;
        this.files.set(dlUrl, {
          data: bin,
          deleteToken: 'pd_tok',
          lockerHost: host,
          expiresAtMs: nowMs + 60 * 86_400_000,
        });
        return new Response(JSON.stringify({ success: true, id: fileId }), {
          status: 201,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      if (request.method === 'DELETE') {
        if (!this.files.has(request.url)) return new Response('Not Found', { status: 404 });
        this.files.delete(request.url);
        return new Response(JSON.stringify({ success: true }), { status: 200 });
      }
    }

    // 9. Pomf DELETE (`DELETE https://pomf2.lain.la/f/:id`)
    if (request.method === 'DELETE' && this.files.has(request.url)) {
      this.files.delete(request.url);
      return new Response(null, { status: 204 });
    }

    // 10. 共通 HTTP Range GET (`206 Partial Content`) ハンドラ
    if (request.method === 'GET') {
      const entry = this.files.get(request.url);
      if (!entry || entry.expiresAtMs <= nowMs) {
        return new Response('Not Found', { status: 404 });
      }
      if (this.disabledHosts.has(entry.lockerHost)) {
        return new Response('Locker Host Offline', { status: 503 });
      }
      const rangeHeader = request.headers.get('Range');
      if (rangeHeader) {
        const m = /^bytes=(\d+)-(\d+)?$/.exec(rangeHeader.trim());
        if (m) {
          const start = parseInt(m[1], 10);
          const end = m[2] ? Math.min(parseInt(m[2], 10), entry.data.byteLength - 1) : entry.data.byteLength - 1;
          if (start >= 0 && start <= end && start < entry.data.byteLength) {
            const slice = entry.data.subarray(start, end + 1);
            return new Response(slice as Uint8Array<ArrayBuffer>, {
              status: 206,
              headers: {
                'Accept-Ranges': 'bytes',
                'Content-Type': 'application/octet-stream',
                'Content-Length': slice.byteLength.toString(),
                'Content-Range': `bytes ${start}-${end}/${entry.data.byteLength}`,
              },
            });
          }
        }
      }
      return new Response(entry.data as Uint8Array<ArrayBuffer>, {
        status: 200,
        headers: {
          'Accept-Ranges': 'bytes',
          'Content-Type': 'application/octet-stream',
          'Content-Length': entry.data.byteLength.toString(),
        },
      });
    }

    return new Response('Not Found', { status: 404 });
  }
}

// ============================================================================
// 9. 汎用ロッカー対応 二重タイマー付き RAM Slab ステージング・ミキサー (`GenericLockerSlabStagingMixer`)
// ============================================================================
export interface SlabChunkSlot {
  readonly shareIndex: number;
  readonly slotOffsetIndex: number;
}

export interface GenericFlushedSlabResult {
  readonly receipt: UploadedLockerSlabReceipt;
  readonly flushReason: FlushReason;
  readonly chunkCount: number;
  readonly totalBytes: number;
  readonly chunkMap: SlabChunkSlot[];
  /** Manifest に入れる置き場所 (削除トークンは入れない) */
  readonly location: OzzySlabLocation;
}

/** 置いた直後に Slab を確かめる関数 (置いたと言うだけの偽の受け取り票を弾く)。false なら別のロッカーで置き直す */
export type SlabUploadVerifier = (receipt: UploadedLockerSlabReceipt, chunkMap: readonly SlabChunkSlot[]) => Promise<boolean>;

function shuffleEntries<T>(items: T[]): T[] {
  const arr = [...items];
  for (let i = arr.length - 1; i > 0; i--) {
    const r = sodium.randombytes_uniform(i + 1);
    const tmp = arr[i];
    arr[i] = arr[r];
    arr[r] = tmp;
  }
  return arr;
}

export class GenericLockerSlabStagingMixer {
  private readonly chunkBytes: number;
  private readonly targetBatchChunks: number;
  private readonly idleGapMs: number;
  private readonly maxWaitMs: number;
  private staged: { shareIndex: number; arenaSlot: number; data: Uint8Array }[] = [];
  private idleTimer: ReturnType<typeof setTimeout> | null = null;
  private maxWaitTimer: ReturnType<typeof setTimeout> | null = null;
  private activeFlushes: Promise<GenericFlushedSlabResult | null>[] = [];
  private flushedResults: GenericFlushedSlabResult[] = [];
  /** 置けなかった (全ロッカーが失敗した) シェアの番号 */
  private failedShares: number[] = [];

  constructor(
    private readonly opts: {
      readonly adapter: OverseasLockerAdapter;
      readonly fallbackAdapters?: readonly OverseasLockerAdapter[];
      readonly arena: RamChunkArena;
      readonly chunkBytes?: number;
      readonly targetBatchChunks?: number;
      readonly idleGapMs?: number;
      readonly maxWaitMs?: number;
      readonly verify?: SlabUploadVerifier | null;
      readonly onSlabFlushed?: (res: GenericFlushedSlabResult) => void;
    },
  ) {
    this.chunkBytes = opts.chunkBytes ?? OZZY_CHUNK_BYTES;
    this.targetBatchChunks = opts.targetBatchChunks ?? 8;
    this.idleGapMs = opts.idleGapMs ?? 60;
    this.maxWaitMs = opts.maxWaitMs ?? 200;
  }

  private clearTimers(): void {
    if (this.idleTimer !== null) {
      clearTimeout(this.idleTimer);
      this.idleTimer = null;
    }
    if (this.maxWaitTimer !== null) {
      clearTimeout(this.maxWaitTimer);
      this.maxWaitTimer = null;
    }
  }

  ingestChunk(shareIndex: number, rawChunk: Uint8Array): void {
    if (rawChunk.byteLength !== this.chunkBytes) {
      throw new RangeError(`Expected ${this.chunkBytes}-byte chunk, got ${rawChunk.byteLength}`);
    }
    // RAM スロットそのものに置く (コピーを作らない。解放時にゼロで埋まる)
    const { arenaSlot, buffer } = this.opts.arena.acquire(rawChunk);
    this.staged.push({ shareIndex, arenaSlot, data: buffer.subarray(0, this.chunkBytes) });

    if (this.staged.length >= this.targetBatchChunks) {
      this.clearTimers();
      this.triggerFlush('batch_full');
      return;
    }

    if (this.staged.length === 1 && this.maxWaitTimer === null) {
      this.maxWaitTimer = setTimeout(() => {
        this.maxWaitTimer = null;
        this.clearTimers();
        if (this.staged.length > 0) this.triggerFlush('max_wait_timeout');
      }, this.maxWaitMs);
    }

    if (this.idleTimer !== null) clearTimeout(this.idleTimer);
    this.idleTimer = setTimeout(() => {
      this.idleTimer = null;
      this.clearTimers();
      if (this.staged.length > 0) this.triggerFlush('idle_gap_timeout');
    }, this.idleGapMs);
  }

  async flushRemainingAndWait(): Promise<GenericFlushedSlabResult[]> {
    this.clearTimers();
    if (this.staged.length > 0) {
      this.triggerFlush('manual_force');
    }
    await Promise.all(this.activeFlushes);
    return [...this.flushedResults];
  }

  /** 全ロッカーへの PUT が失敗して置けなかったシェアの番号 */
  get failedShareIndices(): readonly number[] {
    return this.failedShares;
  }

  private triggerFlush(reason: FlushReason): void {
    if (this.staged.length === 0) return;
    const batch = this.staged.splice(0, this.staged.length);
    // ★ 失敗はその場で受け止める (reject を放置すると Node では unhandledRejection で落ちる)
    const shares = batch.map(b => b.shareIndex);
    const p = this.executeBatchFlush(batch, reason).catch(() => {
      this.failedShares.push(...shares);
      return null;
    });
    this.activeFlushes.push(p);
  }

  private async executeBatchFlush(
    batch: { shareIndex: number; arenaSlot: number; data: Uint8Array }[],
    reason: FlushReason,
  ): Promise<GenericFlushedSlabResult> {
    await sodiumReady;
    try {
      const shuffled = shuffleEntries(batch);
      const totalBytes = shuffled.length * this.chunkBytes;
      const slabBinary = new Uint8Array(totalBytes);
      const chunkMap: SlabChunkSlot[] = [];

      for (let slotIdx = 0; slotIdx < shuffled.length; slotIdx++) {
        slabBinary.set(shuffled[slotIdx].data, slotIdx * this.chunkBytes);
        chunkMap.push({
          shareIndex: shuffled[slotIdx].shareIndex,
          slotOffsetIndex: slotIdx,
        });
      }

      const randHex = Encoding.toHex(sodium.randombytes_buf(12));
      // タイミング相関防止用の暗号学的ランダムジッタ遅延 (sodium.randombytes_uniform)
      const jitterRange = Math.max(1, Math.min(this.idleGapMs, 40));
      const jitterMs = sodium.randombytes_uniform(jitterRange);
      if (jitterMs > 0) {
        await new Promise(r => setTimeout(r, jitterMs));
      }

      const candidates: OverseasLockerAdapter[] = [
        this.opts.adapter,
        ...(this.opts.fallbackAdapters ?? []).filter(a => a.lockerId !== this.opts.adapter.lockerId),
      ];
      let receipt: UploadedLockerSlabReceipt | null = null;
      let lastErr: unknown = null;
      try {
        for (const candidate of candidates) {
          if (totalBytes > candidate.maxSlabBytes) continue;
          try {
            const r = await candidate.uploadSlab(slabBinary, `slab_${randHex}.bin`);
            // ★ 置いたと言うだけの受け取り票 (M1 の嘘・ロッカーの取りこぼし) は、確かめて弾く
            if (this.opts.verify && !(await this.opts.verify(r, chunkMap))) {
              lastErr = new Error(`${candidate.lockerId}: uploaded Slab could not be verified`);
              continue;
            }
            receipt = r;
            break;
          } catch (err) {
            lastErr = err;
          }
        }
      } finally {
        slabBinary.fill(0);
      }
      if (!receipt) {
        throw lastErr instanceof Error ? lastErr : new Error('All locker adapters failed to upload Slab');
      }

      const res: GenericFlushedSlabResult = {
        receipt,
        flushReason: reason,
        chunkCount: batch.length,
        totalBytes,
        chunkMap,
        location: { lockerId: receipt.lockerId, url: receipt.downloadUrl, slabChunks: shuffled.length, chunkMap },
      };
      this.flushedResults.push(res);
      this.opts.onSlabFlushed?.(res);
      return res;
    } finally {
      for (const item of batch) {
        this.opts.arena.releaseAndZeroize(item.arenaSlot);
      }
    }
  }
}

// ============================================================================
// 10. 異種混合マルチロッカー並列コーディネータ (`OverseasMultiLockerCoordinator`)
//     - 32 個のシェアを複数のロッカーに散らす。1 つのロッカーが丸ごと消えても残りから 16 個集まれば復元できる
//     - 置き場所は Manifest に入れ、Manifest は P2P のファイル保管に置く (共通のディレクトリ・Worker を使わない)
//     - 置くときは OnionLockerAdapter (回路の M1 に頼む)、取るときは P2P メッシュの取得役 (SlabReader + MeshRange)
// ============================================================================

/** 1 ストライプで置けたシェアがこれ未満なら、アップロードを失敗にする (16 で復元できるが、余裕が無いと 1 つの消失で読めなくなる) */
export const OZZY_MIN_COMMITTED_SHARES = OZZY_RS_K + 4;

export interface OverseasCoordinatorOptions {
  /** Manifest の置き場所 (P2P のファイル保管。OzNode.ozzyManifestStore) */
  readonly manifestStore: OzzyManifestStore;
  readonly adapters: readonly OverseasLockerAdapter[];
  readonly chunkBytes?: number;
  readonly targetBatchChunks?: number;
  readonly idleGapMs?: number;
  readonly maxWaitMs?: number;
  /** P2P メッシュの取得役 (OzNode.ozzyMesh)。あれば取るとき・置いた Slab を確かめるときに使う */
  readonly mesh?: Pick<OzzyMeshFetcher, 'fetchRange' | 'ready'> | null;
  /** 取り方 (既定: mesh があれば 'mesh-only'、無ければ 'direct-only')。direct はアダプタで取る */
  readonly route?: OzzyFetchRoute;
  /** 1 ストライプで置けたシェアの下限 (既定 OZZY_MIN_COMMITTED_SHARES) */
  readonly minCommittedShares?: number;
  /** 置いた直後に Slab の最後のチャンクの tag を取って確かめる (既定 true) */
  readonly verifyUploads?: boolean;
}

export class OverseasMultiLockerCoordinator {
  readonly arena: RamChunkArena;
  private readonly chunkBytes: number;
  private readonly targetBatchChunks: number;
  private readonly idleGapMs: number;
  private readonly maxWaitMs: number;
  private readonly minCommitted: number;
  private readonly route: OzzyFetchRoute;
  private readonly adaptersById = new Map<string, OverseasLockerAdapter>();
  private readonly reader: OzzySlabReader;
  /** 診断・テスト用 */
  public readonly uploadStats = { slabs: 0, verified: 0, verifyFailed: 0 };

  constructor(private readonly opts: OverseasCoordinatorOptions) {
    this.chunkBytes = opts.chunkBytes ?? OZZY_CHUNK_BYTES;
    this.targetBatchChunks = opts.targetBatchChunks ?? 8;
    this.idleGapMs = opts.idleGapMs ?? 50;
    this.maxWaitMs = opts.maxWaitMs ?? 180;
    this.minCommitted = opts.minCommittedShares ?? OZZY_MIN_COMMITTED_SHARES;
    this.route = opts.route ?? (opts.mesh ? 'mesh-only' : 'direct-only');
    this.arena = new RamChunkArena(32, this.chunkBytes);
    for (const a of opts.adapters) {
      this.adaptersById.set(a.lockerId, a);
    }
    this.reader = new OzzySlabReader({
      manifestStore: opts.manifestStore,
      mesh: opts.mesh,
      route: this.route,
      direct: (loc, start, end, signal) => {
        const adapter = this.adaptersById.get(loc.lockerId);
        // 知らないロッカー (Manifest に入っていた未知の lockerId) へは直接取りに行かない
        return adapter ? adapter.fetchSlabRange(loc.downloadUrl, start, end, undefined, signal) : Promise.resolve(null);
      },
    });
  }

  /** 直近のダウンロードが失敗した理由 */
  get lastDownloadFailure(): SlabReadFailure | null {
    return this.reader.lastFailure;
  }

  /** 取得の統計 (メッシュ経由・直接のシェア数など) */
  get downloadStats() {
    return this.reader.stats;
  }

  /** 置いた Slab の最後のスロットの tag を取って確かめる (メッシュがあればメッシュで。自分の IP をロッカーに見せない) */
  private verifier(stripeIndex: number, kTag: Uint8Array): SlabUploadVerifier | null {
    if (this.opts.verifyUploads === false) return null;
    return async (receipt, chunkMap) => {
      const last = chunkMap.reduce((a, b) => (b.slotOffsetIndex > a.slotOffsetIndex ? b : a));
      const expectedTag = computeChunkTag(kTag, stripeIndex, last.shareIndex);
      const start = last.slotOffsetIndex * this.chunkBytes;
      let ok = false;
      if (this.opts.mesh && this.route !== 'direct-only') {
        const r = await this.opts.mesh.fetchRange(
          { lockerId: receipt.lockerId, url: receipt.downloadUrl, start, length: OZZY_TAG_BYTES, expectedTag }, () => true,
        );
        ok = r.ok;
      } else {
        const adapter = this.adaptersById.get(receipt.lockerId);
        const got = adapter ? await adapter.fetchSlabRange(receipt.downloadUrl, start, start + OZZY_TAG_BYTES - 1).catch(() => null) : null;
        ok = got !== null && got.length === OZZY_TAG_BYTES && bytesEqual(got, expectedTag);
      }
      if (ok) this.uploadStats.verified++;
      else this.uploadStats.verifyFailed++;
      return ok;
    };
  }

  async uploadStripeAcrossLockers(
    stripePlaintext: Uint8Array,
    stripeIndex: number,
    stripeSeed: Uint8Array,
    dropShareIndices?: ReadonlySet<number>,
  ): Promise<{
    locations: OzzySlabLocation[];
    receipts: UploadedLockerSlabReceipt[];
    shareDigests: Uint8Array;
    committedShares: number;
  }> {
    await sodiumReady;
    const keys = await deriveOzzyKeys(stripeSeed);
    const dataChunks = await encryptStripeDataChunks(stripePlaintext, stripeIndex, keys, this.chunkBytes);
    const parityChunks = generateStripeParityChunks(dataChunks, stripeIndex, keys.kTag);
    const allChunks: OzzyChunk[] = [...dataChunks, ...parityChunks];
    const shareDigests = computeStripeShareDigests(allChunks);

    const receipts: UploadedLockerSlabReceipt[] = [];
    const locations: OzzySlabLocation[] = [];
    let committedShares = 0;
    const verify = this.verifier(stripeIndex, keys.kTag);

    const mixers = this.opts.adapters.map(
      adapter =>
        new GenericLockerSlabStagingMixer({
          adapter,
          fallbackAdapters: this.opts.adapters,
          arena: this.arena,
          chunkBytes: this.chunkBytes,
          targetBatchChunks: this.targetBatchChunks,
          idleGapMs: this.idleGapMs,
          maxWaitMs: this.maxWaitMs,
          verify,
          onSlabFlushed: res => {
            this.uploadStats.slabs++;
            receipts.push(res.receipt);
            locations.push(res.location);
            committedShares += res.chunkMap.length;
          },
        }),
    );

    // シェアをロッカーごとのミキサーへ振り分ける (1 つのロッカーが落ちても他から 16 個集まるように散らす)
    for (const chunk of allChunks) {
      if (dropShareIndices?.has(chunk.shareIndex)) continue;
      mixers[chunk.shareIndex % mixers.length].ingestChunk(chunk.shareIndex, chunk.rawChunk);
    }
    for (const c of allChunks) c.rawChunk.fill(0); // ミキサーの RAM スロットへ写したので、元の暗号文は消す

    await Promise.all(mixers.map(m => m.flushRemainingAndWait()));

    if (committedShares < this.minCommitted) {
      throw new Error(
        `Only ${committedShares}/32 shares of stripe ${stripeIndex} reached a locker (need ${this.minCommitted})`,
      );
    }
    return { locations, receipts, shareDigests, committedShares };
  }

  /**
   * ファイルをストライプ単位で読みながら (全体をメモリに載せない) 上げ、最後に Manifest (置き場所入り) を P2P に置いてリンクを返す。
   * source は File / Blob / Uint8Array。fileData は旧名 (Uint8Array)。
   */
  async uploadFile(params: {
    source?: OzzyUploadSource;
    fileData?: Uint8Array;
    fileName: string;
    mimeType: string;
    dropShareIndices?: ReadonlySet<number>;
    stripeConcurrency?: number;
    onProgress?: (completedStripes: number, totalStripes: number) => void;
    signal?: AbortSignal;
  }): Promise<{
    linkText: string;
    manifest: OzzyManifestV4;
    receipts: UploadedLockerSlabReceipt[];
  }> {
    await sodiumReady;
    const src = params.source ?? params.fileData;
    if (!src) throw new Error('uploadFile: source is required');
    const fileSeed = await generateOzzySeed();
    const reader = new OrderedSourceReader(src, maxStripePlainBytes(this.chunkBytes));
    const stripeCount = reader.count;
    const stripes = new Array<OzzyStripeV4>(stripeCount);
    const allReceipts: UploadedLockerSlabReceipt[] = [];

    // 複数ストライプを並列にアップロードする (1 ストライプ = 平文 64 MiB + 暗号文 128 MiB を持つので既定 1 本)。
    // ★ 読み出しは先頭から 1 つずつ (OrderedSourceReader)。同時に持つのは並列数ぶんのストライプだけ
    const concurrency = Math.max(1, params.stripeConcurrency ?? 1);
    let completed = 0;
    let failure: unknown = null;
    const workers = Array.from({ length: Math.min(concurrency, stripeCount) }, async () => {
      while (failure === null) {
        if (params.signal?.aborted) {
          failure = new Error('aborted');
          return;
        }
        let next: { index: number; data: Uint8Array } | null;
        try {
          next = await reader.next();
        } catch (e) {
          failure = e;
          return;
        }
        if (!next) return;
        const s = next.index;
        const stripeSeed = await deriveStripeSeed(fileSeed, s);
        try {
          const res = await this.uploadStripeAcrossLockers(next.data, s, stripeSeed, params.dropShareIndices);
          allReceipts.push(...res.receipts);
          stripes[s] = { stripeSeed, shareDigests: res.shareDigests, locations: res.locations };
          params.onProgress?.(++completed, stripeCount + 1);
        } catch (e) {
          failure = e;
        }
        // ★ next.data は呼び出し側の Uint8Array の一部のことがある (subarray)。ここでゼロで埋めない
      }
    });
    await Promise.all(workers);
    fileSeed.fill(0);
    if (failure !== null) throw failure;

    const manifest: OzzyManifestV4 = {
      version: 4,
      chunkBytes: this.chunkBytes,
      totalFileSize: reader.size,
      createdAtDay: blindedEpochDay(),
      fileHash: reader.digest(),
      fileName: params.fileName,
      mimeType: params.mimeType,
      stripes,
    };
    // ★ Manifest (鍵・置き場所) は P2P のファイル保管へ。保管するノードには暗号文しか見えない (鍵はリンクの中)
    const body = await this.opts.manifestStore.put(serializeOzzyManifestV4(manifest), params.signal);
    params.onProgress?.(stripeCount + 1, stripeCount + 1);

    return { linkText: formatOzzyLinkV3(body), manifest, receipts: allReceipts };
  }

  /** リンクから Manifest だけを取る (名前・大きさを先に見せて、保存先を選んでもらうため) */
  async readManifest(linkText: string, signal?: AbortSignal): Promise<OzzyManifestV4 | null> {
    return this.reader.readManifest(linkText, signal);
  }

  /** リンクからファイルを取り、番号順に sink へ書き出す (全体をメモリに載せない)。失敗したら lastDownloadFailure を見る */
  async downloadToSink(
    linkText: string,
    sink: OzzyByteSink,
    opts: { manifest?: OzzyManifestV4; onProgress?: (p: SlabReadProgress) => void; signal?: AbortSignal } = {},
  ): Promise<OzzyManifestV4 | null> {
    return this.reader.downloadToSink(linkText, sink, opts);
  }

  /** リンクからファイル全体を取って復元する (小さいファイル・テスト用)。失敗したら lastDownloadFailure を見る */
  async downloadFile(
    linkText: string,
    opts?: { onProgress?: (done: number, total: number) => void; signal?: AbortSignal },
  ): Promise<{ manifest: OzzyManifestV4; data: Uint8Array } | null> {
    return this.reader.downloadFile(linkText, p => opts?.onProgress?.(p.stripesDone, p.stripeCount), opts?.signal);
  }

  async deleteAllReceipts(receipts: readonly UploadedLockerSlabReceipt[]): Promise<number> {
    const results = await Promise.all(
      receipts.map(async r => {
        const adapter = this.adaptersById.get(r.lockerId);
        try {
          return adapter ? await adapter.deleteSlab(r) : false;
        } catch {
          return false;
        }
      }),
    );
    return results.filter(Boolean).length;
  }
}

/**
 * メッシュの取得役 (ozzy/MeshRange の OzzyRangeServer) がロッカーから範囲を取る関数。ロッカーの種類で取り方を変える
 * (Gofile はゲスト ID とセッションの有効化、0x0.st は User-Agent が要る)。それ以外は素の HTTP Range GET。
 * ★ ブラウザでは CORS を返さないロッカーが多いので、transport には中継 Worker 経由のもの (createWorkerCorsProxyTransport) を渡す。
 * ★ 404 / 410 は 'not-found' (読み手は別の置き場所へ回る)。
 */
export function createLockerRangeFetch(
  transport: HttpTransportFn = (req) => fetch(req, { cache: 'no-store' }),
): OzzyRangeFetchFn {
  const http = createHttpRangeFetch(transport);
  // 他人の要求で取りに行くので、Gofile のゲスト ID は 5 秒に 1 つまでしか作らない
  const gofile = new GofileLockerAdapter(transport, { minMintIntervalMs: 5_000 });
  const zeroX = new ZeroXZeroLockerAdapter(transport);
  return async (lockerId, url, start, end, signal) => {
    if (lockerId === 'gofile') return gofile.fetchSlabRange(url, start, end, undefined, signal);
    if (lockerId === '0x0.st') return zeroX.fetchSlabRange(url, start, end, undefined, signal);
    return http(lockerId, url, start, end, signal);
  };
}

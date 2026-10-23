/**
 * InternetArchiveSlab — Internet Archive (archive.org IAS3 API) の定数・ヘッダ・試験用の模擬サーバ。
 *
 * ★ Ozzy は IA へのアップロードを使わない (旧 OzzyInternetArchiveCoordinator / RamSlabStagingMixer は削除)。
 *   IA は利用者自身のアカウント (メールアドレスで登録した鍵) で PUT する。アップロードをオニオン回路の M1 に頼むと
 *   鍵を M1 に渡すことになり、頼まなければ告発者の IP が IA (と中継 Worker) に届く。どちらでもアカウントそのものが
 *   告発者を名指しする。公開ロッカーへのアップロードは OnionLockers (資格情報なし・M1 経由) を使う。
 */
export const IA_S3_ENDPOINT = 'https://s3.us.archive.org';
export const IA_DOWNLOAD_ENDPOINT = 'https://archive.org/download';
export const DEFAULT_IA_POLITE_CAP_BYTES = 10 * 1024 * 1024 * 1024; // 1 アカウントあたり自主上限 10 GiB

export interface IaS3Credentials {
  readonly itemIdentifier: string; // 例: "ozzy-blind-vault-01"
  readonly accessKey: string;
  readonly secretKey: string;
  readonly politeCapBytes?: number;
  readonly s3Endpoint?: string; // 既定: https://s3.us.archive.org (実機 Worker テスト時: https://.../ias3)
  readonly downloadEndpoint?: string; // 既定: https://archive.org/download (実機 Worker テスト時: https://.../download)
}

export type IaUploadSlabHeaders = Record<string, string> & {
  readonly Authorization: string;
  readonly 'Content-Type': string;
  readonly 'x-archive-auto-make-bucket': '1';
  readonly 'x-archive-meta-mediatype': 'data';
  readonly 'x-archive-meta-noindex': 'true';
  readonly 'x-archive-queue-derive': '0';
};

/**
 * Internet Archive IAS3 API への行儀の良い PUT ヘッダを生成する。
 * - `x-archive-queue-derive: 0`: IA のバックグラウンド変換ジョブを走らせない (迷惑防止の最重要ヘッダ)
 * - `x-archive-meta-noindex: true`: 公開検索一覧に載せない
 */
export function buildIaS3PutHeaders(creds: IaS3Credentials): IaUploadSlabHeaders {
  return {
    Authorization: `LOW ${creds.accessKey}:${creds.secretKey}`,
    'Content-Type': 'application/octet-stream',
    'x-archive-auto-make-bucket': '1',
    'x-archive-meta-mediatype': 'data',
    'x-archive-meta-noindex': 'true',
    'x-archive-queue-derive': '0',
  };
}

export function buildIaS3DeleteHeaders(creds: IaS3Credentials): Record<string, string> {
  return {
    Authorization: `LOW ${creds.accessKey}:${creds.secretKey}`,
  };
}

/**
 * テストおよびローカル検証用の Internet Archive (IAS3 + archive.org/download Range GET + DELETE) 模擬サーバ。
 * 自主容量上限 (politeCapBytes) を超えた場合は最も古い Slab を自動 DELETE して容量を空ける。
 */
export class MemoryInternetArchiveServer {
  private readonly files = new Map<
    string,
    {
      data: Uint8Array;
      createdAtMs: number;
      lastAccessedMs: number;
      expireAtMs: number;
      noindex: boolean;
      deriveDisabled: boolean;
    }
  >();
  private totalBytes = 0;
  private putCount = 0;
  private rangeGetCount = 0;
  private deleteCount = 0;

  constructor(readonly politeCapBytes: number = DEFAULT_IA_POLITE_CAP_BYTES) {}

  get stats() {
    return {
      fileCount: this.files.size,
      totalBytes: this.totalBytes,
      putCount: this.putCount,
      rangeGetCount: this.rangeGetCount,
      deleteCount: this.deleteCount,
    };
  }

  /** 期限切れまたは自主容量上限超過分の Slab を自動で DELETE パージする */
  purgeExpiredOrOverCap(nowMs: number = Date.now(), requiredBytes: number = 0): number {
    let purged = 0;
    // 1. 期限切れ Slab の削除
    for (const [key, entry] of this.files.entries()) {
      if (entry.expireAtMs <= nowMs) {
        this.totalBytes -= entry.data.byteLength;
        this.files.delete(key);
        this.deleteCount++;
        purged++;
      }
    }

    // 2. 自主容量上限 (politeCapBytes) を超える場合は最終アクセスが最も古い Slab から DELETE
    while (this.totalBytes + requiredBytes > this.politeCapBytes && this.files.size > 0) {
      let oldestKey: string | null = null;
      let oldestAccess = Infinity;
      for (const [key, entry] of this.files.entries()) {
        if (entry.lastAccessedMs < oldestAccess) {
          oldestAccess = entry.lastAccessedMs;
          oldestKey = key;
        }
      }
      if (!oldestKey) break;
      const victim = this.files.get(oldestKey)!;
      this.totalBytes -= victim.data.byteLength;
      this.files.delete(oldestKey);
      this.deleteCount++;
      purged++;
    }
    return purged;
  }

  async handleFetch(request: Request, nowMs: number = Date.now(), ttlMs: number = 90 * 86_400_000): Promise<Response> {
    const url = new URL(request.url);
    // パス形式: /{itemIdentifier}/{slabFilename} または /download/{itemIdentifier}/{slabFilename}
    const parts = url.pathname.split('/').filter(Boolean);
    const key = parts[0] === 'download' ? parts.slice(1).join('/') : parts.join('/');

    if (request.method === 'PUT') {
      const auth = request.headers.get('Authorization') ?? '';
      if (!auth.startsWith('LOW ')) {
        return new Response('Missing IAS3 LOW Authorization', { status: 401 });
      }
      const noindex = request.headers.get('x-archive-meta-noindex') === 'true';
      const deriveDisabled = request.headers.get('x-archive-queue-derive') === '0';
      const body = new Uint8Array(await request.arrayBuffer());

      this.purgeExpiredOrOverCap(nowMs, body.byteLength);
      if (this.totalBytes + body.byteLength > this.politeCapBytes) {
        return new Response('Polite Storage Cap Exceeded', { status: 507 });
      }

      const existing = this.files.get(key);
      if (existing) {
        this.totalBytes -= existing.data.byteLength;
      }

      this.files.set(key, {
        data: body,
        createdAtMs: nowMs,
        lastAccessedMs: nowMs,
        expireAtMs: nowMs + ttlMs,
        noindex,
        deriveDisabled,
      });
      this.totalBytes += body.byteLength;
      this.putCount++;

      return new Response(null, { status: 200 });
    }

    if (request.method === 'DELETE') {
      const auth = request.headers.get('Authorization') ?? '';
      if (!auth.startsWith('LOW ')) {
        return new Response('Missing IAS3 LOW Authorization', { status: 401 });
      }
      const existing = this.files.get(key);
      if (!existing) {
        return new Response('Not Found', { status: 404 });
      }
      this.totalBytes -= existing.data.byteLength;
      this.files.delete(key);
      this.deleteCount++;
      return new Response(null, { status: 204 });
    }

    if (request.method === 'GET') {
      const entry = this.files.get(key);
      if (!entry) {
        return new Response('Not Found', { status: 404 });
      }
      entry.lastAccessedMs = nowMs;

      const rangeHeader = request.headers.get('Range');
      if (rangeHeader) {
        const m = /^bytes=(\d+)-(\d+)?$/.exec(rangeHeader.trim());
        if (m) {
          const start = parseInt(m[1], 10);
          const end = m[2] ? Math.min(parseInt(m[2], 10), entry.data.byteLength - 1) : entry.data.byteLength - 1;
          if (start >= 0 && start <= end && start < entry.data.byteLength) {
            const slice = entry.data.subarray(start, end + 1);
            this.rangeGetCount++;
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

    return new Response('Method Not Allowed', { status: 405 });
  }
}

export type FlushReason = 'batch_full' | 'idle_gap_timeout' | 'max_wait_timeout' | 'manual_force';

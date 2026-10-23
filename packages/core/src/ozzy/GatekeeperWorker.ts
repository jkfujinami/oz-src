/**
 * GatekeeperWorker — Cloudflare R2 バケット前段で動作する自律型 Gatekeeper Worker 実装。
 *
 * 設計仕様 (docs/design/03_storage_format.md §3.3, docs/design/04_placement.md §4.3-4.4, docs/design/10_abuse.md §10.1):
 *   1. 容量 9.0 GiB ハードキャップ (2,304 スロット × 4 MiB = 9,663,676,416 B)
 *   2. Denial-of-Wallet 完全防御:
 *      - 月間 Class A 操作上限: 500,000 回 (無料枠 100 万回の 50%)
 *      - 月間 Class B 操作上限: 5,000,000 回 (無料枠 1,000 万回の 50%)
 *   3. Manifest 専用保護プール隔離:
 *      - スロット 0..229 (先頭 10% = 230 枠): Manifest ストライプ専用
 *      - スロット 230..2303 (残り 90% = 2,074 枠): 通常データチャンク専用
 *   4. 4 段階の自律リングバッファ退避 (selectVictimSlot):
 *      ① 期限切れスロット (expireDay <= today または初期ダミー expireDay == 0)
 *      ② 一度も読まれていない未取得スロット (lastFetchedDay == 0 のスパム/死蔵データ優先パージ)
 *      ③ 長期間読まれていないコールドスロット (today - lastFetchedDay >= 30 日の LRU)
 *      ④ 候補 4 スロットすべてがアクティブなホットデータの場合は上書きを拒否し `409 SLOT_HOT_FULL` を返却
 *   5. GET 時の自律 TOUCH & HTTP Range: bytes=start-end スライシング対応 + ブラウザ CORS 完全対応
 */
import { bytesEqual } from '../files/FileFormat';
import {
  OZZY_DATA_POOL_SLOTS,
  OZZY_MANIFEST_POOL_SLOTS,
  OZZY_TAG_BYTES,
  OZZY_TOTAL_SLOTS,
} from './OzzyKdf';
import { OZZY_CHUNK_BYTES } from './OzzyChunk4M';
import { verifyChunkVoucherProof } from './OzzyVoucher';

export const WORKER_MONTHLY_CLASS_A_CAP = 500_000;
export const WORKER_MONTHLY_CLASS_B_CAP = 5_000_000;
export const WORKER_HOT_PROTECT_DAYS = 30;
export const WORKER_TOUCH_EXTEND_DAYS = 75;
export const SLOT_META_BYTES = 20; // tag(16B) + expireDay(u16) + lastFetchedDay(u16)

const ZERO_TAG_16 = new Uint8Array(16);

function isAllZeroTag(tag: Uint8Array): boolean {
  return bytesEqual(tag, ZERO_TAG_16);
}

/** Cloudflare R2 バインディングの最小互換インターフェース (実機 Worker とローカルテストの双方で動作) */
export interface R2BucketLike {
  get(key: string, options?: { range?: { offset: number; length: number } }): Promise<R2ObjectBodyLike | null>;
  put(key: string, value: Uint8Array | ArrayBuffer): Promise<void>;
}

export interface R2ObjectBodyLike {
  arrayBuffer(): Promise<ArrayBuffer>;
  readonly size: number;
}

/** テストおよびローカルシミュレーション用のオンメモリ R2 バケット実装 */
export class MemoryR2Bucket implements R2BucketLike {
  private readonly objects = new Map<string, Uint8Array>();

  async get(key: string, options?: { range?: { offset: number; length: number } }): Promise<R2ObjectBodyLike | null> {
    const data = this.objects.get(key);
    if (!data) return null;
    if (options?.range) {
      const start = Math.max(0, options.range.offset);
      const end = Math.min(data.length, start + options.range.length);
      const slice = data.subarray(start, end);
      return {
        size: slice.byteLength,
        async arrayBuffer() {
          return slice.slice().buffer;
        },
      };
    }
    return {
      size: data.byteLength,
      async arrayBuffer() {
        return data.slice().buffer;
      },
    };
  }

  async put(key: string, value: Uint8Array | ArrayBuffer): Promise<void> {
    const bytes = value instanceof Uint8Array ? new Uint8Array(value) : new Uint8Array(value);
    this.objects.set(key, bytes);
  }

  get objectCount(): number {
    return this.objects.size;
  }
}

export interface SlotMetadata {
  tag: Uint8Array; // 16 B
  expireDay: number; // u16 (0 = 初期未割り当て/事前充填ダミー)
  lastFetchedDay: number; // u16 (0 = 未取得)
}

export interface GatekeeperConfig {
  readonly prefix?: string;
  readonly expectedChunkBytes?: number;
  readonly monthlyClassACap?: number;
  readonly monthlyClassBCap?: number;
  readonly hotProtectDays?: number;
  /** true の場合、PUT 時に有効な X-Ozzy-Quota-Proof (OZ_VOUCHER 署名証明) を必須とする */
  readonly requireQuotaProof?: boolean;
  /** メンバーの公開鍵 (ristretto255) の名簿 (hex 文字列の集合)。招待券のリングの全員がここにいることを求める */
  readonly activeMemberRoster?: ReadonlySet<string>;
  /**
   * 1 つのキーイメージ (= 1 人のメンバーの 1 日ぶんの招待券) で書き込めるチャンクの数の上限 (既定 2048 = 8 GiB)。
   * ★ 招待券の maxChunks は発行者が決める値なので、これだけに頼らない (同じ日に maxChunks の大きい招待券を出し直せる)
   */
  readonly maxChunksPerKeyImage?: number;
}

export const CORS_HEADERS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, PUT, POST, OPTIONS',
  'Access-Control-Allow-Headers':
    'Content-Type, Range, X-Ozzy-Pool, X-Ozzy-Candidates, X-Ozzy-TTL-Days, X-Ozzy-Quota-Proof, X-Ozzy-Tag',
  'Access-Control-Expose-Headers': 'Content-Range, Content-Length, X-Ozzy-Slot-Id, X-Ozzy-Tag',
  'Access-Control-Max-Age': '86400',
};

function currentEpochDay(nowMs: number = Date.now()): number {
  return Math.floor(nowMs / 86_400_000);
}

function slotKey(prefix: string, slotId: number): string {
  return `${prefix}/b/${slotId.toString(16).padStart(4, '0')}`;
}

function metaTableKey(prefix: string): string {
  return `${prefix}/m`;
}

function toHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
  return out;
}

function fromHex(hex: string): Uint8Array | null {
  const clean = hex.trim().toLowerCase();
  if (clean.length % 2 !== 0 || !/^[0-9a-f]+$/.test(clean)) return null;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * 候補スロット群 (cand_0..cand_3) から 4 段階ルールに従って上書き対象スロットを選出する。
 * 4 候補すべてがホットデータ (直近 hotProtectDays 以内に GET/TOUCH された有効チャンク) の場合は null を返す。
 */
export function selectVictimSlot(
  candidates: readonly number[],
  slots: readonly SlotMetadata[],
  today: number,
  hotProtectDays: number = WORKER_HOT_PROTECT_DAYS,
): { slotId: number; reason: 'expired' | 'unfetched' | 'lru_cold' } | null {
  // 第1優先: 期限切れスロット (expireDay <= today または初期ダミー expireDay == 0)
  let bestExpiredSlot = -1;
  let minExpireDay = Infinity;
  for (const c of candidates) {
    const meta = slots[c];
    if (meta.expireDay === 0 || meta.expireDay <= today) {
      if (meta.expireDay < minExpireDay) {
        minExpireDay = meta.expireDay;
        bestExpiredSlot = c;
      }
    }
  }
  if (bestExpiredSlot !== -1) {
    return { slotId: bestExpiredSlot, reason: 'expired' };
  }

  // 第2優先: 一度もダウンロードされていない未取得スロット (lastFetchedDay === 0)
  // スパムや死蔵データを既読の重要リークより先にパージする
  let bestUnfetchedSlot = -1;
  let oldestUnfetchedExpire = Infinity;
  for (const c of candidates) {
    const meta = slots[c];
    if (meta.lastFetchedDay === 0) {
      if (meta.expireDay < oldestUnfetchedExpire) {
        oldestUnfetchedExpire = meta.expireDay;
        bestUnfetchedSlot = c;
      }
    }
  }
  if (bestUnfetchedSlot !== -1) {
    return { slotId: bestUnfetchedSlot, reason: 'unfetched' };
  }

  // 第3優先: 最終取得日から hotProtectDays (30日) 以上経過したコールド LRU スロット
  let bestColdLruSlot = -1;
  let oldestFetchedDay = Infinity;
  for (const c of candidates) {
    const meta = slots[c];
    if (today - meta.lastFetchedDay >= hotProtectDays) {
      if (meta.lastFetchedDay < oldestFetchedDay) {
        oldestFetchedDay = meta.lastFetchedDay;
        bestColdLruSlot = c;
      }
    }
  }
  if (bestColdLruSlot !== -1) {
    return { slotId: bestColdLruSlot, reason: 'lru_cold' };
  }

  // 第4段階: 4 候補すべてがホットデータ -> 409 SLOT_HOT_FULL (別バケットまたは Tier 2 へスピルオーバー)
  return null;
}

export class OzzyGatekeeperWorker {
  private readonly prefix: string;
  private readonly expectedChunkBytes: number;
  private readonly monthlyClassACap: number;
  private readonly monthlyClassBCap: number;
  private readonly hotProtectDays: number;
  private readonly requireQuotaProof: boolean;
  private readonly activeMemberRoster?: ReadonlySet<string>;
  private readonly maxChunksPerKeyImage: number;

  private slots: SlotMetadata[] | null = null;
  private classACount = 0;
  private classBCount = 0;
  private dirtyMeta = false;
  /** バウチャー keyImageHex ごとの書き込み済み chunkTagHex 集合 (クォータ超過・使い回し監査用) */
  private readonly voucherChunkUsage = new Map<string, Set<string>>();

  constructor(
    private readonly bucket: R2BucketLike,
    config: GatekeeperConfig = {},
  ) {
    this.prefix = config.prefix ?? 'ozzy';
    this.expectedChunkBytes = config.expectedChunkBytes ?? OZZY_CHUNK_BYTES;
    this.monthlyClassACap = config.monthlyClassACap ?? WORKER_MONTHLY_CLASS_A_CAP;
    this.monthlyClassBCap = config.monthlyClassBCap ?? WORKER_MONTHLY_CLASS_B_CAP;
    this.hotProtectDays = config.hotProtectDays ?? WORKER_HOT_PROTECT_DAYS;
    this.requireQuotaProof = config.requireQuotaProof ?? false;
    this.activeMemberRoster = config.activeMemberRoster;
    this.maxChunksPerKeyImage = config.maxChunksPerKeyImage ?? 2048;
  }

  get stats() {
    return {
      classACount: this.classACount,
      classBCount: this.classBCount,
      dirtyMeta: this.dirtyMeta,
    };
  }

  private async ensureMetaLoaded(): Promise<SlotMetadata[]> {
    if (this.slots) return this.slots;
    this.classBCount++;
    const obj = await this.bucket.get(metaTableKey(this.prefix));
    const loaded: SlotMetadata[] = [];
    if (obj && obj.size === OZZY_TOTAL_SLOTS * SLOT_META_BYTES) {
      const buf = new Uint8Array(await obj.arrayBuffer());
      const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
      for (let i = 0; i < OZZY_TOTAL_SLOTS; i++) {
        const offset = i * SLOT_META_BYTES;
        loaded.push({
          tag: buf.slice(offset, offset + 16),
          expireDay: dv.getUint16(offset + 16, true),
          lastFetchedDay: dv.getUint16(offset + 18, true),
        });
      }
    } else {
      for (let i = 0; i < OZZY_TOTAL_SLOTS; i++) {
        loaded.push({
          tag: new Uint8Array(16),
          expireDay: 0,
          lastFetchedDay: 0,
        });
      }
    }
    this.slots = loaded;
    return loaded;
  }

  /** メモリ上の管理テーブル `<prefix>/m` (46,080 B) を R2 へフラッシュする */
  async flushMetaTable(): Promise<void> {
    if (!this.slots || !this.dirtyMeta) return;
    if (this.classACount >= this.monthlyClassACap) return;
    const buf = new Uint8Array(OZZY_TOTAL_SLOTS * SLOT_META_BYTES);
    const dv = new DataView(buf.buffer);
    for (let i = 0; i < OZZY_TOTAL_SLOTS; i++) {
      const offset = i * SLOT_META_BYTES;
      buf.set(this.slots[i].tag, offset);
      dv.setUint16(offset + 16, this.slots[i].expireDay & 0xffff, true);
      dv.setUint16(offset + 18, this.slots[i].lastFetchedDay & 0xffff, true);
    }
    this.classACount++;
    await this.bucket.put(metaTableKey(this.prefix), buf);
    this.dirtyMeta = false;
  }

  /** HTTP Request を処理するエントリポイント (Cloudflare Workers の fetch ハンドラ互換) */
  async handleFetch(request: Request, nowMs: number = Date.now()): Promise<Response> {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    const url = new URL(request.url);
    if (url.pathname === '/ozzy/v2/status' && request.method === 'GET') {
      const slots = await this.ensureMetaLoaded();
      const today = currentEpochDay(nowMs);
      let freeDataSlots = 0;
      for (let i = OZZY_MANIFEST_POOL_SLOTS; i < OZZY_TOTAL_SLOTS; i++) {
        if (slots[i].expireDay === 0 || slots[i].expireDay <= today) {
          freeDataSlots++;
        }
      }
      return new Response(
        JSON.stringify({
          ok: true,
          version: 2,
          totalSlots: OZZY_TOTAL_SLOTS,
          manifestPoolSlots: OZZY_MANIFEST_POOL_SLOTS,
          dataPoolSlots: OZZY_DATA_POOL_SLOTS,
          freeDataSlots,
          expectedChunkBytes: this.expectedChunkBytes,
          classACount: this.classACount,
          classBCount: this.classBCount,
          monthlyClassACap: this.monthlyClassACap,
          monthlyClassBCap: this.monthlyClassBCap,
        }),
        {
          status: 200,
          headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
        },
      );
    }
    if (url.pathname === '/ozzy/v2/chunk' && request.method === 'PUT') {
      return this.handlePutChunk(request, nowMs);
    }
    if (url.pathname === '/ozzy/v2/chunk' && request.method === 'GET') {
      return this.handleGetChunk(request, url, nowMs);
    }
    if (url.pathname === '/ozzy/v2/touch' && request.method === 'POST') {
      return this.handleTouchChunk(request, nowMs);
    }

    return new Response(JSON.stringify({ error: 'Not Found' }), {
      status: 404,
      headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
    });
  }

  private async handlePutChunk(request: Request, nowMs: number): Promise<Response> {
    // 1. Denial-of-Wallet Class A ハードキャップ検査
    if (this.classACount >= this.monthlyClassACap) {
      return new Response(JSON.stringify({ error: 'CLASS_A_QUOTA_CAP_REACHED' }), {
        status: 429,
        headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
      });
    }

    // 2. プール区分と候補スロットの検証 (Manifest 10% 保護プール vs Data 90% プール) + 重複除去
    const poolHeader = (request.headers.get('X-Ozzy-Pool') ?? 'data').toLowerCase();
    const isManifest = poolHeader === 'manifest';
    const candHeader = request.headers.get('X-Ozzy-Candidates') ?? '';
    const rawCandidates = candHeader
      .split(',')
      .map(s => parseInt(s.trim(), 10))
      .filter(n => Number.isInteger(n));
    const candidates = Array.from(new Set(rawCandidates));

    if (candidates.length === 0 || rawCandidates.length > 4) {
      return new Response(JSON.stringify({ error: 'INVALID_CANDIDATES' }), {
        status: 400,
        headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
      });
    }

    const minSlot = isManifest ? 0 : OZZY_MANIFEST_POOL_SLOTS;
    const maxSlot = isManifest ? OZZY_MANIFEST_POOL_SLOTS - 1 : OZZY_TOTAL_SLOTS - 1;
    for (const c of candidates) {
      if (c < minSlot || c > maxSlot) {
        return new Response(
          JSON.stringify({
            error: 'CANDIDATE_OUT_OF_POOL_BOUNDS',
            pool: poolHeader,
            allowedRange: [minSlot, maxSlot],
          }),
          {
            status: 403,
            headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
          },
        );
      }
    }

    // 3. チャンクサイズの厳格検査 (厳密に expectedChunkBytes = 4 MiB)
    const bodyBuf = new Uint8Array(await request.arrayBuffer());
    if (bodyBuf.byteLength !== this.expectedChunkBytes) {
      return new Response(
        JSON.stringify({
          error: 'INVALID_CHUNK_SIZE',
          expected: this.expectedChunkBytes,
          actual: bodyBuf.byteLength,
        }),
        {
          status: 400,
          headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
        },
      );
    }

    const today = currentEpochDay(nowMs);
    const chunkTag = bodyBuf.slice(0, OZZY_TAG_BYTES);
    if (isAllZeroTag(chunkTag)) {
      return new Response(JSON.stringify({ error: 'ZERO_TAG_FORBIDDEN' }), {
        status: 400,
        headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
      });
    }

    // 4. クォータ証明 (X-Ozzy-Quota-Proof / OZ_VOUCHER) の検証および上限検査
    const quotaProofHeader = request.headers.get('X-Ozzy-Quota-Proof');
    if (this.requireQuotaProof && !quotaProofHeader) {
      return new Response(JSON.stringify({ error: 'QUOTA_PROOF_REQUIRED' }), {
        status: 401,
        headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
      });
    }
    if (quotaProofHeader) {
      const verified = await verifyChunkVoucherProof(
        quotaProofHeader,
        chunkTag,
        today,
        this.activeMemberRoster,
      );
      if (!verified.ok) {
        return new Response(JSON.stringify({ error: 'INVALID_QUOTA_PROOF', reason: verified.reason }), {
          status: 403,
          headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
        });
      }
      const usedSet = this.voucherChunkUsage.get(verified.keyImageHex) ?? new Set<string>();
      const tagHex = toHex(chunkTag);
      if (!usedSet.has(tagHex) && usedSet.size >= Math.min(verified.maxChunks, this.maxChunksPerKeyImage)) {
        return new Response(JSON.stringify({ error: 'VOUCHER_QUOTA_EXCEEDED' }), {
          status: 429,
          headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
        });
      }
      usedSet.add(tagHex);
      this.voucherChunkUsage.set(verified.keyImageHex, usedSet);
    }

    const slots = await this.ensureMetaLoaded();

    // 既に同一 tag が候補スロットに存在する場合はそのスロットを上書き更新 (冪等 PUT / REPAIR)
    let targetSlot = -1;
    let evictionReason: string = 'idempotent_update';
    for (const c of candidates) {
      if (slots[c].expireDay > 0 && bytesEqual(slots[c].tag, chunkTag)) {
        targetSlot = c;
        break;
      }
    }

    // 5. 4 段階の自律退避ルールで書き込み先スロットを決定
    if (targetSlot === -1) {
      const victim = selectVictimSlot(candidates, slots, today, this.hotProtectDays);
      if (!victim) {
        return new Response(
          JSON.stringify({
            error: 'SLOT_HOT_FULL',
            message: 'All candidate slots contain active hot data; spillover to next provider or Tier 2 locker',
          }),
          {
            status: 409,
            headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
          },
        );
      }
      targetSlot = victim.slotId;
      evictionReason = victim.reason;
    }

    const ttlDaysRaw = parseInt(request.headers.get('X-Ozzy-TTL-Days') ?? '90', 10);
    const ttlDays = Number.isInteger(ttlDaysRaw) ? Math.min(Math.max(ttlDaysRaw, 60), 120) : 90;

    // 6. R2 へ 4 MiB チャンクを書き込み、メモリ上の管理テーブルを更新
    this.classACount++;
    await this.bucket.put(slotKey(this.prefix, targetSlot), bodyBuf);

    slots[targetSlot] = {
      tag: chunkTag,
      expireDay: today + ttlDays,
      lastFetchedDay: 0,
    };
    this.dirtyMeta = true;

    return new Response(
      JSON.stringify({
        ok: true,
        slotId: targetSlot,
        tag: toHex(chunkTag),
        expireDay: slots[targetSlot].expireDay,
        evictionReason,
      }),
      {
        status: 200,
        headers: {
          ...CORS_HEADERS,
          'Content-Type': 'application/json',
          'X-Ozzy-Slot-Id': targetSlot.toString(),
          'X-Ozzy-Tag': toHex(chunkTag),
        },
      },
    );
  }

  private async handleGetChunk(request: Request, url: URL, nowMs: number): Promise<Response> {
    if (this.classBCount >= this.monthlyClassBCap) {
      return new Response(JSON.stringify({ error: 'CLASS_B_QUOTA_CAP_REACHED' }), {
        status: 429,
        headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
      });
    }

    const tagHex = url.searchParams.get('tag') ?? request.headers.get('X-Ozzy-Tag') ?? '';
    const expectedTag = fromHex(tagHex);
    if (!expectedTag || expectedTag.length !== OZZY_TAG_BYTES || isAllZeroTag(expectedTag)) {
      return new Response(JSON.stringify({ error: 'INVALID_TAG' }), {
        status: 400,
        headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
      });
    }

    const candParam = url.searchParams.get('candidates') ?? request.headers.get('X-Ozzy-Candidates') ?? '';
    const slotParam = url.searchParams.get('slot');
    const candidates = slotParam
      ? [parseInt(slotParam, 10)].filter(n => Number.isInteger(n) && n >= 0 && n < OZZY_TOTAL_SLOTS)
      : candParam
          .split(',')
          .map(s => parseInt(s.trim(), 10))
          .filter(n => Number.isInteger(n) && n >= 0 && n < OZZY_TOTAL_SLOTS);

    if (candidates.length === 0) {
      return new Response(JSON.stringify({ error: 'MISSING_SLOT_CANDIDATES' }), {
        status: 400,
        headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
      });
    }

    const slots = await this.ensureMetaLoaded();
    const today = currentEpochDay(nowMs);

    // 候補スロットの中から expireDay > 0 かつ tag が一致する有効スロットを特定 (未初期化スロット 0 埋め tag との誤一致を防止)
    let matchedSlot = -1;
    for (const c of candidates) {
      if (c >= 0 && c < OZZY_TOTAL_SLOTS && slots[c].expireDay > 0 && bytesEqual(slots[c].tag, expectedTag)) {
        matchedSlot = c;
        break;
      }
    }

    if (matchedSlot === -1) {
      return new Response(JSON.stringify({ error: 'CHUNK_NOT_FOUND' }), {
        status: 404,
        headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
      });
    }

    // Range ヘッダ解析 (bytes=start-end)
    const rangeHeader = request.headers.get('Range');
    let rangeOpt: { offset: number; length: number } | undefined;
    let startByte = 0;
    let endByte = this.expectedChunkBytes - 1;
    let isPartial = false;

    if (rangeHeader) {
      const m = /^bytes=(\d+)-(\d+)?$/.exec(rangeHeader.trim());
      if (m) {
        startByte = parseInt(m[1], 10);
        endByte = m[2] ? Math.min(parseInt(m[2], 10), this.expectedChunkBytes - 1) : this.expectedChunkBytes - 1;
        if (startByte >= 0 && startByte <= endByte && startByte < this.expectedChunkBytes) {
          rangeOpt = { offset: startByte, length: endByte - startByte + 1 };
          isPartial = true;
        }
      }
    }

    this.classBCount++;
    const obj = await this.bucket.get(slotKey(this.prefix, matchedSlot), rangeOpt ? { range: rangeOpt } : undefined);
    if (!obj) {
      return new Response(JSON.stringify({ error: 'OBJECT_MISSING_IN_BUCKET' }), {
        status: 404,
        headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
      });
    }

    // 自律 TOUCH: 最終取得日を今日に更新し、有効期限を延長 (提供者の PC がオフラインでも自動で延命!)
    slots[matchedSlot].lastFetchedDay = today;
    slots[matchedSlot].expireDay = Math.max(slots[matchedSlot].expireDay, today + WORKER_TOUCH_EXTEND_DAYS);
    this.dirtyMeta = true;

    const data = await obj.arrayBuffer();
    const headers: Record<string, string> = {
      ...CORS_HEADERS,
      'Content-Type': 'application/octet-stream',
      'Content-Length': data.byteLength.toString(),
      'X-Ozzy-Slot-Id': matchedSlot.toString(),
      'X-Ozzy-Tag': toHex(expectedTag),
    };
    if (isPartial) {
      headers['Content-Range'] = `bytes ${startByte}-${endByte}/${this.expectedChunkBytes}`;
    }

    return new Response(data, {
      status: isPartial ? 206 : 200,
      headers,
    });
  }

  private async handleTouchChunk(request: Request, nowMs: number): Promise<Response> {
    const body = (await request.json().catch(() => null)) as {
      candidates?: number[];
      tag?: string;
    } | null;
    if (!body || !Array.isArray(body.candidates) || typeof body.tag !== 'string') {
      return new Response(JSON.stringify({ error: 'INVALID_TOUCH_PAYLOAD' }), {
        status: 400,
        headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
      });
    }
    const expectedTag = fromHex(body.tag);
    if (!expectedTag || expectedTag.length !== OZZY_TAG_BYTES || isAllZeroTag(expectedTag)) {
      return new Response(JSON.stringify({ error: 'INVALID_TAG' }), {
        status: 400,
        headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
      });
    }

    const slots = await this.ensureMetaLoaded();
    const today = currentEpochDay(nowMs);

    for (const c of body.candidates) {
      if (
        Number.isInteger(c) &&
        c >= 0 &&
        c < OZZY_TOTAL_SLOTS &&
        slots[c].expireDay > 0 &&
        bytesEqual(slots[c].tag, expectedTag)
      ) {
        slots[c].lastFetchedDay = today;
        slots[c].expireDay = Math.max(slots[c].expireDay, today + WORKER_TOUCH_EXTEND_DAYS);
        this.dirtyMeta = true;
        return new Response(
          JSON.stringify({
            ok: true,
            slotId: c,
            expireDay: slots[c].expireDay,
            lastFetchedDay: slots[c].lastFetchedDay,
          }),
          {
            status: 200,
            headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
          },
        );
      }
    }

    return new Response(JSON.stringify({ error: 'CHUNK_NOT_FOUND' }), {
      status: 404,
      headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
    });
  }
}

export { OZZY_DATA_POOL_SLOTS, OZZY_MANIFEST_POOL_SLOTS, OZZY_TOTAL_SLOTS };

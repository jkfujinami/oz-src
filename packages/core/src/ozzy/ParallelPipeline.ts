/**
 * ParallelPipeline — Tier 1 (R2 Gatekeeper Worker のリング) への並列アップロード・ダウンロードと、オンメモリの中継アリーナ。
 *
 *   1. RamChunkArena: 中継中のチャンクを置く RAM のスロット。使い終えたらゼロで埋める (ディスクには書かない)。
 *   2. OzzyParallelTransferCoordinator: ストライプ (データ 16 + パリティ 16) を 32 台の Gatekeeper へ並列 PUT し、
 *      取るときは 16 個揃った時点で復元する。
 *
 * ★ 旧版はここに「2 層 Onion の Fetcher」を持っていたが、鍵の生成・封印・開封をすべて自分の中で行って
 *   自分で取りに行くだけの見せかけだった (読み手の IP はそのまま Worker に届いていた)。削除した。
 *   メッシュ経由の取得は ozzy/MeshRange (トンネル種別 OZZY_RANGE) と ozzy/SlabReader が行う。
 *   Tier 1 の Worker (登録した任意の HTTPS ホスト) はメッシュの取得役の許可リストに無いので、ここは直接取る。
 */
import sodium, { sodiumReady } from '../crypto/sodium';
import { Encoding } from '../common/Encoding';
import { bytesEqual } from '../files/FileFormat';
import {
  OZZY_CHUNK_BYTES,
  chunkLayoutFor,
  computeStripeShareDigests,
  decodeStripeFromChunks,
  decodeSystematicPrefix,
  encryptStripeDataChunks,
  generateStripeParityChunks,
  type OzzyChunk,
} from './OzzyChunk4M';
import {
  OZZY_TAG_BYTES,
  computeCandidateSlots,
  computeChunkTag,
  deriveOzzyKeys,
  deriveStripeSeed,
  generateOzzySeed,
} from './OzzyKdf';
import { OZZY_RS_K, OZZY_RS_N } from './ReedSolomon';
import {
  type CloudLeaseSetStore,
  selectStripeProviders,
  unsealProviderEndpoint,
} from './CloudLeaseSet';
import {
  OZZY_MANIFEST_STRIPE_INDEX,
  OzzyTierMode,
  decodeManifestFromStripeChunks,
  deserializeOzzyManifest,
  encodeManifestToStripeChunks,
  formatOzzyLink,
  ozzyChunkBytesOf,
  ozzyLinkFlagsFor,
  serializeOzzyManifest,
  type OzzyLinkV2,
  type OzzyManifestV2,
  type OzzyStripeDescriptor,
} from './OzzyManifest';
import { signChunkWithVoucher, type OzzyUploadVoucher } from './OzzyVoucher';
import { Semaphore } from '../files/FileTransfer';
import { gatherStripe } from './SlabReader';
import { OrderedSourceReader, memorySink, writeStripesInOrder, type OzzyByteSink, type OzzyUploadSource } from './OzzyStream';

export const OZZY_DEFAULT_ARENA_SLOTS = 32; // 再利用して持っておく RAM スロットの数 (超えた分はその場で確保して捨てる)

/** Manifest の作成日を 30 日単位に丸める (告発者の正確な作成日・曜日を残さない) */
export function blindedEpochDay(nowMs: number = Date.now()): number {
  return Math.floor(Math.floor(nowMs / 86_400_000) / 30) * 30;
}

/** ストライプ 1 つに入る平文の最大 (チャンクの大きさから) */
export function maxStripePlainBytes(chunkBytes: number): number {
  return chunkLayoutFor(chunkBytes).maxStripePlainBytes;
}

/**
 * RamChunkArena — 中継中のチャンクを置く RAM のスロット。解放時にゼロで埋める (ディスクへは書かない)。
 *
 * ★ スロットは使うときに確保する (旧版は生成時に slotCount × 4 MiB = 128 MiB を確保していた。ノードを作るだけで
 *   ブラウザのタブが 64〜256 MiB を握っていた)。解放したスロットは slotCount 個まで再利用のために持つ。
 * ★ 全スロットが使用中のときは追加で確保する (旧版は使用中のスロットをゼロで埋めて横取りし、別の転送の中身を壊していた)。
 */
export class RamChunkArena {
  private readonly buffers: (Uint8Array | null)[] = [];
  private readonly inUse: boolean[] = [];
  private zeroizedCount = 0;

  constructor(
    readonly slotCount: number = OZZY_DEFAULT_ARENA_SLOTS,
    readonly slotBytes: number = OZZY_CHUNK_BYTES,
  ) {}

  /** 空き RAM スロットを確保し、データをコピーして格納する */
  acquire(data?: Uint8Array): { arenaSlot: number; buffer: Uint8Array } {
    if (data && data.byteLength > this.slotBytes) throw new RangeError('Data exceeds arena slot size');
    let idx = this.inUse.indexOf(false);
    if (idx === -1) {
      idx = this.inUse.length;
      this.inUse.push(false);
      this.buffers.push(null);
    }
    const buf = this.buffers[idx] ?? new Uint8Array(this.slotBytes);
    this.buffers[idx] = buf;
    this.inUse[idx] = true;
    if (data) buf.set(data, 0);
    return { arenaSlot: idx, buffer: buf };
  }

  /** 転送完了直後に RAM スロットを即座にゼロクリアして解放する */
  releaseAndZeroize(arenaSlot: number): void {
    if (arenaSlot < 0 || arenaSlot >= this.inUse.length || !this.inUse[arenaSlot]) return;
    this.buffers[arenaSlot]?.fill(0);
    this.inUse[arenaSlot] = false;
    this.zeroizedCount++;
    // 再利用のために持つのは slotCount 個まで。それを超えるスロットは手放す
    if (arenaSlot >= this.slotCount) this.buffers[arenaSlot] = null;
  }

  /** 緊急パニックワイプ (Panic Wipe): 全スロットを即座にゼロクリアして手放す */
  panicWipeAll(): void {
    for (let i = 0; i < this.buffers.length; i++) {
      this.buffers[i]?.fill(0);
      this.buffers[i] = null;
      this.inUse[i] = false;
    }
    this.zeroizedCount += this.buffers.length;
  }

  get stats() {
    return {
      slotCount: this.slotCount,
      slotBytes: this.slotBytes,
      activeSlots: this.inUse.filter(Boolean).length,
      allocatedSlots: this.buffers.filter(Boolean).length,
      zeroizedCount: this.zeroizedCount,
    };
  }
}

/**
 * クラウド Worker への HTTP トランスポート抽象インターフェース。
 * 実環境ではブラウザの `fetch(..., { cache: 'no-store' })` を呼び出し、
 * テスト環境ではローカルの `OzzyGatekeeperWorker.handleFetch` に直結できる。
 */
export type WorkerFetchTransport = (workerUrl: string, request: Request) => Promise<Response>;

/**
 * Tier 1 (R2 Gatekeeper Worker のリング) に大きなファイルを並列で置き・取るコーディネータ。
 */
export class OzzyParallelTransferCoordinator {
  readonly arena: RamChunkArena;
  private readonly sem: Semaphore;

  constructor(
    private readonly leaseStore: CloudLeaseSetStore,
    private readonly transport: WorkerFetchTransport,
    private readonly chunkBytes: number = OZZY_CHUNK_BYTES,
    opts: { maxInFlight?: number } = {},
  ) {
    this.arena = new RamChunkArena(OZZY_DEFAULT_ARENA_SLOTS, chunkBytes);
    this.sem = new Semaphore(Math.max(1, opts.maxInFlight ?? 8));
  }

  /**
   * 1 つのストライプ (32 チャンク) を、データ 16 個の暗号化 + パリティ 16 個の生成を経て 32 台のプロバイダ Worker へ並列 PUT する。
   * 戻り値は 32 個のシェアのハッシュ (Manifest に載せる)。
   * ★ 一部の PUT が失敗しても、復元に十分な数 (16 + 4) が置ければ続ける (旧版は 1 つの失敗で全体が失敗した)。
   */
  private async uploadSingleStripe(
    stripePlaintext: Uint8Array,
    stripeIndex: number,
    stripeSeed: Uint8Array,
    isManifest: boolean,
    voucher?: OzzyUploadVoucher,
    quotaProofToken?: string,
  ): Promise<Uint8Array> {
    const keys = await deriveOzzyKeys(stripeSeed);
    const dataChunks = await encryptStripeDataChunks(stripePlaintext, stripeIndex, keys, this.chunkBytes);
    const parityChunks = generateStripeParityChunks(dataChunks, stripeIndex, keys.kTag);
    const allChunks: OzzyChunk[] = [...dataChunks, ...parityChunks];
    const shareDigests = computeStripeShareDigests(allChunks);

    const providers = selectStripeProviders(keys.kLoc, stripeIndex, this.leaseStore.getActiveProviders(), OZZY_RS_N);
    if (providers.length === 0) {
      throw new Error('No active Tier 1 providers available in CloudLeaseSetStore');
    }

    const results = await Promise.allSettled(
      allChunks.map(async chunk => {
        const provider = providers[chunk.shareIndex % providers.length];
        const endpoint = await unsealProviderEndpoint(provider);
        if (!endpoint) throw new Error('Failed to unseal provider endpoint');
        const candidates = computeCandidateSlots(keys.kLoc, stripeIndex, chunk.shareIndex, isManifest);
        // 各チャンク固有の 16B tag に対して OZ_VOUCHER 署名を付与 (リプレイ防止・タグ拘束)
        const perChunkProof = voucher ? await signChunkWithVoucher(voucher, chunk.tag) : quotaProofToken;
        const headers: Record<string, string> = {
          'Content-Type': 'application/octet-stream',
          'X-Ozzy-Pool': isManifest ? 'manifest' : 'data',
          'X-Ozzy-Candidates': candidates.join(','),
          'X-Ozzy-TTL-Days': '90',
        };
        if (perChunkProof) headers['X-Ozzy-Quota-Proof'] = perChunkProof;
        if (!(await this.sem.acquire())) throw new Error('aborted');
        try {
          const res = await this.transport(
            endpoint.workerUrl,
            new Request(`${endpoint.workerUrl}/ozzy/v2/chunk`, { method: 'PUT', headers, body: chunk.rawChunk as Uint8Array<ArrayBuffer> }),
          );
          if (!res.ok) throw new Error(`Worker PUT failed with status ${res.status}`);
        } finally {
          this.sem.release();
          chunk.rawChunk.fill(0); // 置き終えた暗号文はすぐ消す (ハッシュは先に取ってある)
        }
      }),
    );
    const placed = results.filter(r => r.status === 'fulfilled').length;
    if (placed < OZZY_RS_K + 4) {
      const firstErr = results.find((r): r is PromiseRejectedResult => r.status === 'rejected')?.reason;
      throw new Error(`Only ${placed}/${OZZY_RS_N} chunks of stripe ${stripeIndex} were placed (${String(firstErr)})`);
    }
    return shareDigests;
  }

  /**
   * 1 つのストライプを Gatekeeper Worker から並列に取って復元する (16 個揃った時点で残りを取り消す)。
   * ★ 読み手の IP は Worker に見える。Tier 1 の Worker はメッシュの取得役の許可リストに無い (登録した任意の HTTPS ホスト)。
   */
  private async downloadSingleStripe(
    stripeIndex: number,
    stripeSeed: Uint8Array,
    isManifest: boolean,
    chunkBytes: number,
    shareDigests?: Uint8Array,
    signal?: AbortSignal,
  ): Promise<Uint8Array | null> {
    await sodiumReady;
    const keys = await deriveOzzyKeys(stripeSeed);
    const providers = selectStripeProviders(keys.kLoc, stripeIndex, this.leaseStore.getActiveProviders(), OZZY_RS_N);
    if (providers.length === 0) return null;

    const fetchShare = async (shareIndex: number, sig: AbortSignal): Promise<Uint8Array | null> => {
      const provider = providers[shareIndex % providers.length];
      const endpoint = await unsealProviderEndpoint(provider);
      if (!endpoint) return null;
      const candidates = computeCandidateSlots(keys.kLoc, stripeIndex, shareIndex, isManifest);
      const expectedTag = computeChunkTag(keys.kTag, stripeIndex, shareIndex);
      const req = new Request(
        `${endpoint.workerUrl}/ozzy/v2/chunk?candidates=${candidates.join(',')}&tag=${Encoding.toHex(expectedTag)}`,
        { method: 'GET', signal: sig },
      );
      const res = await this.transport(endpoint.workerUrl, req);
      if (!res.ok) return null;
      const raw = new Uint8Array(await res.arrayBuffer());
      if (raw.byteLength !== chunkBytes || !bytesEqual(raw.subarray(0, OZZY_TAG_BYTES), expectedTag)) return null;
      return raw;
    };
    const opened = new Map<number, Uint8Array | null>();
    return gatherStripe({
      shareIndices: Array.from({ length: OZZY_RS_N }, (_, i) => i),
      fetchShare,
      early: (shares) => decodeSystematicPrefix(shares, stripeIndex, keys, chunkBytes, opened, shareDigests),
      decode: (shares) => decodeStripeFromChunks(shares, stripeIndex, keys, chunkBytes, { shareDigests }),
      sem: this.sem,
      extraShares: 2,
      signal,
    });
  }

  /**
   * ファイルをストライプ単位で読みながら (全体をメモリに載せない) 上げ、最後に Manifest を保護プールへ投入して
   * リンク文字列 `[[ozzy:v2:...]]` を返す。source は File / Blob / Uint8Array (fileData は旧名)。
   */
  async uploadFile(params: {
    source?: OzzyUploadSource;
    fileData?: Uint8Array;
    fileName: string;
    mimeType: string;
    voucher?: OzzyUploadVoucher;
    quotaProofToken?: string;
    onProgress?: (completedStripes: number, totalStripes: number) => void;
  }): Promise<{ link: OzzyLinkV2; linkText: string; manifest: OzzyManifestV2 }> {
    await sodiumReady;
    const src = params.source ?? params.fileData;
    if (!src) throw new Error('uploadFile: source is required');
    const manifestSeed = await generateOzzySeed();
    const reader = new OrderedSourceReader(src, maxStripePlainBytes(this.chunkBytes));
    const stripeCount = reader.count;
    const stripeDescriptors: OzzyStripeDescriptor[] = [];

    for (let next = await reader.next(); next; next = await reader.next()) {
      const s = next.index;
      const stripeSeed = await deriveStripeSeed(manifestSeed, s);
      const shareDigests = await this.uploadSingleStripe(next.data, s, stripeSeed, false, params.voucher, params.quotaProofToken);
      stripeDescriptors.push({
        stripeSeed,
        tierMode: OzzyTierMode.Tier1Ring,
        leaseSetId: new Uint8Array(16),
        slabStartChunkIdx: 0,
        shareDigests,
      });
      params.onProgress?.(s + 1, stripeCount + 1);
    }

    const manifest: OzzyManifestV2 = {
      version: 3,
      flags: 0,
      totalFileSize: reader.size,
      createdAtDay: blindedEpochDay(),
      fileHash: reader.digest(),
      fileName: params.fileName,
      mimeType: params.mimeType,
      stripes: stripeDescriptors,
    };

    await this.uploadSingleStripe(
      serializeOzzyManifest(manifest), OZZY_MANIFEST_STRIPE_INDEX, manifestSeed, true, params.voucher, params.quotaProofToken,
    );
    params.onProgress?.(stripeCount + 1, stripeCount + 1);

    const link: OzzyLinkV2 = {
      manifestSeed,
      totalFileSize: reader.size,
      flags: ozzyLinkFlagsFor(this.chunkBytes, true),
    };
    return { link, linkText: formatOzzyLink(link), manifest };
  }

  /** リンクから Manifest だけを取る */
  async readManifest(link: OzzyLinkV2, signal?: AbortSignal): Promise<OzzyManifestV2 | null> {
    await sodiumReady;
    const plain = await this.downloadSingleStripe(OZZY_MANIFEST_STRIPE_INDEX, link.manifestSeed, true, ozzyChunkBytesOf(link), undefined, signal);
    if (!plain) return null;
    const manifest = deserializeOzzyManifest(plain);
    return manifest && manifest.totalFileSize === link.totalFileSize ? manifest : null;
  }

  /** リンクからファイルを取り、ストライプを番号順に sink へ書き出す (全体をメモリに載せない)。大きさ・ハッシュが合わなければ null */
  async downloadToSink(
    link: OzzyLinkV2,
    sink: OzzyByteSink,
    opts: { manifest?: OzzyManifestV2; onProgress?: (completedStripes: number, totalStripes: number) => void; signal?: AbortSignal } = {},
  ): Promise<OzzyManifestV2 | null> {
    const chunkBytes = ozzyChunkBytesOf(link);
    const manifest = opts.manifest ?? (await this.readManifest(link, opts.signal));
    if (!manifest) {
      try {
        await sink.abort?.(new Error('no manifest'));
      } catch {
        // 閉じている
      }
      return null;
    }
    const result = await writeStripesInOrder({
      stripeCount: manifest.stripes.length,
      concurrency: 1,
      fetchStripe: (s, signal) => {
        const d = manifest.stripes[s];
        return this.downloadSingleStripe(s, d.stripeSeed, false, chunkBytes, d.shareDigests, signal);
      },
      sink,
      expectedSize: manifest.totalFileSize,
      expectedHash: manifest.fileHash,
      onStripe: (done, total) => opts.onProgress?.(done + 1, total + 1),
      signal: opts.signal,
    });
    return result === 'ok' ? manifest : null;
  }

  /** リンクからファイル全体をメモリに取る (小さいファイル・テスト用。大きいファイルは downloadToSink) */
  async downloadFile(
    link: OzzyLinkV2,
    onProgress?: (completedStripes: number, totalStripes: number) => void,
    signal?: AbortSignal,
  ): Promise<{ manifest: OzzyManifestV2; data: Uint8Array } | null> {
    const sink = memorySink();
    const manifest = await this.downloadToSink(link, sink, { onProgress, signal });
    return manifest ? { manifest, data: sink.result() } : null;
  }
}

export { encodeManifestToStripeChunks, decodeManifestFromStripeChunks };

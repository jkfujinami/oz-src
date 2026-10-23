/**
 * SlabReader — Tier 2 (ロッカーの Slab) に置いたファイルを、リンク `[[ozzy:v3:...]]` だけから並列に取って復元する。
 *
 *   リンク → Manifest (P2P のファイル保管から。OzzyManifestStore) → データのストライプを stripeConcurrency 本ずつ
 *   1 ストライプ = Manifest に入っている置き場所 (どのシェアがどの URL の何チャンク目か) を見る
 *                → データシェア (0..15) を先に、k + extraShares 個を同時に取り始める
 *                → 失敗したシェアの代わりに次のシェアを取り始める → 16 個揃ったら復元 → 残りは取り消す
 *
 * ★ 取り方 (route):
 *   - 'mesh-only' (メッシュがあるときの既定): P2P メッシュの取得役に頼む (ozzy/MeshRange)。ロッカーにも中継 Worker にも
 *     読み手の IP は届かない。取得役が居なければ失敗する (黙って直接取りに行かない)。
 *   - 'mesh-then-direct': メッシュで取れなかったシェアだけ direct で取る (読み手の IP が中継 Worker かロッカーに見える)。
 *   - 'direct-only': direct だけ (メッシュが無い環境・テスト)。
 * ★ シェアは使う前に確かめる: 長さ・tag・Manifest のハッシュ (データのストライプ)・K_enc での認証復号 (Manifest の
 *   ストライプのデータシェア)。通らなければ取得役を替えて取り直す。偽物を返す取得役が混ざっていても止まらない。
 * ★ 取りかけの状態・どのファイルを取っているかはメモリだけ。ディスクには何も書かない。
 */
import sodium, { sodiumReady } from '../crypto/sodium';
import { bytesEqual } from '../files/FileFormat';
import { Semaphore } from '../files/FileTransfer';
import type { OzzyMeshFetcher } from './MeshRange';
import {
  decodeStripeFromChunks,
  decodeSystematicPrefix,
  openDataShareBody,
  shareMatchesDigest,
} from './OzzyChunk4M';
import {
  OZZY_TAG_BYTES,
  computeChunkTag,
  deriveOzzyKeys,
  type OzzyFileKeys,
} from './OzzyKdf';
import {
  deserializeOzzyManifestV4,
  parseOzzyLinkV3,
  type OzzyManifestStore,
  type OzzyManifestV4,
  type OzzySlabLocation,
} from './OzzyManifest';
import { OZZY_RS_K } from './ReedSolomon';
import { memorySink, writeStripesInOrder, type OzzyByteSink } from './OzzyStream';

export interface SlabShareLocation {
  readonly lockerId: string;
  readonly downloadUrl: string;
  readonly slotOffsetIndex: number;
}

/** 直接取る (メッシュを使わない) 関数。end は含む。取れなければ null */
export type DirectSlabRangeFetch = (
  loc: SlabShareLocation, startByte: number, endByte: number, signal: AbortSignal,
) => Promise<Uint8Array | null>;

export type OzzyFetchRoute = 'mesh-only' | 'mesh-then-direct' | 'direct-only';

export type SlabReadFailure =
  | 'aborted'
  /** メッシュに取得役が居ない (mesh-only) */
  | 'no-fetchers'
  /** Manifest を P2P から取れない (保持者が居ない・リンクが違う) */
  | 'no-manifest'
  /** 16 個のシェアが揃わなかった (ロッカーが消えた・落ちている) */
  | 'insufficient-shares'
  /** Manifest が壊れている・リンクと合わない */
  | 'bad-manifest'
  /** 全体のハッシュが合わない */
  | 'hash-mismatch';

export interface SlabReaderOptions {
  /** Manifest の置き場所 (P2P のファイル保管。OzNode.ozzyManifestStore) */
  readonly manifestStore: OzzyManifestStore;
  /** メッシュの取得役 (OzNode.ozzyMesh)。無ければ direct だけ */
  readonly mesh?: Pick<OzzyMeshFetcher, 'fetchRange' | 'ready'> | null;
  readonly direct?: DirectSlabRangeFetch | null;
  /** 既定: mesh があれば 'mesh-only'、無ければ 'direct-only' */
  readonly route?: OzzyFetchRoute;
  /**
   * 同時に取るシェアの数 (全ストライプ合計。既定 4)。オニオン経由の応答は Guard → 自分の 1 本の線に集まり、
   * 1 本の応答は 600 片/秒 (約 2.3MiB/秒) なので、4 本で Guard の送出の上限 (2,500 片/秒) に収まる。
   */
  readonly maxInFlight?: number;
  /** 同時に取るストライプの数 (既定 2) */
  readonly stripeConcurrency?: number;
  /** 1 ストライプで最初から余分に取り始めるシェアの数 (既定 2。遅い・偽物の取得役への保険) */
  readonly extraShares?: number;
}

export interface SlabReadProgress {
  readonly phase: 'manifest' | 'stripes' | 'done';
  readonly stripesDone: number;
  readonly stripeCount: number;
}

export class OzzySlabReader {
  private readonly sem: Semaphore;
  private readonly route: OzzyFetchRoute;
  private readonly stripeConcurrency: number;
  private readonly extraShares: number;
  /** 直近の失敗の理由 (null を返したときに見る) */
  public lastFailure: SlabReadFailure | null = null;
  /** 診断・テスト用 */
  public readonly stats = { meshShares: 0, directShares: 0, rejectedShares: 0, failedShares: 0 };

  constructor(private readonly opts: SlabReaderOptions) {
    this.route = opts.route ?? (opts.mesh ? 'mesh-only' : 'direct-only');
    this.sem = new Semaphore(Math.max(1, opts.maxInFlight ?? 4));
    this.stripeConcurrency = Math.max(1, opts.stripeConcurrency ?? 2);
    this.extraShares = Math.max(0, opts.extraShares ?? 2);
  }

  private fail(reason: SlabReadFailure): null {
    this.lastFailure ??= reason;
    return null;
  }

  /** shareIndex → 置き場所 (Manifest に入っているもの) */
  private locate(locations: readonly OzzySlabLocation[]): Map<number, SlabShareLocation[]> {
    const out = new Map<number, SlabShareLocation[]>();
    for (const loc of locations) {
      for (const m of loc.chunkMap) {
        if (m.slotOffsetIndex >= loc.slabChunks) continue;
        const list = out.get(m.shareIndex) ?? [];
        if (!list.some(x => x.downloadUrl === loc.url && x.slotOffsetIndex === m.slotOffsetIndex)) {
          list.push({ lockerId: loc.lockerId, downloadUrl: loc.url, slotOffsetIndex: m.slotOffsetIndex });
        }
        out.set(m.shareIndex, list);
      }
    }
    return out;
  }

  /** シェア 1 つを、置き場所を順に試して取る。確かめたデータか null */
  private async fetchShare(
    shareIndex: number, locations: readonly SlabShareLocation[], stripeIndex: number, keys: OzzyFileKeys,
    chunkBytes: number, shareDigests: Uint8Array | undefined, signal: AbortSignal,
  ): Promise<Uint8Array | null> {
    const expectedTag = computeChunkTag(keys.kTag, stripeIndex, shareIndex);
    const accept = (data: Uint8Array): boolean => {
      if (data.length !== chunkBytes || !bytesEqual(data.subarray(0, OZZY_TAG_BYTES), expectedTag)) return false;
      if (shareDigests) return shareMatchesDigest(shareDigests, shareIndex, data);
      // Manifest のストライプ (ハッシュが無い): データシェアだけは K_enc で確かめられる
      if (shareIndex < OZZY_RS_K) return openDataShareBody(data.subarray(OZZY_TAG_BYTES), stripeIndex, shareIndex, keys, chunkBytes) !== null;
      return true;
    };
    const useMesh = this.route !== 'direct-only' && !!this.opts.mesh;
    const useDirect = this.route !== 'mesh-only' && !!this.opts.direct;
    for (const loc of locations) {
      if (signal.aborted) return null;
      const start = loc.slotOffsetIndex * chunkBytes;
      const end = start + chunkBytes - 1;
      let triedMesh = false;
      if (useMesh && this.opts.mesh!.ready) {
        triedMesh = true;
        const r = await this.opts.mesh!.fetchRange(
          { lockerId: loc.lockerId, url: loc.downloadUrl, start, length: chunkBytes, expectedTag },
          accept,
          signal,
        );
        if (r.ok) {
          this.stats.meshShares++;
          return r.data;
        }
        if (r.reason === 'aborted') return null;
        if (r.reason === 'not-found') continue; // このロッカーには無い: 次の置き場所 (移設先・複製) へ
      } else if (useMesh && !useDirect) {
        this.lastFailure ??= 'no-fetchers';
        return null;
      }
      if (useDirect) {
        try {
          const data = await this.opts.direct!(loc, start, end, signal);
          if (data && accept(data)) {
            this.stats.directShares++;
            return data;
          }
          if (data) this.stats.rejectedShares++;
        } catch {
          // 次の置き場所へ
        }
      } else if (triedMesh) {
        continue;
      }
    }
    this.stats.failedShares++;
    return null;
  }

  /** 1 ストライプを取って復元する (置き場所とシェアのハッシュは Manifest にあるもの) */
  public async downloadStripe(
    stripeIndex: number, stripe: { stripeSeed: Uint8Array; shareDigests: Uint8Array; locations: readonly OzzySlabLocation[] },
    chunkBytes: number, signal?: AbortSignal,
  ): Promise<Uint8Array | null> {
    await sodiumReady;
    const keys = await deriveOzzyKeys(stripe.stripeSeed);
    const shareDigests = stripe.shareDigests;
    const locations = this.locate(stripe.locations);
    if (locations.size === 0) return this.fail('insufficient-shares');
    if (locations.size < OZZY_RS_K) return this.fail('insufficient-shares');

    // データシェアを先に (復元の計算が要らず、1 つずつ K_enc で確かめられる)
    const opened = new Map<number, Uint8Array | null>();
    const result = await gatherStripe({
      shareIndices: Array.from(locations.keys()).sort((a, b) => a - b),
      fetchShare: (shareIndex, sig) =>
        this.fetchShare(shareIndex, locations.get(shareIndex)!, stripeIndex, keys, chunkBytes, shareDigests, sig),
      early: (shares) => decodeSystematicPrefix(shares, stripeIndex, keys, chunkBytes, opened, shareDigests),
      decode: (shares) => decodeStripeFromChunks(shares, stripeIndex, keys, chunkBytes, { shareDigests }),
      sem: this.sem,
      extraShares: this.extraShares,
      signal,
    });
    if (!result) {
      if (signal?.aborted) return this.fail('aborted');
      return this.fail('insufficient-shares');
    }
    return result;
  }

  /** リンク (`[[ozzy:v3:...]]` か本体) から Manifest だけを取る (名前・大きさを先に見せて、保存先を選んでもらうため) */
  public async readManifest(linkText: string, signal?: AbortSignal): Promise<OzzyManifestV4 | null> {
    await sodiumReady;
    this.lastFailure = null;
    const body = parseOzzyLinkV3(linkText);
    if (!body) return this.fail('bad-manifest');
    let bytes: Uint8Array | null = null;
    try {
      bytes = await this.opts.manifestStore.get(body, signal);
    } catch {
      bytes = null;
    }
    if (!bytes) return this.fail(signal?.aborted ? 'aborted' : 'no-manifest');
    const manifest = deserializeOzzyManifestV4(bytes);
    return manifest ?? this.fail('bad-manifest');
  }

  /**
   * リンクからファイルを取り、ストライプを番号順に sink へ書き出す (全体をメモリに載せない)。
   * 全体の大きさ・ハッシュが合わなければ sink を abort して null。manifest を渡せば取り直さない。
   */
  public async downloadToSink(
    linkText: string,
    sink: OzzyByteSink,
    opts: { manifest?: OzzyManifestV4; onProgress?: (p: SlabReadProgress) => void; signal?: AbortSignal } = {},
  ): Promise<OzzyManifestV4 | null> {
    await sodiumReady;
    this.lastFailure = null;
    opts.onProgress?.({ phase: 'manifest', stripesDone: 0, stripeCount: 0 });
    const manifest = opts.manifest ?? (await this.readManifest(linkText, opts.signal));
    if (!manifest) {
      try {
        await sink.abort?.(new Error('no manifest'));
      } catch {
        // 閉じている
      }
      return null;
    }
    const stripeCount = manifest.stripes.length;
    const result = await writeStripesInOrder({
      stripeCount,
      concurrency: this.stripeConcurrency,
      fetchStripe: (s, signal) => this.downloadStripe(s, manifest.stripes[s], manifest.chunkBytes, signal),
      sink,
      expectedSize: manifest.totalFileSize,
      expectedHash: manifest.fileHash,
      onStripe: (done, total) => opts.onProgress?.({ phase: done === total ? 'done' : 'stripes', stripesDone: done, stripeCount: total }),
      signal: opts.signal,
    });
    if (result === 'ok') return manifest;
    if (result === 'aborted') return this.fail('aborted');
    if (result === 'size-mismatch' || result === 'hash-mismatch') return this.fail('hash-mismatch');
    return null; // ストライプが取れなかった (理由は downloadStripe が lastFailure に入れている)
  }

  /** リンクからファイル全体をメモリに取る (小さいファイル・テスト用。大きいファイルは downloadToSink) */
  public async downloadFile(
    linkText: string, onProgress?: (p: SlabReadProgress) => void, signal?: AbortSignal,
  ): Promise<{ manifest: OzzyManifestV4; data: Uint8Array } | null> {
    const sink = memorySink();
    const manifest = await this.downloadToSink(linkText, sink, { onProgress, signal });
    return manifest ? { manifest, data: sink.result() } : null;
  }
}

export interface GatherStripeParams {
  /** 取る順のシェア番号 (データシェアを先に) */
  readonly shareIndices: readonly number[];
  /** シェア 1 つを取って確かめる。取れなければ null */
  readonly fetchShare: (shareIndex: number, signal: AbortSignal) => Promise<Uint8Array | null>;
  /** 集めたシェアから復元する。できなければ null */
  readonly decode: (shares: { shareIndex: number; rawChunk: Uint8Array }[]) => Promise<Uint8Array | null>;
  /**
   * シェアが届くたびに試す、16 個を待たない復元 (データシェアの先頭だけで平文が終わっている場合)。できなければ null。
   * 通れば残りの取得を取り消す。
   */
  readonly early?: (shares: { shareIndex: number; rawChunk: Uint8Array }[]) => Uint8Array | null;
  /** 同時に取るシェアの数の上限 (全ストライプで共有) */
  readonly sem: Semaphore;
  /** 最初から 16 個より余分に取り始める数 */
  readonly extraShares: number;
  readonly signal?: AbortSignal;
}

/**
 * 1 ストライプのシェアを並列に集めて復元する (Tier 1 / Tier 2 共通)。
 *
 *   16 + extraShares 個を同時に取り始める → 失敗したシェアの代わりに次を取り始める → 16 個揃ったら復元を試す
 *   → 通れば残りを取り消す / 通らなければ (悪いパリティ) もう 1 つ取って組み合わせを増やす。
 * ★ 旧版は「先頭 18 個を全部待つ → 足りなければ残り全部」の 2 段で、遅いロッカー 1 つに全体が引きずられ、
 *   悪いシェアが先頭 16 個に入ると良いシェアが余っていても復元できなかった。
 */
export function gatherStripe(p: GatherStripeParams): Promise<Uint8Array | null> {
  const ac = new AbortController();
  const onAbort = () => ac.abort();
  p.signal?.addEventListener('abort', onAbort, { once: true });
  if (p.signal?.aborted) ac.abort();

  const got: { shareIndex: number; rawChunk: Uint8Array }[] = [];
  let next = 0;
  let active = 0;
  let decoding = false;
  /** 揃っても復元できなかった回数。そのたびに取るシェアを 1 つ増やす */
  let boost = 0;

  return new Promise<Uint8Array | null>((resolve) => {
    let settled = false;
    const settle = (v: Uint8Array | null) => {
      if (settled) return;
      settled = true;
      p.signal?.removeEventListener('abort', onAbort);
      ac.abort(); // 走っている取得を止める
      resolve(v);
    };
    if (ac.signal.aborted) return settle(null);
    ac.signal.addEventListener('abort', () => settle(null), { once: true });

    const tryDecode = async (): Promise<void> => {
      if (decoding || settled || got.length < OZZY_RS_K) return;
      decoding = true;
      const snapshot = got.slice();
      let plain: Uint8Array | null = null;
      try {
        plain = await p.decode(snapshot);
      } catch {
        plain = null;
      }
      decoding = false;
      if (plain) return settle(plain);
      // ★ 揃っても復元できない (悪いパリティが混ざっている): 待っている間に増えた分で試し直し、それでもだめなら 1 つ足す
      if (got.length > snapshot.length) return tryDecode();
      boost++;
      pump();
    };

    const launch = () => {
      const shareIndex = p.shareIndices[next++];
      active++;
      void (async () => {
        if (!(await p.sem.acquire(ac.signal))) return null;
        try {
          return await p.fetchShare(shareIndex, ac.signal);
        } catch {
          return null;
        } finally {
          p.sem.release();
        }
      })().then((raw) => {
        active--;
        if (settled) return;
        if (raw) {
          got.push({ shareIndex, rawChunk: raw });
          if (p.early) {
            let plain: Uint8Array | null = null;
            try {
              plain = p.early(got);
            } catch {
              plain = null;
            }
            if (plain) return settle(plain);
          }
          void tryDecode();
        }
        pump();
      });
    };

    const pump = () => {
      if (settled) return;
      const want = OZZY_RS_K + p.extraShares + boost;
      while (next < p.shareIndices.length && got.length + active < want) launch();
      if (active === 0 && !decoding && next >= p.shareIndices.length) settle(null);
    };
    pump();
  });
}

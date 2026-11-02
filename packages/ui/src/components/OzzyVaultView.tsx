import { useState, useRef, useEffect } from 'react';
import { useP2P } from '../providers/P2PProvider';
import { useOzzyPrefs } from '../lib/ozzyPrefs';
import { OzzyWorkerForm } from './OzzyWorkerForm';
import { getOzzySessionItems, setOzzySessionItems } from '../lib/ozzySession';
import { copySecret } from '../lib/clipboard';
import { tRich, useT, type PlainKey } from '../i18n';
import {
  CatboxLockerAdapter,
  CloudLeaseSetStore,
  GofileLockerAdapter,
  LitterboxLockerAdapter,
  MemoryOverseasLockerCluster,
  MemoryR2Bucket,
  OZZY_CHUNK_BYTES,
  OZZY_DEMO_CHUNK_BYTES,
  OZZY_RS_K,
  OZZY_RS_N,
  OverseasMultiLockerCoordinator,
  OzzyGatekeeperWorker,
  OzzyParallelTransferCoordinator,
  PixeldrainLockerAdapter,
  PomfLockerAdapter,
  ZeroXZeroLockerAdapter,
  createOnionLockerAdapters,
  OZZY_JOB_LOCKERS,
  createProviderLeaseSet,
  formatOzzyVoucherToken,
  generateMemberKeypair,
  memoryManifestStore,
  OZZY_VOUCHER_MAX_DAYS,
  type OzzyMemberKeypair,
  issueUploadVoucher,
  ozzyIsTier1,
  parseOzzyLink,
  parseOzzyLinkV3,
  parseOzzyVoucherToken,
  sodium,
  sodiumReady,
  type OzzyByteSink,
  type OzzyLinkV2,
  type OzzyManifestStore,
  type OzzyManifestV2,
  type OzzyManifestV4,
  type SlabReadFailure,
  type UploadedLockerSlabReceipt,
  type OzzySlabEvent,
} from '@oz/core';

/** ダウンロードが失敗した理由の表示 */
const FAILURE_KEY: Record<SlabReadFailure, PlainKey> = {
  aborted: 'vault.failure.aborted',
  'no-fetchers': 'vault.failure.noFetchers',
  'no-manifest': 'vault.failure.noManifest',
  'insufficient-shares': 'vault.failure.insufficientShares',
  'bad-manifest': 'vault.failure.badManifest',
  'hash-mismatch': 'vault.failure.hashMismatch',
};

/**
 * 回路の M1 に置いてもらうロッカー。core の OZZY_JOB_LOCKERS (資格情報なしで置け、実地テストで通ったもの) をそのまま使う。
 * ★ ここで別に並べると、M1 が引き受けないロッカー (旧: gofile・0x0.st) が混ざって黙って外され、散らす先が減る。
 */
const ONION_LOCKERS = OZZY_JOB_LOCKERS;

interface StoredLeakItem {
  readonly fileName: string;
  readonly mimeType: string;
  readonly totalBytes: number;
  readonly stripeCount: number;
  readonly linkText: string;
  readonly createdAt: string;
  readonly engine: 'overseas-multi' | 'r2-gatekeeper';
  readonly overseasReceipts?: readonly UploadedLockerSlabReceipt[];
  readonly deleted?: boolean;
}

/**
 * OzzyVaultView — ジャーナリスト・内部告発者向けの大規模ファイル匿名共有メイン画面。
 *
 *   1. 海外の無記名ロッカー (Catbox・0x0.st・Pomf・Gofile ほか) への同時分散 (`OverseasMultiLockerCoordinator`):
 *      - アップロードはオニオン回路の M1 に頼む (`OnionLockerAdapter`)。ロッカー・中継 Worker にあなたの IP は届かない
 *      - 置き場所は Manifest に入れ、Manifest は P2P のファイル保管に置く (`node.ozzyManifestStore`)。共通の Worker は使わない
 *      - 取るときもオニオン回路の M1 に頼む (`node.ozzyMesh`)。`[[ozzy:v3:...]]` リンクだけで別の端末から取れる
 *   2. ジャーナリスト向け「無記名アップロード招待券 (`OZ_VOUCHER`)」発行 & 検証 (Gatekeeper Worker 用)
 *
 * 保存先・束ね方・Gatekeeper の登録などの設定は設定画面 (OzzySettings。値は lib/ozzyPrefs)、
 * 仕組みの説明は「仕組みと安全性」(AboutView) に置き、この画面は送る・受け取るだけにする。
 *
 * ★ Internet Archive は使わない: 利用者自身のアカウントで置くので、アカウントが告発者を名指しする。
 *   回路の M1 に頼むには IA の鍵を M1 に渡すことになる。
 */
export function OzzyVaultView({ onOpenSettings, onOpenAbout }: { onOpenSettings?: () => void; onOpenAbout?: () => void } = {}) {
  const t = useT();
  const { node } = useP2P();
  const {
    storageEngine, useLiveLockers, useFastDemoChunk, targetBatchChunks, idleGapMs, maxWaitMs, registeredWorkers, useOnlyRealWorkers,
  } = useOzzyPrefs();
  const [activeSubTab, setActiveSubTab] = useState<'transfer' | 'voucher'>('transfer');
  const [p2pFetcherCount, setP2pFetcherCount] = useState<number>(0);
  const [meshReady, setMeshReady] = useState<boolean>(false);

  useEffect(() => {
    const update = () => {
      setP2pFetcherCount(node?.ozzyMesh.fetcherCount ?? 0);
      setMeshReady(node?.ozzyMesh.ready ?? false);
    };
    update();
    const timer = setInterval(update, 2000);
    return () => clearInterval(timer);
  }, [node]);

  // 海外ロッカーへの同時分散 (回路の M1 に置いてもらう)
  const overseasPoolRef = useRef<{
    cluster: MemoryOverseasLockerCluster | null;
    coordinator: OverseasMultiLockerCoordinator;
    initialized: boolean;
    configKey: string;
  } | null>(null);
  /** 試験モードの Manifest の置き場所 (この画面のメモリだけ) */
  const demoManifestsRef = useRef<OzzyManifestStore | null>(null);

  // R2 Gatekeeper Worker Pool (オプション)
  const r2PoolRef = useRef<{
    leaseStore: CloudLeaseSetStore;
    workers: Map<string, OzzyGatekeeperWorker>;
    coordinator: OzzyParallelTransferCoordinator;
    initialized: boolean;
    configKey: string;
  } | null>(null);

  const [uploadStatus, setUploadStatus] = useState<string | null>(null);
  const [uploadProgress, setUploadProgress] = useState<number>(0);
  // この起動中に作ったリンク (画面を離れても残す。ロックで消える: lib/ozzySession.ts)
  const [uploadedItems, setUploadedItemsState] = useState<StoredLeakItem[]>(() => getOzzySessionItems<StoredLeakItem>());
  const setUploadedItems = (update: (prev: StoredLeakItem[]) => StoredLeakItem[]) =>
    setUploadedItemsState((prev) => {
      const next = update(prev);
      setOzzySessionItems(next);
      return next;
    });
  const [copiedLink, setCopiedLink] = useState<number | null>(null);
  const copyLink = async (idx: number) => {
    const item = uploadedItems[idx];
    if (!item) return;
    try {
      await copySecret(item.linkText);
      setCopiedLink(idx);
      setTimeout(() => setCopiedLink((c) => (c === idx ? null : c)), 2000);
    } catch {
      // クリップボードが使えない環境では何もしない
    }
  };
  // 送るときの段階 (0 読み込み・暗号化 / 1 ロッカーへ / 2 Manifest / 3 完了) と、ロッカーごとの置いた・失敗の数
  const [slabProgress, setSlabProgress] = useState<{
    step: number;
    placed: number;
    byLocker: Record<string, { placed: number; failed: number }>;
  } | null>(null);
  const onSlab = (e: OzzySlabEvent) =>
    setSlabProgress((prev) => {
      const base = prev ?? { step: 1, placed: 0, byLocker: {} };
      const cur = base.byLocker[e.lockerId] ?? { placed: 0, failed: 0 };
      return {
        step: Math.max(base.step, 1),
        placed: base.placed + (e.kind === 'placed' ? 1 : 0),
        byLocker: {
          ...base.byLocker,
          [e.lockerId]: e.kind === 'placed' ? { ...cur, placed: cur.placed + 1 } : { ...cur, failed: cur.failed + 1 },
        },
      };
    });
  const [voucherInput, setVoucherInput] = useState<string>('');

  const [downloadLinkInput, setDownloadLinkInput] = useState<string>('');
  const [downloadStatus, setDownloadStatus] = useState<string | null>(null);
  const [downloadProgress, setDownloadProgress] = useState<number>(0);
  const [downloadedFile, setDownloadedFile] = useState<{
    name: string;
    mime: string;
    size: number;
    url: string;
  } | null>(null);

  const [issuedVoucherToken, setIssuedVoucherToken] = useState<string>('');
  /** この画面で使うメンバー鍵 (ristretto255)。公開鍵を名簿に載せてもらう。秘密鍵は画面を閉じれば消える */
  const [memberKey, setMemberKey] = useState<OzzyMemberKeypair | null>(null);
  /** 招待券のリングにする名簿の公開鍵 (hex、改行区切り)。自分の鍵は自動で足す */
  const [ringInput, setRingInput] = useState<string>('');
  const [voucherError, setVoucherError] = useState<string | null>(null);
  const [voucherMaxGiB, setVoucherMaxGiB] = useState<number>(8);
  const [voucherValidDays, setVoucherValidDays] = useState<number>(14);

  const [isDragging, setIsDragging] = useState<boolean>(false);

  // ── 自分の中継 Worker (Ozzy を使う条件) ──
  const [ownWorker, setOwnWorker] = useState<string | null>(node?.ozzyWorkerUrl ?? null);
  useEffect(() => {
    setOwnWorker(node?.ozzyWorkerUrl ?? null);
  }, [node]);

  async function ensureOverseasPoolReady(chunkBytes: number) {
    await sodiumReady;
    const live = useLiveLockers && Boolean(node);
    const configKey = [chunkBytes, live, targetBatchChunks, idleGapMs, maxWaitMs, node ? 'node' : 'no-node'].join(':');
    if (overseasPoolRef.current && overseasPoolRef.current.initialized && overseasPoolRef.current.configKey === configKey) {
      return overseasPoolRef.current;
    }

    let coordinator: OverseasMultiLockerCoordinator;
    let cluster: MemoryOverseasLockerCluster | null = null;
    if (live && node) {
      // ★ 置くのも取るのもオニオン回路の M1 に頼む。M1 は交換で集めた他人の中継 Worker でロッカーへ行く。
      //   Manifest (鍵・置き場所) は P2P のファイル保管へ。共通の Worker・ディレクトリは使わない
      coordinator = new OverseasMultiLockerCoordinator({
        manifestStore: node.ozzyManifestStore,
        adapters: createOnionLockerAdapters(node.ozzyMesh, ONION_LOCKERS),
        chunkBytes,
        targetBatchChunks,
        idleGapMs,
        maxWaitMs,
        mesh: node.ozzyMesh,
        route: 'mesh-only',
      });
    } else {
      // 試験モード: この画面のメモリ上のロッカーと Manifest の置き場所 (通信しない)
      const c = new MemoryOverseasLockerCluster();
      cluster = c;
      const memFetch = (req: Request) => c.handleFetch(req);
      demoManifestsRef.current ??= memoryManifestStore();
      coordinator = new OverseasMultiLockerCoordinator({
        manifestStore: demoManifestsRef.current,
        adapters: [
          new CatboxLockerAdapter(memFetch), new LitterboxLockerAdapter(memFetch), new ZeroXZeroLockerAdapter(memFetch),
          new PomfLockerAdapter(memFetch, { variant: 'pomf-uguu' }), new GofileLockerAdapter(memFetch), new PixeldrainLockerAdapter(memFetch),
        ],
        chunkBytes,
        targetBatchChunks: Math.min(targetBatchChunks, 6),
        idleGapMs,
        maxWaitMs,
        route: 'direct-only',
      });
    }

    overseasPoolRef.current = { cluster, coordinator, initialized: true, configKey };
    return overseasPoolRef.current;
  }

  async function ensureR2PoolReady(chunkBytes: number) {
    await sodiumReady;
    const configKey = `${chunkBytes}:${useOnlyRealWorkers}:${registeredWorkers.map(w => w.workerUrl).join(',')}`;
    if (r2PoolRef.current && r2PoolRef.current.initialized && r2PoolRef.current.configKey === configKey) {
      return r2PoolRef.current;
    }
    const leaseStore = new CloudLeaseSetStore();
    const workers = new Map<string, OzzyGatekeeperWorker>();
    const backends = ['cloudflare-r2', 'backblaze-b2', 'oracle-s3'];
    const nowSec = Math.floor(Date.now() / 1000);

    for (const rw of registeredWorkers) {
      await leaseStore.upsertProvider(rw.lease, nowSec);
    }

    if (registeredWorkers.length === 0 || !useOnlyRealWorkers) {
      for (let i = 0; i < OZZY_RS_N; i++) {
        const kp = sodium.crypto_sign_keypair();
        const workerUrl = `https://r2-gatekeeper-${i.toString().padStart(2, '0')}.ozzy.workers.dev`;
        const bucket = new MemoryR2Bucket();
        const worker = new OzzyGatekeeperWorker(bucket, { expectedChunkBytes: chunkBytes });
        workers.set(workerUrl, worker);

        const lease = await createProviderLeaseSet({
          providerPubKey: kp.publicKey,
          providerPrivKey: kp.privateKey,
          endpoint: {
            workerUrl,
            backendId: backends[i % backends.length],
            authToken: 'blind-token',
          },
          expiresAtSec: nowSec + 86400 * 30,
          freeDataSlots: 2074,
        });
        await leaseStore.upsertProvider(lease, nowSec);
      }
    }

    const coordinator = new OzzyParallelTransferCoordinator(
      leaseStore,
      async (workerUrl, req) => {
        const w = workers.get(workerUrl);
        if (w) return w.handleFetch(req);
        return fetch(req, { cache: 'no-store' });
      },
      chunkBytes,
    );

    r2PoolRef.current = { leaseStore, workers, coordinator, initialized: true, configKey };
    return r2PoolRef.current;
  }

  const handleFileUpload = async (file: File) => {
    try {
      setUploadStatus(t('vault.reading'));
      setUploadProgress(5);
      const chunkBytes = useFastDemoChunk ? OZZY_DEMO_CHUNK_BYTES : OZZY_CHUNK_BYTES;
      // ★ ファイル全体をメモリに読み込まない。各エンジンがストライプ (最大約 64 MiB) ずつ File から切り出して読む
      const source: Blob = file;

      if (storageEngine === 'overseas-multi') {
        const live = useLiveLockers && Boolean(node);
        if (live && !meshReady) {
          setUploadStatus(t('vault.noCircuit'));
          return;
        }
        const ovPool = await ensureOverseasPoolReady(chunkBytes);
        setUploadProgress(10);
        setSlabProgress({ step: 0, placed: 0, byLocker: {} });
        setUploadStatus(
          live
            ? t('vault.spreadingLive', { lockers: ONION_LOCKERS.join(' / ') })
            : t('vault.spreadingDemo'),
        );
        const result = await ovPool.coordinator.uploadFile({
          source,
          fileName: file.name,
          mimeType: file.type || 'application/octet-stream',
          onProgress: (done, total) => {
            setUploadProgress(10 + Math.round((done / total) * 90));
            setUploadStatus(done < total ? t('vault.stripePlaced', { done, total: total - 1 }) : t('vault.placingManifest'));
            if (done >= total - 1) setSlabProgress((p) => (p ? { ...p, step: Math.max(p.step, 2) } : p));
          },
          onSlab,
        });
        setUploadProgress(100);
        setSlabProgress((p) => (p ? { ...p, step: 3 } : p));
        const lockerSet = Array.from(new Set(result.receipts.map(r => r.lockerId)));
        setUploadedItems(prev => [
          {
            fileName: result.manifest.fileName,
            mimeType: result.manifest.mimeType,
            totalBytes: result.manifest.totalFileSize,
            stripeCount: result.manifest.stripes.length,
            linkText: result.linkText,
            createdAt: new Date().toLocaleTimeString(),
            engine: 'overseas-multi',
            overseasReceipts: result.receipts,
            deleted: false,
          },
          ...prev,
        ]);
        setDownloadLinkInput(result.linkText);
        setUploadStatus(
          t('vault.uploadDone', { slabs: result.receipts.length, lockers: lockerSet.length, names: lockerSet.join(', ') }),
        );
        return;
      }

      const pool = await ensureR2PoolReady(chunkBytes);
      let parsedVoucher = undefined;
      if (voucherInput.trim()) {
        parsedVoucher = parseOzzyVoucherToken(voucherInput.trim()) ?? undefined;
        if (!parsedVoucher) {
          setUploadStatus(t('vault.badVoucher'));
          return;
        }
      }

      const result = await pool.coordinator.uploadFile({
        source,
        fileName: file.name,
        mimeType: file.type || 'application/octet-stream',
        voucher: parsedVoucher,
        onProgress: (done, total) => {
          setUploadProgress(Math.round((done / total) * 100));
          setUploadStatus(
            t('vault.proxyProgress', { done, total, k: OZZY_RS_K, n: OZZY_RS_N }),
          );
        },
      });

      setUploadedItems(prev => [
        {
          fileName: result.manifest.fileName,
          mimeType: result.manifest.mimeType,
          totalBytes: result.manifest.totalFileSize,
          stripeCount: result.manifest.stripes.length,
          linkText: result.linkText,
          createdAt: new Date().toLocaleTimeString(),
          engine: 'r2-gatekeeper',
        },
        ...prev,
      ]);
      setDownloadLinkInput(result.linkText);
      setUploadStatus(t('vault.uploadDoneR2'));
    } catch (err) {
      setUploadStatus(t('vault.uploadFailed', { reason: err instanceof Error ? err.message : String(err) }));
    }
  };

  /** 置いた Slab をロッカーから消す (削除も回路の M1 に頼む。匿名の Catbox / Pomf は消せない) */
  const handleDeleteSlabs = async (itemIndex: number) => {
    const target = uploadedItems[itemIndex];
    if (!target?.overseasReceipts) return;
    try {
      const chunkBytes = useFastDemoChunk ? OZZY_DEMO_CHUNK_BYTES : OZZY_CHUNK_BYTES;
      const ovPool = await ensureOverseasPoolReady(chunkBytes);
      const okCount = await ovPool.coordinator.deleteAllReceipts(target.overseasReceipts);
      setUploadedItems(prev => prev.map((it, idx) => (idx === itemIndex ? { ...it, deleted: true } : it)));
      setUploadStatus(
        t('vault.deleted', { ok: okCount, total: target.overseasReceipts.length }),
      );
    } catch (err) {
      setUploadStatus(t('vault.deleteFailed', { reason: err instanceof Error ? err.message : String(err) }));
    }
  };

  /** リンクから Manifest を取り終えて、保存先を選んでもらうのを待っているダウンロード */
  const [pendingDownload, setPendingDownload] = useState<
    | { kind: 'v3'; link: string; manifest: OzzyManifestV4 }
    | { kind: 'tier1'; link: OzzyLinkV2; manifest: OzzyManifestV2 }
    | null
  >(null);

  const chunkBytesNow = () => (useFastDemoChunk ? OZZY_DEMO_CHUNK_BYTES : OZZY_CHUNK_BYTES);

  /** 1 段目: リンクから Manifest を取り、名前・大きさを見せる (保存先はこの後で選ぶ) */
  const handleDownload = async () => {
    setPendingDownload(null);
    const v3 = parseOzzyLinkV3(downloadLinkInput);
    const v2 = v3 ? null : parseOzzyLink(downloadLinkInput);
    if (!v3 && !(v2 && ozzyIsTier1(v2))) {
      setDownloadStatus(t('vault.badLink'));
      return;
    }
    try {
      setDownloadProgress(5);
      if (v3) {
        const live = useLiveLockers && Boolean(node);
        if (live && !meshReady) {
          setDownloadStatus(t('vault.error', { reason: t(FAILURE_KEY['no-fetchers']) }));
          return;
        }
        setDownloadStatus(t('vault.fetchingManifestP2p'));
        const engine = (await ensureOverseasPoolReady(chunkBytesNow())).coordinator;
        const manifest = await engine.readManifest(v3);
        if (!manifest) {
          const failure = engine.lastDownloadFailure;
          setDownloadStatus(t('vault.error', { reason: failure ? t(FAILURE_KEY[failure]) : t('vault.manifestFailed') }));
          return;
        }
        setDownloadProgress(10);
        setPendingDownload({ kind: 'v3', link: v3, manifest });
        setDownloadStatus(t('vault.chooseDestination', { name: manifest.fileName, bytes: manifest.totalFileSize.toLocaleString() }));
        return;
      }
      setDownloadStatus(t('vault.fetchingManifestGk'));
      const engine = (await ensureR2PoolReady(chunkBytesNow())).coordinator;
      const manifest = await engine.readManifest(v2!);
      if (!manifest) {
        setDownloadStatus(t('vault.manifestGone'));
        return;
      }
      setDownloadProgress(10);
      setPendingDownload({ kind: 'tier1', link: v2!, manifest });
      setDownloadStatus(t('vault.chooseDestination', { name: manifest.fileName, bytes: manifest.totalFileSize.toLocaleString() }));
    } catch (err) {
      setDownloadStatus(t('vault.downloadFailed', { reason: err instanceof Error ? err.message : String(err) }));
    }
  };

  /**
   * 2 段目: 保存先を選んで、ストライプ単位で番号順に書き出す (ファイル全体をメモリに載せない)。
   * File System Access API (Chromium・Electron) があれば選んだファイルへ直接書く。ハッシュが合わなければ書きかけを破棄する。
   * 無いブラウザでは Blob の断片に貯めて最後に保存リンクにする。
   */
  const handleSave = async () => {
    const pd = pendingDownload;
    if (!pd) return;
    const picker = (window as unknown as {
      showSaveFilePicker?: (o: { suggestedName?: string }) => Promise<{ createWritable(): Promise<OzzyByteSink & { close(): Promise<void> }> }>;
    }).showSaveFilePicker;
    let sink: OzzyByteSink;
    let blobParts: Blob[] | null = null;
    try {
      if (picker) {
        // ★ ユーザー操作の直後に呼ぶ (ここより前に await を挟むと、ブラウザが保存ダイアログを出さない)
        const handle = await picker({ suggestedName: pd.manifest.fileName });
        sink = await handle.createWritable();
      } else {
        const parts: Blob[] = [];
        blobParts = parts;
        sink = { write: (chunk) => { parts.push(new Blob([chunk.slice().buffer])); } };
      }
    } catch {
      setDownloadStatus(t('vault.pickCancelled'));
      return;
    }
    try {
      const onStripes = (done: number, total: number) => {
        setDownloadProgress(total > 0 ? 10 + Math.round((done / total) * 90) : 10);
        setDownloadStatus(t('vault.stripesWritten', { done, total }));
      };
      let manifest: { fileName: string; mimeType: string; totalFileSize: number } | null;
      let failure: SlabReadFailure | null = null;
      if (pd.kind === 'tier1') {
        const engine = (await ensureR2PoolReady(chunkBytesNow())).coordinator;
        manifest = await engine.downloadToSink(pd.link, sink, { manifest: pd.manifest, onProgress: onStripes });
      } else {
        const engine = (await ensureOverseasPoolReady(chunkBytesNow())).coordinator;
        manifest = await engine.downloadToSink(pd.link, sink, {
          manifest: pd.manifest,
          onProgress: (p) => onStripes(p.stripesDone, p.stripeCount),
        });
        failure = engine.lastDownloadFailure;
      }
      if (!manifest) {
        setDownloadStatus(t('vault.error', { reason: failure ? t(FAILURE_KEY[failure]) : t('vault.chunksFailed') }));
        return;
      }
      setDownloadProgress(100);
      setPendingDownload(null);
      if (blobParts) {
        if (downloadedFile?.url) URL.revokeObjectURL(downloadedFile.url);
        const url = URL.createObjectURL(new Blob(blobParts, { type: manifest.mimeType }));
        setDownloadedFile({ name: manifest.fileName, mime: manifest.mimeType, size: manifest.totalFileSize, url });
        setDownloadStatus(t('vault.restored', { name: manifest.fileName }));
      } else {
        setDownloadStatus(t('vault.saved', { name: manifest.fileName, bytes: manifest.totalFileSize.toLocaleString() }));
      }
    } catch (err) {
      try {
        await sink.abort?.(err);
      } catch {
        // 閉じている
      }
      setDownloadStatus(t('vault.downloadFailed', { reason: err instanceof Error ? err.message : String(err) }));
    }
  };

  const ensureMemberKey = async (): Promise<OzzyMemberKeypair> => {
    if (memberKey) return memberKey;
    const kp = await generateMemberKeypair();
    setMemberKey(kp);
    return kp;
  };

  const handleMintVoucher = async () => {
    await sodiumReady;
    setVoucherError(null);
    const member = await ensureMemberKey();
    const ring: Uint8Array[] = [];
    for (const line of ringInput.split(/[\s,]+/).map(x => x.trim()).filter(Boolean)) {
      if (!/^[0-9a-f]{64}$/i.test(line)) {
        setVoucherError(t('vault.badRingKey', { key: line.slice(0, 16) }));
        return;
      }
      ring.push(sodium.from_hex(line.toLowerCase()));
    }
    if (ring.length + 1 < 2) {
      setVoucherError(t('vault.ringTooSmall'));
      return;
    }
    const today = Math.floor(Date.now() / 86_400_000);
    const maxChunks = Math.min(65535, voucherMaxGiB * 256); // 1 GiB = 256 × 4 MiB chunks
    try {
      const voucher = await issueUploadVoucher({
        member,
        ring,
        validStartDay: today,
        validDays: Math.min(OZZY_VOUCHER_MAX_DAYS, voucherValidDays),
        maxChunks,
      });
      setIssuedVoucherToken(formatOzzyVoucherToken(voucher));
    } catch (err) {
      setVoucherError(t('vault.mintFailed', { reason: err instanceof Error ? err.message : String(err) }));
    }
  };

  // ★ デスクトップ (ozzyDirect) は Worker を使わず、ロッカーへ直接つなぐ。Worker を求めるのはブラウザだけ
  if (!ownWorker && !node?.ozzyDirect) {
    return (
      <section className="column-content">
        <div className="page-head">
          <div>
            <div className="eyebrow">Ozzy</div>
            <h1 className="page-title">{t('vault.title')}</h1>
          </div>
        </div>
        <div className="panel">
          <h2 className="panel-title">{t('vault.firstTitle')}</h2>
          <p className="panel-desc">
            {tRich('vault.firstDesc', { link: (c) => <button type="button" className="btn-link" onClick={onOpenAbout}>{c}</button> })}
          </p>
          <div style={{ marginTop: 14 }}>
            <OzzyWorkerForm onSaved={setOwnWorker} />
          </div>
        </div>
      </section>
    );
  }

  const demo = storageEngine === 'overseas-multi' && !useLiveLockers;

  return (
    <section className="column-content">
      <div className="page-head">
        <div>
          <div className="eyebrow">Ozzy</div>
          <h1 className="page-title">{t('vault.title')}</h1>
        </div>
        <div className="segmented" role="tablist" aria-label={t('vault.tabsLabel')}>
          <button role="tab" aria-selected={activeSubTab === 'transfer'} onClick={() => setActiveSubTab('transfer')}>
            {t('vault.tabTransfer')}
          </button>
          <button role="tab" aria-selected={activeSubTab === 'voucher'} onClick={() => setActiveSubTab('voucher')}>
            {t('vault.tabVoucher')}
          </button>
        </div>
      </div>

      {activeSubTab === 'transfer' && (
        <div className="grid-2">
          {/* 送る */}
          <div className="panel">
            <div className="panel-head">
              <div>
                <h2 className="panel-title">{t('vault.sendTitle')}</h2>
                <p className="panel-desc">
                  {storageEngine === 'overseas-multi'
                    ? t('vault.sendDescOverseas')
                    : t('vault.sendDescGatekeeper')}
                </p>
              </div>
              <button type="button" className="btn btn-sm btn-ghost" onClick={onOpenSettings}>{t('vault.storageSettings')}</button>
            </div>

            <div className="stack">
              {demo && <div className="alert alert-warn">{t('vault.demoNote')}</div>}

              {storageEngine === 'r2-gatekeeper' && (
                <div className="field">
                  <label className="field-label" htmlFor="ozzy-voucher-input">{t('vault.voucherLabel')}</label>
                  <input
                    id="ozzy-voucher-input"
                    type="text"
                    className="mono"
                    placeholder="[[ozzy-voucher:v3:...]]"
                    value={voucherInput}
                    onChange={e => setVoucherInput(e.target.value)}
                  />
                </div>
              )}

              {/* ドロップゾーン */}
              <div
                className={`dropzone${isDragging ? ' is-over' : ''}`}
                onDragOver={e => {
                  e.preventDefault();
                  setIsDragging(true);
                }}
                onDragLeave={() => setIsDragging(false)}
                onDrop={e => {
                  e.preventDefault();
                  setIsDragging(false);
                  const f = e.dataTransfer.files?.[0];
                  if (f) void handleFileUpload(f);
                }}
                onClick={() => {
                  const input = document.getElementById('vault-file-input') as HTMLInputElement | null;
                  input?.click();
                }}
              >
                <input
                  id="vault-file-input"
                  type="file"
                  className="visually-hidden"
                  onChange={e => {
                    const f = e.target.files?.[0];
                    if (f) void handleFileUpload(f);
                  }}
                />
                <div className="dropzone-icon" aria-hidden="true">⬆</div>
                <div className="dropzone-title">{t('vault.dropTitle')}</div>
                <div className="dropzone-sub">{t('vault.dropSub')}</div>
              </div>

              {uploadStatus && (
                <div className="alert alert-info" style={{ flexDirection: 'column', gap: 6 }}>
                  <div className="small strong">{uploadStatus}</div>
                  <div className="progress">
                    <span style={{ width: `${uploadProgress}%` }} />
                  </div>
                </div>
              )}

              {storageEngine === 'overseas-multi' && slabProgress && (
                <div className="upload-progress-detail">
                  <ol className="upload-steps" aria-label={t('vault.stepsLabel')}>
                    {[t('vault.stepRead'), t('vault.stepLockers', { count: slabProgress.placed }), t('vault.stepManifest'), t('vault.stepDone')].map((label, i) => (
                      <li
                        key={i}
                        className={i < slabProgress.step ? 'is-done' : i === slabProgress.step ? 'is-current' : undefined}
                        aria-current={i === slabProgress.step ? 'step' : undefined}
                      >
                        {label}
                      </li>
                    ))}
                  </ol>
                  {Object.keys(slabProgress.byLocker).length > 0 && (
                    <table className="locker-table">
                      <thead>
                        <tr><th>{t('vault.colLocker')}</th><th>{t('vault.colPlaced')}</th><th>{t('vault.colFailed')}</th></tr>
                      </thead>
                      <tbody>
                        {Object.entries(slabProgress.byLocker).sort(([a], [b]) => a.localeCompare(b)).map(([id, n]) => (
                          <tr key={id}>
                            <td>{id}</td>
                            <td>{n.placed}</td>
                            <td className={n.failed > 0 ? 'text-warn' : undefined}>{n.failed}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              )}

              {uploadedItems.length > 0 && (
                <div className="stack stack-sm" style={{ marginTop: 8 }}>
                  <div className="eyebrow">{t('vault.madeLinks')}</div>
                  <div className="item-list">
                    {uploadedItems.map((item, idx) => (
                      <div key={idx} className="item">
                        <div className="item-head">
                          <span className="item-name">
                            {item.fileName} <span className="muted">{t('vault.itemSize', { bytes: item.totalBytes.toLocaleString(), count: item.stripeCount })}</span>
                          </span>
                          <span className="item-meta">{item.createdAt}</span>
                        </div>
                        <code className="code-block">{item.linkText}</code>
                        <div className="row row-end" style={{ marginTop: 8 }}>
                          <button className="btn btn-sm" onClick={() => void copyLink(idx)}>
                            {copiedLink === idx ? t('vault.copied') : t('vault.copy')}
                          </button>
                        </div>

                        {item.overseasReceipts && item.overseasReceipts.length > 0 && (
                          <div className="row row-between row-wrap" style={{ marginTop: 10, gap: 8 }}>
                            <span className="xsmall muted">
                              {tRich('vault.slabs', { strong: (c) => <strong className="text-2">{c}</strong> }, { count: item.overseasReceipts.length, lockers: Array.from(new Set(item.overseasReceipts.map(r => r.lockerId))).join(', ') })}
                            </span>
                            <button
                              className={`btn btn-sm ${item.deleted ? 'btn-ghost' : 'btn-danger'}`}
                              disabled={item.deleted}
                              onClick={() => void handleDeleteSlabs(idx)}
                            >
                              {item.deleted ? t('vault.deletedDone') : t('vault.deleteFromLockers')}
                            </button>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* 受け取る */}
          <div className="panel">
            <div className="panel-head">
              <div>
                <h2 className="panel-title">{t('vault.receiveTitle')}</h2>
                <p className="panel-desc">{t('vault.receiveDesc')}</p>
              </div>
            </div>

            <div className="stack">
              <div className="row row-wrap" style={{ gap: 8 }}>
                {meshReady ? (
                  <span className="badge badge-ok">{t('vault.circuitReady', { count: p2pFetcherCount })}</span>
                ) : (
                  <span className="badge badge-warn">{t('vault.circuitBuilding')}</span>
                )}
              </div>

              <div className="field">
                <label className="field-label" htmlFor="ozzy-link-input">{t('vault.linkLabel')}</label>
                <input
                  id="ozzy-link-input"
                  type="text"
                  className="mono"
                  placeholder={t('vault.linkPlaceholder')}
                  value={downloadLinkInput}
                  onChange={e => setDownloadLinkInput(e.target.value)}
                />
              </div>

              <button
                className="btn btn-primary btn-block"
                onClick={() => void handleDownload()}
                disabled={!downloadLinkInput.trim()}
              >
                {t('vault.fetch')}
              </button>

              {pendingDownload && (
                <div className="result">
                  <div className="row row-between row-wrap" style={{ gap: 12 }}>
                    <div>
                      <div className="strong" style={{ fontSize: 15 }}>{pendingDownload.manifest.fileName}</div>
                      <div className="xsmall muted">
                        {pendingDownload.manifest.totalFileSize.toLocaleString()} bytes · {pendingDownload.manifest.mimeType}
                      </div>
                    </div>
                    <button className="btn btn-primary" onClick={() => void handleSave()}>
                      {t('vault.saveAndFetch')}
                    </button>
                  </div>
                </div>
              )}

              {downloadStatus && (
                <div className="alert alert-info" style={{ flexDirection: 'column', gap: 6 }}>
                  <div className="small strong">{downloadStatus}</div>
                  <div className="progress progress-ok">
                    <span style={{ width: `${downloadProgress}%` }} />
                  </div>
                </div>
              )}

              {downloadedFile && (
                <div className="result">
                  <div className="row row-between row-wrap" style={{ gap: 12 }}>
                    <div>
                      <div className="badge badge-ok" style={{ marginBottom: 6 }}>{t('vault.restoredBadge')}</div>
                      <div className="strong" style={{ fontSize: 15 }}>{downloadedFile.name}</div>
                      <div className="xsmall muted">{downloadedFile.size.toLocaleString()} bytes · {downloadedFile.mime}</div>
                    </div>
                    <a
                      href={downloadedFile.url}
                      download={downloadedFile.name}
                      className="btn btn-primary"
                    >
                      {t('vault.saveToDevice')}
                    </a>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {activeSubTab === 'voucher' && (
        <div className="panel">
          <div className="panel-head">
            <div>
              <h2 className="panel-title">{t('vault.mintTitle')}</h2>
              <p className="panel-desc">
                {t('vault.mintDesc')}
              </p>
            </div>
          </div>

          <div className="stack stack-sm" style={{ marginBottom: 16 }}>
            <div className="field">
              <label className="field-label">{t('vault.memberKey')}</label>
              {memberKey ? (
                <code className="code-block">{sodium.to_hex(memberKey.publicKey)}</code>
              ) : (
                <button className="btn btn-sm" style={{ alignSelf: 'flex-start' }} onClick={() => void ensureMemberKey()}>{t('vault.makeMemberKey')}</button>
              )}
            </div>
            <div className="field">
              <label className="field-label">{t('vault.ringLabel')}</label>
              <textarea
                className="mono"
                rows={4}
                value={ringInput}
                onChange={e => setRingInput(e.target.value)}
                placeholder={t('vault.ringPlaceholder')}
              />
            </div>
            {voucherError && <div className="msg msg-warn">{voucherError}</div>}
          </div>

          <div className="field-grid" style={{ marginBottom: 16 }}>
            <div className="field">
              <label className="field-label">{t('vault.maxGiB')}</label>
              <input
                type="number"
                min={1}
                max={64}
                value={voucherMaxGiB}
                onChange={e => setVoucherMaxGiB(Math.max(1, parseInt(e.target.value || '8', 10)))}
              />
            </div>
            <div className="field">
              <label className="field-label">{t('vault.validDays')}</label>
              <input
                type="number"
                min={1}
                max={14}
                value={voucherValidDays}
                onChange={e => setVoucherValidDays(Math.max(1, parseInt(e.target.value || '14', 10)))}
              />
            </div>
            <div style={{ display: 'flex', alignItems: 'flex-end' }}>
              <button
                className="btn btn-primary btn-block"
                onClick={() => void handleMintVoucher()}
              >
                {t('vault.mint')}
              </button>
            </div>
          </div>

          {issuedVoucherToken && (
            <div className="alert alert-info">
              <div className="stack stack-sm grow">
                <div className="eyebrow" style={{ color: 'var(--warn)' }}>{t('vault.issuedTitle')}</div>
                <code className="code-block is-gold">
                  {issuedVoucherToken}
                </code>
              </div>
            </div>
          )}
        </div>
      )}

    </section>
  );
}

import { describe, expect, it } from 'vitest';
import sodium, { sodiumReady } from '../src/crypto/sodium';
import { bytesEqual } from '../src/files/FileFormat';
import {
  CatboxLockerAdapter,
  GenericLockerSlabStagingMixer,
  GofileLockerAdapter,
  LitterboxLockerAdapter,
  MemoryOverseasLockerCluster,
  OverseasMultiLockerCoordinator,
  PixeldrainLockerAdapter,
  PomfLockerAdapter,
  RamChunkArena,
  ZeroXZeroLockerAdapter,
  createWorkerCorsProxyTransport,
  deserializeOzzyManifestV4,
  generateGofileWebsiteToken,
  memoryManifestStore,
  parseOzzyLinkV3,
  serializeOzzyManifestV4,
} from '../src/ozzy';

describe('Ozzy v0.2 Overseas Anonymous Lockers Module-by-Module Verification Suite', () => {
  const chunkBytes = 64 * 1024; // 64 KiB uniform chunk for fast deterministic verification

  it('[Module 1: Catbox.moe] uploads a multi-chunk Slab via multipart, slices individual 64 KiB chunks via HTTP Range (206), and deletes via reqtype=deletefiles', async () => {
    await sodiumReady;
    const cluster = new MemoryOverseasLockerCluster();
    const catbox = new CatboxLockerAdapter(req => cluster.handleFetch(req), {
      userhash: 'ozzy_ephemeral_userhash',
    });

    const chunk0 = sodium.randombytes_buf(chunkBytes);
    const chunk1 = sodium.randombytes_buf(chunkBytes);
    const chunk2 = sodium.randombytes_buf(chunkBytes);
    const slab = new Uint8Array(chunkBytes * 3);
    slab.set(chunk0, 0);
    slab.set(chunk1, chunkBytes);
    slab.set(chunk2, chunkBytes * 2);

    const receipt = await catbox.uploadSlab(slab, 'catbox_test_slab.bin');
    expect(receipt.lockerId).toBe('catbox');
    expect(receipt.downloadUrl).toMatch(/^https:\/\/files\.catbox\.moe\//);
    expect(receipt.byteLength).toBe(chunkBytes * 3);

    // HTTP Range (206 Partial Content) で真ん中の chunk1 だけを切り出し
    const sliced1 = await catbox.fetchSlabRange(receipt.downloadUrl, chunkBytes, chunkBytes * 2 - 1);
    expect(sliced1).not.toBeNull();
    expect(bytesEqual(sliced1!, chunk1)).toBe(true);

    // 末尾の chunk2 だけを切り出し
    const sliced2 = await catbox.fetchSlabRange(receipt.downloadUrl, chunkBytes * 2, chunkBytes * 3 - 1);
    expect(sliced2).not.toBeNull();
    expect(bytesEqual(sliced2!, chunk2)).toBe(true);

    // Polite Delete (reqtype=deletefiles)
    const deleted = await catbox.deleteSlab(receipt);
    expect(deleted).toBe(true);

    // 削除後は 404 (null) になること
    const afterDel = await catbox.fetchSlabRange(receipt.downloadUrl, 0, chunkBytes - 1);
    expect(afterDel).toBeNull();
  });

  it('[Module 2: Litterbox] uploads ephemeral Slab with 72h timer, serves HTTP Range (206) slices, and automatically expires after TTL', async () => {
    await sodiumReady;
    let currentNowMs = Date.now();
    const cluster = new MemoryOverseasLockerCluster();
    const litterbox = new LitterboxLockerAdapter(req => cluster.handleFetch(req, currentNowMs), {
      expiryTime: '72h',
    });

    const chunk0 = sodium.randombytes_buf(chunkBytes);
    const chunk1 = sodium.randombytes_buf(chunkBytes);
    const slab = new Uint8Array(chunkBytes * 2);
    slab.set(chunk0, 0);
    slab.set(chunk1, chunkBytes);

    const receipt = await litterbox.uploadSlab(slab, 'litter_slab.bin');
    expect(receipt.lockerId).toBe('litterbox');
    expect(receipt.downloadUrl).toMatch(/^https:\/\/litter\.catbox\.moe\//);

    const slice = await litterbox.fetchSlabRange(receipt.downloadUrl, chunkBytes, chunkBytes * 2 - 1);
    expect(slice).not.toBeNull();
    expect(bytesEqual(slice!, chunk1)).toBe(true);

    // 73 時間経過後にアクセスすると自動消去 (404) されていること
    currentNowMs += 73 * 3600 * 1000;
    const expiredSlice = await litterbox.fetchSlabRange(receipt.downloadUrl, 0, chunkBytes - 1);
    expect(expiredSlice).toBeNull();
  });

  it('[Module 3: 0x0.st] uploads Slab with custom User-Agent, captures X-Token header, slices via HTTP Range (206), and purges via X-Token delete', async () => {
    await sodiumReady;
    const cluster = new MemoryOverseasLockerCluster();
    const zeroXZero = new ZeroXZeroLockerAdapter(req => cluster.handleFetch(req), {
      expiresHours: 360,
    });

    const c0 = sodium.randombytes_buf(chunkBytes);
    const c1 = sodium.randombytes_buf(chunkBytes);
    const slab = new Uint8Array(chunkBytes * 2);
    slab.set(c0, 0);
    slab.set(c1, chunkBytes);

    const receipt = await zeroXZero.uploadSlab(slab, 'nullpointer_slab.bin');
    expect(receipt.lockerId).toBe('0x0.st');
    expect(receipt.downloadUrl).toMatch(/^https:\/\/0x0\.st\//);
    expect(receipt.deleteToken.length).toBeGreaterThan(0);

    const sliced0 = await zeroXZero.fetchSlabRange(receipt.downloadUrl, 0, chunkBytes - 1);
    expect(sliced0).not.toBeNull();
    expect(bytesEqual(sliced0!, c0)).toBe(true);

    // X-Token を用いた即時物理削除
    const delOk = await zeroXZero.deleteSlab(receipt);
    expect(delOk).toBe(true);

    const afterDel = await zeroXZero.fetchSlabRange(receipt.downloadUrl, 0, chunkBytes - 1);
    expect(afterDel).toBeNull();
  });

  it('[Module 4: Pomf Clones (pomf2.lain.la & qu.ax)] uploads via files[] multipart JSON protocol, slices via HTTP Range (206), and deletes cleanly', async () => {
    await sodiumReady;
    const cluster = new MemoryOverseasLockerCluster();
    const lain = new PomfLockerAdapter(req => cluster.handleFetch(req), { variant: 'pomf-lain' });
    const quax = new PomfLockerAdapter(req => cluster.handleFetch(req), { variant: 'pomf-quax' });

    for (const adapter of [lain, quax]) {
      const c0 = sodium.randombytes_buf(chunkBytes);
      const c1 = sodium.randombytes_buf(chunkBytes);
      const slab = new Uint8Array(chunkBytes * 2);
      slab.set(c0, 0);
      slab.set(c1, chunkBytes);

      const receipt = await adapter.uploadSlab(slab, 'pomf_slab.bin');
      expect(receipt.lockerId).toBe(adapter.lockerId);

      const slice1 = await adapter.fetchSlabRange(receipt.downloadUrl, chunkBytes, chunkBytes * 2 - 1);
      expect(slice1).not.toBeNull();
      expect(bytesEqual(slice1!, c1)).toBe(true);

      expect(await adapter.deleteSlab(receipt)).toBe(true);
      expect(await adapter.fetchSlabRange(receipt.downloadUrl, 0, chunkBytes - 1)).toBeNull();
    }
  });

  it('[Module 5: Gofile.io] discovers edge server via /servers, uploads Slab to /contents/uploadfile, slices with guestToken Range GET (206), and deletes via DELETE /contents', async () => {
    await sodiumReady;
    const cluster = new MemoryOverseasLockerCluster();
    const gofile = new GofileLockerAdapter(req => cluster.handleFetch(req));

    const c0 = sodium.randombytes_buf(chunkBytes);
    const c1 = sodium.randombytes_buf(chunkBytes);
    const slab = new Uint8Array(chunkBytes * 2);
    slab.set(c0, 0);
    slab.set(c1, chunkBytes);

    const receipt = await gofile.uploadSlab(slab, 'gofile_slab.bin');
    expect(receipt.lockerId).toBe('gofile');
    expect(receipt.downloadUrl).toContain('store1.gofile.io/download/web/');
    expect(receipt.deleteToken).toMatch(/^gftok_/);

    const slice1 = await gofile.fetchSlabRange(
      receipt.downloadUrl,
      chunkBytes,
      chunkBytes * 2 - 1,
      receipt.deleteToken,
    );
    expect(slice1).not.toBeNull();
    expect(bytesEqual(slice1!, c1)).toBe(true);

    expect(await gofile.deleteSlab(receipt)).toBe(true);
    expect(await gofile.fetchSlabRange(receipt.downloadUrl, 0, chunkBytes - 1, receipt.deleteToken)).toBeNull();
  });

  it('[Module 6: Pixeldrain] uploads raw binary via PUT /api/file/:name, slices via HTTP Range (206), and deletes via DELETE /api/file/:id', async () => {
    await sodiumReady;
    const cluster = new MemoryOverseasLockerCluster();
    const pixeldrain = new PixeldrainLockerAdapter(req => cluster.handleFetch(req));

    const c0 = sodium.randombytes_buf(chunkBytes);
    const c1 = sodium.randombytes_buf(chunkBytes);
    const slab = new Uint8Array(chunkBytes * 2);
    slab.set(c0, 0);
    slab.set(c1, chunkBytes);

    const receipt = await pixeldrain.uploadSlab(slab, 'pixeldrain_slab.bin');
    expect(receipt.lockerId).toBe('pixeldrain');
    expect(receipt.downloadUrl).toMatch(/^https:\/\/pixeldrain\.com\/api\/file\/pd_/);

    const slice0 = await pixeldrain.fetchSlabRange(receipt.downloadUrl, 0, chunkBytes - 1);
    expect(slice0).not.toBeNull();
    expect(bytesEqual(slice0!, c0)).toBe(true);

    expect(await pixeldrain.deleteSlab(receipt)).toBe(true);
    expect(await pixeldrain.fetchSlabRange(receipt.downloadUrl, 0, chunkBytes - 1)).toBeNull();
  });

  it('[Module 7: GenericLockerSlabStagingMixer] shuffles chunks in RAM and flushes automatically on idle_gap_timeout when chunks are missing', async () => {
    await sodiumReady;
    const cluster = new MemoryOverseasLockerCluster();
    const zeroXZero = new ZeroXZeroLockerAdapter(req => cluster.handleFetch(req));
    const arena = new RamChunkArena(16, chunkBytes);

    // 事前生成しておくことで ingest ループ中の WASM RNG ブロッキングを排除
    const pregeneratedChunks = Array.from({ length: 7 }, () => sodium.randombytes_buf(chunkBytes));

    const flushed: { reason: string; count: number }[] = [];
    const mixer = new GenericLockerSlabStagingMixer({
      adapter: zeroXZero,
      arena,
      chunkBytes,
      targetBatchChunks: 8,
      idleGapMs: 40,
      maxWaitMs: 300,
      onSlabFlushed: res => {
        flushed.push({ reason: res.flushReason, count: res.chunkCount });
      },
    });

    // 8 チャンク目標に対して 5 チャンクしか届かない状況を発生させる
    for (let i = 0; i < 5; i++) {
      mixer.ingestChunk(i, pregeneratedChunks[i]);
    }

    await new Promise(r => setTimeout(r, 85));
    expect(flushed.length).toBe(1);
    expect(flushed[0].reason).toBe('idle_gap_timeout');
    expect(flushed[0].count).toBe(5);
    expect(arena.stats.activeSlots).toBe(0);

    // さらに遅れて到着した 2 チャンク (Straggler) も Tail Slab として自動フラッシュされることを確認
    mixer.ingestChunk(5, pregeneratedChunks[5]);
    mixer.ingestChunk(6, pregeneratedChunks[6]);
    await new Promise(r => setTimeout(r, 85));

    const results = await mixer.flushRemainingAndWait();
    expect(results.length).toBe(2);
    expect(results[0].flushReason).toBe('idle_gap_timeout');
    expect(results[0].chunkCount).toBe(5);
    expect(results[1].flushReason).toBe('idle_gap_timeout');
    expect(results[1].chunkCount).toBe(2);
    expect(arena.stats.activeSlots).toBe(0);

    // Manifest に入れる置き場所: ロッカー・URL・Slab の中の並び (削除トークンは入らない)
    const loc = results[0].location;
    expect(loc.lockerId).toBe('0x0.st');
    expect(loc.url).toBe(results[0].receipt.downloadUrl);
    expect(loc.slabChunks).toBe(5);
    expect(loc.chunkMap.length).toBe(5);
    expect(JSON.stringify(loc)).not.toContain(results[0].receipt.deleteToken);
  });

  it('[Module 8: OverseasMultiLockerCoordinator] distributes across 6 heterogeneous lockers, survives simultaneous 2-locker outages, and executes Polite DELETE', async () => {
    await sodiumReady;
    const cluster = new MemoryOverseasLockerCluster();
    const catbox = new CatboxLockerAdapter(req => cluster.handleFetch(req));
    const litterbox = new LitterboxLockerAdapter(req => cluster.handleFetch(req));
    const zeroXZero = new ZeroXZeroLockerAdapter(req => cluster.handleFetch(req));
    const lain = new PomfLockerAdapter(req => cluster.handleFetch(req), { variant: 'pomf-lain' });
    const gofile = new GofileLockerAdapter(req => cluster.handleFetch(req));
    const pixeldrain = new PixeldrainLockerAdapter(req => cluster.handleFetch(req));

    const coordinator = new OverseasMultiLockerCoordinator({
      manifestStore: memoryManifestStore(),
      adapters: [catbox, litterbox, zeroXZero, lain, gofile, pixeldrain],
      chunkBytes,
      targetBatchChunks: 5,
      idleGapMs: 35,
      maxWaitMs: 120,
    });

    // 1.15 MiB (複数ストライプ) のファイルを 6 社の異なる海外ロッカーへ同時に分散アップロード
    // さらに途中で 4 チャンク (shareIndex 1, 8, 15, 22) が欠落するカオス条件も注入
    const originalFile = sodium.randombytes_buf(Math.floor(chunkBytes * 18.5));
    const uploaded = await coordinator.uploadFile({
      fileData: originalFile,
      fileName: 'heterogeneous-overseas-vault.bin',
      mimeType: 'application/octet-stream',
      dropShareIndices: new Set([1, 8, 15, 22]),
    });

    // 複数の異なる海外ロッカーへ Slab が分散配置されたことを確認
    const usedLockerIds = new Set(uploaded.receipts.map(r => r.lockerId));
    expect(usedLockerIds.size).toBeGreaterThanOrEqual(5);
    expect(coordinator.arena.stats.activeSlots).toBe(0);
    // 置いた Slab はすべて確かめてから Manifest に入れた
    expect(coordinator.uploadStats.verified).toBe(uploaded.receipts.length);
    // 置き場所は Manifest に入っている (共通のディレクトリへは何も出さない)
    const locs = uploaded.manifest.stripes.flatMap(st => st.locations);
    expect(locs.length).toBe(uploaded.receipts.length);

    // ★ 大規模障害・検閲シミュレート: Litterbox と 0x0.st の 2 社が同時に完全ダウン (503)
    cluster.setHostOffline('litter.catbox.moe', true);
    cluster.setHostOffline('0x0.st', true);

    // 残りのロッカー群 + Reed-Solomon(16,32) で、リンクだけから 1 バイトの欠損もなく復元できる
    const downloaded = await coordinator.downloadFile(uploaded.linkText);
    expect(downloaded).not.toBeNull();
    expect(downloaded!.manifest.fileName).toBe('heterogeneous-overseas-vault.bin');
    expect(bytesEqual(downloaded!.data, originalFile)).toBe(true);
    expect(coordinator.arena.stats.activeSlots).toBe(0);

    // オフライン状態を解除して全海外ロッカーから一括 Polite DELETE
    cluster.setHostOffline('litter.catbox.moe', false);
    cluster.setHostOffline('0x0.st', false);
    const deletable = uploaded.receipts.filter(r => r.lockerId !== 'litterbox' && r.lockerId !== 'catbox').length;
    const deletedCount = await coordinator.deleteAllReceipts(uploaded.receipts);
    expect(deletedCount).toBeGreaterThanOrEqual(deletable);
  });

  it('[Module 9: Cross-Device Link-Only Transfer] Device A uploads and shares ONLY [[ozzy:v3:...]]; Device B (separate memory) fetches the Manifest from P2P storage and downloads the file', async () => {
    await sodiumReady;
    const cluster = new MemoryOverseasLockerCluster();
    // 端末 A と B の間で共有されるのは P2P のファイル保管だけ (アプリでは OzNode.ozzyManifestStore)。共通の Worker は無い
    const p2p = memoryManifestStore();

    const makeAdapters = () => [
      new CatboxLockerAdapter(req => cluster.handleFetch(req)),
      new LitterboxLockerAdapter(req => cluster.handleFetch(req)),
      new ZeroXZeroLockerAdapter(req => cluster.handleFetch(req)),
      new PomfLockerAdapter(req => cluster.handleFetch(req), { variant: 'pomf-lain' }),
      new GofileLockerAdapter(req => cluster.handleFetch(req)),
      new PixeldrainLockerAdapter(req => cluster.handleFetch(req)),
    ];

    const coordinatorDeviceA = new OverseasMultiLockerCoordinator({
      manifestStore: p2p,
      adapters: makeAdapters(),
      chunkBytes,
      targetBatchChunks: 5,
      idleGapMs: 30,
      maxWaitMs: 120,
    });
    const secretPayload = sodium.randombytes_buf(chunkBytes * 12 + 7777);
    const { linkText } = await coordinatorDeviceA.uploadFile({
      fileData: secretPayload,
      fileName: 'cross-device-shared-document.pdf',
      mimeType: 'application/pdf',
    });
    expect(linkText).toMatch(/^\[\[ozzy:v3:[A-Za-z0-9_-]{74}\]\]$/);
    expect(p2p.size).toBe(1);

    // P2P に置かれた Manifest は暗号文 (保管するノードには名前も置き場所も見えない)
    const stored = await p2p.get(parseOzzyLinkV3(linkText)!);
    expect(stored).not.toBeNull();

    // 端末 B: 端末 A とは一切メモリを共有しない。チャット等で受け取った linkText だけを入力
    const coordinatorDeviceB = new OverseasMultiLockerCoordinator({
      manifestStore: p2p,
      adapters: makeAdapters(),
      chunkBytes,
    });
    const manifest = await coordinatorDeviceB.readManifest(linkText);
    expect(manifest?.fileName).toBe('cross-device-shared-document.pdf');
    const downloadedOnDeviceB = await coordinatorDeviceB.downloadFile(linkText);
    expect(downloadedOnDeviceB).not.toBeNull();
    expect(downloadedOnDeviceB!.manifest.fileName).toBe('cross-device-shared-document.pdf');
    expect(downloadedOnDeviceB!.manifest.mimeType).toBe('application/pdf');
    expect(bytesEqual(downloadedOnDeviceB!.data, secretPayload)).toBe(true);
    // Manifest v4 の往復
    expect(deserializeOzzyManifestV4(serializeOzzyManifestV4(manifest!))).toEqual(manifest);

    // リンクが違えば取れない (別のリンクの Manifest は開けない)
    const wrong = new OverseasMultiLockerCoordinator({ manifestStore: p2p, adapters: makeAdapters(), chunkBytes });
    expect(await wrong.downloadFile('[[ozzy:v3:' + 'A'.repeat(74) + ']]')).toBeNull();
  });

  it('[Module 10: Reverse-Engineered Wrappers] verifies GoFile dynamic X-Website-Token & guest session activation, 0x0.st -> x0.at mirror failover, and Pomf -> Uguu.se failover', async () => {
    await sodiumReady;
    const cluster = new MemoryOverseasLockerCluster();

    // 1. GoFile の動的 X-Website-Token (`SHA256(ua::en-US::token::timeSlot::12af056dacea0b)`) 検証
    const wt = await generateGofileWebsiteToken('Mozilla/5.0', 'test_token_123', 14400 * 100);
    expect(wt).toMatch(/^[0-9a-f]{64}$/);

    // Gofile アップロード -> 別端末 (authToken 未保持) が /accounts + /contents?wt=... を自動実行して Range 206 取得
    const gofileA = new GofileLockerAdapter(req => cluster.handleFetch(req));
    const gofileB = new GofileLockerAdapter(req => cluster.handleFetch(req));
    const sample = sodium.randombytes_buf(chunkBytes * 2);
    const gfReceipt = await gofileA.uploadSlab(sample, 'gofile_re_slab.bin');
    expect(gfReceipt.downloadUrl).toContain('#folder=');

    const gfSlice = await gofileB.fetchSlabRange(gfReceipt.downloadUrl, chunkBytes, chunkBytes * 2 - 1);
    expect(gfSlice).not.toBeNull();
    expect(bytesEqual(gfSlice!, sample.subarray(chunkBytes, chunkBytes * 2))).toBe(true);
    expect(await gofileA.deleteSlab(gfReceipt)).toBe(true);

    // 2. 本家 `0x0.st` が 503 で閉鎖中でも自動的に `https://x0.at` へフェイルオーバーして `.txt` バイナリを格納・Range 206 取得できること
    cluster.setHostOffline('0x0.st', true);
    const zeroXZero = new ZeroXZeroLockerAdapter(req => cluster.handleFetch(req));
    const zxReceipt = await zeroXZero.uploadSlab(sample, 'failover_slab.bin');
    expect(zxReceipt.downloadUrl).toMatch(/^https:\/\/x0\.at\/.*\.txt$/);
    const zxSlice = await zeroXZero.fetchSlabRange(zxReceipt.downloadUrl, 0, chunkBytes - 1);
    expect(zxSlice).not.toBeNull();
    expect(bytesEqual(zxSlice!, sample.subarray(0, chunkBytes))).toBe(true);

    // 3. `pomf2.lain.la` がダウン中でも自動的に `https://uguu.se/upload` (`d.uguu.se`) へフェイルオーバーして Range 206 取得できること
    cluster.setHostOffline('pomf2.lain.la', true);
    const pomf = new PomfLockerAdapter(req => cluster.handleFetch(req), { variant: 'pomf-lain' });
    const pfReceipt = await pomf.uploadSlab(sample, 'uguu_failover.bin');
    expect(pfReceipt.downloadUrl).toMatch(/^https:\/\/d\.uguu\.se\//);
    const pfSlice = await pomf.fetchSlabRange(pfReceipt.downloadUrl, chunkBytes, chunkBytes * 2 - 1);
    expect(pfSlice).not.toBeNull();
    expect(bytesEqual(pfSlice!, sample.subarray(chunkBytes, chunkBytes * 2))).toBe(true);
  });

  it('[Module 11: Anonymity Hardening] enforces Fail-Closed Blind Relay (zero raw IP leak), strips identifying headers, isolates Gofile guest identities per Slab, and blinds manifest timestamps to 30-day epochs', async () => {
    await sodiumReady;

    // 1. Fail-Closed Blind Relay: Worker プロキシが 502 を返した際、生 IP で直接海外ロッカーへフォールバックせず 502 のまま遮断すること
    const seenUrls: string[] = [];
    let lastProxyRequest: Request | null = null;
    const mockFetch = async (req: Request): Promise<Response> => {
      seenUrls.push(req.url);
      if (req.url.includes('/ozzy/v2/locker-proxy')) {
        lastProxyRequest = req;
        return new Response(JSON.stringify({ ok: false, error: 'Upstream unreachable' }), { status: 502 });
      }
      return new Response('DIRECT_IP_LEAKED', { status: 200 });
    };

    const strictTransport = createWorkerCorsProxyTransport('https://blind-relay.example.workers.dev', mockFetch);
    const leakTestReq = new Request('https://catbox.moe/user/api.php', {
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain',
        'Referer': 'https://secret-internal.local/page',
        'Origin': 'https://secret-internal.local',
        'X-Forwarded-For': '203.0.113.99',
        'CF-Connecting-IP': '203.0.113.99',
      },
      body: 'test',
    });
    const relayResp = await strictTransport(leakTestReq);
    expect(relayResp.status).toBe(502);
    // 生 IP での直接通信 (`https://catbox.moe/user/api.php`) が一度も呼ばれていないこと
    expect(seenUrls).toEqual(['https://blind-relay.example.workers.dev/ozzy/v2/locker-proxy']);
    // 識別ヘッダー (Referer, Origin, X-Forwarded-For, CF-Connecting-IP) がプロキシ転送前に剥離されていること
    expect(lastProxyRequest).not.toBeNull();
    expect(lastProxyRequest!.headers.get('referer')).toBeNull();
    expect(lastProxyRequest!.headers.get('origin')).toBeNull();
    expect(lastProxyRequest!.headers.get('x-forwarded-for')).toBeNull();
    expect(lastProxyRequest!.headers.get('cf-connecting-ip')).toBeNull();

    // 2. Gofile 1-Slab 1-Identity Unlinkability: 同一インスタンスで2回異なる Slab を取得しても、Slab (folderCode) ごとに独立した使い捨てゲストトークンを発行すること
    const seenBearerTokens: string[] = [];
    const cluster = new MemoryOverseasLockerCluster();
    const gofileUploader = new GofileLockerAdapter(req => cluster.handleFetch(req));
    const slab1 = sodium.randombytes_buf(chunkBytes);
    const slab2 = sodium.randombytes_buf(chunkBytes);
    const r1 = await gofileUploader.uploadSlab(slab1, 's1.bin');
    const r2 = await gofileUploader.uploadSlab(slab2, 's2.bin');
    expect(r1.deleteToken).not.toBe(r2.deleteToken);

    const gofileDownloader = new GofileLockerAdapter(async (req: Request): Promise<Response> => {
      if (req.url.includes('/download/web/')) {
        seenBearerTokens.push(req.headers.get('Authorization') ?? '');
      }
      return cluster.handleFetch(req);
    });
    await gofileDownloader.fetchSlabRange(r1.downloadUrl, 0, 1023);
    await gofileDownloader.fetchSlabRange(r2.downloadUrl, 0, 1023);
    expect(seenBearerTokens.length).toBe(2);
    expect(seenBearerTokens[0]).toMatch(/^Bearer gftok_guest_/);
    expect(seenBearerTokens[1]).toMatch(/^Bearer gftok_guest_/);
    expect(seenBearerTokens[0]).not.toBe(seenBearerTokens[1]);

    // 3. 2-Hop Onion + 30-Day Coarse Epoch Blinding: マニフェストの createdAtDay が 30 日単位に丸められていること
    const coordinator = new OverseasMultiLockerCoordinator({
      manifestStore: memoryManifestStore(),
      adapters: [new CatboxLockerAdapter(req => cluster.handleFetch(req))],
      chunkBytes,
      targetBatchChunks: 4,
    });
    const uploaded = await coordinator.uploadFile({
      fileName: 'blinded-timestamp.txt',
      mimeType: 'text/plain',
      fileData: sodium.randombytes_buf(1024),
    });
    const downloaded = await coordinator.downloadFile(uploaded.linkText);
    expect(downloaded).not.toBeNull();
    expect(downloaded!.manifest.createdAtDay % 30).toBe(0);
  });
});

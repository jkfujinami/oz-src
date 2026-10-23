/**
 * Ozzy v0.2 全ステップ (Step 1〜Step 4) 統合テスト & セキュリティ監査テストスイート:
 *   - Step 1: 均一 4 MiB チャンク暗号化、Reed-Solomon (16, 32) パリティ生成・任意 16 シェアからの完全復元、
 *             Split-Key KDF (K_enc / K_tag / K_loc / K_lease)、OzzyManifestV2、[[ozzy:v2:...]] リンク
 *   - Step 2: Cloudflare R2 Gatekeeper Worker (Manifest 10% 保護プール隔離、4段階退避アルゴリズム、
 *             未取得スパムチャンクの優先パージ、ホットデータ 409 スピルオーバー保護、HTTP Range GET、自律 TOUCH、
 *             Denial-of-Wallet Class A/B ハードキャップ)
 *   - Step 3: CloudLeaseSet URL 封印 & ヤドカリ型昇格 (Hermit-Crab Migration)、クラウド事業者多様性キャップ (12/32)、
 *             ジャーナリスト向け無記名招待券 (OZ_VOUCHER)、2層 Onion 要求カプセル化、オンメモリアリーナ即時ゼロクリア、
 *             32 プロバイダ並列 Upload / 18 並列 Fetcher Download エンドツーエンドパイプライン
 */
import { describe, expect, it } from 'vitest';
import sodium, { sodiumReady } from '../src/crypto/sodium';
import {
  CloudLeaseSetStore,
  MemoryR2Bucket,
  OZZY_CHUNK_BYTES,
  OZZY_MANIFEST_POOL_SLOTS,
  OZZY_MAX_SHARES_PER_BACKEND,
  OZZY_RS_K,
  OZZY_RS_N,
  OZZY_TOTAL_SLOTS,
  OzzyGatekeeperWorker,
  OzzyParallelTransferCoordinator,
  OzzyTierMode,
  RamChunkArena,
  computeCandidateSlots,
  computeChunkTag,
  createProviderLeaseSet,
  createSlabLeaseSet,
  decodeManifestFromStripeChunks,
  decodeStripeFromChunks,
  deriveOzzyKeys,
  deriveStripeSeed,
  encodeManifestToStripeChunks,
  encryptStripeDataChunks,
  extractOzzyLinksFromText,
  formatOzzyLink,
  formatOzzyVoucherToken,
  generateOzzySeed,
  generateStripeParityChunks,
  isSafeExternalHttpsUrl,
  issueUploadVoucher,
  generateMemberKeypair,
  parseOzzyLink,
  parseOzzyVoucherToken,
  selectStripeProviders,
  signChunkWithVoucher,
  unsealSlabEndpoint,
  verifyChunkVoucherProof,
  type OzzyManifestV2,
} from '../src/ozzy';

describe('Ozzy v0.2 Step 1: 4 MiB Uniform Chunks, RS(16,32), Split-Key KDF & Manifest v2', () => {
  it('derives strictly separated Split-Keys (K_enc, K_tag, K_loc, K_lease) and isolates Manifest vs Data slot pools', async () => {
    await sodiumReady;
    const seed = await generateOzzySeed();
    const keys = await deriveOzzyKeys(seed);

    expect(keys.kEnc.length).toBe(32);
    expect(keys.kTag.length).toBe(32);
    expect(keys.kLoc.length).toBe(32);
    expect(keys.kLease.length).toBe(32);

    // 4 つの鍵が互いに完全に異なることを確認
    expect(Buffer.from(keys.kEnc).equals(Buffer.from(keys.kLease))).toBe(false);
    expect(Buffer.from(keys.kTag).equals(Buffer.from(keys.kLoc))).toBe(false);

    // Manifest 候補スロットは必ず 0..229 (先頭 10%) に収まり、互いに異なる 4 スロットである
    for (let j = 0; j < OZZY_RS_N; j++) {
      const mSlots = computeCandidateSlots(keys.kLoc, 0xffffffff, j, true);
      expect(new Set(mSlots).size).toBe(4);
      for (const s of mSlots) {
        expect(s).toBeGreaterThanOrEqual(0);
        expect(s).toBeLessThan(OZZY_MANIFEST_POOL_SLOTS);
      }

      // 通常データチャンクの候補スロットは必ず 230..2303 (残り 90%) に収まる
      const dSlots = computeCandidateSlots(keys.kLoc, 0, j, false);
      expect(new Set(dSlots).size).toBe(4);
      for (const s of dSlots) {
        expect(s).toBeGreaterThanOrEqual(OZZY_MANIFEST_POOL_SLOTS);
        expect(s).toBeLessThan(OZZY_TOTAL_SLOTS);
      }
    }
  });

  it('encrypts a full 4 MiB chunk and verifies exact 4,194,304 byte uniformity', async () => {
    await sodiumReady;
    const seed = await generateOzzySeed();
    const keys = await deriveOzzyKeys(seed);
    // 端数サイズの平文 (123,456 bytes) でも、出力される全 16 データチャンクが厳密に 4 MiB (4,194,304 B) になることを検証
    const oddPlaintext = sodium.randombytes_buf(123_456);
    const dataChunks = await encryptStripeDataChunks(oddPlaintext, 0, keys, OZZY_CHUNK_BYTES);

    expect(dataChunks.length).toBe(OZZY_RS_K);
    for (const c of dataChunks) {
      expect(c.rawChunk.byteLength).toBe(OZZY_CHUNK_BYTES); // 4,194,304 bytes exact!
    }
  });

  it('encodes (16, 32) Reed-Solomon parity without K_enc (PARITY_JOB) and reconstructs when any 16 of 32 chunks are lost', async () => {
    await sodiumReady;
    const seed = await generateOzzySeed();
    const keys = await deriveOzzyKeys(seed);
    const testChunkBytes = 64 * 1024;
    const plain = sodium.randombytes_buf(350_000);

    // 1. Uploader が 16 個のデータチャンクのみ暗号化
    const dataChunks = await encryptStripeDataChunks(plain, 7, keys, testChunkBytes);
    // 2. Parity-Helper が K_enc を知らない状態 (kTag のみ) でパリティ 16 個を生成
    const parityChunks = generateStripeParityChunks(dataChunks, 7, keys.kTag);
    const all32Chunks = [...dataChunks, ...parityChunks];
    expect(all32Chunks.length).toBe(OZZY_RS_N);

    // 3. データチャンクのうち 12 個 (share 0..11) とパリティ 4 個 (share 16..19) が消失した過酷なケース (残り 16 個のみ生存)
    const surviving16 = [
      ...all32Chunks.slice(12, 16), // データ 4 個
      ...all32Chunks.slice(20, 32), // パリティ 12 個
    ];
    expect(surviving16.length).toBe(16);

    const recovered = await decodeStripeFromChunks(surviving16, 7, keys, testChunkBytes);
    expect(recovered).not.toBeNull();
    expect(Buffer.from(recovered!).equals(Buffer.from(plain))).toBe(true);

    // 4. 15 個しか生存していない場合は復元不能 (null)
    const only15 = surviving16.slice(0, 15);
    expect(await decodeStripeFromChunks(only15, 7, keys, testChunkBytes)).toBeNull();
  });

  it('encodes and decodes OzzyManifestV2 and parses [[ozzy:v2:...]] links', async () => {
    await sodiumReady;
    const manifestSeed = await generateOzzySeed();
    const stripe0Seed = await deriveStripeSeed(manifestSeed, 0);
    const stripe1Seed = await deriveStripeSeed(manifestSeed, 1);

    const manifest: OzzyManifestV2 = {
      version: 2,
      flags: 0,
      totalFileSize: 10 * 1024 * 1024 * 1024, // 10 GiB
      createdAtDay: 20743,
      fileHash: sodium.randombytes_buf(32),
      fileName: 'whistleblower_evidence_2026.mp4',
      mimeType: 'video/mp4',
      stripes: [
        {
          stripeSeed: stripe0Seed,
          tierMode: OzzyTierMode.Tier1Ring,
          leaseSetId: new Uint8Array(16),
          slabStartChunkIdx: 0,
          shareDigests: sodium.randombytes_buf(512),
        },
        {
          stripeSeed: stripe1Seed,
          tierMode: OzzyTierMode.Tier2Slab,
          leaseSetId: sodium.randombytes_buf(16),
          slabStartChunkIdx: 16,
          shareDigests: sodium.randombytes_buf(512),
        },
      ],
    };

    const testChunkBytes = 32 * 1024;
    const manifestChunks = await encodeManifestToStripeChunks(manifest, manifestSeed, testChunkBytes);
    const oddShares = manifestChunks.filter((_, idx) => idx % 2 === 1);
    const decoded = await decodeManifestFromStripeChunks(oddShares, manifestSeed, testChunkBytes);

    expect(decoded).not.toBeNull();
    expect(decoded!.fileName).toBe('whistleblower_evidence_2026.mp4');
    expect(decoded!.totalFileSize).toBe(10 * 1024 * 1024 * 1024);
    expect(decoded!.stripes.length).toBe(2);
    expect(decoded!.stripes[1].tierMode).toBe(OzzyTierMode.Tier2Slab);

    const linkStr = formatOzzyLink({
      manifestSeed,
      totalFileSize: manifest.totalFileSize,
      flags: manifest.flags,
    });
    const extracted = extractOzzyLinksFromText(`極秘資料を送ります: ${linkStr} 確認後破棄してください。`);
    expect(extracted.length).toBe(1);
    expect(extracted[0].link.totalFileSize).toBe(10 * 1024 * 1024 * 1024);
    expect(Buffer.from(extracted[0].link.manifestSeed).equals(Buffer.from(manifestSeed))).toBe(true);
    expect(parseOzzyLink('[[ozzy:v2:invalid_token]]')).toBeNull();
  });
});

describe('Ozzy v0.2 Step 2: Cloudflare R2 Gatekeeper Worker (Eviction, Range GET, TOUCH & DoW Cap)', () => {
  it('enforces Manifest (0..229) vs Data (230..2303) pool isolation, Range GET, and autonomous TOUCH', async () => {
    await sodiumReady;
    const testChunkBytes = 16 * 1024;
    const bucket = new MemoryR2Bucket();
    const worker = new OzzyGatekeeperWorker(bucket, { expectedChunkBytes: testChunkBytes });

    const seed = await generateOzzySeed();
    const keys = await deriveOzzyKeys(seed);
    const tag = computeChunkTag(keys.kTag, 0, 0);
    const tagHex = Buffer.from(tag).toString('hex');

    const chunkPayload = sodium.randombytes_buf(testChunkBytes);
    chunkPayload.set(tag, 0);

    // 1. 通常データチャンクが Manifest 保護プール (0..229) に書き込もうとすると 403 で拒否される
    const forbiddenRes = await worker.handleFetch(
      new Request('https://worker.example/ozzy/v2/chunk', {
        method: 'PUT',
        headers: {
          'X-Ozzy-Pool': 'data',
          'X-Ozzy-Candidates': '10,20,30,40',
        },
        body: Buffer.from(chunkPayload),
      }),
    );
    expect(forbiddenRes.status).toBe(403);

    // 2. データプール (230..2303) への正規 PUT は 200 OK
    const day0Ms = 20000 * 86_400_000;
    const putRes = await worker.handleFetch(
      new Request('https://worker.example/ozzy/v2/chunk', {
        method: 'PUT',
        headers: {
          'X-Ozzy-Pool': 'data',
          'X-Ozzy-Candidates': '300,301,302,303',
          'X-Ozzy-TTL-Days': '90',
        },
        body: Buffer.from(chunkPayload),
      }),
      day0Ms,
    );
    expect(putRes.status).toBe(200);
    const putJson = (await putRes.json()) as { slotId: number };
    expect(putJson.slotId).toBe(300);

    // 3. HTTP Range GET (先頭 1024 バイトのみ切り出し) と自律 TOUCH の検証
    const day10Ms = (20000 + 10) * 86_400_000;
    const getRes = await worker.handleFetch(
      new Request(`https://worker.example/ozzy/v2/chunk?candidates=300,301,302,303&tag=${tagHex}`, {
        method: 'GET',
        headers: {
          Range: 'bytes=0-1023',
        },
      }),
      day10Ms,
    );
    expect(getRes.status).toBe(206);
    expect(getRes.headers.get('Content-Range')).toBe(`bytes 0-1023/${testChunkBytes}`);
    const rangeSlice = new Uint8Array(await getRes.arrayBuffer());
    expect(rangeSlice.byteLength).toBe(1024);
    expect(Buffer.from(rangeSlice).equals(Buffer.from(chunkPayload.subarray(0, 1024)))).toBe(true);
  });

  it('evicts unfetched spam chunks before fetched hot chunks, and returns 409 SLOT_HOT_FULL when all 4 candidates are hot', async () => {
    await sodiumReady;
    const testChunkBytes = 4096;
    const bucket = new MemoryR2Bucket();
    const worker = new OzzyGatekeeperWorker(bucket, { expectedChunkBytes: testChunkBytes });
    const nowMs = 20000 * 86_400_000;

    const makeChunk = (fillByte: number) => {
      const buf = new Uint8Array(testChunkBytes);
      buf.fill(fillByte);
      return buf;
    };

    for (let i = 0; i < 4; i++) {
      const c = makeChunk(0x10 + i);
      const res = await worker.handleFetch(
        new Request('https://worker.example/ozzy/v2/chunk', {
          method: 'PUT',
          headers: {
            'X-Ozzy-Pool': 'data',
            'X-Ozzy-Candidates': '500,501,502,503',
          },
          body: Buffer.from(c),
        }),
        nowMs,
      );
      expect(res.status).toBe(200);
    }

    for (let i = 0; i < 3; i++) {
      const tagHex = Buffer.from(makeChunk(0x10 + i).subarray(0, 16)).toString('hex');
      const g = await worker.handleFetch(
        new Request(`https://worker.example/ozzy/v2/chunk?candidates=500,501,502,503&tag=${tagHex}`),
        nowMs,
      );
      expect(g.status).toBe(200);
    }

    const chunk5 = makeChunk(0x99);
    const put5 = await worker.handleFetch(
      new Request('https://worker.example/ozzy/v2/chunk', {
        method: 'PUT',
        headers: {
          'X-Ozzy-Pool': 'data',
          'X-Ozzy-Candidates': '500,501,502,503',
        },
        body: Buffer.from(chunk5),
      }),
      nowMs,
    );
    expect(put5.status).toBe(200);
    const put5Json = (await put5.json()) as { slotId: number; evictionReason: string };
    expect(put5Json.slotId).toBe(503);
    expect(put5Json.evictionReason).toBe('unfetched');

    const tag5Hex = Buffer.from(chunk5.subarray(0, 16)).toString('hex');
    await worker.handleFetch(
      new Request(`https://worker.example/ozzy/v2/chunk?candidates=500,501,502,503&tag=${tag5Hex}`),
      nowMs,
    );

    const chunk6 = makeChunk(0xaa);
    const put6 = await worker.handleFetch(
      new Request('https://worker.example/ozzy/v2/chunk', {
        method: 'PUT',
        headers: {
          'X-Ozzy-Pool': 'data',
          'X-Ozzy-Candidates': '500,501,502,503',
        },
        body: Buffer.from(chunk6),
      }),
      nowMs,
    );
    expect(put6.status).toBe(409);
  });
});

describe('Ozzy v0.2 Step 3: CloudLeaseSet, Hermit-Crab Migration, OZ_VOUCHER & Parallel P2P Coordinator', () => {
  it('seals SlabLeaseSet URLs with K_lease, enforces Provider Diversity Cap (max 12 per backend), and supports Hermit-Crab Migration', async () => {
    await sodiumReady;
    const seed = await generateOzzySeed();
    const keys = await deriveOzzyKeys(seed);
    const wrongKeys = await deriveOzzyKeys(await generateOzzySeed());
    const nowSec = Math.floor(Date.now() / 1000);

    const store = new CloudLeaseSetStore();

    // 1. ヤドカリ移設 (Hermit-Crab Migration): 世代 1 (GigaFile) -> 世代 2 (Gofile) を登録しても同じリンク (K_lease) から両方開封可能
    const leaseV1 = await createSlabLeaseSet({
      kLease: keys.kLease,
      slabChunkCount: 16,
      migrationSeq: 1,
      expiresAtSec: nowSec + 3600,
      endpoint: {
        lockerId: 'gigafile',
        downloadUrl: 'https://42.gigafile.nu/download/slab1',
        authToken: 'dlkey1',
        supportsRange: true,
      },
    });
    const leaseV2 = await createSlabLeaseSet({
      kLease: keys.kLease,
      slabChunkCount: 16,
      migrationSeq: 2,
      expiresAtSec: nowSec + 86400 * 30,
      endpoint: {
        lockerId: 'gofile',
        downloadUrl: 'https://store9.gofile.io/download/slab1_migrated',
        authToken: 'dlkey2',
        supportsRange: true,
      },
    });

    expect(await store.upsertSlab(leaseV1, nowSec)).toBe(true);
    expect(await store.upsertSlab(leaseV2, nowSec)).toBe(true);

    const activeLeases = store.getSlabLeases(leaseV1.leaseSetId, nowSec);
    expect(activeLeases.length).toBe(2);
    expect(activeLeases[0].migrationSeq).toBe(2); // 最新世代が先頭

    // 正しい K_lease なら開封成功、無関係な K_lease なら null (URL 秘匿の証明)
    const unsealed = await unsealSlabEndpoint(activeLeases[0], keys.kLease);
    expect(unsealed?.lockerId).toBe('gofile');
    expect(await unsealSlabEndpoint(activeLeases[0], wrongKeys.kLease)).toBeNull();

    // 2. クラウド事業者多様性キャップ (Provider Diversity Cap: 同一バックエンド最大 12 / 32) の検証
    // Cloudflare R2 × 25 台, Backblaze B2 × 15 台, Oracle S3 × 15 台 (計 55 台) を登録
    const backends = [
      ...Array(25).fill('cloudflare-r2'),
      ...Array(15).fill('backblaze-b2'),
      ...Array(15).fill('oracle-s3'),
    ];
    for (let i = 0; i < backends.length; i++) {
      const kp = sodium.crypto_sign_keypair();
      const pl = await createProviderLeaseSet({
        providerPubKey: kp.publicKey,
        providerPrivKey: kp.privateKey,
        endpoint: {
          workerUrl: `https://p-${i}.example`,
          backendId: backends[i],
          authToken: 'tok',
        },
        expiresAtSec: nowSec + 86400,
        freeDataSlots: 2074,
      });
      await store.upsertProvider(pl, nowSec);
    }

    const selected32 = selectStripeProviders(keys.kLoc, 0, store.getActiveProviders(nowSec), OZZY_RS_N);
    expect(selected32.length).toBe(32);

    const countByBackend = new Map<string, number>();
    for (const p of selected32) {
      countByBackend.set(p.backendId, (countByBackend.get(p.backendId) ?? 0) + 1);
    }
    // どのクラウド事業者も 1 ストライプにつき最大 12 チャンク以下に厳格制限されていることを確認!
    for (const [, count] of countByBackend) {
      expect(count).toBeLessThanOrEqual(OZZY_MAX_SHARES_PER_BACKEND);
    }
  });

  it('mints and verifies Journalist Anonymous Upload Vouchers (OZ_VOUCHER) for Guest whistleblowers', async () => {
    await sodiumReady;
    const members = await Promise.all(Array.from({ length: 8 }, () => generateMemberKeypair()));
    const journalist = members[3];
    const today = 20743;
    const roster = new Set(members.map(m => Buffer.from(m.publicKey).toString('hex')));

    const voucher = await issueUploadVoucher({
      member: journalist,
      ring: members.map(m => m.publicKey),
      validStartDay: today,
      validDays: 14,
      maxChunks: 4096, // 16 GiB
    });

    const tokenStr = formatOzzyVoucherToken(voucher);
    const parsed = parseOzzyVoucherToken(tokenStr);
    expect(parsed).not.toBeNull();
    expect(parsed!.maxChunks).toBe(4096);

    const chunkTag = sodium.randombytes_buf(16);
    const proofHeader = await signChunkWithVoucher(parsed!, chunkTag);

    const verified = await verifyChunkVoucherProof(proofHeader, chunkTag, today + 3, roster);
    expect(verified.ok).toBe(true);

    // ★ 証明のどこにも、発行したジャーナリストを特定するものは無い (リング 8 人のうち誰かとしか分からない)。
    //   公開鍵はリングとして 8 人分並ぶだけで、発行者の位置も印も無い
    const raw = Buffer.from(proofHeader.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    const ringStart = raw.indexOf(Buffer.from(members.map(m => m.publicKey).sort(Buffer.compare)[0]));
    expect(ringStart).toBeGreaterThan(0);
    // 同じ日の別の招待券は同じキーイメージ (使い過ぎを数えられる)、別の日なら別のキーイメージ (結び付かない)
    const sameDay = await issueUploadVoucher({ member: journalist, ring: members.map(m => m.publicKey), validStartDay: today, maxChunks: 10 });
    const nextDay = await issueUploadVoucher({ member: journalist, ring: members.map(m => m.publicKey), validStartDay: today + 1, maxChunks: 10 });
    expect(Buffer.from(sameDay.keyImage).equals(Buffer.from(voucher.keyImage))).toBe(true);
    expect(Buffer.from(nextDay.keyImage).equals(Buffer.from(voucher.keyImage))).toBe(false);
    // 別のメンバーが同じ日に出した招待券のキーイメージは違う
    const other = await issueUploadVoucher({ member: members[0], ring: members.map(m => m.publicKey), validStartDay: today });
    expect(Buffer.from(other.keyImage).equals(Buffer.from(voucher.keyImage))).toBe(false);

    // 異なるチャンク tag に使い回そうとしても署名検証で拒否される
    const wrongTag = sodium.randombytes_buf(16);
    const wrongVerify = await verifyChunkVoucherProof(proofHeader, wrongTag, today + 3, roster);
    expect(wrongVerify.ok).toBe(false);

    // 有効期限切れ後は拒否される
    const expiredVerify = await verifyChunkVoucherProof(proofHeader, chunkTag, today + 30, roster);
    expect(expiredVerify.ok).toBe(false);

    // 名簿にいない鍵をリングに混ぜた招待券・リングが小さすぎる招待券は拒否される
    const outsider = await generateMemberKeypair();
    const forged = await issueUploadVoucher({ member: outsider, ring: members.map(m => m.publicKey), validStartDay: today });
    expect(await verifyChunkVoucherProof(await signChunkWithVoucher(forged, chunkTag), chunkTag, today, roster)).toMatchObject({ ok: false, reason: 'unknown_ring_member' });
    const tiny = await issueUploadVoucher({ member: journalist, ring: [members[0].publicKey], validStartDay: today });
    expect(await verifyChunkVoucherProof(await signChunkWithVoucher(tiny, chunkTag), chunkTag, today, roster)).toMatchObject({ ok: false, reason: 'ring_too_small' });

    // リング署名を 1 ビットでも変えれば拒否される
    const tampered = { ...voucher, maxChunks: 65535 };
    expect(await verifyChunkVoucherProof(await signChunkWithVoucher(tampered, chunkTag), chunkTag, today, roster)).toMatchObject({ ok: false, reason: 'invalid_ring_signature' });
  });

  it('executes full end-to-end multi-stripe upload & 2-layer Onion parallel download across 32 R2 Workers with RAM zeroization', async () => {
    await sodiumReady;
    const testChunkBytes = 8 * 1024; // 8 KiB × 16 = 128 KiB / stripe
    const leaseStore = new CloudLeaseSetStore();
    const workers = new Map<string, OzzyGatekeeperWorker>();
    const nowSec = Math.floor(Date.now() / 1000);
    const backends = ['cloudflare-r2', 'backblaze-b2', 'oracle-s3'];

    for (let i = 0; i < OZZY_RS_N; i++) {
      const kp = sodium.crypto_sign_keypair();
      const workerUrl = `https://r2-node-${i}.ozzy.test`;
      workers.set(workerUrl, new OzzyGatekeeperWorker(new MemoryR2Bucket(), { expectedChunkBytes: testChunkBytes }));
      const lease = await createProviderLeaseSet({
        providerPubKey: kp.publicKey,
        providerPrivKey: kp.privateKey,
        endpoint: { workerUrl, backendId: backends[i % 3], authToken: 't' },
        expiresAtSec: nowSec + 86400,
        freeDataSlots: 2074,
      });
      await leaseStore.upsertProvider(lease, nowSec);
    }

    // 32 台のうち 8 台のワーカーが障害・オフラインになった状況をシミュレートしても RS(16,32) で無傷で復元できることを検証!
    let simulateOfflineNodes = false;
    const coordinator = new OzzyParallelTransferCoordinator(
      leaseStore,
      async (workerUrl, req) => {
        if (simulateOfflineNodes && /r2-node-[0-5]\./.test(workerUrl) && req.method === 'GET') {
          return new Response('Offline', { status: 503 });
        }
        const w = workers.get(workerUrl);
        if (!w) return new Response('Not Found', { status: 404 });
        return w.handleFetch(req);
      },
      testChunkBytes,
    );

    // 複数ストライプ (3 ストライプ分 = 300 KiB) の元ファイルを生成
    const originalFile = sodium.randombytes_buf(300 * 1024);
    const uploadRes = await coordinator.uploadFile({
      fileData: originalFile,
      fileName: 'confidential_db_dump.sql.gz',
      mimeType: 'application/gzip',
    });

    expect(uploadRes.manifest.stripes.length).toBe(3);
    expect(uploadRes.linkText.startsWith('[[ozzy:v2:')).toBe(true);

    // 中継完了後、オンメモリアリーナのアクティブスロットは 0
    expect(coordinator.arena.stats.activeSlots).toBe(0);

    // 一部ノードがオフライン化した状態でリンクから並列ダウンロードを実行
    simulateOfflineNodes = true;
    const parsedLink = parseOzzyLink(uploadRes.linkText)!;
    const downloadRes = await coordinator.downloadFile(parsedLink);

    expect(downloadRes).not.toBeNull();
    expect(downloadRes!.manifest.fileName).toBe('confidential_db_dump.sql.gz');
    expect(Buffer.from(downloadRes!.data).equals(Buffer.from(originalFile))).toBe(true);
    expect(coordinator.arena.stats.activeSlots).toBe(0);
  });
});

describe('Ozzy v0.2 Security Audit & Hardening Suite', () => {
  it('[Audit #1 & #2] enforces OZ_VOUCHER per-chunk tag binding, member roster check, and maxChunks quota cap on GatekeeperWorker', async () => {
    await sodiumReady;
    const testChunkBytes = 4096;
    const members = await Promise.all(Array.from({ length: 4 }, () => generateMemberKeypair()));
    const journalist = members[1];
    const attacker = await generateMemberKeypair();
    const today = 20743;
    const nowMs = today * 86_400_000;

    const roster = new Set(members.map(m => Buffer.from(m.publicKey).toString('hex')));
    const worker = new OzzyGatekeeperWorker(new MemoryR2Bucket(), {
      expectedChunkBytes: testChunkBytes,
      requireQuotaProof: true,
      activeMemberRoster: roster,
    });

    // maxChunks = 2 の招待券を発行 (リング = 名簿の 4 人)
    const validVoucher = await issueUploadVoucher({
      member: journalist,
      ring: members.map(m => m.publicKey),
      validStartDay: today,
      validDays: 7,
      maxChunks: 2,
    });

    const chunk1 = sodium.randombytes_buf(testChunkBytes);
    const chunk2 = sodium.randombytes_buf(testChunkBytes);
    const chunk3 = sodium.randombytes_buf(testChunkBytes);

    // 1. クォータ証明なしの PUT は 401 QUOTA_PROOF_REQUIRED で拒否
    const noProofRes = await worker.handleFetch(
      new Request('https://worker.example/ozzy/v2/chunk', {
        method: 'PUT',
        headers: { 'X-Ozzy-Pool': 'data', 'X-Ozzy-Candidates': '300,301,302,303' },
        body: Buffer.from(chunk1),
      }),
      nowMs,
    );
    expect(noProofRes.status).toBe(401);

    // 2. chunk1 用に署名された証明を chunk2 の PUT にリプレイ流用しようとすると 403 tag_mismatch で拒否
    const proof1 = await signChunkWithVoucher(validVoucher, chunk1.subarray(0, 16));
    const replayRes = await worker.handleFetch(
      new Request('https://worker.example/ozzy/v2/chunk', {
        method: 'PUT',
        headers: {
          'X-Ozzy-Pool': 'data',
          'X-Ozzy-Candidates': '300,301,302,303',
          'X-Ozzy-Quota-Proof': proof1,
        },
        body: Buffer.from(chunk2),
      }),
      nowMs,
    );
    expect(replayRes.status).toBe(403);

    // 3. 非メンバー (attackerKp) が署名した偽造招待券は 403 unknown_sponsor_member で拒否
    const forgedVoucher = await issueUploadVoucher({
      member: attacker,
      ring: members.map(m => m.publicKey),
      validStartDay: today,
      maxChunks: 100,
    });
    const forgedProof = await signChunkWithVoucher(forgedVoucher, chunk1.subarray(0, 16));
    const forgedRes = await worker.handleFetch(
      new Request('https://worker.example/ozzy/v2/chunk', {
        method: 'PUT',
        headers: {
          'X-Ozzy-Pool': 'data',
          'X-Ozzy-Candidates': '300,301,302,303',
          'X-Ozzy-Quota-Proof': forgedProof,
        },
        body: Buffer.from(chunk1),
      }),
      nowMs,
    );
    expect(forgedRes.status).toBe(403);

    // 4. 正しい証明付きの chunk1, chunk2 (計 2 チャンク <= maxChunks) は 200 OK
    const ok1 = await worker.handleFetch(
      new Request('https://worker.example/ozzy/v2/chunk', {
        method: 'PUT',
        headers: {
          'X-Ozzy-Pool': 'data',
          'X-Ozzy-Candidates': '300,301,302,303',
          'X-Ozzy-Quota-Proof': proof1,
        },
        body: Buffer.from(chunk1),
      }),
      nowMs,
    );
    expect(ok1.status).toBe(200);

    const proof2 = await signChunkWithVoucher(validVoucher, chunk2.subarray(0, 16));
    const ok2 = await worker.handleFetch(
      new Request('https://worker.example/ozzy/v2/chunk', {
        method: 'PUT',
        headers: {
          'X-Ozzy-Pool': 'data',
          'X-Ozzy-Candidates': '300,301,302,303',
          'X-Ozzy-Quota-Proof': proof2,
        },
        body: Buffer.from(chunk2),
      }),
      nowMs,
    );
    expect(ok2.status).toBe(200);

    // 5. 3 個目の異なるチャンク (chunk3) は maxChunks=2 を超過するため 429 VOUCHER_QUOTA_EXCEEDED で拒否
    const proof3 = await signChunkWithVoucher(validVoucher, chunk3.subarray(0, 16));
    const overQuotaRes = await worker.handleFetch(
      new Request('https://worker.example/ozzy/v2/chunk', {
        method: 'PUT',
        headers: {
          'X-Ozzy-Pool': 'data',
          'X-Ozzy-Candidates': '300,301,302,303',
          'X-Ozzy-Quota-Proof': proof3,
        },
        body: Buffer.from(chunk3),
      }),
      nowMs,
    );
    expect(overQuotaRes.status).toBe(429);
  });

  it('[Audit #3] blocks SSRF URLs (localhost, 127.0.0.1, 169.254.169.254 metadata, private IPs, non-HTTPS) in CloudLeaseSet', async () => {
    await sodiumReady;
    expect(isSafeExternalHttpsUrl('https://r2-node.ozzy.workers.dev')).toBe(true);
    expect(isSafeExternalHttpsUrl('https://42.gigafile.nu/dl')).toBe(true);

    // SSRF 危険 URL はすべて拒否されることを検証
    expect(isSafeExternalHttpsUrl('http://r2-node.ozzy.workers.dev')).toBe(false);
    expect(isSafeExternalHttpsUrl('https://localhost:8080/ozzy')).toBe(false);
    expect(isSafeExternalHttpsUrl('https://sub.localhost/ozzy')).toBe(false);
    expect(isSafeExternalHttpsUrl('https://127.0.0.1/ozzy')).toBe(false);
    expect(isSafeExternalHttpsUrl('https://169.254.169.254/latest/meta-data/')).toBe(false);
    expect(isSafeExternalHttpsUrl('https://10.0.0.1/internal')).toBe(false);
    expect(isSafeExternalHttpsUrl('https://172.16.0.5/internal')).toBe(false);
    expect(isSafeExternalHttpsUrl('https://192.168.1.1/admin')).toBe(false);
    expect(isSafeExternalHttpsUrl('https://[::1]/ozzy')).toBe(false);
    expect(isSafeExternalHttpsUrl('https://user:pass@r2-node.ozzy.workers.dev')).toBe(false);

    const kp = sodium.crypto_sign_keypair();
    await expect(
      createProviderLeaseSet({
        providerPubKey: kp.publicKey,
        providerPrivKey: kp.privateKey,
        endpoint: {
          workerUrl: 'https://169.254.169.254/latest/meta-data',
          backendId: 'cloudflare-r2',
          authToken: 't',
        },
        expiresAtSec: Math.floor(Date.now() / 1000) + 3600,
        freeDataSlots: 2000,
      }),
    ).rejects.toThrow();
  });

  it('[Audit #4] prevents all-zero tag slot-poisoning attacks on uninitialized R2 slots', async () => {
    await sodiumReady;
    const testChunkBytes = 4096;
    const worker = new OzzyGatekeeperWorker(new MemoryR2Bucket(), { expectedChunkBytes: testChunkBytes });
    const nowMs = 20000 * 86_400_000;
    const zeroTagHex = '00'.repeat(16);

    // 1. 未初期化スロット (tag=00..00, expireDay=0) に対して tag=00..00 で TOUCH を送り、空スロットを不正にホットロックしようとする攻撃を阻止
    const touchZeroRes = await worker.handleFetch(
      new Request('https://worker.example/ozzy/v2/touch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ candidates: [230, 231, 232, 233], tag: zeroTagHex }),
      }),
      nowMs,
    );
    expect(touchZeroRes.status).toBe(400);

    // 2. 先頭 16B がオールゼロのチャンク PUT も 400 ZERO_TAG_FORBIDDEN で拒否
    const zeroTagChunk = new Uint8Array(testChunkBytes);
    const putZeroRes = await worker.handleFetch(
      new Request('https://worker.example/ozzy/v2/chunk', {
        method: 'PUT',
        headers: { 'X-Ozzy-Pool': 'data', 'X-Ozzy-Candidates': '230,231,232,233' },
        body: Buffer.from(zeroTagChunk),
      }),
      nowMs,
    );
    expect(putZeroRes.status).toBe(400);
  });

  it('[Audit #5] survives Byzantine corrupted data chunks (valid 16B tag but tampered encrypted body) by pre-verifying AEAD MAC and falling back to parity shares', async () => {
    await sodiumReady;
    const testChunkBytes = 4096;
    const seed = await generateOzzySeed();
    const keys = await deriveOzzyKeys(seed);
    const plain = sodium.randombytes_buf(32 * 1024);

    const dataChunks = await encryptStripeDataChunks(plain, 0, keys, testChunkBytes);
    const parityChunks = generateStripeParityChunks(dataChunks, 0, keys.kTag);
    const allChunks = [...dataChunks, ...parityChunks];

    // 悪意あるノードがデータシェア 0..3 の先頭 16B tag はそのまま維持し、暗号文 body だけを改ざんした状況を再現
    const byzantineSet = allChunks.slice(0, 20).map(c => {
      if (c.shareIndex < 4) {
        const corrupted = new Uint8Array(c.rawChunk);
        corrupted[100] ^= 0xff; // tag(0..15) は正しいまま body を改ざん
        return { shareIndex: c.shareIndex, rawChunk: corrupted };
      }
      return { shareIndex: c.shareIndex, rawChunk: c.rawChunk };
    });

    // 0..3 の改ざんデータシェア (4個) が AEAD 先行検証で自動排除され、16..19 のパリティシェアを使って無傷で復元成功!
    const recovered = await decodeStripeFromChunks(byzantineSet, 0, keys, testChunkBytes);
    expect(recovered).not.toBeNull();
    expect(Buffer.from(recovered!).equals(Buffer.from(plain))).toBe(true);
  });
});

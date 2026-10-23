import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import sodium, { sodiumReady } from '../src/crypto/sodium';
import { Encoding } from '../src/common/Encoding';
import { createSimNode, link, startAll, stopAll, sleep, type SimNode } from './helpers/onionNet';
import { hasSubarray, randBytes } from './helpers/fileNet';
import { WireType } from '../src/network/wire/WireTypes';
import {
  CatboxLockerAdapter,
  CloudLeaseSetStore,
  GofileLockerAdapter,
  createLockerRangeFetch,
  MemoryOverseasLockerCluster,
  OZZY_MESH_STATUS,
  OverseasMultiLockerCoordinator,
  OzzyMeshFetcher,
  OzzyOnionExit,
  OzzyOnionReplyRelay,
  OzzyRangeServer,
  OzzySlabReader,
  PixeldrainLockerAdapter,
  PomfLockerAdapter,
  ZeroXZeroLockerAdapter,
  computeChunkTag,
  createHttpRangeFetch,
  createSlabLeaseSet,
  decodeRangeResponse,
  decodeStripeFromChunks,
  deriveLeaseSignKeypair,
  deriveOzzyKeys,
  encodeFullStripe,
  encodeRangeRequest,
  generateOzzySeed,
  isAllowedOzzyFetchUrl,
  leaseSetIdFromSignPubKey,
  memoryManifestStore,
  parseOzzyLinkV3,
  serializeOzzyManifestV4,
  verifySlabLeaseSet,
  computeStripeShareDigests,
  type OzzyManifestStore,
  type OzzyRangeFetchFn,
  type SlabLeaseSet,
  OnionLockerAdapter,
  OZZY_JOB_LOCKERS,
  OZZY_ONION_JOB_KIND,
  OZZY_UP_PIECE_BYTES,
  createLockerJobRunner,
  createOnionLockerAdapters,
  decodeLockerJob,
  encodeLockerJob,
  type OzzyLockerJob,
  type OzzyLockerJobRunner,
} from '../src/ozzy';

/**
 * Ozzy のメッシュ取得: 読み手 r の要求をオニオン回路 (r → Guard g → M1) で運び、M1 がロッカーから取って g 経由で返す。
 * 本物の PeerManager・WireCodec・OnionCircuit (cover と同じ送出枠・3 枠ごとの M1 の交代) を通す (createSimNode / link)。
 *
 *              m0  m1  m2
 *                \  |  /
 *      r ─── g ─────────        r の隣人は g だけ。M1 の候補は g の隣人 m0..m5 (r の隣人ではない)
 *                /  |  \        全ノードが OzzyOnionExit (M1 の役) と OzzyOnionReplyRelay (Guard の役) を持つ
 *              m3  m4  m5
 */
beforeAll(async () => { await sodiumReady; });

interface MeshNet {
  r: SimNode;
  g: SimNode;
  middles: SimNode[];
  exits: OzzyOnionExit[];
  relays: OzzyOnionReplyRelay[];
  servers: Map<string, OzzyRangeServer>;
  /** M1 が取りに行った URL */
  seen: Map<string, string[]>;
  /** M1 が引き受けたロッカーへの作業 */
  jobs: Map<string, OzzyLockerJob[]>;
  all: SimNode[];
}

let net: MeshNet | null = null;
const fetchers: OzzyMeshFetcher[] = [];
afterEach(() => {
  for (const f of fetchers.splice(0)) f.destroy();
  if (!net) return;
  for (const e of net.exits) e.destroy();
  for (const x of net.relays) x.destroy();
  stopAll(net.all);
  net = null;
});

const CHUNK = 64 * 1024;

/**
 * evil の M1 は tag だけ正しいゴミを返し、disabled の M1 は取得役を止めている (REFUSED)。
 * liar の M1 はアップロードを頼まれると、置かずに「置いた」と嘘の受け取り票を返す。
 */
async function buildMeshNet(
  cluster: MemoryOverseasLockerCluster,
  opts: { n?: number; evil?: ReadonlySet<string>; disabled?: ReadonlySet<string>; liar?: ReadonlySet<string> } = {},
): Promise<MeshNet> {
  const r = await createSimNode('r');
  const g = await createSimNode('g');
  link(r, g);
  const middles: SimNode[] = [];
  for (let i = 0; i < (opts.n ?? 6); i++) {
    const m = await createSimNode(`m${i}`);
    link(g, m);
    middles.push(m);
  }
  const all = [r, g, ...middles];
  const servers = new Map<string, OzzyRangeServer>();
  const seen = new Map<string, string[]>();
  const jobs = new Map<string, OzzyLockerJob[]>();
  const honest = createHttpRangeFetch((req) => cluster.handleFetch(req));
  const honestJobs = createLockerJobRunner((req) => cluster.handleFetch(req));
  const exits: OzzyOnionExit[] = [];
  const relays: OzzyOnionReplyRelay[] = [];
  for (const node of all) {
    let server: OzzyRangeServer | null = null;
    let jobRunner: OzzyLockerJobRunner | null = null;
    if (!opts.disabled?.has(node.name)) {
      const fetchRange: OzzyRangeFetchFn = async (lockerId, url, start, end, signal) => {
        seen.set(node.name, [...(seen.get(node.name) ?? []), url]);
        const got = await honest(lockerId, url, start, end, signal);
        if (opts.evil?.has(node.name) && got instanceof Uint8Array) {
          const bad = randBytes(got.length);
          bad.set(got.subarray(0, 16), 0); // tag だけ本物
          return bad;
        }
        return got;
      };
      server = new OzzyRangeServer({ fetchRange });
      servers.set(node.name, server);
      jobRunner = async (job, body, signal) => {
        jobs.set(node.name, [...(jobs.get(node.name) ?? []), job]);
        if (opts.liar?.has(node.name) && job.op === 'upload') {
          const fake = { lockerId: job.lockerId, slabId: 'x', downloadUrl: 'https://files.catbox.moe/never-uploaded.bin', deleteToken: '', byteLength: body.length };
          return new TextEncoder().encode(JSON.stringify(fake));
        }
        return honestJobs(job, body, signal);
      };
    }
    exits.push(new OzzyOnionExit(node.peerManager, node.circuit, server, { dispatcher: node.dispatcher, jobRunner }));
    relays.push(new OzzyOnionReplyRelay(node.peerManager, node.dispatcher, node.identity));
  }
  startAll(all);
  await sleep(100); // r が g の隣人表 (PEX) を受け取り、回路が組めるまで
  return { r, g, middles, exits, relays, servers, seen, jobs, all };
}

async function uploadToLockers(cluster: MemoryOverseasLockerCluster, data: Uint8Array) {
  const transport = (req: Request) => cluster.handleFetch(req);
  const up = new OverseasMultiLockerCoordinator({
    manifestStore: MANIFESTS,
    adapters: [
      new CatboxLockerAdapter(transport),
      new ZeroXZeroLockerAdapter(transport),
      new PomfLockerAdapter(transport, { variant: 'pomf-uguu' }),
      new PixeldrainLockerAdapter(transport),
    ],
    chunkBytes: CHUNK,
    targetBatchChunks: 4,
    idleGapMs: 5,
    maxWaitMs: 20,
  });
  return up.uploadFile({ source: data, fileName: 'evidence.bin', mimeType: 'application/octet-stream' });
}

/** 端末をまたぐ Manifest の置き場所 (アプリでは WebLite の P2P のファイル保管。OzNode.ozzyManifestStore) */
let MANIFESTS: OzzyManifestStore = memoryManifestStore();

function readerFor(n: MeshNet, opts: { direct?: () => never } = {}) {
  const mesh = new OzzyMeshFetcher({
    circuit: n.r.circuit,
    peerManager: n.r.peerManager,
    dispatcher: n.r.dispatcher,
    limits: { hedgeMs: 1500, inactivityMs: 5000 },
  });
  fetchers.push(mesh);
  // ★ 取る側は別の端末: 上げた側とメモリを共有しない (Manifest は P2P から取る)
  const reader = new OzzySlabReader({
    manifestStore: MANIFESTS,
    mesh,
    route: 'mesh-only',
    direct: opts.direct ?? null,
  });
  return { mesh, reader };
}

describe('Ozzy: オニオン回路 (r → Guard → M1) で並列取得', () => {
  it('★往復: 取る側は直接ロッカーへ行かず、複数の M1 に分けて取って復元する。M1 に取る側の peerId は渡らず、Guard に URL は見えない', async () => {
    MANIFESTS = memoryManifestStore();
    const cluster = new MemoryOverseasLockerCluster();
    net = await buildMeshNet(cluster);

    const data = randBytes(1_700_000); // 64 KiB チャンク → 2 ストライプ
    const up = await uploadToLockers(cluster, data);
    const link = up.linkText;
    expect(parseOzzyLinkV3(link)).not.toBeNull();
    expect(up.manifest.chunkBytes).toBe(CHUNK); // チャンクの大きさは Manifest に入っている

    let directCalls = 0;
    const { mesh, reader } = readerFor(net, { direct: (() => { directCalls++; throw new Error('direct must not be used'); }) as () => never });
    expect(mesh.ready).toBe(true);
    expect(mesh.fetcherCount).toBe(6);
    const t0 = performance.now();
    const res = await reader.downloadFile(link);
    const ms = performance.now() - t0;
    expect(res, `failure: ${reader.lastFailure}`).not.toBeNull();
    expect(Buffer.from(res!.data).equals(Buffer.from(data))).toBe(true);
    expect(res!.manifest.fileName).toBe('evidence.bin');

    // 直接は 1 度も取りに行っていない。全シェアがオニオン経由
    expect(directCalls).toBe(0);
    expect(reader.stats.directShares).toBe(0);
    // ★ 16 個を待たない: データシェアの先頭で平文が終わる分だけ取る
    expect(reader.stats.meshShares).toBeGreaterThan(0);
    expect(reader.stats.meshShares).toBeLessThan(16 * 3);
    // 並列: 回路が M1 を替えるので、複数の M1 が働いた。r 自身と g は M1 にならない
    const working = net.middles.filter(m => (net!.servers.get(m.name)?.stats.served ?? 0) > 0).length;
    expect(working).toBeGreaterThanOrEqual(3);
    expect(net.servers.get('r')!.stats.served + net.servers.get('g')!.stats.served).toBe(0);
    console.log(`[ozzy onion] 1.7MB: ${(ms / 1000).toFixed(2)}s, shares ${reader.stats.meshShares}, M1 used ${working}/6`);

    // ★ M1 に届いたフレームのどこにも、取る側の peerId は現れない (M1 に見えるのは g だけ)
    const rRaw = Encoding.fromHex(net.r.identity.peerId);
    for (const m of net.middles) {
      for (const f of m.inbox) expect(hasSubarray(f.raw, rRaw)).toBe(false);
      for (const f of m.inbox) expect(f.from).toBe(net.g.identity.peerId);
    }
    // ★ Guard (g) に届いたフレームのどこにも、URL は平文で現れない (M1 宛ての封印の中)
    const anyUrl = new TextEncoder().encode(Array.from(net.seen.values())[0][0]);
    for (const f of net.g.inbox) expect(hasSubarray(f.raw, anyUrl)).toBe(false);
    // ★ Guard が r へ流した応答の片に、チャンクの平文 (tag も含む暗号文の先頭) は現れない (r の鍵で暗号化されている)
    const firstShare = net.r.inbox.find(f => f.type === WireType.OZZY_RESULT);
    expect(firstShare).toBeDefined();
  }, 120_000);

  it('★偽物: tag だけ正しいゴミを返す M1 が混ざっていても、ハッシュで見分けてその M1 を避け、別の M1 から取り直す', async () => {
    MANIFESTS = memoryManifestStore();
    const cluster = new MemoryOverseasLockerCluster();
    net = await buildMeshNet(cluster, { evil: new Set(['m0', 'm3']) });
    const data = randBytes(900_000);
    const link = (await uploadToLockers(cluster, data)).linkText;

    const { mesh, reader } = readerFor(net);
    const res = await reader.downloadFile(link);
    expect(res, `failure: ${reader.lastFailure}`).not.toBeNull();
    expect(Buffer.from(res!.data).equals(Buffer.from(data))).toBe(true);
    if (net.servers.get('m0')!.stats.served + net.servers.get('m3')!.stats.served > 0) {
      expect(mesh.stats.rejected).toBeGreaterThan(0);
    }
  }, 120_000);

  it('★フェイルクローズ: 回路が組めなければ失敗し、直接は取りに行かない', async () => {
    MANIFESTS = memoryManifestStore();
    const cluster = new MemoryOverseasLockerCluster();
    net = await buildMeshNet(cluster, { n: 0 }); // g の先に M1 の候補がいない
    const link = (await uploadToLockers(cluster, randBytes(200_000))).linkText;

    let directCalls = 0;
    const { mesh, reader } = readerFor(net, { direct: (() => { directCalls++; throw new Error('no'); }) as () => never });
    expect(mesh.ready).toBe(false);
    const res = await reader.downloadFile(link);
    expect(res).toBeNull();
    expect(reader.lastFailure).toBe('no-fetchers');
    expect(directCalls).toBe(0);
  }, 120_000);

  it('取得役を止めている M1 (REFUSED) は避けて、他の M1 で取る', async () => {
    MANIFESTS = memoryManifestStore();
    const cluster = new MemoryOverseasLockerCluster();
    net = await buildMeshNet(cluster, { disabled: new Set(['m0', 'm1', 'm2']) });
    const data = randBytes(600_000);
    const link = (await uploadToLockers(cluster, data)).linkText;
    const { reader } = readerFor(net);
    const res = await reader.downloadFile(link);
    expect(res && Buffer.from(res.data).equals(Buffer.from(data))).toBe(true);
  }, 120_000);
});

describe('Ozzy: アップロードもオニオン回路 (告発者 → Guard → M1 → 中継 Worker → ロッカー)', () => {
  /** r が告発者。ロッカーへの PUT は回路の M1 に頼む (OnionLockerAdapter)。置いた Slab は別の M1 で確かめる */
  function onionUploader(n: MeshNet, lockers: string[] = ['catbox', '0x0.st', 'pomf-uguu', 'pixeldrain']) {
    const mesh = new OzzyMeshFetcher({
      circuit: n.r.circuit, peerManager: n.r.peerManager, dispatcher: n.r.dispatcher, limits: { hedgeMs: 1500, inactivityMs: 5000 },
    });
    fetchers.push(mesh);
    const coordinator = new OverseasMultiLockerCoordinator({
      manifestStore: MANIFESTS,
      adapters: createOnionLockerAdapters(mesh, lockers),
      mesh,
      chunkBytes: CHUNK,
      targetBatchChunks: 4,
      idleGapMs: 5,
      maxWaitMs: 20,
    });
    return { mesh, coordinator };
  }

  it('★往復: 告発者はロッカーへ 1 度も直接行かず、M1 が置き、別の端末がリンクだけで取れる。M1 に告発者の peerId は渡らず、Guard に中身・置き先は見えない', async () => {
    MANIFESTS = memoryManifestStore();
    const cluster = new MemoryOverseasLockerCluster();
    net = await buildMeshNet(cluster);
    const { mesh, coordinator } = onionUploader(net);
    const data = randBytes(700_000);
    const up = await coordinator.uploadFile({ source: data, fileName: 'leak.pdf', mimeType: 'application/pdf' });
    expect(parseOzzyLinkV3(up.linkText)).not.toBeNull();
    expect(mesh.stats.jobsOk).toBeGreaterThan(0);
    expect(coordinator.uploadStats.verified).toBe(coordinator.uploadStats.slabs); // 置いた Slab は全部確かめた
    // 作業をしたのは M1 (g の隣人) だけ。r と g は M1 にならない
    const workers = net.middles.filter(m => (net!.jobs.get(m.name) ?? []).length > 0);
    expect(workers.length).toBeGreaterThanOrEqual(2);
    expect(net.jobs.get('r')).toBeUndefined();
    expect(net.jobs.get('g')).toBeUndefined();

    // ★ M1 に届いたフレームのどこにも、告発者の peerId は現れない
    const rRaw = Encoding.fromHex(net.r.identity.peerId);
    for (const m of net.middles) {
      for (const f of m.inbox) {
        expect(hasSubarray(f.raw, rRaw)).toBe(false);
        expect(f.from).toBe(net.g.identity.peerId);
      }
    }
    // ★ Guard に届いた本体の片 (OZZY_UP) に、Slab の中身 (暗号文の先頭 = チャンクの tag) もロッカーの URL も現れない
    const ups = net.g.inbox.filter(f => f.type === WireType.OZZY_UP);
    expect(ups.length).toBeGreaterThan(0);
    const keys0 = await deriveOzzyKeys(up.manifest.stripes[0].stripeSeed);
    const tag0 = computeChunkTag(keys0.kTag, 0, 0);
    const url0 = new TextEncoder().encode(up.manifest.stripes[0].locations[0].url);
    for (const f of net.g.inbox) {
      expect(hasSubarray(f.raw, tag0)).toBe(false);
      expect(hasSubarray(f.raw, url0)).toBe(false);
    }

    // 別の端末 (メモリを共有しない) がリンクだけで取る
    const { reader } = readerFor(net);
    const res = await reader.downloadFile(up.linkText);
    expect(res, `failure: ${reader.lastFailure}`).not.toBeNull();
    expect(Buffer.from(res!.data).equals(Buffer.from(data))).toBe(true);
    expect(res!.manifest.fileName).toBe('leak.pdf');
  }, 120_000);

  it('★嘘の受け取り票: 置かずに「置いた」と言う M1 が混ざっていても、確かめて弾き、別の M1・ロッカーで置き直す', async () => {
    MANIFESTS = memoryManifestStore();
    const cluster = new MemoryOverseasLockerCluster();
    net = await buildMeshNet(cluster, { liar: new Set(['m0', 'm1']) });
    const { coordinator } = onionUploader(net);
    const data = randBytes(400_000);
    const up = await coordinator.uploadFile({ source: data, fileName: 'a.bin', mimeType: 'application/octet-stream' });
    // Manifest に嘘の置き場所は入っていない
    for (const s of up.manifest.stripes) for (const l of s.locations) expect(l.url).not.toContain('never-uploaded');
    const liarJobs = (net.jobs.get('m0')?.length ?? 0) + (net.jobs.get('m1')?.length ?? 0);
    if (liarJobs > 0) expect(coordinator.uploadStats.verifyFailed).toBeGreaterThan(0);
    const { reader } = readerFor(net);
    const res = await reader.downloadFile(up.linkText);
    expect(res && Buffer.from(res.data).equals(Buffer.from(data))).toBe(true);
  }, 120_000);

  it('★フェイルクローズ: 回路が組めなければアップロードは失敗し、ロッカーへ直接は行かない', async () => {
    MANIFESTS = memoryManifestStore();
    const cluster = new MemoryOverseasLockerCluster();
    net = await buildMeshNet(cluster, { n: 0 });
    const { coordinator } = onionUploader(net);
    const before = cluster.storedFileCount;
    await expect(coordinator.uploadFile({ source: randBytes(100_000), fileName: 'a.bin', mimeType: 'application/octet-stream' })).rejects.toThrow();
    expect(cluster.storedFileCount).toBe(before);
    expect((MANIFESTS as any).size).toBe(0);
  }, 60_000);

  it('削除も回路の M1 に頼める (0x0.st の削除トークン)', async () => {
    MANIFESTS = memoryManifestStore();
    const cluster = new MemoryOverseasLockerCluster();
    net = await buildMeshNet(cluster);
    const { mesh, coordinator } = onionUploader(net, ['0x0.st']);
    const up = await coordinator.uploadFile({ source: randBytes(150_000), fileName: 'a.bin', mimeType: 'application/octet-stream' });
    const stored = cluster.storedFileCount;
    expect(stored).toBeGreaterThan(0);
    const deleted = await coordinator.deleteAllReceipts(up.receipts);
    expect(deleted).toBe(up.receipts.length);
    expect(cluster.storedFileCount).toBe(stored - up.receipts.length);
    expect(mesh.stats.jobsOk).toBeGreaterThanOrEqual(up.receipts.length * 2);
  }, 120_000);

  it('M1 は形の悪い作業・資格情報の要るロッカー・宣言を超える本体を断る', async () => {
    expect(() => encodeLockerJob({ op: 'upload', lockerId: 'internet-archive-s3', filename: 'a.bin' }, 10)).toThrow();
    expect(() => encodeLockerJob({ op: 'upload', lockerId: 'catbox', filename: '../etc/passwd' }, 10)).toThrow();
    expect(() => encodeLockerJob({ op: 'upload', lockerId: 'catbox', filename: 'a.bin' }, 65 * 1024 * 1024)).toThrow();
    expect(() => new OnionLockerAdapter('internet-archive-s3', { runJob: async () => ({ ok: false, reason: 'failed' }), ready: true } as any)).toThrow();
    const ok = encodeLockerJob({ op: 'upload', lockerId: 'catbox', filename: 'slab_1.bin' }, 1234);
    expect(decodeLockerJob(ok)).toEqual({ job: { op: 'upload', lockerId: 'catbox', filename: 'slab_1.bin' }, totalBytes: 1234 });
    const bad = ok.slice();
    bad[2] = 'X'.charCodeAt(0); // lockerId を壊す
    expect(decodeLockerJob(bad)).toBeNull();
    expect(OZZY_JOB_LOCKERS).not.toContain('internet-archive-s3');

    // 宣言より多い片を送りつけると、M1 は溜め込まずに失敗を返す
    const cluster = new MemoryOverseasLockerCluster();
    net = await buildMeshNet(cluster, { n: 1 });
    const m = net.middles[0];
    const exit = net.exits[net.all.indexOf(m)];
    const before = exit.stats.jobsDone;
    const { sealReplyHeader } = await import('../src/ozzy/MeshRange');
    const { encryptChunk } = await import('../src/network/tunnel/TunnelCrypto');
    const header = sealReplyHeader(net.g.identity.pubkey, net.r.identity.peerId, 1);
    const respKey = sodium.randombytes_buf(32);
    const upKey = sodium.randombytes_buf(32);
    const uploadId = sodium.randombytes_buf(16);
    const job = encodeLockerJob({ op: 'upload', lockerId: 'catbox', filename: 'a.bin' }, 10);
    const body = new Uint8Array([...header, ...respKey, ...upKey, ...uploadId, ...job]);
    // M1 の回路の出口へ直接渡す (Guard = g から届いたことにする)
    (m.circuit as any).directExits.get(OZZY_ONION_JOB_KIND)(body, net.g.identity.peerId);
    const gid = net.g.identity.peerId;
    const send = (seq: number, final: boolean, n: number) => (m.dispatcher as any).dispatch(gid, WireType.OZZY_UP_FWD, {
      uploadId, seq, final, body: encryptChunk(upKey, 0x50, seq, final, new Uint8Array(n)),
    });
    send(0, false, 10);
    send(1, true, 10); // 宣言は 10 バイトなのに 2 片目
    await sleep(50);
    expect(exit.stats.jobsDone).toBe(before); // 実行していない
    expect(net.jobs.get(m.name)).toBeUndefined();
    void OZZY_UP_PIECE_BYTES;
  }, 60_000);
});

describe('Ozzy: 取得役の許可リスト・要求の形 (OzzyRangeServer)', () => {
  const tag = new Uint8Array(16).fill(7);
  const okData = (n: number) => {
    const b = new Uint8Array(n);
    b.set(tag, 0);
    return b;
  };

  it('公開ロッカー以外 (攻撃者のホスト・LAN・http・ポート指定) には取りに行かない', async () => {
    let calls = 0;
    const srv = new OzzyRangeServer({ fetchRange: async (_l, _u, s, e) => { calls++; return okData(e - s + 1); } });
    const ask = async (url: string) => {
      const r = decodeRangeResponse(await srv.serve(encodeRangeRequest({ lockerId: 'catbox', url, start: 0, length: 1024, expectedTag: tag })));
      return r?.status;
    };
    for (const bad of [
      'https://attacker.example/x.bin',
      'http://files.catbox.moe/a.bin',
      'https://127.0.0.1/a',
      'https://192.168.1.1/a',
      'https://files.catbox.moe:8443/a.bin',
      'https://files.catbox.moe.attacker.example/a.bin',
      'https://evilgofile.io/a.bin',
    ]) {
      expect(await ask(bad), bad).toBe(OZZY_MESH_STATUS.REFUSED);
    }
    expect(calls).toBe(0);
    expect(await ask('https://files.catbox.moe/a.bin')).toBe(OZZY_MESH_STATUS.OK);
    expect(await ask('https://ia800.us.archive.org/1/items/x/y.bin')).toBe(OZZY_MESH_STATUS.OK);
    expect(isAllowedOzzyFetchUrl('https://my-relay.workers.dev/download/a', ['my-relay.workers.dev'])).toBe(true);
    expect(isAllowedOzzyFetchUrl('https://other.workers.dev/download/a', ['my-relay.workers.dev'])).toBe(false);
  });

  it('範囲は 1 チャンク (4 MiB) まで。長さ・tag が合わないものは返さない。404 は NOT_FOUND', async () => {
    expect(() => encodeRangeRequest({ lockerId: 'catbox', url: 'https://files.catbox.moe/a', start: 0, length: 4 * 1024 * 1024 + 1, expectedTag: tag })).toThrow();
    const short = new OzzyRangeServer({ fetchRange: async (_l, _u, s, e) => okData(e - s) });
    const wrongTag = new OzzyRangeServer({ fetchRange: async (_l, _u, s, e) => new Uint8Array(e - s + 1) });
    const missing = new OzzyRangeServer({ fetchRange: async () => 'not-found' });
    const req = encodeRangeRequest({ lockerId: 'catbox', url: 'https://files.catbox.moe/a', start: 4096, length: 2048, expectedTag: tag });
    expect(decodeRangeResponse(await short.serve(req))?.status).toBe(OZZY_MESH_STATUS.FETCH_ERROR);
    expect(decodeRangeResponse(await wrongTag.serve(req))?.status).toBe(OZZY_MESH_STATUS.FETCH_ERROR);
    expect(decodeRangeResponse(await missing.serve(req))?.status).toBe(OZZY_MESH_STATUS.NOT_FOUND);
    // 壊れた要求
    expect(decodeRangeResponse(await missing.serve(new Uint8Array([1, 2, 3])))?.status).toBe(OZZY_MESH_STATUS.REFUSED);
  });

  it('同時数の上限を超えたら BUSY を返す', async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    const srv = new OzzyRangeServer({
      maxConcurrent: 1,
      fetchRange: async (_l, _u, s, e) => { await gate; return okData(e - s + 1); },
    });
    const req = encodeRangeRequest({ lockerId: 'catbox', url: 'https://files.catbox.moe/a', start: 0, length: 64, expectedTag: tag });
    const first = srv.serve(req);
    expect(decodeRangeResponse(await srv.serve(req))?.status).toBe(OZZY_MESH_STATUS.BUSY);
    release();
    expect(decodeRangeResponse(await first)?.status).toBe(OZZY_MESH_STATUS.OK);
  });
});

describe('Ozzy: 取得役のロッカーごとの取り方 (createLockerRangeFetch)', () => {
  it('Gofile の Slab も取れる。他人の要求で取りに行っても、ゲスト ID を作るのは 5 秒に 1 つまで', async () => {
    const cluster = new MemoryOverseasLockerCluster();
    let accountsMinted = 0;
    const transport = async (req: Request) => {
      const u = new URL(req.url);
      if (u.hostname === 'api.gofile.io' && u.pathname === '/accounts') accountsMinted++;
      return cluster.handleFetch(req);
    };
    const receipt = await new GofileLockerAdapter(transport).uploadSlab(randBytes(3 * 4096), 'slab.bin');
    const fetchRange = createLockerRangeFetch(transport);
    const ac = new AbortController();
    const got = await fetchRange('gofile', receipt.downloadUrl, 4096, 8191, ac.signal);
    expect(got instanceof Uint8Array && got.length === 4096).toBe(true);
    const before = accountsMinted;
    // フラグメントの folder を変えて 10 回 (攻撃者が取得役に作らせようとする)
    for (let i = 0; i < 10; i++) {
      await fetchRange('gofile', `${receipt.downloadUrl.split('#')[0]}#folder=fake${i}`, 0, 1023, ac.signal);
    }
    expect(accountsMinted - before).toBeLessThanOrEqual(1);
  });
});

describe('Ozzy: Lease の改ざん・Manifest への資格情報の漏れ', () => {
  it('★識別子は署名鍵に縛られる: K_lease を知らない相手は同じ識別子へ Lease を積めない', async () => {
    const keys = await deriveOzzyKeys(await generateOzzySeed());
    const nowSec = Math.floor(Date.now() / 1000);
    const real = await createSlabLeaseSet({
      kLease: keys.kLease, slabChunkCount: 4, migrationSeq: 1, expiresAtSec: nowSec + 3600,
      endpoint: { lockerId: 'catbox', downloadUrl: 'https://files.catbox.moe/real.bin', authToken: '', supportsRange: true },
    });
    expect(await verifySlabLeaseSet(real, nowSec)).toBe(true);
    const signKp = await deriveLeaseSignKeypair(keys.kLease);
    expect(Encoding.toHex(real.leaseSetId)).toBe(Encoding.toHex(leaseSetIdFromSignPubKey(signKp.publicKey)));

    // 別の鍵で署名した Lease を、同じ識別子で偽造する
    const otherKeys = await deriveOzzyKeys(await generateOzzySeed());
    const fake = await createSlabLeaseSet({
      kLease: otherKeys.kLease, slabChunkCount: 4, migrationSeq: 99, expiresAtSec: nowSec + 3600,
      endpoint: { lockerId: 'catbox', downloadUrl: 'https://files.catbox.moe/junk.bin', authToken: '', supportsRange: true },
    });
    const forged: SlabLeaseSet = { ...fake, leaseSetId: real.leaseSetId };
    expect(await verifySlabLeaseSet(forged, nowSec)).toBe(false);
    const store = new CloudLeaseSetStore();
    expect(await store.upsertSlab(forged, nowSec)).toBe(false);
    expect(await store.upsertSlab(real, nowSec)).toBe(true);
    // 期限が遠すぎる Lease も受け付けない
    const tooLong = await createSlabLeaseSet({
      kLease: keys.kLease, slabChunkCount: 4, migrationSeq: 2, expiresAtSec: nowSec + 3 * 365 * 86_400,
      endpoint: { lockerId: 'catbox', downloadUrl: 'https://files.catbox.moe/x.bin', authToken: '', supportsRange: true },
    });
    expect(await verifySlabLeaseSet(tooLong, nowSec)).toBe(false);
  });

  it('★削除トークンは Manifest に入らない (リンクを受け取った全員が消せる穴)', async () => {
    MANIFESTS = memoryManifestStore();
    const cluster = new MemoryOverseasLockerCluster();
    const up = await uploadToLockers(cluster, randBytes(100_000));
    // アップロードの結果: 受け取りの記録 (本人のメモリ) には削除トークンが残るが、Manifest には入らない
    const tokens = up.receipts.map(r => r.deleteToken).filter(t => t.length >= 6);
    expect(tokens.length).toBeGreaterThan(0);
    const bytes = serializeOzzyManifestV4(up.manifest);
    for (const t of tokens) expect(hasSubarray(bytes, new TextEncoder().encode(t))).toBe(false);
    // 置き場所 (URL) は入っている
    expect(up.manifest.stripes[0].locations.length).toBeGreaterThan(0);
  });

  it('同じ識別子の Lease は先着順に持つ (新しい署名で古い Lease を押し出せない)', async () => {
    const keys = await deriveOzzyKeys(await generateOzzySeed());
    const nowSec = Math.floor(Date.now() / 1000);
    const store = new CloudLeaseSetStore();
    const mk = (seq: number) => createSlabLeaseSet({
      kLease: keys.kLease, slabChunkCount: 1, migrationSeq: seq, expiresAtSec: nowSec + 3600,
      endpoint: { lockerId: 'catbox', downloadUrl: `https://files.catbox.moe/${seq}.bin`, authToken: '', supportsRange: true },
    });
    const first = await mk(1);
    expect(await store.upsertSlab(first, nowSec)).toBe(true);
    for (let i = 2; i <= 70; i++) await store.upsertSlab(await mk(i), nowSec);
    const kept = store.getSlabLeases(first.leaseSetId, nowSec);
    expect(kept.length).toBe(64);
    expect(kept.some(l => l.migrationSeq === 1)).toBe(true); // 最初の Lease は残っている
  });
});

describe('Ozzy: 悪いパリティが混ざっても復元できる (Manifest のストライプはハッシュ無し)', () => {
  it('先頭 16 個に悪いパリティが入っていても、別の組み合わせで復元する', async () => {
    const seed = await generateOzzySeed();
    const keys = await deriveOzzyKeys(seed);
    const plain = randBytes(200_000);
    const chunks = await encodeFullStripe(plain, 7, keys, 32 * 1024);
    // データシェア 0..5 が欠け、パリティ 16 (番号が小さいので最初の組み合わせに入る) が改ざんされている
    const shares = chunks
      .filter(c => c.shareIndex >= 6)
      .map(c => ({ shareIndex: c.shareIndex, rawChunk: c.shareIndex === 16 ? (() => { const b = c.rawChunk.slice(); b[100] ^= 0xff; return b; })() : c.rawChunk }));
    const out = await decodeStripeFromChunks(shares, 7, keys, 32 * 1024);
    expect(out && Buffer.from(out).equals(Buffer.from(plain))).toBe(true);

    // ハッシュがあれば、悪いシェアは最初に捨てられる
    const digests = computeStripeShareDigests(chunks.map(c => ({ ...c, rawChunk: c.rawChunk })));
    const out2 = await decodeStripeFromChunks(shares, 7, keys, 32 * 1024, { shareDigests: digests });
    expect(out2 && Buffer.from(out2).equals(Buffer.from(plain))).toBe(true);
    // tag は正しい
    expect(Encoding.toHex(shares[0].rawChunk.subarray(0, 16))).toBe(Encoding.toHex(computeChunkTag(keys.kTag, 7, shares[0].shareIndex)));
    void sodium;
  });
});

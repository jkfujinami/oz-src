/**
 * Ozzy に対する法執行型の攻撃者のシミュレーション (実装をそのまま動かす)。
 *
 *   攻撃者 (LE) ができること: 監視ノード・中継 Worker を網に混ぜる (Sybil)、事業者 (Cloudflare・Guard の運営・
 *   トラッカー) にログを開示させる/今後のログを取らせる、端末を押収する。全網の盗聴 (GPA) はしない。
 *
 *   今の構成 (共通の Worker・ディレクトリは無い):
 *     上げる  告発者 U ─(回路の要求 + OZZY_UP)→ U の Guard ─→ M1 ─(M1 が選んだ他人の中継 Worker)→ ロッカー
 *     Manifest (置き場所入り) は P2P のファイル保管 (WebLite。U → U の Guard → 受け口 → 保持者のトンネル)
 *     取る    読み手 R ─(回路)→ R の Guard ─→ M1 ─(中継 Worker)→ ロッカー
 *
 *   1. 観測台帳: 実際のコード (OverseasMultiLockerCoordinator + OnionLockerAdapter・OzzyMeshFetcher.runJob・
 *      OzzyOnionExit/ReplyRelay・WorkerPool・createPooledRelayTransport・SlabReader) で 1 回上げて 1 回取り、
 *      各観測点が記録しうるものを全部台帳に書く。LE がリンクを入手したとして、台帳の照合で誰が特定されるかを計算する。
 *   2. 確率: 実際の WorkerPool.pickRelay で LE の Worker が選ばれる割合 (いまは M1 の中継の選び方)。
 *   3. 上げ下ろし 1 回あたりの回路の使用回数 (実測) と、特定される確率 (旧構成との比較)。
 *
 * 走らせ方: RUN_SIM=1 npx vitest run tests/simulation/OzzyLawEnforcement.sim.test.ts
 */
import { describe, it, expect, beforeAll } from 'vitest';
import sodium, { sodiumReady } from '../../src/crypto/sodium';
import { NodeIdentity, NODE_ID_POW } from '../../src/crypto/NodeIdentity';
import { MessageDispatcher } from '../../src/network/MessageDispatcher';
import { WireType } from '../../src/network/wire/WireTypes';
import { createSimNode, link, startAll, stopAll, sleep, FAST_POW, type SimNode } from '../helpers/onionNet';
import {
  MemoryOverseasLockerCluster,
  OverseasMultiLockerCoordinator,
  OzzyMeshFetcher,
  OzzyOnionExit,
  OzzyOnionReplyRelay,
  OzzyRangeServer,
  OzzySlabReader,
  OzzyWorkerPool,
  createLockerJobRunner,
  createLockerRangeFetch,
  createOnionLockerAdapters,
  createPooledRelayTransport,
  deserializeOzzyManifestV4,
  maxStripePlainBytes,
  memoryManifestStore,
  parseJobReceipt,
  parseOzzyLinkV3,
  OZZY_CHUNK_BYTES,
  type OzzyManifestStore,
} from '../../src/ozzy';

const CHUNK = 64 * 1024; // 64 KiB で動かし、4 MiB の本番へは「ストライプの数」を合わせて換算する
const SCALE = OZZY_CHUNK_BYTES / CHUNK;
const MiB = 1024 * 1024;

beforeAll(async () => {
  await sodiumReady;
});

// ───────────────────────── 観測台帳 ─────────────────────────

/** 観測点が記録しうる 1 件 */
interface Obs {
  /** 観測点 (誰のログか) */
  at: string;
  /** 観測点から見た相手 (IP を持つ主体の名前) */
  client: string;
  what: 'relay-put' | 'relay-get' | 'm1-job' | 'm1-fetch' | 'guard-up' | 'guard-reply' | 'p2p-put' | 'p2p-get';
  /** 中継: 行き先の URL / M1: URL / Guard: 相手の M1 / P2P: Manifest のリンクの本体 */
  key: string;
  extra?: string;
  bytes?: number;
}

class Ledger {
  readonly rows: Obs[] = [];
  add(o: Obs) { this.rows.push(o); }
}

/** 中継 Worker の本体 (worker.js の /ozzy/v2/locker-proxy と同じ振る舞い) を、誰が使ったかを記録しながら動かす */
function relayWorker(ledger: Ledger, cluster: MemoryOverseasLockerCluster, client: string) {
  return async (req: Request): Promise<Response> => {
    const worker = new URL(req.url).origin;
    const target = req.headers.get('X-Ozzy-Target-Url')!;
    const method = req.headers.get('X-Ozzy-Target-Method') ?? 'GET';
    const headers = JSON.parse(req.headers.get('X-Ozzy-Target-Headers') ?? '{}');
    const body = method === 'GET' || method === 'HEAD' ? undefined : new Uint8Array(await req.arrayBuffer());
    const upstream = await cluster.handleFetch(new Request(target, { method, headers, body: body as BodyInit | undefined }));
    const buf = new Uint8Array(await upstream.arrayBuffer());
    // 中継の持ち主に見えるもの: 使った人 (CF-Connecting-IP)・行き先の URL・応答 (アップロードなら置き場所の URL が返る)
    const respText = buf.length < 4096 ? new TextDecoder().decode(buf) : '';
    ledger.add({ at: `worker:${worker}`, client, what: method === 'GET' ? 'relay-get' : 'relay-put', key: target, extra: respText, bytes: (body?.length ?? 0) + buf.length });
    return new Response(buf, { status: upstream.status, headers: { 'X-Ozzy-Proxied-Status': String(upstream.status), 'Content-Type': upstream.headers.get('Content-Type') ?? '' } });
  };
}

/**
 * Manifest の P2P 保管 (WebLite のファイル保管) の観測。上げる人・取る人のトンネルは「自分 → 自分の Guard → 受け口 → 保持者」
 * なので、保持者・受け口に見えるのは手前のホップ (Guard / 受け口) だけ。自分の Guard には「トンネルで何か出し入れした」ことと量。
 */
function ledgeredManifestStore(ledger: Ledger, inner: OzzyManifestStore, who: string): OzzyManifestStore {
  return {
    async put(bytes, signal) {
      const body = await inner.put(bytes, signal);
      ledger.add({ at: 'p2p-holder', client: 'gateway', what: 'p2p-put', key: body, bytes: bytes.length });
      ledger.add({ at: `node:guard-of-${who}`, client: who, what: 'p2p-put', key: 'tunnel', bytes: bytes.length });
      return body;
    },
    async get(body, signal) {
      ledger.add({ at: 'p2p-holder', client: 'gateway', what: 'p2p-get', key: body });
      ledger.add({ at: `node:guard-of-${who}`, client: who, what: 'p2p-get', key: 'tunnel' });
      return inner.get(body, signal);
    },
  };
}

/** 中継 Worker の交換プール (本物)。honest 台の参加者の Worker と、LE の Worker を広告として入れる */
async function buildPool(honest: number, le: number, opts: { leAgeMs?: number; honestAgeMs?: number; now?: () => number } = {}) {
  const dispatcher = new MessageDispatcher();
  const pm: any = { peers: new Map(), sendMessage: () => undefined, on: () => undefined, off: () => undefined, myPeerId: 'f'.repeat(32) };
  const me = await NodeIdentity.mine(FAST_POW);
  let clock = Date.now();
  const now = opts.now ?? (() => clock);
  const pool = new OzzyWorkerPool(pm, dispatcher, me, { powParams: FAST_POW, now });
  pool.setOwn('https://ozzy.me.workers.dev');
  const inject = async (url: string, at: number) => {
    const id = await NodeIdentity.mine(FAST_POW);
    const expiresMin = Math.floor((at + 24 * 3600_000) / 60_000);
    clock = at;
    dispatcher.dispatch('e'.repeat(32), WireType.OZZY_WORKER_ADS, {
      ads: [{ pubkey: id.pubkey, powCounter: id.powCounter, expiresMin, url, signature: id.signOzzyWorkerAd(url, expiresMin) }],
    });
  };
  const t0 = Date.now();
  for (let i = 0; i < honest; i++) await inject(`https://ozzy.h${i}.workers.dev`, t0 - (opts.honestAgeMs ?? 2 * 3600_000));
  for (let i = 0; i < le; i++) await inject(`https://ozzy.le${i}.workers.dev`, t0 - (opts.leAgeMs ?? 2 * 3600_000));
  clock = t0;
  return { pool, setClock: (t: number) => { clock = t; } };
}

const isLE = (workerOrigin: string) => /\/\/ozzy\.le\d+\.workers\.dev/.test(workerOrigin);

/**
 * 網: 告発者 u → u の Guard gu、読み手 r → r の Guard gr。M1 の候補 m0..m{n-1} は両方の Guard の隣人。
 * 全ノードが M1 の役 (取得と作業) と Guard の役を持つ。M1 は中継プール経由でロッカーへ行く。
 */
async function buildOnionNet(ledger: Ledger, cluster: MemoryOverseasLockerCluster, pool: OzzyWorkerPool, nMiddles: number) {
  const u = await createSimNode('uploader');
  const gu = await createSimNode('guard-of-uploader');
  const r = await createSimNode('reader');
  const gr = await createSimNode('guard-of-reader');
  link(u, gu);
  link(r, gr);
  const middles: SimNode[] = [];
  for (let i = 0; i < nMiddles; i++) {
    const m = await createSimNode(`m${i}`);
    link(gu, m);
    link(gr, m);
    middles.push(m);
  }
  const all = [u, gu, r, gr, ...middles];
  const exits: OzzyOnionExit[] = [];
  const relays: OzzyOnionReplyRelay[] = [];
  for (const node of all) {
    const transport = createPooledRelayTransport(() => pool.pickRelay(), (x) => pool.reportFailure(x), relayWorker(ledger, cluster, node.name));
    const relayed = createLockerRangeFetch(transport);
    const jobs = createLockerJobRunner(transport);
    const server = new OzzyRangeServer({
      fetchRange: async (lockerId, url, start, end, signal) => {
        // M1 に見えるもの: URL と範囲、手前の Guard (要求はオニオンで届く)
        ledger.add({ at: `node:${node.name}`, client: 'guard', what: 'm1-fetch', key: url, extra: `${start}-${end}` });
        return relayed(lockerId, url, start, end, signal);
      },
    });
    const exit = new OzzyOnionExit(node.peerManager, node.circuit, server, {
      dispatcher: node.dispatcher,
      jobRunner: async (job, body, signal) => {
        const out = await jobs(job, body, signal);
        // M1 に見えるもの: 置き先のロッカー・Slab (暗号文)・結果の URL、手前の Guard
        const receipt = job.op === 'upload' ? parseJobReceipt(out, job.lockerId) : null;
        ledger.add({ at: `node:${node.name}`, client: 'guard', what: 'm1-job', key: receipt?.downloadUrl ?? job.op, bytes: body.length });
        return out;
      },
    });
    exits.push(exit);
    relays.push(new OzzyOnionReplyRelay(node.peerManager, node.dispatcher, node.identity));
  }
  startAll(all);
  await sleep(150);
  const stop = () => {
    for (const e of exits) e.destroy();
    for (const x of relays) x.destroy();
    stopAll(all);
  };
  return { u, gu, r, gr, middles, all, stop };
}

type OnionNet = Awaited<ReturnType<typeof buildOnionNet>>;

/** Guard に見えるもの (フレームそのものから): 告発者からの本体の量、読み手への応答の量、相手の M1 */
function guardObservations(ledger: Ledger, net: OnionNet) {
  for (const f of net.gu.inbox) {
    if (f.type === WireType.OZZY_UP && f.from === net.u.identity.peerId) {
      ledger.add({ at: 'node:guard-of-uploader', client: 'uploader', what: 'guard-up', key: 'M1 (封印を開けて分かる)', bytes: f.raw.length });
    }
    if (f.type === WireType.OZZY_REPLY) ledger.add({ at: 'node:guard-of-uploader', client: 'uploader', what: 'guard-reply', key: f.from, bytes: f.raw.length });
  }
  for (const f of net.gr.inbox) {
    if (f.type === WireType.OZZY_REPLY) ledger.add({ at: 'node:guard-of-reader', client: 'reader', what: 'guard-reply', key: f.from, bytes: f.raw.length });
  }
}

/** 本番 (4 MiB チャンク) で fileBytes のファイルと同じストライプ数になる、64 KiB チャンクでの大きさ */
function emulatedSize(fileBytes: number): number {
  const stripes = Math.max(1, Math.ceil(fileBytes / maxStripePlainBytes(OZZY_CHUNK_BYTES)));
  const lastFrac = fileBytes / maxStripePlainBytes(OZZY_CHUNK_BYTES) - (stripes - 1);
  return Math.max(1, Math.round((stripes - 1 + lastFrac) * maxStripePlainBytes(CHUNK)));
}

/** 1 回上げて 1 回取る (告発者と読み手は別の端末。共有するのは P2P の Manifest の保管だけ) */
async function roundTrip(ledger: Ledger, net: OnionNet, size: number) {
  const p2p = memoryManifestStore();
  const uMesh = new OzzyMeshFetcher({ circuit: net.u.circuit, peerManager: net.u.peerManager, dispatcher: net.u.dispatcher, limits: { hedgeMs: 3000, inactivityMs: 8000 } });
  const uploader = new OverseasMultiLockerCoordinator({
    manifestStore: ledgeredManifestStore(ledger, p2p, 'uploader'),
    adapters: createOnionLockerAdapters(uMesh, ['gofile', 'pomf-uguu', 'catbox', '0x0.st']),
    mesh: uMesh,
    chunkBytes: CHUNK, targetBatchChunks: 8, idleGapMs: 5, maxWaitMs: 20,
  });
  const up = await uploader.uploadFile({ source: sodium.randombytes_buf(emulatedSize(size)), fileName: 'leak.zip', mimeType: 'application/zip' });

  const rMesh = new OzzyMeshFetcher({ circuit: net.r.circuit, peerManager: net.r.peerManager, dispatcher: net.r.dispatcher, limits: { hedgeMs: 3000, inactivityMs: 8000 } });
  const reader = new OzzySlabReader({ manifestStore: ledgeredManifestStore(ledger, p2p, 'reader'), mesh: rMesh, route: 'mesh-only' });
  const got = await reader.downloadFile(up.linkText);
  expect(got, `failure: ${reader.lastFailure}`).not.toBeNull();
  guardObservations(ledger, net);

  // ── LE がリンクを入手した (公開されたリーク / 記者の端末の押収): Manifest を P2P から取り、置き場所の URL を知る ──
  const body = parseOzzyLinkV3(up.linkText)!;
  const manifest = deserializeOzzyManifestV4((await p2p.get(body))!)!;
  const urls = new Set(manifest.stripes.flatMap(s => s.locations.map(l => l.url)));
  const stats = { uJobs: uMesh.stats.jobs, uAttempts: uMesh.stats.middlesUsed.size, uRanges: uMesh.stats.attempts, rRanges: rMesh.stats.attempts, rMiddles: rMesh.stats.middlesUsed.size, uMiddles: uMesh.stats.middlesUsed.size };
  uMesh.destroy();
  rMesh.destroy();
  return { up, manifest, body, urls, stats, slabs: up.receipts.length };
}

describe('Ozzy 対 法執行型の攻撃者', () => {
  it('1. 観測台帳: 1 回上げて 1 回取ったときに、各観測点が記録しうるもの (リンクを入手した LE が照合)', async () => {
    const ledger = new Ledger();
    const cluster = new MemoryOverseasLockerCluster();
    // 参加者の Worker 20 台、うち LE が 5 台 (25%)
    const { pool } = await buildPool(15, 5);
    const net = await buildOnionNet(ledger, cluster, pool, 6);
    const { body, urls } = await roundTrip(ledger, net, 100 * MiB);
    net.stop();

    const matches = (o: Obs) =>
      (o.what.startsWith('p2p') && o.key === body) ||
      (o.what.startsWith('relay') && (urls.has(o.key) || [...urls].some(u => o.extra?.includes(u)))) ||
      ((o.what === 'm1-fetch' || o.what === 'm1-job') && urls.has(o.key));

    const exposures: Record<string, Set<string>> = {};
    const note = (point: string, who: string) => { (exposures[point] ??= new Set()).add(who); };
    for (const o of ledger.rows) {
      if (!matches(o)) continue;
      const pointClass = o.at === 'p2p-holder' ? 'P2P の Manifest の保持者'
        : o.at.startsWith('worker:') ? (isLE(o.at.slice(7)) ? 'LE の中継 Worker' : '他の参加者の中継 Worker (LE 以外)')
          : o.at.startsWith('node:guard') ? 'Guard' : 'M1';
      note(pointClass, o.client);
    }
    const sum = (rows: Obs[]) => rows.reduce((a, o) => a + (o.bytes ?? 0), 0);
    const guardUp = ledger.rows.filter(o => o.what === 'guard-up');
    const readerReplies = ledger.rows.filter(o => o.at === 'node:guard-of-reader' && o.what === 'guard-reply');
    const workerClients = new Set(ledger.rows.filter(o => o.at.startsWith('worker:')).map(o => o.client));
    const m1Jobs = ledger.rows.filter(o => o.what === 'm1-job' && urls.has(o.key));

    console.log('\n=== 1. 観測台帳 (100 MiB 相当を 1 回上げ、別の端末で 1 回取る。中継 Worker 20 台のうち LE 5 台) ===');
    console.log(`リンクから LE が分かるもの: Manifest (P2P) → 置き場所の URL ${urls.size} 個`);
    for (const [point, who] of Object.entries(exposures)) console.log(`  ${point.padEnd(30)} → リンクと照合できる記録の主: ${[...who].join(', ')}`);
    console.log(`  中継 Worker を使った主: ${[...workerClients].join(', ')} (告発者・読み手は Worker を使わない)`);
    console.log(`  M1 が置いた Slab: ${m1Jobs.length} 本 (M1 に見える相手は Guard だけ)`);
    console.log(`  告発者の Guard が見た本体: ${(sum(guardUp) * SCALE / MiB).toFixed(0)} MiB 相当 (本番換算。中身・置き先は見えない)`);
    console.log(`  読み手の Guard が見た応答: ${(sum(readerReplies) * SCALE / MiB).toFixed(0)} MiB 相当`);
    console.log(`  共通の Worker・ディレクトリ: 無し (台帳に記録 0 件)`);

    // ★ 事実の確認 (実装がこう振る舞う)
    expect(workerClients.has('uploader')).toBe(false); // 告発者の IP は中継 Worker に届かない
    expect(workerClients.has('reader')).toBe(false); // 読み手の IP も
    for (const who of Object.values(exposures)) {
      expect(who.has('uploader')).toBe(false); // リンクと照合できる記録に、告発者・読み手は直接は現れない
      expect(who.has('reader')).toBe(false);
    }
    expect(m1Jobs.length).toBeGreaterThan(0);
    expect(guardUp.length).toBeGreaterThan(0);
  }, 300_000);

  it('2. LE の中継 Worker が選ばれる割合 (本物の WorkerPool.pickRelay、2 万回。いまは M1 が中継を選ぶ)', async () => {
    const rows: string[] = [];
    const measure = async (label: string, honest: number, le: number, leAgeMs: number) => {
      const { pool } = await buildPool(honest, le, { leAgeMs });
      let hit = 0;
      const N = 20_000;
      for (let i = 0; i < N; i++) if (isLE(pool.pickRelay()!)) hit++;
      rows.push(`  ${label.padEnd(44)} LE の割合 ${(100 * le / (honest + le)).toFixed(0).padStart(3)}% → 選ばれる ${(100 * hit / N).toFixed(1)}%`);
      return hit / N;
    };
    const fresh = await measure('正直 100 台 + LE 100 台 (現れて 5 分)', 100, 100, 5 * 60_000);
    const aged = await measure('正直 100 台 + LE 100 台 (1 時間以上前から)', 100, 100, 2 * 3600_000);
    await measure('正直 100 台 + LE 10 台 (1 時間以上前から)', 100, 10, 2 * 3600_000);
    await measure('正直 100 台 + LE 400 台 (1 時間以上前から)', 100, 400, 2 * 3600_000);

    const t0 = performance.now();
    const n = 3;
    for (let i = 0; i < n; i++) await NodeIdentity.mine(NODE_ID_POW);
    const perId = (performance.now() - t0) / n;
    console.log('\n=== 2. LE の中継 Worker が選ばれる割合 ===');
    for (const r of rows) console.log(r);
    console.log(`  身元 (広告 1 つ) を作る費用: 約 ${(perId / 1000).toFixed(1)} 秒/個 (この端末)`);
    console.log('  ★ いまは中継 Worker を使うのは M1 だけ。LE の Worker に当たっても、見えるのは M1 の IP');
    expect(fresh).toBeLessThan(aged);
  }, 600_000);

  it('3. 上げ下ろし 1 回あたりの回路の使用回数 (実測) と、特定される確率 (旧構成との比較)', async () => {
    const sizes = [10 * MiB, 100 * MiB, 1024 * MiB];
    const counts: Array<{ size: number; slabs: number; jobs: number; uMiddles: number; uRanges: number; rRanges: number; rMiddles: number; guardUpMiB: number; guardReplyMiB: number }> = [];
    for (const size of sizes) {
      const ledger = new Ledger();
      const cluster = new MemoryOverseasLockerCluster();
      const { pool } = await buildPool(10, 0);
      const net = await buildOnionNet(ledger, cluster, pool, 6);
      const { stats, slabs } = await roundTrip(ledger, net, size);
      net.stop();
      const sumMiB = (pred: (o: Obs) => boolean) => (ledger.rows.filter(pred).reduce((a, o) => a + (o.bytes ?? 0), 0) * SCALE) / MiB;
      counts.push({
        size, slabs, jobs: stats.uJobs, uMiddles: stats.uMiddles, uRanges: stats.uRanges, rRanges: stats.rRanges, rMiddles: stats.rMiddles,
        guardUpMiB: sumMiB(o => o.what === 'guard-up'),
        guardReplyMiB: sumMiB(o => o.at === 'node:guard-of-reader' && o.what === 'guard-reply'),
      });
    }
    console.log('\n=== 3a. 1 回あたりの使用回数 (実測。本番 4 MiB チャンクに換算) ===');
    console.log('  大きさ    | 告発者: Slab / 回路の作業 / 確かめの取得 / 使った M1 | 告発者の Guard を通る本体 | 読み手: 回路の要求 / 使った M1 | 読み手の Guard を通る応答');
    for (const c of counts) {
      console.log(`  ${(c.size / MiB).toFixed(0).padStart(5)} MiB | ${String(c.slabs).padStart(5)} / ${String(c.jobs).padStart(5)} / ${String(c.uRanges).padStart(5)} / ${String(c.uMiddles).padStart(3)}            | ${c.guardUpMiB.toFixed(0).padStart(6)} MiB                | ${String(c.rRanges).padStart(6)} / ${String(c.rMiddles).padStart(3)}             | ${c.guardReplyMiB.toFixed(0)} MiB`);
    }

    const pAtLeastOne = (p: number, n: number) => 1 - Math.pow(1 - p, n);
    // 旧構成: 告発者が自分の IP で中継 Worker を使い、Slab を置くたびに応答 (置き場所の URL) が Worker に見えた。
    //         1 回でも LE の Worker に当たれば、リンクの置き場所と告発者の IP が一致した
    console.log('\n=== 3b. 告発者が特定される確率 ===');
    console.log('  旧 (告発者が直接中継 Worker を使う。LE の Worker が選ばれる割合 p)');
    console.log('  大きさ    | p=5%    p=10%   p=25%   p=50%');
    for (const c of counts) {
      console.log(`  ${(c.size / MiB).toFixed(0).padStart(5)} MiB | ${[0.05, 0.1, 0.25, 0.5].map(p => (100 * pAtLeastOne(p, c.slabs)).toFixed(1).padStart(5) + '% ').join(' ')}`);
    }
    // 新構成: 告発者の IP は自分の Guard にしか届かない。リンクと結び付けるには、告発者の Guard が LE で、
    //         かつ作業を頼んだ M1 に 1 台でも LE (M1 は置き場所の URL を知る) が要る (Tor の 2 ホップと同じ限界)
    console.log('  新 (オニオン回路。隣人・M1 候補のうち LE の割合 f。告発者の Guard が LE かつ作業の M1 に 1 台でも LE)');
    console.log('  大きさ    | f=5%    f=10%   f=25%   f=50%');
    for (const c of counts) {
      const draws = Math.max(1, c.uMiddles);
      console.log(`  ${(c.size / MiB).toFixed(0).padStart(5)} MiB | ${[0.05, 0.1, 0.25, 0.5].map(f => (100 * f * pAtLeastOne(f, draws)).toFixed(1).padStart(5) + '% ').join(' ')}`);
    }
    console.log('\n=== 3c. 読み手が特定される確率 (同じ条件: 読み手の Guard が LE かつ M1 に 1 台でも LE) ===');
    console.log('  大きさ    | f=5%    f=10%   f=25%   f=50%');
    for (const c of counts) {
      const draws = Math.max(1, c.rMiddles);
      console.log(`  ${(c.size / MiB).toFixed(0).padStart(5)} MiB | ${[0.05, 0.1, 0.25, 0.5].map(f => (100 * f * pAtLeastOne(f, draws)).toFixed(1).padStart(5) + '% ').join(' ')}`);
    }
    console.log('\n  ★ 上限は f (自分の Guard が LE である確率)。Guard を信頼できる隣人に固定すれば f はさらに下がる。');
    console.log('  ★ Guard は量を見る: 告発者の Guard には「この隣人が約 2 倍 (RS 32/16) の量を M1 へ送った」ことが見える。');
    for (const c of counts) expect(c.jobs).toBeGreaterThanOrEqual(c.slabs);
  }, 1_200_000);
});

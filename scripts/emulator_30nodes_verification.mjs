/**
 * Oz P2P ネットワーク 30 ノード実動エミュレーター — 一連の流れの検証 (精密版)
 *
 * 本物の Chromium レンダラー (WebRTC) + 本物の WSS トラッカー (EdgeTrackerHub) + 本物の STUN 上で、次を順に回して確かめる。
 * どの段階にも合否の基準と時間の上限があり、要約は実際の結果から作る。1 つでも不合格なら終了コード 1。
 *
 *   1. 起動            Guard 2 台 + 一般ノード (デスクトップ役・ブラウザ役) が全部起動する
 *   2. 収束            孤立 0・各ノードの検証済みの隣人 3 以上。信頼 Guard の無い網では一般ノードも Guard 並みに受け持つ
 *   3. 匿名経路        全ノードでオニオン回路 (自分 → Guard → M1) が組め、leaseSet が行き渡る
 *   4. P2P のファイル   698B / 493KiB / 1MiB を上げる (複製の数も見る)
 *   5. 掲示板          スレ立てが全ノードに届き、スレの中の返信 (別々のノードから 3 件) も全ノードに届く
 *   6. 取得            ウィンドウ (= 別のプロセス) をまたいだ複数のノードが全ファイルを取り、SHA-256 が一致する
 *   7. 後から参加      (a) 新しいノードが追いつきでスレを受け取る
 *                      (b) 全ノードの直近の投稿 (RecentBuffer) を消したあとに来たノードが、保持者からの過去ログで
 *                          スレと返信を受け取り、ファイルも取れる
 *   8. Ozzy            デスクトップ役が M1 経由でロッカーへ上げ、別のノード (ブラウザ役を含む) が M1 経由で取って一致する。
 *                      ロッカーへは main の ozlocker:// (apps/desktop/electron/ozlocker.ts) を通る = デスクトップの直接の経路。
 *                      Guard とブラウザ役 (Worker 未設定) は M1 の役をしない (REFUSED) ので、それに当たっても終わることを確かめる
 *   9. 診断            中継・レート制限・送出の列で捨てたもの、接続の衝突などを数える (合否には入れない)
 *
 * 実行: npx electron scripts/emulator_30nodes_verification.mjs [--nodes=30] [--observe=60] [--ozzy=memory|real|off] [--until=N] [--verbose]
 *   --until=N             段階 N まで進めたら要約へ (問題の段階だけを繰り返し確かめる用)
 *   --ozzy=memory (既定)  main のメモリ上の偽のロッカー (core の MemoryOverseasLockerCluster)。外へは出ない
 *   --ozzy=real           本物の公開ロッカーへ上げる (乱数のファイル。数 MiB)。この端末の IP がロッカーに残る
 *   --ozzy=off            Ozzy の段階を飛ばす
 */

import { app, BrowserWindow, protocol, session } from 'electron';
import { createServer as createHttpsServer } from 'node:https';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';
import * as esbuild from 'esbuild';
import { WebSocketServer } from 'ws';

const require = createRequire(import.meta.url);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');
const CORE_INDEX = path.join(ROOT_DIR, 'packages/core/src/index.ts');

// ── 引数 ──
const args = process.argv.slice(2);
const argOf = (name, def) => args.find(a => a.startsWith(`--${name}=`))?.split('=')[1] ?? def;
const TOTAL_NODES = Number(argOf('nodes', 30));
const OBSERVE_SECONDS = Number(argOf('observe', 60));
const OZZY_MODE = argOf('ozzy', 'memory');
const VERBOSE = args.includes('--verbose');
/** この段階まで進めたら要約へ (問題の段階だけを繰り返し確かめる用)。既定は全部 */
const UNTIL = Number(argOf('until', 99));
/**
 * 画面 (packages/ui) の窓をこの網に参加させる。値は画面だけの開発サーバーの URL
 * (例: apps/desktop で `OZ_RENDERER_ONLY=1 npx vite --port 5199` → --ui=http://localhost:5199/)。
 * 掲示板の段 (5) のあとで開き、トラッカーと STUN を手元のものに設定してから --ui-tour の手順を動かす。
 */
const UI_URL = argOf('ui', null);
/** 画面の窓で動かす手順 (`export async function tour(ctx)` の .mjs)。無ければ各画面を 1 枚ずつ撮るだけ */
const UI_TOUR = argOf('ui-tour', null);
/** 画面の窓のスクリーンショットの置き場 */
const UI_SHOTS = argOf('ui-shots', path.join(os.tmpdir(), 'oz-ui-shots'));
const TRACKER_HOSTNAME = 'ozzy-r2-gatekeeper.jkfujinamis.workers.dev';
const LOCKER_SCHEME = 'ozlocker';
const MAX_RENDERER_WINDOWS = 10;
const GUARDS = 2;

if (!['memory', 'real', 'off'].includes(OZZY_MODE)) {
  console.error(`--ozzy は memory / real / off のどれかです (${OZZY_MODE})`);
  process.exit(2);
}
if (TOTAL_NODES < 8) {
  console.error('--nodes は 8 以上にしてください (取得役・ブラウザ役・後から参加の組み合わせが作れない)');
  process.exit(2);
}

app.commandLine.appendSwitch('disk-cache-size', '1');
app.commandLine.appendSwitch('disable-breakpad');
app.commandLine.appendSwitch('enforce-webrtc-ip-permission-check');
app.commandLine.appendSwitch('ignore-certificate-errors');
// ★ 画面の窓は既定の STUN (Google / Cloudflare) やトラッカーへ行こうとする。--ui のときは外への名前解決をすべて止める
app.commandLine.appendSwitch('host-resolver-rules', [
  `MAP ${TRACKER_HOSTNAME} 127.0.0.1`,
  'MAP ozzy-tracker.jkfujinami.deno.net 127.0.0.1:1',
  ...(UI_URL && OZZY_MODE !== 'real' ? ['MAP * ~NOTFOUND, EXCLUDE localhost'] : []),
].join(', '));
app.commandLine.appendSwitch('disable-features', 'LimitOpenUDPSockets');
// Chromium の内部ログ (WebRTC の ERROR 行など) で結果が埋もれないようにする
if (!VERBOSE) app.commandLine.appendSwitch('log-level', '3');

// ★ 独自スキームの登録は ready より前 (apps/desktop/electron/ozlocker.ts の registerOzLockerScheme と同じ権限)
protocol.registerSchemesAsPrivileged([{
  scheme: LOCKER_SCHEME,
  privileges: { standard: true, secure: true, supportFetchAPI: true, corsEnabled: true, stream: true },
}]);

let httpsServer;
let edgeHub;
let stunServer;
let wss;
const windows = [];

// ── 合否の記録 ──
const results = [];
function check(name, ok, detail = '') {
  results.push({ name, ok: Boolean(ok), detail });
  console.log(`  ${ok ? '[PASS]' : '[FAIL]'} ${name}${detail ? ` — ${detail}` : ''}`);
  return Boolean(ok);
}
function note(text) {
  console.log(`  [INFO] ${text}`);
}
function phase(title) {
  console.log('\n================================================================================');
  console.log(title);
  console.log('================================================================================');
}

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

/** 条件が満たされるまで待つ。満たされたら true、時間切れなら false */
async function waitFor(cond, timeoutMs, intervalMs = 1000, onTick) {
  const end = Date.now() + timeoutMs;
  for (;;) {
    const v = await cond();
    if (v) return true;
    if (Date.now() >= end) return false;
    if (onTick) await onTick();
    await sleep(intervalMs);
  }
}

// 画面の console の行。決まった騒がしい行は数えるだけにする
const consoleCounts = new Map();
const NOISY = [
  ['remoteDescription not set yet', 'ICE 候補の先着 (バッファした)'],
  ['allowSameOriginHops is explicitly enabled', '同一端末の経路を許可 (エミュレーター)'],
  ["Failed to set remote answer sdp: Called in wrong state: stable", '接続の衝突 (双方が同時に申し込み)'],
  ['Worker error', 'PoW の Worker が起動しない (画面側で計算)'],
];

// ── トラッカーと STUN ──

function generateSelfSignedCert(tmpDir) {
  const keyPath = path.join(tmpDir, 'key.pem');
  const certPath = path.join(tmpDir, 'cert.pem');
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', keyPath, '-out', certPath, '-days', '1',
    '-subj', `/CN=${TRACKER_HOSTNAME}`,
    '-addext', `subjectAltName=DNS:${TRACKER_HOSTNAME},IP:127.0.0.1`,
  ], { stdio: 'ignore' });
  return { key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) };
}

async function startRealTracker(tmpDir) {
  const trackerBundlePath = path.join(tmpDir, 'tracker-bundle.cjs');
  await esbuild.build({
    entryPoints: [path.join(ROOT_DIR, 'packages/tracker/src/index.ts')],
    bundle: true, outfile: trackerBundlePath, platform: 'node', format: 'cjs', loader: { '.wasm': 'binary' }, logLevel: 'warning',
  });
  const { EdgeTrackerHub, StunServer } = require(trackerBundlePath);

  stunServer = new StunServer(Date.now, { perIpPerSec: 10 * Math.max(1, TOTAL_NODES) });
  const stunPort = await stunServer.listen(0, '127.0.0.1');

  httpsServer = createHttpsServer(generateSelfSignedCert(tmpDir), (_req, res) => {
    res.writeHead(200);
    res.end('ok');
  });
  edgeHub = new EdgeTrackerHub();
  wss = new WebSocketServer({ server: httpsServer, path: '/ws' });
  wss.on('connection', (ws, req) => {
    const remoteAddr = req.socket.remoteAddress ?? '127.0.0.1';
    const hostHeader = req.headers['host'] ?? TRACKER_HOSTNAME;
    if (!edgeHub.canAccept(remoteAddr)) {
      ws.close(1013, 'Try Again Later');
      return;
    }
    edgeHub.acceptConnection(ws, hostHeader, remoteAddr);
    ws.on('message', (data, isBinary) => {
      if (!isBinary) {
        ws.close(1003, 'binary only');
        return;
      }
      const buf = data instanceof ArrayBuffer
        ? new Uint8Array(data)
        : ArrayBuffer.isView(data) ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength) : new Uint8Array(Buffer.from(data));
      void edgeHub.handleMessage(ws, buf);
    });
    ws.on('close', () => edgeHub.handleClose(ws));
    ws.on('error', () => edgeHub.handleClose(ws));
  });

  await new Promise(resolve => httpsServer.listen(0, '127.0.0.1', resolve));
  const port = httpsServer.address().port;
  return {
    stunUrl: `stun:127.0.0.1:${stunPort}`,
    trackerUrl: `wss://${TRACKER_HOSTNAME}:${port}/ws`,
    getSessionCount: () => edgeHub.sessionCount,
  };
}

// ── main 側: ロッカーへの口 (ozlocker://) ──

async function buildMainHelpers(tmpDir) {
  const entry = path.join(tmpDir, 'main-helpers-entry.ts');
  fs.writeFileSync(entry, [
    `export { handleLockerRequest, plainUserAgent } from ${JSON.stringify(path.join(ROOT_DIR, 'apps/desktop/electron/ozlocker.ts'))};`,
    `export { MemoryOverseasLockerCluster } from ${JSON.stringify(path.join(ROOT_DIR, 'packages/core/src/ozzy/OverseasLockers.ts'))};`,
  ].join('\n'), 'utf8');
  const out = path.join(tmpDir, 'main-helpers.cjs');
  await esbuild.build({
    entryPoints: [entry], bundle: true, outfile: out, platform: 'node', format: 'cjs',
    external: ['electron'], loader: { '.wasm': 'binary' }, alias: { '@oz/core': CORE_INDEX }, logLevel: 'warning',
  });
  return require(out);
}

/** デスクトップの main と同じ受け口 (handleLockerRequest: 許可したロッカーだけ・Cookie なし) を付け、行き先を数える */
function installLockerGateway(helpers) {
  let cluster = null;
  let egress;
  if (OZZY_MODE === 'real') {
    const ses = session.fromPartition('ozzy-lockers', { cache: false });
    ses.setUserAgent(helpers.plainUserAgent(ses.getUserAgent()));
    egress = (url, init) => ses.fetch(url, init);
  } else {
    cluster = new helpers.MemoryOverseasLockerCluster();
    egress = (url, init) => {
      const { cache: _cache, ...rest } = init;
      return cluster.handleFetch(new Request(url, rest));
    };
  }
  const counters = { requests: 0, refused: 0, byHost: new Map() };
  const handler = async (req) => {
    counters.requests++;
    let host = '?';
    try { host = new URL(req.url).hostname; } catch { /* 数えるだけ */ }
    counters.byHost.set(host, (counters.byHost.get(host) ?? 0) + 1);
    const res = await helpers.handleLockerRequest(req, egress);
    if (res.status === 403) counters.refused++;
    return res;
  };
  session.defaultSession.protocol.handle(LOCKER_SCHEME, handler);
  // 画面の窓 (--ui) は自分のセッションで動くので、そこにも同じ受け口を付ける
  return { cluster, counters, attach: (ses) => ses.protocol.handle(LOCKER_SCHEME, handler) };
}

/** 画面の窓にデスクトップ版の印 (ozzyDirect) だけを渡す preload。ファイル共有はデスクトップと同じ ozlocker:// を通る */
function writeUiPreload(dir) {
  const file = path.join(dir, 'ui-preload.cjs');
  fs.writeFileSync(file, "require('electron').contextBridge.exposeInMainWorld('electronAPI', { ozzyDirect: true });\n");
  return file;
}

// ── 画面側 (レンダラー) のノード群 ──

function rendererEntrySource() {
  return `
import {
  OzNode, IndexedDBStore, KeyManager, createSchemeLockerTransport,
  OverseasMultiLockerCoordinator, createOnionLockerAdapters, OZZY_JOB_LOCKERS,
} from ${JSON.stringify(CORE_INDEX)};

// 画面の公開板「雑談」と同じ板 (packages/ui の publicBoardKey と同じ導出)。--ui の窓からそのまま見える
const BOARD_ID = 'zatsudan';
// ★ 鍵の導出は sodium の準備が済んでから (読み込みの時点ではまだ使えない)。ノードを作ったあとに初めて呼ぶ
let boardKeyCache = null;
function boardKey() {
  if (!boardKeyCache) boardKeyCache = KeyManager.cryptoHash(new TextEncoder().encode('OZ/v1/public-board/' + BOARD_ID)).slice(0, 32);
  return boardKeyCache;
}
const instances = new Map();

function slotOf(id) {
  if (!instances.has(id)) instances.set(id, { node: null, phase: 'idle', errorMsg: null, kind: null, events: { connect: 0, verified: 0, disconnect: 0 }, coordinators: new Map() });
  return instances.get(id);
}
function need(id) {
  const s = instances.get(id);
  if (!s || !s.node) throw new Error('node not found: ' + id);
  return s;
}
function randomBytes(n) {
  const out = new Uint8Array(n);
  for (let o = 0; o < n; o += 65536) crypto.getRandomValues(out.subarray(o, Math.min(n, o + 65536)));
  return out;
}
async function sha256hex(u8) {
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', u8));
  return Array.from(h).map(b => b.toString(16).padStart(2, '0')).join('');
}
function timeout(p, ms, onTimeout) {
  let t;
  return Promise.race([
    p.finally(() => clearTimeout(t)),
    new Promise((_, rej) => { t = setTimeout(() => { try { onTimeout && onTimeout(); } catch (e) {} rej(new Error('timeout ' + ms + 'ms')); }, ms); }),
  ]);
}
/**
 * leaseSet の SYNC のやり取りを時刻つきで記録する (診断用)。頼んだ相手・応答の件数・頼まれた相手・2 回目の SYNC。
 * ★ 送受信の口を差し替えるだけで、動きは変えない
 */
function traceLeaseSync(slot, node) {
  const log = slot.leaseTrace = [];
  const push = (ev, peer, extra) => { if (log.length < 200) log.push(Object.assign({ at: Date.now(), ev, peer: String(peer).slice(0, 8) }, extra || {})); };
  const pm = node.peerManager;
  const send = pm.sendMessage.bind(pm);
  pm.sendMessage = (peerId, type, msg) => {
    if (type === 0x71) push('req→', peerId);
    return send(peerId, type, msg);
  };
  const router = node.storage && node.storage.router;
  if (!router) return;
  const onSync = router.handleSync.bind(router);
  router.handleSync = (peerId, msg) => {
    const before = node.storage.leaseSets.size;
    onSync(peerId, msg);
    push('←sync', peerId, { n: Array.isArray(msg && msg.leaseSets) ? msg.leaseSets.length : -1, size: before + '→' + node.storage.leaseSets.size, awaited: router.awaiting.has(peerId) });
  };
  const onReq = router.handleSyncReq.bind(router);
  router.handleSyncReq = (peerId) => {
    const had = router.sessions.has(peerId);
    const p = pm.peers.get(peerId);
    const last = router.lastSyncServed.get(peerId);
    const why = !p || !p.isConnected || !p.isVerified ? 'unverified' : had ? 'in-session'
      : last !== undefined && Date.now() - last < router.opts.syncMinIntervalMs ? 'too-soon'
      : router.sessions.size >= 8 ? 'busy' : null;
    onReq(peerId);
    push('←req', peerId, { why: why ?? 'served', store: node.storage.leaseSets.size });
  };
  const onLs = router.handleLeaseSet.bind(router);
  let floods = 0;
  router.handleLeaseSet = (peerId, msg) => {
    const before = node.storage.leaseSets.size;
    onLs(peerId, msg);
    if (node.storage.leaseSets.size > before && ++floods <= 40) push('←flood+', peerId, { size: node.storage.leaseSets.size });
  };
}

function coordinatorFor(slot) {
  let c = slot.coordinators.get('ozzy');
  if (!c) {
    // 画面 (OzzyVaultView) の「実機のロッカー」と同じ組み方: 置くのも取るのも回路の M1、Manifest は P2P のファイル保管
    c = new OverseasMultiLockerCoordinator({
      manifestStore: slot.node.ozzyManifestStore,
      adapters: createOnionLockerAdapters(slot.node.ozzyMesh, OZZY_JOB_LOCKERS),
      chunkBytes: slot.chunkBytes,
      mesh: slot.node.ozzyMesh,
      route: 'mesh-only',
    });
    slot.coordinators.set('ozzy', c);
  }
  return c;
}

const pool = {
  async create(id, cfg) {
    const slot = slotOf(id);
    slot.phase = 'creating';
    slot.kind = cfg.kind;
    try {
      const common = {
        db: new IndexedDBStore(cfg.dbName), passphrase: cfg.passphrase, autoStart: false, allowSameOriginHops: true,
        guardOptions: { adaptiveOpen: true }, iceServers: cfg.iceServers, storage: { defaultSlots: cfg.slots },
      };
      let node;
      if (cfg.kind === 'guard') {
        node = await OzNode.create(Object.assign({}, common, { role: 'guard', identityMode: 'persistent', trackerUrl: cfg.trackerUrl }));
      } else {
        // デスクトップ役は main の ozlocker:// でロッカーへ直接つなぐ (Worker なし)。ブラウザ役は Worker 未設定 = M1 の役をしない
        const ozzy = cfg.kind === 'desktop' ? { ozzy: { lockerTransport: createSchemeLockerTransport() } } : {};
        node = await OzNode.create(Object.assign({}, common, ozzy));
        await node.setTrackerUrl(cfg.trackerUrl);
      }
      node.peerManager.on('peer:connect', () => { slot.events.connect++; });
      node.peerManager.on('peer:verified', () => { slot.events.verified++; });
      node.peerManager.on('peer:disconnect', () => { slot.events.disconnect++; });
      traceLeaseSync(slot, node);
      slot.node = node;
      slot.phase = 'starting';
      await node.start();
      slot.phase = 'running';
      return { peerId: node.peerId };
    } catch (err) {
      slot.phase = 'error';
      slot.errorMsg = err instanceof Error ? err.message : String(err);
      throw err;
    }
  },

  status(id) {
    const slot = slotOf(id);
    const node = slot.node;
    if (!node) return { phase: slot.phase, errorMsg: slot.errorMsg, degree: 0, verified: 0, leaseSets: 0, circuitReady: false };
    const c = node.circuit;
    return {
      phase: slot.phase, errorMsg: slot.errorMsg, kind: slot.kind, peerId: node.peerId.slice(0, 8),
      degree: node.degree, verified: node.peerManager.verifiedPeers.length, maxDegree: node.peerManager.maxDegree,
      servesAsOpenGuard: node.servesAsOpenGuard, guardMode: node.guardStatus.mode,
      leaseSets: node.storage ? node.storage.leaseSets.size : 0,
      circuitReady: c.routeReady, middles: c.middleCandidateCount, guardId: c.currentGuardHop ? c.currentGuardHop.peerId.slice(0, 8) : null,
      ozzy: { direct: node.ozzyDirect, fetcher: node.ozzyFetcherEnabled, meshReady: node.ozzyMesh.ready },
      events: slot.events,
    };
  },

  async uploadP2P(id, size, name, ms) {
    const slot = need(id);
    const data = randomBytes(size);
    const hash = await sha256hex(data);
    let last = null;
    const t0 = performance.now();
    const up = slot.node.uploadFile(data, { name, mime: 'application/octet-stream' }, p => { last = p; });
    try {
      const token = await timeout(up.link, ms, () => up.cancel());
      return {
        ok: true, token, hash, size, ms: Math.round(performance.now() - t0),
        progress: last ? { chunksPlaced: last.chunksPlaced, replicasAcked: last.replicasAcked, degradedChunks: last.degradedChunks } : null,
      };
    } catch (e) {
      return { ok: false, error: String((e && (e.code || e.message)) || e), replicas: e && e.replicas, ms: Math.round(performance.now() - t0) };
    }
  },

  async downloadP2P(id, token, ms) {
    const slot = need(id);
    const t0 = performance.now();
    const dl = slot.node.downloadFile(token);
    try {
      const parts = [];
      await timeout((async () => { for await (const c of dl) parts.push(c); })(), ms, () => dl.cancel());
      const total = parts.reduce((a, c) => a + c.length, 0);
      const merged = new Uint8Array(total);
      let o = 0;
      for (const c of parts) { merged.set(c, o); o += c.length; }
      return { ok: true, size: total, hash: await sha256hex(merged), ms: Math.round(performance.now() - t0) };
    } catch (e) {
      return { ok: false, error: String((e && (e.code || e.message)) || e), ms: Math.round(performance.now() - t0) };
    }
  },

  async activateBoard(id) {
    await need(id).node.boardOrchestrator.activate(BOARD_ID, boardKey());
    return true;
  },
  async postThread(id, title) {
    const node = need(id).node;
    await node.boardOrchestrator.activate(BOARD_ID, boardKey());
    return await node.boardOrchestrator.submitThread(BOARD_ID, boardKey(), title);
  },
  boardHas(id, title) {
    const s = instances.get(id);
    return !!(s && s.node && s.node.boardOrchestrator.getThreads().some(t => t.content === title));
  },
  async activateThread(id, threadId) {
    await need(id).node.threadOrchestrator.activate(BOARD_ID, threadId, boardKey());
    return true;
  },
  async reply(id, text) {
    await need(id).node.threadOrchestrator.submitReply(text);
    return true;
  },
  threadHasAll(id, texts) {
    const s = instances.get(id);
    if (!s || !s.node) return false;
    const have = new Set(s.node.threadOrchestrator.getPosts().map(p => p.content));
    return texts.every(t => have.has(t));
  },
  clearRecent(id) {
    const node = need(id).node;
    const n = node.recent.size;
    node.recent.clear();
    return n;
  },
  historyStats(id) {
    return Object.assign({}, need(id).node.history.stats);
  },
  leaseDiag(id) {
    const node = need(id).node;
    const st = node.storage.router.stats;
    return {
      size: node.storage.leaseSets.size, published: st.published, accepted: st.accepted, stale: st.stale,
      tooSoon: st.tooSoon, deferred: st.deferred, rejected: Object.fromEntries(st.rejected), syncRetries: st.syncRetries, secondPass: st.secondPass,
      guardId: node.circuit.currentGuardHop ? node.circuit.currentGuardHop.peerId.slice(0, 8) : null,
      pinned: node.dandelion.getPinnedGuardId() ? node.dandelion.getPinnedGuardId().slice(0, 8) : null,
      verified: node.peerManager.verifiedPeers.length,
      requested: Array.from(node.storage.router.requested).map(p => p.slice(0, 8)),
      synced: Array.from(node.storage.router.synced).map(p => p.slice(0, 8)),
      secondPassDone: node.storage.router.secondPassDone,
      trace: need(id).leaseTrace || [],
    };
  },

  async ozzyUpload(id, size, chunkBytes, ms) {
    const slot = need(id);
    slot.chunkBytes = chunkBytes;
    const data = randomBytes(size);
    const hash = await sha256hex(data);
    const t0 = performance.now();
    try {
      const r = await timeout(coordinatorFor(slot).uploadFile({ source: data, fileName: 'ozzy-test.bin', mimeType: 'application/octet-stream' }), ms);
      return {
        ok: true, link: r.linkText, hash, size, ms: Math.round(performance.now() - t0),
        lockers: Array.from(new Set(r.receipts.map(x => x.lockerId))), slabs: r.receipts.length,
      };
    } catch (e) {
      return { ok: false, error: String((e && e.message) || e), ms: Math.round(performance.now() - t0) };
    }
  },
  async ozzyDownload(id, link, ms) {
    const slot = need(id);
    slot.chunkBytes = slot.chunkBytes || 64 * 1024;
    const c = coordinatorFor(slot);
    const t0 = performance.now();
    try {
      const r = await timeout(c.downloadFile(link), ms);
      if (!r) return { ok: false, error: 'download failed: ' + JSON.stringify(c.lastDownloadFailure), ms: Math.round(performance.now() - t0) };
      return { ok: true, size: r.data.length, hash: await sha256hex(r.data), ms: Math.round(performance.now() - t0) };
    } catch (e) {
      return { ok: false, error: String((e && e.message) || e), ms: Math.round(performance.now() - t0) };
    }
  },
  ozzyStats(id) {
    const node = need(id).node;
    const m = node.ozzyMesh.stats;
    const x = node.ozzyExit.stats;
    return {
      mesh: { ranges: m.ranges, attempts: m.attempts, ok: m.ok, busy: m.busy, failed: m.failed, rejected: m.rejected, jobs: m.jobs, jobsOk: m.jobsOk, middles: m.middlesUsed.size },
      exit: { requests: x.requests, rejected: x.rejected, jobs: x.jobs, jobsDone: x.jobsDone },
    };
  },

  netStats(id) {
    const node = need(id).node;
    let senderDropped = 0;
    for (const p of node.peerManager.peers.values()) senderDropped += (p.chunkedSender && p.chunkedSender.dropped) || 0;
    return {
      relayDropped: Object.assign({}, node.tunnelRelay.stats.dropped),
      rateDropped: Object.fromEntries(node.rateLimiter.dropped),
      senderDropped,
      historyBadChunks: node.history.stats.badChunks,
    };
  },

  async stop(id) {
    const s = instances.get(id);
    if (s && s.node) await s.node.stop();
    return true;
  },
};

window.emulatorCall = async (method, args) => {
  try {
    return { ok: true, value: await pool[method].apply(null, args) };
  } catch (e) {
    return { ok: false, error: String((e && (e.code || e.message)) || e) };
  }
};
`;
}

async function buildRendererBundle(tmpDir) {
  const entryPath = path.join(tmpDir, 'renderer-entry.js');
  const bundlePath = path.join(tmpDir, 'renderer-bundle.js');
  const htmlPath = path.join(tmpDir, 'node.html');
  fs.writeFileSync(entryPath, rendererEntrySource(), 'utf8');
  await esbuild.build({
    entryPoints: [entryPath], bundle: true, outfile: bundlePath, platform: 'browser', format: 'iife', target: 'chrome120',
    loader: { '.wasm': 'binary' }, logLevel: 'warning',
  });
  fs.writeFileSync(htmlPath, '<!DOCTYPE html><html><head><meta charset="utf-8"></head><body><script src="./renderer-bundle.js"></script></body></html>', 'utf8');
  return htmlPath;
}

async function windowFor(htmlPath, poolIndex) {
  if (windows[poolIndex]) return windows[poolIndex];
  const win = new BrowserWindow({ show: false, webPreferences: { nodeIntegration: false, contextIsolation: false, backgroundThrottling: false } });
  if (typeof win.webContents.setWebRTCIPHandlingPolicy === 'function') win.webContents.setWebRTCIPHandlingPolicy('default_public_interface_only');
  windows[poolIndex] = win;
  win.webContents.on('console-message', (_event, level, message) => {
    if (level < 2 || message.includes('Electron Security Warning')) return;
    const noisy = NOISY.find(([needle]) => message.includes(needle));
    if (noisy) {
      consoleCounts.set(noisy[1], (consoleCounts.get(noisy[1]) ?? 0) + 1);
      if (!VERBOSE) return;
    }
    console.log(`    [Win#${poolIndex}] ${message}`);
  });
  await win.loadFile(htmlPath);
  return win;
}

/** ノード 1 台の操作口。call は画面側の失敗も { ok: false } で返す。時間の上限を超えたら { ok: false, error: 'timeout' } */
async function handleFor(htmlPath, index, kind, label) {
  const poolIndex = index % MAX_RENDERER_WINDOWS;
  const win = await windowFor(htmlPath, poolIndex);
  const slotId = `slot_${index}`;
  const call = async (method, callArgs = [], timeoutMs = 120_000) => {
    let t;
    const js = `window.emulatorCall(${JSON.stringify(method)}, ${JSON.stringify([slotId, ...callArgs])})`;
    try {
      return await Promise.race([
        win.webContents.executeJavaScript(js).catch(err => ({ ok: false, error: `script failed: ${err?.message ?? err}` })),
        new Promise(resolve => { t = setTimeout(() => resolve({ ok: false, error: `timeout ${timeoutMs}ms (${method})` }), timeoutMs); }),
      ]);
    } finally {
      clearTimeout(t);
    }
  };
  const value = async (method, callArgs, timeoutMs) => {
    const r = await call(method, callArgs, timeoutMs);
    if (!r.ok) throw new Error(`${label}.${method}: ${r.error}`);
    return r.value;
  };
  return { index, kind, label, poolIndex, slotId, call, value };
}

const kindOfClient = (i) => (i % 3 === 0 ? 'browser' : 'desktop');
const fmtMs = (ms) => (ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${ms}ms`);
const short = (s) => (s.length > 140 ? `${s.slice(0, 110)}…${s.slice(-20)}` : s);

/**
 * 画面の窓を開き、利用規約・パスワード・トラッカー・STUN を済ませてから手順 (--ui-tour) を動かす。
 * ★ 窓は網のノードの 1 台として参加する (画面の P2PProvider がノードを作る)。結果の合否には入れない。
 */
async function runUiTour({ tracker, nodes, threadId, title, replies, lockers, tmpDir }) {
  fs.mkdirSync(UI_SHOTS, { recursive: true });
  const partition = `oz-ui-${Date.now()}`;
  if (lockers && OZZY_MODE !== 'off') lockers.attach(session.fromPartition(partition));
  // ★ 陰になった窓は描画が止まり、capturePage が古い絵を返す。描画を止めず、撮る前に描き直させる
  const win = new BrowserWindow({
    width: 1280, height: 820, show: true,
    webPreferences: {
      partition, backgroundThrottling: false,
      ...(lockers && OZZY_MODE !== 'off' ? { preload: writeUiPreload(tmpDir), sandbox: false } : {}),
    },
  });
  const js = (code) => win.webContents.executeJavaScript(code);
  // 画面の窓のエラー (React の警告・例外など) は手順のあとにまとめて出す
  const uiErrors = [];
  win.webContents.on('console-message', (_e, level, message) => {
    if (level >= 3 && uiErrors.length < 50) uiErrors.push(String(message).slice(0, 300));
  });
  const shot = async (name) => {
    win.moveTop();
    win.webContents.invalidate();
    await js(`new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)))`);
    await sleep(300);
    const file = path.join(UI_SHOTS, `${name}.png`);
    fs.writeFileSync(file, (await win.webContents.capturePage()).toPNG());
    note(`画面: ${file}`);
    return file;
  };
  // ナビの先頭のアイコン文字を除いた文言が完全に一致する要素を押す
  const click = (text) => js(`(() => {
    const norm = (e) => e.textContent.replace(/^[^\\p{L}\\p{N}]+/u, '').trim();
    const el = [...document.querySelectorAll('button, a, [role=button], label')].find(e => norm(e) === ${JSON.stringify(text)});
    if (!el) return false; el.click(); return true;
  })()`);
  const setInput = (selector, value) => js(`(() => {
    const el = document.querySelector(${JSON.stringify(selector)});
    if (!el) return false;
    const set = Object.getOwnPropertyDescriptor(el.constructor.prototype, 'value').set;
    set.call(el, ${JSON.stringify(value)}); el.dispatchEvent(new Event('input', { bubbles: true })); return true;
  })()`);
  const waitText = async (text, ms = 60_000) => waitFor(async () => js(`document.body.innerText.includes(${JSON.stringify(text)})`), ms, 500);
  try {
    await win.loadURL(UI_URL);
    await waitText('同意して始める', 30_000);
    await js(`document.querySelector('label.check input').click()`);
    await click('同意して始める');
    const has = (sel) => js(`!!document.querySelector(${JSON.stringify(sel)})`);
    await waitFor(() => has('input[aria-label="パスワード (確認)"]'), 30_000, 300);
    const pass = 'emulator ui window passphrase 2026';
    await waitFor(async () => {
      await setInput('input[aria-label="パスワード"]', pass);
      await sleep(200);
      await setInput('input[aria-label="パスワード (確認)"]', pass);
      await sleep(200);
      return js(`[...document.querySelectorAll('input[type=password]')].every(e => e.value === ${JSON.stringify(pass)})`);
    }, 10_000, 300);
    await js(`document.querySelector('form').requestSubmit()`);
    if (!(await waitFor(() => has('.side-status'), 90_000, 500))) throw new Error('ロック解除のあとの画面が出ない');
    // ★ STUN・トラッカーを保存すると画面はノードを作り直す (その間はロック画面の「起動中」)。保存のたびに戻るのを待つ
    // ★ トラッカーは localhost で指す: 手元のトラッカーの網でだけ、同じ端末の中継を許す (TrackerUrl.isLoopbackTrackerUrl)
    const ready = async () => {
      await sleep(1500);
      if (!(await waitFor(() => has('.side-status'), 90_000, 500))) throw new Error('ノードの作り直しが終わらない');
    };
    const localTracker = tracker.trackerUrl.replace(TRACKER_HOSTNAME, 'localhost');
    await click('設定');
    await sleep(800);
    await setInput('input[aria-label="STUN サーバー"]', tracker.stunUrl);
    await click('STUN を保存');
    await ready();
    await click('設定');
    await sleep(800);
    await setInput('input[aria-label="トラッカーの URL"]', localTracker);
    await click('保存');
    await ready();
    note(`画面の窓: トラッカー ${localTracker}・STUN ${tracker.stunUrl}。隣人と匿名経路を待つ`);
    await waitFor(async () => js(`(() => { const t = document.querySelector('.side-status')?.innerText ?? ''; return /Peers: [1-9]/.test(t); })()`), 90_000, 1000);
    const ctx = { win, js, click, setInput, waitText, shot, sleep, waitFor, note, nodes, threadId, title, replies, boardId: 'zatsudan', lockers };
    if (UI_TOUR) {
      const mod = await import(pathToFileURL(path.resolve(UI_TOUR)).href);
      await mod.tour(ctx);
    } else {
      for (const [label, name] of [['掲示板', 'board'], ['状態とログ', 'status'], ['ファイル共有', 'vault']]) {
        await click(label);
        await sleep(3000);
        await shot(name);
      }
    }
  } catch (e) {
    note(`画面の窓の手順が失敗: ${e && e.stack || e}`);
    await shot('ui-failure').catch(() => {});
  } finally {
    note(`画面の窓のエラー: ${uiErrors.length} 件`);
    for (const m of uiErrors.slice(0, 15)) console.log(`    ${m}`);
    win.destroy();
  }
}

/** 診断の時刻の基準 (この実行を始めた時刻) */
const RUN_T0 = Date.now();

/** --until で途中まで進めたときの印 (不合格には数えない) */
class StopEarly extends Error {}

/** leaseSet の行き渡り方をノードごとに出す (参加した順・1 ホップ目・受け付けた数と断った理由) */
async function printLeaseDiag(list, names = null, all = list) {
  const rows = await Promise.all(all.map(n => n.call('leaseDiag', [], 10_000).then(r => ({ n, d: r.ok ? r.value : null }))));
  const who = new Map(names ?? []);
  const nameOf = (p) => (who.has(p) ? `${who.get(p)}(${p})` : p);
  const t0 = RUN_T0;
  for (const { n, d } of rows) {
    if (!d || !list.includes(n)) continue;
    console.log(`    #${String(n.index).padStart(2)} ${n.label.padEnd(11)} leaseSets=${String(d.size).padStart(2)} published=${d.published} accepted=${d.accepted} stale=${d.stale} tooSoon=${d.tooSoon} deferred=${d.deferred} rejected=${JSON.stringify(d.rejected)} syncRetries=${d.syncRetries} secondPass=${d.secondPass} pinned=${nameOf(d.pinned)} verified=${d.verified}`);
    // 遅れたノード (names あり) は SYNC のやり取りを時刻つきで出す (相手側でその端末の要求をどう扱ったかも混ぜる)
    if (names) {
      const me = [...who.entries()].find(([, label]) => label === n.label)?.[0];
      console.log(`       頼んだ相手=${d.requested.map(nameOf).join(',')} 応答の来た相手=${d.synced.map(nameOf).join(',')} 2 回目=${d.secondPassDone}`);
      const events = d.trace.map(e => ({ ...e, side: '' }));
      for (const o of rows) {
        if (!o.d || o.n === n) continue;
        for (const e of o.d.trace) if (e.peer === me && e.ev === '←req') events.push({ ...e, ev: '相手が受けた', peer: o.d.self ?? o.n.label, side: o.n.label });
      }
      events.sort((a, b) => a.at - b.at);
      for (const e of events) {
        const { at, ev, peer, side, ...rest } = e;
        console.log(`       ${String(((at - t0) / 1000).toFixed(1)).padStart(6)}s ${ev.padEnd(8)} ${side || nameOf(peer)} ${Object.keys(rest).length ? JSON.stringify(rest) : ''}`);
      }
    }
  }
}

// ── 本体 ──

app.whenReady().then(async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'oz-emulator-30nodes-'));
  const runId = Date.now();
  const nodes = [];
  let exitCode = 1;
  try {
    console.log('================================================================================');
    console.log('Oz P2P エミュレーター: 一連の流れの検証');
    console.log(`- ノード: ${TOTAL_NODES} (Guard ${GUARDS} + 一般 ${TOTAL_NODES - GUARDS}。一般は 3 台に 1 台がブラウザ役 = Worker 未設定)`);
    console.log(`- トラッカー: EdgeTrackerHub (WSS) / STUN: 組み込み / Ozzy のロッカー: ${OZZY_MODE}`);
    console.log('================================================================================');
    if (OZZY_MODE === 'real') note('--ozzy=real: 本物の公開ロッカーへ乱数のファイルを上げます (この端末の IP がロッカーに残ります)');

    const tracker = await startRealTracker(tmpDir);
    const helpers = await buildMainHelpers(tmpDir);
    const lockers = installLockerGateway(helpers);
    const htmlPath = await buildRendererBundle(tmpDir);
    console.log(`[Tracker] ${tracker.trackerUrl} (STUN ${tracker.stunUrl})`);

    const createConfig = (index, kind) => ({
      dbName: `oz_emu_${runId}_${index}`, passphrase: `emulator-passphrase-${index}`,
      trackerUrl: tracker.trackerUrl, iceServers: [tracker.stunUrl], kind, slots: kind === 'guard' ? 4 : 1,
    });
    const statusAll = (list = nodes) => Promise.all(list.map(n => n.call('status', [], 15_000).then(r => (r.ok ? r.value : { phase: 'unreachable' }))));

    // ── 1. 起動 ──
    phase('1. 起動');
    const spawnT0 = Date.now();
    for (let i = 0; i < TOTAL_NODES; i++) {
      const kind = i < GUARDS ? 'guard' : kindOfClient(i);
      const label = i < GUARDS ? `Guard#${i}` : `${kind === 'browser' ? 'Browser' : 'Desktop'}#${i}`;
      const h = await handleFor(htmlPath, i, kind, label);
      nodes.push(h);
      void h.call('create', [createConfig(i, kind)], 180_000).then(r => { if (!r.ok) console.log(`    ${label} の起動に失敗: ${r.error}`); });
      await sleep(800);
    }
    const allRunning = await waitFor(async () => (await statusAll()).every(s => s.phase === 'running'), 90_000, 2000);
    const st1 = await statusAll();
    check('全ノードが起動する', allRunning, `${st1.filter(s => s.phase === 'running').length}/${TOTAL_NODES} 台 (${fmtMs(Date.now() - spawnT0)})`);
    for (const [i, s] of st1.entries()) if (s.phase !== 'running') note(`${nodes[i].label}: ${s.phase} ${s.errorMsg ?? ''}`);

    // ── 2. 収束 ──
    phase(`2. 収束 (最大 ${OBSERVE_SECONDS} 秒)`);
    let converged = false;
    let last = st1;
    const convT0 = Date.now();
    await waitFor(async () => {
      last = await statusAll();
      const vers = last.map(s => s.verified);
      const isolated = vers.filter(v => v === 0).length;
      const min = Math.min(...vers);
      const avg = (vers.reduce((a, b) => a + b, 0) / vers.length).toFixed(1);
      console.log(`  [t=${String(Math.round((Date.now() - convT0) / 1000)).padStart(3)}s] TrackerWS=${tracker.getSessionCount()} verified(min/avg/max)=${min}/${avg}/${Math.max(...vers)} isolated=${isolated}`);
      converged = isolated === 0 && min >= 3;
      return converged;
    }, OBSERVE_SECONDS * 1000, 3000);
    check('メッシュが収束する (孤立 0・各ノードの検証済みの隣人 3 以上)', converged);
    const clients = last.filter(s => s.kind !== 'guard');
    check('信頼 Guard の無い網では、一般ノードも Guard 並みに受け持つ (次数の上限 64)',
      clients.every(s => s.servesAsOpenGuard && s.maxDegree === 64), `${clients.filter(s => s.servesAsOpenGuard).length}/${clients.length} 台`);

    // ── 3. 匿名経路と leaseSet ──
    phase('3. 匿名経路 (自分 → Guard → M1) と leaseSet');
    const circuitsOk = await waitFor(async () => (last = await statusAll()).every(s => s.circuitReady), 60_000, 2000);
    check('全ノードでオニオン回路が組める', circuitsOk, `${last.filter(s => s.circuitReady).length}/${TOTAL_NODES} 台`);
    const holders = TOTAL_NODES;
    // ★ 後から来た端末は、1 ホップ目の写し (SYNC) と、20 秒ごとの別の隣人の写し (新しいものが無くなるまで・最大 3 回) で埋める。
    //   最後の端末が参加してから 3 回分 (+ 応答待ち) が済む 100 秒を上限にする
    const leaseT0 = Date.now();
    const lagging = new Set();
    const leaseOk = await waitFor(async () => (last = await statusAll()).every(s => s.leaseSets >= holders - 1), 100_000, 5000, async () => {
      const v = last.map(s => s.leaseSets);
      v.forEach((x, i) => { if (x < holders - 1) lagging.add(nodes[i]); });
      console.log(`  [t=${String(Math.round((Date.now() - leaseT0) / 1000)).padStart(3)}s] leaseSets min=${Math.min(...v)} 欠けている端末=${v.filter(x => x < holders - 1).length}`);
    });
    const ls = last.map(s => s.leaseSets);
    check('leaseSet が行き渡る (各ノードが保持者のほぼ全員を知る)', leaseOk,
      `min/max=${Math.min(...ls)}/${Math.max(...ls)} (保持者 ${holders}・回路が揃ってから ${fmtMs(Date.now() - leaseT0)}・遅れた端末 ${lagging.size})`);
    const names = last.map((s, i) => [s.peerId, nodes[i].label]);
    if (!leaseOk || VERBOSE) await printLeaseDiag(nodes);
    if (lagging.size > 0) await printLeaseDiag([...lagging], names, nodes);
    if (UNTIL <= 3) throw new StopEarly();

    // ── 4. P2P のファイル ──
    phase('4. P2P のファイル (保持者のトンネル経由で 5 か所に複製)');
    const uploaderA = nodes[2];
    const uploaderB = nodes.find(n => n.kind === 'browser');
    const files = [];
    for (const [size, name, who] of [[698, 'small-698b.bin', uploaderA], [493 * 1024, 'mid-493k.bin', uploaderA], [1024 * 1024, 'big-1m.bin', uploaderB]]) {
      const r = (await who.call('uploadP2P', [size, name, 180_000], 200_000));
      const v = r.ok ? r.value : { ok: false, error: r.error };
      const detail = v.ok
        ? `${who.label} ${fmtMs(v.ms)} 複製 ${v.progress?.replicasAcked ?? '?'} 件 (チャンク ${v.progress?.chunksPlaced ?? '?'}・複製不足 ${v.progress?.degradedChunks ?? '?'})`
        : `${who.label} ${v.error}${v.replicas ? ` (置けたのは ${v.replicas.placed}/${v.replicas.needed})` : ''}`;
      check(`アップロード ${name} (${size} B)`, v.ok, detail);
      if (v.ok) files.push({ name, size, token: v.token, hash: v.hash });
    }

    // ── 5. 掲示板 ──
    phase('5. 掲示板 (スレ立てと、スレの中の返信)');
    await Promise.all(nodes.map(n => n.call('activateBoard', [], 60_000)));
    const title = `emulator ${runId} ` + files.map(f => f.token).join(' ');
    const threadId = await uploaderA.value('postThread', [title], 60_000);
    note(`スレ ${threadId} を ${uploaderA.label} から立てた`);
    const tPost = Date.now();
    let boardCount = 0;
    const boardOk = await waitFor(async () => {
      const has = await Promise.all(nodes.map(n => n.call('boardHas', [title], 10_000).then(r => r.ok && r.value)));
      boardCount = has.filter(Boolean).length;
      return boardCount === TOTAL_NODES;
    }, 45_000, 1000);
    check('スレ立てが全ノードに届く', boardOk, `${boardCount}/${TOTAL_NODES} 台 (${fmtMs(Date.now() - tPost)})`);

    await Promise.all(nodes.map(n => n.call('activateThread', [threadId], 60_000)));
    const repliers = [nodes[1], nodes[TOTAL_NODES - 1], nodes[7 % TOTAL_NODES]];
    const replies = repliers.map((n, i) => `reply ${i + 1} from ${n.label} ${files[i % Math.max(1, files.length)]?.token ?? ''}`);
    for (const [i, n] of repliers.entries()) await n.value('reply', [replies[i]], 60_000);
    const tReply = Date.now();
    let replyCount = 0;
    const repliesOk = await waitFor(async () => {
      const has = await Promise.all(nodes.map(n => n.call('threadHasAll', [replies], 10_000).then(r => r.ok && r.value)));
      replyCount = has.filter(Boolean).length;
      return replyCount === TOTAL_NODES;
    }, 60_000, 1000);
    check('別々のノードからの返信 3 件が全ノードに届く', repliesOk, `${replyCount}/${TOTAL_NODES} 台 (${fmtMs(Date.now() - tReply)}・${repliers.map(n => n.label).join(' / ')})`);

    if (UI_URL) {
      phase('5b. 画面の窓 (--ui)');
      await runUiTour({ tracker, nodes, threadId, title, replies, lockers, tmpDir });
    }
    if (UNTIL <= 5) throw new StopEarly();

    // ── 6. 取得 ──
    phase('6. 取得 (ウィンドウ = 別のプロセスをまたいだ複数のノード)');
    const downloaderIdx = [0, TOTAL_NODES - 1, 4, 11, 17, 23].filter(i => i < TOTAL_NODES && i !== 2);
    const downloaders = Array.from(new Set(downloaderIdx)).map(i => nodes[i]);
    for (const f of files) {
      const rs = await Promise.all(downloaders.map(n => n.call('downloadP2P', [f.token, 120_000], 140_000).then(r => ({ n, v: r.ok ? r.value : { ok: false, error: r.error } }))));
      const good = rs.filter(({ v }) => v.ok && v.hash === f.hash && v.size === f.size);
      const times = good.map(({ v }) => v.ms);
      check(`取得 ${f.name}: 全員が取れて SHA-256 が一致`, good.length === rs.length,
        `${good.length}/${rs.length} 台${times.length ? ` (${fmtMs(Math.min(...times))}〜${fmtMs(Math.max(...times))})` : ''}`);
      for (const { n, v } of rs) if (!(v.ok && v.hash === f.hash)) note(`${n.label}: ${v.ok ? `ハッシュ違い size=${v.size}` : v.error}`);
    }

    // ── 7. 後から参加 ──
    phase('7. 後から参加');
    const lateA = await handleFor(htmlPath, TOTAL_NODES, 'desktop', 'LateA');
    nodes.push(lateA);
    await lateA.value('create', [createConfig(TOTAL_NODES, 'desktop')], 180_000);
    await lateA.value('activateBoard', [], 60_000);
    const tA = Date.now();
    const lateAOk = await waitFor(async () => (await lateA.call('boardHas', [title], 10_000)).value === true, 60_000, 1000);
    check('(a) 新しいノードがスレを受け取る (追いつき・直近の投稿)', lateAOk, fmtMs(Date.now() - tA));

    const cleared = await Promise.all(nodes.map(n => n.call('clearRecent', [], 10_000).then(r => (r.ok ? r.value : 0))));
    note(`全 ${nodes.length} 台の直近の投稿 (RecentBuffer) を消した (合計 ${cleared.reduce((a, b) => a + b, 0)} 件)。以後、過去の投稿は保持者からしか取れない`);
    const lateB = await handleFor(htmlPath, TOTAL_NODES + 1, 'desktop', 'LateB');
    nodes.push(lateB);
    await lateB.value('create', [createConfig(TOTAL_NODES + 1, 'desktop')], 180_000);
    await waitFor(async () => {
      const s = (await lateB.call('status', [], 10_000)).value;
      return s && s.circuitReady && s.leaseSets >= holders - 1;
    }, 60_000, 1000);
    await lateB.value('activateBoard', [], 60_000);
    const tB = Date.now();
    const lateBBoard = await waitFor(async () => (await lateB.call('boardHas', [title], 10_000)).value === true, 90_000, 1000);
    await lateB.value('activateThread', [threadId], 60_000);
    const lateBReplies = await waitFor(async () => (await lateB.call('threadHasAll', [replies], 10_000)).value === true, 90_000, 1000);
    const hs = await lateB.value('historyStats', [], 10_000);
    check('(b) 直近の投稿が消えたあとのノードが、保持者からの過去ログでスレと返信を受け取る',
      lateBBoard && lateBReplies && hs.fetches > 0,
      `スレ ${lateBBoard ? 'OK' : 'NG'}・返信 ${lateBReplies ? 'OK' : 'NG'} (${fmtMs(Date.now() - tB)})・過去ログの取得 ${hs.fetches} 回 / 保持者への要求 ${hs.attempts} 回`);
    const big = files.find(f => f.size === 1024 * 1024) ?? files[files.length - 1];
    if (big) {
      const r = await lateB.call('downloadP2P', [big.token, 120_000], 140_000);
      const v = r.ok ? r.value : { ok: false, error: r.error };
      check(`(b) そのノードが ${big.name} を取れて SHA-256 が一致`, v.ok && v.hash === big.hash, v.ok ? fmtMs(v.ms) : v.error);
    }

    // ── 8. Ozzy ──
    if (OZZY_MODE !== 'off') {
      phase(`8. Ozzy (M1 経由でロッカーへ。ロッカー: ${OZZY_MODE === 'real' ? '本物' : 'main のメモリ上の偽物'})`);
      const ozUploader = nodes[5];
      const ozReaders = [nodes[TOTAL_NODES - 2], nodes.find(n => n.kind === 'browser' && n.index !== uploaderB?.index) ?? nodes[6], lateB];
      const ozNodes = [ozUploader, ...ozReaders];
      const meshOk = await waitFor(async () => (await statusAll(ozNodes)).every(s => s.ozzy?.meshReady), 60_000, 1000);
      const allSt = await statusAll();
      const fetchers = allSt.filter(s => s.ozzy?.fetcher).length;
      note(`M1 の役をしているノード ${fetchers}/${allSt.length} 台 (Guard とブラウザ役はしない)`);
      check('Ozzy の取得役の回路が使える (上げる人・取る人)', meshOk);
      const OZZY_SIZE = 2 * 1024 * 1024;
      const CHUNK = 64 * 1024;
      const up = await ozUploader.call('ozzyUpload', [OZZY_SIZE, CHUNK, 300_000], 320_000);
      const uv = up.ok ? up.value : { ok: false, error: up.error };
      check(`Ozzy アップロード (${OZZY_SIZE} B・チャンク ${CHUNK} B・${ozUploader.label})`, uv.ok,
        uv.ok ? `${fmtMs(uv.ms)} Slab ${uv.slabs} 本 / ロッカー ${uv.lockers.join(', ')}` : uv.error);
      if (uv.ok) {
        check('置き先が 3 つ以上のロッカーに散る', uv.lockers.length >= 3, `${uv.lockers.length} 社`);
        for (const reader of ozReaders) {
          const r = await reader.call('ozzyDownload', [uv.link, 300_000], 320_000);
          const v = r.ok ? r.value : { ok: false, error: r.error };
          check(`Ozzy 取得 ${reader.label} (${reader.kind === 'browser' ? 'ブラウザ役 = 自分は M1 をしない' : 'デスクトップ役'})`,
            v.ok && v.hash === uv.hash && v.size === OZZY_SIZE, v.ok ? `${fmtMs(v.ms)}${v.hash === uv.hash ? '' : ' ハッシュ違い'}` : v.error);
        }
      }
      const oz = await Promise.all(nodes.map(n => n.call('ozzyStats', [], 10_000).then(r => (r.ok ? r.value : null))));
      const refused = oz.reduce((a, s, i) => a + ((s && !allSt[i]?.ozzy?.fetcher) ? s.exit.rejected : 0), 0);
      const served = oz.reduce((a, s) => a + (s ? s.exit.requests - s.exit.rejected : 0), 0);
      note(`M1 の役をしないノードが断った (REFUSED) 要求 ${refused} 件・M1 が受けた要求 ${served} 件 (別の M1 へ回して完了した)`);
      const byHost = Array.from(lockers.counters.byHost.entries()).map(([h, c]) => `${h}=${c}`).join(' ');
      note(`ozlocker:// への要求 ${lockers.counters.requests} 件 (許可外で断ったもの ${lockers.counters.refused}): ${byHost}`);
      check('ozlocker:// が許可外の行き先を通していない', lockers.counters.refused === 0);
    }

    // ── 9. 診断 ──
    phase('9. 診断 (合否には入れない)');
    const net = await Promise.all(nodes.map(n => n.call('netStats', [], 10_000).then(r => (r.ok ? r.value : null))));
    const sum = (pick) => net.reduce((a, s) => a + (s ? pick(s) : 0), 0);
    const relay = {};
    const rate = {};
    for (const s of net) {
      if (!s) continue;
      for (const [k, v] of Object.entries(s.relayDropped)) relay[k] = (relay[k] ?? 0) + v;
      for (const [k, v] of Object.entries(s.rateDropped)) rate[k] = (rate[k] ?? 0) + v;
    }
    note(`中継 (TunnelRelay) が捨てた: ${JSON.stringify(relay)}`);
    note(`レート制限で捨てた (カテゴリ別): ${JSON.stringify(rate)}`);
    note(`送出の列の上限で捨てたフレーム: ${sum(s => s.senderDropped)}・過去ログの壊れた片: ${sum(s => s.historyBadChunks)}`);
    const finalSt = await statusAll();
    note(`切断の合計: ${finalSt.reduce((a, s) => a + (s.events?.disconnect ?? 0), 0)} 回`);
    for (const [k, v] of consoleCounts) note(`画面のログ「${k}」: ${v} 回`);

    exitCode = results.every(r => r.ok) ? 0 : 1;
  } catch (err) {
    if (err instanceof StopEarly) {
      note(`--until=${UNTIL} のため、ここで止めます`);
      exitCode = results.every(r => r.ok) ? 0 : 1;
    } else {
      console.error('\n[ABORT] 検証の途中で止まりました:', err);
      check('検証が最後まで走る', false, String(err?.message ?? err));
    }
  } finally {
    phase('要約');
    for (const r of results) console.log(`  ${r.ok ? 'PASS' : 'FAIL'}  ${r.name}${r.detail ? ` — ${short(r.detail)}` : ''}`);
    const passed = results.filter(r => r.ok).length;
    console.log(`\n  ${passed}/${results.length} 項目合格 → ${exitCode === 0 ? '合格' : '不合格'}`);
    for (const n of nodes) {
      try { await n.call('stop', [], 15_000); } catch { /* 片付け */ }
    }
    for (const win of windows) {
      try { if (win && !win.isDestroyed()) win.destroy(); } catch { /* 片付け */ }
    }
    try { httpsServer?.close(); } catch { /* 片付け */ }
    try { void stunServer?.close(); } catch { /* 片付け */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* 片付け */ }
    app.exit(exitCode);
  }
});

/**
 * Oz P2P ネットワーク 本番完全忠実エミュレーター
 *
 * 【制約・設計方針】
 * 1. パッケージ (@oz/core, @oz/tracker) のコードを1文字も改変せずそのまま使用する。
 * 2. 偽の WebRTC モックやテスト用の軽量化パラメータ (VAULT_PARAMS_FAST, slotEffort: 1 等) を一切使わない。
 * 3. 本番環境と完全に同一の条件を再現する:
 *    - トラッカー: TLS (wss://ozzy-r2-gatekeeper.jkfujinamis.workers.dev:<port>/ws) 上で稼働する本物の EdgeTrackerHub / TrackerServer
 *      (isLoopbackTrackerUrl が本番通り false になり、同一オリジン PEX フィルタ等が本番通りに機能する)
 *    - STUN: 本物の @oz/tracker StunServer (UDP)
 *    - クライアント: 本番の P2PProvider.tsx と同じく OzNode.create({ db, passphrase, autoStart: false, storage: { defaultSlots }, iceServers })
 *      → oz.setTrackerUrl(url) → oz.start()
 *    - Guard (オプション --with-desktop-guard): 本番の apps/desktop/src/guard.ts と同じく DEFAULT_TRACKER_URL を参照して起動
 * 4. 1秒に1個ずつノードを追加していき、トラッカー上の接続数 (TrackerWS) と各ノードの P2P 接続数 (degree / verified) の推移を検証する。
 */

import { app, BrowserWindow } from 'electron';
import { createServer as createHttpsServer } from 'node:https';
import { createServer as createHttpServer } from 'node:http';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import * as esbuild from 'esbuild';
import { WebSocketServer } from 'ws';

const require = createRequire(import.meta.url);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');

// CLI 引数
const args = process.argv.slice(2);
const TOTAL_NODES = Number(args.find(a => a.startsWith('--nodes='))?.split('=')[1] ?? 8);
const OBSERVE_SECONDS = Number(args.find(a => a.startsWith('--observe='))?.split('=')[1] ?? 35);
const WITH_DESKTOP_GUARD = args.includes('--with-desktop-guard');
const WITH_DIRECT_GUARD = args.includes('--with-direct-guard');
const USE_NODE_TRACKER = args.includes('--use-node-tracker');
const USE_TRACKER_TOKEN = args.includes('--use-tracker-token');
const PREWARM_CREATE = args.includes('--prewarm-create');

const TRACKER_HOSTNAME = 'ozzy-r2-gatekeeper.jkfujinamis.workers.dev';

// 本番の apps/desktop/electron/main.ts と同一のスイッチ + ローカル TLS トラッカーへの名前解決
app.commandLine.appendSwitch('disk-cache-size', '1');
app.commandLine.appendSwitch('disable-breakpad');
app.commandLine.appendSwitch('enforce-webrtc-ip-permission-check');
app.commandLine.appendSwitch('ignore-certificate-errors');
app.commandLine.appendSwitch('host-resolver-rules', `MAP ${TRACKER_HOSTNAME} 127.0.0.1, MAP ozzy-tracker.jkfujinami.deno.net 127.0.0.1:1`);
// ★ エミュレーター固有: Chromium は「1 つのネットワークサービス プロセスで同時に開ける UDP ソケット」を
//   6000 に制限する (LimitOpenUDPSockets)。全ウィンドウが 1 つのネットワークサービスを共有するので、
//   本番では端末ごとに別々の 6000 枠が、ここでは 100 ノードで 1 つの枠を奪い合う。
//   インターフェースの多い端末では PeerConnection 1 本が数十ソケットを開くので、約 27 ノードで枯渇し
//   bind() が ERR_INSUFFICIENT_RESOURCES (-12) で失敗して新規ノードが孤立していた。本番の 1 端末 1 ノードに揃えるため外す。
app.commandLine.appendSwitch('disable-features', 'LimitOpenUDPSockets');

let httpsServer;
let trackerServer;
let edgeHub;
let stunServer;
let wss;
const windows = [];

function generateSelfSignedCert(tmpDir) {
  const keyPath = path.join(tmpDir, 'key.pem');
  const certPath = path.join(tmpDir, 'cert.pem');
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', keyPath,
    '-out', certPath,
    '-days', '1',
    '-subj', `/CN=${TRACKER_HOSTNAME}`,
    '-addext', `subjectAltName=DNS:${TRACKER_HOSTNAME},IP:127.0.0.1`,
  ], { stdio: 'ignore' });
  return {
    key: fs.readFileSync(keyPath),
    cert: fs.readFileSync(certPath),
  };
}

async function startRealTracker(tmpDir) {
  const trackerBundlePath = path.join(tmpDir, 'tracker-bundle.cjs');
  await esbuild.build({
    entryPoints: [path.join(ROOT_DIR, 'packages/tracker/src/index.ts')],
    bundle: true,
    outfile: trackerBundlePath,
    platform: 'node',
    format: 'cjs',
    loader: { '.wasm': 'binary' },
  });
  const { TrackerServer, EdgeTrackerHub, StunServer } = require(trackerBundlePath);

  // 全ノードが同じ 127.0.0.1 から来るため、本番の「送信元 IP あたり 10 件/秒」では
  // 1 IP = 1 端末という前提が崩れる。ノード数に比例して IP あたりの上限だけ広げる
  // (1 ノードあたりの許容量は本番と同じ。全体上限 5000/秒も本番のまま)
  stunServer = new StunServer(Date.now, { perIpPerSec: 10 * Math.max(1, TOTAL_NODES) });
  const stunPort = await stunServer.listen(0, '127.0.0.1');

  if (USE_TRACKER_TOKEN) {
    httpsServer = createHttpServer((_req, res) => {
      res.writeHead(200);
      res.end('ok');
    });
  } else {
    const tlsCreds = generateSelfSignedCert(tmpDir);
    httpsServer = createHttpsServer(tlsCreds, (_req, res) => {
      res.writeHead(200);
      res.end('ok');
    });
  }

  if (!USE_NODE_TRACKER) {
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
          : ArrayBuffer.isView(data)
            ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
            : new Uint8Array(Buffer.from(data));
        void edgeHub.handleMessage(ws, buf);
      });
      ws.on('close', () => edgeHub.handleClose(ws));
      ws.on('error', () => edgeHub.handleClose(ws));
    });
  } else {
    trackerServer = new TrackerServer(httpsServer);
  }

  await new Promise(resolve => httpsServer.listen(0, '127.0.0.1', resolve));
  const port = httpsServer.address().port;
  let trackerUrl = `wss://${TRACKER_HOSTNAME}:${port}/ws`;
  if (USE_TRACKER_TOKEN) {
    const coreBundlePath = path.join(tmpDir, 'core-bundle.cjs');
    await esbuild.build({
      entryPoints: [path.join(ROOT_DIR, 'packages/core/src/network/TrackerUrl.ts')],
      bundle: true,
      outfile: coreBundlePath,
      platform: 'node',
      format: 'cjs',
    });
    const { createTrackerString } = require(coreBundlePath);
    trackerUrl = createTrackerString({ host: TRACKER_HOSTNAME, port, tls: false, path: '/ws' });
  }
  return {
    port,
    stunPort,
    stunUrl: `stun:127.0.0.1:${stunPort}`,
    trackerUrl,
    getSessionCount: () => (!USE_NODE_TRACKER ? edgeHub.sessionCount : trackerServer.sessionCount),
    getConnectionCount: () => (!USE_NODE_TRACKER ? edgeHub.connectionCount : trackerServer.connectionCount),
    getActivePeerIds: () => {
      if (!USE_NODE_TRACKER) {
        return Array.from(edgeHub.sessions.keys()).map(id => id.slice(0, 8));
      }
      return [];
    },
  };
}

async function buildRendererBundle(tmpDir) {
  const entryPath = path.join(tmpDir, 'renderer-entry.js');
  const bundlePath = path.join(tmpDir, 'renderer-bundle.js');
  const htmlPath = path.join(tmpDir, 'node.html');

  // @oz/core と @oz/ui の本番設定そのままのエントリ
  const entryCode = `
    import { OzNode, IndexedDBStore } from ${JSON.stringify(path.join(ROOT_DIR, 'packages/core/src/index.ts'))};
    import { DEFAULT_TRACKER_URL as STANDARD_DEFAULT_TRACKER } from ${JSON.stringify(path.join(ROOT_DIR, 'packages/ui/src/index.ts'))};

    const instances = new Map();

    function getOrInitSlot(slotId) {
      if (!instances.has(slotId)) {
        instances.set(slotId, {
          node: null,
          phase: 'idle',
          errorMsg: null,
          events: [],
        });
      }
      return instances.get(slotId);
    }

    window.emulatorNodePool = {
      async createOnly(slotId, config) {
        const slot = getOrInitSlot(slotId);
        slot.phase = 'creating(KDF+PoW)';
        try {
          const db = new IndexedDBStore(config.dbName);
          let node;
          if (config.mode === 'desktop-guard') {
            node = await OzNode.create({
              db,
              role: 'guard',
              identityMode: 'persistent',
              passphrase: config.passphrase,
              trackerUrl: config.trackerUrl || STANDARD_DEFAULT_TRACKER,
              iceServers: config.iceServers,
              autoStart: false,
              storage: { defaultSlots: config.slots ?? 4 },
            });
          } else if (config.mode === 'direct-guard') {
            node = await OzNode.create({
              db,
              role: 'guard',
              identityMode: 'persistent',
              passphrase: config.passphrase,
              trackerUrl: config.trackerUrl,
              iceServers: config.iceServers,
              autoStart: false,
              storage: { defaultSlots: config.slots ?? 4 },
            });
          } else {
            node = await OzNode.create({
              db,
              passphrase: config.passphrase,
              autoStart: false,
              storage: { defaultSlots: config.slots ?? 1 },
              iceServers: config.iceServers,
            });
            await node.setTrackerUrl(config.trackerUrl);
          }

          node.peerManager.on('peer:connect', (p) => {
            slot.events.push({ t: Date.now(), type: 'connect', peerId: p.peerId.slice(0, 8), dir: p.direction });
          });
          node.peerManager.on('peer:verified', (p) => {
            slot.events.push({ t: Date.now(), type: 'verified', peerId: p.peerId.slice(0, 8), dir: p.direction });
          });
          node.peerManager.on('peer:disconnect', (peerId) => {
            slot.events.push({ t: Date.now(), type: 'disconnect', peerId: String(peerId).slice(0, 8) });
          });

          slot.node = node;
          slot.phase = 'created';
          return { peerId: node.peerId };
        } catch (err) {
          slot.phase = 'error';
          slot.errorMsg = err instanceof Error ? err.message : String(err);
          throw err;
        }
      },

      async startOnly(slotId) {
        const slot = getOrInitSlot(slotId);
        if (!slot.node) throw new Error('node not created');
        slot.phase = 'starting';
        await slot.node.start();
        slot.phase = 'running';
        return {
          peerId: slot.node.peerId,
          trackerConnected: slot.node.trackerConnected,
          degree: slot.node.degree,
        };
      },

      async createAndStartFull(slotId, config) {
        await this.createOnly(slotId, config);
        return await this.startOnly(slotId);
      },

      getStatus(slotId) {
        const slot = getOrInitSlot(slotId);
        const node = slot.node;
        if (!node) {
          return {
            phase: slot.phase,
            errorMsg: slot.errorMsg,
            peerId: '--------',
            trackerConnected: false,
            degree: 0,
            verifiedCount: 0,
            totalPeerEntries: 0,
            outboundCount: 0,
            sameOriginHopsAllowed: null,
            peers: [],
            recentEvents: slot.events.splice(0, slot.events.length),
          };
        }
        const peers = [];
        for (const [id, p] of node.peerManager.peers.entries()) {
          peers.push({
            id: id.slice(0, 8),
            connected: p.isConnected,
            connecting: p.isConnecting,
            verified: p.isVerified,
            dir: p.direction,
            origin: node.peerManager.originOf(id),
          });
        }
        return {
          phase: slot.phase,
          errorMsg: slot.errorMsg,
          peerId: node.peerId.slice(0, 8),
          fullPeerId: node.peerId,
          trackerUrl: node.trackerUrl,
          trackerConnected: node.trackerConnected,
          degree: node.degree,
          verifiedCount: node.peerManager.verifiedPeers.length,
          totalPeerEntries: node.peerManager.peers.size,
          outboundCount: node.peerManager.outboundCount,
          sameOriginHopsAllowed: node.peerManager.sameOriginHopsAllowed,
          peers,
          recentEvents: slot.events.splice(0, slot.events.length),
        };
      },

      async stop(slotId) {
        const slot = instances.get(slotId);
        if (slot && slot.node) await slot.node.stop();
      }
    };
  `;

  fs.writeFileSync(entryPath, entryCode, 'utf8');

  await esbuild.build({
    entryPoints: [entryPath],
    bundle: true,
    outfile: bundlePath,
    platform: 'browser',
    format: 'iife',
    target: 'chrome120',
    loader: { '.wasm': 'binary' },
  });

  fs.writeFileSync(
    htmlPath,
    `<!DOCTYPE html><html><head><meta charset="utf-8"></head><body><script src="./renderer-bundle.js"></script></body></html>`,
    'utf8',
  );

  return htmlPath;
}

const MAX_RENDERER_WINDOWS = Number(args.find(a => a.startsWith('--windows='))?.split('=')[1] ?? 10);

async function getOrSpawnPoolWindow(htmlPath, poolIndex) {
  if (windows[poolIndex]) return windows[poolIndex];
  const win = new BrowserWindow({
    show: false,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: false,
      backgroundThrottling: false,
    },
  });
  if (typeof win.webContents.setWebRTCIPHandlingPolicy === 'function') {
    win.webContents.setWebRTCIPHandlingPolicy('default_public_interface_only');
  }
  windows[poolIndex] = win;

  win.webContents.on('console-message', (_event, level, message) => {
    if (level >= 2 && !message.includes('Electron Security Warning')) {
      console.log(`  [Win#${poolIndex} Console] ${message}`);
    }
  });

  await win.loadFile(htmlPath);
  return win;
}

async function spawnEmptyWindow(htmlPath, index, mode) {
  const poolIndex = index % MAX_RENDERER_WINDOWS;
  const win = await getOrSpawnPoolWindow(htmlPath, poolIndex);
  const slotId = `slot_${index}`;
  return {
    index,
    mode,
    win,
    createOnly: (cfg) => win.webContents.executeJavaScript(`window.emulatorNodePool.createOnly(${JSON.stringify(slotId)}, ${JSON.stringify(cfg)})`),
    startOnly: () => win.webContents.executeJavaScript(`window.emulatorNodePool.startOnly(${JSON.stringify(slotId)})`),
    createAndStartFull: (cfg) => win.webContents.executeJavaScript(`window.emulatorNodePool.createAndStartFull(${JSON.stringify(slotId)}, ${JSON.stringify(cfg)})`),
    getStatus: () => win.webContents.executeJavaScript(`window.emulatorNodePool.getStatus(${JSON.stringify(slotId)})`),
    stop: () => win.webContents.executeJavaScript(`window.emulatorNodePool.stop(${JSON.stringify(slotId)})`),
  };
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

app.whenReady().then(async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'oz-emulator-'));
  console.log('================================================================================');
  console.log(`Oz P2P Production Emulator`);
  console.log(`- Nodes: ${TOTAL_NODES} (1 node added every 1.0s)`);
  console.log(`- Tracker: ${USE_NODE_TRACKER ? 'TrackerServer' : 'EdgeTrackerHub'} over WSS (${TRACKER_HOSTNAME})`);
  console.log(`- Desktop Guard: ${WITH_DESKTOP_GUARD} | Direct Guard: ${WITH_DIRECT_GUARD} | Prewarm Create: ${PREWARM_CREATE}`);
  console.log('================================================================================');

  const tracker = await startRealTracker(tmpDir);
  console.log(`[Tracker] Listening on ${tracker.trackerUrl} (STUN: ${tracker.stunUrl})`);

  const htmlPath = await buildRendererBundle(tmpDir);

  const nodeSpecs = [];
  if (WITH_DESKTOP_GUARD) {
    nodeSpecs.push({ index: 0, mode: 'desktop-guard', label: 'Guard(Desktop)' });
  } else if (WITH_DIRECT_GUARD) {
    nodeSpecs.push({ index: 0, mode: 'direct-guard', label: 'Guard(Direct)' });
  }
  for (let i = 1; i <= TOTAL_NODES; i++) {
    nodeSpecs.push({ index: i, mode: 'client', label: `Client#${i}` });
  }

  const activeNodes = [];

  if (PREWARM_CREATE) {
    console.log(`\n[Prewarm] Creating ${nodeSpecs.length} OzNode instances across ${Math.min(nodeSpecs.length, MAX_RENDERER_WINDOWS)} renderer processes with real production Argon2id parameters...`);
    const tAll = Date.now();
    for (const spec of nodeSpecs) {
      const handle = await spawnEmptyWindow(htmlPath, spec.index, spec.mode);
      handle.label = spec.label;
      activeNodes.push(handle);
    }
    // 各ウィンドウで並列にバッチ生成 (1バッチ = MAX_RENDERER_WINDOWS 個)
    for (let batchStart = 0; batchStart < nodeSpecs.length; batchStart += MAX_RENDERER_WINDOWS) {
      const batch = nodeSpecs.slice(batchStart, batchStart + MAX_RENDERER_WINDOWS);
      const tBatch = Date.now();
      await Promise.all(batch.map((spec, offset) => {
        const handle = activeNodes[batchStart + offset];
        return handle.createOnly({
          dbName: `oz_emu_${Date.now()}_${spec.index}`,
          passphrase: `emulator-production-passphrase-${spec.index}`,
          trackerUrl: tracker.trackerUrl,
          iceServers: [tracker.stunUrl],
          mode: spec.mode,
          slots: 1,
        });
      }));
      console.log(`  Prewarmed nodes ${batchStart + 1}..${batchStart + batch.length} / ${nodeSpecs.length} in ${Date.now() - tBatch}ms`);
    }
    console.log(`[Prewarm] All ${nodeSpecs.length} nodes created in ${Date.now() - tAll}ms`);
  }

  console.log('\n--------------------------------------------------------------------------------');
  console.log('Adding 1 node per second and monitoring TrackerWS & P2P degree in real time...');
  console.log('--------------------------------------------------------------------------------');

  const spawnedNodes = [];
  const startTime = Date.now();

  async function printSnapshot(secLabel) {
    const statuses = await Promise.all(spawnedNodes.map(n => n.getStatus()));
    const trackerSessions = tracker.getSessionCount();
    const trackerConns = tracker.getConnectionCount();

    if (spawnedNodes.length <= 12) {
      const summary = statuses.map((s, idx) => {
        const n = spawnedNodes[idx];
        const tag = n.mode === 'client' ? `C${n.index}` : 'G';
        if (s.phase !== 'running') {
          return `${tag}[${s.phase}]`;
        }
        const trk = s.trackerConnected ? 'T' : '-';
        return `${tag}(${trk}):deg=${s.degree}/ver=${s.verifiedCount}`;
      }).join(' | ');

      console.log(`[t=${String(secLabel).padStart(3, ' ')}s] Nodes=${spawnedNodes.length} | TrackerWS=${trackerSessions}(conn:${trackerConns}) | ${summary}`);
    } else {
      const running = statuses.filter(s => s.phase === 'running');
      const trkConnected = running.filter(s => s.trackerConnected).length;
      const degs = running.map(s => s.degree);
      const vers = running.map(s => s.verifiedCount);
      const minDeg = degs.length ? Math.min(...degs) : 0;
      const maxDeg = degs.length ? Math.max(...degs) : 0;
      const avgDeg = degs.length ? (degs.reduce((a, b) => a + b, 0) / degs.length).toFixed(1) : '0.0';
      const minVer = vers.length ? Math.min(...vers) : 0;
      const maxVer = vers.length ? Math.max(...vers) : 0;
      const avgVer = vers.length ? (vers.reduce((a, b) => a + b, 0) / vers.length).toFixed(1) : '0.0';
      const isolated = running.filter(s => s.verifiedCount === 0).length;
      const latestIdx = spawnedNodes.length - 1;
      const latestS = statuses[latestIdx];
      const latestN = spawnedNodes[latestIdx];
      const latestTag = latestN.mode === 'client' ? `C${latestN.index}` : 'G';
      console.log(
        `[t=${String(secLabel).padStart(3, ' ')}s] Nodes=${String(spawnedNodes.length).padStart(3, ' ')} | ` +
        `TrackerWS=${String(trackerSessions).padStart(3, ' ')}(nodeT:${String(trkConnected).padStart(3, ' ')}) | ` +
        `deg=${minDeg}/${avgDeg}/${maxDeg} | ver=${minVer}/${avgVer}/${maxVer} | isolated=${isolated} | ` +
        `latest=${latestTag}(deg=${latestS.degree}/ver=${latestS.verifiedCount})`
      );
    }
  }

  for (let i = 0; i < nodeSpecs.length; i++) {
    const spec = nodeSpecs[i];
    if (PREWARM_CREATE) {
      const handle = activeNodes[i];
      spawnedNodes.push(handle);
      void handle.startOnly().catch(err => console.error(`${spec.label} start error:`, err));
    } else {
      const handle = await spawnEmptyWindow(htmlPath, spec.index, spec.mode);
      handle.label = spec.label;
      spawnedNodes.push(handle);
      void handle.createAndStartFull({
        dbName: `oz_emu_${Date.now()}_${spec.index}`,
        passphrase: `emulator-production-passphrase-${spec.index}`,
        trackerUrl: tracker.trackerUrl,
        iceServers: [tracker.stunUrl],
        mode: spec.mode,
        slots: 1,
      }).catch(err => console.error(`${spec.label} error:`, err));
    }

    await sleep(1000);
    const elapsedSec = Math.round((Date.now() - startTime) / 1000);
    await printSnapshot(elapsedSec);
  }

  for (let s = 1; s <= OBSERVE_SECONDS; s++) {
    await sleep(1000);
    const elapsedSec = Math.round((Date.now() - startTime) / 1000);
    await printSnapshot(elapsedSec);
  }

  console.log('\n================================================================================');
  console.log('Final Detailed Peer Table:');
  console.log('================================================================================');
  const finalStatuses = await Promise.all(spawnedNodes.map(n => n.getStatus()));
  for (let i = 0; i < finalStatuses.length; i++) {
    const s = finalStatuses[i];
    const n = spawnedNodes[i];
    console.log(
      `${n.label} (mode=${n.mode}) id=${s.peerId} phase=${s.phase} trackerUrl=${s.trackerUrl} ` +
      `trackerConnected=${s.trackerConnected} sameOriginHopsAllowed=${s.sameOriginHopsAllowed} ` +
      `degree=${s.degree} verified=${s.verifiedCount} outbound=${s.outboundCount} peers=${JSON.stringify(s.peers)}`
    );
  }

  for (const n of spawnedNodes) {
    try { await n.stop(); } catch {}
  }
  for (const win of windows) {
    try { if (win && !win.isDestroyed()) win.destroy(); } catch {}
  }
  httpsServer.close();
  void stunServer.close();
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  app.quit();
});

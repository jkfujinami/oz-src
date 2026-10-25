/**
 * Deno Deploy 用スタンドアロン無料トラッカー (`deno-tracker.ts`)。
 *
 * 起動・デプロイ方法:
 * 1. ローカル実行:
 *    `deno run --allow-net --allow-env packages/tracker/deno-tracker.ts`
 * 2. Deno Deploy (完全無料・クレカ不要):
 *    GitHub リポジトリを https://dash.deno.com に接続し、エントリーポイントに
 *    `packages/tracker/deno-tracker.ts` を指定するだけで `wss://<project>.deno.dev/ws` が稼働します。
 *
 * 複数リージョン・複数 Isolate で起動された場合も、Deno Deploy ネイティブの
 * `BroadcastChannel("oz-tracker-v3")` によってピア発見と SDP/ICE 中継が自動同期されます。
 */

import { EdgeTrackerHub } from './src/EdgeTrackerHub.ts';

declare const Deno: {
  env: { get(key: string): string | undefined };
  serve(
    options: { port?: number },
    handler: (req: Request, info: { remoteAddr?: { hostname?: string } }) => Response | Promise<Response>,
  ): unknown;
  upgradeWebSocket(req: Request, options?: { idleTimeout?: number }): { socket: WebSocket; response: Response };
};

/** 数値の環境変数 (未設定・不正なら undefined = 既定値) */
function envInt(name: string): number | undefined {
  const raw = Deno.env.get(name);
  if (raw === undefined || raw.trim() === '') return undefined;
  const n = Number(raw);
  return Number.isInteger(n) && n >= 0 ? n : undefined;
}

const allowedHostsEnv = Deno.env.get('OZ_TRACKER_ALLOWED_HOSTS');
const allowedHosts = allowedHostsEnv
  ? allowedHostsEnv
      .split(',')
      .map(s => s.trim())
      .filter(Boolean)
  : undefined;

// ★ 同時接続の上限 (EdgeTrackerHub の既定: 登録 2048・登録前 256・1 アドレス 16)。
//   OZ_TRACKER_MAX_PER_ADDRESS=0 で 1 アドレスあたりの上限を外す (手前のプロキシのアドレスしか
//   見えない環境で、全員が同じアドレスに数えられてしまう場合)。
const hub = new EdgeTrackerHub({
  allowedHosts,
  broadcastChannelName: 'oz-tracker-v3',
  maxSessions: envInt('OZ_TRACKER_MAX_SESSIONS'),
  maxPendingConnections: envInt('OZ_TRACKER_MAX_PENDING'),
  maxConnectionsPerAddress: envInt('OZ_TRACKER_MAX_PER_ADDRESS'),
});

const port = Number(Deno.env.get('PORT') ?? '8080');

Deno.serve({ port }, (req, info): Response => {
  const url = new URL(req.url);

  if (url.pathname === '/health' || url.pathname === '/ozzy/v2/tracker-status') {
    return new Response(
      JSON.stringify({
        ok: true,
        runtime: 'deno-deploy',
        protocolVersion: 3,
        activeSessions: hub.sessionCount,
        connections: hub.connectionCount,
      }),
      {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
        },
      },
    );
  }

  if (url.pathname === '/ws' || url.pathname === '/') {
    const upgrade = req.headers.get('upgrade') ?? '';
    if (upgrade.toLowerCase() !== 'websocket') {
      return new Response('Expected Upgrade: websocket on /ws', { status: 426 });
    }

    // 送信元アドレス (同時接続数を数えるだけ。ログにも応答にも出さない)
    const remoteAddress = info?.remoteAddr?.hostname ?? null;
    // ★ 上限を超えていれば WebSocket を作らずに断る (作ってから切るより軽い)
    if (!hub.canAccept(remoteAddress)) {
      return new Response('Tracker is busy', { status: 503, headers: { 'Retry-After': '30' } });
    }

    try {
      const hostHeader = req.headers.get('x-forwarded-host') ?? req.headers.get('host') ?? url.host;
      // 応答 (pong) の無い相手は 30 秒で切る (Deno の既定値。明示しておく)
      const { socket, response } = Deno.upgradeWebSocket(req, { idleTimeout: 30 });
      socket.binaryType = 'arraybuffer';

      socket.onopen = () => {
        try {
          hub.acceptConnection(socket, hostHeader, remoteAddress);
        } catch (err) {
          console.error('[tracker:open:err]', err);
        }
      };
      socket.onmessage = event => {
        void hub.handleMessage(socket, event.data).catch(err => {
          console.error('[tracker:msg:err]', err);
        });
      };
      socket.onclose = () => {
        hub.handleClose(socket);
      };
      socket.onerror = () => {
        hub.handleClose(socket);
      };

      return response;
    } catch (err) {
      console.error('[upgrade:err]', err);
      return new Response(String(err), { status: 500 });
    }
  }

  return new Response('Not Found', { status: 404 });
});

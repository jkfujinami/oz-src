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
    handler: (req: Request) => Response | Promise<Response>,
  ): unknown;
  upgradeWebSocket(req: Request): { socket: WebSocket; response: Response };
};

const allowedHostsEnv = Deno.env.get('OZ_TRACKER_ALLOWED_HOSTS');
const allowedHosts = allowedHostsEnv
  ? allowedHostsEnv
      .split(',')
      .map(s => s.trim())
      .filter(Boolean)
  : undefined;

const hub = new EdgeTrackerHub({
  allowedHosts,
  broadcastChannelName: 'oz-tracker-v3',
});

const port = Number(Deno.env.get('PORT') ?? '8080');

Deno.serve({ port }, (req: Request): Response => {
  const url = new URL(req.url);

  if (url.pathname === '/health' || url.pathname === '/ozzy/v2/tracker-status') {
    return new Response(
      JSON.stringify({
        ok: true,
        runtime: 'deno-deploy',
        protocolVersion: 3,
        activeSessions: hub.sessionCount,
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

    try {
      const hostHeader = req.headers.get('x-forwarded-host') ?? req.headers.get('host') ?? url.host;
      const { socket, response } = Deno.upgradeWebSocket(req);
      socket.binaryType = 'arraybuffer';

      socket.onopen = () => {
        try {
          hub.acceptConnection(socket, hostHeader);
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

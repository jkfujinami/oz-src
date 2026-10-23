/**
 * トラッカーを単体で動かす。
 *
 *   PORT=8080 TRACKER_ALLOWED_HOSTS=tracker.example.org npm run tracker   (esbuild でまとめてから node で動かす)
 *
 * STUN: UDP 3478 (STUN_PORT で変更、0 で無効) で Binding Request に答える。待ち受けるアドレスは STUN_HOST
 *   (省略時は HOST と同じ)。ノードの WebRTC は第三者 (Google 等) の STUN ではなくここを使う。UDP 3478 を開けておくこと。
 *   ★ WebSocket をリバースプロキシの裏 (HOST=127.0.0.1) で動かすときも、STUN は UDP なのでプロキシを通らない。
 *     その場合は STUN_HOST=0.0.0.0 (または ::) で外へ開く。
 *
 * TLS (wss://) はリバースプロキシで終端すること。ノードは wss:// のトラッカーにしか
 * 接続しない (localhost を除く)。プロキシが Host ヘッダを書き換える構成では、
 * 公開しているホスト名を TRACKER_ALLOWED_HOSTS (カンマ区切り) に設定する。
 *
 * ★ 運用者には接続してきたノードの IP アドレスが見える。アクセスログを残さない設定にし、
 *   その旨を利用者に公開すること。このプログラム自体は peerId も IP も記録しない。
 */
import { createServer } from 'node:http';
import { TrackerServer } from './TrackerServer';
import { StunServer } from './StunServer';

const port = Number.parseInt(process.env.PORT ?? '8080', 10);
const hostname = process.env.HOST ?? '127.0.0.1';
const allowedHosts = (process.env.TRACKER_ALLOWED_HOSTS ?? '')
  .split(',')
  .map((h) => h.trim())
  .filter((h) => h.length > 0);

const server = createServer((req, res) => {
  if (req.url === '/healthz') {
    res.writeHead(200, { 'content-type': 'text/plain' }).end('ok');
    return;
  }
  res.writeHead(404).end();
});

const tracker = new TrackerServer(server, {
  allowedHosts: allowedHosts.length > 0 ? allowedHosts : undefined,
  exclusiveUpgrade: true,
});

server.listen(port, hostname, () => {
  console.log(`[tracker] listening on ${hostname}:${port} (WebSocket path /ws)`);
});

// ★ STUN。トラッカーには WebSocket で IP がすでに見えているので、ここで答えても新たに漏れるものは無い。
//   記録するのは件数だけ (IP も時刻も残さない)。
const stunPort = Number.parseInt(process.env.STUN_PORT ?? '3478', 10);
const stunHost = process.env.STUN_HOST ?? hostname;
let stun: StunServer | null = null;
let stunLog: ReturnType<typeof setInterval> | null = null;
if (Number.isInteger(stunPort) && stunPort > 0 && stunPort <= 65535) {
  const s = new StunServer();
  s.listen(stunPort, stunHost).then(
    () => {
      stun = s;
      console.log(`[tracker] STUN listening on udp ${stunHost}:${stunPort}`);
      if (stunHost === '127.0.0.1' || stunHost === '::1' || stunHost === 'localhost') {
        console.warn('[tracker] STUN is bound to loopback only; set STUN_HOST=0.0.0.0 (or ::) so nodes can reach it');
      }
      stunLog = setInterval(() => {
        const c = s.takeCounts();
        if (c.responded + c.ignored + c.limited > 0) {
          console.log(`[tracker] stun last 60s: responded=${c.responded} ignored=${c.ignored} limited=${c.limited}`);
        }
      }, 60_000);
      stunLog.unref();
    },
    (err: Error) => console.error(`[tracker] STUN disabled: ${err.message}`),
  );
} else if (stunPort !== 0) {
  console.error('[tracker] STUN_PORT is invalid; STUN disabled');
}

const shutdown = () => {
  if (stunLog) clearInterval(stunLog);
  void stun?.close();
  tracker.shutdown();
  server.close(() => process.exit(0));
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

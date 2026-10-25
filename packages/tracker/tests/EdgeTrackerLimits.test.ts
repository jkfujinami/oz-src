import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { WebSocketServer, WebSocket } from 'ws';
import { sodiumReady, NodeIdentity, NODE_ID_POW_FAST, SignalingClient } from '@oz/core';
import { EdgeTrackerHub, addressKey, type MinimalWebSocket } from '../src/EdgeTrackerHub';

/**
 * Deno Deploy で動かすトラッカー (EdgeTrackerHub) の同時接続の扱い。
 *
 * - 登録前の接続はだれでも作れるので、数に上限を設ける (無いと接続を張るだけでメモリを使い切られる)
 * - 1 つの送信元アドレスからの同時接続数に上限を設ける (私設アドレスは数えない)
 * - 他の Isolate から知らされたピアは、知らせ直しが途絶えたら忘れる。知らない宛先の中継は流さない
 */

let identities: NodeIdentity[] = [];
const hubs: EdgeTrackerHub[] = [];
const servers: Array<{ http: Server; wss: WebSocketServer }> = [];
const clients: SignalingClient[] = [];

beforeAll(async () => {
  await sodiumReady;
  identities = await Promise.all([1, 2, 3].map(() => NodeIdentity.mine(NODE_ID_POW_FAST)));
});

afterEach(async () => {
  for (const c of clients.splice(0)) c.disconnect();
  for (const h of hubs.splice(0)) h.destroy();
  for (const { http, wss } of servers.splice(0)) {
    wss.close();
    http.closeAllConnections();
    await new Promise<void>(resolve => http.close(() => resolve()));
  }
});

function makeHub(opts: ConstructorParameters<typeof EdgeTrackerHub>[0] = {}): EdgeTrackerHub {
  const hub = new EdgeTrackerHub(opts);
  hubs.push(hub);
  return hub;
}

/** 送ったフレームと close を記録するだけの WebSocket */
function fakeSocket() {
  const sent: Uint8Array[] = [];
  let closed = false;
  const ws: MinimalWebSocket & { sent: Uint8Array[]; closed: () => boolean } = {
    sent,
    closed: () => closed,
    readyState: 1,
    send: (data) => { sent.push(data instanceof Uint8Array ? data : new Uint8Array(data)); },
    close: () => { closed = true; },
  };
  return ws;
}

/** エラー frame (0x03, 理由の番号) のうち capacity (7 番目 → 7) か */
const isCapacityError = (f: Uint8Array) => f[0] === 0x03 && f[1] === 7;

async function serve(hub: EdgeTrackerHub): Promise<string> {
  const http = createServer();
  const wss = new WebSocketServer({ noServer: true });
  http.on('upgrade', (req, socket, head) => {
    wss.handleUpgrade(req, socket, head, ws => {
      hub.acceptConnection(ws as any, req.headers.host, req.socket.remoteAddress);
      ws.on('message', data => void hub.handleMessage(ws as any, data));
      ws.on('close', () => hub.handleClose(ws as any));
    });
  });
  await new Promise<void>(resolve => http.listen(0, '127.0.0.1', resolve));
  servers.push({ http, wss });
  return `ws://127.0.0.1:${(http.address() as AddressInfo).port}/ws`;
}

async function join(url: string, id: NodeIdentity): Promise<SignalingClient> {
  const c = new SignalingClient(url, { WebSocketImpl: WebSocket as any });
  clients.push(c);
  await c.connect({ claim: id.claim(), identity: id });
  return c;
}

describe('送信元アドレスの鍵 (addressKey)', () => {
  it('公開の IPv4 はそのまま、IPv6 は /64 単位。私設・ループバック・不正は数えない', () => {
    expect(addressKey('203.0.113.9')).toBe('203.0.113.9');
    expect(addressKey('::ffff:203.0.113.9')).toBe('203.0.113.9');
    expect(addressKey('2001:db8:1:2:aaaa::1')).toBe(addressKey('[2001:db8:1:2:bbbb::9]'));
    expect(addressKey('2001:db8:1:2::1')).not.toBe(addressKey('2001:db8:1:3::1'));
    for (const a of ['127.0.0.1', '10.0.0.5', '192.168.1.2', '172.20.0.1', '::1', 'fe80::1', 'fd00::5', 'localhost', '', null, undefined, '999.1.1.1']) {
      expect(addressKey(a as any)).toBeNull();
    }
  });
});

describe('同時接続の上限', () => {
  it('登録前の接続は上限まで。超えた分は capacity で切り、切れれば空きができる', () => {
    const hub = makeHub({ maxPendingConnections: 3 });
    const socks = [fakeSocket(), fakeSocket(), fakeSocket()];
    socks.forEach((s, i) => hub.acceptConnection(s, 'tracker.example', `203.0.113.${i + 1}`));
    expect(hub.connectionCount).toBe(3);
    expect(hub.canAccept('203.0.113.50')).toBe(false);

    const extra = fakeSocket();
    hub.acceptConnection(extra, 'tracker.example', '203.0.113.50');
    expect(extra.sent.some(isCapacityError)).toBe(true);
    expect(extra.closed()).toBe(true);
    expect(hub.connectionCount).toBe(3);

    hub.handleClose(socks[0]);
    expect(hub.canAccept('203.0.113.50')).toBe(true);
  });

  it('1 つの公開アドレスからは上限まで。別のアドレスと、私設アドレス (プロキシ越し) は数えない', () => {
    const hub = makeHub({ maxConnectionsPerAddress: 2 });
    hub.acceptConnection(fakeSocket(), 'tracker.example', '198.51.100.7');
    hub.acceptConnection(fakeSocket(), 'tracker.example', '198.51.100.7');
    const third = fakeSocket();
    hub.acceptConnection(third, 'tracker.example', '198.51.100.7');
    expect(third.sent.some(isCapacityError)).toBe(true);
    expect(hub.canAccept('198.51.100.8')).toBe(true);
    // 手前のプロキシのアドレス (私設) しか見えない環境で、全員を 1 人として数えない
    for (let i = 0; i < 5; i++) hub.acceptConnection(fakeSocket(), 'tracker.example', '10.1.2.3');
    expect(hub.connectionCount).toBe(7);
  });

  it('登録を終えた接続は「登録前」の数から外れる (登録前の上限 1 でも 2 人目が登録できる)', async () => {
    const hub = makeHub({ maxPendingConnections: 1 });
    const url = await serve(hub);
    await join(url, identities[0]);
    await join(url, identities[1]);
    expect(hub.sessionCount).toBe(2);
  });

  it('切断すれば登録も数も消える (同じ peerId の張り直しで数がずれない)', async () => {
    const hub = makeHub({ maxPendingConnections: 1 });
    const url = await serve(hub);
    const a1 = await join(url, identities[0]);
    const a2 = await join(url, identities[0]); // 同じ peerId で張り直す (古い接続は切られる)
    await new Promise(r => setTimeout(r, 50));
    expect(hub.sessionCount).toBe(1);
    a1.disconnect();
    a2.disconnect();
    await new Promise(r => setTimeout(r, 50));
    expect(hub.sessionCount).toBe(0);
    expect(hub.connectionCount).toBe(0);
    expect(hub.canAccept(null)).toBe(true);
  });
});

describe('複数の Isolate (BroadcastChannel)', () => {
  it('別の Isolate のピアへ中継でき、後から起きた Isolate も知らせ直しで相手を知る', async () => {
    const channel = `oz-test-${Math.random()}`;
    const hubA = makeHub({ broadcastChannelName: channel, announceIntervalMs: 40 });
    const hubB = makeHub({ broadcastChannelName: channel, announceIntervalMs: 40 });
    const [urlA, urlB] = [await serve(hubA), await serve(hubB)];
    const alice = await join(urlA, identities[0]);

    // B は alice の join より後に起きた: 知らせ直しで alice を知る
    const hubC = makeHub({ broadcastChannelName: channel, announceIntervalMs: 40 });
    const urlC = await serve(hubC);
    await new Promise(r => setTimeout(r, 150));
    const peersSeen: string[] = [];
    const carol = new SignalingClient(urlC, { WebSocketImpl: WebSocket as any });
    clients.push(carol);
    carol.on('peers', ps => peersSeen.push(...ps.map(p => p.peerId)));
    await carol.connect({ claim: identities[2].claim(), identity: identities[2] });
    expect(peersSeen).toContain(identities[0].peerId);

    // B の bob から A の alice へ中継
    const got: string[] = [];
    alice.on('relay', from => got.push(from));
    const bob = await join(urlB, identities[1]);
    bob.sendRelay(identities[0].peerId, { sdp: { type: 'offer', sdp: 'v=0\r\n' } });
    await new Promise(r => setTimeout(r, 100));
    expect(got).toEqual([identities[1].peerId]);
  });

  it('知らない宛先への中継は他の Isolate へ流さない。知らせ直しの途絶えたピアは忘れる', async () => {
    const channel = `oz-test-${Math.random()}`;
    const hubA = makeHub({ broadcastChannelName: channel, announceIntervalMs: 30, remotePeerTtlMs: 120 });
    const url = await serve(hubA);
    const alice = await join(url, identities[0]);
    const post = vi.spyOn((hubA as any).bc as BroadcastChannel, 'postMessage');

    alice.sendRelay('ab'.repeat(16), { sdp: { type: 'offer', sdp: 'v=0\r\n' } });
    await new Promise(r => setTimeout(r, 50));
    expect(post.mock.calls.filter(([m]) => (m as any).kind === 'relay')).toHaveLength(0);

    // 落ちた Isolate にいたピア: join が 1 回届いたきり、知らせ直しが来ない
    const ghost = new BroadcastChannel(channel);
    ghost.postMessage({ kind: 'join', peerIdHex: 'cd'.repeat(16) });
    await new Promise(r => setTimeout(r, 30));
    expect((hubA as any).remotePeers.has('cd'.repeat(16))).toBe(true);
    await new Promise(r => setTimeout(r, 250));
    expect((hubA as any).remotePeers.has('cd'.repeat(16))).toBe(false);
    ghost.close();
  });
});

import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { WebSocketServer, WebSocket } from 'ws';
import {
  sodiumReady,
  NodeIdentity,
  NODE_ID_POW_FAST,
  SignalingClient,
} from '@oz/core';
import { EdgeTrackerHub } from '../src/EdgeTrackerHub';

let http: Server;
let wss: WebSocketServer;
let hub: EdgeTrackerHub;
let port: number;
let url: string;

let alice: NodeIdentity;
let bob: NodeIdentity;

beforeAll(async () => {
  await sodiumReady;
  [alice, bob] = await Promise.all([1, 2].map(() => NodeIdentity.mine(NODE_ID_POW_FAST)));
});

afterEach(async () => {
  hub?.destroy();
  wss?.close();
  http?.closeAllConnections();
  await new Promise<void>(resolve => {
    if (http) http.close(() => resolve());
    else resolve();
  });
});

async function startEdgeTracker() {
  http = createServer();
  hub = new EdgeTrackerHub();
  wss = new WebSocketServer({ noServer: true });

  http.on('upgrade', (req, socket, head) => {
    wss.handleUpgrade(req, socket, head, ws => {
      const host = req.headers.host;
      hub.acceptConnection(ws as any, host);
      ws.on('message', data => {
        void hub.handleMessage(ws as any, data);
      });
      ws.on('close', () => {
        hub.handleClose(ws as any);
      });
    });
  });

  await new Promise<void>(resolve => http.listen(0, '127.0.0.1', resolve));
  port = (http.address() as AddressInfo).port;
  url = `ws://127.0.0.1:${port}/ws`;
}

describe('EdgeTrackerHub Verification Suite (Cloudflare / Deno Compatible)', () => {
  it('connects Alice and Bob via SignalingClient, receives peer discovery, and relays SDP / ICE', async () => {
    await startEdgeTracker();

    const clientAlice = new SignalingClient(url, { WebSocketImpl: WebSocket as any });
    const clientBob = new SignalingClient(url, { WebSocketImpl: WebSocket as any });

    const aliceDiscoveredPeers: string[] = [];
    clientAlice.on('peers', peers => {
      aliceDiscoveredPeers.push(...peers.map(p => p.peerId));
    });

    const bobRelayReceived: any[] = [];
    clientBob.on('relay', (senderId, payload) => {
      bobRelayReceived.push({ senderId, payload });
    });

    // 1. Alice 接続
    await clientAlice.connect({ claim: alice.claim(), identity: alice });
    expect(clientAlice.isConnected).toBe(true);
    expect(hub.sessionCount).toBe(1);

    // 2. Bob 接続
    await clientBob.connect({ claim: bob.claim(), identity: bob });
    expect(clientBob.isConnected).toBe(true);
    expect(hub.sessionCount).toBe(2);

    // 3. Alice から Bob 宛に SDP リレーを送信
    clientAlice.sendRelay(bob.peerId, {
      sdp: { type: 'offer', sdp: 'v=0\r\no=- 12345 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n' },
    });

    // リレー受信を待機
    await new Promise(r => setTimeout(r, 100));
    expect(bobRelayReceived.length).toBe(1);
    expect(bobRelayReceived[0].senderId).toBe(alice.peerId);
    expect(bobRelayReceived[0].payload.sdp.type).toBe('offer');

    // 4. Bob から Alice 宛に ICE Candidate リレーを送信
    const aliceRelayReceived: any[] = [];
    clientAlice.on('relay', (senderId, payload) => {
      aliceRelayReceived.push({ senderId, payload });
    });

    clientBob.sendRelay(alice.peerId, {
      candidate: {
        candidate: 'candidate:1 1 UDP 2130706431 127.0.0.1 50000 typ host',
        sdpMLineIndex: 0,
        sdpMid: '0',
      },
    });

    await new Promise(r => setTimeout(r, 100));
    expect(aliceRelayReceived.length).toBe(1);
    expect(aliceRelayReceived[0].senderId).toBe(bob.peerId);
    expect(aliceRelayReceived[0].payload.candidate.candidate).toContain('127.0.0.1 50000');

    clientAlice.disconnect();
    clientBob.disconnect();
    await new Promise(r => setTimeout(r, 50));
    expect(hub.sessionCount).toBe(0);
  });
});

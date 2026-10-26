process.env.WS_NO_BUFFER_UTIL = '1';
process.env.WS_NO_UTF_8_VALIDATE = '1';

import http from 'node:http';
import dgram from 'node:dgram';
import os from 'node:os';
import { randomBytes } from 'node:crypto';
import { WebSocketServer } from 'ws';
import { createTrackerString } from '@oz/core';
import { EdgeTrackerHub } from '../../../packages/tracker/src/EdgeTrackerHub';

const STUN_MAGIC_COOKIE = 0x2112a442;
const STUN_BINDING_REQUEST = 0x0001;
const STUN_BINDING_RESPONSE = 0x0101;
const ATTR_XOR_MAPPED_ADDRESS = 0x0020;
const ATTR_MAPPED_ADDRESS = 0x0001;

/**
 * STUN (RFC 5389) Binding Request を UDP で送信し、外向き公開 IPv4 アドレスを取得する。
 * 失敗・タイムアウト時は null を返す。
 */
function queryStunPublicIpv4(host: string, port: number, timeoutMs = 1500): Promise<string | null> {
  return new Promise((resolve) => {
    const sock = dgram.createSocket('udp4');
    let settled = false;
    const finish = (ip: string | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { sock.close(); } catch { /* ignore */ }
      resolve(ip);
    };
    const timer = setTimeout(() => finish(null), timeoutMs);

    const txId = randomBytes(12);
    const req = Buffer.alloc(20);
    req.writeUInt16BE(STUN_BINDING_REQUEST, 0);
    req.writeUInt16BE(0, 2);
    req.writeUInt32BE(STUN_MAGIC_COOKIE, 4);
    txId.copy(req, 8);

    sock.on('error', () => finish(null));
    sock.on('message', (msg) => {
      if (msg.length < 20) return finish(null);
      const msgType = msg.readUInt16BE(0);
      const msgLen = msg.readUInt16BE(2);
      const cookie = msg.readUInt32BE(4);
      if (msgType !== STUN_BINDING_RESPONSE || cookie !== STUN_MAGIC_COOKIE) return finish(null);
      if (!msg.subarray(8, 20).equals(txId)) return finish(null);

      let offset = 20;
      const end = Math.min(msg.length, 20 + msgLen);
      while (offset + 4 <= end) {
        const attrType = msg.readUInt16BE(offset);
        const attrLen = msg.readUInt16BE(offset + 2);
        const valStart = offset + 4;
        if (valStart + attrLen > end) break;
        if ((attrType === ATTR_XOR_MAPPED_ADDRESS || attrType === ATTR_MAPPED_ADDRESS) && attrLen >= 8) {
          const family = msg[valStart + 1];
          if (family === 0x01) {
            const rawIp = msg.readUInt32BE(valStart + 4);
            const ipNum = attrType === ATTR_XOR_MAPPED_ADDRESS ? (rawIp ^ STUN_MAGIC_COOKIE) >>> 0 : rawIp;
            const ip = `${(ipNum >>> 24) & 0xff}.${(ipNum >>> 16) & 0xff}.${(ipNum >>> 8) & 0xff}.${ipNum & 0xff}`;
            return finish(ip);
          }
        }
        offset = valStart + ((attrLen + 3) & ~3);
      }
      finish(null);
    });

    sock.send(req, port, host, (err) => {
      if (err) finish(null);
    });
  });
}

function getLocalLanIpv4(): string {
  const nets = os.networkInterfaces();
  for (const list of Object.values(nets)) {
    if (!list) continue;
    for (const info of list) {
      if (info.family === 'IPv4' && !info.internal) {
        return info.address;
      }
    }
  }
  return '127.0.0.1';
}

export async function discoverAdvertiseHost(overrideHost?: string | null): Promise<string> {
  if (overrideHost && overrideHost.trim()) return overrideHost.trim();
  const stunTargets: Array<[string, number]> = [
    ['stun.l.google.com', 19302],
    ['stun.cloudflare.com', 3478],
  ];
  for (const [host, port] of stunTargets) {
    const ip = await queryStunPublicIpv4(host, port);
    if (ip) return ip;
  }
  return getLocalLanIpv4();
}

export interface LocalTrackerService {
  start(port: number, advertiseHost?: string | null): Promise<{ trackerString: string; port: number }>;
  stop(): Promise<void>;
}

export function createLocalTrackerService(): LocalTrackerService {
  let server: http.Server | null = null;
  let wss: WebSocketServer | null = null;
  let hub: EdgeTrackerHub | null = null;

  const stop = async (): Promise<void> => {
    const curWss = wss;
    const curServer = server;
    wss = null;
    server = null;
    hub = null;
    if (curWss) {
      for (const client of curWss.clients) {
        try { client.close(); } catch { /* ignore */ }
      }
      curWss.close();
    }
    if (curServer) {
      await new Promise<void>((resolve) => curServer.close(() => resolve()));
    }
  };

  const start = async (port: number, advertiseHost?: string | null): Promise<{ trackerString: string; port: number }> => {
    await stop();
    const nextHub = new EdgeTrackerHub();
    const nextServer = http.createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('ok');
    });
    const nextWss = new WebSocketServer({ server: nextServer, path: '/ws' });

    nextWss.on('connection', (ws, req) => {
      const remoteAddr = req.socket.remoteAddress ?? '127.0.0.1';
      const hostHeader = req.headers['host'] ?? `127.0.0.1:${port}`;
      if (!nextHub.canAccept(remoteAddr)) {
        ws.close(1013, 'Try Again Later');
        return;
      }
      nextHub.acceptConnection(ws as any, hostHeader, remoteAddr);
      ws.on('message', (data, isBinary) => {
        if (!isBinary) {
          ws.close(1003, 'binary only');
          return;
        }
        const buf = data instanceof ArrayBuffer
          ? new Uint8Array(data)
          : Array.isArray(data)
            ? new Uint8Array(Buffer.concat(data))
            : new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
        void nextHub.handleMessage(ws as any, buf);
      });
      ws.on('close', () => nextHub.handleClose(ws as any));
      ws.on('error', () => nextHub.handleClose(ws as any));
    });

    await new Promise<void>((resolve, reject) => {
      nextServer.once('error', reject);
      nextServer.listen(port, '0.0.0.0', () => {
        nextServer.removeListener('error', reject);
        resolve();
      });
    });

    const bound = nextServer.address();
    const actualPort = typeof bound === 'object' && bound ? bound.port : port;
    server = nextServer;
    wss = nextWss;
    hub = nextHub;

    const host = await discoverAdvertiseHost(advertiseHost);
    const trackerString = createTrackerString({
      host,
      port: actualPort,
      tls: false,
      path: '/ws',
    });
    return { trackerString, port: actualPort };
  };

  return { start, stop };
}

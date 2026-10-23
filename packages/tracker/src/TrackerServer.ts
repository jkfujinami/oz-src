import { WebSocketServer, WebSocket } from 'ws';
import type { IncomingMessage, Server } from 'http';
import type { Duplex } from 'stream';
import {
  sodium,
  sodiumReady,
  NodeIdentity,
  NODE_ID_POW,
  trackerJoinMessage,
  RateLimiter,
  TRACKER_PROTOCOL_VERSION,
  TRACKER_MAX_FRAME_BYTES,
  TRACKER_MAX_PEERS,
  parseTrackerClientMessage,
  encodeTrackerServerMessage,
  normalizeHostHeader,
  type NodeIdPowParams,
  type RateLimitConfig,
  type TrackerErrorCode,
  type TrackerServerMessage,
  type TrackerJoin,
  type TrackerRelayOut,
} from '@oz/core';
import { SessionManager } from './SessionManager';

/**
 * トラッカー側のレート制限。「1 本の WebSocket 接続あたり」で数える。
 */
export const TRACKER_LIMITS: Record<string, RateLimitConfig> = {
  // NodeId PoW の検証は Argon2id 1 回なので特に絞る
  join: { ratePerSec: 0.2, burst: 3 },
  relay: { ratePerSec: 20, burst: 60 },
};

export interface TrackerOptions {
  /** NodeId PoW のパラメータ。テストや開発では難易度を下げられる */
  powParams?: NodeIdPowParams;
  rateLimiter?: RateLimiter;
  /**
   * 受け付けるホスト名 (ノードが署名した host と照合する)。
   * 未指定なら、接続要求の Host ヘッダと照合する。リバースプロキシが Host を
   * 書き換える構成では、公開しているホスト名をここに列挙する。
   */
  allowedHosts?: string[];
  /** WebSocket を受け付けるパス */
  path?: string;
  /**
   * 他のパスへの WebSocket 要求を切る。単体で動かすときは true にする。
   * Next.js などと同じ HTTP サーバを共有するときは false (他の upgrade を邪魔しない)。
   */
  exclusiveUpgrade?: boolean;
  /** 同時に登録できるノード数 */
  maxSessions?: number;
  /** 1 つの送信元アドレスからの同時接続数 */
  maxConnectionsPerAddress?: number;
  /** 接続してから登録を終えるまでの猶予 */
  handshakeTimeoutMs?: number;
  /** peers で返す件数 */
  peersPerJoin?: number;
  /** 運用ログ。peerId や IP アドレスは渡さない (件数と理由だけ) */
  log?: (line: string) => void;
}

interface Connection {
  id: string;
  nonce: Uint8Array;
  /** Host ヘッダ (正規化済み)。無い・不正なら null */
  host: string | null;
  address: string;
  peerId: string | null;
  handshakeTimer: ReturnType<typeof setTimeout> | null;
}

/**
 * TrackerServer — ブートストラップ用のシグナリング (プロトコル v3 (バイナリフレーム))。
 *
 * プロトコルの定義は @oz/core の TrackerProtocol (クライアントと共有)。
 *
 *   1. 接続ごとに新しい nonce を hello で送る。
 *   2. join を検証する:
 *        - Bound Identity: peerId = hash(pubkey) かつ NodeId PoW を満たす
 *        - 所有証明: pubkey の秘密鍵で (nonce, peerId, host) に署名している
 *        - host: このトラッカーのホスト名である (別のトラッカーの nonce を中継させて
 *          得た署名の流用を防ぐ)
 *      どれか 1 つでも通らなければ、理由を返して切断する。
 *   3. 同じ peerId の登録が既にあれば置き換える (所有証明を通ったのは本人なので)。
 *   4. relay は登録済みの接続からだけ受け付け、送信元はサーバが知っている peerId で付け直す。
 *
 * ★ 旧実装 (v1) は peerId・pubkey・powCounter の整合しか見ていなかった。これらは
 *   P2P の JOIN で全隣人に渡る公開情報なので、誰でも他人の ID で登録し、その人宛ての
 *   接続要求 (SDP/ICE) を受け取れた。
 *
 * 保持するのは peerId と接続だけ。IP アドレスは同時接続数を数えるためにメモリ上で
 * 使うだけで、ログにも出さない。
 */
export class TrackerServer {
  private wss: WebSocketServer;
  private sessions: SessionManager;
  private connections = new Map<WebSocket, Connection>();
  private perAddress = new Map<string, number>();
  private rateLimiter: RateLimiter;
  private powParams: NodeIdPowParams;
  private allowedHosts: Set<string> | null;
  private readonly path: string;
  private readonly maxConnectionsPerAddress: number;
  private readonly handshakeTimeoutMs: number;
  private readonly peersPerJoin: number;
  private readonly log: (line: string) => void;
  private connSeq = 0;
  private stopped = false;
  private readonly onUpgrade: (req: IncomingMessage, socket: Duplex, head: Buffer) => void;

  constructor(private server: Server, options: TrackerOptions = {}) {
    this.sessions = new SessionManager({ maxSessions: options.maxSessions });
    this.rateLimiter = options.rateLimiter ?? new RateLimiter(TRACKER_LIMITS);
    this.powParams = options.powParams ?? NODE_ID_POW;
    this.path = options.path ?? '/ws';
    const exclusiveUpgrade = options.exclusiveUpgrade ?? false;
    this.maxConnectionsPerAddress = options.maxConnectionsPerAddress ?? 16;
    this.handshakeTimeoutMs = options.handshakeTimeoutMs ?? 10_000;
    this.peersPerJoin = Math.min(options.peersPerJoin ?? 8, TRACKER_MAX_PEERS);
    this.log = options.log ?? ((line) => console.log(`[tracker] ${line}`));
    this.allowedHosts = options.allowedHosts
      ? new Set(options.allowedHosts.map((h) => normalizeHostHeader(h)).filter((h): h is string => h !== null))
      : null;
    this.wss = new WebSocketServer({ noServer: true, maxPayload: TRACKER_MAX_FRAME_BYTES });

    // Next.js の HMR などと競合しないよう、指定のパスだけを受け付ける
    this.onUpgrade = (req, socket, head) => {
      let pathname: string;
      try {
        pathname = new URL(req.url ?? '/', 'http://localhost').pathname;
      } catch {
        return;
      }
      if (pathname !== this.path) {
        if (exclusiveUpgrade) socket.destroy();
        return;
      }
      this.wss.handleUpgrade(req, socket, head, (ws) => this.accept(ws, req));
    };
    server.on('upgrade', this.onUpgrade);
  }

  /** 登録済みのノード数 */
  public get sessionCount(): number {
    return this.sessions.size;
  }

  private accept(ws: WebSocket, req: IncomingMessage): void {
    const address = req.socket.remoteAddress ?? 'unknown';
    const count = this.perAddress.get(address) ?? 0;
    if (count >= this.maxConnectionsPerAddress) {
      this.sendError(ws, 'capacity');
      ws.close();
      return;
    }
    this.perAddress.set(address, count + 1);

    const conn: Connection = {
      id: `c${++this.connSeq}`,
      nonce: new Uint8Array(0),
      host: normalizeHostHeader(req.headers.host),
      address,
      peerId: null,
      handshakeTimer: null,
    };
    this.connections.set(ws, conn);

    conn.handshakeTimer = setTimeout(() => {
      conn.handshakeTimer = null;
      if (!conn.peerId) this.reject(ws, 'timeout');
    }, this.handshakeTimeoutMs);

    ws.on('message', (data: Buffer, isBinary: boolean) => {
      // ★ テキストフレームは受け付けない (JSON 時代の名残を残さない)
      void this.handleMessage(ws, conn, isBinary ? data : null);
    });
    ws.on('close', () => this.release(ws, conn));
    ws.on('error', () => { /* close で回収される */ });

    void sodiumReady.then(() => {
      if (ws.readyState !== WebSocket.OPEN) return;
      conn.nonce = sodium.randombytes_buf(32);
      this.send(ws, { type: 'hello', v: TRACKER_PROTOCOL_VERSION, nonce: conn.nonce });
    });
  }

  private release(ws: WebSocket, conn: Connection): void {
    if (!this.connections.delete(ws)) return;
    if (conn.handshakeTimer) clearTimeout(conn.handshakeTimer);
    this.rateLimiter.forget(conn.id);
    const left = (this.perAddress.get(conn.address) ?? 1) - 1;
    if (left <= 0) this.perAddress.delete(conn.address);
    else this.perAddress.set(conn.address, left);
  }

  private async handleMessage(ws: WebSocket, conn: Connection, raw: Buffer | null): Promise<void> {
    const msg = raw === null ? null : parseTrackerClientMessage(raw);
    if (!msg) return this.reject(ws, 'bad-message');

    try {
      if (msg.type === 'join') await this.handleJoin(ws, conn, msg);
      else this.handleRelay(ws, conn, msg);
    } catch {
      this.log('internal error while handling a message');
      this.reject(ws, 'bad-message');
    }
  }

  private async handleJoin(ws: WebSocket, conn: Connection, msg: TrackerJoin): Promise<void> {
    if (!this.rateLimiter.allow(conn.id, 'join')) return this.sendError(ws, 'rate-limited');
    await sodiumReady;
    if (conn.peerId) return this.sendError(ws, 'bad-message'); // 1 接続 1 登録
    if (conn.nonce.length === 0) return this.reject(ws, 'bad-message'); // hello より先の join
    if (msg.v !== TRACKER_PROTOCOL_VERSION) return this.reject(ws, 'unsupported-version');

    const claimedHost = normalizeHostHeader(msg.host);
    const hostOk = claimedHost !== null &&
      (this.allowedHosts ? this.allowedHosts.has(claimedHost) : claimedHost === conn.host);
    if (!hostOk) return this.reject(ws, 'bad-host');

    const claim = { peerId: msg.peerId, pubkey: msg.pubkey, powCounter: msg.powCounter };
    if (!NodeIdentity.verifyClaim(claim, this.powParams)) return this.reject(ws, 'invalid-identity');
    const nonce = conn.nonce;
    // nonce は 1 回限り (検証の成否にかかわらず使い捨てる)
    conn.nonce = new Uint8Array(0);
    // Bound Identity は確認済みなので、ここでは署名だけを見る (Argon2id を 2 回回さない)
    let signed = false;
    try {
      signed = sodium.crypto_sign_verify_detached(
        msg.sig,
        trackerJoinMessage(nonce, msg.peerId, msg.host),
        claim.pubkey,
      );
    } catch {
      signed = false;
    }
    if (!signed) return this.reject(ws, 'bad-signature');
    if (ws.readyState !== WebSocket.OPEN) return;

    const result = this.sessions.registerSession(ws, msg.peerId);
    if (!result.ok) return this.reject(ws, 'capacity');
    conn.peerId = msg.peerId;
    if (conn.handshakeTimer) {
      clearTimeout(conn.handshakeTimer);
      conn.handshakeTimer = null;
    }
    if (result.replaced && result.replaced !== ws) {
      // 本人が新しい接続で登録し直した。古い接続は役目を終えている
      const old = this.connections.get(result.replaced);
      if (old) old.peerId = null;
      result.replaced.close();
    }

    const peers = this.sessions.getRandomPeers(msg.peerId, this.peersPerJoin, (n) => sodium.randombytes_uniform(n));
    this.send(ws, { type: 'peers', peers });
  }

  private handleRelay(ws: WebSocket, conn: Connection, msg: TrackerRelayOut): void {
    // 送信元は接続からの逆引きだけを信じる
    const senderId = conn.peerId;
    if (!senderId) return this.reject(ws, 'not-joined');
    if (!this.rateLimiter.allow(conn.id, 'relay')) return;
    if (msg.targetPeerId === senderId) return;

    const target = this.sessions.getSession(msg.targetPeerId);
    // 相手がいない場合は黙って捨てる (誰が登録しているかを問い合わせる手段にしない)
    if (!target) return;

    // payload の中の senderId 等は信用しない。外側の senderId だけが送信元を表す
    this.send(target.ws, { type: 'relay', senderId, payload: msg.payload });
  }

  private send(ws: WebSocket, msg: TrackerServerMessage): void {
    if (ws.readyState !== WebSocket.OPEN) return;
    try {
      ws.send(encodeTrackerServerMessage(msg));
    } catch {
      this.log('dropped an unencodable message');
    }
  }

  private sendError(ws: WebSocket, code: TrackerErrorCode): void {
    this.send(ws, { type: 'error', code });
  }

  /** 理由を返して切断する */
  private reject(ws: WebSocket, code: TrackerErrorCode): void {
    this.sendError(ws, code);
    ws.close();
  }

  public shutdown(): void {
    if (this.stopped) return;
    this.stopped = true;
    this.server.off('upgrade', this.onUpgrade);
    for (const [ws, conn] of this.connections) {
      if (conn.handshakeTimer) clearTimeout(conn.handshakeTimer);
      ws.terminate();
    }
    this.connections.clear();
    this.perAddress.clear();
    this.sessions.destroy();
    this.wss.close();
  }
}

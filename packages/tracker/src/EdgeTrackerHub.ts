/**
 * EdgeTrackerHub — Cloudflare Workers (Durable Objects) および Deno Deploy の両方で
 * 外部 npm パッケージ (Node.js の `ws` / `http` / WASM Argon2id) に一切依存せず、
 * Web 標準の `crypto.subtle` (SHA-256 / Ed25519) のみで動作する Oz Tracker Protocol v3 エンジン。
 *
 * 特徴:
 * 1. CPU 時間 < 0.2ms / JOIN:
 *    Cloudflare Workers 無料枠の 10ms CPU 制限に引っかからないよう、
 *    Bound Identity (`peerId = SHA256("OZ/v3/peerid" || pubkey)[0..16]`) と
 *    Ed25519 所有証明署名 (`crypto.subtle.verify('Ed25519', ...)`) をネイティブ Web Crypto で検証。
 *    重い Argon2id PoW は P2P 接続確立時にピア同士で相互検証する。
 * 2. マルチ Isolate 連携 (BroadcastChannel 対応):
 *    Deno Deploy の複数リージョン / Isolate 間でも `BroadcastChannel` を通じて
 *    ピア一覧の共有と `RELAY_SDP` / `RELAY_ICE` の横断ルーティングが可能。
 */

import { selectJoinPeers, type RingCandidate } from './RingSelect';

export interface MinimalWebSocket {
  send(data: Uint8Array | ArrayBuffer): void;
  close(code?: number, reason?: string): void;
  readonly readyState?: number;
}

export interface EdgeTrackerOptions {
  /** 許可する Host ヘッダ一覧 (省略時は接続時の Host ヘッダと一致検査) */
  allowedHosts?: string[];
  /** 同時セッション上限 (デフォルト: 2048) */
  maxSessions?: number;
  /**
   * 登録 (JOIN) 前の接続の同時上限 (デフォルト: 256)。
   * ★ 登録前の接続はだれでも作れる。上限が無いと、接続を大量に張るだけでメモリを使い切られる
   *   (1 本あたり数十 KB)。
   */
  maxPendingConnections?: number;
  /**
   * 1 つの送信元アドレスからの同時接続数 (登録前・登録後の合計。デフォルト: 16、0 で無制限)。
   * IPv6 は /64 単位で数える。アドレスが分からない接続には適用しない。
   */
  maxConnectionsPerAddress?: number;
  /** 他の Isolate から知らされたピアを覚えておく時間 (デフォルト: 90,000ms) */
  remotePeerTtlMs?: number;
  /** 自分のセッションを他の Isolate へ知らせ直す間隔 (デフォルト: 30,000ms) */
  announceIntervalMs?: number;
  /** 1回の JOIN で返すランダムピア数の上限 (デフォルト: 8, 最大: 32) */
  peersPerJoin?: number;
  /** ハンドシェイクタイムアウト (デフォルト: 10,000ms) */
  handshakeTimeoutMs?: number;
  /** Deno Deploy 等で複数 Isolate 間をブリッジする BroadcastChannel 名 */
  broadcastChannelName?: string;
}

const PROTOCOL_VERSION = 3;
const CHALLENGE_BYTES = 32;
const PEER_ID_BYTES = 16;
const PUBKEY_BYTES = 32;
const SIGNATURE_BYTES = 64;
const MAX_PEERS = 32;
const MAX_HOST_BYTES = 254;
const MAX_SDP_BYTES = 16 * 1024 - 64;
const MAX_ICE_CANDIDATE_BYTES = 1024;
const NULL_LEN8 = 0xff;
const NULL_U16 = 0xffff;

const T_HELLO = 0x01;
const T_PEERS = 0x02;
const T_ERROR = 0x03;
const T_RELAY_SDP = 0x04;
const T_RELAY_ICE = 0x05;
const T_JOIN = 0x11;

const ERROR_CODES = [
  'bad-message',
  'unsupported-version',
  'invalid-identity',
  'bad-signature',
  'bad-host',
  'rate-limited',
  'capacity',
  'not-joined',
  'invalid-target',
  'too-large',
  'timeout',
] as const;
export type EdgeTrackerErrorCode = (typeof ERROR_CODES)[number];

const FRAME_LIMITS = {
  JOIN: 1 + 1 + PUBKEY_BYTES + 4 + SIGNATURE_BYTES + 1 + MAX_HOST_BYTES,
  RELAY: 1 + PEER_ID_BYTES + 1 + 2 + MAX_SDP_BYTES,
} as const;

const HOST_RE = /^(?:[a-z0-9.-]{1,253}|\[[0-9a-f:.]{2,45}\])(?::\d{1,5})?$/;
const PEER_ID_HEX_RE = /^[0-9a-f]{32}$/;
/** 他の Isolate から知らされたピアを覚えておく数の上限 */
const MAX_REMOTE_PEERS = 8192;
/** 1 通の alive で知らせるピアの数 */
const ALIVE_CHUNK = 512;
const PEER_ID_DOMAIN = new TextEncoder().encode('OZ/v3/peerid');
const TRACKER_JOIN_DOMAIN = new TextEncoder().encode('OZ/v1/tracker-join');
const utf8Enc = new TextEncoder();
const utf8StrictDec = new TextDecoder('utf-8', { fatal: true });

function toHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, '0');
  }
  return out;
}

function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * 同時接続数を数えるための送信元アドレスの鍵。IPv6 は /64 単位 (1 台・1 家庭に配られる範囲)。
 * ループバック・私設アドレス・取れないものは null (数えない)。
 *
 * ★ 手前のプロキシのアドレスしか見えない環境では、全員が同じアドレスに見える。
 *   そのときに全員をまとめて数えてしまわないよう、私設アドレスは数えない。
 * ★ アドレスはメモリ上で数えるだけで、ログにも応答にも出さない。
 */
export function addressKey(address: string | null | undefined): string | null {
  if (typeof address !== 'string') return null;
  let a = address.trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (a.startsWith('::ffff:') && a.includes('.')) a = a.slice(7);
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(a);
  if (v4) {
    const octets = [1, 2, 3, 4].map(i => Number(v4[i]));
    if (octets.some(o => o > 255)) return null;
    const [o1, o2] = octets;
    const internal =
      o1 === 0 || o1 === 10 || o1 === 127 || (o1 === 172 && o2 >= 16 && o2 <= 31) ||
      (o1 === 192 && o2 === 168) || (o1 === 169 && o2 === 254);
    return internal ? null : octets.join('.');
  }
  if (!a.includes(':')) return null;
  const parts = a.split('%')[0].split('::');
  if (parts.length > 2) return null;
  const head = parts[0] ? parts[0].split(':') : [];
  const tail = parts.length === 2 && parts[1] ? parts[1].split(':') : [];
  if ([...head, ...tail].some(h => !/^[0-9a-f]{1,4}$/.test(h))) return null;
  const missing = 8 - head.length - tail.length;
  if (missing < 0 || (parts.length === 1 && missing !== 0)) return null;
  const full = [...head, ...Array(missing).fill('0'), ...tail].map(h => parseInt(h, 16));
  // ::1・未指定 (::)・リンクローカル (fe80::/10)・ULA (fc00::/7) は数えない
  if (full.slice(0, 7).every(h => h === 0) && full[7] <= 1) return null;
  if ((full[0] & 0xffc0) === 0xfe80 || (full[0] & 0xfe00) === 0xfc00) return null;
  return full.slice(0, 4).map(h => h.toString(16)).join(':') + '::/64';
}

function normalizeHost(host: string | null | undefined): string | null {
  if (typeof host !== 'string') return null;
  const h = host.trim().toLowerCase();
  if (!HOST_RE.test(h)) return null;
  return h.replace(/:(80|443)$/, '');
}

function lengthPrefixed16(text: string): Uint8Array {
  const b = utf8Enc.encode(text);
  const out = new Uint8Array(2 + b.length);
  new DataView(out.buffer).setUint16(0, b.length, false);
  out.set(b, 2);
  return out;
}

function buildTrackerJoinMessage(nonce: Uint8Array, peerIdHex: string, trackerHost: string): Uint8Array {
  const lpPeer = lengthPrefixed16(peerIdHex);
  const lpHost = lengthPrefixed16(trackerHost.toLowerCase());
  const out = new Uint8Array(TRACKER_JOIN_DOMAIN.length + nonce.length + lpPeer.length + lpHost.length);
  let off = 0;
  out.set(TRACKER_JOIN_DOMAIN, off);
  off += TRACKER_JOIN_DOMAIN.length;
  out.set(nonce, off);
  off += nonce.length;
  out.set(lpPeer, off);
  off += lpPeer.length;
  out.set(lpHost, off);
  return out;
}

async function derivePeerIdBytes(pubkey: Uint8Array): Promise<Uint8Array> {
  const buf = new Uint8Array(PEER_ID_DOMAIN.length + pubkey.length);
  buf.set(PEER_ID_DOMAIN, 0);
  buf.set(pubkey, PEER_ID_DOMAIN.length);
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return new Uint8Array(hash, 0, PEER_ID_BYTES);
}

const POSITION_DOMAIN = new TextEncoder().encode('OZ/v3/position');

/** NodeIdentity.derivePosition と同じ式: SHA-256(domain || peerIdBytes) の先頭 8 バイト / 2^64 */
async function deriveRingPosition(peerIdBytes: Uint8Array): Promise<number> {
  const buf = new Uint8Array(POSITION_DOMAIN.length + peerIdBytes.length);
  buf.set(POSITION_DOMAIN, 0);
  buf.set(peerIdBytes, POSITION_DOMAIN.length);
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return Number(new DataView(hash, 0, 8).getBigUint64(0, false)) / 18446744073709551616;
}

async function verifyEd25519Signature(
  pubkey: Uint8Array,
  signature: Uint8Array,
  message: Uint8Array,
): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      pubkey.buffer.slice(pubkey.byteOffset, pubkey.byteOffset + pubkey.byteLength) as ArrayBuffer,
      { name: 'Ed25519' },
      false,
      ['verify'],
    );
    return await crypto.subtle.verify(
      'Ed25519',
      key,
      signature.buffer.slice(signature.byteOffset, signature.byteOffset + signature.byteLength) as ArrayBuffer,
      message.buffer.slice(message.byteOffset, message.byteOffset + message.byteLength) as ArrayBuffer,
    );
  } catch {
    return false;
  }
}

/**
 * RELAY_SDP (0x04) / RELAY_ICE (0x05) フレームの厳格な構文・UTF-8・長さ上限検査。
 * WireCodec の SDP_RELAY / ICE_RELAY と完全に同一の検証を行う。
 */
export function validateRelayFrame(b: Uint8Array): boolean {
  if (b.length < 1 + PEER_ID_BYTES || b.length > FRAME_LIMITS.RELAY) return false;
  const type = b[0];
  let pos = 1 + PEER_ID_BYTES;

  try {
    if (type === T_RELAY_SDP) {
      if (pos + 3 > b.length) return false;
      const sdpTypeIdx = b[pos++];
      if (sdpTypeIdx > 3) return false;
      const sdpLen = (b[pos] << 8) | b[pos + 1];
      pos += 2;
      if (sdpLen > MAX_SDP_BYTES || pos + sdpLen !== b.length) return false;
      utf8StrictDec.decode(b.subarray(pos, pos + sdpLen));
      return true;
    }

    if (type === T_RELAY_ICE) {
      if (pos + 2 > b.length) return false;
      const mLine = (b[pos] << 8) | b[pos + 1];
      pos += 2;
      if (mLine !== NULL_U16 && mLine >= NULL_U16) return false;

      // lp8(sdpMid)
      if (pos >= b.length) return false;
      const midLen = b[pos++];
      if (midLen !== NULL_LEN8) {
        if (pos + midLen > b.length) return false;
        utf8StrictDec.decode(b.subarray(pos, pos + midLen));
        pos += midLen;
      }

      // lp8(ufrag)
      if (pos >= b.length) return false;
      const ufragLen = b[pos++];
      if (ufragLen !== NULL_LEN8) {
        if (pos + ufragLen > b.length) return false;
        utf8StrictDec.decode(b.subarray(pos, pos + ufragLen));
        pos += ufragLen;
      }

      // lp16(candidate)
      if (pos + 2 > b.length) return false;
      const candLen = (b[pos] << 8) | b[pos + 1];
      pos += 2;
      if (candLen === 0 || candLen > MAX_ICE_CANDIDATE_BYTES || pos + candLen !== b.length) return false;
      utf8StrictDec.decode(b.subarray(pos, pos + candLen));
      return true;
    }
  } catch {
    return false;
  }

  return false;
}

interface ConnState {
  ws: MinimalWebSocket;
  nonce: Uint8Array;
  host: string | null;
  /** 送信元アドレスの鍵 ({@link addressKey})。数えない接続は null */
  address: string | null;
  /** 登録 (JOIN) を終えたか。同じ peerId の登録し直しで peerIdHex が消えても true のまま */
  joined: boolean;
  peerIdHex: string | null;
  peerIdBytes: Uint8Array | null;
  timer: ReturnType<typeof setTimeout> | null;
  joinTokens: number;
  lastJoinMs: number;
  relayTokens: number;
  lastRelayMs: number;
}

interface BroadcastMessage {
  kind: 'join' | 'leave' | 'relay' | 'alive';
  peerIdHex?: string;
  /** alive: この Isolate に今いるピア (知らせ直し。後から起きた Isolate も知れるように) */
  peerIds?: string[];
  targetPeerIdHex?: string;
  frameBytes?: number[];
}

export class EdgeTrackerHub {
  private readonly connections = new Map<MinimalWebSocket, ConnState>();
  private readonly sessions = new Map<
    string,
    { ws: MinimalWebSocket; peerIdBytes: Uint8Array; position: number; joinedAt: number }
  >();
  /** peerIdHex -> リング座標 (導出値のキャッシュ。BroadcastChannel 経由のピア用) */
  private readonly positionCache = new Map<string, number>();
  private readonly remotePeers = new Map<string, number>(); // peerIdHex -> seenAtMs (BroadcastChannel 経由)
  private readonly perAddress = new Map<string, number>();
  private readonly allowedHosts: Set<string> | null;
  private readonly maxSessions: number;
  private readonly maxPending: number;
  private readonly maxPerAddress: number;
  private readonly remotePeerTtlMs: number;
  private readonly peersPerJoin: number;
  private readonly handshakeTimeoutMs: number;
  private readonly bc: BroadcastChannel | null = null;
  private announceTimer: ReturnType<typeof setInterval> | null = null;
  /** 登録前の接続の数 */
  private pending = 0;

  constructor(opts: EdgeTrackerOptions = {}) {
    this.allowedHosts = opts.allowedHosts
      ? new Set(opts.allowedHosts.map(h => normalizeHost(h)).filter((h): h is string => h !== null))
      : null;
    this.maxSessions = opts.maxSessions ?? 2048;
    this.maxPending = opts.maxPendingConnections ?? 256;
    this.maxPerAddress = opts.maxConnectionsPerAddress ?? 16;
    this.remotePeerTtlMs = opts.remotePeerTtlMs ?? 90_000;
    this.peersPerJoin = Math.min(opts.peersPerJoin ?? 8, MAX_PEERS);
    this.handshakeTimeoutMs = opts.handshakeTimeoutMs ?? 10_000;

    if (opts.broadcastChannelName && typeof BroadcastChannel !== 'undefined') {
      try {
        this.bc = new BroadcastChannel(opts.broadcastChannelName);
        this.bc.onmessage = (ev: MessageEvent<BroadcastMessage>) => this.handleBroadcast(ev.data);
        // ★ 自分のセッションを定期的に知らせ直す。join は 1 回しか流れないので、後から起きた Isolate は
        //   ずっとつながっている相手 (Guard など) を知らないままになる。知らせ直しが途絶えた相手
        //   (落ちた Isolate にいたピア) は remotePeerTtlMs で忘れる。
        const interval = opts.announceIntervalMs ?? 30_000;
        this.announceTimer = setInterval(() => this.announceAndPrune(), interval);
        (this.announceTimer as unknown as { unref?: () => void }).unref?.();
      } catch {
        this.bc = null;
      }
    }
  }

  private handleBroadcast(data: BroadcastMessage | null | undefined): void {
    if (!data || typeof data !== 'object') return;
    if (
      (data.kind === 'join' || data.kind === 'leave') &&
      typeof data.peerIdHex === 'string' &&
      PEER_ID_HEX_RE.test(data.peerIdHex)
    ) {
      if (data.kind === 'join') this.rememberRemote(data.peerIdHex);
      else this.remotePeers.delete(data.peerIdHex);
    } else if (data.kind === 'alive' && Array.isArray(data.peerIds)) {
      for (const id of data.peerIds.slice(0, ALIVE_CHUNK)) {
        if (typeof id === 'string' && PEER_ID_HEX_RE.test(id)) this.rememberRemote(id);
      }
    } else if (
      data.kind === 'relay' &&
      typeof data.targetPeerIdHex === 'string' &&
      Array.isArray(data.frameBytes) &&
      data.frameBytes.length <= FRAME_LIMITS.RELAY
    ) {
      const localTarget = this.sessions.get(data.targetPeerIdHex);
      if (localTarget) {
        this.safeSend(localTarget.ws, new Uint8Array(data.frameBytes));
      }
    }
  }

  private rememberRemote(peerIdHex: string): void {
    if (!this.remotePeers.has(peerIdHex) && this.remotePeers.size >= MAX_REMOTE_PEERS) return;
    this.remotePeers.set(peerIdHex, Date.now());
  }

  private isRemoteFresh(peerIdHex: string, now: number): boolean {
    const seen = this.remotePeers.get(peerIdHex);
    return seen !== undefined && now - seen <= this.remotePeerTtlMs;
  }

  /** 自分のセッションを知らせ直し、知らせ直しの途絶えた他の Isolate のピアを忘れる */
  private announceAndPrune(): void {
    const now = Date.now();
    for (const [id, seen] of this.remotePeers) {
      if (now - seen > this.remotePeerTtlMs) this.remotePeers.delete(id);
    }
    if (!this.bc || this.sessions.size === 0) return;
    const ids = [...this.sessions.keys()];
    for (let i = 0; i < ids.length; i += ALIVE_CHUNK) {
      try {
        this.bc.postMessage({ kind: 'alive', peerIds: ids.slice(i, i + ALIVE_CHUNK) } satisfies BroadcastMessage);
      } catch {
        return;
      }
    }
  }

  public get sessionCount(): number {
    return this.sessions.size;
  }

  /** 登録前・登録後を合わせた接続の数 */
  public get connectionCount(): number {
    return this.connections.size;
  }

  /**
   * WebSocket を開く前の確認。上限を超えていれば false (呼び出し側は 503 を返し、WebSocket を作らない)。
   * ★ 予約はしない。acceptConnection でも同じ確認をする。
   */
  public canAccept(remoteAddress?: string | null): boolean {
    if (this.pending >= this.maxPending) return false;
    if (this.connections.size >= this.maxSessions + this.maxPending) return false;
    const key = addressKey(remoteAddress);
    if (key && this.maxPerAddress > 0 && (this.perAddress.get(key) ?? 0) >= this.maxPerAddress) return false;
    return true;
  }

  /**
   * 新規 WebSocket 接続を受け入れ、即座に HELLO (0x01) フレームを送信する。
   */
  public acceptConnection(
    ws: MinimalWebSocket,
    requestHostHeader: string | null | undefined,
    remoteAddress?: string | null,
  ): void {
    if (!this.canAccept(remoteAddress)) {
      this.reject(ws, 'capacity');
      return;
    }
    const nonce = crypto.getRandomValues(new Uint8Array(CHALLENGE_BYTES));
    const address = addressKey(remoteAddress);
    const state: ConnState = {
      ws,
      nonce,
      host: normalizeHost(requestHostHeader),
      address,
      joined: false,
      peerIdHex: null,
      peerIdBytes: null,
      timer: null,
      joinTokens: 3,
      lastJoinMs: Date.now(),
      relayTokens: 60,
      lastRelayMs: Date.now(),
    };
    this.connections.set(ws, state);
    this.pending++;
    if (address) this.perAddress.set(address, (this.perAddress.get(address) ?? 0) + 1);

    state.timer = setTimeout(() => {
      state.timer = null;
      if (!state.peerIdHex) {
        this.reject(ws, 'timeout');
      }
    }, this.handshakeTimeoutMs);

    // HELLO (0x01 || v=3 || nonce 32B)
    const helloFrame = new Uint8Array(2 + CHALLENGE_BYTES);
    helloFrame[0] = T_HELLO;
    helloFrame[1] = PROTOCOL_VERSION;
    helloFrame.set(nonce, 2);
    this.safeSend(ws, helloFrame);
  }

  /**
   * クライアントから受信した WebSocket メッセージを処理する。
   * 文字列フレームはプロトコル v3 規約により即座に `bad-message` で切断する。
   */
  public async handleMessage(ws: MinimalWebSocket, rawData: unknown): Promise<void> {
    const state = this.connections.get(ws);
    if (!state) return;

    let bytes: Uint8Array;
    if (rawData instanceof Uint8Array) {
      bytes = rawData;
    } else if (rawData instanceof ArrayBuffer) {
      bytes = new Uint8Array(rawData);
    } else {
      this.reject(ws, 'bad-message');
      return;
    }

    if (bytes.length < 1 || bytes.length > FRAME_LIMITS.RELAY) {
      this.reject(ws, 'bad-message');
      return;
    }

    const frameType = bytes[0];
    if (frameType === T_JOIN) {
      await this.handleJoinFrame(ws, state, bytes);
    } else if (frameType === T_RELAY_SDP || frameType === T_RELAY_ICE) {
      this.handleRelayFrame(ws, state, bytes);
    } else {
      this.reject(ws, 'bad-message');
    }
  }

  public handleClose(ws: MinimalWebSocket): void {
    const state = this.connections.get(ws);
    if (!state) return;
    this.connections.delete(ws);
    if (!state.joined) this.pending--;
    if (state.address) {
      const left = (this.perAddress.get(state.address) ?? 1) - 1;
      if (left <= 0) this.perAddress.delete(state.address);
      else this.perAddress.set(state.address, left);
    }
    if (state.timer) {
      clearTimeout(state.timer);
      state.timer = null;
    }
    if (state.peerIdHex) {
      const current = this.sessions.get(state.peerIdHex);
      if (current && current.ws === ws) {
        this.sessions.delete(state.peerIdHex);
        this.bc?.postMessage({ kind: 'leave', peerIdHex: state.peerIdHex } satisfies BroadcastMessage);
      }
    }
  }

  public destroy(): void {
    if (this.announceTimer) {
      clearInterval(this.announceTimer);
      this.announceTimer = null;
    }
    for (const [ws, state] of this.connections) {
      if (state.timer) clearTimeout(state.timer);
      try {
        ws.close();
      } catch {
        // ignore
      }
    }
    this.connections.clear();
    this.sessions.clear();
    this.remotePeers.clear();
    this.perAddress.clear();
    this.pending = 0;
    try {
      this.bc?.close();
    } catch {
      // ignore
    }
  }

  private consumeRateLimit(state: ConnState, kind: 'join' | 'relay'): boolean {
    const now = Date.now();
    if (kind === 'join') {
      const elapsedSec = Math.max(0, (now - state.lastJoinMs) / 1000);
      state.joinTokens = Math.min(3, state.joinTokens + elapsedSec * 0.2);
      state.lastJoinMs = now;
      if (state.joinTokens < 1) return false;
      state.joinTokens -= 1;
      return true;
    } else {
      const elapsedSec = Math.max(0, (now - state.lastRelayMs) / 1000);
      state.relayTokens = Math.min(60, state.relayTokens + elapsedSec * 20);
      state.lastRelayMs = now;
      if (state.relayTokens < 1) return false;
      state.relayTokens -= 1;
      return true;
    }
  }

  /** リング座標 (peerId からの導出値)。キャッシュは remotePeers と同程度の上限で打ち切る */
  private async positionOf(peerIdHex: string, peerIdBytes: Uint8Array): Promise<number> {
    const cached = this.positionCache.get(peerIdHex);
    if (cached !== undefined) return cached;
    const pos = await deriveRingPosition(peerIdBytes);
    if (this.positionCache.size >= MAX_REMOTE_PEERS) this.positionCache.clear();
    this.positionCache.set(peerIdHex, pos);
    return pos;
  }

  private async handleJoinFrame(ws: MinimalWebSocket, state: ConnState, b: Uint8Array): Promise<void> {
    if (!this.consumeRateLimit(state, 'join')) {
      this.sendError(ws, 'rate-limited');
      return;
    }
    if (state.peerIdHex) {
      this.sendError(ws, 'bad-message');
      return;
    }
    if (state.nonce.length !== CHALLENGE_BYTES) {
      this.reject(ws, 'bad-message');
      return;
    }
    // JOIN 最小長: 1(type) + 1(v) + 32(pubkey) + 4(powCounter) + 64(sig) + 1(hostLen) = 103
    if (b.length < 103 || b.length > FRAME_LIMITS.JOIN) {
      this.reject(ws, 'bad-message');
      return;
    }

    const v = b[1];
    const pubkey = b.subarray(2, 34);
    // powCounter (34..38)
    const sig = b.subarray(38, 102);
    const hostLen = b[102];
    if (103 + hostLen !== b.length) {
      this.reject(ws, 'bad-message');
      return;
    }

    let claimedHostRaw: string;
    try {
      claimedHostRaw = utf8StrictDec.decode(b.subarray(103, 103 + hostLen));
    } catch {
      this.reject(ws, 'bad-message');
      return;
    }
    if (!HOST_RE.test(claimedHostRaw)) {
      this.reject(ws, 'bad-message');
      return;
    }

    if (v !== PROTOCOL_VERSION) {
      this.reject(ws, 'unsupported-version');
      return;
    }

    const claimedHost = normalizeHost(claimedHostRaw);
    const hostOk =
      claimedHost !== null &&
      (this.allowedHosts ? this.allowedHosts.has(claimedHost) : claimedHost === state.host);
    if (!hostOk) {
      this.reject(ws, 'bad-host');
      return;
    }

    const nonce = state.nonce;
    state.nonce = new Uint8Array(0); // 1回限りで使い捨て

    const peerIdBytes = await derivePeerIdBytes(pubkey);
    const peerIdHex = toHex(peerIdBytes);
    const joinMsg = buildTrackerJoinMessage(nonce, peerIdHex, claimedHostRaw);
    const sigValid = await verifyEd25519Signature(pubkey, sig, joinMsg);
    if (!sigValid) {
      this.reject(ws, 'bad-signature');
      return;
    }
    // await を挟むのはここまで (以降のセッション表の確認と登録の間に他の JOIN を割り込ませない)
    const position = await this.positionOf(peerIdHex, peerIdBytes);

    const existing = this.sessions.get(peerIdHex);
    if (!existing && this.sessions.size >= this.maxSessions) {
      this.reject(ws, 'capacity');
      return;
    }

    if (existing && existing.ws !== ws) {
      const oldState = this.connections.get(existing.ws);
      if (oldState) oldState.peerIdHex = null;
      try {
        existing.ws.close();
      } catch {
        // ignore
      }
    }

    this.sessions.set(peerIdHex, { ws, peerIdBytes, position, joinedAt: Date.now() });
    state.peerIdHex = peerIdHex;
    state.peerIdBytes = peerIdBytes;
    if (!state.joined) {
      state.joined = true;
      this.pending--;
    }
    if (state.timer) {
      clearTimeout(state.timer);
      state.timer = null;
    }

    this.bc?.postMessage({ kind: 'join', peerIdHex } satisfies BroadcastMessage);

    // リング近傍 + 新着 + ランダムで最大 peersPerJoin 件を選んで PEERS (0x02) を返却 (RingSelect)
    const selfPosition = this.sessions.get(peerIdHex)?.position ?? null;
    const candidates: RingCandidate<Uint8Array>[] = [];
    for (const [idHex, entry] of this.sessions) {
      if (idHex !== peerIdHex) {
        candidates.push({ item: entry.peerIdBytes, position: entry.position, joinedAt: entry.joinedAt });
      }
    }
    const now = Date.now();
    for (const [remoteHex, seen] of this.remotePeers) {
      if (now - seen > this.remotePeerTtlMs) continue;
      if (remoteHex !== peerIdHex && !this.sessions.has(remoteHex)) {
        const bytes = fromHex(remoteHex);
        candidates.push({ item: bytes, position: await this.positionOf(remoteHex, bytes), joinedAt: seen });
      }
    }

    const randomInt = (n: number): number => crypto.getRandomValues(new Uint32Array(1))[0] % n;
    const selected = selectJoinPeers(selfPosition, candidates, this.peersPerJoin, randomInt);
    const peersFrame = new Uint8Array(2 + selected.length * PEER_ID_BYTES);
    peersFrame[0] = T_PEERS;
    peersFrame[1] = selected.length;
    for (let i = 0; i < selected.length; i++) {
      peersFrame.set(selected[i], 2 + i * PEER_ID_BYTES);
    }
    this.safeSend(ws, peersFrame);
  }

  private handleRelayFrame(ws: MinimalWebSocket, state: ConnState, b: Uint8Array): void {
    if (!validateRelayFrame(b)) {
      this.reject(ws, 'bad-message');
      return;
    }
    if (!state.peerIdHex || !state.peerIdBytes) {
      this.reject(ws, 'not-joined');
      return;
    }
    if (!this.consumeRateLimit(state, 'relay')) {
      return;
    }

    const targetPeerIdHex = toHex(b.subarray(1, 1 + PEER_ID_BYTES));
    if (targetPeerIdHex === state.peerIdHex) return;

    // 送信元 peerIdBytes を [1..17] に上書きして転送用フレームを作成
    const forwarded = new Uint8Array(b.length);
    forwarded.set(b);
    forwarded.set(state.peerIdBytes, 1);

    const target = this.sessions.get(targetPeerIdHex);
    if (target) {
      this.safeSend(target.ws, forwarded);
    } else if (this.bc && this.isRemoteFresh(targetPeerIdHex, Date.now())) {
      // ★ 他の Isolate にいると分かっている相手宛てだけを流す。知らない宛先まで流すと、
      //   でたらめな宛先の SDP (最大 16KB) が全 Isolate に複製されて配られる
      this.bc.postMessage({
        kind: 'relay',
        peerIdHex: state.peerIdHex,
        targetPeerIdHex,
        frameBytes: Array.from(forwarded),
      } satisfies BroadcastMessage);
    }
  }

  private sendError(ws: MinimalWebSocket, code: EdgeTrackerErrorCode): void {
    const idx = ERROR_CODES.indexOf(code);
    if (idx < 0) return;
    this.safeSend(ws, Uint8Array.of(T_ERROR, idx + 1));
  }

  private reject(ws: MinimalWebSocket, code: EdgeTrackerErrorCode): void {
    this.sendError(ws, code);
    try {
      ws.close();
    } catch {
      // ignore
    }
  }

  private safeSend(ws: MinimalWebSocket, frame: Uint8Array): void {
    if (typeof ws.readyState === 'number' && ws.readyState !== 1) return;
    try {
      ws.send(frame);
    } catch {
      // ignore
    }
  }
}

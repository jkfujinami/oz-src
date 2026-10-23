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
  peerIdHex: string | null;
  peerIdBytes: Uint8Array | null;
  timer: ReturnType<typeof setTimeout> | null;
  joinTokens: number;
  lastJoinMs: number;
  relayTokens: number;
  lastRelayMs: number;
}

interface BroadcastMessage {
  kind: 'join' | 'leave' | 'relay';
  peerIdHex: string;
  targetPeerIdHex?: string;
  frameBytes?: number[];
}

export class EdgeTrackerHub {
  private readonly connections = new Map<MinimalWebSocket, ConnState>();
  private readonly sessions = new Map<string, { ws: MinimalWebSocket; peerIdBytes: Uint8Array }>();
  private readonly remotePeers = new Map<string, number>(); // peerIdHex -> seenAtMs (BroadcastChannel 経由)
  private readonly allowedHosts: Set<string> | null;
  private readonly maxSessions: number;
  private readonly peersPerJoin: number;
  private readonly handshakeTimeoutMs: number;
  private readonly bc: BroadcastChannel | null = null;

  constructor(opts: EdgeTrackerOptions = {}) {
    this.allowedHosts = opts.allowedHosts
      ? new Set(opts.allowedHosts.map(h => normalizeHost(h)).filter((h): h is string => h !== null))
      : null;
    this.maxSessions = opts.maxSessions ?? 2048;
    this.peersPerJoin = Math.min(opts.peersPerJoin ?? 8, MAX_PEERS);
    this.handshakeTimeoutMs = opts.handshakeTimeoutMs ?? 10_000;

    if (opts.broadcastChannelName && typeof BroadcastChannel !== 'undefined') {
      try {
        this.bc = new BroadcastChannel(opts.broadcastChannelName);
        this.bc.onmessage = (ev: MessageEvent<BroadcastMessage>) => {
          const data = ev.data;
          if (!data || typeof data !== 'object') return;
          if (data.kind === 'join' && typeof data.peerIdHex === 'string') {
            this.remotePeers.set(data.peerIdHex, Date.now());
          } else if (data.kind === 'leave' && typeof data.peerIdHex === 'string') {
            this.remotePeers.delete(data.peerIdHex);
          } else if (
            data.kind === 'relay' &&
            typeof data.targetPeerIdHex === 'string' &&
            Array.isArray(data.frameBytes)
          ) {
            const localTarget = this.sessions.get(data.targetPeerIdHex);
            if (localTarget) {
              this.safeSend(localTarget.ws, new Uint8Array(data.frameBytes));
            }
          }
        };
      } catch {
        this.bc = null;
      }
    }
  }

  public get sessionCount(): number {
    return this.sessions.size;
  }

  /**
   * 新規 WebSocket 接続を受け入れ、即座に HELLO (0x01) フレームを送信する。
   */
  public acceptConnection(ws: MinimalWebSocket, requestHostHeader: string | null | undefined): void {
    const nonce = crypto.getRandomValues(new Uint8Array(CHALLENGE_BYTES));
    const state: ConnState = {
      ws,
      nonce,
      host: normalizeHost(requestHostHeader),
      peerIdHex: null,
      peerIdBytes: null,
      timer: null,
      joinTokens: 3,
      lastJoinMs: Date.now(),
      relayTokens: 60,
      lastRelayMs: Date.now(),
    };
    this.connections.set(ws, state);

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

    this.sessions.set(peerIdHex, { ws, peerIdBytes });
    state.peerIdHex = peerIdHex;
    state.peerIdBytes = peerIdBytes;
    if (state.timer) {
      clearTimeout(state.timer);
      state.timer = null;
    }

    this.bc?.postMessage({ kind: 'join', peerIdHex } satisfies BroadcastMessage);

    // ランダムに最大 peersPerJoin 件のピアを選んで PEERS (0x02) を返却
    const candidates: Uint8Array[] = [];
    for (const [idHex, entry] of this.sessions) {
      if (idHex !== peerIdHex) {
        candidates.push(entry.peerIdBytes);
      }
    }
    for (const [remoteHex] of this.remotePeers) {
      if (remoteHex !== peerIdHex && !this.sessions.has(remoteHex)) {
        candidates.push(fromHex(remoteHex));
      }
    }

    // Fisher-Yates シャッフル
    for (let i = candidates.length - 1; i > 0; i--) {
      const rand = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
      const tmp = candidates[i];
      candidates[i] = candidates[rand];
      candidates[rand] = tmp;
    }

    const selected = candidates.slice(0, this.peersPerJoin);
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
    } else if (this.bc) {
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

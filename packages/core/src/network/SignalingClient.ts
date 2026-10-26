import type { PeerId, ISignalingClient, WireNodeClaim, TrackerJoinSigner } from '../types';
import { createLogger } from '../common/Logger';
import { parseTrackerUrl, resolveTrackerWebSocketUrl } from './TrackerUrl';
import {
  TRACKER_PROTOCOL_VERSION,
  encodeTrackerClientMessage,
  parseTrackerServerMessage,
  trackerHostOf,
  isPeerId,
  type TrackerClientMessage,
  type TrackerErrorCode,
  type TrackerJoin,
  type TrackerRelayOut,
} from './TrackerProtocol';

const log = createLogger('net.signaling');

type PeersCallback = (peers: Array<{ peerId: PeerId }>) => void;
type RelayCallback = (senderId: PeerId, payload: any) => void;

/** トラッカーが設定されていない (公式のトラッカーは無いので、利用者が設定するまでこの状態) */
export class TrackerNotConfiguredError extends Error {
  constructor() {
    super('tracker URL is not configured');
    this.name = 'TrackerNotConfiguredError';
  }
}

/** トラッカーが登録を拒否した (理由のコード付き) */
export class TrackerJoinError extends Error {
  constructor(public readonly code: TrackerErrorCode) {
    super(`tracker rejected join: ${code}`);
    this.name = 'TrackerJoinError';
  }
}

export interface SignalingClientOptions {
  /** テスト用。既定は globalThis.WebSocket */
  WebSocketImpl?: typeof WebSocket;
  /** 接続待ちの上限 */
  connectTimeoutMs?: number;
}

const DEFAULT_CONNECT_TIMEOUT_MS = 10_000;
const WS_CONNECTING = 0;
const WS_OPEN = 1;

export class SignalingClient implements ISignalingClient {
  private ws: WebSocket | null = null;
  private onPeersCb?: PeersCallback;
  private onRelayCb?: RelayCallback;
  private _url: string | null = null;
  private pending: Promise<void> | null = null;
  /** setUrl / disconnect のたびに進める。古い接続のコールバックを無効にするため */
  private generation = 0;
  private readonly WebSocketImpl: typeof WebSocket | undefined;
  private readonly connectTimeoutMs: number;

  /**
   * ★ 旧実装は URL 未指定やページの場所から接続先を推測していた
   *   (Electron では ws://localhost:3000、開発時は Vite のサーバ)。
   *   利用者の知らない相手に peerId と IP を送らないよう、推測はしない。
   *   URL が無ければ connect() は失敗する。
   */
  constructor(url?: string | null, options: SignalingClientOptions = {}) {
    this.WebSocketImpl = options.WebSocketImpl ?? (globalThis as any).WebSocket;
    this.connectTimeoutMs = options.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS;
    if (url) this.setUrl(url);
  }

  public get url(): string | null {
    return this._url;
  }

  public get isConnected(): boolean {
    return this.ws !== null && this.ws.readyState === WS_OPEN;
  }

  /**
   * 接続先を変える (null で未設定に戻す)。既存の接続は切る。
   * 不正な URL は例外にし、以前の設定を残す。
   */
  public setUrl(url: string | null): void {
    let next: string | null = null;
    if (url !== null) {
      const parsed = parseTrackerUrl(url);
      if (!parsed.ok) throw new Error(`invalid tracker URL: ${parsed.reason}`);
      next = parsed.url;
    }
    this.disconnect();
    this._url = next;
    log.debug(() => `Tracker URL ${next ? 'configured' : 'cleared'}`);
  }

  public async connect(options: { claim: WireNodeClaim; identity?: TrackerJoinSigner }): Promise<void> {
    if (!this._url) throw new TrackerNotConfiguredError();
    if (this.isConnected) return;
    if (this.pending) return this.pending;
    if (!this.WebSocketImpl) throw new Error('WebSocket is not available');
    const identity = options.identity;
    if (!identity) throw new Error('tracker join requires an identity that can sign');

    // 閉じかけの古い接続は捨てる (二重接続で同じ peerId を 2 回登録しない)
    this.closeSocket();
    const generation = ++this.generation;
    const url = resolveTrackerWebSocketUrl(this._url);
    const host = trackerHostOf(url);

    const attempt = new Promise<void>((resolve, reject) => {
      log.debug(`Connecting to tracker`);
      let settled = false;
      let phase: 'hello' | 'joining' | 'joined' = 'hello';
      const ws = new this.WebSocketImpl!(url);
      // ★ フレームはバイナリ。既定 (Blob) のままだと非同期にしか読めない
      ws.binaryType = 'arraybuffer';
      this.ws = ws;

      const fail = (err: unknown) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (this.ws === ws) this.closeSocket();
        reject(err);
      };
      // hello → join → peers までを含めた上限
      const timer = setTimeout(() => fail(new Error('tracker connect timeout')), this.connectTimeoutMs);

      ws.onopen = () => {
        if (generation !== this.generation) return;
        log.debug(`Connected to tracker, waiting for hello`);
      };

      ws.onmessage = (event) => {
        if (generation !== this.generation) return;
        const msg = parseTrackerServerMessage(event.data);
        if (!msg) {
          log.warn(`Dropped malformed message from tracker`);
          return;
        }

        if (phase === 'hello') {
          if (msg.type !== 'hello') return fail(new TrackerJoinError('bad-message'));
          if (msg.v !== TRACKER_PROTOCOL_VERSION) return fail(new TrackerJoinError('unsupported-version'));
          // 接続直後に、所有証明つきの join で自身を登録する。
          // position と zones は送らない (前者は peerId から導出可能、
          // 後者は購読宣言そのものでトラッカーに興味を晒すことになる)。
          const join: TrackerJoin = {
            type: 'join',
            v: TRACKER_PROTOCOL_VERSION,
            // ★ peerId はワイヤに載せない (pubkey から導出される)。署名は identity.peerId で作られる
            peerId: identity.peerId,
            pubkey: identity.pubkey,
            powCounter: identity.powCounter,
            host,
            sig: identity.signTrackerJoin(msg.nonce, host),
          };
          phase = 'joining';
          this.sendRaw(ws, join);
          return;
        }

        if (msg.type === 'error') {
          if (phase === 'joining') return fail(new TrackerJoinError(msg.code));
          log.warn(`Tracker error: ${msg.code}`);
          return;
        }

        if (msg.type === 'peers') {
          if (phase === 'joining') {
            phase = 'joined';
            settled = true;
            clearTimeout(timer);
            log.debug(`Registered with tracker`);
            resolve();
          }
          this.onPeersCb?.(msg.peers);
          return;
        }

        if (msg.type === 'relay' && phase === 'joined') {
          this.onRelayCb?.(msg.senderId, msg.payload);
        }
      };

      ws.onerror = () => {
        // 詳細 (URL を含むことがある) はログに出さない
        log.warn(`Tracker connection error`);
        fail(new Error('tracker connection error'));
      };

      ws.onclose = () => {
        log.debug(`Disconnected from tracker`);
        fail(new Error('tracker connection closed'));
        if (this.ws === ws) this.ws = null;
      };
    });

    this.pending = attempt;
    try {
      await attempt;
    } finally {
      if (this.pending === attempt) this.pending = null;
    }
  }

  public sendRelay(targetPeerId: PeerId, payload: any): void {
    if (!this.ws || !isPeerId(targetPeerId) || typeof payload !== 'object' || payload === null) return;
    const msg: TrackerRelayOut = { type: 'relay', targetPeerId, payload };
    this.sendRaw(this.ws, msg);
  }

  private sendRaw(ws: WebSocket, msg: TrackerClientMessage): void {
    if (ws.readyState !== WS_OPEN) return;
    let frame: Uint8Array;
    try {
      frame = encodeTrackerClientMessage(msg);
    } catch {
      // 範囲違反 (大きすぎる SDP など) は送らない
      log.warn(`Dropped unencodable message to tracker`);
      return;
    }
    ws.send(frame);
  }

  public on(event: 'peers', cb: PeersCallback): void;
  public on(event: 'relay', cb: RelayCallback): void;
  public on(event: string, cb: any): void {
    if (event === 'peers') this.onPeersCb = cb;
    if (event === 'relay') this.onRelayCb = cb;
  }

  private closeSocket(): void {
    const ws = this.ws;
    this.ws = null;
    if (ws && (ws.readyState === WS_CONNECTING || ws.readyState === WS_OPEN)) {
      try { ws.close(); } catch { /* 既に閉じている */ }
    }
  }

  public disconnect(): void {
    this.generation++;
    this.pending = null;
    this.closeSocket();
  }
}

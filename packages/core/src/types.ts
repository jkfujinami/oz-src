import type { PowCommitted, PowSolution } from './crypto/PowPolicy';

export type PeerId = string;

/**
 * トラッカーに提示する Bound Identity の主張。
 *
 * position と zones は載せない:
 *   - position は peerId の純粋関数なので受け取る側が自分で計算する
 *     (申告させると詐称の余地が生まれる → Eclipse)
 *   - zones (購読ゾーン) を申告すると、そのピアが何に興味を持っているかが
 *     トラッカーと全隣人に漏れ、交差攻撃の材料になる (本家 18.6.2)
 */
export interface WireNodeClaim {
  peerId: PeerId;
  /** Ed25519 公開鍵 (32 バイト) */
  pubkey: Uint8Array;
  /** NodeId PoW の解 */
  powCounter: number;
}

// -- Signaling Serverとの通信用メッセージ --
// トラッカーとのメッセージの型は network/TrackerProtocol.ts にある (サーバと共有)

// -- Gossipの型定義 --
export interface GossipPacket {
  /**
   * SHA-256("OZ/v5/id" ‖ version ‖ time ‖ tag ‖ age ‖ payload) の先頭 16 バイトの hex (32 文字)。
   * ワイヤには載らず、decode 時に導出される (PacketCodec)。effort / nonce / 解を含めないので、解き直しても変わらない。
   */
  packet_id: string;
  /** ms。ワイヤでは OZ_EPOCH からの分 (u24)。作る側は分に丸める */
  timestamp: number;
  /** 12 ビットの tag (ワイヤでは u16 の下位 12 ビット)。板 / スレの日替わりの目印 (PacketTag 参照) */
  tag: number;
  /** スレ立てからの日数 (0..90) */
  age: number;
  /** PoW の effort の指数 e。effort = floor(2^(e/4)) */
  effort_exp: number;
  /** Equi-X の challenge に付ける u32 */
  pow_nonce: number;
  /** Equi-X の解 (16 バイト) */
  pow_solution: Uint8Array;
  /** SIV 暗号文 (siv 16 バイト ‖ 暗号文) */
  payload: Uint8Array;
}

// ── インターフェース抽象群 (アーキテクチャ設計通り) ──

export interface IPeerConnection {
  readonly peerId: PeerId;
  /** peerId から導出された値。相手の申告ではない */
  readonly position: number;
  readonly rtt: number;
  readonly isConnected: boolean;
  /** HELLO/JOIN のハンドシェイクで Bound Identity を検証済みか */
  readonly isVerified: boolean;
  readonly direction?: 'inbound' | 'outbound';
  send(msg: Uint8Array | string): void;
  close(): void;
}

export interface IPeerManager {
  readonly peers: ReadonlyMap<PeerId, IPeerConnection>;
  readonly degree: number;
  readonly myPeerId: PeerId;
  readonly myPosition: number;
  connect(peerId: PeerId, initiator?: boolean, viaPeerId?: PeerId): IPeerConnection | Promise<IPeerConnection> | undefined;
  disconnect(peerId: PeerId): void;
  // 高レベルバイナリ送信 (Wire V2)
  sendMessage(peerId: PeerId, type: number, payload: any): void;
  /** outbound (自分で選んで張った) 接続の数 */
  readonly outboundCount?: number;
  /** 次数が上限を超えていれば、Sybil 対策の優先順位に従って調整する */
  rebalance?(newcomerId?: PeerId): void;
  /** 相手の出所の鍵 ('lan' / 'unknown' / 'pending' / ハッシュ)。PeerManager を参照 */
  originOf?(peerId: PeerId): string;
  /** 自分と同じ出所か (同じ LAN・同じ公開 IP) */
  isOwnOrigin?(origin: string): boolean;
  /** 経路の出所の制限を外してよいか (開発用の網だけ true) */
  readonly sameOriginHopsAllowed?: boolean;
  on(event: string, handler: (...args: any[]) => void): void;
  off(event: string, handler: (...args: any[]) => void): void;
}

// ── Message Dispatcher ──
export interface IMessageDispatcher {
  register(type: number, handler: (peerId: PeerId, payload: any) => void): void;
  dispatch(peerId: PeerId, type: number, payload: any): void;
}

// ── Signaling Client ──
/** トラッカーへの登録に署名できる主体 (NodeIdentity が満たす) */
export interface TrackerJoinSigner {
  readonly peerId: PeerId;
  readonly pubkey: Uint8Array;
  readonly powCounter: number;
  signTrackerJoin(nonce: Uint8Array, trackerHost: string): Uint8Array;
}

export interface ISignalingClient {
  readonly isConnected?: boolean;
  /** 現在の接続先 (未設定なら null)。URL を持たない実装 (テスト用など) では undefined */
  readonly url?: string | null;
  /** 接続先を変える。不正な URL は例外。既存の接続は切る */
  setUrl?(url: string | null): void;
  /**
   * トラッカーへ接続して登録する。登録が受け付けられたら解決する。
   * identity は所有証明 (トラッカーの nonce への署名) に使う。
   */
  connect(options: { claim: WireNodeClaim; identity?: TrackerJoinSigner }): Promise<void>;
  sendRelay(targetPeerId: PeerId, payload: any): void;
  disconnect(): void;
  on(event: 'peers', cb: (peers: Array<{ peerId: PeerId }>) => void): void;
  on(event: 'relay', cb: (senderId: PeerId, payload: any) => void): void;
}

// ── Storage ──
export interface DAGMetadata {
  parents: string[];
  cumulative_pow: number;
  thread_root: string;
}

// ── Key Management ──
export interface IKeyManager {
  deriveThreadKey(boardKey: Uint8Array, threadId: string): Uint8Array;
}

// ── Identity & Signing ──
export interface SignatureResult {
  sessionPubkey: Uint8Array;
  sessionSignature: Uint8Array;
  tripPubkey: Uint8Array | null;
  tripSignature: Uint8Array | null;
}

/**
 * セッション鍵を選ぶ文脈。同じ (板, スレ, 日) なら同じ鍵、違えば別の鍵 (投稿同士を鍵で紐付けさせない)。
 * day = パケット時刻の UTC 日。スレ立ては新しいスレの id を threadId に使う。
 */
export interface SignContext {
  boardId: string;
  threadId: string;
  day: number;
}

export interface IIdentity {
  /**
   * トリップを持つか。持つ投稿はトリップの署名だけを載せ、セッション鍵は載せない (PostCodec)。
   * 署名対象にこの有無が入るので、sign の前に決まっていなければならない。
   */
  readonly hasTrip: boolean;
  /**
   * ctx は型の上では省略可 (古いテスト用の実装との互換のため)。本番の PacketBuilder は常に渡す。
   */
  sign(data: Uint8Array, ctx?: SignContext): SignatureResult;
}

// ── Anti-Spam (PoW) ──
export interface IPoWEngine {
  /** コミット済みヘッダ全体 (effort 込み) に対して Equi-X の PoW を探索する */
  compute(header: PowCommitted): Promise<PowSolution>;
}

// ── Crypto Engine ──
/**
 * SIV (決定的 AEAD)。nonce を別に持たない: payload = siv(16) ‖ 暗号文。
 * aad は外側ヘッダの先頭 7 バイト (version ‖ time ‖ tag ‖ age)。
 */
export interface ICryptoEngine {
  encrypt(key: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Uint8Array;
  decrypt(key: Uint8Array, payload: Uint8Array, aad: Uint8Array): Uint8Array | null;
}

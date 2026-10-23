import type {
  IPeerConnection,
  IPeerManager,
  PeerId,
  IMessageDispatcher,
  ISignalingClient,
} from '../types';
import { WebRTCPeer } from './WebRTCPeer';
import { RingPosition } from './RingPosition';
import { groupCap } from './NetGroup';
import { RING_MESH } from '../constants';
import { WireCodec, WIRE_BODY_BYTES, MAX_PEX_ENTRIES, MAX_ICE_CANDIDATE_BYTES, MAX_CATCHUP_FRAME_BYTES, MAX_LEASESET_FRAME_BYTES, MAX_TUNNEL_FRAME_BYTES, MAX_OZZY_FRAME_BYTES, MAX_OZZY_WORKER_FRAME_BYTES } from './wire/WireCodec';
import { LEASESET_MAX_BYTES } from './storage/LeaseSet';
import { OnionRouter } from '../crypto/OnionRouter';
import { WireType } from './wire/WireTypes';
import { RateLimiter } from './RateLimiter';
import { PeerMisbehaviorManager, ViolationType } from './PeerMisbehaviorManager';
import {
  NodeIdentity,
  NODE_ID_POW,
  CHALLENGE_BYTES,
  type NodeIdPowParams,
  type SignedNodeClaim,
} from '../crypto/NodeIdentity';
import { toBytes } from '../crypto/PowPolicy';
import { TrackerNotConfiguredError } from './SignalingClient';
import { createLogger } from '../common/Logger';

const log = createLogger('net.peer');

/** peerId は Bound Identity なので hex 32 文字に固定されている */
const PEER_ID_RE = /^[0-9a-f]{32}$/;

/**
 * WireType → レートリミッタのカテゴリ。
 *
 * ★ すべての WireType を必ずどこかに割り当てる (Record で網羅を型検査させる)。
 *   旧実装は Partial で、PING / PONG などが表から漏れて無制限に受け付けられていた。
 */
const RATE_CATEGORY: Record<Exclude<WireType, WireType.UNKNOWN>, string> = {
  [WireType.HELLO]: 'handshake',
  [WireType.JOIN]: 'handshake',
  [WireType.PING]: 'control',
  [WireType.PONG]: 'control',
  [WireType.GOSSIP]: 'gossip',
  [WireType.STEM]: 'gossip',
  [WireType.ONION_STEM]: 'onion',
  // ★ 追いつきは GOSSIP と別バケット。同じバケットだと、Guard からの追いつき (数千件) が
  //   「Guard からの GOSSIP の枠」を使い切り、いま流れている投稿 (ライブ) が落ちる
  //   (旧方式で HINT を分けたのと同じ理由。tests/peer/PeerManagerLimits.test.ts の「追いつきを使い切っても GOSSIP の予算は減らない」)。
  [WireType.CATCHUP_REQ]: 'catchup',
  [WireType.CATCHUP_DATA]: 'catchup',
  [WireType.CATCHUP_END]: 'catchup',
  // ★ leaseSet も別バケット。GOSSIP と混ぜると、同期 (全 leaseSet の一括受信) が投稿の枠を食う
  [WireType.LEASESET]: 'leaseset',
  [WireType.LEASESET_SYNC_REQ]: 'leaseset',
  [WireType.LEASESET_SYNC]: 'leaseset',
  // ★ トンネルも別バケット (応答は 16KiB のフレームの列。GOSSIP の枠を食わせない)
  [WireType.TUNNEL_REGISTER]: 'tunnel',
  [WireType.TUNNEL_REGISTERED]: 'tunnel',
  [WireType.TUNNEL_SEND]: 'tunnel',
  [WireType.TUNNEL_FWD]: 'tunnel',
  [WireType.TUNNEL_DELIVER]: 'tunnel',
  [WireType.TUNNEL_REPLY]: 'tunnel',
  [WireType.TUNNEL_RET]: 'tunnel',
  [WireType.TUNNEL_RESULT]: 'tunnel',
  [WireType.TUNNEL_ERROR]: 'tunnel',
  [WireType.PEX_REQUEST]: 'pex',
  [WireType.PEX_RESPONSE]: 'pex',
  [WireType.SDP_RELAY]: 'signaling',
  [WireType.ICE_RELAY]: 'signaling',
  // ★ Ozzy の代理取得の応答も別バケット (4KiB のフレームの列で、1 チャンク約 1,050 フレーム)
  [WireType.OZZY_REPLY]: 'ozzy',
  [WireType.OZZY_RESULT]: 'ozzy',
  [WireType.OZZY_UP]: 'ozzy',
  [WireType.OZZY_UP_FWD]: 'ozzy',
  // 中継 Worker の広告の交換は PEX と同じ枠 (1 分に 1 回程度)
  [WireType.OZZY_WORKER_REQ]: 'pex',
  [WireType.OZZY_WORKER_ADS]: 'pex',
};

/**
 * ハンドシェイク完了前でも通す WireType。
 * これ以外は Bound Identity の検証が済むまで一切ディスパッチしない。
 */
const PRE_HANDSHAKE_TYPES = new Set<WireType>([WireType.HELLO, WireType.JOIN]);

/**
 * WireType ごとのフレーム長の上限 (bytes)。デコードの前に確かめる。
 *
 * レート制限は件数しか数えないので、1 件を巨大にすると (再組み立ての上限 1MB)
 * デコード負荷を何百倍にも水増しできる。正規のメッセージが取りうる大きさで切る。
 * CATCHUP_DATA だけは投稿を束ねて運ぶので 16KiB (WebRTC DataChannel で安全に送れる大きさ)。
 *
 * ★ 固定レイアウトの型 (HELLO / JOIN / PING / PONG / PEX) は、正規の長さそのものを上限にする
 *   (1 + 本体。WireCodec.WIRE_BODY_BYTES)。余りバイトはどのみち decode が拒否するが、
 *   巨大なフレームをデコーダに触らせないために入口でも切る。
 */
export const MAX_FRAME_BYTES: Readonly<Partial<Record<WireType, number>>> = {
  [WireType.HELLO]: 1 + WIRE_BODY_BYTES.HELLO,
  [WireType.JOIN]: 1 + WIRE_BODY_BYTES.JOIN,
  [WireType.PING]: 1 + WIRE_BODY_BYTES.PING,
  [WireType.PONG]: 1 + WIRE_BODY_BYTES.PONG,
  // ★ セルは 1,200 バイト固定、投稿は本文 2048 バイトまで (パケット最大 約 2.45KB、
  //   Stem の item は Slot 込みで 約 2.6KB)。上限はそれに余裕を足した値にする。
  //   大きすぎる上限は、1 フレームを巨大にしてデコード処理を水増しされる余地になる。
  //   最大の正規フレームがこの上限に収まることは CellCapacity.test.ts で固定してある。
  [WireType.ONION_STEM]: 1 + OnionRouter.CELL_SIZE,
  [WireType.GOSSIP]: 3072,
  [WireType.STEM]: 3072,
  [WireType.CATCHUP_REQ]: 1 + WIRE_BODY_BYTES.CATCHUP_REQ,
  [WireType.CATCHUP_DATA]: MAX_CATCHUP_FRAME_BYTES,
  [WireType.CATCHUP_END]: 1 + WIRE_BODY_BYTES.CATCHUP_END,
  [WireType.LEASESET]: 1 + LEASESET_MAX_BYTES,
  [WireType.LEASESET_SYNC_REQ]: 1,
  [WireType.LEASESET_SYNC]: MAX_LEASESET_FRAME_BYTES,
  [WireType.TUNNEL_REGISTER]: 1 + WIRE_BODY_BYTES.TUNNEL_REGISTER,
  [WireType.TUNNEL_REGISTERED]: 1 + WIRE_BODY_BYTES.TUNNEL_REGISTERED,
  [WireType.TUNNEL_SEND]: MAX_TUNNEL_FRAME_BYTES,
  [WireType.TUNNEL_FWD]: MAX_TUNNEL_FRAME_BYTES,
  [WireType.TUNNEL_DELIVER]: MAX_TUNNEL_FRAME_BYTES,
  [WireType.TUNNEL_REPLY]: MAX_TUNNEL_FRAME_BYTES,
  [WireType.TUNNEL_RET]: MAX_TUNNEL_FRAME_BYTES,
  [WireType.TUNNEL_RESULT]: MAX_TUNNEL_FRAME_BYTES,
  [WireType.TUNNEL_ERROR]: 1 + WIRE_BODY_BYTES.TUNNEL_ERROR,
  [WireType.PEX_REQUEST]: 1,
  [WireType.PEX_RESPONSE]: 2 + MAX_PEX_ENTRIES * WIRE_BODY_BYTES.PEX_ENTRY,
  [WireType.SDP_RELAY]: 16 * 1024,
  // target 16 + sender 16 + mLineIndex 2 + sdpMid (最大 255) + ufrag (最大 255) + 長さ 2 + 本文 (最大 512)
  [WireType.ICE_RELAY]: 1 + 32 + 2 + 255 + 255 + 2 + MAX_ICE_CANDIDATE_BYTES,
  [WireType.OZZY_REPLY]: MAX_OZZY_FRAME_BYTES,
  [WireType.OZZY_RESULT]: MAX_OZZY_FRAME_BYTES,
  [WireType.OZZY_UP]: MAX_OZZY_FRAME_BYTES,
  [WireType.OZZY_UP_FWD]: MAX_OZZY_FRAME_BYTES,
  [WireType.OZZY_WORKER_REQ]: 1,
  [WireType.OZZY_WORKER_ADS]: MAX_OZZY_WORKER_FRAME_BYTES,
};
const DEFAULT_MAX_FRAME_BYTES = 1024 * 1024;

/**
 * ハンドシェイク未完了 (未検証) の接続の同時上限。一般枠 (下の予約枠は別)。
 * 利用者は 8。多数の利用者を受け入れる Guard 役は 64 (maxDegree が大きい役目なので、同時に
 * 握手中の相手も多い。8 のままだと正直な利用者の波だけで埋まる)。
 */
const MAX_PENDING_PEERS = 8;
const MAX_PENDING_PEERS_GUARD = 64;
/**
 * 1 つの「出所」が同時に握手待ちにできる数。
 * 出所 = 攻撃者が無償では増やせないもの:
 *   - トラッカー経由の offer: トラッカーが認証した送信者 peerId (参加時に NodeId PoW と署名を要求する)
 *   - P2P 中継 (SDP_RELAY) の offer: 中継してきた隣人。メッセージ内の senderId は名乗りに過ぎず、
 *     乱数で毎回変えられるので出所にならない
 */
const MAX_PENDING_PER_SOURCE = 2;
/**
 * 待ち受け Guard への outbound ダイヤルに別枠で取っておく数 (一般枠を消費せず、一般枠が満杯でも通る)。
 * inbound のゴミで Guard に張りに行けなくなると、利用者は信頼できない隣人へ落ちるため。
 * 待ち受け Guard のサンプルは 3 本 (GUARD_SAMPLE_SIZE)。不在の Guard が先に枠を握っても
 * 到達できる Guard を締め出さないよう、サンプル数 + 1 を取る。上限が小さいと実際に
 * 「不在の 2 本でダイヤルが埋まり、生きている 3 本目に張れない」ことが起きた。
 */
const PENDING_RESERVED_FOR_GUARD_DIAL = 4;
/** 待ち受け Guard 用の予約枠に足せるバックボーンの数の上限 (Guard の数は数台〜数十台を想定) */
const PENDING_RESERVED_BACKBONE_MAX = 32;
/**
 * バックボーンで、peerId の大きい側が自分から張らずに待つ時間。両側が同時に張ると互いの offer が
 * すれ違う (glare) ので、peerId の小さい側だけが張る。小さい側が落ちていても、この時間を過ぎたら
 * 大きい側からも張る。
 */
const BACKBONE_DIAL_GRACE_MS = 45_000;
/**
 * 枠が満杯のとき、ICE は繋がったが JOIN が来ない inbound を追い出してよくなる経過時間。
 * (繋がらないものは年齢を問わず最優先で追い出す。繋がった相手は実際に WebRTC を
 *  終えており、正直な相手なら JOIN は数百 ms で届くので、5 秒黙っていれば居座りと見なす)
 */
const PENDING_EVICT_CONNECTED_AFTER_MS = 5_000;
/**
 * 接続 (DataChannel open) に至らない試行を捨てるまで。
 * 実際の WebRTC (STUN のみ) は通常 1〜3 秒、劣悪な回線でも 5〜6 秒程度で繋がるため、
 * 余裕を見て 8 秒。旧 15 秒は「繋がらない試行が枠を握る時間」をそのまま攻撃者の持ち時間にしていた。
 */
const PENDING_CONNECT_TIMEOUT_MS = 8_000;
/**
 * 検証 (HELLO/JOIN) まで含めて捨てるまで (試行の開始から)。繋がってからの握手は
 * DataChannel 上の往復 1 回 + 署名検証 (数 ms) なので、接続の猶予にあと 4 秒で足りる。旧 30 秒。
 */
const PENDING_HANDSHAKE_TIMEOUT_MS = 12_000;
/** 未接続ピアから先行して届いたシグナルのバッファ上限 (1 送信者あたり / 送信者数) */
const MAX_SIGNALS_PER_SENDER = 32;
const MAX_SIGNAL_SENDERS = 32;

/** トラッカーから切り離すまでの通常の待ち時間 */
const TRACKER_DETACH_MS = 15_000;
/** 待ち受け Guard の検証を待って、切り離しを延ばせる上限 (登録からの時間) */
const TRACKER_DETACH_GUARD_CAP_MS = 60_000;
/** 切り離しを延ばしている間に、Guard の検証を見に行く間隔 */
const TRACKER_DETACH_RECHECK_MS = 2_000;
/** 待ち受け Guard への再接続の間隔 (失敗するたびに倍にして上限まで) */
const GUARD_REDIAL_BASE_MS = 30_000;
const GUARD_REDIAL_MAX_MS = 5 * 60_000;

/**
 * PeerManager が信頼 Guard について知るための窓口 (実体は GuardManager)。
 * PeerManager は Guard の方針を持たず、「つなぎ続ける相手」と「信頼してよい相手か」だけを訊く。
 */
export interface GuardSource {
  /** 接続を保ちたい Guard の peerId (優先順) */
  wantedGuardIds(): PeerId[];
  /** 信頼 Guard か (リストにあり、公開鍵が一致する) */
  isTrusted(peerId: PeerId, pubkey: Uint8Array | null | undefined): boolean;
}

export class PeerManager implements IPeerManager {
  private _peers: Map<PeerId, WebRTCPeer> = new Map();
  private signaling: ISignalingClient;
  private eventListeners: Map<string, Array<(...args: any[]) => void>> = new Map();
  private pexRoutes: Map<PeerId, PeerId> = new Map();
  private pendingSignals: Map<PeerId, any[]> = new Map();
  private coolDowns: Map<PeerId, number> = new Map();
  private rateLimiter: RateLimiter;
  private powParams: NodeIdPowParams;
  private identity: NodeIdentity;
  public readonly misbehavior: PeerMisbehaviorManager;
  private reannounceTimer: any = null;
  private detachTimer: ReturnType<typeof setTimeout> | null = null;
  /** 直近にトラッカーへ登録した時刻 (Guard 待ちで切り離しを延ばす上限の起点) */
  private trackerAttachedAt = 0;
  private guardSource: GuardSource | null = null;
  /**
   * Guard 同士のバックボーン (他の信頼 Guard すべて)。Guard 役のノードだけが設定する (history v2 §4.4)。
   * 待ち受け Guard (guardSource のサンプル) と同じ機構で、つなぎ続ける相手に加わる。
   */
  private backboneSource: (() => PeerId[]) | null = null;
  /** バックボーンの相手を最初に「足りない」と見た時刻 (どちらから張るかの猶予の起点) */
  private backboneMissingSince = new Map<PeerId, number>();
  /** 待ち受け Guard への再接続の予定 (peerId → 次に試してよい時刻と、今の間隔) */
  private guardDial = new Map<PeerId, { nextAt: number; delay: number }>();
  private readonly maxDegreeLimit: number;
  private readonly maxPendingPeers: number;
  /** 握手待ち (未検証) の接続の出所と開始時刻。検証済み・切断で消す */
  private pendingMeta = new Map<PeerId, { source: string; startedAt: number; reserved: boolean }>();
  private readonly keepTrackerAttached: boolean;
  /** stop() 済みか。停止後は新規接続も再アナウンスもしない */
  private stopped = false;
  private readonly allowMissingDtlsFingerprint: boolean;
  private readonly iceServersProvider?: () => RTCIceServer[];

  public readonly myPeerId: PeerId;
  public readonly myPosition: number;
  private dispatcher: IMessageDispatcher;

  constructor(
    identity: NodeIdentity,
    dispatcher: IMessageDispatcher,
    signaling: ISignalingClient,
    options: {
      rateLimiter?: RateLimiter;
      powParams?: NodeIdPowParams;
      misbehavior?: PeerMisbehaviorManager;
      /**
       * ★ テスト専用。SDP に a=fingerprint が無い環境 (偽の WebRTC 等) で
       *   JOIN の DTLS 束縛を省略する。実運用では絶対に true にしないこと
       *   (中継型 MITM による ID 乗っ取りが再び可能になる)。
       */
      allowMissingDtlsFingerprint?: boolean;
      /**
       * 次数の上限。既定は RING_MESH.MAX_DEGREE。Guard 役のノードだけが大きくする
       * (多数の利用者を受け入れる役目なので)。
       */
      maxDegree?: number;
      /** 握手待ち (未検証) 接続の同時上限。既定は利用者 8、Guard 役 (keepTrackerAttached) 64 */
      maxPendingPeers?: number;
      /** true ならトラッカーから切り離さない (Guard 役。利用者が自分を見つけられるように) */
      keepTrackerAttached?: boolean;
      /** WebRTC に渡す STUN の一覧を、接続のたびに返す (トラッカーが後から変わっても追従する) */
      iceServers?: () => RTCIceServer[];
    } = {},
  ) {
    this.iceServersProvider = options.iceServers;
    this.maxDegreeLimit = options.maxDegree ?? RING_MESH.MAX_DEGREE;
    this.keepTrackerAttached = options.keepTrackerAttached ?? false;
    this.maxPendingPeers = options.maxPendingPeers ?? (this.keepTrackerAttached ? MAX_PENDING_PEERS_GUARD : MAX_PENDING_PEERS);
    this.allowMissingDtlsFingerprint = options.allowMissingDtlsFingerprint ?? false;
    this.identity = identity;
    this.myPeerId = identity.peerId;
    this.myPosition = identity.position;
    this.dispatcher = dispatcher;
    this.signaling = signaling;
    this.rateLimiter = options.rateLimiter ?? new RateLimiter();
    this.powParams = options.powParams ?? NODE_ID_POW;
    this.misbehavior = options.misbehavior ?? new PeerMisbehaviorManager();

    this.registerInternalHandlers();

    this.signaling.on('peers', (peers) => this.handleTrackerPeers(peers));
    // トラッカー経由: senderId はトラッカーが参加時に認証した peerId (サーバが付け直す)
    this.signaling.on('relay', (senderId, payload) => this.handleRelay(senderId, payload));
  }

  private registerInternalHandlers() {
    // ── SDP / ICE の P2P リレー ──
    const handleRelay = (peerId: PeerId, msg: any, type: WireType) => {
      if (msg?.targetPeerId === this.myPeerId) {
        // ★ senderId は中継経路上の誰でも名乗れる値である (認証されていない)。
        //   ここで pexRoutes を書き換えると、既存の正規接続のシグナリング経路まで
        //   乗っ取られる。経路は「新しく接続を作るとき」にだけ handleRelay が記録する。
        const sender = msg.senderId;
        if (typeof sender === 'string' && PEER_ID_RE.test(sender)) {
          this.handleRelay(sender, msg, peerId);
        }
      } else if (typeof msg?.targetPeerId === 'string' && this._peers.has(msg.targetPeerId)) {
        this.sendMessage(msg.targetPeerId, type, msg);
      }
    };

    this.dispatcher.register(WireType.SDP_RELAY, (peerId, payload) => handleRelay(peerId, payload, WireType.SDP_RELAY));
    this.dispatcher.register(WireType.ICE_RELAY, (peerId, payload) => handleRelay(peerId, payload, WireType.ICE_RELAY));

    // ── ハンドシェイク ──
    this.dispatcher.register(WireType.HELLO, (peerId, msg) => this.handleHello(peerId, msg));
    this.dispatcher.register(WireType.JOIN, (peerId, msg) => this.handleJoin(peerId, msg));
  }

  /**
   * HELLO を受けたら、その challenge に署名した JOIN を返す。
   */
  private handleHello(peerId: PeerId, msg: any) {
    const challenge = toBytes(msg?.challenge);
    if (challenge.length !== CHALLENGE_BYTES) {
      log.warn(`HELLO from ${peerId.substring(0, 8)} with malformed challenge`);
      return;
    }
    const peer = this._peers.get(peerId);
    if (!peer) return;

    // 自分 (署名者) の視点: 自分の指紋 = local、検証者の指紋 = remote
    const fp = peer.dtlsFingerprints();
    if (!this.fingerprintsUsable(fp)) {
      log.warn(`Refusing to sign JOIN for ${peerId.substring(0, 8)}: DTLS fingerprint unavailable`);
      return;
    }
    this.sendMessage(peerId, WireType.JOIN, this.identity.signClaim(challenge, {
      verifierId: peerId,
      signerFingerprint: fp.local,
      verifierFingerprint: fp.remote,
    }));
  }

  /**
   * 指紋が JOIN の束縛に使えるか。
   * 実ブラウザの WebRTC では必ず存在する。欠けている場合は束縛が成立しないので、
   * 明示的に許可されていない限りハンドシェイクを進めない (fail-closed)。
   */
  private fingerprintsUsable(fp: { local: string; remote: string }): boolean {
    if (fp.local && fp.remote) return true;
    return this.allowMissingDtlsFingerprint;
  }

  /**
   * JOIN の検証。ここが Eclipse 攻撃を止める要。
   *
   * 旧実装は `peer.updatePosition(msg.position)` と、相手が名乗った座標を
   * 無検証で採用していた。現在は
   *   1. 主張された peerId が、この接続の相手 peerId と一致するか
   *   2. peerId = SHA256("OZ/v3/peerid" ‖ pubkey)[0..16] か  (束縛)
   *   3. NodeId PoW (Argon2id) を満たすか                        (グラインド耐性)
   *   4. 自分がこの接続で送った challenge への署名が正しいか      (所有証明・リプレイ耐性)
   * をすべて通ったときだけ verified にする。座標はそもそも受け取らない。
   */
  private handleJoin(peerId: PeerId, msg: any) {
    const peer = this._peers.get(peerId);
    if (!peer) return;

    if (peer.isVerified) {
      // ハンドシェイクは 1 接続 1 回。再送は無視する (PoW 検証の再実行を避ける)
      return;
    }

    const expected = peer.challenge;
    if (!expected) {
      log.warn(`JOIN from ${peerId.substring(0, 8)} before HELLO was sent`);
      return;
    }

    // ★ JOIN は peerId も challenge も運ばない。peerId は pubkey から導出し、challenge は自分が
    //   この接続で送った値 (expected) で検証する。名乗りを受け取って比べるのではなく、
    //   「この接続の相手の peerId」と「この pubkey から導かれる peerId」が一致するかを見る。
    const pubkey = toBytes(msg?.pubkey);
    const claim: SignedNodeClaim = {
      peerId: pubkey.length === 32 ? NodeIdentity.derivePeerId(pubkey) : '',
      pubkey,
      powCounter: typeof msg?.powCounter === 'number' ? msg.powCounter : -1,
      signature: toBytes(msg?.signature),
    };

    // 名乗った peerId と、この接続の相手として認識している peerId が
    // 一致しなければならない。ここが緩いと「別人になりすました JOIN」が通る。
    // ★ ハンドシェイク失敗では違反を記録しない (切断だけ)。
    //
    //   この接続の peerId は、シグナリングで「相手が名乗っただけ」の値である。
    //   旧実装はここで名乗られた ID に 100 点 (即 BAN) を付けていたため、
    //   攻撃者は正規ノード V を名乗って接続し、わざと JOIN に失敗するだけで
    //   V を 1 時間 BAN させられた。隣人ごとに繰り返せば Eclipse が完成する。
    if (claim.peerId !== peerId) {
      log.warn(
        `[PeerManager] JOIN identity mismatch: connection=${peerId.substring(0, 8)} claimed=${String(claim.peerId).substring(0, 8)}`,
      );
      this.disconnect(peerId);
      return;
    }

    // 自分 (検証者) の視点: 署名者の指紋 = remote、自分の指紋 = local
    const fp = peer.dtlsFingerprints();
    if (!this.fingerprintsUsable(fp)) {
      log.warn(`JOIN from ${peerId.substring(0, 8)} rejected: DTLS fingerprint unavailable`);
      this.disconnect(peerId);
      return;
    }
    const binding = {
      verifierId: this.myPeerId,
      signerFingerprint: fp.remote,
      verifierFingerprint: fp.local,
    };

    if (!NodeIdentity.verifySignedClaim(claim, expected, binding, this.powParams)) {
      log.warn(`JOIN verification failed for ${peerId.substring(0, 8)} — dropping peer`);
      this.disconnect(peerId);
      return;
    }

    peer.markVerified(claim.pubkey, claim.powCounter);
    this.pendingMeta.delete(peerId);
    log.debug(
      `[PeerManager] Peer ${peerId.substring(0, 8)} verified (bound position: ${peer.position.toFixed(6)})`,
    );
    this.emit('peer:verified', peer);

    // 次数の調整は「検証が済んだ後」にだけ行う (未認証の offer で既存リンクを追い出させない)。
    // 出所の区分 (getStats) を求めてから行う。取れなくても 'unknown' として進む。
    void peer.resolveNetGroup().then((group) => {
      this.noteGroup(group);
      this.rebalance(peerId);
    });
  }

  /**
   * 検証済みピアが MAX_DEGREE を超えたときの調整。超えている間は 1 人ずつ外す。
   *
   * 外す順番 (Sybil 対策。どれも「拒否」ではなく「枠が足りないときの優先順位」):
   *   1. outbound (自分で選んだ相手) は外さない。inbound の新顔が何人来ても、
   *      自分で選んだ接続は押し出されない (A1)
   *   2. ローカルリンク (リング上の最近接 LOCAL_LINKS 人) は外さない
   *   3. 残りの inbound のうち、出所の区分が多すぎるものから (A2)
   *   4. 同じなら、観測期間が短い (新しい) ものから (A3)
   *   5. 同じなら、リング上で遠いものから
   *
   * 網が小さいうちは次数が上限に届かないので、この調整自体が起きない
   * (初期成長を妨げない)。
   */
  public rebalance(newcomerId?: PeerId): void {
    for (let guard = 0; guard < this.maxDegreeLimit * 2; guard++) {
      const verified = this.verifiedPeers;
      if (verified.length <= this.maxDegreeLimit) return;
      const victim = this.pickEvictionVictim(verified, newcomerId);
      if (!victim) return;
      if (victim.peerId !== newcomerId) this.coolDowns.set(victim.peerId, Date.now());
      log.debug(() => `rebalance: dropping ${victim.direction} ${victim.peerId.substring(0, 8)}`);
      this.disconnect(victim.peerId);
    }
  }

  private pickEvictionVictim(verified: WebRTCPeer[], newcomerId?: PeerId): WebRTCPeer | null {
    const distance = (p: WebRTCPeer) => RingPosition.distance(this.myPosition, p.position);
    const byDistance = [...verified].sort((a, b) => distance(a) - distance(b));
    const local = new Set(byDistance.slice(0, RING_MESH.LOCAL_LINKS).map(p => p.peerId));
    // ★ 信頼 Guard は外さない。サンプルの Guard を押し出されると、利用者は信頼できない
    //   隣人へフォールバックしてしまう (inbound の新顔を大量に送り込むだけで起こせる)。
    for (const p of verified) if (this.isTrustedGuardPeer(p)) local.add(p.peerId);

    let pool = verified.filter(p => p.direction === 'inbound' && !local.has(p.peerId));
    if (pool.length === 0) {
      // 外せる inbound が無い: 枠を超えた新顔 (outbound) の方を諦める
      const newcomer = newcomerId ? verified.find(p => p.peerId === newcomerId) : undefined;
      if (newcomer && !local.has(newcomer.peerId)) return newcomer;
      pool = verified.filter(p => !local.has(p.peerId) && p.peerId !== newcomerId);
      if (pool.length === 0) return null;
    }

    const counts = new Map<string, number>();
    for (const p of verified) {
      const g = p.netGroup ?? 'unknown';
      counts.set(g, (counts.get(g) ?? 0) + 1);
    }
    const cap = groupCap(this.maxDegreeLimit, this.seenGroups.size);
    const overflow = (p: WebRTCPeer) => (counts.get(p.netGroup ?? 'unknown') ?? 0) - cap;

    pool.sort((a, b) =>
      overflow(b) - overflow(a) ||
      (b.verifiedAt ?? 0) - (a.verifiedAt ?? 0) ||
      distance(b) - distance(a),
    );
    return pool[0];
  }

  private isTrustedGuardPeer(p: WebRTCPeer): boolean {
    return this.guardSource?.isTrusted(p.peerId, p.pubkey) === true;
  }

  /** 信頼 Guard か (リストの peerId と公開鍵の両方が一致)。TunnelRelay が、バックボーンの相手に高い枠を許すのに使う */
  public isTrustedGuard(peerId: PeerId): boolean {
    const p = this._peers.get(peerId);
    return !!p && p.isVerified && this.isTrustedGuardPeer(p);
  }

  /** このセッションで見えた出所の区分。区分の上限 ({@link groupCap}) の母数になる */
  private seenGroups = new Set<string>();

  private noteGroup(group: string): void {
    if (this.seenGroups.size >= 1024 && !this.seenGroups.has(group)) return;
    this.seenGroups.add(group);
  }

  /** outbound (自分で選んで張った) 接続の数。接続中のものも含む */
  public get outboundCount(): number {
    let n = 0;
    for (const p of this._peers.values()) if (p.direction === 'outbound') n++;
    return n;
  }

  /** ハンドシェイクが済んでいない接続 (接続中 + 接続済み未検証) の数 */
  private get pendingCount(): number {
    let n = 0;
    for (const p of this._peers.values()) if (!p.isVerified) n++;
    return n;
  }

  private isWantedGuard(peerId: PeerId): boolean {
    return this.guardSource?.wantedGuardIds().includes(peerId) === true || this.isBackbonePeer(peerId);
  }

  /** 待ち受け Guard / バックボーンへのダイヤルに別枠で取っておく数 */
  private reservedDialCap(): number {
    const backbone = this.backboneSource ? Math.min(this.backboneSource().length, PENDING_RESERVED_BACKBONE_MAX) : 0;
    return PENDING_RESERVED_FOR_GUARD_DIAL + backbone;
  }

  /** 現在握手待ちの試行 (メタ情報と実体が一致するもの) */
  private pendingEntries(): Array<{ peerId: PeerId; peer: WebRTCPeer; source: string; startedAt: number; reserved: boolean }> {
    const out = [];
    for (const [peerId, meta] of this.pendingMeta) {
      const peer = this._peers.get(peerId);
      if (peer && !peer.isVerified) out.push({ peerId, peer, ...meta });
    }
    return out;
  }

  /**
   * 新しい握手待ちを受け入れてよいか (必要なら古い試行を追い出して空ける)。
   *
   * ★ 旧実装は「全体で 8 本、満杯なら新着を拒否」だけだった。攻撃者は ICE を終えない offer を
   *   (でたらめな senderId で) 数秒おきに 8 通送るだけで枠を埋め続けられ、正直な利用者は Guard に
   *   つながれず、猶予のあと信頼できない隣人へフォールバックさせられた (DoS = 匿名性攻撃)。
   *
   *   1. 出所ごとの上限 (MAX_PENDING_PER_SOURCE): 出所は攻撃者が無償で増やせないもの
   *      (connect の呼び出し元で決める。トラッカー認証済みの送信者 / 中継した隣人)。
   *      自分で張りに行く接続 ('self') は自分の判断なので対象外。
   *   2. 待ち受け Guard へのダイヤルは別枠 (PENDING_RESERVED_FOR_GUARD_DIAL)。一般枠が満杯でも通る。
   *   3. 一般枠が満杯なら「進捗のない inbound のうち最古のもの」を追い出す。
   *      ランダムに落とす (random early drop) 案もあるが、正直な試行が運悪く落ちる確率が
   *      攻撃が弱くても 0 にならない。最古優先なら、正直な試行は入った時点で最も新しく、
   *      追い出されるのは「その後に N 件 (一般枠の数) の新着が、正直な握手が終わる 1〜3 秒の間に
   *      続いた」場合だけ。攻撃者の滞留 (古い) が先に抜けるので、定常攻撃でも枠を決定論的に
   *      占有し続けられない。追い出せるのは inbound だけ (自分で選んだ outbound は攻撃者が
   *      差し込めない)。繋がっていない試行を最優先とし、繋がったが JOIN を寄こさない試行は
   *      5 秒経ってから対象にする。
   */
  private admitPending(source: string, reserved: boolean): boolean {
    const entries = this.pendingEntries();
    if (reserved) {
      return entries.filter((e) => e.reserved).length < this.reservedDialCap();
    }
    if (source !== 'self' && entries.filter((e) => e.source === source).length >= MAX_PENDING_PER_SOURCE) {
      return false;
    }
    const general = entries.filter((e) => !e.reserved);
    if (general.length < this.maxPendingPeers) return true;

    const now = Date.now();
    const oldestFirst = (a: { startedAt: number }, b: { startedAt: number }) => a.startedAt - b.startedAt;
    const inbound = general.filter((e) => e.peer.direction === 'inbound');
    const victim =
      inbound.filter((e) => !e.peer.isConnected).sort(oldestFirst)[0] ??
      inbound.filter((e) => now - e.startedAt >= PENDING_EVICT_CONNECTED_AFTER_MS).sort(oldestFirst)[0];
    if (!victim) return false;
    log.debug(() => `pending full: evicting stalled inbound ${victim.peerId.substring(0, 8)} (${victim.source})`);
    this.disconnect(victim.peerId);
    return true;
  }

  public get peers(): ReadonlyMap<PeerId, IPeerConnection> {
    return this._peers;
  }

  public get degree(): number {
    let count = 0;
    for (const peer of this._peers.values()) {
      if (peer.isConnected) count++;
    }
    return count;
  }

  /** ハンドシェイク済みのピアだけを返す。 */
  public get verifiedPeers(): WebRTCPeer[] {
    return Array.from(this._peers.values()).filter((p) => p.isConnected && p.isVerified);
  }

  /** 公開鍵が判明している検証済みピアのリスト (Onion Circuit 構築用) */
  public get verifiedPeersWithKeys(): Array<{ peerId: PeerId; pubkey: Uint8Array }> {
    return this.verifiedPeers
      .filter((p): p is WebRTCPeer & { pubkey: Uint8Array } => p.pubkey !== null)
      .map((p) => ({ peerId: p.peerId, pubkey: p.pubkey }));
  }

  public get nodeIdentity(): NodeIdentity {
    return this.identity;
  }

  /** NodeId PoW の検証パラメータ (他モジュールが claim を検証するときに揃える) */
  public get nodeIdPowParams(): NodeIdPowParams {
    return this.powParams;
  }

  public async start(): Promise<void> {
    log.debug(`Starting as ${this.myPeerId} (bound position: ${this.myPosition.toFixed(6)})`);
    this.stopped = false;

    // 接続数低下時または孤立防止の動的再アナウンス (Adaptive Re-announce)。
    // ★ 旧実装は最初のトラッカー接続が成功した後にだけこれを仕掛けていたため、
    //   起動時にトラッカーへ届かないと二度と再試行しなかった。先に仕掛ける。
    if (this.reannounceTimer) clearInterval(this.reannounceTimer);
    this.reannounceTimer = setInterval(() => {
      if (this.stopped) return;
      if (this.degree < 4 && !this.signaling.isConnected) {
        log.info(`Degree dropped to ${this.degree} (< 4). Reconnecting to tracker for network repair.`);
        this.connectTracker().catch((err) => {
          if (err instanceof TrackerNotConfiguredError) return;
          log.warn(`Adaptive tracker reconnect failed: ${err}`);
        });
      }
      // 待ち受け Guard が切れていれば張り直す (新しいタイマーは足さず、この周期に相乗りする)
      void this.maintainWantedGuards();
    }, 30_000);

    await this.connectTracker();
    void this.maintainWantedGuards();
  }

  /**
   * 信頼 Guard の窓口を設定する (null で解除)。OzNode が GuardManager を渡す。
   */
  public setGuardSource(source: GuardSource | null): void {
    this.guardSource = source;
    if (!source && !this.backboneSource) this.guardDial.clear();
  }

  /**
   * Guard 役のバックボーン (他の信頼 Guard すべて) を設定する (null で解除)。
   *
   * ★ 待ち受け Guard と同じ機構 (maintainWantedGuards の再接続・指数バックオフ・予約枠) で保つ。
   *   次数の上限 (GUARD_MAX_DEGREE) の中で、バックボーンの Guard は信頼 Guard として押し出されない
   *   (pickEvictionVictim)。つまり利用者がどれだけ来ても、バックボーンの枠は空けられる。
   *   自分の peerId は含めないこと (OzNode が除く)。
   */
  public setBackboneSource(source: (() => PeerId[]) | null): void {
    this.backboneSource = source;
    this.backboneMissingSince.clear();
    if (!source && !this.guardSource) this.guardDial.clear();
  }

  /** つなぎ続けたい Guard (待ち受け Guard + バックボーン。重複なし) */
  private wantedAll(): PeerId[] {
    const out = new Set<PeerId>(this.guardSource?.wantedGuardIds() ?? []);
    for (const id of this.backboneSource?.() ?? []) if (id !== this.myPeerId) out.add(id);
    return Array.from(out);
  }

  private isBackbonePeer(peerId: PeerId): boolean {
    return this.backboneSource?.().includes(peerId) === true;
  }

  /** 待ち受け Guard のうち、まだ検証済みでつながっていないもの */
  private wantedGuardsUnverified(): PeerId[] {
    return this.wantedAll().filter((id) => {
      const p = this._peers.get(id);
      return !(p && p.isConnected && p.isVerified);
    });
  }

  /**
   * 待ち受け Guard (GuardManager のサンプル) への接続を保つ。
   *
   * Guard は自分から探しに行く: 近隣から来る相手を待つだけだと、トラッカーに居座る
   * 攻撃者の方が先に隣人になってしまう。シグナリングはトラッカー経由なので、
   * Guard が 1 つもつながっていなければトラッカーへ繋ぎ直す。
   * 失敗は 30 秒 → 60 秒 → … (上限 5 分) と間隔を空けて再試行する。
   */
  public async maintainWantedGuards(): Promise<void> {
    if (this.stopped || (!this.guardSource && !this.backboneSource)) return;
    const wanted = this.wantedAll();
    const wantedSet = new Set(wanted);
    for (const id of Array.from(this.guardDial.keys())) if (!wantedSet.has(id)) this.guardDial.delete(id);
    if (wanted.length === 0) return;

    const missing = this.wantedGuardsUnverified();
    for (const id of wanted) if (!missing.includes(id)) this.guardDial.delete(id);
    if (missing.length === 0) return;

    // 1 つもつながっていないなら、到達するためにトラッカーへ繋ぎ直す
    if (missing.length === wanted.length && !this.signaling.isConnected) {
      try {
        await this.reconnectTracker();
      } catch (err) {
        if (!(err instanceof TrackerNotConfiguredError)) log.warn('Could not reach the tracker to connect to a guard');
        return;
      }
    }
    if (this.stopped || !this.signaling.isConnected) return;

    const now = Date.now();
    const sampleIds = new Set(this.guardSource?.wantedGuardIds() ?? []);
    for (const id of Array.from(this.backboneMissingSince.keys())) if (!missing.includes(id)) this.backboneMissingSince.delete(id);
    for (const id of missing) {
      // バックボーンだけの相手 (自分のサンプルでもある相手は、利用者として張るので常に張る):
      // peerId の小さい側から張る。大きい側は猶予のあいだ相手からの接続を待つ
      if (!sampleIds.has(id) && this.isBackbonePeer(id) && this.myPeerId > id) {
        const since = this.backboneMissingSince.get(id) ?? now;
        this.backboneMissingSince.set(id, since);
        if (now - since < BACKBONE_DIAL_GRACE_MS) continue;
      }
      const state = this.guardDial.get(id);
      if (state && now < state.nextAt) continue;
      const delay = state ? Math.min(state.delay * 2, GUARD_REDIAL_MAX_MS) : GUARD_REDIAL_BASE_MS;
      this.guardDial.set(id, { nextAt: now + delay, delay });
      log.debug(() => `dialing wanted guard ${id.substring(0, 8)}`);
      this.connect(id, true);
    }
  }

  /**
   * トラッカーへ接続して自身を登録し、しばらくしたら切り離す。
   *
   * 購読ゾーンは送らない。トラッカーに申告すると、そのピアが何に興味を
   * 持っているかをトラッカーと全ピアに晒すことになる (本家 18.6.2 の交差攻撃)。
   * 接続し続けないのも同じ理由で、トラッカーが見られる期間を短くするため。
   */
  private async connectTracker(): Promise<void> {
    if (this.stopped) return;
    await this.signaling.connect({ claim: this.identity.claim(), identity: this.identity });
    if (this.stopped) {
      this.signaling.disconnect();
      return;
    }

    this.trackerAttachedAt = Date.now();
    if (this.detachTimer) clearTimeout(this.detachTimer);
    // Guard 役は切り離さない (利用者がトラッカー経由で自分を見つけられるように)
    if (this.keepTrackerAttached) return;
    this.scheduleDetach(TRACKER_DETACH_MS);
  }

  /**
   * トラッカーからの切り離しを予約する。
   *
   * ★ 待ち受け Guard が検証済みになる前に切り離すと、Guard へのシグナリング (トラッカー経由)
   *   が届かず、利用者は信頼できない隣人にフォールバックしてしまう。そのため、
   *   Guard の検証が済むまで (登録から最大 60 秒) 切り離しを延ばす。
   *   上限があるのは、トラッカーに晒される時間を無制限に延ばさないため。
   */
  private scheduleDetach(afterMs: number): void {
    this.detachTimer = setTimeout(() => {
      this.detachTimer = null;
      if (this.stopped) return;
      const waited = Date.now() - this.trackerAttachedAt;
      if (this.wantedGuardsUnverified().length > 0 && waited < TRACKER_DETACH_GUARD_CAP_MS) {
        this.scheduleDetach(Math.min(TRACKER_DETACH_RECHECK_MS, TRACKER_DETACH_GUARD_CAP_MS - waited));
        return;
      }
      log.debug(`Detaching from Tracker Server! Entering Fully Decentralized Mode.`);
      this.signaling.disconnect();
    }, afterMs);
  }

  /**
   * トラッカーの設定を変えた直後に呼ぶ。停止中は何もしない。
   * 失敗 (未設定・到達不能) は例外で返す。以後は再アナウンスが再試行する。
   */
  public async reconnectTracker(): Promise<void> {
    if (this.stopped) return;
    if (this.detachTimer) {
      clearTimeout(this.detachTimer);
      this.detachTimer = null;
    }
    await this.connectTracker();
  }

  /**
   * 停止。以後トラッカーへの再アナウンスも新規接続も行わない。
   *
   * ★ 旧実装の OzNode.stop() はこれを呼んでおらず、停止後も 30 秒ごとに
   *   「次数 < 4」を検出してトラッカーへ peerId と IP を再登録し、接続を
   *   張り直していた。利用者が「止めた」と思った後も網に参加し続けていた。
   */
  public stop(): void {
    this.stopped = true;
    if (this.reannounceTimer) {
      clearInterval(this.reannounceTimer);
      this.reannounceTimer = null;
    }
    if (this.detachTimer) {
      clearTimeout(this.detachTimer);
      this.detachTimer = null;
    }
    this.pendingSignals.clear();
    this.guardDial.clear();
    this.signaling.disconnect();
    for (const peerId of Array.from(this._peers.keys())) {
      this.disconnect(peerId);
    }
  }

  private handleTrackerPeers(peers: Array<{ peerId: PeerId }>): void {
    if (this.stopped) return;
    if (!Array.isArray(peers)) return;
    log.debug(`Received ${peers.length} peers from tracker`);

    // 旧実装はここで「共有ゾーン数が多い順」に並べ替えていた。
    // これはトラッカーに購読ゾーンを申告している前提の処理で、
    // 交差攻撃の材料そのものだったため撤去した。
    for (const p of peers) {
      if (!p || typeof p.peerId !== 'string') continue;
      if (!this._peers.has(p.peerId) && this.degree < this.maxDegreeLimit) {
        this.connect(p.peerId, true);
      }
    }
  }

  /**
   * @param viaPeerId DataChannel 越しに中継されてきた場合、その中継者
   */
  private handleRelay(senderId: PeerId, msg: any, viaPeerId?: PeerId): void {
    if (this.stopped) return;
    if (this.misbehavior.isBanned(senderId)) {
      return;
    }
    if (!PEER_ID_RE.test(senderId)) {
      log.warn(`Rejecting relay from malformed peerId`);
      return;
    }

    const isOffer = msg?.sdp?.type === 'offer';

    // ★ 相手が同じ peerId でセッションを張り直した場合の処理。
    //
    //   Bound Identity により peerId が端末ごとに永続化された。以前は
    //   起動のたびに乱数で変わっていたので、相手がリロードすれば必ず
    //   別ピアとして扱われた。今は同じ ID で戻ってくる。
    //
    //   古い WebRTCPeer に新しい offer を流し込むと、既に死んでいる
    //   RTCPeerConnection に setRemoteDescription することになり、
    //   ICE は connected になるのに DataChannel が二度と open しない。
    //   offer は「張り直したい」という意思表示なので、古い接続を畳む。
    //
    //   ★ ただし検証済みで生きている接続は置き換えない。
    //     senderId は中継経路上の誰でも名乗れるので、旧実装では
    //     「正規隣人 V を名乗る offer」1 通で V との接続を切らせ、
    //     攻撃者の端点に V の名前で繋ぎ直させることができた。
    //     本物の V が張り直す場合、古い接続は ICE 切断 / onclose で先に畳まれる。
    if (isOffer && this._peers.has(senderId)) {
      const existing = this._peers.get(senderId)!;
      if (existing.isVerified && existing.isConnected) {
        log.warn(`Ignoring re-offer for live verified peer ${senderId.substring(0, 8)}`);
        return;
      }
      log.debug(`Peer ${senderId.substring(0, 8)} re-offered; replacing stale connection`);
      this.disconnect(senderId);
      // disconnect のクールダウンには入れない (正当な再接続なので)
      this.coolDowns.delete(senderId);
    }

    let peer = this._peers.get(senderId);

    if (!peer) {
      // ★ P2P のフレームは型名を運ばない (sdp を持つもの = SDP_RELAY)。トラッカー経由の JSON も同じ形
      const isNewSession = isOffer || msg?.type === 'offer' || msg?.sdp !== undefined;

      if (isNewSession) {
        log.debug(`Received Offer via relay from ${senderId.substring(0, 8)}`);
        // ★ 未認証の offer で既存リンクを追い出さない。
        //   旧実装は MAX_DEGREE に達していると offer 1 通ごとに正規の
        //   ロングレンジリンクを切り、30 秒のクールダウンに入れていた。
        //   次数の調整は検証後に rebalance() が行う。
        peer = this.connect(senderId, false, viaPeerId);

        if (!peer) return;
        peer.signal(msg);

        const buffered = this.pendingSignals.get(senderId) || [];
        for (const sig of buffered) peer.signal(sig);
        this.pendingSignals.delete(senderId);
      } else {
        // オファー以外（ICE等）が先に来た場合は一旦バッファ
        if (this.coolDowns.has(senderId) && Date.now() - this.coolDowns.get(senderId)! < 30_000) return;
        const buffered = this.pendingSignals.get(senderId) || [];
        // 未接続ピアのバッファは無制限に伸ばさない (メモリ枯渇の防止)
        if (buffered.length >= MAX_SIGNALS_PER_SENDER) return;
        // 送信者の数にも上限を置く。senderId は自由に名乗れるので、
        // 1 人あたりの上限だけでは乱数 ID を変えながら無限に積める。
        if (!this.pendingSignals.has(senderId) && this.pendingSignals.size >= MAX_SIGNAL_SENDERS) {
          const oldest = this.pendingSignals.keys().next().value;
          if (oldest !== undefined) this.pendingSignals.delete(oldest);
        }
        buffered.push(msg);
        this.pendingSignals.set(senderId, buffered);
      }
      return;
    }

    peer.signal(msg);
  }

  public connect(peerId: PeerId, initiator: boolean = true, viaPeerId?: PeerId): WebRTCPeer | undefined {
    if (this.stopped) return undefined;
    if (this.misbehavior.isBanned(peerId)) {
      log.warn(`Refusing connection to banned peer ${peerId.substring(0, 8)}`);
      return undefined;
    }

    // Bound Identity なので peerId の形式は固定。壊れた ID は座標計算も
    // 壊れるため、ここで確実に落とす。
    if (!PEER_ID_RE.test(peerId)) {
      log.warn(`Refusing to connect to malformed peerId`);
      return undefined;
    }
    if (peerId === this.myPeerId) return undefined;

    const existing = this._peers.get(peerId);
    if (existing) {
      if (existing.isConnected || existing.isConnecting) return existing;
      log.debug(`Cleaning up zombie peer ${peerId.substring(0, 8)} before reconnect`);
      this.disconnect(peerId);
    }

    const lastEvicted = this.coolDowns.get(peerId);
    if (lastEvicted && Date.now() - lastEvicted < 30_000) return undefined;
    if (lastEvicted) this.coolDowns.delete(peerId);

    // ★ ハンドシェイク未完了の接続数に上限を置く。
    //   degree は接続済みしか数えないため、旧実装では乱数 senderId の offer を
    //   送るたびに RTCPeerConnection が無制限に増え、ブラウザの上限で
    //   ノードが機能停止した。
    //   上限は「出所ごと」と「全体」の二段 (admitPending)。全体が満杯でも、進捗のない
    //   inbound の試行を追い出して空ける。
    const reserved = initiator && this.isWantedGuard(peerId);
    const source = initiator ? 'self' : viaPeerId ? `via:${viaPeerId}` : `trk:${peerId}`;
    if (!this.admitPending(source, reserved)) {
      log.warn(`Refusing connection to ${peerId.substring(0, 8)}: too many pending handshakes`);
      return undefined;
    }

    if (viaPeerId) this.pexRoutes.set(peerId, viaPeerId);

    // 下の各コールバックは「自分がまだ登録されている本人か」を確認してから
    // 破棄処理を行う。同じ peerId で張り直したとき、古いインスタンスの
    // onclose やタイムアウトが遅れて発火し、差し替わった新しい接続を
    // 巻き込んで消してしまうのを防ぐ (RTCDataChannel.onclose は非同期に来る)。
    let created: WebRTCPeer | undefined;
    const isStillCurrent = () => created !== undefined && this._peers.get(peerId) === created;

    const peer = new WebRTCPeer({
      iceServers: this.iceServersProvider?.() ?? [],
      localId: this.myPeerId,
      remoteId: peerId,
      initiator,
      onSignal: (payload) => {
        let relayMsg: any;
        if (payload.renegotiate || payload.type === 'offer' || payload.type === 'answer' || payload.type === 'rollback') {
          const sdpPlain = (typeof payload.toJSON === 'function')
            ? payload.toJSON()
            : { type: payload.type, sdp: payload.sdp };

          // position / zones は載せない (peerId から導出できる / 漏らしてはいけない)
          relayMsg = {
            type: 'sdp-relay',
            targetPeerId: peerId,
            senderId: this.myPeerId,
            sdp: sdpPlain,
          };
        } else if (payload.candidate) {
          const icePlain = (typeof payload.toJSON === 'function') ? payload.toJSON() : payload;
          relayMsg = {
            type: 'ice-relay',
            targetPeerId: peerId,
            senderId: this.myPeerId,
            candidate: icePlain,
          };
        }

        if (!relayMsg) return;

        const via = this.pexRoutes.get(peerId);
        if (via && this._peers.has(via)) {
          this.sendMessage(via, relayMsg.type === 'sdp-relay' ? WireType.SDP_RELAY : WireType.ICE_RELAY, relayMsg);
        } else {
          this.signaling.sendRelay(peerId, relayMsg);
        }
      },
      onConnect: () => {
        this.emit('peer:connect', peer);
        // 接続が開いたら即座にチャレンジを送る。相手はこれに署名した JOIN を返す。
        const challenge = NodeIdentity.newChallenge();
        peer.setChallenge(challenge);
        this.sendMessage(peerId, WireType.HELLO, { challenge });
      },
      onDisconnect: () => {
        if (isStillCurrent()) this.disconnect(peerId);
      },
      onData: (data) => this.handleData(peerId, data),
    });

    created = peer;
    this._peers.set(peerId, peer);
    this.pendingMeta.set(peerId, { source, startedAt: Date.now(), reserved });

    setTimeout(() => {
      if (isStillCurrent() && !peer.isConnected) this.disconnect(peerId);
    }, PENDING_CONNECT_TIMEOUT_MS);

    // ハンドシェイクが完了しないピアは居座らせない
    setTimeout(() => {
      if (isStillCurrent() && !peer.isVerified) {
        log.warn(`Handshake timeout for ${peerId.substring(0, 8)} — dropping`);
        this.disconnect(peerId);
      }
    }, PENDING_HANDSHAKE_TIMEOUT_MS);

    return peer;
  }

  /**
   * 受信データの入口。ここで
   *   1. レート制限 (本家 18.11.3 —「実際の防御はレート制限」)
   *   2. ハンドシェイク未完了ピアの遮断
   * を掛けてからディスパッチする。
   */
  private handleData(peerId: PeerId, data: Uint8Array | string): void {
    if (this.misbehavior.isBanned(peerId)) {
      this.disconnect(peerId);
      return;
    }

    const bytes = (data instanceof Uint8Array) ? data : new TextEncoder().encode(data);
    const limit = MAX_FRAME_BYTES[bytes[0] as WireType] ?? DEFAULT_MAX_FRAME_BYTES;
    if (bytes.byteLength > limit) {
      log.debug(() => `dropped oversized frame (type=0x${bytes[0]?.toString(16)}, ${bytes.byteLength}B) from ${peerId.substring(0, 8)}`);
      return;
    }
    const decoded = WireCodec.decode(bytes);

    const peer = this._peers.get(peerId);
    // 違反点は「本人確認が済んだ peerId」にだけ付ける。未検証の接続の
    // peerId は名乗りに過ぎず、そこに点を付けると第三者を陥れられる。
    const authenticated = peer?.isVerified === true;

    if (decoded.type === WireType.UNKNOWN) {
      log.warn(`Dropped unknown wire message from ${peerId.substring(0, 8)}`);
      if (authenticated) {
        this.misbehavior.recordViolation(peerId, ViolationType.MALFORMED_WIRE, 'Unknown wire message');
      }
      this.disconnect(peerId);
      return;
    }

    // ★ レート超過は「捨てる」だけで、違反点は付けない。
    //   Gossip は正直な隣人がそのまま中継してくるものなので、網全体で投稿が
    //   集中すると正直な隣人も一時的に上限を超える。旧実装はこれに 25 点を付けて
    //   4 回で BAN していたため、攻撃者が安い PoW のパケットを網に流すだけで
    //   正直なノード同士が互いを BAN し合い、網が自然に分断された。
    //   流量の上限はトークンバケットが既に保証している。
    const category = RATE_CATEGORY[decoded.type as Exclude<WireType, WireType.UNKNOWN>] ?? 'unknown';
    if (!this.rateLimiter.allow(peerId, category)) {
      log.trace(() => `rate limited ${category} from ${peerId.substring(0, 8)}`);
      return;
    }

    if (!PRE_HANDSHAKE_TYPES.has(decoded.type) && !peer?.isVerified) {
      return;
    }

    this.dispatcher.dispatch(peerId, decoded.type, decoded.payload);
    this.emit('peer:data', peerId, data);
  }

  public sendMessage(peerId: PeerId, type: WireType, payload: any): void {
    const peer = this._peers.get(peerId);
    if (peer && peer.isConnected) {
      let frame: Uint8Array;
      try {
        frame = WireCodec.encode(type, payload);
      } catch (e) {
        // 呼び出し側のバグ (範囲外の値など)。1 通を送れないだけで、ここから先へは波及させない
        log.warn(`encode failed (type=0x${type.toString(16)}): ${e}`);
        return;
      }
      peer.send(frame);
    }
  }

  /** その隣人の DataChannel に溜まっている送信待ちのバイト数 (送り過ぎないよう送出を待つのに使う)。不明なら 0 */
  public bufferedAmountOf(peerId: PeerId): number {
    const peer = this._peers.get(peerId) as { bufferedAmount?: number } | undefined;
    return typeof peer?.bufferedAmount === 'number' ? peer.bufferedAmount : 0;
  }

  public disconnect(peerId: PeerId): void {
    const peer = this._peers.get(peerId);
    if (peer) {
      peer.close();
      this._peers.delete(peerId);
      this.pexRoutes.delete(peerId);
      this.pendingSignals.delete(peerId);
      this.pendingMeta.delete(peerId);
      this.rateLimiter.forget(peerId);
      this.emit('peer:disconnect', peerId);
    }
  }

  public broadcast(msg: Uint8Array | string): void {
    for (const peer of this._peers.values()) {
      if (peer.isConnected) peer.send(msg);
    }
  }

  public on(event: string, handler: (...args: any[]) => void): void {
    const handlers = this.eventListeners.get(event) || [];
    handlers.push(handler);
    this.eventListeners.set(event, handlers);
  }

  public off(event: string, handler: (...args: any[]) => void): void {
    const handlers = this.eventListeners.get(event);
    if (handlers) {
      this.eventListeners.set(event, handlers.filter(h => h !== handler));
    }
  }

  private emit(event: string, ...args: any[]): void {
    const handlers = this.eventListeners.get(event);
    if (handlers) handlers.forEach((h) => h(...args));
  }
}

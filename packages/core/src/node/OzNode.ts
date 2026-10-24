import { sodiumReady } from '../crypto/sodium';
import { IndexedDBStore } from '../storage/IndexedDBStore';
import type { VaultParams } from '../storage/SecretVault';
import { NodeIdentityStore } from '../crypto/NodeIdentityStore';
import type { NodeIdentity } from '../crypto/NodeIdentity';
import { CryptoEngine } from '../crypto/CryptoEngine';
import { PoWEngine } from '../crypto/PoWEngine';
import { equixReady } from '../crypto/equix/EquiX';
import { KeyManager } from '../crypto/KeyManager';
import { Identity } from '../crypto/Identity';
import { MessageDispatcher } from '../network/MessageDispatcher';
import { SignalingClient, TrackerNotConfiguredError } from '../network/SignalingClient';
import { isLoopbackTrackerUrl, parseTrackerUrl } from '../network/TrackerUrl';
import { parseIceServers, resolveIceServers, deriveStunFromTracker, DEFAULT_STUN_SERVER, type IceServersResult } from '../network/IceServers';
import { RateLimiter } from '../network/RateLimiter';
import { PeerManager } from '../network/PeerManager';
import { DandelionRouter } from '../network/gossip/DandelionRouter';
import { OnionCircuit, type OnionCircuitOptions } from '../network/onion/OnionCircuit';
import { GossipRouter } from '../network/gossip/GossipRouter';
import { RecentBuffer } from '../network/history/RecentBuffer';
import { CatchupServer } from '../network/history/CatchupServer';
import { CatchupClient } from '../network/history/CatchupClient';
import { StorageService } from '../network/storage/StorageService';
import { TunnelRelay } from '../network/tunnel/TunnelRelay';
import { TunnelClient } from '../network/tunnel/TunnelClient';
import { HistoryClient } from '../network/history/HistoryClient';
import { FileUploader, type UploadProgress } from '../files/FileUploader';
import { FileDownloader, type DownloadProgress, type FileDownload } from '../files/FileDownloader';
import type { FileSource } from '../files/FileCodec';
import type { RoutingParts } from '../files/ChunkRouting';
import { PEXHandler } from '../network/PEXHandler';
import { RingMaintainer } from '../network/RingMaintainer';
import { Heartbeat } from '../network/Heartbeat';
import { BoardOrchestrator } from '../logic/BoardOrchestrator';
import { startThreadRetention } from '../logic/ThreadRetention';
import { ThreadOrchestrator } from '../logic/ThreadOrchestrator';
import type { IPoWEngine, IKeyManager, ISignalingClient } from '../types';
import { GuardManager, type GuardManagerOptions, type GuardStatus } from '../trust/GuardManager';
import type { MaintainerKeySet, GuardListResult } from '../trust/TrustedGuards';
import { GUARD_MAX_DEGREE } from '../constants';
import { Encoding } from '../common/Encoding';
import { createLogger } from '../common/Logger';
import {
  OzzyMeshFetcher, OzzyOnionExit, OzzyOnionReplyRelay, OzzyRangeServer, type OzzyLockerJobRunner, type OzzyRangeFetchFn,
} from '../ozzy/MeshRange';
import { createLockerRangeFetch, createPooledRelayTransport, type HttpTransportFn } from '../ozzy/OverseasLockers';
import { createLockerJobRunner } from '../ozzy/OnionLockers';
import type { OzzyManifestStore } from '../ozzy/OzzyManifest';
import { OzzyWorkerPool, checkOzzyWorker, normalizeOzzyWorkerUrl } from '../ozzy/WorkerPool';

/** 自分の中継 Worker の URL を置く暗号化 DB の設定名 */
const OZZY_WORKER_SETTING_KEY = 'ozzy.workerUrl';
/** Ozzy の Manifest (置き場所入り) の大きさの上限。これより大きいものは取らない */
const OZZY_MANIFEST_MAX_BYTES = 16 * 1024 * 1024;

const log = createLogger('node.facade');

/** {@link OzNode.uploadFile} の戻り値 */
export interface FileUpload {
  /** 取得用のリンク (`[[file:...]]`)。全チャンクを置き終えたときだけ解決する。失敗・中止なら拒否 (FileTransferError) */
  link: Promise<string>;
  cancel(): void;
  pause(): void;
  resume(): void;
}

export interface OzNodeConfig {
  /**
   * トラッカー (シグナリングサーバ) の URL。公式のトラッカーは無いので利用者が設定する。
   * wss:// のみ (ws:// は localhost に限る)。未設定 (null / 省略) なら接続しない。
   * 起動後の変更は {@link OzNode.setTrackerUrl}。
   */
  trackerUrl?: string | null;
  /**
   * STUN サーバ (`stun:host:port` の列)。省略・空ならトラッカー URL のホストの 3478 番を使う。
   * ★ 第三者の STUN は使わない (利用者の IP と接続時刻を渡さないため)。TURN は未対応。
   */
  iceServers?: readonly string[] | null;
  signalingClient?: ISignalingClient;
  turnstileToken?: string;
  db?: IndexedDBStore;
  autoStart?: boolean;
  /**
   * オニオン回路のパラメータ。★ テスト専用 (タイマーを縮めるとき)。
   * 本番コードは渡さないこと。網の挙動は全ノードで同一でなければならない。
   */
  circuit?: OnionCircuitOptions;
  /**
   * ノード identity (peerId) の扱い。
   *
   * - 'ephemeral' (既定): 起動ごとに採掘し直し、保存しない。セッションを跨いで
   *   同一端末だと紐付けられない。起動時に数秒の採掘が掛かる。
   * - 'persistent': パスフレーズで封印して保存する。`passphrase` が必須。
   */
  identityMode?: 'ephemeral' | 'persistent';
  /**
   * 端末に保存する全データ (投稿・スレッド統計・板の鍵・最後に見た投稿の時刻・ノード鍵・トリップ鍵)
   * の暗号化に使うパスワード。**必須**。
   *
   * 忘れた場合の復元手段は無い。{@link IndexedDBStore.wipeAll} で全消去して作り直す。
   */
  passphrase?: string;
  /** パスワードからの鍵導出 (Argon2id) のパラメータ。テストで軽くするときだけ指定する */
  vaultParams?: VaultParams;
  /**
   * 信頼 Guard の設定。メンテナの公開鍵の組はアプリに組み込む。
   * `guardList` は初期のリスト (端末に保存済みのものより版が高ければ採用する)。
   * 省略した場合、Guard は普通の隣人から選ぶ (UI に警告を出すべき状態)。
   */
  trust?: { maintainerKeys: MaintainerKeySet; guardList?: string };
  /**
   * ノードの役割。
   * - 'client' (既定): 通常の利用者。
   * - 'guard': 信頼 Guard として運用する。peerId がリストに載るので
   *   `identityMode: 'persistent'` が必須。トラッカーに常時登録し、最大 {@link GUARD_MAX_DEGREE} 人を受け入れる。
   */
  role?: 'client' | 'guard';
  /**
   * Guard 選択のタイミング定数 (待ち時間・人数)。★ テスト専用 (縮めるとき)。
   * 本番コードは渡さないこと。
   */
  /**
   * 保管担当 (過去ログ v2 の保持者)。容量は枠の数 (1 枠 = 256MiB)。
   * `defaultSlots` は端末に設定が無いときの枠の数 (デスクトップ 4、ブラウザ 1。省略は 1)。
   * 後から変えるときは {@link OzNode.setStorageCapacity}。
   * `slotEffort` は ★ テスト専用 (枠の PoW を軽くする)。本番コードは渡さないこと。
   * `chunkEffort` も ★ テスト専用 (大容量ファイルのチャンクの保存の PoW。上げる側と預かる側の両方に効く)。
   */
  storage?: { defaultSlots?: number; slotEffort?: number; chunkEffort?: number };
  /**
   * Ozzy (外部ロッカーに置いた大容量ファイル) のメッシュ取得 (ozzy/MeshRange)。読み手はオニオン回路 (自分 → Guard → M1) の
   * M1 に取ってもらう。
   * - `fetcher`: 自分も M1 として、回路で届いた要求に答えてロッカーから範囲を取るか (既定 true)。
   *   ★ M1 は自分の中継 Worker を設定するまで動かない (setOzzyWorker)。取りに行くときは、交換で集めた他人の Worker を
   *     中継に使う (ozzy/WorkerPool)。ロッカーに見えるのは Cloudflare の IP。読み手の IP・peerId は M1 に届かない。
   * - `fetchRange`: 取得役としてロッカーから取る関数を差し替える (★ テスト・サーバー用。渡すと Worker の設定なしで M1 になる)。
   * - `jobRunner`: M1 としてロッカーへのアップロード・削除を実行する関数を差し替える (★ テスト用。fetchRange と一緒に渡す)。
   * - `extraAllowedHosts`: 取得役が取りに行ってよいホストの追加。既定の許可リストは公開ロッカーだけ。
   */
  ozzy?: {
    fetcher?: boolean; fetchRange?: OzzyRangeFetchFn; jobRunner?: OzzyLockerJobRunner; extraAllowedHosts?: readonly string[];
  };
  guardOptions?: Pick<
    GuardManagerOptions,
    'fallbackGraceMs' | 'minOpenCandidates' | 'openSelectionDelayMs' | 'sampleSize' | 'now' | 'randomIndex'
  >;
}

/**
 * OzNode — WebLite プロトコルスタック全体をカプセル化する統合ノードファサード。
 *
 * 内部で多数のサブシステム (PeerManager, Dandelion++, 追いつき (Guard の 72 時間バッファ),
 * Orchestrators 等) を自動配線し、
 * 単一のエントリポイントとして提供する。
 */
export class OzNode {
  public readonly db: IndexedDBStore;
  public readonly nodeIdentity: NodeIdentity;
  public readonly identity: Identity;
  public readonly cryptoEngine: CryptoEngine;
  public readonly keyManager: IKeyManager;
  public readonly powEngine: IPoWEngine;
  /** 利用者が選んだ STUN (空なら既定 = トラッカーの STUN)。PeerManager は接続のたびにここを読む */
  private readonly iceState: { explicit: string[] };

  public readonly dispatcher: MessageDispatcher;
  public readonly signaling: ISignalingClient;
  public readonly rateLimiter: RateLimiter;
  public readonly peerManager: PeerManager;
  public readonly dandelion: DandelionRouter;
  public readonly guards: GuardManager;
  public readonly circuit: OnionCircuit;
  public readonly gossipRouter: GossipRouter;
  /** 直近に見た投稿 (Guard は 72 時間・256MiB、それ以外は 1 時間・16MiB。メモリだけ) */
  public readonly recent: RecentBuffer;
  public readonly catchupServer: CatchupServer;
  public readonly catchupClient: CatchupClient;
  /** 保管担当 (SID・枠・leaseSet・担当の判定・預かり)。history v2 §4 */
  public readonly storage: StorageService;
  /** トンネルの中継の役 (全ノード。受け口の登録を受け、要求と応答を中継する)。history v2 §4.4 */
  public readonly tunnelRelay: TunnelRelay;
  /** 自分の 1 ホップ目へトンネルの要求を出す窓口 (HistoryClient が使う) */
  public readonly tunnelClient: TunnelClient;
  /** 保管担当から過去ログを取る (72 時間より古い分)。history v2 §4.5 */
  public readonly history: HistoryClient;
  public readonly pex: PEXHandler;
  public readonly maintainer: RingMaintainer;
  public readonly heartbeat: Heartbeat;

  public readonly boardOrchestrator: BoardOrchestrator;
  public readonly threadOrchestrator: ThreadOrchestrator;

  /** Ozzy: メッシュの取得役に範囲を取ってもらう窓口 (読み手の側)。ozzy/SlabReader に渡す */
  public readonly ozzyMesh: OzzyMeshFetcher;
  /** Ozzy: 自分が M1 として回路で届いた要求に答える側 (config.ozzy.fetcher = false なら断る) */
  public readonly ozzyExit: OzzyOnionExit;
  /** Ozzy: 自分が Guard として、M1 からの応答を隣人 (読み手) へ流す側 */
  public readonly ozzyReplyRelay: OzzyOnionReplyRelay;
  /** Ozzy: 参加者の中継 Worker の広告を交換し、中継に使う Worker を選ぶ */
  public readonly ozzyWorkers: OzzyWorkerPool;
  /**
   * Ozzy: Manifest (鍵・置き場所) の置き場所。WebLite の P2P のファイル保管 (トンネル経由で保持者へ) をそのまま使う。
   * ★ 共通のディレクトリ・Worker は使わない。保持者に見えるのは暗号文だけ (鍵はリンクの中)。
   */
  public readonly ozzyManifestStore: OzzyManifestStore;
  private readonly ozzyConfig: OzNodeConfig['ozzy'];

  private readonly chunkEffort: number | undefined;
  private isStarted = false;
  private retention: { stop: () => void } | null = null;
  private isDestroyed = false;

  private constructor(
    params: {
      db: IndexedDBStore;
      nodeIdentity: NodeIdentity;
      identity: Identity;
      cryptoEngine: CryptoEngine;
      keyManager: IKeyManager;
      powEngine: IPoWEngine;
      dispatcher: MessageDispatcher;
      signaling: ISignalingClient;
      iceState: { explicit: string[] };
      rateLimiter: RateLimiter;
      peerManager: PeerManager;
      dandelion: DandelionRouter;
      guards: GuardManager;
      circuit: OnionCircuit;
      gossipRouter: GossipRouter;
      recent: RecentBuffer;
      catchupServer: CatchupServer;
      catchupClient: CatchupClient;
      storage: StorageService;
      tunnelRelay: TunnelRelay;
      tunnelClient: TunnelClient;
      history: HistoryClient;
      pex: PEXHandler;
      maintainer: RingMaintainer;
      heartbeat: Heartbeat;
      boardOrchestrator: BoardOrchestrator;
      threadOrchestrator: ThreadOrchestrator;
      ozzyConfig: OzNodeConfig['ozzy'];
      chunkEffort?: number;
    },
  ) {
    this.chunkEffort = params.chunkEffort;
    this.db = params.db;
    this.nodeIdentity = params.nodeIdentity;
    this.identity = params.identity;
    this.cryptoEngine = params.cryptoEngine;
    this.keyManager = params.keyManager;
    this.powEngine = params.powEngine;
    this.iceState = params.iceState;
    this.dispatcher = params.dispatcher;
    this.signaling = params.signaling;
    this.rateLimiter = params.rateLimiter;
    this.peerManager = params.peerManager;
    this.dandelion = params.dandelion;
    this.guards = params.guards;
    this.circuit = params.circuit;
    this.gossipRouter = params.gossipRouter;
    this.recent = params.recent;
    this.catchupServer = params.catchupServer;
    this.catchupClient = params.catchupClient;
    this.storage = params.storage;
    this.tunnelRelay = params.tunnelRelay;
    this.tunnelClient = params.tunnelClient;
    this.history = params.history;
    this.pex = params.pex;
    this.maintainer = params.maintainer;
    this.heartbeat = params.heartbeat;
    this.boardOrchestrator = params.boardOrchestrator;
    this.threadOrchestrator = params.threadOrchestrator;

    this.ozzyConfig = params.ozzyConfig;
    this.ozzyWorkers = new OzzyWorkerPool(this.peerManager, this.dispatcher, this.nodeIdentity, {
      powParams: this.peerManager.nodeIdPowParams,
    });
    // ★ M1 の役は、自分の中継 Worker を設定してから (setOzzyWorker)。fetchRange を渡されたとき (テスト・サーバー) は最初から
    this.ozzyExit = new OzzyOnionExit(
      this.peerManager, this.circuit, this.ozzyConfig?.fetchRange ? this.makeRangeServer() : null,
      { dispatcher: this.dispatcher, jobRunner: this.ozzyConfig?.fetchRange ? this.makeJobRunner() : null },
    );
    this.ozzyReplyRelay = new OzzyOnionReplyRelay(this.peerManager, this.dispatcher, this.nodeIdentity);
    this.ozzyMesh = new OzzyMeshFetcher({ circuit: this.circuit, peerManager: this.peerManager, dispatcher: this.dispatcher });
    this.ozzyManifestStore = {
      put: (bytes, signal) => this.putOzzyManifest(bytes, signal),
      get: (body, signal) => this.getOzzyManifest(body, signal),
    };
  }

  /**
   * ノードを非同期生成・初期化する。
   */
  public static async create(config: OzNodeConfig = {}): Promise<OzNode> {
    await sodiumReady;
    // ★ PacketValidator の PoW 検証は同期関数。Equi-X の Wasm は非同期でしか読み込めないので、
    //   受信を始める前にここで済ませる (読み込み前の検証は例外になる)。
    await equixReady;

    // 不正なトラッカー URL は、鍵の導出やデータの解錠より前に拒否する
    if (config.trackerUrl && !config.signalingClient) {
      const parsed = parseTrackerUrl(config.trackerUrl);
      if (!parsed.ok) throw new Error(`invalid tracker URL: ${parsed.reason}`);
    }

    if (config.iceServers) {
      const ice = parseIceServers(config.iceServers);
      if (!ice.ok) throw new Error(ice.reason);
    }

    // Guard 役の peerId はリストに載る。起動のたびに変わる ID では役に立たないので、
    // 鍵の導出やデータの解錠より前に拒否する。
    if (config.role === 'guard' && config.identityMode !== 'persistent') {
      throw new Error("OzNode.create: role 'guard' requires identityMode 'persistent' (the guard list names a fixed peerId)");
    }

    // 1. ストレージ (パスワード必須。ロックを解除しない限りデータは読み書きできない)
    const passphrase = config.passphrase ?? '';
    if (passphrase.length === 0) {
      throw new RangeError('OzNode.create: a non-empty passphrase is required (local data is encrypted with it)');
    }
    const db = config.db || new IndexedDBStore();
    await db.init();
    await db.unlock(passphrase, config.vaultParams);
    try {
      return await OzNode.wire(db, passphrase, config);
    } catch (err) {
      // 起動が途中で失敗したら鍵をメモリに残さない。残すと、次の試行が
      // パスワードを照合せずに「解除済み」として通ってしまう。
      db.lock();
      throw err;
    }
  }

  private static async wire(db: IndexedDBStore, passphrase: string, config: OzNodeConfig): Promise<OzNode> {

    // 2. Bound Identity
    const nodeIdentity = config.identityMode === 'persistent'
      ? await NodeIdentityStore.loadOrMine(db, passphrase)
      : await NodeIdentityStore.mineEphemeral(db);
    log.debug(() => `Node identity initialized (${config.identityMode ?? 'ephemeral'})`);

    // 3. エンジン群
    const cryptoEngine = new CryptoEngine();
    const powEngine: IPoWEngine = {
      compute: (header) => PoWEngine.compute(header),
    };
    const keyManager: IKeyManager = {
      deriveThreadKey: KeyManager.deriveThreadKey,
    };

    // 4. 通信・ルーティング
    const dispatcher = new MessageDispatcher();
    const signaling = config.signalingClient || new SignalingClient(config.trackerUrl ?? null);
    const rateLimiter = new RateLimiter();
    // ★ 接続のたびに現在のトラッカー URL から導く (トラッカーを後から設定・変更しても追従する)
    const explicitIce = parseIceServers(config.iceServers);
    // 利用者が後から選び直せるよう、明示の STUN は書き換えられる箱に入れる (setIceServers)
    const iceState = { explicit: explicitIce.ok ? explicitIce.servers : [] };
    const iceServers = () => resolveIceServers(iceState.explicit, signaling.url ?? null);
    const isGuardRole = config.role === 'guard';
    const peerManager = new PeerManager(nodeIdentity, dispatcher, signaling, {
      rateLimiter,
      iceServers,
      // ★ 経路の各段が同じ端末でもよいのは、トラッカーが自分の端末 (開発用の網) のときだけ
      allowSameOriginHops: () => isLoopbackTrackerUrl(signaling.url ?? null),
      ...(isGuardRole ? { maxDegree: GUARD_MAX_DEGREE, keepTrackerAttached: true } : {}),
    });
    const identity = new Identity();
    await identity.initTrip(db);

    // Guard の方針。保存済みのリストの読み込みは、回路が Guard を選び始める前に済ませる
    // (start() より前なので、cover traffic の最初の 1 枠から方針が効く)。
    const guards = new GuardManager({
      keyset: config.trust?.maintainerKeys,
      guardList: config.trust?.guardList,
      store: {
        get: (name) => db.getSetting(name),
        set: (name, value) => db.setSetting(name, value),
      },
      ...config.guardOptions,
    });
    await guards.init();
    peerManager.setGuardSource(guards);
    // ★ Guard 役は、リストの他の Guard すべてとつなぎ続ける (バックボーン。history v2 §4.4)。
    //   リストが無い網 (オープン) では空 = バックボーンなし。受け口へは G_R が直接張る (TunnelRelay)。
    if (isGuardRole) {
      peerManager.setBackboneSource(() => guards.trustedGuardIds().filter(id => id !== nodeIdentity.peerId));
    }

    const dandelion = new DandelionRouter(peerManager, guards);
    const circuit = new OnionCircuit(peerManager, dispatcher, dandelion, config.circuit);

    // ★ 過去ログ v2: 流れた投稿を一定時間持ち (Guard は 72 時間)、再接続した隣人に差分を流す。
    //   自分の側では、1 ホップ目の Guard につながったら取り逃した分を頼む。
    const recent = RecentBuffer.forRole(isGuardRole ? 'guard' : 'client');
    const gossipRouter = new GossipRouter(peerManager, dispatcher, dandelion, circuit, recent);
    const catchupServer = new CatchupServer(peerManager, dispatcher, recent);
    const catchupClient = new CatchupClient(peerManager, dispatcher, dandelion, gossipRouter, {
      get: (name) => db.getSetting(name),
      set: (name, value) => db.setSetting(name, value),
    });
    await catchupClient.init();


    // ★ 保管担当 (history v2 §4): 検証済みの投稿 (live・追いつき・自分の発信) を、担当なら預かる。
    //   受け口に使えるのは、信頼 Guard のリストが有効なら信頼 Guard だけ (リストが無い網では誰でも)。
    const storage = await StorageService.create({
      peerManager,
      dispatcher,
      dandelion,
      gossipRouter,
      settings: {
        get: (name) => db.getSetting(name),
        set: (name, value) => db.setSetting(name, value),
      },
      holderDb: await db.openHolderDb(),
      gatewayAllowed: (peerId) => !guards.hasUsableList || guards.isTrustedPeerId(peerId),
      defaultSlots: config.storage?.defaultSlots ?? 1,
      slotEffort: config.storage?.slotEffort,
      chunkEffort: config.storage?.chunkEffort,
    });

    // ★ トンネル (history v2 §4.4): 中継の役は全ノードが持つ (警告状態では一般の隣人が G_R の役をする)。
    //   バックボーンの相手 (信頼 Guard) には広い枠を許す。受け口へ未接続のときの接続は peerManager.connect。
    const tunnelRelay = new TunnelRelay(peerManager, dispatcher, {
      role: isGuardRole ? 'guard' : 'client',
      isBackbone: (peerId) => peerManager.isTrustedGuard(peerId),
    });
    const tunnelClient = new TunnelClient(peerManager, dispatcher, dandelion);
    const history = new HistoryClient({
      tunnel: tunnelClient,
      peerManager,
      dandelion,
      duty: storage.duty,
      leaseSets: storage.leaseSets,
      deliver: (packet) => gossipRouter.deliverFetched(packet),
      ownSid: () => Encoding.toHex(storage.identity.publicKey),
    });

    const pex = new PEXHandler(peerManager, dispatcher);
    const maintainer = new RingMaintainer(peerManager, pex);
    const heartbeat = new Heartbeat(peerManager, dispatcher);

    const boardOrchestrator = new BoardOrchestrator(
      peerManager,
      db,
      gossipRouter,
      cryptoEngine,
      powEngine,
      identity,
      catchupClient,
      history,
    );

    const threadOrchestrator = new ThreadOrchestrator(
      peerManager,
      db,
      gossipRouter,
      cryptoEngine,
      powEngine,
      identity,
      keyManager,
      catchupClient,
      history,
    );

    const node = new OzNode({
      db,
      iceState,
      nodeIdentity,
      identity,
      cryptoEngine,
      keyManager,
      powEngine,
      dispatcher,
      signaling,
      rateLimiter,
      peerManager,
      dandelion,
      guards,
      circuit,
      gossipRouter,
      recent,
      catchupServer,
      catchupClient,
      storage,
      tunnelRelay,
      tunnelClient,
      history,
      pex,
      maintainer,
      heartbeat,
      boardOrchestrator,
      threadOrchestrator,
      ozzyConfig: config.ozzy,
      chunkEffort: config.storage?.chunkEffort,
    });

    // Ozzy: 設定済みの自分の中継 Worker を戻す (無ければ、設定されるまで Ozzy と M1 の役は止めておく)
    const savedWorker = await db.getSetting(OZZY_WORKER_SETTING_KEY);
    if (typeof savedWorker === 'string' && normalizeOzzyWorkerUrl(savedWorker)) node.applyOzzyWorker(savedWorker);

    if (config.autoStart) {
      await node.start();
    }

    return node;
  }

  /**
   * P2P ネットワークへ参加し、バックグラウンドメンテナを起動する。
   */
  public async start(): Promise<void> {
    if (this.isDestroyed) {
      throw new Error('OzNode: a stopped node cannot be restarted; create a new one');
    }
    if (this.isStarted) return;
    this.isStarted = true;

    this.heartbeat.start();
    this.ozzyWorkers.start();
    // cover traffic は投稿の有無に関係なく起動直後から流す (OnionCircuit.start 参照)
    this.circuit.start();
    // 保管担当: leaseSet の配布を始め、枠を裏で解く (初回は 1 枠 約 2 秒)
    this.storage.start();
    // 期限切れのスレを端末から消す (起動時に 1 回、以後 1 時間ごと)
    this.retention = startThreadRetention({
      db: this.db,
      cryptoEng: this.cryptoEngine,
      onPruned: (r) => this.boardOrchestrator.forgetThreads(r.deletedThreadIds),
    });

    try {
      await this.peerManager.start();
    } catch (err) {
      if (err instanceof TrackerNotConfiguredError) {
        log.info(() => 'No tracker configured; waiting for one to be set');
      } else {
        // URL はログに出さない (どのネットワークに参加しているかの手掛かりになる)
        log.warn(() => 'Could not reach the tracker on start; will retry periodically');
      }
    }
    log.info(() => 'OzNode started');
  }

  /**
   * ノードの全通信を停止し、リソースを解放する。
   */
  /**
   * ノードの全通信を止め、全タイマーを解放する。停止は終端で、再開はできない。
   *
   * ★ 旧実装は Schrödinger の再放流を止めて接続を切るだけだった。
   *   PeerManager の再アナウンスタイマーが生き残り、停止後も 30 秒ごとに
   *   トラッカーへ peerId と IP を再登録して接続を張り直していた。
   *   heartbeat / maintainer / replication / zone / 各ルータのタイマーも残っていた。
   */
  public async stop(): Promise<void> {
    if (this.isDestroyed) return;
    this.isDestroyed = true;
    this.isStarted = false;

    this.retention?.stop();
    this.retention = null;
    this.boardOrchestrator.clear();
    this.threadOrchestrator.clear();
    this.ozzyMesh.destroy();
    this.ozzyExit.destroy();
    this.ozzyReplyRelay.destroy();
    this.ozzyWorkers.destroy();
    // ★ 投稿の署名はオーケストレータ経由でしか起きない。ここで止めてから鍵 (セッション鍵の元) を消す
    this.identity.dispose();
    // ★ 最後に見た投稿の時刻を書き切ってから鍵を消す (下の db.lock の前に)
    const catchupFlushed = this.catchupClient.flush();
    // 預かりの書き込みも流してから鍵を消す
    const storageStopped = this.storage.stop();
    this.history.destroy();
    this.tunnelRelay.destroy();
    this.tunnelClient.destroy();
    this.catchupClient.destroy();
    this.catchupServer.destroy();
    this.circuit.destroy();
    this.heartbeat.stop();
    this.maintainer.destroy();
    this.gossipRouter.destroy();
    this.recent.clear();
    this.peerManager.stop(); // 再アナウンス停止・トラッカー切断・全ピア切断
    await this.guards.flush(); // 保存中の書き込みを待ってから鍵を消す
    await catchupFlushed;
    await storageStopped;
    this.db.lock(); // メモリ上のデータ鍵を消す
    log.info(() => 'OzNode stopped');
  }

  /**
   * 緊急消去 (パニックワイプ)。
   *
   * 通信を止め、データ鍵の封印を消してからデータベースごと削除する。
   * 鍵の封印を消した時点で、残りのデータは誰にも読めなくなる。元には戻せない。
   */
  public async panicWipe(): Promise<void> {
    await this.stop();
    await this.db.wipeAll();
  }

  // ── 保管担当 ──

  /** 保管担当の容量 (枠の数。1 枠 = 256MiB) */
  public get storageCapacity(): number {
    return this.storage.capacitySlots;
  }

  /** 保管担当の容量を変える (枠の数、最小 1)。UI は後続 */
  public async setStorageCapacity(slots: number): Promise<void> {
    if (this.isDestroyed) throw new Error('OzNode: node is stopped');
    await this.storage.setCapacity(slots);
  }

  // ── 大容量ファイル (docs/design/file-sharing.md) ──

  private fileRouting(): RoutingParts {
    return {
      duty: this.storage.duty,
      leaseSets: this.storage.leaseSets,
      ownSid: () => Encoding.toHex(this.storage.identity.publicKey),
    };
  }

  /**
   * ファイルを暗号化して保持者へ置く。全チャンクを置き終えたら `link` が解決する (その前に投稿へ載せない)。
   *
   * ★ **アップロードの状態はディスクに書かない**。アプリ (タブ) を閉じるとアップロードは失われ、最初からやり直す。
   *   途中の記録は「何を上げていたか」の痕跡になるため。一時停止・再開・中止は同じセッションの中でだけ効く。
   * ★ source は Uint8Array / Blob (File) / AsyncIterable<Uint8Array>。Blob と AsyncIterable は 1 チャンクずつ読む (メモリは数チャンク分)。
   */
  public uploadFile(
    source: FileSource, meta: { name: string; mime: string }, onProgress?: (p: UploadProgress) => void,
  ): FileUpload {
    if (this.isDestroyed) throw new Error('OzNode: node is stopped');
    const up = new FileUploader(
      { tunnel: this.tunnelClient, routing: this.fileRouting(), chunkEffort: this.chunkEffort },
      source, { name: meta.name, mime: meta.mime }, onProgress,
    ).start();
    return { link: up.link, cancel: () => up.cancel(), pause: () => up.pause(), resume: () => up.resume() };
  }

  /**
   * リンク (`[[file:...]]` か本体) からファイルを取る。返り値を `for await` すると平文が番号順に出る (保存先は呼び出し側が決める)。
   * `manifest` で名前・MIME・大きさが分かる。`cancel()` でいつでも中止できる。取りかけはディスクに書かない。
   */
  public downloadFile(linkToken: string, onProgress?: (p: DownloadProgress) => void): FileDownload {
    if (this.isDestroyed) throw new Error('OzNode: node is stopped');
    return new FileDownloader({ tunnel: this.tunnelClient, routing: this.fileRouting() }, linkToken, onProgress).start();
  }

  // ── Ozzy の中継 Worker (参加の条件) ──

  /** 自分の中継 Worker (未設定なら null)。設定するまで Ozzy の上げ下ろしと M1 の役は使えない */
  public get ozzyWorkerUrl(): string | null {
    return this.ozzyWorkers.own;
  }

  /** Ozzy を使えるか (自分の中継 Worker を設定済み) */
  public get ozzyReady(): boolean {
    return this.ozzyWorkers.own !== null;
  }

  /**
   * 自分の中継 Worker (packages/r2-worker をデプロイしたもの) を設定する。`/ozzy/v2/status` で今の版の Ozzy 中継かを確かめ、
   * 暗号化 DB に保存し、広告として網に流し、M1 の役を始める。null で外す (Ozzy と M1 の役が止まる)。
   * ★ Worker の URL (workers.dev のサブドメイン) は Cloudflare のアカウントに結び付く。身元に繋がらないアカウントで作ること。
   */
  public async setOzzyWorker(
    url: string | null, check: (url: string) => ReturnType<typeof checkOzzyWorker> = (u) => checkOzzyWorker(u),
  ): Promise<{ ok: true } | { ok: false; reason: 'bad-url' | 'unreachable' | 'not-ozzy' | 'outdated' }> {
    if (this.isDestroyed) throw new Error('OzNode: node is stopped');
    if (url === null) {
      await this.db.setSetting(OZZY_WORKER_SETTING_KEY, null);
      this.applyOzzyWorker(null);
      return { ok: true };
    }
    const norm = normalizeOzzyWorkerUrl(url);
    if (!norm) return { ok: false, reason: 'bad-url' };
    const res = await check(norm);
    if (!res.ok) return res;
    await this.db.setSetting(OZZY_WORKER_SETTING_KEY, norm);
    this.applyOzzyWorker(norm);
    return { ok: true };
  }

  private applyOzzyWorker(url: string | null): void {
    this.ozzyWorkers.setOwn(url);
    if (!this.ozzyConfig?.fetchRange) {
      this.ozzyExit.setServer(url ? this.makeRangeServer() : null, url ? this.makeJobRunner() : null);
    }
  }

  /** ロッカーへは、交換で集めた他人の中継 Worker を通して行く (自分の IP をロッカーに見せない・直接は行かない) */
  private relayTransport(): HttpTransportFn {
    return createPooledRelayTransport(() => this.ozzyWorkers.pickRelay(), (u) => this.ozzyWorkers.reportFailure(u));
  }

  /** M1 としてロッカーから取る取得役。既定は他人の中継 Worker を通して取る */
  private makeRangeServer(): OzzyRangeServer | null {
    if (this.ozzyConfig?.fetcher === false) return null;
    return new OzzyRangeServer({
      fetchRange: this.ozzyConfig?.fetchRange ?? createLockerRangeFetch(this.relayTransport()),
      extraAllowedHosts: this.ozzyConfig?.extraAllowedHosts,
    });
  }

  /** M1 として、回路で頼まれたロッカーへのアップロード・削除を実行する関数。既定は他人の中継 Worker を通す */
  private makeJobRunner(): OzzyLockerJobRunner | null {
    if (this.ozzyConfig?.fetcher === false) return null;
    if (this.ozzyConfig?.fetchRange) return this.ozzyConfig.jobRunner ?? null;
    return createLockerJobRunner(this.relayTransport());
  }

  /** Manifest を P2P のファイル保管に置き、WebLite のファイルリンクの本体を返す */
  private async putOzzyManifest(bytes: Uint8Array, signal?: AbortSignal): Promise<string> {
    if (bytes.length > OZZY_MANIFEST_MAX_BYTES) throw new RangeError('ozzy manifest too large');
    const up = this.uploadFile(bytes, { name: 'm.bin', mime: 'application/octet-stream' });
    const onAbort = () => up.cancel();
    signal?.addEventListener('abort', onAbort, { once: true });
    try {
      const token = await up.link;
      const m = /^\[\[file:([A-Za-z0-9_-]+)\]\]$/.exec(token.trim());
      if (!m) throw new Error('unexpected file link');
      return m[1];
    } finally {
      signal?.removeEventListener('abort', onAbort);
    }
  }

  /** Manifest を P2P のファイル保管から取る。取れない・大き過ぎるなら null */
  private async getOzzyManifest(body: string, signal?: AbortSignal): Promise<Uint8Array | null> {
    let dl: FileDownload;
    try {
      dl = this.downloadFile(body);
    } catch {
      return null;
    }
    const onAbort = () => dl.cancel();
    signal?.addEventListener('abort', onAbort, { once: true });
    try {
      const info = await dl.manifest;
      if (info.size > OZZY_MANIFEST_MAX_BYTES) {
        dl.cancel();
        return null;
      }
      const parts: Uint8Array[] = [];
      let total = 0;
      for await (const piece of dl) {
        total += piece.length;
        if (total > OZZY_MANIFEST_MAX_BYTES) {
          dl.cancel();
          return null;
        }
        parts.push(piece);
      }
      const out = new Uint8Array(total);
      let o = 0;
      for (const p of parts) {
        out.set(p, o);
        o += p.length;
      }
      return out;
    } catch {
      return null;
    } finally {
      signal?.removeEventListener('abort', onAbort);
    }
  }

  public get peerId(): string {
    return this.nodeIdentity.peerId;
  }

  public get degree(): number {
    return this.peerManager.degree;
  }

  public get running(): boolean {
    return this.isStarted;
  }

  /** 現在のトラッカー URL (未設定なら null) */
  public get trackerUrl(): string | null {
    return this.signaling.url ?? null;
  }

  /** 利用者が選んだ STUN の一覧。空なら既定 (トラッカーの STUN) を使う */
  public get iceServers(): string[] {
    return [...this.iceState.explicit];
  }

  /** 既定の STUN (Google Anycast STUN) */
  public get defaultStunServer(): string | null {
    return DEFAULT_STUN_SERVER;
  }

  /** 実際に使う STUN (選んだもの、無ければ既定) */
  public get effectiveIceServers(): string[] {
    return resolveIceServers(this.iceState.explicit, this.trackerUrl).flatMap((s) =>
      Array.isArray(s.urls) ? s.urls : [String(s.urls)],
    );
  }

  /**
   * STUN を選ぶ。null か空なら既定 (トラッカーの STUN) に戻す。`stun:` の URL のみ、4 つまで。
   * 次に張る接続から効く (張ってある接続はそのまま)。
   *
   * ★ トラッカー以外の STUN を選ぶと、その運営者に IP と接続の時刻が伝わる (トラッカーには元から見えている)。
   *   選ぶのは利用者の自由だが、画面ではそのことを一言添える。
   */
  public setIceServers(input: string | readonly string[] | null): IceServersResult {
    const parsed = parseIceServers(input);
    if (parsed.ok) this.iceState.explicit = parsed.servers;
    return parsed;
  }

  /** トラッカーへ接続中か (登録後しばらくすると切り離すので、普段は false) */
  public get trackerConnected(): boolean {
    return this.signaling.isConnected === true;
  }

  /**
   * トラッカーを変更する (null で未設定に戻す)。不正な URL は例外で、設定は変わらない。
   * 起動中なら新しいトラッカーへ接続し直し、到達できなければ例外を返す
   * (設定自体は変わっており、以後は定期的に再試行する)。
   */
  public async setTrackerUrl(url: string | null): Promise<void> {
    if (this.isDestroyed) throw new Error('OzNode: node is stopped');
    if (!this.signaling.setUrl) throw new Error('signaling client does not support changing the tracker');
    let normalized: string | null = null;
    if (url !== null) {
      const parsed = parseTrackerUrl(url);
      if (!parsed.ok) throw new Error(`invalid tracker URL: ${parsed.reason}`);
      normalized = parsed.url;
    }
    this.signaling.setUrl(normalized);
    if (this.isStarted && normalized) await this.peerManager.reconnectTracker();
  }

  // ── 信頼 Guard ──

  /**
   * 信頼 Guard のリストを取り込む。署名・期間・版 (巻き戻し) を検証し、通れば端末に保存する。
   * 失敗しても現在の状態は変わらない。
   */
  public async importGuardList(text: string): Promise<GuardListResult> {
    if (this.isDestroyed) throw new Error('OzNode: node is stopped');
    const result = await this.guards.importList(text);
    // 新しいリストの Guard へすぐ接続しに行く
    if (result.ok && this.isStarted) void this.peerManager.maintainWantedGuards();
    return result;
  }

  /** Guard の現在の状態 (信頼 Guard か、警告状態か、リストの版と期限) */
  public get guardStatus(): GuardStatus {
    return this.guards.status;
  }

  /** Guard の状態の変化を購読する。戻り値は購読解除 */
  public onGuardStatus(cb: (status: GuardStatus) => void): () => void {
    return this.guards.onStatus(cb);
  }
}

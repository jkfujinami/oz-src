import type { IMessageDispatcher, IPeerManager, PeerId } from '../../types';
import { OnionRouter, SEALED_EXIT_LAYER_SIZE, FRAG_ID_BYTES, MAX_FRAGMENTS, type ExitPayload, type OnionHop } from '../../crypto/OnionRouter';
import { decodeExitItem, encodeExitItem, splitIntoFragments, type ExitItem } from '../../crypto/ExitItem';
import { FragmentReassembler, type Fragment } from './FragmentReassembler';
import { NodeIdentity, NODE_ID_POW, type NodeIdPowParams } from '../../crypto/NodeIdentity';
import sodium from '../../crypto/sodium';
import { toBytes } from '../../crypto/PowPolicy';
import { Encoding } from '../../common/Encoding';
import { createLogger } from '../../common/Logger';
import { WireType } from '../wire/WireTypes';
import { SeenCache } from '../gossip/SeenCache';
import { secureWeightedIndex, OBSERVATION_SATURATION_MS, type DandelionRouter } from '../gossip/DandelionRouter';
import { ORIGIN_PENDING, sameOrigin } from '../NetGroup';

const log = createLogger('net.onion');

const PEER_ID_RE = /^[0-9a-f]{32}$/;

/**
 * 回路の既定パラメータ (全利用者で共通の固定値)。
 *
 * ★ 匿名性レベル (standard / safer / safest) は設けない。理由:
 *   1. 中継ノード自身の遅延設定は、その中継ノード自身の設定で適用される。
 *      そのため利用者が「最も安全」を選んでも、自分の投稿の遅延は長くならず、
 *      変わるのは自分が出す cover traffic の量だけだった。
 *   2. cover traffic の量は利用者の Guard と ISP から見える。非既定の値を選んだ
 *      利用者は、それだけで識別可能な小さな集団になってしまう。
 *   Tor Browser のセキュリティレベルも、ネットワークの振る舞いは一切変えない。
 *   よって網の挙動は全ノードで同一であることを保つ。
 *
 * レイテンシの内訳 (平均): 次の送出枠までの待ち + 各ホップの中継遅延
 * (Guard, M1, 以後の Stem 1 歩ごと) + 伝播。
 * 送出枠はポアソン過程なので、次の枠までの待ちは平均で COVER_INTERVAL そのもの
 * (無記憶性。間隔の半分にはならない)。
 * 1 枚に収まる投稿は約 0.5 秒 + Stem で約 1 秒。3 枚の投稿は回路の先頭 (位置 1) からしか
 * 始められないので、平均で 1〜2 秒余計に待ち、3 枠ぶん (約 1.5 秒) かけて送り出す。
 */
export const CIRCUIT_CONFIG = {
  /** cover traffic の平均送出間隔 (ms, 指数分布 = ポアソン過程) */
  COVER_INTERVAL_MS: 500,
  /** 各ホップ (Guard / M1 / Stem の各ノード) での遅延の平均 (ms, 指数分布) */
  RELAY_DELAY_MS: 40,
  /**
   * エコー待ちの上限 (ms)。**最後の断片を送り出した時点から**数える。
   * M1 での再構成 + Stem の歩み + 伝播を十分に覆う値。
   */
  ECHO_TIMEOUT_MS: 5_000,
  /**
   * 1 つの回路 (同じ M1 へ続けて送るセルの数)。全トラフィック (cover も本物も) で共通。
   * 1 つの item は MAX_FRAGMENTS 枚までで、1 つの回路に収まる。{@link OnionCircuit} の
   * 「3 スロット固定回路」を参照。
   */
  CIRCUIT_SLOTS: 3,
  /**
   * 送出枠が回ってくるのを待つ上限 (ms)。先頭の item が回路の途中に収まらないときなど、
   * 順番待ちが長引いたものを諦めるための安全弁 (stop でも解除される)。
   */
  SEND_WAIT_MS: 20_000,
  /** 1 つの発信に使う M1 の数 (同じ Guard のまま M1 だけ替える) */
  MAX_ATTEMPTS: 2,
  /**
   * 回路が使えるようになる (Guard と M1 の候補が揃う) のを待つ上限 (ms)。
   * Guard は起動直後の数秒間、意図して選ばない (信頼 Guard を待つ / 開放モードは
   * 隣人 4 人と 20 秒を待つ)。この間に投稿した利用者へ即座にエラーを見せないために待つ。
   * 待っても揃わなければ、そこで初めて fail-closed で諦める。
   */
  READY_WAIT_MS: 60_000,
  /** Guard に隣人表 (PEX) を問い合わせる間隔 (ms) */
  GUARD_PEX_INTERVAL_MS: 30_000,
  /** Guard の隣人情報の有効期限 (ms) */
  GUARD_NEIGHBOR_TTL_MS: 10 * 60 * 1000,
  /** 中継・Stem 処理の保留上限 (全体 / 送信者ごと) */
  MAX_PENDING: 128,
  MAX_PENDING_PER_PEER: 16,
  /** 送信待ちの本物のセルの上限 */
  MAX_QUEUE: 64,
  /**
   * Stem の各ノードが、受け取った投稿をその場で Fluff (全体へ flood) する確率。
   * 外れたら、直前の相手以外のランダムな検証済み隣人へ渡す。M1 の後の期待歩数は 1/p = 4。
   *
   * ★ 暫定値。3 万ノード規模のシミュレーションで「Guard から見て Fluff 地点が
   *   予測できなくなる歩数」を測り、その結果で再調整する。
   *   ホップ数をワイヤに載せない (載せると Fluff 地点までの距離が漏れる) ので、
   *   歩数の長さはこの確率でしか制御できない。
   */
  STEM_FLUFF_PROBABILITY: 0.25,
};

/**
 * ★ テスト専用。本番コードはこれを渡してはならない。
 * 渡すと、そのノードだけ遅延や cover 間隔が変わり、網の挙動が一様でなくなる
 * (上の CIRCUIT_CONFIG の説明を参照)。タイマーを縮めるためにテストで使う。
 */
export interface OnionCircuitOptions {
  coverIntervalMs?: number;
  relayDelayMs?: number;
  echoTimeoutMs?: number;
  /** 送出枠が回ってくるのを待つ上限 (ms) */
  sendWaitMs?: number;
  /** 断片の再構成の上限・猶予 (M1 側) */
  reassembly?: { MAX_PARTIAL_PER_SENDER: number; MAX_PARTIAL_TOTAL: number; TIMEOUT_MS: number };
  /** 回路が使えるようになるのを待つ上限 (ms) */
  readyWaitMs?: number;
  /** [0, 1) の乱数。Stem の Fluff 判定と次の隣人の選択に使う (決定的なテスト用) */
  random?: () => number;
}

type ExitType = ExitItem['type'];
type ExitHandler = (payload: ExitItem, fromPeerId: PeerId) => void;
/** M1 として歩かせ始めたものを、Guard を除外するために覚えておく件数の上限 */
const M1_GUARD_MEMORY = 4096;

/** Stem で運ぶもの (cover の drop は運ばない) */
type StemItem = ExitItem;

/**
 * Stem を歩く投稿の検査窓口。ルーターが `onExit` と一緒に登録する。
 *
 * 検査は各ルーターが持つ「検証」と「flood 済みか」の状態に依存するので、
 * 回路はそれを知らずに、この 2 つを呼ぶだけにしてある。
 */
export interface StemInspector {
  /** 検証 (Gossip は PacketValidator)。通れば重複判定用の id、不正なら null */
  inspect(payload: ExitItem): string | null;
  /** その id を既に全隣人へ flood したか (flood 済みなら歩かせない) */
  isFlooded(id: string): boolean;
}

/** 送出待ちの item (断片に分けてある) */
interface QueuedItem {
  frags: Fragment[];
  /** この item を既に試した M1。再送ではここを避ける */
  tried: Set<PeerId>;
  /** 最後の断片を送り出したとき (または諦めたとき) に呼ぶ。ok = 送り出せた */
  settle: (ok: boolean) => void;
  /** 送り出した回路 (Guard と M1)。sendDirect が返送の経路を知るのに使う */
  onSent?: (guardId: PeerId, middleId: PeerId) => void;
}

/** 今の回路 (同じ M1 へ続けて送る CIRCUIT_SLOTS 枠) */
interface ActiveCircuit {
  guardId: PeerId;
  middle: OnionHop;
  /** 送り出した枠の数 */
  used: number;
}

interface GuardNeighbor {
  pubkey: Uint8Array;
  /** Guard の隣人表で最初に見た時刻 (このセッション内) */
  firstSeen: number;
  /** 最後に見た時刻 (有効期限の判定) */
  seenAt: number;
}

interface ReadyWaiter {
  /** 回路が組めるか確かめ、組めれば待機を終える */
  poll(): void;
  /** 待機を打ち切って null を返す (stop / タイムアウト) */
  cancel(): void;
}

/** 指数分布の乱数 (平均 mean)。上限 max で打ち切る */
export function exponentialDelay(mean: number, max: number = Number.POSITIVE_INFINITY): number {
  if (mean <= 0) return 0;
  const u = (crypto.getRandomValues(new Uint32Array(1))[0] + 1) / 0x100000001;
  return Math.min(max, Math.round(-Math.log(u) * mean));
}

/**
 * OnionCircuit — 作者が網へ出すものを、すべて固定長セルで運ぶ。
 *
 * ★ 経路の全体像
 *
 *   author --onion--> Guard --onion--> M1 --stem--> W1 --stem--> ... --> F が flood (Fluff)
 *
 *   オニオンは 2 層 [Guard, M1] のまま。M1 は層を剥いだあと**自分では決して flood せず**、
 *   ランダムな隣人へ Stem (WireType.STEM) で渡す。Stem を受け取ったノード (walker) は
 *   確率 STEM_FLUFF_PROBABILITY でその場で Fluff し、外れたら直前の相手以外のランダムな
 *   隣人へ渡す。ワイヤにホップ数は載せない (Fluff 地点までの距離が漏れるため)。
 *
 * ★ なぜ M1 が flood してはいけないのか (旧実装は Exit が flood していた)
 *
 *   網は疎 (次数 16 以下) で、Guard は「どの出口へセルを転送したか」を知っている。
 *   出口は投稿を flood する本人なので、誰でも「出口 E が P を flood した」を観測できる。
 *   Guard (または Guard になった者) は「クライアント C が E へセルを送った」と
 *   「E が直後に P を flood した」を突き合わせられ、同じ偽名で 10 件ほど投稿されると
 *   作者を統計的に特定できた。出口での遅延は相関を薄めるだけで消せない。
 *   M1 が flood しなければ、Guard が知る「セルの行き先」と「flood した者」が別人になり、
 *   しかもその間の歩数は Guard から見えない。
 *
 * ★ 残る限界 (正直に書いておく)
 *
 *   - 既知で受け入れたリスク: 最後の walker (一般の利用者) は、その投稿を最初に flood する
 *     ノードとして観測される。「最初に broadcast した者 = 作者」と単純に見なす観測者は、
 *     無関係な利用者を指すことになる。プロジェクトの方針として、この性質を承知で選んだ。
 *   - Guard と M1 が結託すれば時刻相関で作者が分かる (Tor と同じ end-to-end 相関)。
 *     さらに M1 の隣人 (最初の walker) も、M1 から投稿を受け取った時刻を知っている。
 *   - M1 候補は Guard の申告に依存する。悪意ある Guard は自分の仲間だけを申告して
 *     M1 を誘導できる。Guard を長期固定しているのは、この位置を攻撃者が得る機会そのものを
 *     減らすため。
 *   - 歩数 (Fluff 確率) は暫定値。3 万ノードのシミュレーションで再調整する。
 *
 * ★ Stem の途中で投稿が消えたとき
 *
 *   walker は、タイマーで代わりに Fluff する Dandelion++ の fail-safe を**持たない**。
 *   持つと、攻撃者は投稿を握りつぶすだけで M1 や最初の walker (Guard が位置を絞り込める
 *   ノード) に Fluff を強制できる。消えた場合は作者のエコー待ちが時間切れになり、
 *   {@link send} が別の M1 で端から端までやり直す。
 *
 * ★ 固定長セルと断片化
 *
 *   セルは CELL_SIZE = 1,200 バイト。1 枚の出口層に収まらない item (本文が長い投稿など) は
 *   最大 MAX_FRAGMENTS = 3 枚の断片 (frag) に分け、同じ M1 へ送る。M1 は (送り主 = Guard, 断片 id)
 *   ごとに集め、揃ったら item に戻してから Stem を始める (FragmentReassembler)。
 *   3 枚を超える item は send で拒否する (本文 2048 バイト + コンパクト形式なら起こらない)。
 *   断片は封印された出口層の内側にあり、Guard には cover と区別が付かない。
 *
 * ★ 3 スロット固定回路 (匿名性の不変条件)
 *
 *   Guard は各セルの「次のホップ」(= M1) を知っている。cover が 1 枚ごとに別の M1 を選び、
 *   断片化された本物だけが「同じ M1 へ続けて k 枚」送られるなら、Guard は
 *   「同じ M1 への連続セル = 複数枚の本物の投稿」と見抜ける。そこで:
 *
 *     **M1 は 3 スロットごとにしか替えない (cover も本物も同じ)。**
 *
 *   「回路」= 同じ M1 への連続 3 スロット。Guard から見える次ホップの列は、本物を何枚送っても
 *   常に「同じ M1 が 3 回 → 別の M1 が 3 回 → ...」で、本物の有無・枚数は現れない。
 *   (隣り合う回路の M1 は、候補が 2 つ以上あれば必ず別にする。同じ M1 が続いて 6 回に見えて
 *   区切りが曖昧になることを避けるため。)
 *   k 枚の本物は、回路の位置 p (1..3) から始めるとき p + k - 1 ≤ 3 を満たす場合にだけ送り出す。
 *   2 つの回路にまたがらない。キューの先頭が収まらないときは、収まる回路まで cover を出して待つ
 *   (順序は保つ。1 枚の item はどこにでも収まる)。
 *   M1 は回路ごとに従来どおりの重み付け (pickMiddle) で選び、再送は試した M1 を除外して
 *   「後の回路・別の M1」で全断片を送り直す。回路の途中で Guard が替わったら回路は打ち切る
 *   (途中まで送った item は M1 の猶予切れで捨てられ、エコー待ちが切れて再送される)。
 *
 * ★ なぜ cover traffic が要るのか (C2)
 *
 *   セルは作者が投稿したときにしか出ないと、Guard にとって
 *   「relay 層を剥けた = 送ってきた隣人が作者」が確定してしまう。
 *   現在は全ノードが平均 COVER_INTERVAL_MS のポアソン過程で常にセルを出し続け、
 *   本物の発信は次の送出枠を drop セルの代わりに使うだけである。
 *   M1 層は固定長なので、Guard から見て drop と本物はビット単位で区別できない。
 *   drop は M1 で捨てられる。Guard に分かるのは「この隣人がオンラインである」ことだけになる。
 *
 * ★ M1 の選び方
 *
 *   M1 は「Guard の隣人で、自分の隣人ではないノード」から選ぶ。
 *   M1 も作者の直接の隣人だと、M1 は「作者 ∈ N(Guard) ∩ N(M1)」と候補を数人に
 *   絞り込めてしまう。Guard の隣人表は Guard への PEX で得る。各エントリは
 *   peerId ↔ pubkey の束縛と NodeId PoW を検証してから使う。
 *
 * ★ 回路が使えるまで待つ
 *
 *   Guard は起動直後の数秒間、意図して選ばれない。この間の投稿を即座に失敗させると、
 *   起動直後に書いた利用者は必ずエラーを見る。{@link send} は READY_WAIT_MS まで待ち、
 *   それでも揃わなければ fail-closed で諦める (待っている間も何も送らない)。
 */
export class OnionCircuit {
  private readonly coverIntervalMs: number;
  private readonly relayDelayMs: number;
  private readonly readyWaitMs: number;
  private readonly random: () => number;
  public readonly echoTimeoutMs: number;

  private exitHandlers = new Map<ExitType, Set<ExitHandler>>();
  /** M1 で受け取る、Stem を歩かせない種別 (先頭 1 バイト) → ハンドラ。Ozzy の代理取得など */
  private directExits = new Map<number, (body: Uint8Array, guardId: PeerId) => void>();
  private inspectors = new Map<ExitType, StemInspector>();
  private queue: QueuedItem[] = [];
  /** 送出中の item (先頭の断片を送り出したあと、残りを続く枠で送る) */
  private inflight: { item: QueuedItem; next: number } | null = null;
  private activeCircuit: ActiveCircuit | null = null;
  /** M1 として受け取った断片の再構成 */
  private reassembler: FragmentReassembler;
  private readonly sendWaitMs: number;
  private guardNeighbors = new Map<PeerId, GuardNeighbor>();
  private seenCells = new SeenCache();
  /**
   * 自分が Fluff してはならないもの (type:id)。M1 として歩かせ始めたものと、自分が作者のもの。
   * 歩きが戻ってきても Fluff せず、また渡す。M1 が Fluff すると Guard の相関が復活する。
   */
  private neverFluff = new SeenCache();
  /**
   * M1 として歩かせ始めたもの (type:id) → そのセルを中継してきた Guard。
   * ★ 歩きが戻ってきても、この Guard には決して渡さない。Guard は直前に自分が M1 へ
   *   中継したセルと「M1 から届いた Stem」を時刻で突き合わせ、投稿と利用者を結び付けられる。
   */
  private m1Guards = new Map<string, PeerId>();
  /**
   * 自分が作者のもの (type:id) → 送るのに使った Guard (試行ごとに変わりうる)。
   * ★ 歩きが作者に戻ってきたとき、作者が自分の Guard に平文の Stem を渡してはいけない。Guard は
   *   「この利用者がこの投稿を持っている」を直接見る (匿名性シミュレーション D1 で 0.5% の頻度で検出)。
   *   M1 の m1Guards と同じ理由で、送るのに使った Guard と今の Guard をどちらも渡し先から外す。
   */
  private authorGuards = new Map<string, Set<PeerId>>();
  private readyWaiters = new Set<ReadyWaiter>();

  private pending = new Set<ReturnType<typeof setTimeout>>();
  private pendingPerPeer = new Map<PeerId, number>();

  private coverTimer: ReturnType<typeof setTimeout> | null = null;
  private pexTimer: ReturnType<typeof setInterval> | null = null;
  private running = false;

  private curveKeys: { pk: Uint8Array; sk: Uint8Array } | null = null;

  constructor(
    private peerManager: IPeerManager,
    dispatcher: IMessageDispatcher,
    private dandelion: DandelionRouter,
    options: OnionCircuitOptions = {},
  ) {
    this.coverIntervalMs = options.coverIntervalMs ?? CIRCUIT_CONFIG.COVER_INTERVAL_MS;
    this.relayDelayMs = options.relayDelayMs ?? CIRCUIT_CONFIG.RELAY_DELAY_MS;
    this.readyWaitMs = options.readyWaitMs ?? CIRCUIT_CONFIG.READY_WAIT_MS;
    this.echoTimeoutMs = options.echoTimeoutMs ?? CIRCUIT_CONFIG.ECHO_TIMEOUT_MS;
    this.sendWaitMs = options.sendWaitMs ?? CIRCUIT_CONFIG.SEND_WAIT_MS;
    this.reassembler = new FragmentReassembler(options.reassembly);
    this.random = options.random ?? secureUnit;

    dispatcher.register(WireType.ONION_STEM, (senderId, msg) => this.handleCell(senderId, msg));
    dispatcher.register(WireType.STEM, (senderId, msg) => this.handleStem(senderId, msg));
    dispatcher.register(WireType.PEX_RESPONSE, (senderId, msg) => this.handleGuardPex(senderId, msg));

    // Guard が変わったら、前の Guard の隣人表は使えない
    this.dandelion.onGuardChange((guard) => {
      this.guardNeighbors.clear();
      if (guard && this.running) this.requestGuardNeighbors();
      this.wakeWaiters();
    });
  }

  // ── Fluff ハンドラ ──

  /**
   * Fluff の時点 (Stem の終点) で呼ばれるハンドラを登録する。
   *
   * ★ 名前は旧実装の「出口」のまま残してある。今は M1 ではなく、Stem を歩いた末に
   *   Fluff を決めたノードで呼ばれる。
   *
   * @param inspector Stem を歩く投稿の検証窓口。Gossip のルーターが渡す。
   *   窓口の無い種別は Stem で受け取らない (検証できないものを増幅しない)。
   */
  public onExit(type: ExitType, handler: ExitHandler, inspector?: StemInspector): void {
    if (!this.exitHandlers.has(type)) this.exitHandlers.set(type, new Set());
    this.exitHandlers.get(type)!.add(handler);
    if (inspector) this.inspectors.set(type, inspector);
  }

  /**
   * M1 で受け取る「Stem を歩かせない」種別を登録する。組み立てた item の先頭 1 バイトが kind なら、
   * 残りを handler に渡す (送ってきた Guard の peerId つき)。M1 は Fluff も Stem もしない。
   * ★ kind は ExitItem の種別 (1 = fluff) と重ならない値にすること。
   */
  public onDirectExit(kind: number, handler: (body: Uint8Array, guardId: PeerId) => void): void {
    if (!Number.isInteger(kind) || kind < 2 || kind > 0xff) throw new RangeError('onDirectExit: bad kind');
    this.directExits.set(kind, handler);
  }

  /** 回路が組めるか (Guard が決まっていて、M1 の候補がいる) */
  public get routeReady(): boolean {
    const guard = this.currentGuard();
    return !!guard && this.pickMiddle(guard.peerId, new Set()) !== null;
  }

  /** M1 の候補の数 (Guard の隣人で、使えるもの) */
  public get middleCandidateCount(): number {
    const guard = this.currentGuard();
    if (!guard) return 0;
    const now = Date.now();
    let n = 0;
    for (const [peerId, info] of this.guardNeighbors) {
      if (now - info.seenAt > CIRCUIT_CONFIG.GUARD_NEIGHBOR_TTL_MS) continue;
      if (peerId === this.peerManager.myPeerId || peerId === guard.peerId) continue;
      n++;
    }
    return n;
  }

  /** 今の Guard (回路の 1 ホップ目)。応答の返送先を Guard 宛てに封印するのに使う */
  public get currentGuardHop(): OnionHop | null {
    return this.currentGuard();
  }

  /**
   * kind ‖ body を回路に載せて M1 へ送る (エコーは待たない。M1 が onDirectExit で受け取る)。
   * cover traffic の送出枠を使うので、Guard からは cover と区別が付かない。
   * exclude の M1 は使わない (保険の要求を別の M1 へ回すため)。
   *
   * @returns 送り出せたら { ok: true, guardId, middleId }。回路が組めない・枠を待ちきれない・3 枚を超えるなら ok: false
   */
  public async sendDirect(
    kind: number, body: Uint8Array, exclude: ReadonlySet<PeerId> = new Set(),
  ): Promise<{ ok: true; guardId: PeerId; middleId: PeerId } | { ok: false }> {
    if (!this.running || !this.directExitKindOk(kind)) return { ok: false };
    const bytes = new Uint8Array(1 + body.length);
    bytes[0] = kind;
    bytes.set(body, 1);
    const frags = splitIntoFragments(bytes, sodium.randombytes_buf(FRAG_ID_BYTES));
    if (!frags) return { ok: false };
    const route = await this.waitForRoute(new Set(exclude), Date.now() + this.readyWaitMs);
    if (!route || this.queue.length >= CIRCUIT_CONFIG.MAX_QUEUE) return { ok: false };
    const tried = new Set<PeerId>(exclude);
    let used: { guardId: PeerId; middleId: PeerId } | null = null;
    const ok = await new Promise<boolean>((resolve) => {
      let waitTimer: ReturnType<typeof setTimeout> | null = null;
      const entry: QueuedItem = {
        frags,
        tried,
        settle: (sent) => {
          if (waitTimer) clearTimeout(waitTimer);
          waitTimer = null;
          resolve(sent);
        },
        onSent: (guardId, middleId) => { used = { guardId, middleId }; },
      };
      this.queue.push(entry);
      waitTimer = setTimeout(() => {
        const i = this.queue.indexOf(entry);
        if (i >= 0) {
          this.queue.splice(i, 1);
          entry.settle(false);
        }
      }, this.sendWaitMs);
    });
    const u = used as { guardId: PeerId; middleId: PeerId } | null;
    return ok && u ? { ok: true, ...u } : { ok: false };
  }

  private directExitKindOk(kind: number): boolean {
    return Number.isInteger(kind) && kind >= 2 && kind <= 0xff;
  }

  // ── ライフサイクル ──

  /**
   * cover traffic を開始する。ノード起動時に必ず呼ぶこと。
   *
   * ★ 「最初の投稿のときに起動する」は不可。セルの出始めがそのまま
   *   「この端末が今投稿した」という合図になる。
   */
  public start(): void {
    if (this.running) return;
    this.running = true;
    this.scheduleCover();
    this.requestGuardNeighbors();
    this.pexTimer = setInterval(() => this.requestGuardNeighbors(), CIRCUIT_CONFIG.GUARD_PEX_INTERVAL_MS);
  }

  public stop(): void {
    this.running = false;
    if (this.coverTimer) clearTimeout(this.coverTimer);
    this.coverTimer = null;
    if (this.pexTimer) clearInterval(this.pexTimer);
    this.pexTimer = null;
    for (const t of this.pending) clearTimeout(t);
    this.pending.clear();
    this.pendingPerPeer.clear();
    // 順番待ち・送出中の発信は、タイマーを残さず失敗として終わらせる
    const abandoned = [...this.queue, ...(this.inflight ? [this.inflight.item] : [])];
    this.queue = [];
    this.inflight = null;
    this.activeCircuit = null;
    this.reassembler.clear();
    for (const item of abandoned) item.settle(false);
    // 回路を待っている発信は、タイマーを残さず失敗として終わらせる
    for (const w of [...this.readyWaiters]) w.cancel();
  }

  public destroy(): void {
    this.stop();
    this.seenCells.destroy();
    this.reassembler.clear();
    this.neverFluff.destroy();
    this.m1Guards.clear();
    this.authorGuards.clear();
    this.exitHandlers.clear();
    this.directExits.clear();
    this.inspectors.clear();
  }

  // ── 発信 ──

  /**
   * item を回路に載せ、エコー (網に現れたこと) を待つ。
   *
   * ★ Fail-Closed: 回路が組めない・エコーが返らない場合は false を返すだけで、
   *   平文の送信には決して落ちない。回路が組めるまで待つ間も、何も送らない。
   *
   * item は断片 (最大 MAX_FRAGMENTS 枚) に分けて、回路の途中に跨らない位置から送り出す。
   * 3 枚を超えるものは false (ここで拒否。何も送らない)。
   *
   * 失敗時は同じ Guard のまま M1 だけを替えて 1 回だけやり直す (全断片を新しい断片 id で
   * 後の回路から送り直す)。セルは cover traffic に混ざるので、やり直しは Guard から見て
   * 通常の送出と区別できない。Stem の途中で投稿が握りつぶされた場合も、
   * エコーが返らないのでここで拾われる。エコー待ちは最後の断片を送り出した時点から数える。
   *
   * @param echoId 網に現れたことを確かめる識別子 (packet_id)
   */
  public async send(item: ExitItem, echoId: string): Promise<boolean> {
    if (!this.running) {
      log.warn(`circuit not running; refusing to send ${echoId.substring(0, 8)}`);
      return false;
    }
    let bytes: Uint8Array;
    try {
      bytes = encodeExitItem(item);
    } catch (err) {
      log.error(`cannot encode item ${echoId.substring(0, 8)}: ${(err as Error)?.message ?? err}`);
      return false;
    }
    if (splitIntoFragments(bytes, new Uint8Array(FRAG_ID_BYTES)) === null) {
      log.error(`item ${echoId.substring(0, 8)} needs more than ${MAX_FRAGMENTS} cells (${bytes.length} bytes); rejected`);
      return false;
    }

    const triedMiddles = new Set<PeerId>();
    const deadline = Date.now() + this.readyWaitMs;

    // 歩きが自分に戻ってきても、作者本人は Fluff しない。自分の Guard にも渡さない (authorGuards)
    const ownKey = `${item.type}:${echoId}`;
    this.neverFluff.add(ownKey);
    const ownGuards = this.rememberAuthorGuards(ownKey);

    for (let attempt = 0; attempt < CIRCUIT_CONFIG.MAX_ATTEMPTS; attempt++) {
      const route = await this.waitForRoute(triedMiddles, deadline);
      if (!route) {
        log.warn(`circuit not ready; dropping ${echoId.substring(0, 8)} (fail-closed)`);
        return false;
      }
      ownGuards.add(route.guard.peerId);
      if (this.queue.length >= CIRCUIT_CONFIG.MAX_QUEUE) {
        log.warn(`circuit queue full; dropping ${echoId.substring(0, 8)}`);
        return false;
      }

      // 断片 id は試行ごとに新しくする (M1 での再構成が試行どうしで混ざらないように)
      const frags = splitIntoFragments(bytes, sodium.randombytes_buf(FRAG_ID_BYTES))!;
      let echo: Promise<boolean> = Promise.resolve(false);
      let waitTimer: ReturnType<typeof setTimeout> | null = null;
      const queued = new Promise<boolean>((resolve) => {
        const entry: QueuedItem = {
          frags,
          tried: triedMiddles,
          settle: (ok) => {
            if (waitTimer) clearTimeout(waitTimer);
            waitTimer = null;
            // 最後の断片を送り出した時点からエコーを待つ (順番待ちの時間を数えない)
            if (ok) echo = this.dandelion.awaitEcho(echoId, this.echoTimeoutMs);
            resolve(ok);
          },
        };
        this.queue.push(entry);
        waitTimer = setTimeout(() => {
          // まだ 1 枚も出ていなければ諦めて取り下げる
          const i = this.queue.indexOf(entry);
          if (i >= 0) {
            this.queue.splice(i, 1);
            entry.settle(false);
          }
        }, this.sendWaitMs);
      });

      if (!(await queued)) {
        if (!this.running) return false;
        log.warn(`circuit slot wait expired; dropping ${echoId.substring(0, 8)}`);
        return false;
      }
      if (await echo) return true;
      if (!this.running) return false;
      log.debug(() => `no echo for ${echoId.substring(0, 8)} (attempt ${attempt + 1}); trying another M1`);
    }
    return false;
  }

  /**
   * Guard と M1 の候補が揃うまで待つ。
   *
   * 起床の契機: cover の送出枠 (Guard の選択はここで評価される) / Guard の変更 /
   * Guard からの PEX 応答。タイマーは上限用の 1 本だけで、解決・stop で必ず外す。
   */
  private waitForRoute(
    exclude: Set<PeerId>,
    deadline: number,
  ): Promise<{ guard: OnionHop; middle: OnionHop } | null> {
    const tryRoute = () => {
      const guard = this.currentGuard();
      if (!guard) return null;
      const middle = this.pickMiddle(guard.peerId, exclude);
      return middle ? { guard, middle } : null;
    };

    const ready = tryRoute();
    if (ready) return Promise.resolve(ready);
    const remaining = deadline - Date.now();
    if (!this.running || remaining <= 0) return Promise.resolve(null);

    return new Promise((resolve) => {
      const finish = (route: { guard: OnionHop; middle: OnionHop } | null) => {
        clearTimeout(timer);
        this.readyWaiters.delete(waiter);
        resolve(route);
      };
      const waiter: ReadyWaiter = {
        poll: () => {
          const route = tryRoute();
          if (route) finish(route);
        },
        cancel: () => finish(null),
      };
      const timer = setTimeout(() => finish(null), remaining);
      this.readyWaiters.add(waiter);
    });
  }

  private wakeWaiters(): void {
    if (this.readyWaiters.size === 0) return;
    for (const w of [...this.readyWaiters]) w.poll();
  }

  /** テスト・診断用: 次の送出枠を待たずに 1 枠ぶん送出する */
  public flushOnce(): void {
    this.emitCell();
  }

  private scheduleCover(): void {
    if (!this.running) return;
    if (this.coverTimer) clearTimeout(this.coverTimer);
    const delay = Math.max(1, exponentialDelay(this.coverIntervalMs, this.coverIntervalMs * 10));
    this.coverTimer = setTimeout(() => {
      this.emitCell();
      this.reassembler.sweep();
      // 送出枠ごとに Guard の選択が評価されるので、待っている発信はここで起こす
      this.wakeWaiters();
      this.scheduleCover();
    }, delay);
  }

  /**
   * 送出枠 1 つぶんのセルを出す。本物の断片があればそれを、無ければ drop を載せる。
   *
   * 回路は CIRCUIT_SLOTS 枠ごとに M1 を替える (cover も本物も同じ。OnionCircuit の説明を参照)。
   */
  private emitCell(): void {
    const guard = this.currentGuard();
    if (!guard) return;

    // Guard が替わったら回路を打ち切る。送出中だった item は M1 の猶予切れで捨てられ、
    // 作者のエコー待ちが切れて新しい Guard で送り直される
    if (this.activeCircuit && this.activeCircuit.guardId !== guard.peerId) {
      this.activeCircuit = null;
      if (this.inflight) {
        const dead = this.inflight.item;
        this.inflight = null;
        // 送り出した扱いにしてエコー待ちへ。届かなければ再送される (直接の出口は応答待ちで同じく再送される)
        dead.settle(true);
      }
    }

    // 新しい回路: 先頭の item が試した M1 と直前の M1 を避けて、重み付けで選ぶ
    if (!this.activeCircuit || this.activeCircuit.used >= CIRCUIT_CONFIG.CIRCUIT_SLOTS) {
      const head = this.queue[0];
      const tried = new Set(head?.tried ?? []);
      const middle =
        this.pickMiddle(guard.peerId, tried, this.activeCircuit?.middle.peerId) ??
        // 先頭の item が全候補を試し済みでも、cover の回路は続ける (item は取り下げを待つ)
        this.pickMiddle(guard.peerId, new Set(), this.activeCircuit?.middle.peerId);
      if (!middle) return;
      this.activeCircuit = { guardId: guard.peerId, middle, used: 0 };
    }
    const circuit = this.activeCircuit;
    const position = circuit.used + 1; // 1..CIRCUIT_SLOTS

    // 本物を載せるか: 送出中の続きは必ず次の枠へ。新しく始めるのは「収まる」ときだけ
    if (!this.inflight) {
      const head = this.queue[0];
      if (
        head &&
        !head.tried.has(circuit.middle.peerId) &&
        position + head.frags.length - 1 <= CIRCUIT_CONFIG.CIRCUIT_SLOTS
      ) {
        this.queue.shift();
        head.tried.add(circuit.middle.peerId);
        this.inflight = { item: head, next: 0 };
      }
    }

    let payload: ExitPayload = { type: 'drop' };
    let finished: QueuedItem | null = null;
    if (this.inflight) {
      payload = this.inflight.item.frags[this.inflight.next++];
      if (this.inflight.next >= this.inflight.item.frags.length) {
        finished = this.inflight.item;
        this.inflight = null;
      }
    }

    circuit.used++;
    let cell: Uint8Array;
    try {
      cell = OnionRouter.wrapCircuit(payload, [guard, circuit.middle]);
    } catch (err) {
      log.error(`failed to wrap onion cell: ${err}`);
      finished?.settle(false);
      return;
    }
    this.peerManager.sendMessage(guard.peerId, WireType.ONION_STEM, { onionBytes: cell });
    finished?.onSent?.(guard.peerId, circuit.middle.peerId);
    finished?.settle(true);
  }

  private currentGuard(): OnionHop | null {
    return this.dandelion.getPinnedGuard(this.guardCandidates());
  }

  /**
   * Guard の候補。自分と同じ出所 (同じ LAN・同じ公開 IP。同じ端末の別のノードを含む) の隣人は除く。
   *
   * ★ Guard が自分と同じ家にいると、M1 から見た「前の段」の IP が自分の IP になる。M1 は投稿や
   *   要求の中身を見る出口なので、M1 だけで作者が分かってしまう。
   * ★ 出所をまだ求めていない隣人も使わない (分かってから選ぶ)。
   */
  private guardCandidates(): OnionHop[] {
    const all = this.verifiedNeighbors();
    const pm = this.peerManager;
    if (!pm.originOf || !pm.isOwnOrigin || pm.sameOriginHopsAllowed) return all;
    return all.filter((h) => {
      const origin = pm.originOf!(h.peerId);
      return origin !== ORIGIN_PENDING && !pm.isOwnOrigin!(origin);
    });
  }

  /**
   * Guard として、この送り主のセルを M1 へ渡してよいか。
   *
   * - 送り主と M1 が同じ出所なら渡さない。M1 が出す要求や投稿が、送り主の IP から出ることになる。
   * - 送り主が自分 (Guard) と同じ出所なら渡さない。M1 から見た前の段の IP が送り主の IP になる。
   * 出所をまだ求めていない相手も、分かるまでは渡さない。
   */
  private relayAllowed(senderId: PeerId, nextHop: PeerId): boolean {
    const pm = this.peerManager;
    if (!pm.originOf || !pm.isOwnOrigin || pm.sameOriginHopsAllowed) return true;
    const from = pm.originOf(senderId);
    if (from === ORIGIN_PENDING || pm.isOwnOrigin(from)) return false;
    return !sameOrigin(from, pm.originOf(nextHop));
  }

  private verifiedNeighbors(): OnionHop[] {
    const list = (this.peerManager as any)?.verifiedPeersWithKeys as OnionHop[] | undefined;
    return Array.isArray(list) ? list : [];
  }

  /**
   * M1 を選ぶ。Guard の隣人であることが前提 (Guard が直接転送できる相手)。
   *
   * 優先: 自分の隣人ではないノード (M1 が作者の候補を N(Guard) ∩ N(M1) に絞れない)
   * 次点: 自分の隣人でもあるノード (小さな網では避けられない)
   *
   * @param softAvoid 直前の回路の M1。他に候補があれば避ける (必須の除外ではない)
   */
  private pickMiddle(guardId: PeerId, exclude: Set<PeerId>, softAvoid?: PeerId): OnionHop | null {
    const now = Date.now();
    const me = this.peerManager.myPeerId;
    const fresh: OnionHop[] = [];
    for (const [peerId, info] of this.guardNeighbors) {
      if (now - info.seenAt > CIRCUIT_CONFIG.GUARD_NEIGHBOR_TTL_MS) {
        this.guardNeighbors.delete(peerId);
        continue;
      }
      if (peerId === me || peerId === guardId || exclude.has(peerId)) continue;
      fresh.push({ peerId, pubkey: info.pubkey });
    }
    if (fresh.length === 0) return null;

    const nonAdjacent = fresh.filter(h => !this.peerManager.peers.has(h.peerId));
    let pool = nonAdjacent.length > 0 ? nonAdjacent : fresh;
    // 直前の回路の M1 は、同じ区分 (隣接/非隣接) に他の候補があるかぎり避ける。Guard から見て
    // 回路の区切り (3 スロット) が曖昧にならないようにするため。候補が 1 つしか無いときは、
    // 「M1 は自分の隣人でない」を優先して同じ M1 が続く (見える連続は 3 の倍数のまま)
    if (softAvoid && pool.length > 1) pool = pool.filter(h => h.peerId !== softAvoid);
    // 観測期間の長い候補ほど選ばれやすくする (A3)。新しく Guard の隣に
    // 張り付いた Sybil は M1 に選ばれにくい。拒否はしないので、小さな網でも回路は組める。
    const weights = pool.map(h => {
      const firstSeen = this.guardNeighbors.get(h.peerId)?.firstSeen ?? now;
      return 0.25 + Math.min(now - firstSeen, OBSERVATION_SATURATION_MS) / OBSERVATION_SATURATION_MS;
    });
    return pool[secureWeightedIndex(weights)];
  }

  // ── Guard の隣人表 ──

  private requestGuardNeighbors(): void {
    const guard = this.currentGuard();
    if (!guard) return;
    this.peerManager.sendMessage(guard.peerId, WireType.PEX_REQUEST, { minDistance: 0 });
  }

  /**
   * Guard からの PEX 応答で隣人表を更新する。
   * 他の隣人からの応答は M1 選びに使わない (Guard が直接転送できる相手とは限らない)。
   */
  private handleGuardPex(senderId: PeerId, msg: any): void {
    if (senderId !== this.dandelion.getPinnedGuardId()) return;
    if (!msg || !Array.isArray(msg.peers)) return;

    const powParams: NodeIdPowParams = (this.peerManager as any)?.nodeIdPowParams ?? NODE_ID_POW;
    const now = Date.now();
    for (const entry of msg.peers.slice(0, 16)) {
      const peerId = entry?.id;
      if (typeof peerId !== 'string' || !PEER_ID_RE.test(peerId)) continue;
      if (peerId === this.peerManager.myPeerId) continue;

      const known = this.guardNeighbors.get(peerId);
      const pubkey = toBytes(entry?.pubkey);
      if (known && sodium.memcmp(known.pubkey, pubkey)) {
        known.seenAt = now;
        continue;
      }
      // peerId ↔ pubkey の束縛と NodeId PoW を確かめる。束縛が無いと
      // Guard は任意の公開鍵を差し込める (=M1 のセルを自分で復号できる)。
      const claim = { peerId, pubkey, powCounter: entry?.powCounter };
      if (!NodeIdentity.verifyClaim(claim, powParams)) continue;
      this.guardNeighbors.set(peerId, { pubkey, firstSeen: now, seenAt: now });
    }
    this.wakeWaiters();
  }

  // ── 受信 (Guard / M1) ──

  private myCurveKeys(): { pk: Uint8Array; sk: Uint8Array } | null {
    if (this.curveKeys) return this.curveKeys;
    const identity = (this.peerManager as any)?.nodeIdentity;
    if (!identity) return null;
    const secret = identity.exportSecret();
    this.curveKeys = {
      pk: OnionRouter.toCurvePublicKey(secret.pubkey),
      sk: OnionRouter.toCurvePrivateKey(secret.privkey),
    };
    return this.curveKeys;
  }

  private handleCell(senderId: PeerId, msg: any): void {
    const cell = msg?.onionBytes;
    if (!(cell instanceof Uint8Array) || cell.byteLength !== OnionRouter.CELL_SIZE) return;

    // 同じセルの再送 (リプレイ) は処理しない。同じセルを流し直して
    // 下流の反応を見るタグ付けを防ぐ。
    const cellId = Encoding.toHex(sodium.crypto_generichash(16, cell, null));
    if (this.seenCells.has(cellId)) return;
    this.seenCells.add(cellId);

    const keys = this.myCurveKeys();
    if (!keys) return;
    const result = OnionRouter.unwrapWithCurveKeys(cell, keys.pk, keys.sk);
    if (!result) {
      log.trace(() => `ONION_STEM unwrap failed from=${senderId.substring(0, 8)}`);
      return;
    }

    if (result.type === 'relay') {
      this.relay(senderId, result.nextHop, result.innerOnion);
      return;
    }
    // cover は M1 で捨てる
    if (result.type === 'drop') return;

    // M1: 本物の断片。(送り主 = Guard, 断片 id) で集め、揃ったら item に戻す。
    const bytes = this.reassembler.add(senderId, result);
    if (!bytes) return;
    // Stem を歩かせない種別 (Ozzy の代理取得など): M1 として自分で受け取る
    const direct = bytes.length > 0 ? this.directExits.get(bytes[0]) : undefined;
    if (direct) {
      const body = bytes.slice(1);
      this.defer(senderId, this.relayJitter(), () => direct(body, senderId));
      return;
    }
    const item = decodeExitItem(bytes);
    if (!item) {
      log.debug(() => `reassembled item rejected (malformed) from=${senderId.substring(0, 8)}`);
      return;
    }
    // 自分では Fluff せず、Stem の最初の一歩を踏み出す。
    this.defer(senderId, this.relayJitter(), () => this.startStem(item, senderId));
  }

  private relay(senderId: PeerId, nextHop: PeerId, innerOnion: Uint8Array): void {
    // 送り主へ送り返さない・自分宛てにしない (反射・ループの防止)
    if (nextHop === senderId || nextHop === this.peerManager.myPeerId) return;
    // 正規の回路 (Guard → M1) の内側は常に固定長の M1 層。それ以外は作られたセル
    if (innerOnion.byteLength !== SEALED_EXIT_LAYER_SIZE) return;
    // 送り主・M1・自分が同じ家にならないこと (relayAllowed)
    if (!this.relayAllowed(senderId, nextHop)) return;

    let padded: Uint8Array;
    try {
      padded = OnionRouter.padCell(innerOnion);
    } catch {
      return;
    }

    this.defer(senderId, this.relayJitter(), () => {
      const peer = this.peerManager.peers.get(nextHop);
      if (!peer || !peer.isConnected || !peer.isVerified) return;
      this.peerManager.sendMessage(nextHop, WireType.ONION_STEM, { onionBytes: padded });
    });
  }

  // ── Stem (M1 以降の歩き) ──

  private relayJitter(): number {
    return exponentialDelay(this.relayDelayMs, this.relayDelayMs * 10);
  }

  /**
   * M1 として、本物を歩かせ始める。
   *
   * ★ ここで Fluff してはならない。M1 が Fluff すると Guard が持つ「セルの行き先」と
   *   「flood した者」が一致し、旧実装の相関攻撃が復活する。
   *   渡す相手が居なければ捨てる (作者のエコー待ちが切れて別の M1 でやり直される)。
   */
  private startStem(item: ExitItem, guardId: PeerId): void {
    const key = this.inspect(item);
    if (!key) return;
    this.neverFluff.add(key);
    this.m1Guards.set(key, guardId);
    // 上限を超えたら古いものから忘れる (Map は挿入順)。忘れたものは普通の walker と
    // 同じに扱われるが、Guard を除外する目的は歩き始めの直後にこそ要る
    while (this.m1Guards.size > M1_GUARD_MEMORY) {
      const oldest = this.m1Guards.keys().next().value;
      if (oldest === undefined) break;
      this.m1Guards.delete(oldest);
    }
    if (!this.forwardStem(item, guardId)) {
      log.debug(() => `stem start: no neighbor to hand ${key.substring(0, 16)} to; dropped`);
    }
  }

  /** WireType.STEM の受信。ペイロードは { item: ExitItem } (ホップ数は載せない) */
  private handleStem(senderId: PeerId, msg: any): void {
    const item = parseStemItem(msg?.item);
    if (!item) {
      log.debug(() => `STEM REJECTED (malformed) from=${senderId.substring(0, 8)}`);
      return;
    }
    // 保留の上限 (全体 / 送信者ごと) は検証より先に掛ける。隣人 1 人が
    // 検証 (PoW) の計算とキューを占有して他人の Stem を落とせないように。
    this.defer(senderId, this.relayJitter(), () => this.walk(item, senderId));
  }

  /**
   * Stem の 1 歩。検証し、重複を除き、確率 STEM_FLUFF_PROBABILITY で Fluff、
   * 外れたら直前の相手以外のランダムな隣人へ渡す。
   *
   * ★ 状態の扱い:
   *   - flood 済み        … 捨てる (既に網に出ている)
   *   - 自分が Fluff してはならないもの (M1 が歩かせ始めたもの / 自分の投稿) … 渡すだけ
   *   - 渡す相手が居ない  … 行き止まり。その場で Fluff する (タイマーによる Fluff ではない)
   *
   * ★ 同じものが Stem で再び届いても (ループ・やり直し)、特別扱いせず普通の 1 歩として扱う。
   *   「一度見たら Fluff」にすると、作者がやり直したとき (別の M1' 経由) に、1 回目で
   *   通ったノードが M1' のすぐ隣で Fluff してしまい、Guard から Fluff 地点が読みやすくなる。
   *   歩きは 1 歩ごとに確率 STEM_FLUFF_PROBABILITY で終わるので、ループしても必ず終わる。
   *   同じものを送り直させて歩かせる手口は、新しい Stem を送るのと同じ手間で、増幅にならない
   *   (隣人ごとの保留上限・レート制限が掛かる)。
   */
  private walk(item: StemItem, from: PeerId): void {
    const key = this.inspect(item);
    if (!key) return;

    if (this.neverFluff.has(key)) {
      // 自分が Fluff してはならないもの (M1 として歩かせ始めた / 自分が作者)。渡すだけ。
      // M1 なら、そのセルを中継してきた Guard には渡さない (上の m1Guards の説明)。
      // 作者なら、送るのに使った Guard と今の Guard (authorGuards の説明)。
      const avoid = new Set<PeerId>();
      const guardOfMine = this.m1Guards.get(key);
      if (guardOfMine) avoid.add(guardOfMine);
      const mine = this.authorGuards.get(key);
      if (mine) {
        for (const g of mine) avoid.add(g);
        const current = this.currentGuard()?.peerId;
        if (current) avoid.add(current);
      }
      if (this.forwardStem(item, from, avoid)) return;
      // ★ 作者で、自分の Guard 以外に渡す先が無い (3 台ほどの小さな網の行き止まり)。ここで捨てたり直前の相手 (M1)
      //   へ返したりすると、作者と M1 の間で行き来が終わらなくなる (どちらも Fluff しないため)。
      //   そのときだけ Guard に渡す。隣人が数本ある網では、Guard 以外の候補が必ずあるのでここには来ない。
      if (mine) {
        if (this.forwardStem(item, from)) return;
        // 作者の隣人が直前の相手だけ。捨てると投稿が消えるので返す。直前の相手が自分の Guard でも返す:
        // Guard はたった今この投稿を作者へ渡したので、返されて新たに分かることは「作者に他の隣人が居ない」だけ。
        this.sendStem(from, item);
        return;
      }
      // M1 の行き止まり: 渡す先が直前の相手しか居ない。捨てると投稿が消えるので、
      // 直前の相手へ返す。ただしそれが自分の Guard なら返さない (捨てて作者のやり直しに任せる)。
      if (!avoid.has(from)) this.sendStem(from, item);
      return;
    }

    if (this.random() < CIRCUIT_CONFIG.STEM_FLUFF_PROBABILITY) {
      this.fluff(item, from);
      return;
    }
    if (!this.forwardStem(item, from)) this.fluff(item, from);
  }

  /** 検証と flood 済み判定。歩かせてよいなら `type:id` を返す */
  private inspect(item: StemItem): string | null {
    const inspector = this.inspectors.get(item.type);
    if (!inspector) return null;
    let id: string | null;
    try {
      id = inspector.inspect(item);
    } catch {
      return null;
    }
    if (!id) return null;
    if (inspector.isFlooded(id)) return null;
    return `${item.type}:${id}`;
  }

  /** 自分が作者の item に使う Guard の記録 (古いものから捨てる。M1_GUARD_MEMORY 件まで) */
  private rememberAuthorGuards(key: string): Set<PeerId> {
    let set = this.authorGuards.get(key);
    if (!set) {
      set = new Set<PeerId>();
      this.authorGuards.set(key, set);
      while (this.authorGuards.size > M1_GUARD_MEMORY) {
        const oldest = this.authorGuards.keys().next().value;
        if (oldest === undefined) break;
        this.authorGuards.delete(oldest);
      }
    }
    const current = this.currentGuard()?.peerId;
    if (current) set.add(current);
    return set;
  }

  /**
   * 直前の相手以外のランダムな検証済み隣人へ Stem で渡す。
   * @returns 渡せたか (相手が居なければ false)
   */
  private forwardStem(item: StemItem, from: PeerId, alsoExclude?: ReadonlySet<PeerId>): boolean {
    const me = this.peerManager.myPeerId;
    const candidates: PeerId[] = [];
    for (const peer of this.peerManager.peers.values()) {
      if (peer.peerId === from || peer.peerId === me || alsoExclude?.has(peer.peerId)) continue;
      if (!peer.isConnected || !peer.isVerified) continue;
      candidates.push(peer.peerId);
    }
    if (candidates.length === 0) return false;
    const next = candidates[Math.min(candidates.length - 1, Math.floor(this.random() * candidates.length))];
    this.sendStem(next, item);
    return true;
  }

  private sendStem(to: PeerId, item: StemItem): void {
    const peer = this.peerManager.peers.get(to);
    if (!peer || !peer.isConnected || !peer.isVerified) return;
    this.peerManager.sendMessage(to, WireType.STEM, { item });
  }

  /** Fluff: ルーターのハンドラ (エコー通知・ローカル配信・flood) に任せる */
  private fluff(item: StemItem, from: PeerId): void {
    const handlers = this.exitHandlers.get(item.type);
    if (!handlers) return;
    for (const h of handlers) {
      try {
        h(item, from);
      } catch (err) {
        log.error(`fluff handler for ${item.type} failed`, err);
      }
    }
  }

  /**
   * 遅延実行。保留数に全体と送信者ごとの上限を置く。
   * 全体の上限だけだと、隣人 1 人がキューを埋めて他人の中継を落とせる。
   * Stem の歩きにも同じ上限を使う。
   */
  private defer(senderId: PeerId, delay: number, fn: () => void): boolean {
    const perPeer = this.pendingPerPeer.get(senderId) ?? 0;
    if (this.pending.size >= CIRCUIT_CONFIG.MAX_PENDING || perPeer >= CIRCUIT_CONFIG.MAX_PENDING_PER_PEER) {
      log.debug(() => `onion work dropped: pending limit (from=${senderId.substring(0, 8)})`);
      return false;
    }
    this.pendingPerPeer.set(senderId, perPeer + 1);

    const timer = setTimeout(() => {
      this.pending.delete(timer);
      const n = (this.pendingPerPeer.get(senderId) ?? 1) - 1;
      if (n > 0) this.pendingPerPeer.set(senderId, n);
      else this.pendingPerPeer.delete(senderId);
      fn();
    }, delay);
    this.pending.add(timer);
    return true;
  }
}

/** [0, 1) の暗号論的乱数 */
function secureUnit(): number {
  return crypto.getRandomValues(new Uint32Array(1))[0] / 0x100000000;
}

/**
 * Stem で受け取ったものの形を確定させる。送り主は任意のペイロードを作れるので、
 * 余計なフィールドは持ち込まず、種別ごとに必要なものだけ取り出す。
 * (WireCodec が STEM フレームの item を decodeExitItem で戻した後の値が入る)
 */
function parseStemItem(raw: any): StemItem | null {
  if (!raw || typeof raw !== 'object') return null;
  if (raw.type === 'exit_fluff') {
    if (!raw.packet || typeof raw.packet !== 'object') return null;
    return { type: 'exit_fluff', packet: raw.packet };
  }
  return null;
}

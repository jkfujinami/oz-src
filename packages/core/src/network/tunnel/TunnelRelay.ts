import type { IMessageDispatcher, IPeerManager, PeerId } from '../../types';
import sodium from '../../crypto/sodium';
import { Encoding } from '../../common/Encoding';
import { createLogger } from '../../common/Logger';
import { WireType } from '../wire/WireTypes';
import { TUNNEL_ERROR_CODE } from '../wire/WireCodec';
import { DAY_MS } from '../../crypto/PowPolicy';

const log = createLogger('net.tunnel');

/** 1 つの相手に許す量 (要求数・帯域・同時数) */
export interface PeerBudget {
  /** 要求 (SEND / FWD) の定常レート (件/秒) とバースト */
  reqPerSec: number;
  reqBurst: number;
  /** 同時に生きている経路 (応答待ち) の数 */
  concurrent: number;
  /** その相手から受け取るトンネルフレームの本体のバイト/秒とバースト */
  bytesPerSec: number;
  bytesBurst: number;
}

/** 利用者の TUNNEL_SEND の枠 (PeerBudget に 1 日の上限が付く) */
export interface ClientSendBudget extends PeerBudget {
  bytesPerDay: number;
}

/**
 * トンネルの制限。★ どの段 (G_R・G_h・H) も、相手ごとに「要求数・帯域・同時数」を絞る。
 *   Guard は 1 台で数百人を受け入れ、バックボーンの相手 (他の信頼 Guard) は自分の利用者全員ぶんを束ねて送ってくるので、
 *   バックボーンには広い枠、それ以外 (利用者・一般の隣人・Guard を名乗って張ってきた誰か) には狭い枠を与える。
 */
export const TUNNEL_LIMITS = {
  /** 経路の状態を持ち続ける最大の無通信時間 (最後の要求・応答の片から) */
  ROUTE_IDLE_MS: 60_000,
  /** 掃除の間隔 */
  SWEEP_INTERVAL_MS: 5_000,
  /** 1 つの接続が登録できる tunnelId の数 (1 つの SID は (SID, 受け口) ごとに 1 本。余裕を見て 4) */
  MAX_TUNNELS_PER_PEER: 4,
  /** 登録の上限 (全体)。Guard は多数の保持者を受け持つ。一般の隣人 (受け口の役) は少数 */
  MAX_TUNNELS: { guard: 4096, client: 64 },
  /** 経路の状態の上限 (全体。G_R と G_h の合計) */
  MAX_ROUTES: { guard: 8192, client: 256 },
  /** 普通の相手 (利用者・一般の隣人・信頼 Guard でない誰か)。1 回の応答 (最大 4MiB) が収まるバースト */
  PEER: {
    reqPerSec: 2, reqBurst: 6, concurrent: 6,
    bytesPerSec: 2 * 1024 * 1024, bytesBurst: 8 * 1024 * 1024,
  } satisfies PeerBudget,
  /**
   * ── C4: 利用者 1 人 (R) が自分の Guard (G_R) へ出す TUNNEL_SEND の上り制限 (docs/design/file-sharing.md §6) ──
   * 大容量ファイルの預け入れ (1 チャンク = 約 18 本 × 15KiB の SEND) が主な負荷。押し流し (大量のゴミを保持者へ送り込む) の防御は
   * PoW ではなく**ここ**が主役: Guard は利用者の接続を元々知っていて、1 人あたりの上りを絞れる。
   *   - 帯域 1MiB/秒 (≒ 8Mbit/秒、家庭回線の上りの目安): 2GiB のファイルが最短 約 34 分。ここまで絞っても正直な利用者は
   *     裏でゆっくり上げるので困らない (設計 §3「上げるのは裏でゆっくり」)。
   *   - バースト 64MiB: 小さなファイル (数十 MiB) は待たずに出せる。空になったら 1MiB/秒に戻る (補充も 1MiB/秒)。
   *   - 1 日 4GiB (UTC の日): 最大のファイル 2 つ分。1 人が何日も流し続けても、保持者の容量 (枠 × 256MiB) の押し出しは 1 日 4GiB が上限。
   *   - 件数 60/秒 (バースト 120): 断片 15KiB × 60 = 900KiB/秒で帯域とほぼ釣り合う。ここを超える小さな要求の洪水は件数で止まる
   *     (帯域だけだと、数十バイトの GET_CHUNK を大量に出す洪水が通る)。
   *   - 同時 32 本: 断片の応答待ちの経路 (1 本 60 秒まで状態を持つ) を 1 人で握り続けられない。TunnelClient の手元の上限 (30) の少し上。
   * ★ 1 日の使用量は接続が切れても覚える (peerId ごとに上限付きのメモリ。日が変わると捨てる)。切って張り直すと枠が戻る穴を塞ぐ。
   *   キーは peerId (束縛された身元: 作るのに採掘が要る)。IP そのものは PeerManager が中継に渡さないので使えない — 同じ IP から
   *   peerId を作り直す攻撃者への歯止めは、身元の採掘の費用 (NODE_ID_POW) が担う。
   */
  CLIENT_SEND: {
    reqPerSec: 60, reqBurst: 120, concurrent: 32,
    bytesPerSec: 1024 * 1024, bytesBurst: 64 * 1024 * 1024,
    bytesPerDay: 4 * 1024 * 1024 * 1024,
  } satisfies ClientSendBudget,
  /** 1 日の使用量を覚えておく利用者の数の上限 */
  MAX_DAILY_ENTRIES: 20_000,
  /** バックボーンの相手 (他の信頼 Guard) */
  BACKBONE: {
    reqPerSec: 100, reqBurst: 400, concurrent: 1024,
    bytesPerSec: 32 * 1024 * 1024, bytesBurst: 64 * 1024 * 1024,
  } satisfies PeerBudget,
  /** 登録 (REGISTER) の頻度 (相手ごと) */
  REGISTER: { perSec: 0.5, burst: 4 },
  /** G_R が受け口 (G_h) へ自分から張る (ダイヤル) とき */
  DIAL: {
    /** 接続して検証が済むのを待つ上限 */
    TIMEOUT_MS: 10_000,
    /** 1 つの受け口を待つ要求の数 */
    MAX_PENDING_PER_GATEWAY: 16,
    /** 同時に待つ受け口の数 */
    MAX_GATEWAYS: 8,
    /** 全体のダイヤル頻度 (1 回/2 秒、バースト 3) */
    perSec: 0.5, burst: 3,
    /** 失敗した受け口へ再び張るまで */
    COOLDOWN_MS: 30_000,
  },
} as const;

export interface TunnelRelayOptions {
  /** 'guard' は枠が広い。省略は 'client' */
  role?: 'guard' | 'client';
  /** バックボーンの相手 (他の信頼 Guard) か。広い枠を許す。省略は誰も該当しない */
  isBackbone?: (peerId: PeerId) => boolean;
  /** 受け口へ自分から張る。省略は peerManager.connect(peerId, true) */
  dial?: (peerId: PeerId) => void;
  now?: () => number;
  /** ★ テスト専用 */
  limits?: Partial<{
    idleMs: number; peer: Partial<PeerBudget>; backbone: Partial<PeerBudget>; clientSend: Partial<ClientSendBudget>;
    maxTunnelsPerPeer: number; maxRoutes: number; dialTimeoutMs: number;
  }>;
}

/** 自分自身を指す印 (G_R = G_h のとき、前のホップ / 次のホップが自分) */
const SELF = '#self';

/** G_R の経路: 利用者 R の要求 1 件。応答 (RET) の返し先 */
interface UpRoute {
  tag: number;
  client: PeerId;
  reqId: number;
  /** 応答を返してくるはずの相手 (受け口の Guard)。自分が受け口なら SELF */
  via: PeerId;
  lastAt: number;
}

/** G_h の経路: G_R (または自分) から来た要求 1 件。応答 (REPLY) の返し先 */
interface DownRoute {
  tag: number;
  prevHop: PeerId;
  prevTag: number;
  holder: PeerId;
  lastAt: number;
}

interface Bucket { tokens: number; last: number }

interface PeerState {
  req: Bucket;
  bytes: Bucket;
}

interface PendingDial {
  startedAt: number;
  items: Array<{ tag: number; tunnelId: Uint8Array; body: Uint8Array }>;
  timer: ReturnType<typeof setTimeout>;
}

/**
 * TunnelRelay — 全ノードが持つ、トンネルの中継の役 (history v2 §4.4)。
 *
 *   取る:  R → G_R ─TUNNEL_SEND→ ─TUNNEL_FWD→ G_h ─TUNNEL_DELIVER→ H
 *   返す:  H ─TUNNEL_REPLY→ G_h ─TUNNEL_RET→ G_R ─TUNNEL_RESULT→ R
 *
 * 1 つのノードが 3 つの役 (G_R・G_h・登録の受け手) を兼ねる。G_R = G_h のときは FWD / RET を経由せず直接つなぐ。
 *
 * ★ 各ホップが覚えるのは「返しタグ → 前のホップ」だけ (無通信 60 秒で捨てる)。本体 (body) は H の鍵への sealed box で
 *   読めない。各ホップが**自分でタグを振り直す**ので、タグの値から前後のホップをつなげて見ることもできない
 *   (R の reqId は G_R の先へは出ず、G_R のタグは G_h の先へは出ない)。
 * ★ G_R が G_h へ届けるとき、既につながっていなければ自分から張る (どのノードでもよい。回数と同時数を絞る)。
 *   バックボーン (信頼 Guard 同士) がある網では張る必要がない。リストが無い網 (オープン) では
 *   R の 1 ホップ目 (ただの隣人) が G_R になり、受け口へ直接張る。
 * ★ H に渡す fromHop は、H のすぐ前のホップの peerId だけ。R の peerId は H にも G_h にも渡らない
 *   (G_R = G_h のときは、fromHop = G_h 自身)。
 * ★ 応答の片が壊れた・黙った場合の安全は端から端まで暗号 (TunnelCrypto) が担う。中継の判断は
 *   「状態があるか・送ってきた相手が正しいか・枠に収まっているか」だけ。
 */
export class TunnelRelay {
  private readonly now: () => number;
  private readonly role: 'guard' | 'client';
  private readonly cfg: {
    idleMs: number; peer: PeerBudget; backbone: PeerBudget; clientSend: ClientSendBudget; maxTunnelsPerPeer: number; maxRoutes: number; maxTunnels: number; dialTimeoutMs: number;
  };
  private readonly isBackbone: (peerId: PeerId) => boolean;
  private readonly dial: (peerId: PeerId) => void;

  /** tunnelId (hex) → 登録した接続 */
  private tunnels = new Map<string, PeerId>();
  private tunnelsByPeer = new Map<PeerId, Set<string>>();
  private up = new Map<number, UpRoute>();
  private down = new Map<number, DownRoute>();
  /** 重複 (同じ前のホップの同じタグ) の判定。`${prevHop}:${prevTag}` → down の tag */
  private downByPrev = new Map<string, number>();
  private peerState = new Map<PeerId, PeerState>();
  /** 利用者ごとの TUNNEL_SEND の枠 (件数・帯域)。peerState (他のホップからの FWD・REPLY・RET) とは別に数える */
  private sendState = new Map<PeerId, PeerState>();
  /** 利用者ごとの 1 日の使用量 (切断しても覚える)。day は UTC の日番号 */
  private daily = new Map<PeerId, { day: number; used: number }>();
  /** 利用者ごとの生きている経路の数 (up を数え直さないための索引) */
  private upCount = new Map<PeerId, number>();
  private registerBuckets = new Map<PeerId, Bucket>();
  private pendingDial = new Map<PeerId, PendingDial>();
  private dialCooldown = new Map<PeerId, number>();
  private dialBucket: Bucket | null = null;
  private sweepTimer: ReturnType<typeof setInterval> | null = null;
  private destroyed = false;

  /** 診断・テスト用 */
  public readonly stats = {
    dropped: { rate: 0, concurrent: 0, bytes: 0, daily: 0, full: 0, unknownRoute: 0, wrongPeer: 0, duplicate: 0, noTunnel: 0, noRoute: 0 },
    forwarded: { requests: 0, chunks: 0, bytes: 0 },
    dialed: 0,
  };

  private readonly onVerified = (peer: { peerId: PeerId }) => this.flushDial(peer?.peerId);
  private readonly onDisconnect = (peerId: PeerId) => this.forgetPeer(peerId);

  constructor(
    private readonly peerManager: IPeerManager,
    dispatcher: IMessageDispatcher,
    options: TunnelRelayOptions = {},
  ) {
    this.now = options.now ?? Date.now;
    this.role = options.role ?? 'client';
    this.isBackbone = options.isBackbone ?? (() => false);
    this.dial = options.dial ?? ((id) => { peerManager.connect(id, true); });
    const lim = options.limits ?? {};
    this.cfg = {
      idleMs: lim.idleMs ?? TUNNEL_LIMITS.ROUTE_IDLE_MS,
      peer: { ...TUNNEL_LIMITS.PEER, ...lim.peer },
      backbone: { ...TUNNEL_LIMITS.BACKBONE, ...lim.backbone },
      clientSend: { ...TUNNEL_LIMITS.CLIENT_SEND, ...lim.clientSend },
      maxTunnelsPerPeer: lim.maxTunnelsPerPeer ?? TUNNEL_LIMITS.MAX_TUNNELS_PER_PEER,
      maxRoutes: lim.maxRoutes ?? TUNNEL_LIMITS.MAX_ROUTES[this.role],
      maxTunnels: TUNNEL_LIMITS.MAX_TUNNELS[this.role],
      dialTimeoutMs: lim.dialTimeoutMs ?? TUNNEL_LIMITS.DIAL.TIMEOUT_MS,
    };
    dispatcher.register(WireType.TUNNEL_REGISTER, (from, msg) => this.handleRegister(from, msg));
    dispatcher.register(WireType.TUNNEL_SEND, (from, msg) => this.handleSend(from, msg));
    dispatcher.register(WireType.TUNNEL_FWD, (from, msg) => this.handleFwd(from, msg));
    dispatcher.register(WireType.TUNNEL_REPLY, (from, msg) => this.handleReply(from, msg));
    dispatcher.register(WireType.TUNNEL_RET, (from, msg) => this.handleRet(from, msg));
    dispatcher.register(WireType.TUNNEL_ERROR, (from, msg) => this.handleError(from, msg));
    peerManager.on('peer:verified', this.onVerified);
    peerManager.on('peer:disconnect', this.onDisconnect);
    this.sweepTimer = setInterval(() => this.sweep(), TUNNEL_LIMITS.SWEEP_INTERVAL_MS);
  }

  // ── 診断 ──

  public get routeCount(): number {
    return this.up.size + this.down.size;
  }
  public get upstreamCount(): number {
    return this.up.size;
  }
  public get downstreamCount(): number {
    return this.down.size;
  }
  public get tunnelCount(): number {
    return this.tunnels.size;
  }
  public get pendingDialCount(): number {
    return this.pendingDial.size;
  }
  /** この tunnelId を登録している接続 (無ければ undefined) */
  public tunnelHolder(tunnelId: Uint8Array): PeerId | undefined {
    return this.tunnels.get(Encoding.toHex(tunnelId));
  }

  // ── 制限 (トークンバケット) ──

  private budgetFor(peerId: PeerId): PeerBudget {
    return this.isBackbone(peerId) ? this.cfg.backbone : this.cfg.peer;
  }

  private stateOf(peerId: PeerId): PeerState {
    let st = this.peerState.get(peerId);
    if (!st) {
      const b = this.budgetFor(peerId);
      const t = this.now();
      st = { req: { tokens: b.reqBurst, last: t }, bytes: { tokens: b.bytesBurst, last: t } };
      this.peerState.set(peerId, st);
    }
    return st;
  }

  private take(bucket: Bucket, n: number, rate: number, burst: number): boolean {
    const t = this.now();
    bucket.tokens = Math.min(burst, bucket.tokens + (Math.max(0, t - bucket.last) / 1000) * rate);
    bucket.last = t;
    if (bucket.tokens < n) return false;
    bucket.tokens -= n;
    return true;
  }

  /** 相手から受け取った本体のバイト数を帯域の枠から引く。枠が無ければ false */
  private chargeBytes(peerId: PeerId, n: number): boolean {
    const b = this.budgetFor(peerId);
    if (!this.take(this.stateOf(peerId).bytes, n, b.bytesPerSec, b.bytesBurst)) {
      this.stats.dropped.bytes++;
      return false;
    }
    return true;
  }

  /** 新しい要求 1 件を受け付けてよいか (件数・帯域・同時数・全体の上限)。concurrent はその相手の生きている経路の数 */
  private admit(peerId: PeerId, bodyBytes: number, concurrent: number): boolean {
    const b = this.budgetFor(peerId);
    if (!this.take(this.stateOf(peerId).req, 1, b.reqPerSec, b.reqBurst)) {
      this.stats.dropped.rate++;
      return false;
    }
    if (concurrent >= b.concurrent) {
      this.stats.dropped.concurrent++;
      return false;
    }
    if (this.routeCount >= this.cfg.maxRoutes) {
      this.stats.dropped.full++;
      return false;
    }
    return this.chargeBytes(peerId, bodyBytes);
  }

  private countUp(client: PeerId): number {
    return this.upCount.get(client) ?? 0;
  }

  /** up の出し入れは必ずこの 2 つを通す (利用者ごとの数の索引を保つ) */
  private addUp(route: UpRoute): void {
    this.up.set(route.tag, route);
    this.upCount.set(route.client, (this.upCount.get(route.client) ?? 0) + 1);
  }

  private removeUp(tag: number): UpRoute | undefined {
    const r = this.up.get(tag);
    if (!r) return undefined;
    this.up.delete(tag);
    const n = (this.upCount.get(r.client) ?? 1) - 1;
    if (n <= 0) this.upCount.delete(r.client);
    else this.upCount.set(r.client, n);
    return r;
  }

  private sendStateOf(peerId: PeerId): PeerState {
    let st = this.sendState.get(peerId);
    if (!st) {
      const b = this.cfg.clientSend;
      const t = this.now();
      st = { req: { tokens: b.reqBurst, last: t }, bytes: { tokens: b.bytesBurst, last: t } };
      this.sendState.set(peerId, st);
    }
    return st;
  }

  /**
   * 利用者の新しい要求 (TUNNEL_SEND) を受け付けてよいか (C4)。バックボーンの相手は従来の枠 (admit)。
   * 件数 → 同時数 → 全体の上限 → 帯域 → 1 日の上限 の順に見て、通ったときだけ帯域と 1 日の使用量を引く
   * (断られた要求に帯域を払わせない)。
   */
  private admitSend(peerId: PeerId, bodyBytes: number): boolean {
    if (this.isBackbone(peerId)) return this.admit(peerId, bodyBytes, this.countUp(peerId));
    const b = this.cfg.clientSend;
    const st = this.sendStateOf(peerId);
    if (!this.take(st.req, 1, b.reqPerSec, b.reqBurst)) {
      this.stats.dropped.rate++;
      return false;
    }
    if (this.countUp(peerId) >= b.concurrent) {
      this.stats.dropped.concurrent++;
      return false;
    }
    if (this.routeCount >= this.cfg.maxRoutes) {
      this.stats.dropped.full++;
      return false;
    }
    const day = Math.floor(this.now() / DAY_MS);
    let d = this.daily.get(peerId);
    if (!d || d.day !== day) {
      d = { day, used: 0 };
      this.daily.delete(peerId);
      this.daily.set(peerId, d); // 末尾へ (古い順に捨てるため)
      while (this.daily.size > TUNNEL_LIMITS.MAX_DAILY_ENTRIES) {
        const oldest = this.daily.keys().next().value;
        if (oldest === undefined) break;
        this.daily.delete(oldest);
      }
    }
    if (d.used + bodyBytes > b.bytesPerDay) {
      this.stats.dropped.daily++;
      return false;
    }
    if (!this.take(st.bytes, bodyBytes, b.bytesPerSec, b.bytesBurst)) {
      this.stats.dropped.bytes++;
      return false;
    }
    d.used += bodyBytes;
    return true;
  }

  private countDown(prevHop: PeerId): number {
    let n = 0;
    for (const r of this.down.values()) if (r.prevHop === prevHop) n++;
    return n;
  }

  // ── 送信の道具 ──

  private send(peerId: PeerId, type: WireType, payload: any): void {
    this.peerManager.sendMessage(peerId, type, payload);
  }

  private sendError(peerId: PeerId, id: number, code: number): void {
    this.send(peerId, WireType.TUNNEL_ERROR, { id, code });
  }

  private newTag(table: Map<number, unknown>): number {
    for (let i = 0; i < 16; i++) {
      const tag = sodium.randombytes_random() >>> 0;
      if (tag !== 0 && !table.has(tag)) return tag;
    }
    return 0;
  }

  private isUsable(peerId: PeerId): boolean {
    const p = this.peerManager.peers.get(peerId);
    return !!p && p.isConnected && p.isVerified;
  }

  // ── 登録 (H → 受け口の Guard) ──

  private handleRegister(from: PeerId, msg: any): void {
    if (this.destroyed) return;
    const tunnelId: unknown = msg?.tunnelId;
    if (!(tunnelId instanceof Uint8Array) || tunnelId.length !== 8) return;
    let bucket = this.registerBuckets.get(from);
    if (!bucket) {
      bucket = { tokens: TUNNEL_LIMITS.REGISTER.burst, last: this.now() };
      this.registerBuckets.set(from, bucket);
    }
    if (!this.take(bucket, 1, TUNNEL_LIMITS.REGISTER.perSec, TUNNEL_LIMITS.REGISTER.burst)) {
      this.stats.dropped.rate++;
      return;
    }
    const hex = Encoding.toHex(tunnelId);
    const reply = (ok: boolean) => this.send(from, WireType.TUNNEL_REGISTERED, { tunnelId, ok });
    const owner = this.tunnels.get(hex);
    if (owner === from) return reply(true); // 再登録 (冪等)
    // ★ 先着: 生きている別の接続が持っている tunnelId は奪わせない。leaseSet は全員に見えるので、tunnelId 自体は秘密ではない
    //   (奪われても本体は H の鍵で封印されているので読めないが、要求を握りつぶされる)。
    if (owner !== undefined && this.isUsable(owner)) return reply(false);
    const mine = this.tunnelsByPeer.get(from) ?? new Set<string>();
    if (mine.size >= this.cfg.maxTunnelsPerPeer) return reply(false);
    if (this.tunnels.size >= this.cfg.maxTunnels) return reply(false);
    if (owner !== undefined) this.tunnelsByPeer.get(owner)?.delete(hex);
    this.tunnels.set(hex, from);
    mine.add(hex);
    this.tunnelsByPeer.set(from, mine);
    reply(true);
  }

  // ── G_R の役: R からの要求 ──

  private handleSend(from: PeerId, msg: any): void {
    if (this.destroyed) return;
    const { reqId, gateway, tunnelId, body } = msg ?? {};
    if (!Number.isInteger(reqId) || typeof gateway !== 'string' || !(tunnelId instanceof Uint8Array) || !(body instanceof Uint8Array)) return;
    if (!this.admitSend(from, body.length)) {
      this.sendError(from, reqId, TUNNEL_ERROR_CODE.BUSY);
      return;
    }
    const direct = gateway === this.peerManager.myPeerId;
    const tag = this.newTag(this.up);
    if (tag === 0) {
      this.sendError(from, reqId, TUNNEL_ERROR_CODE.BUSY);
      return;
    }
    const route: UpRoute = { tag, client: from, reqId, via: direct ? SELF : gateway, lastAt: this.now() };
    this.addUp(route);
    this.stats.forwarded.requests++;

    if (direct) {
      this.deliverToHolder(SELF, tag, tunnelId, body);
      return;
    }
    if (this.isUsable(gateway)) {
      this.send(gateway, WireType.TUNNEL_FWD, { returnTag: tag, tunnelId, body });
      return;
    }
    this.queueDial(gateway, { tag, tunnelId, body });
  }

  // ── ダイヤル (受け口へまだつながっていないとき) ──

  private queueDial(gateway: PeerId, item: { tag: number; tunnelId: Uint8Array; body: Uint8Array }): void {
    const fail = (code: number) => this.failUp(item.tag, code);
    const cool = this.dialCooldown.get(gateway);
    if (cool !== undefined && this.now() < cool) {
      this.stats.dropped.noRoute++;
      return fail(TUNNEL_ERROR_CODE.NO_ROUTE);
    }
    let pending = this.pendingDial.get(gateway);
    if (!pending) {
      if (this.pendingDial.size >= TUNNEL_LIMITS.DIAL.MAX_GATEWAYS) return fail(TUNNEL_ERROR_CODE.BUSY);
      const b = (this.dialBucket ??= { tokens: TUNNEL_LIMITS.DIAL.burst, last: this.now() });
      if (!this.take(b, 1, TUNNEL_LIMITS.DIAL.perSec, TUNNEL_LIMITS.DIAL.burst)) return fail(TUNNEL_ERROR_CODE.BUSY);
      pending = {
        startedAt: this.now(),
        items: [],
        timer: setTimeout(() => this.dialTimedOut(gateway), this.cfg.dialTimeoutMs),
      };
      this.pendingDial.set(gateway, pending);
      this.stats.dialed++;
      log.debug(() => `dialing gateway ${gateway.substring(0, 8)}`);
      try {
        this.dial(gateway);
      } catch (e) {
        log.warn('dial failed', e);
      }
    }
    if (pending.items.length >= TUNNEL_LIMITS.DIAL.MAX_PENDING_PER_GATEWAY) return fail(TUNNEL_ERROR_CODE.BUSY);
    pending.items.push(item);
  }

  private flushDial(gateway: PeerId | undefined): void {
    if (!gateway) return;
    const pending = this.pendingDial.get(gateway);
    if (!pending) return;
    clearTimeout(pending.timer);
    this.pendingDial.delete(gateway);
    this.dialCooldown.delete(gateway);
    for (const it of pending.items) {
      if (!this.up.has(it.tag)) continue; // その間に利用者が切れた
      this.send(gateway, WireType.TUNNEL_FWD, { returnTag: it.tag, tunnelId: it.tunnelId, body: it.body });
    }
  }

  private dialTimedOut(gateway: PeerId): void {
    const pending = this.pendingDial.get(gateway);
    if (!pending) return;
    this.pendingDial.delete(gateway);
    this.dialCooldown.set(gateway, this.now() + TUNNEL_LIMITS.DIAL.COOLDOWN_MS);
    for (const it of pending.items) this.failUp(it.tag, TUNNEL_ERROR_CODE.NO_ROUTE);
  }

  /** G_R の経路を閉じて、利用者へ ERROR を返す */
  private failUp(tag: number, code: number): void {
    const r = this.removeUp(tag);
    if (!r) return;
    this.sendError(r.client, r.reqId, code);
  }

  // ── G_h の役: 転送されてきた要求を保持者へ ──

  private handleFwd(from: PeerId, msg: any): void {
    if (this.destroyed) return;
    const { returnTag, tunnelId, body } = msg ?? {};
    if (!Number.isInteger(returnTag) || !(tunnelId instanceof Uint8Array) || !(body instanceof Uint8Array)) return;
    if (!this.admit(from, body.length, this.countDown(from))) {
      this.sendError(from, returnTag, TUNNEL_ERROR_CODE.BUSY);
      return;
    }
    this.deliverToHolder(from, returnTag, tunnelId, body);
  }

  /** prevHop = G_R (または SELF)。prevTag はその相手が振ったタグ */
  private deliverToHolder(prevHop: PeerId, prevTag: number, tunnelId: Uint8Array, body: Uint8Array): void {
    const answerNoRoute = (code: number) => {
      if (prevHop === SELF) this.failUp(prevTag, code);
      else this.sendError(prevHop, prevTag, code);
    };
    const dupKey = `${prevHop}:${prevTag}`;
    if (this.downByPrev.has(dupKey)) {
      this.stats.dropped.duplicate++;
      return;
    }
    const holder = this.tunnels.get(Encoding.toHex(tunnelId));
    if (holder === undefined || !this.isUsable(holder)) {
      this.stats.dropped.noTunnel++;
      return answerNoRoute(TUNNEL_ERROR_CODE.NO_TUNNEL);
    }
    const tag = this.newTag(this.down);
    if (tag === 0) return answerNoRoute(TUNNEL_ERROR_CODE.BUSY);
    this.down.set(tag, { tag, prevHop, prevTag, holder, lastAt: this.now() });
    this.downByPrev.set(dupKey, tag);
    this.stats.forwarded.requests++;
    this.send(holder, WireType.TUNNEL_DELIVER, {
      returnTag: tag,
      fromHop: prevHop === SELF ? this.peerManager.myPeerId : prevHop,
      body,
    });
  }

  // ── 応答 ──

  /** H → G_h */
  private handleReply(from: PeerId, msg: any): void {
    if (this.destroyed) return;
    const { returnTag, toHop, seq, final, body } = msg ?? {};
    if (!Number.isInteger(returnTag) || !(body instanceof Uint8Array)) return;
    const r = this.down.get(returnTag);
    if (!r) {
      this.stats.dropped.unknownRoute++;
      return;
    }
    // ★ 経路に紐づいた保持者の接続からだけ受け付ける。toHop は DELIVER で渡した fromHop の折り返しで、食い違えば捨てる
    const expectedTo = r.prevHop === SELF ? this.peerManager.myPeerId : r.prevHop;
    if (r.holder !== from || toHop !== expectedTo) {
      this.stats.dropped.wrongPeer++;
      return;
    }
    if (!this.chargeBytes(from, body.length)) return;
    r.lastAt = this.now();
    this.stats.forwarded.chunks++;
    this.stats.forwarded.bytes += body.length;
    if (r.prevHop === SELF) this.routeBack(r.prevTag, seq, final, body);
    else this.send(r.prevHop, WireType.TUNNEL_RET, { returnTag: r.prevTag, seq, final, body });
    if (final) this.dropDown(r);
  }

  /** G_h → G_R */
  private handleRet(from: PeerId, msg: any): void {
    if (this.destroyed) return;
    const { returnTag, seq, final, body } = msg ?? {};
    if (!Number.isInteger(returnTag) || !(body instanceof Uint8Array)) return;
    const r = this.up.get(returnTag);
    if (!r) {
      this.stats.dropped.unknownRoute++;
      return;
    }
    if (r.via !== from) {
      this.stats.dropped.wrongPeer++;
      return;
    }
    if (!this.chargeBytes(from, body.length)) return;
    this.routeBack(returnTag, seq, final, body);
  }

  /** G_R の経路 tag の利用者へ、応答の 1 片を返す */
  private routeBack(tag: number, seq: number, final: boolean, body: Uint8Array): void {
    const r = this.up.get(tag);
    if (!r) return;
    r.lastAt = this.now();
    this.send(r.client, WireType.TUNNEL_RESULT, { reqId: r.reqId, seq, final, body });
    if (final) this.removeUp(tag);
  }

  /** 保持者の ERROR (G_h の役) または受け口の ERROR (G_R の役) */
  private handleError(from: PeerId, msg: any): void {
    if (this.destroyed) return;
    const { id, code } = msg ?? {};
    if (!Number.isInteger(id) || !Number.isInteger(code)) return;
    const u = this.up.get(id);
    if (u && u.via === from) {
      this.removeUp(id);
      this.sendError(u.client, u.reqId, code);
      return;
    }
    const d = this.down.get(id);
    if (d && d.holder === from) {
      this.dropDown(d);
      if (d.prevHop === SELF) this.failUp(d.prevTag, code);
      else this.sendError(d.prevHop, d.prevTag, code);
    }
  }

  private dropDown(r: DownRoute): void {
    this.down.delete(r.tag);
    this.downByPrev.delete(`${r.prevHop}:${r.prevTag}`);
  }

  // ── 掃除・切断 ──

  /**
   * 無通信の経路を捨てる。上流 (利用者・前のホップ) には TIMEOUT を返す。
   * ★ 状態を持ち続けない (60 秒): 応答が来ない要求がいつまでも枠を握らないように。
   */
  public sweep(nowMs: number = this.now()): number {
    const horizon = nowMs - this.cfg.idleMs;
    let n = 0;
    for (const r of Array.from(this.up.values())) {
      if (r.lastAt > horizon) continue;
      this.failUp(r.tag, TUNNEL_ERROR_CODE.TIMEOUT);
      n++;
    }
    for (const r of Array.from(this.down.values())) {
      if (r.lastAt > horizon) continue;
      this.dropDown(r);
      if (r.prevHop !== SELF) this.sendError(r.prevHop, r.prevTag, TUNNEL_ERROR_CODE.TIMEOUT);
      n++;
    }
    for (const [id, until] of this.dialCooldown) if (until <= nowMs) this.dialCooldown.delete(id);
    // 掃除のついでに、もう居ない相手の制限の状態も捨てる
    for (const id of Array.from(this.peerState.keys())) if (!this.peerManager.peers.has(id)) this.peerState.delete(id);
    for (const id of Array.from(this.registerBuckets.keys())) if (!this.peerManager.peers.has(id)) this.registerBuckets.delete(id);
    // 利用者の上り枠は、補充が満タンに戻る時間 (バースト ÷ 補充の速さ = 64 秒の倍) 触られていなければ捨てる
    for (const [id, st] of Array.from(this.sendState)) {
      if (nowMs - Math.max(st.req.last, st.bytes.last) > 120_000) this.sendState.delete(id);
    }
    // 1 日の使用量は、日が変わったものだけ捨てる (切断しても覚えておくため)
    const today = Math.floor(nowMs / DAY_MS);
    for (const [id, d] of Array.from(this.daily)) if (d.day !== today) this.daily.delete(id);
    return n;
  }

  private forgetPeer(peerId: PeerId): void {
    for (const hex of this.tunnelsByPeer.get(peerId) ?? []) {
      if (this.tunnels.get(hex) === peerId) this.tunnels.delete(hex);
    }
    this.tunnelsByPeer.delete(peerId);
    this.peerState.delete(peerId);
    // ★ sendState (利用者の上り枠) は切断しても消さない: 切って張り直すたびにバースト (64MiB) が戻る穴になる。掃除が時間で捨てる
    this.registerBuckets.delete(peerId);
    for (const r of Array.from(this.up.values())) {
      if (r.client === peerId) this.removeUp(r.tag); // 利用者が居ない: 返す先が無い
      else if (r.via === peerId) this.failUp(r.tag, TUNNEL_ERROR_CODE.NO_ROUTE);
    }
    for (const r of Array.from(this.down.values())) {
      if (r.prevHop === peerId) this.dropDown(r);
      else if (r.holder === peerId) {
        this.dropDown(r);
        if (r.prevHop === SELF) this.failUp(r.prevTag, TUNNEL_ERROR_CODE.NO_TUNNEL);
        else this.sendError(r.prevHop, r.prevTag, TUNNEL_ERROR_CODE.NO_TUNNEL);
      }
    }
  }

  public destroy(): void {
    this.destroyed = true;
    if (this.sweepTimer) clearInterval(this.sweepTimer);
    this.sweepTimer = null;
    for (const p of this.pendingDial.values()) clearTimeout(p.timer);
    this.pendingDial.clear();
    this.up.clear();
    this.upCount.clear();
    this.sendState.clear();
    this.daily.clear();
    this.down.clear();
    this.downByPrev.clear();
    this.tunnels.clear();
    this.tunnelsByPeer.clear();
    this.peerManager.off('peer:verified', this.onVerified);
    this.peerManager.off('peer:disconnect', this.onDisconnect);
  }
}

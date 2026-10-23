import type { GossipPacket, IMessageDispatcher, IPeerManager, PeerId } from '../../types';
import type { DandelionRouter } from '../gossip/DandelionRouter';
import type { GossipRouter } from '../gossip/GossipRouter';
import { PacketValidator } from '../gossip/PacketValidator';
import { decodePacket } from '../../crypto/PacketCodec';
import { MINUTE_MS, minutesToMs, msToMinutes } from '../../crypto/PowPolicy';
import { WireType } from '../wire/WireTypes';
import { CATCHUP_STATUS } from '../wire/WireCodec';
import { CATCHUP_MAX_PAST_MS } from './RecentBuffer';
import { createLogger } from '../../common/Logger';

const log = createLogger('net.catchup.client');

/** lastSeen を保存する kv の名前 (暗号化 DB の中。平文には出ない) */
export const CATCHUP_LAST_SEEN_KEY = 'catchup.lastSeen';

/** 要求の since は lastSeen よりこれだけ戻す (遅れて届いた分・時計のずれの取りこぼしを防ぐ重なり) */
export const CATCHUP_OVERLAP_MS = 5 * MINUTE_MS;

const CLIENT_LIMITS = {
  /** 何も届かないまま待つ上限。超えたらこの回は諦める */
  INACTIVITY_MS: 60_000,
  /** BUSY / 中断のあとの再試行までの間隔 (回数が増えると倍) */
  RETRY_BASE_MS: 15_000,
  RETRY_MAX_MS: 5 * 60_000,
  /** 1 回で受け取るバイト数の上限 (Guard の保持の上限 256MiB に余裕を足した値)。超えたら打ち切る */
  MAX_SESSION_BYTES: 300 * 1024 * 1024,
  /** lastSeen を暗号化 DB に書く間隔 (投稿のたびには書かない) */
  PERSIST_DELAY_MS: 10_000,
} as const;

/** 画面 (オーケストレータ) が「過去ログを取得中か」を知るための窓口 */
export interface CatchupProgress {
  /** 追いつきの受信中か */
  readonly active: boolean;
  /** active が変わったときの通知。戻り値は購読解除 */
  onChange(cb: () => void): () => void;
}

export interface CatchupStore {
  get(name: string): Promise<unknown>;
  set(name: string, value: unknown): Promise<void>;
}

export interface CatchupClientOptions {
  /** テスト用の時計 */
  now?: () => number;
}

interface Active {
  peerId: PeerId;
  bytes: number;
  timer: ReturnType<typeof setTimeout> | null;
}

/**
 * CatchupClient — 1 ホップ目 (固定した Guard) につながったら、取り逃した投稿を頼む (history v2 §3)。
 *
 *   since = lastSeen − 5 分 を CATCHUP_REQ で送る → CATCHUP_DATA (古い順) → CATCHUP_END
 *
 * ★ いつ送るか: 固定した Guard (DandelionRouter.getPinnedGuardId。警告状態・一般ノードのときもその 1 ホップ目) が
 *   **検証済み** (peer:verified = HELLO/JOIN 完了) になったとき、または固定した Guard が替わったとき。
 *   peer:connect は握手の前に出るので使わない (握手前は相手が受け付けない)。
 *   Guard が切れたら印を消し、つなぎ直したらもう一度送る。
 * ★ lastSeen = 受け取った最新の投稿の時刻 (**分単位**)。暗号化 DB の中だけに置く。日に丸めてはいけない
 *   (丸めると毎回最大 1 日分を取り直す)。分単位の「最後に見た時刻」は押収された端末では
 *   接続の記録と同じ程度の情報だが、鍵を持たない者には読めない。
 * ★ lastSeen を進めてよいのは次のときだけ:
 *     - 追いつきで届いた投稿 (古い順に来るので、途中で切れてもそこから再開できる)
 *     - 追いつきが完了した後に届いた live の投稿
 *     - CATCHUP_END の nextSince (ここまで送ったという Guard の申告。自分の時計を超えない)
 *   追いつきが済んでいないうちに live の投稿で進めると、その間の取り逃しが永久に取り戻せなくなる。
 *   (オフラインから戻った直後は、先に一般の隣人から live の投稿が届くことがある。)
 * ★ 届いた投稿は live と同じ検証 (PacketValidator) を通す。違いは時刻の検査だけで、過去は 72 時間 + 15 分まで。
 *   通ったものは GossipRouter.deliverCatchup で手元に配る (flood しない)。通らないものは捨てる。
 * ★ 頼んだ Guard 以外から来た CATCHUP_DATA は無視する (頼んでいない相手が古い投稿を押し込めない)。
 */
export class CatchupClient implements CatchupProgress {
  private lastSeenMin: number | null = null;
  private dirty = false;
  private persistTimer: ReturnType<typeof setTimeout> | null = null;
  private persisting: Promise<void> = Promise.resolve();

  private active_: Active | null = null;
  /** 追いつきが完了した Guard (切れるまで再度は送らない) */
  private doneFor: PeerId | null = null;
  /** 完了済み (live の投稿で lastSeen を進めてよい) */
  private caughtUp = false;
  private liveMaxWhileActive = 0;
  private retryTimer: ReturnType<typeof setTimeout> | null = null;
  private retries = 0;
  private inited = false;
  private destroyed = false;
  private changeListeners = new Set<() => void>();
  private readonly now: () => number;

  private readonly onVerified = (peer: { peerId: PeerId }) => {
    if (peer?.peerId === this.dandelion.getPinnedGuardId()) this.maybeStart();
  };
  private readonly onDisconnect = (peerId: PeerId) => {
    if (this.active_?.peerId === peerId) this.abort('guard disconnected');
    if (this.doneFor === peerId) {
      this.doneFor = null;
      this.caughtUp = false;
    }
  };
  private readonly onGuardChange = (guard: PeerId | null) => {
    // 別の Guard になった。前の Guard で済ませた追いつきは当てにしない
    if (this.active_ && this.active_.peerId !== guard) this.abort('guard changed');
    if (this.doneFor !== guard) {
      this.doneFor = null;
      this.caughtUp = false;
    }
    if (guard) this.maybeStart();
  };

  constructor(
    private peerManager: IPeerManager,
    dispatcher: IMessageDispatcher,
    private dandelion: DandelionRouter,
    private router: GossipRouter,
    private store: CatchupStore,
    options: CatchupClientOptions = {},
  ) {
    this.now = options.now ?? Date.now;
    dispatcher.register(WireType.CATCHUP_DATA, (peerId, msg) => this.handleData(peerId, msg));
    dispatcher.register(WireType.CATCHUP_END, (peerId, msg) => this.handleEnd(peerId, msg));
    peerManager.on('peer:verified', this.onVerified);
    peerManager.on('peer:disconnect', this.onDisconnect);
    dandelion.onGuardChange(this.onGuardChange);
    router.onStoredCandidate((packet, source) => this.noteAccepted(packet, source));
  }

  /** 保存済みの lastSeen を読む。起動時に 1 回 (読み終わるまで要求は出さない) */
  public async init(): Promise<void> {
    try {
      const v = await this.store.get(CATCHUP_LAST_SEEN_KEY);
      if (typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= 0xffffff) this.lastSeenMin = v;
    } catch {
      // 読めなければ「何も見ていない」として扱う (全部取り直すだけ)
    }
    this.inited = true;
    this.maybeStart();
  }

  public get active(): boolean {
    return this.active_ !== null;
  }

  /** 最後に見た投稿の時刻 (OZ_EPOCH からの分)。無ければ null (診断・テスト用) */
  public get lastSeen(): number | null {
    return this.lastSeenMin;
  }

  public onChange(cb: () => void): () => void {
    this.changeListeners.add(cb);
    return () => { this.changeListeners.delete(cb); };
  }

  private fireChange(): void {
    this.changeListeners.forEach(cb => {
      try { cb(); } catch (e) { log.warn('catch-up listener failed', e); }
    });
  }

  // ── 要求を出す ──

  private maybeStart(): void {
    if (!this.inited || this.destroyed) return;
    const id = this.dandelion.getPinnedGuardId();
    if (!id || this.active_ || this.doneFor === id) return;
    const peer = this.peerManager.peers.get(id);
    if (!peer || !peer.isConnected || !peer.isVerified) return;

    // 何も見ていない端末 (初回・新しい端末) は since = 0: Guard が持っている分を全部返す (status は partial)
    const since = this.lastSeenMin === null ? 0 : Math.max(0, this.lastSeenMin - CATCHUP_OVERLAP_MS / MINUTE_MS);
    this.active_ = { peerId: id, bytes: 0, timer: null };
    this.liveMaxWhileActive = 0;
    this.armInactivity();
    this.fireChange();
    log.debug(() => `catch-up request to ${id.substring(0, 8)} since=${since}`);
    this.peerManager.sendMessage(id, WireType.CATCHUP_REQ, { since });
  }

  private armInactivity(): void {
    const a = this.active_;
    if (!a) return;
    if (a.timer) clearTimeout(a.timer);
    a.timer = setTimeout(() => this.abort('inactivity'), CLIENT_LIMITS.INACTIVITY_MS);
  }

  private abort(reason: string): void {
    const a = this.active_;
    if (!a) return;
    if (a.timer) clearTimeout(a.timer);
    this.active_ = null;
    this.caughtUp = false;
    this.liveMaxWhileActive = 0;
    log.debug(() => `catch-up aborted: ${reason}`);
    this.fireChange();
    this.scheduleRetry();
  }

  private scheduleRetry(): void {
    if (this.destroyed || this.retryTimer) return;
    const delay = Math.min(CLIENT_LIMITS.RETRY_BASE_MS * 2 ** this.retries, CLIENT_LIMITS.RETRY_MAX_MS);
    this.retries++;
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null;
      this.maybeStart();
    }, delay);
  }

  // ── 受け取る ──

  private handleData(senderId: PeerId, msg: any): void {
    const a = this.active_;
    if (!a || a.peerId !== senderId) return; // 頼んでいない相手からは受け取らない
    const packets: unknown = msg?.packets;
    if (!Array.isArray(packets)) return;
    this.armInactivity();

    const now = this.now();
    let rejected = 0;
    for (const bytes of packets) {
      if (!(bytes instanceof Uint8Array)) continue;
      a.bytes += bytes.length;
      const packet = decodePacket(bytes);
      if (!packet) { rejected++; continue; }
      // ★ live と同じ検証。時刻の過去側だけ 72 時間 + 15 分まで緩める (未来側・PoW・packet_id は同じ)
      const res = PacketValidator.check(packet, { now, maxPastMs: CATCHUP_MAX_PAST_MS });
      if (!res.ok) { rejected++; continue; }
      this.router.deliverCatchup(packet);
      // 重複 (既に持っていた) でも、見たことには変わりない。古い順に来るので lastSeen は単調に進む
      this.advance(packet.timestamp, now);
    }
    if (rejected > 0) log.debug(() => `catch-up: rejected ${rejected} invalid packet(s)`);
    if (a.bytes > CLIENT_LIMITS.MAX_SESSION_BYTES) this.abort('too much data');
  }

  private handleEnd(senderId: PeerId, msg: any): void {
    const a = this.active_;
    if (!a || a.peerId !== senderId) return;
    const status = msg?.status;
    const nextSince = msg?.nextSince;
    if (a.timer) clearTimeout(a.timer);
    this.active_ = null;

    if (status === CATCHUP_STATUS.BUSY) {
      // 送ってもらえなかった。あとでもう一度
      this.liveMaxWhileActive = 0;
      this.fireChange();
      this.scheduleRetry();
      return;
    }
    if (status !== CATCHUP_STATUS.OK && status !== CATCHUP_STATUS.PARTIAL) {
      this.liveMaxWhileActive = 0;
      this.fireChange();
      this.scheduleRetry();
      return;
    }

    // 完了。ここから先の live の投稿は取り逃しなく届いている (相手につながっているので)
    this.retries = 0;
    this.doneFor = senderId;
    this.caughtUp = true;
    const now = this.now();
    if (Number.isInteger(nextSince) && nextSince >= 0 && nextSince <= 0xffffff) {
      this.advance(minutesToMs(nextSince), now);
    }
    if (this.liveMaxWhileActive > 0) this.advance(this.liveMaxWhileActive, now);
    this.liveMaxWhileActive = 0;
    log.debug(() => `catch-up done (${status === CATCHUP_STATUS.PARTIAL ? 'partial' : 'ok'})`);
    this.fireChange();
  }

  /** 投稿を新しく手にしたとき (live・自分の発信・追いつき) */
  private noteAccepted(packet: GossipPacket, source: 'live' | 'catchup' | 'self' | 'fetch'): void {
    if (source === 'catchup') return; // handleData が古い順に進める
    if (source === 'fetch') return; // 保管担当から取った過去ログ。lastSeen (追いつきの起点) は動かさない
    const now = this.now();
    if (this.active_) {
      // 追いつきの途中。ここで進めると、まだ届いていない古い分を飛ばす。終わってから反映する
      this.liveMaxWhileActive = Math.max(this.liveMaxWhileActive, Math.min(packet.timestamp, now));
      return;
    }
    if (!this.caughtUp) return; // 追いつきが済んでいない (Guard 未接続など)。進めない
    this.advance(packet.timestamp, now);
  }

  /** lastSeen を進める (戻さない。自分の時計より先へは進めない) */
  private advance(timestampMs: number, now: number): void {
    let min: number;
    try {
      min = msToMinutes(Math.min(timestampMs, now));
    } catch {
      return;
    }
    if (this.lastSeenMin !== null && min <= this.lastSeenMin) return;
    this.lastSeenMin = min;
    this.dirty = true;
    this.schedulePersist();
  }

  // ── 保存 ──

  private schedulePersist(): void {
    if (this.persistTimer || this.destroyed) return;
    this.persistTimer = setTimeout(() => {
      this.persistTimer = null;
      void this.flush();
    }, CLIENT_LIMITS.PERSIST_DELAY_MS);
  }

  /** 保存待ちの lastSeen を今すぐ書く。停止前に待つこと */
  public async flush(): Promise<void> {
    if (this.persistTimer) {
      clearTimeout(this.persistTimer);
      this.persistTimer = null;
    }
    this.persisting = this.persisting.then(async () => {
      if (!this.dirty || this.lastSeenMin === null) return;
      this.dirty = false;
      try {
        await this.store.set(CATCHUP_LAST_SEEN_KEY, this.lastSeenMin);
      } catch (e) {
        this.dirty = true;
        log.warn('could not persist lastSeen', e);
      }
    });
    await this.persisting;
  }

  /** タイマーと購読を止める。保存は flush() で済ませてから呼ぶ */
  public destroy(): void {
    this.destroyed = true;
    if (this.active_?.timer) clearTimeout(this.active_.timer);
    this.active_ = null;
    if (this.persistTimer) clearTimeout(this.persistTimer);
    this.persistTimer = null;
    if (this.retryTimer) clearTimeout(this.retryTimer);
    this.retryTimer = null;
    this.peerManager.off('peer:verified', this.onVerified);
    this.peerManager.off('peer:disconnect', this.onDisconnect);
    this.changeListeners.clear();
  }
}

import type { IndexedDBStore } from '../storage/IndexedDBStore';
import type { GossipRouter } from '../network/gossip/GossipRouter';
import type { CatchupProgress } from '../network/history/CatchupClient';
import type { HistoryFetcher } from '../network/history/HistoryClient';
import { HistorySession, type HistoryJob } from './HistorySession';
import { boardTag, dayOf, mondayOf } from '../crypto/PacketTag';
import type { CryptoEngine } from '../crypto/CryptoEngine';
import type { Identity } from '../crypto/Identity';
import type { IPeerManager, IPoWEngine } from '../types';
import type { ThreadMeta } from './types';
import { PacketBuilder } from '../crypto/PacketBuilder';
import { MINUTE_MS, estimateSolveMs, msToMinutes } from '../crypto/PowPolicy';
import { CONGESTION_NOTICE, SLOW_POW_NOTICE_MS } from './PowNotice';
import { encodePacket, decodePacket } from '../crypto/PacketCodec';
import { assertPostLimits } from '../crypto/PostCodec';
import { THREAD_LIMITS, THREAD_ID_RANDOM_CHARS, makeThreadId, threadBirthFromId, isThreadMetaTimeConsistent } from './ThreadLimits';
import { BOARD_META_THREAD_ID, BoardStatus } from './types';
import { createLogger } from '../common/Logger';
import { CryptoUtils } from '../common/CryptoUtils';

const log = createLogger('logic.board');



/**
 * BoardOrchestrator
 * 管理対象の「板」のスレッド一覧の取得、同期、投稿、およびメモリ保持を統括する。
 */
export class BoardOrchestrator {
  private listeners: Set<() => void> = new Set();
  private statusListeners: Set<() => void> = new Set();
  private threads: Map<string, ThreadMeta> = new Map();
  /**
   * useSyncExternalStore に渡すスナップショット。
   *
   * getSnapshot は「データが変わらない限り同じ参照」を返さなければならない
   * (返さないと React が無限ループを検出して例外を投げる)。
   * よって notify() のタイミングでだけ作り直し、それ以外では使い回す。
   */
  private snapshot: ThreadMeta[] = [];
  private seenPacketIds: Set<string> = new Set();
  private currentStatus: BoardStatus = { phase: 'idle', message: '' };
  private statsTimer: any = null;

  private currentBoardId: string | null = null;
  private currentBoardKey: Uint8Array | null = null;
  private isListening: boolean = false;
  /** 実行中の fullSync。多重起動を防ぐ */
  private syncInFlight: Promise<void> | null = null;
  private syncDebounce: any = null;
  /**
   * 隣人が居る状態でこれだけ待ってから「1 件も無い」と判定する。
   * 過去ログ (Guard からの追いつき) は、1 ホップ目の Guard が決まって握手が済んでから
   * 非同期に届くので、即断すると必ず「無い」と出る。
   */
  private static readonly EMPTY_VERDICT_GRACE_MS = 8000;
  /** 現在の活性化で最初に隣人が現れた時刻 */
  private firstPeerAt: number | null = null;
  private emptyVerdictTimer: any = null;




  private unsubCatchup: (() => void) | null = null;
  /** 保管担当からの過去ログの取得 (開いたとき 1 回と、1 ホップ目の再接続のとき) */
  private historySession: HistorySession;

  /** 板のスレ立て (週単位のバケット) を何週間前まで取るか。スレの寿命 (90 日) を覆う */
  public static readonly HISTORY_WEEKS = 13;
  /** 週別の取得の同時数 */
  public static readonly HISTORY_CONCURRENCY = 3;

  constructor(
    private pm: IPeerManager,
    private db: IndexedDBStore,
    private router: GossipRouter,
    private cryptoEng: CryptoEngine,
    private powEng: IPoWEngine,
    private identity: Identity,
    /**
     * Guard からの追いつきの進み具合。受信中は「無い」と断定しない。
     * 省略可 (単体テスト用)。本番 (OzNode) は必ず渡す。
     */
    private catchup: CatchupProgress | null = null,
    /**
     * 保管担当から取る窓口 (72 時間より古い分)。省略可 (単体テスト用)。本番 (OzNode) は必ず渡す。
     * 板を開いたとき、手元の DB を読んだあとに裏で取る (画面は待たない)。
     */
    history: HistoryFetcher | null = null,
  ) {
    this.historySession = new HistorySession(history, () => this.refreshEmptyStatus());
  }

  /**
   * 変更通知を購読する。
   *
   * useSyncExternalStore の subscribe としてそのまま渡せるよう、
   * 「購読解除関数を返すだけ」に徹する。以前はここで即座に listener を
   * 呼んでいたが、それは useSyncExternalStore の契約に反する
   * (初期値は getSnapshot が返す)。
   */
  public subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => { this.listeners.delete(listener); };
  }

  public subscribeStatus(listener: () => void): () => void {
    this.statusListeners.add(listener);
    return () => { this.statusListeners.delete(listener); };
  }

  /** useSyncExternalStore の getSnapshot。キャッシュ済みの参照を返す。 */
  public getThreads(): ThreadMeta[] {
    return this.snapshot;
  }

  public getStatus(): BoardStatus {
    return this.currentStatus;
  }

  private updateStatus(phase: BoardStatus['phase'], message: string, isSubmitting: boolean = false, powProgress: number = 0) {
    const cur = this.currentStatus;
    // 同じ内容なら通知しない。空判定の再評価は頻繁に走るので、
    // ここで畳まないと無意味な再描画が積み上がる。
    if (cur.phase === phase && cur.message === message &&
        (cur.isSubmitting ?? false) === isSubmitting && (cur.powProgress ?? 0) === powProgress) {
      return;
    }
    this.currentStatus = { phase, message, isSubmitting, powProgress };
    this.statusListeners.forEach(l => l());
  }

  /**
   * 「スレッドが 1 件も無い」と表示してよいかを判定する。
   *
   * ★ 即断してはいけない。
   *
   *   過去ログは**非同期にしか届かない**: 手元の DB を読んだあと、1 ホップ目の Guard が決まって
   *   握手が済むと追いつき (CatchupClient) が始まり、数秒〜数分かけて届く。
   *   繋がった直後に同期的に `threads.size === 0` を見て「見つかりませんでした」と断定すると、
   *   必ず「無い」と表示され、その後スレッドが届いても文言が残って一覧と食い違う。
   *
   *   追いつきの受信中は「無い」と言わない。隣人が居る状態で猶予を過ぎ、かつ追いつきが
   *   受信中でなければ「無い」と言う。新しい隣人が増えたら (新しい Guard かもしれない) 猶予を引き直す。
   */
  private refreshEmptyStatus(): void {
    // 投稿中の表示は壊さない
    if (this.currentStatus.isSubmitting) return;

    if (this.emptyVerdictTimer) {
      clearTimeout(this.emptyVerdictTimer);
      this.emptyVerdictTimer = null;
    }

    // 保管担当から過去ログを取っている間は、その旨を出す (スレが届いても、取り終わるまで残す)
    if (this.historySession.active && this.pm.degree > 0) {
      this.updateStatus('syncing', this.historySession.message());
      return;
    }

    if (this.threads.size > 0) {
      this.updateStatus('idle', '');
      return;
    }

    if (this.pm.degree === 0) {
      this.firstPeerAt = null;
      this.updateStatus('loading', '隣人を探しています (接続中)...');
      return;
    }

    if (this.firstPeerAt === null) this.firstPeerAt = Date.now();
    const remaining = BoardOrchestrator.EMPTY_VERDICT_GRACE_MS - (Date.now() - this.firstPeerAt);

    if (this.catchup?.active) {
      this.updateStatus('syncing', '過去ログを取得中...');
      return; // 終わったら onChange で再評価される
    }

    if (remaining > 0) {
      this.updateStatus('syncing', `${this.pm.degree}人の隣人と同期中...`);
      this.emptyVerdictTimer = setTimeout(() => {
        this.emptyVerdictTimer = null;
        this.refreshEmptyStatus();
      }, remaining);
      return;
    }

    this.updateStatus('idle', 'スレッドが見つかりませんでした。一番乗りで立ててみませんか？');
  }



  /**
   * スナップショットを作り直してから購読者に「変わった」と伝える。
   *
   * 参照が必ず変わるので、React は確実に再描画する。
   */
  private notify() {
    this.snapshot = Array.from(this.threads.values());
    log.debug(() => `notify: ${this.snapshot.length} threads -> ${this.listeners.size} listener(s)`);
    this.listeners.forEach(l => l());
  }

  /**
   * 端末から消したスレを、メモリ上の一覧からも外す (ThreadRetention の削除の後に呼ぶ)。
   */
  public forgetThreads(threadIds: Iterable<string>): void {
    let changed = false;
    for (const id of threadIds) {
      const t = this.threads.get(id);
      if (!t) continue;
      this.seenPacketIds.delete(t.packet_id);
      this.threads.delete(id);
      changed = true;
    }
    if (changed) this.notify();
  }

  // --- 以降、将来のステップでロジックを順次移植する ---

  /**
   * パケット（JSONオブジェクト）を処理し、板の状態を更新する
   */
  public async handlePacketObject(
    boardId: string, boardKey: Uint8Array, packet: any, isFromDB: boolean, rawData?: Uint8Array,
  ) {
    log.trace(() => `packet enter ${short(packet?.packet_id)} fromDB=${isFromDB}`);
    if (this.seenPacketIds.has(packet.packet_id)) {
      log.trace(() => `packet DROP (already seen) ${short(packet.packet_id)}`);
      return;
    }
    this.seenPacketIds.add(packet.packet_id);
    try {
      // ★ tag / age が「この板の、その日のスレ立て」でなければ、復号の前に落ちる
      const meta = await PacketBuilder.verifyAndDecrypt(packet, boardKey, { kind: 'meta', boardId }, this.cryptoEng);
      if (!meta) {
        log.debug(() => `packet DROP (tag/age/SIV/signature) ${short(packet.packet_id)}`);
        return;
      }
      if (meta.post_type !== 1) {
        log.trace(() => `packet DROP (post_type=${meta.post_type}, want 1) ${short(packet.packet_id)}`);
        return;
      }

      const created_at = this.normalizeTimestamp(meta.created_at);
      // ★ ID に埋め込んだスレ立て日と時刻が合わないスレ立ては受け付けない (ThreadLimits.makeThreadId 参照)
      if (!isThreadMetaTimeConsistent(meta.thread_id, created_at)) {
        log.debug(() => `packet DROP (thread meta time does not match its id) ${short(packet.packet_id)}`);
        return;
      }
      // ★ 寿命 (90 日) を過ぎたスレは、一覧にも出さず端末にも残さない。
      //   端末から消したスレが、履歴の同期 (保管担当や隣人) から戻ってきて復活するのを防ぐ。
      const birth = threadBirthFromId(meta.thread_id) ?? created_at;
      if (birth + THREAD_LIMITS.MAX_LIFETIME_MS < Date.now()) {
        log.trace(() => `packet DROP (thread past max lifetime) ${short(packet.packet_id)}`);
        return;
      }
      const max_pow = await this.resolveMaxPow(boardId, meta);
      const changed = this.mergeThread(meta, packet.packet_id, max_pow, created_at);
      log.debug(() => `merge thread=${short(meta.thread_id)} changed=${changed} total=${this.threads.size}`);
      if (changed) {
        this.notify();
        // 1 件でも届いたら「無い」の表示を消す
        this.refreshEmptyStatus();
      }
      if (!isFromDB) await this.persistThread(boardId, packet, meta, rawData);
    } catch (e: any) {
      log.error(`Error processing packet ${packet?.packet_id}:`, e);
    }
  }

  private normalizeTimestamp(raw: any): number {
    const n = Number(raw);
    return isFinite(n) && n > 0 ? n : Date.now();
  }

  private async resolveMaxPow(boardId: string, meta: any): Promise<number> {
    // ★ 累積 PoW はワイヤに無い。スレ立て自体の熱量は 0 から始め、レスで DB の統計 (祖先数 n(p)) が積み上がる
    const base = 0;
    const stats = await this.db.getThreads(boardId)
      .then((list: any[]) => list.find((s: any) => s.threadId === meta.thread_id));
    return stats ? Math.max(base, stats.max_pow || 0) : base;
  }

  private mergeThread(meta: any, packetId: string, max_pow: number, created_at: number): boolean {
    const existing = this.threads.get(meta.thread_id);
    if (existing) {
      const mergedPow = Math.max(existing.max_pow || 0, max_pow);
      const mergedAt = isFinite(existing.created_at) && existing.created_at > 0
        ? existing.created_at : created_at;
      if (mergedPow === existing.max_pow && mergedAt === existing.created_at) return false;
      this.threads.set(meta.thread_id, { ...existing, max_pow: mergedPow, created_at: mergedAt });
    } else {
      this.threads.set(meta.thread_id, { ...meta, packet_id: packetId, max_pow, created_at });
    }
    return true;
  }

  private async persistThread(boardId: string, packet: any, meta: any, rawData?: Uint8Array): Promise<void> {
    // 保存は常に新形式 (rawData はコンパクト形式の本体。無ければ符号化する)
    const data = rawData ?? encodePacket(packet);
    await this.db.save({
      boardId,
      threadId: BOARD_META_THREAD_ID,
      metaFor: meta.thread_id,
      payload: data,
      dag: {
        parents: meta.parents || [],
        cumulative_pow: 0,
        thread_root: meta.thread_id,
        created_at: meta.created_at
      }
    }).catch((err) => {
      log.error(`DB Save failed for thread meta ${meta?.thread_id}:`, err);
    });
  }


  /**
   * 板全体の過去ログをネットワークから取得する
   */
  public async fullSync(boardId: string, boardKey: Uint8Array): Promise<void> {
    // 同時に複数の fullSync が走ると 同期の待ちが
    // そのぶん重なり、UI が「同期中」から抜けられなくなる。
    if (this.syncInFlight) return this.syncInFlight;
    this.syncInFlight = this.runFullSync(boardId, boardKey).finally(() => {
      this.syncInFlight = null;
    });
    return this.syncInFlight;
  }

  private async runFullSync(boardId: string, boardKey: Uint8Array): Promise<void> {
    if (!this.pm) return;

    try {
      if (this.pm.degree === 0) {
        this.refreshEmptyStatus();
        return;
      }

      // ★ 網への問い合わせはしない。履歴は次の 2 つだけで埋まる (どちらも何も申告しない):
      //     1. 手元の DB (activate の loadInitialCache)
      //     2. Guard からの追いつき (全員に同じものが流れる。受け取った投稿は live と同じ
      //        handlePacketObject に入る) と、直近に見た分の流し込み (activate)
      //   板の鍵から誰でも計算できる索引で GET すると「この IP はこの板を読んでいる」が漏れるので、
      //   板ごとの取得要求は存在しない。

      // 「無い」の判定は refreshEmptyStatus に一本化する (即断しない)
      this.refreshEmptyStatus();

      // 定期的なDB統計の同期を開始
      this.startStatsSync(boardId);

    } catch (err) {
      log.error('[BoardOrchestrator] fullSync error:', err);
      this.updateStatus('error', '最新スレッドの取得に失敗しました');
    }
  }

  /**
   * DBの統計情報を定期的にメモリへ反映する
   */
  public startStatsSync(boardId: string) {
    this.stopStatsSync();
    this.statsTimer = setInterval(async () => {
      const allStats = await this.db.getThreads(boardId).catch(() => []);
      if (allStats.length === 0) return;

      let changed = false;
      for (const s of allStats) {
        const t = this.threads.get(s.threadId);
        if (!t) continue;

        const newPow = Math.max(s.max_pow || 0, t.max_pow || 0);
        const currentCreatedAt = (isFinite(t.created_at) && t.created_at > 0) ? t.created_at : 0;
        const dbCreatedAt = (isFinite(s.created_at) && s.created_at > 0) ? s.created_at : 0;
        const bestCreatedAt = currentCreatedAt > 0 ? currentCreatedAt : (dbCreatedAt > 0 ? dbCreatedAt : Date.now());

        if (newPow !== t.max_pow || bestCreatedAt !== t.created_at) {
          this.threads.set(s.threadId, { ...t, max_pow: newPow, created_at: bestCreatedAt });
          changed = true;
        }
      }
      if (changed) this.notify();
    }, 5000);
  }

  public stopStatsSync() {
    if (this.statsTimer) {
      clearInterval(this.statsTimer);
      this.statsTimer = null;
    }
  }

  /**
   * ハンドラ: 新しいパケットを検知したとき
   */
  private onGossipPacket = async (packet: any) => {
    if (this.currentBoardId && this.currentBoardKey) {
      await this.handlePacketObject(this.currentBoardId, this.currentBoardKey, packet, false);
    } else {
      log.trace(() => `gossip DROP (board not activated, current=${this.currentBoardId}) ${short(packet?.packet_id)}`);
    }
  };

  /**
   * ハンドラ: 新しい隣人と繋がったとき
   */
  /**
   * 隣人が増えたら再同期する。ただし接続は一気に何本も張られるので、
   * そのたびに fullSync を投げると重なる。
   * デバウンスして 1 本に畳む。
   */
  private onPeerConnect = () => {
    // 新しい隣人は履歴を持っているかもしれない。空判定の猶予を引き直す。
    if (this.threads.size === 0) this.firstPeerAt = Date.now();
    this.refreshEmptyStatus();

    if (!this.currentBoardId || !this.currentBoardKey) return;
    if (this.syncDebounce) clearTimeout(this.syncDebounce);
    this.syncDebounce = setTimeout(() => {
      this.syncDebounce = null;
      if (this.currentBoardId && this.currentBoardKey) {
        this.fullSync(this.currentBoardId, this.currentBoardKey);
      }
    }, 500);
  };

  /**
   * 板の同期を活性化する
   */
  public async activate(boardId: string, boardKey: Uint8Array) {
    // 1. 板が切り替わった場合はリセット (同じ板 ID でも鍵が違えば別の板として扱う)
    const sameKey = this.currentBoardKey !== null &&
      this.currentBoardKey.length === boardKey.length &&
      this.currentBoardKey.every((b, i) => b === boardKey[i]);
    if (this.currentBoardId !== boardId || !sameKey) {
      this.clear();
      this.currentBoardId = boardId;
      this.currentBoardKey = boardKey;
    }

    // 2. リスナーの登録（一度だけ）
    if (!this.isListening) {
      this.router.onMessage(this.onGossipPacket);
      this.pm.on('peer:connect', this.onPeerConnect);
      this.unsubCatchup = this.catchup?.onChange(() => this.refreshEmptyStatus()) ?? null;
      this.isListening = true;
    }

    // 3. ローカルDBからキャッシュを復元
    await this.loadInitialCache(boardId, boardKey);

    // 3b. 直近に見た投稿 (追いつきは起動直後に届くので、板を開く前に来た分はここで拾う)。
    //     live と同じ経路 (handlePacketObject)。DB と重なる分は seenPacketIds が落とす
    for (const packet of this.router.recentPackets()) {
      if (this.currentBoardId !== boardId) break;
      await this.handlePacketObject(boardId, boardKey, packet, false);
    }

    // 3c. 保管担当から過去ログ (72 時間より古い分)。裏で取る: 画面は待たない
    this.startHistoryFetch(boardId, boardKey);

    // 4. 初期ネットワーク同期
    await this.fullSync(boardId, boardKey);
  }

  /**
   * 板の直近 13 週のスレ立て (週単位のバケット) を、新しい週から順に保持者から取る (同時 3 本)。
   *
   * ★ スレ立ては週にまとめてある (PacketTag.metaTagAge): バケット = (月曜の日番号, 板の鍵の tag)。13 本で 90 日ぶんが取れる。
   * ★ since: その週に手元のスレ立てが 1 件も無ければ 0 (全部)、あれば**その週で手元の最新のスレ立て − 5 分**。
   *   開くたびに 13 週ぶんを丸ごと取り直さない。
   * ★ 取るのは開いたとき 1 回と、1 ホップ目の再接続のときだけ (HistorySession)。
   */
  private startHistoryFetch(boardId: string, boardKey: Uint8Array): void {
    this.historySession.start((): HistoryJob[] => {
      if (this.currentBoardId !== boardId) return [];
      const thisMonday = mondayOf(dayOf(Date.now()));
      // 週ごとの手元の最新のスレ立て (ms)
      const newestByWeek = new Map<number, number>();
      for (const t of this.threads.values()) {
        if (!(t.created_at > 0)) continue;
        const monday = mondayOf(dayOf(t.created_at));
        if (t.created_at > (newestByWeek.get(monday) ?? 0)) newestByWeek.set(monday, t.created_at);
      }
      const jobs: HistoryJob[] = [];
      for (let i = 0; i < BoardOrchestrator.HISTORY_WEEKS; i++) {
        const monday = thisMonday - 7 * i;
        const newest = newestByWeek.get(monday);
        let since = 0;
        if (newest !== undefined) {
          try {
            since = Math.max(0, msToMinutes(newest - 5 * MINUTE_MS));
          } catch {
            since = 0;
          }
        }
        // birthDay = 投稿日 − age = その週の月曜
        jobs.push({ birthDay: monday, tag: boardTag(boardKey, monday), since });
      }
      return jobs;
    }, BoardOrchestrator.HISTORY_CONCURRENCY);
  }

  /**
   * DBから既知のパケットを読み込む
   */
  private async loadInitialCache(boardId: string, boardKey: Uint8Array) {
    const rawEntries = await this.db.getPosts(boardId, BOARD_META_THREAD_ID).catch(() => []);
    for (const entry of rawEntries) {
      try {
        // 旧形式 (v1・JSON) の保存分は decodePacket が null を返すので、黙って飛ばす
        const packet = decodePacket(entry.payload);
        if (packet) await this.handlePacketObject(boardId, boardKey, packet, true, entry.payload);
      } catch (e) {}
    }
  }




  /**
   * 新しいスレッドを立てる
   */
  public async submitThread(boardId: string, boardKey: Uint8Array, title: string): Promise<string | null> {
    // ★ 上限を超える本文は、PoW や送信の前にここで弾く
    if (title) assertPostLimits({ postType: 1, boardId: '', threadId: '', parents: [], content: title });
    if (!title || !boardKey || !this.powEng || !this.identity || !this.cryptoEng || !this.router || !this.db) return null;

    this.updateStatus('submitting', 'スレッドを構築中...', true, 30);

    try {
      // スレッド ID は網に出るので暗号論的乱数で作る (Math.random は状態を復元され得る)
      // 先頭 4 文字はスレ立て日 (寿命の起点。偽のスレ立てで動かせないよう ID に固定する)
      const threadId = makeThreadId(Date.now(), CryptoUtils.generateId(THREAD_ID_RANDOM_CHARS));
      // 板のメタデータ (スレッド作成通知)。板の鍵で暗号化し、tag は板の日替わりの値 (PacketTag)。
      // 難易度 (effort) は長さの最低値と網の推奨 effort の大きい方。端末の閲覧状況から計算した値を載せない。
      const packet = await PacketBuilder.build({
        content: title, key: boardKey, identity: this.identity, cryptoEngine: this.cryptoEng,
        powEngine: this.powEng, boardId, threadId, postType: 1,
        suggestedEffortPerCell: this.router.suggestedEffortPerCell?.(),
        onEffort: ({ effort }) => {
          // ★ 推奨 effort で重くなったときだけ、理由を一言添える (最低値は一瞬なので何も出さない)
          if (estimateSolveMs(effort) > SLOW_POW_NOTICE_MS) {
            this.updateStatus('submitting', CONGESTION_NOTICE, true, 30);
          }
        },
      });

      this.updateStatus('submitting', '拡散中...', true, 100);

      const rawPacketData = encodePacket(packet);

      // ★ 先に自分の画面へ反映する。
      //
      //   以前は `await this.router.broadcast(packet)` としていたが、
      //   broadcast は Dandelion++ のエコー確認を待つため
      //   ECHO_TIMEOUT(5秒) × (MAX_RETRIES+1 = 3回) = 最大 15 秒ブロックする。
      //   その間 isSubmitting が立ちっぱなしになり、立てたスレッドが
      //   画面に出ないまま固まって見えた。
      //   ThreadOrchestrator.submitReply は元から非同期送信だったので、
      //   スレ立てだけが取り残されていた。
      // 表示上の作成時刻は、網に出したパケットと同じ (分単位に丸めた) 値にそろえる
      const savedAt = packet.timestamp;
      this.mergeThread(
        { thread_id: threadId, board_id: boardId, content: title, post_type: 1, created_at: savedAt },
        packet.packet_id,
        0,
        savedAt
      );
      this.seenPacketIds.add(packet.packet_id);
      this.notify();

      await this.db.save({
        boardId: boardId,
        threadId: BOARD_META_THREAD_ID,
        metaFor: threadId,
        payload: rawPacketData,
        dag: {
            parents: [],
            cumulative_pow: 0,
            thread_root: threadId,
            created_at: savedAt
        }
      }).catch(() => {});

      // ── ここから先はネットワークへの送出。UI を待たせない。 ──
      this.sendAnonymously(packet);

      this.updateStatus('idle', '', false, 0);
      return threadId;
    } catch (err) {
      log.error('[BoardOrchestrator] submitThread error:', err);
      this.updateStatus('error', 'スレッドの作成に失敗しました', false, 0);
      return null;
    }
  }


  /**
   * 投稿をオニオン回路で送り出す。
   *
   * ★ 本体だけがオニオンセルに載る。保管 (Slot) や索引 (Hint) の依頼は無い: 投稿は flood で全員に届き、
   *   過去ログは Guard のバッファと保管担当が、受け取った投稿から自分で持つ (history v2)。
   *   回路で届かなかった場合は平文に落とさず、その旨を表示する (Fail-Closed)。
   */
  private sendAnonymously(packet: any): void {
    void (async () => {
      const delivered = await this.router.broadcast(packet);
      if (!delivered) {
        this.updateStatus('error', '匿名経路で送信できませんでした (平文での送信は行っていません)。隣人が増えてから再度お試しください。');
      }
    })().catch((err: any) => {
      log.error('[BoardOrchestrator] anonymous send failed:', err);
    });
  }

  /**
   * メモリ状態をリセットする（板の切り替え時など）
   */
  public clear() {
    this.stopStatsSync();
    this.firstPeerAt = null;
    if (this.emptyVerdictTimer) {
      clearTimeout(this.emptyVerdictTimer);
      this.emptyVerdictTimer = null;
    }
    if (this.syncDebounce) {
      clearTimeout(this.syncDebounce);
      this.syncDebounce = null;
    }

    if (this.isListening) {
      this.unsubCatchup?.();
      this.unsubCatchup = null;
      this.router.offMessage(this.onGossipPacket);
      this.pm.off('peer:connect', this.onPeerConnect);
      this.isListening = false;
    }

    this.historySession.reset();
    this.currentBoardId = null;
    this.currentBoardKey = null;
    this.threads.clear();
    this.seenPacketIds.clear();
    this.notify();
  }


}

/** ログ用の短縮表示。undefined でも落ちないようにしておく */
function short(id: string | undefined | null): string {
  return id ? id.substring(0, 8) : '?';
}

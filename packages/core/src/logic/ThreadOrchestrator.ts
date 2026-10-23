import type { IndexedDBStore } from '../storage/IndexedDBStore';
import type { GossipRouter } from '../network/gossip/GossipRouter';
import type { CatchupProgress } from '../network/history/CatchupClient';
import type { HistoryFetcher } from '../network/history/HistoryClient';
import { HistorySession } from './HistorySession';
import { birthDayOfThread, threadTag } from '../crypto/PacketTag';
import type { CryptoEngine } from '../crypto/CryptoEngine';
import type { Identity } from '../crypto/Identity';
import type { IPeerManager, IPoWEngine, IKeyManager } from '../types';
import { ThreadDAGManager, type DAGPost, type ThreadState } from './ThreadDAGManager';
import { ThreadClosedError } from './ThreadClosedError';
import { threadBirthFromId } from './ThreadLimits';
import { ThreadStatus } from './types';
import { PacketBuilder } from '../crypto/PacketBuilder';
import { MINUTE_MS, estimateSolveMs, msToMinutes } from '../crypto/PowPolicy';
import { CONGESTION_NOTICE, SLOW_POW_NOTICE_MS } from './PowNotice';
import { encodePacket, decodePacket } from '../crypto/PacketCodec';
import { assertPostLimits } from '../crypto/PostCodec';
import { createLogger } from '../common/Logger';

const log = createLogger('logic.thread');




/**
 * ThreadOrchestrator
 * 特定のスレッドにおける投稿（Post）の取得、DAG構築、同期、および投稿を統括する。
 */
export class ThreadOrchestrator {
  private listeners: Set<() => void> = new Set();
  private statusListeners: Set<() => void> = new Set();
  /**
   * useSyncExternalStore に渡すスナップショット。
   * データが変わらない限り同じ参照を返す必要があるため、notify() でだけ作り直す。
   */
  private snapshot: DAGPost[] = [];
  /** スレッドの状態 (埋まった・落ちた等)。snapshot と同じく notify() でだけ作り直す */
  private stateSnapshot: ThreadState = ThreadOrchestrator.emptyState();
  /** expiresAt に「落ちた」へ切り替えるためのタイマー */
  private expiryTimer: any = null;
  /** DB からの一括読み込み中 (解析は重いので、1 件ごとに notify しない) */
  private bulkLoading = false;
  private dag: ThreadDAGManager = new ThreadDAGManager(''); // 初期はダミー
  private seenPacketIds: Set<string> = new Set();
  private currentStatus: ThreadStatus = { phase: 'idle', message: '' };

  private currentBoardId: string | null = null;
  private currentBoardKey: Uint8Array | null = null;
  private currentThreadId: string | null = null;
  private currentThreadKey: Uint8Array | null = null;
  private isListening: boolean = false;
  /** 実行中の fullSync。多重起動を防ぐ */
  private syncInFlight: Promise<void> | null = null;
  private syncDebounce: any = null;
  /** 隣人が居る状態でこれだけ待ってから「1 件も無い」と判定する */
  private static readonly EMPTY_VERDICT_GRACE_MS = 8000;
  private firstPeerAt: number | null = null;
  private emptyVerdictTimer: any = null;



  private unsubCatchup: (() => void) | null = null;
  /** 保管担当からの過去ログの取得 (開いたとき 1 回と、1 ホップ目の再接続のとき) */
  private historySession: HistorySession;

  constructor(
    private pm: IPeerManager,
    private db: IndexedDBStore,
    private router: GossipRouter,
    private cryptoEng: CryptoEngine,
    private powEng: IPoWEngine,
    private identity: Identity,
    private keyMgr: IKeyManager,
    /**
     * Guard からの追いつきの進み具合。受信中は「無い」と断定しない。
     * 省略可 (単体テスト用)。本番 (OzNode) は必ず渡す。
     */
    private catchup: CatchupProgress | null = null,
    /**
     * 保管担当から取る窓口 (72 時間より古い分)。省略可 (単体テスト用)。本番 (OzNode) は必ず渡す。
     * スレを開いたとき、手元の DB を読んだあとに裏で取る (画面は待たない)。
     */
    history: HistoryFetcher | null = null,
  ) {
    this.historySession = new HistorySession(history, () => this.refreshEmptyStatus());
  }

  /** useSyncExternalStore の subscribe。購読解除関数を返すだけに徹する。 */
  public subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => { this.listeners.delete(listener); };
  }

  public subscribeStatus(listener: () => void): () => void {
    this.statusListeners.add(listener);
    return () => { this.statusListeners.delete(listener); };
  }

  /** useSyncExternalStore の getSnapshot。キャッシュ済みの参照を返す。 */
  public getPosts(): DAGPost[] {
    return this.snapshot;
  }

  /** useSyncExternalStore の getSnapshot (スレッドの状態)。購読は subscribe と共通 */
  public getThreadState(): ThreadState {
    return this.stateSnapshot;
  }

  /** `>>n` が指すレスの packet_id (ThreadDAGManager.resolveAnchor 参照) */
  public resolveAnchor(fromPacketId: string, n: number): string | null {
    return this.dag.resolveAnchor(fromPacketId, n);
  }

  private static emptyState(): ThreadState {
    return {
      visibleCount: 0, hiddenCount: 0, contentBytes: 0, closed: false,
      birthAt: null, lastPostAt: null, expiresAt: null, expired: false,
    };
  }

  public getStatus(): ThreadStatus {
    return this.currentStatus;
  }

  private updateStatus(phase: ThreadStatus['phase'], message: string, isSubmitting: boolean = false, powProgress: number = 0) {
    const cur = this.currentStatus;
    // 同じ内容なら通知しない (空判定の再評価が頻繁に走るため)
    if (cur.phase === phase && cur.message === message &&
        (cur.isSubmitting ?? false) === isSubmitting && (cur.powProgress ?? 0) === powProgress) {
      return;
    }
    this.currentStatus = { phase, message, isSubmitting, powProgress };
    this.statusListeners.forEach(l => l());
  }

  /**
   * 「レスが 1 件も無い」と表示してよいかを判定する。
   *
   * ★ 即断してはいけない。理由は BoardOrchestrator.refreshEmptyStatus と同じ。
   *   過去ログは非同期にしか届かない (手元の DB のあと、Guard からの追いつき) ので、
   *   繋がった直後に同期的に判定すると必ず「無い」と表示されてしまう。追いつきの受信中は断定しない。
   */
  private refreshEmptyStatus(): void {
    if (this.currentStatus.isSubmitting) return;

    if (this.emptyVerdictTimer) {
      clearTimeout(this.emptyVerdictTimer);
      this.emptyVerdictTimer = null;
    }

    // 保管担当から過去ログを取っている間は、その旨を出す (投稿が届いても、取り終わるまで残す)
    if (this.historySession.active && this.pm.degree > 0) {
      this.updateStatus('syncing', this.historySession.message());
      return;
    }

    if (this.dag.getCount() > 0) {
      this.updateStatus('idle', '');
      return;
    }

    if (this.pm.degree === 0) {
      this.firstPeerAt = null;
      this.updateStatus('idle', 'ネット接続待機中... 他の人がレスをすれば自動で反映されます。');
      return;
    }

    if (this.firstPeerAt === null) this.firstPeerAt = Date.now();
    const remaining = ThreadOrchestrator.EMPTY_VERDICT_GRACE_MS - (Date.now() - this.firstPeerAt);

    if (this.catchup?.active) {
      this.updateStatus('syncing', '過去ログを取得中...');
      return; // 終わったら onChange で再評価される
    }

    if (remaining > 0) {
      this.updateStatus('syncing', 'ピアと同期中...');
      this.emptyVerdictTimer = setTimeout(() => {
        this.emptyVerdictTimer = null;
        this.refreshEmptyStatus();
      }, remaining);
      return;
    }

    this.updateStatus('idle', 'レスが1件もありませんでした。あなたが最初の投稿者になりませんか？');
  }

  /** スナップショットを作り直してから「変わった」と伝える */
  private notify() {
    this.snapshot = this.dag.getSortedPosts();
    this.stateSnapshot = this.dag.getThreadState();
    this.scheduleExpiry();
    log.debug(() => `notify: ${this.snapshot.length} posts -> ${this.listeners.size} listener(s)`);
    this.listeners.forEach(l => l());
  }

  /**
   * 落ちる時刻に再通知する。開いたままのビューで `expired` が切り替わるように。
   * setTimeout は 2^31-1 ms (約 24.8 日) までしか待てないので、超える分は丸めて、
   * 着いたらまた notify() から組み直す。
   */
  private scheduleExpiry() {
    if (this.expiryTimer) {
      clearTimeout(this.expiryTimer);
      this.expiryTimer = null;
    }
    const { expiresAt, expired } = this.stateSnapshot;
    if (expiresAt === null || expired) return;
    const wait = Math.min(Math.max(expiresAt - Date.now() + 1, 0), 2 ** 31 - 1);
    this.expiryTimer = setTimeout(() => {
      this.expiryTimer = null;
      this.notify();
    }, wait);
  }

  /**
   * 表示される投稿が増えたことを DB の「最後の書き込み」に反映する。
   * ★ 隠れる投稿 (上限超過・猶予後) では呼ばない。隠れる投稿でスレの寿命を延ばせてはいけない。
   */
  private touchIfVisible(boardId: string, threadId: string, packetId: string) {
    const last = this.stateSnapshot.lastPostAt;
    if (last === null) return;
    if (!this.snapshot.some(p => p.packet_id === packetId)) return;
    try {
      void Promise.resolve(this.db.touchThread(boardId, threadId, last)).catch(() => {});
    } catch { /* 寿命の記録に失敗しても、表示と保存は止めない */ }
  }

  /**
   * パケット（JSONオブジェクト）を処理し、DAGを更新する
   */
  public async handlePacketObject(
    boardId: string, threadId: string, threadKey: Uint8Array, packet: any, isFromDB: boolean,
  ) {
    log.trace(() => `packet enter ${short(packet?.packet_id)} fromDB=${isFromDB}`);
    if (this.seenPacketIds.has(packet.packet_id)) {
      log.trace(() => `packet DROP (already seen) ${short(packet.packet_id)}`);
      return;
    }
    this.seenPacketIds.add(packet.packet_id);

    try {
      // ★ tag / age がこのスレのものでなければ、復号の前に落ちる (他のスレ・他の板のパケット)。
      //   署名はこの板・このスレの文脈に縛られるので、別のスレへ複製しても通らない。
      const post = await PacketBuilder.verifyAndDecrypt(
        packet, threadKey, { kind: 'reply', boardId, threadId }, this.cryptoEng,
      );
      if (!post) {
        log.debug(() => `packet DROP (tag/age/SIV/signature) ${short(packet.packet_id)}`);
        return;
      }

      if (post.thread_id === threadId && post.post_type === 0) {

        const dagPost: DAGPost = {
          packet_id: packet.packet_id,
          content: post.content,
          post_number: 0,
          created_at: post.created_at,
          board_id: post.board_id,
          thread_id: post.thread_id,
          parents: post.parents,
          session_pubkey: post.session_pubkey,
          trip_pubkey: post.trip_pubkey,
        };

        const isNew = this.dag.addPost(dagPost);
        log.debug(() => `dag.addPost ${short(packet.packet_id)} isNew=${isNew}`);
        if (isNew) {
          // ★ 起動時の一括読み込みでは、1 件ごとに解析し直さず、最後に 1 回だけ通知する
          if (!this.bulkLoading) {
            this.notify();
            this.touchIfVisible(boardId, threadId, dagPost.packet_id);
          }
          // 1 件でも届いたら「無い」の表示を消す
          this.refreshEmptyStatus();

          if (!isFromDB) {
              const rawPacketData = encodePacket(packet);
              await this.db.save({ 
                boardId: boardId, 
                threadId: threadId, 
                payload: rawPacketData,
                dag: {
                  parents: dagPost.parents,
                  // ★ DB の「熱量」は手元で数えた祖先の数 n(p) (ワイヤの累積 PoW は廃止した)
                  cumulative_pow: this.dag.getAncestorCount(dagPost.packet_id) ?? 1,
                  thread_root: threadId,
                  created_at: dagPost.created_at
                }
              }).catch((err) => {
                log.error(`DB Save failed for packet ${packet.packet_id}:`, err);
              });
          }
        } else {
          log.debug(`Packet ${packet.packet_id} already exists in DAG (skipped)`);
        }
      } else {
        log.warn(`Packet ${packet.packet_id} skipped: metadata mismatch.`, {
          expectedThread: threadId,
          actualThread: post.thread_id,
          postType: post.post_type
        });
      }
    } catch (e: any) {
      log.error(`Error processing packet ${packet?.packet_id}:`, e);
    }
  }

  /**
   * スレッドの同期と監視を活性化する
   */
  public async activate(boardId: string, threadId: string, boardKey: Uint8Array) {
    // 1. スレッドが切り替わった場合はリセット
    if (this.currentThreadId !== threadId) {
      this.clear();
      this.currentBoardId = boardId;
      this.currentThreadId = threadId;
      this.currentBoardKey = boardKey;
      // スレッド鍵とハッシュの導出 (useThread L48-49を再現)
      this.currentThreadKey = this.keyMgr.deriveThreadKey(boardKey, threadId);
      this.dag = new ThreadDAGManager(threadId);
    }

    if (!this.currentThreadKey) return;

    this.updateStatus('loading', '過去ログを読み込み中...');

    // 2. リスナーの登録（一度だけ）
    if (!this.isListening) {
      this.router.onMessage(this.onGossipPacket);
      this.pm.on('peer:connect', this.onPeerConnect);
      this.unsubCatchup = this.catchup?.onChange(() => this.refreshEmptyStatus()) ?? null;
      this.isListening = true;
    }

    // 寿命の起点は ID に埋め込んだスレ立て日 (偽のスレ立てで動かせない)。
    // 旧形式の ID だけ、板のメタの birth_at を使う。created_at は返信の時刻のことがあるので使わない
    const birthFromId = threadBirthFromId(threadId);
    if (birthFromId !== null) {
      this.dag.setBirth(birthFromId);
      this.notify();
    } else {
      try {
        const stats = (await this.db.getThreads(boardId)).find((t: any) => t.threadId === threadId);
        if (this.currentThreadId === threadId) {
          this.dag.setBirth(typeof stats?.birth_at === 'number' ? stats.birth_at : null);
          this.notify();
        }
      } catch (e) {
        log.warn('birth lookup failed (falling back to oldest post)', e);
      }
    }

    // 3. ローカルDBからキャッシュを復元
    await this.loadInitialCache(boardId, threadId, this.currentThreadKey);

    // 3b. 直近に見た投稿 (追いつきは起動直後に届くので、スレを開く前に来た分はここで拾う)。
    //     live と同じ経路 (handlePacketObject)。DB と重なる分は seenPacketIds が落とす。
    //     tag が合わないもの (他のスレ・板) は復号の前に落ちる
    for (const packet of this.router.recentPackets()) {
      if (this.currentThreadId !== threadId || !this.currentThreadKey) break;
      await this.handlePacketObject(boardId, threadId, this.currentThreadKey, packet, false);
    }

    // 3c. 保管担当から過去ログ (72 時間より古い分)。裏で取る: 画面は待たない
    this.startHistoryFetch(threadId);

    // 4. ネットワーク同期
    await this.triggerInitialSync(boardId, threadId, boardKey);
  }

  /**
   * このスレのバケット (スレ立て日 + スレ鍵の tag) を保持者から取る。
   *
   * ★ since: 手元に 1 件も無ければ 0 (全部)、あれば**手元の最新の投稿の時刻 − 5 分** (遅れて届いた分・時計のずれの重なり)。
   *   手元の最新より前の取りこぼしは取りに行かない (再接続の追いつきは Guard の 72 時間、それより古い穴は
   *   このスレを最初に開いたときの全取得が埋めている前提)。
   * ★ 取るのは開いたとき 1 回と、1 ホップ目の再接続のときだけ (HistorySession)。旧形式のスレ ID (スレ立て日が無い) は取れない。
   */
  private startHistoryFetch(threadId: string): void {
    const key = this.currentThreadKey;
    const birthDay = birthDayOfThread(threadId);
    if (!key || birthDay === null) return;
    this.historySession.start(() => {
      if (this.currentThreadId !== threadId) return [];
      let since = 0;
      const posts = this.snapshot;
      if (posts.length > 0) {
        let newest = 0;
        for (const p of posts) if (p.created_at > newest) newest = p.created_at;
        try {
          since = Math.max(0, msToMinutes(newest - 5 * MINUTE_MS));
        } catch {
          since = 0;
        }
      }
      return [{ birthDay, tag: threadTag(key, birthDay), since }];
    });
  }

  /**
   * 初回のネットワーク同期 (接続待ちを含む)
   */
  private async triggerInitialSync(boardId: string, threadId: string, boardKey: Uint8Array) {
    if (this.dag.getCount() === 0) {
      this.updateStatus('loading', '隣人を探しています...');
    }

    // 隣人がいない場合は少し待つ (useThread L142-156 を再現)
    let isOnline = false;
    if (this.pm.degree > 0) {
      isOnline = true;
    } else {
      isOnline = await new Promise<boolean>((resolve) => {
        let resolved = false;
        const timer = setTimeout(() => {
          if (!resolved) { resolved = true; resolve(false); }
        }, 10000);
        const onConn = () => {
          if (!resolved) {
            resolved = true;
            clearTimeout(timer);
            this.pm.off('peer:connect', onConn);
            resolve(true);
          }
        };
        this.pm.on('peer:connect', onConn);
      });
    }

    if (isOnline) {
      await this.fullSync(boardId, threadId, boardKey);
    } else {
      this.refreshEmptyStatus();
    }
  }

  /**
   * 同期の状態を整える (網への問い合わせは無い。過去ログは追いつきが運ぶ)
   */
  public async fullSync(boardId: string, threadId: string, boardKey: Uint8Array): Promise<void> {
    if (this.syncInFlight) return this.syncInFlight;
    this.syncInFlight = this.runFullSync(boardId, threadId, boardKey).finally(() => {
      this.syncInFlight = null;
    });
    return this.syncInFlight;
  }

  private async runFullSync(boardId: string, threadId: string, boardKey: Uint8Array): Promise<void> {
    if (this.pm.degree === 0) {
      this.refreshEmptyStatus();
      return;
    }

    this.updateStatus('syncing', 'ピアと同期中...');
    try {
      // ★ 網への問い合わせはしない。スレごとの値で網に GET すると、スレッド鍵を持つ者なら
      //   誰でも計算できて「この IP はこのスレを読んでいる」が漏れる。履歴は手元の DB と、
      //   Guard からの追いつき (全員に同じものが流れる) だけで埋まる。

      // 「無い」の判定は refreshEmptyStatus に一本化する (即断しない)
      this.refreshEmptyStatus();
    } catch (e) {
      log.warn('[ThreadOrchestrator] sync error:', e);
      this.updateStatus('error', '同期中にエラーが発生しました');
    }
  }

  /**
   * ハンドラ: 新しいパケットを検知したとき
   */
  private onGossipPacket = async (packet: any) => {
    if (this.currentBoardId && this.currentThreadId && this.currentThreadKey) {
      await this.handlePacketObject(this.currentBoardId, this.currentThreadId, this.currentThreadKey, packet, false);
    } else {
      log.trace(() => `gossip DROP (thread not activated, current=${this.currentThreadId}) ${short(packet?.packet_id)}`);
    }
  };

  /**
   * ハンドラ: 新しい隣人と繋がったとき
   */
  /** 接続が連続して張られたときに fullSync が何本も重ならないようデバウンスする */
  private onPeerConnect = () => {
    // 新しい隣人は履歴を持っているかもしれない。空判定の猶予を引き直す。
    if (this.dag.getCount() === 0) this.firstPeerAt = Date.now();
    this.refreshEmptyStatus();

    if (!this.currentBoardId || !this.currentThreadId || !this.currentBoardKey) return;
    if (this.syncDebounce) clearTimeout(this.syncDebounce);
    this.syncDebounce = setTimeout(() => {
      this.syncDebounce = null;
      if (this.currentBoardId && this.currentThreadId && this.currentBoardKey) {
        this.fullSync(this.currentBoardId, this.currentThreadId, this.currentBoardKey);
      }
    }, 500);
  };


  /**
   * スレッドへ返信を投稿する
   */
  public async submitReply(text: string) {
    // ★ 上限を超える本文は、PoW や送信の前にここで弾く (UI はバイト数を見せて事前に防ぐ)
    if (text) assertPostLimits({ postType: 0, boardId: '', threadId: '', parents: [], content: text });
    if (!text || !this.currentThreadKey || !this.currentThreadId || !this.currentBoardId) return;

    // ★ 埋まった・落ちた・この書き込みで容量を超えるスレには、PoW の前に断る。
    //   見積もりに使った親をそのままパケットの親にするので、判定と実際の投稿は一致する。
    const preview = this.dag.previewNewPost(new TextEncoder().encode(text).length);
    if (!preview.allowed) throw new ThreadClosedError(preview.reason!);

    this.updateStatus('submitting', 'PoW計算中...', true, 20);

    try {

      const tips = preview.parents;

      // ★ 難易度 (effort) は PacketBuilder が「長さの最低値」と「網の推奨 effort (全員が同じ flood から計算)」の
      //   大きい方から決める。端末の閲覧状況から計算した値をヘッダに載せない。
      //   post_number は載せない (旧実装の「手元の DAG に何件見えているか」は作者の閲覧状況の指紋だった)。
      const packet = await PacketBuilder.build({
        content: text, key: this.currentThreadKey, identity: this.identity, cryptoEngine: this.cryptoEng,
        powEngine: this.powEng, boardId: this.currentBoardId, threadId: this.currentThreadId,
        postType: 0, parents: tips,
        suggestedEffortPerCell: this.router.suggestedEffortPerCell?.(),
        onEffort: ({ effort }) => {
          // ★ 推奨 effort で重くなったときだけ、理由を一言添える (最低値は一瞬なので何も出さない)
          if (estimateSolveMs(effort) > SLOW_POW_NOTICE_MS) {
            this.updateStatus('submitting', CONGESTION_NOTICE, true, 20);
          }
        },
      });

      // Immediately reflect the reply in local state rather than waiting for
      // the gossip loopback to come back through verifyAndDecrypt.
      // 表示上の時刻も、網に出したパケットと同じ (分単位に丸めた) 値にそろえる
      const now = packet.timestamp;
      // 表示に要る署名者の鍵 (ID / トリップ) は、受信と同じ経路で読んで取る (自分の投稿もそのまま読める)
      const own = await PacketBuilder.verifyAndDecrypt(
        packet, this.currentThreadKey, { kind: 'reply', boardId: this.currentBoardId, threadId: this.currentThreadId }, this.cryptoEng,
      );
      const dagPost: DAGPost = {
        packet_id: packet.packet_id,
        content: text,
        post_number: 0,
        created_at: now,
        board_id: this.currentBoardId!,
        thread_id: this.currentThreadId!,
        parents: tips,
        session_pubkey: own?.session_pubkey ?? null,
        trip_pubkey: own?.trip_pubkey ?? null,
      };
      const rawPacketData = encodePacket(packet);
      if (this.dag.addPost(dagPost)) {
        this.seenPacketIds.add(packet.packet_id);
        this.notify();
        this.touchIfVisible(this.currentBoardId!, this.currentThreadId!, packet.packet_id);
        await this.db.save({
          boardId: this.currentBoardId!,
          threadId: this.currentThreadId!,
          payload: rawPacketData,
          dag: {
            parents: tips,
            cumulative_pow: this.dag.getAncestorCount(packet.packet_id) ?? 1,
            thread_root: this.currentThreadId!,
            created_at: now,
          }
        }).catch(() => {});
      }

      this.updateStatus('submitting', '送信完了 (配信待機中...)', true, 100);

      // 物理送信 (バックグラウンド)。本体だけがオニオン回路に載る (保管・索引の依頼は無い)。
      this.sendAnonymously(packet);

      this.updateStatus('idle', '計算完了！送信中...', false, 0);
      setTimeout(() => this.updateStatus('idle', ''), 3000);

    } catch (err: any) {
      log.error('Failed to prepare packet:', err);
      this.updateStatus('error', '🔴 失敗: ' + err.toString());
    }
  }

  /**
   * 投稿をオニオン回路で送り出す (BoardOrchestrator.sendAnonymously と同じ方針)。
   * 回路で届かなかった場合は平文に落とさず、その旨を表示する (Fail-Closed)。
   */
  private sendAnonymously(packet: any): void {
    void (async () => {
      const delivered = await this.router.broadcast(packet);
      if (!delivered) {
        this.updateStatus('error', '匿名経路で送信できませんでした (平文での送信は行っていません)。隣人が増えてから再度お試しください。');
      }
    })().catch((err: any) => {
      log.error('[ThreadOrchestrator] anonymous send failed:', err);
    });
  }

  /**
   * DBから既知のパケットを読み込む
   */

  private async loadInitialCache(boardId: string, threadId: string, threadKey: Uint8Array) {
    const rawEntries = await this.db.getPosts(boardId, threadId).catch(() => []);
    this.bulkLoading = true;
    try {
    for (const entry of rawEntries) {
      try {
        // 旧形式 (v1・JSON) の保存分は decodePacket が null を返すので、黙って飛ばす
        const packet = decodePacket(entry.payload);
        if (packet) await this.handlePacketObject(boardId, threadId, threadKey, packet, true);
      } catch (e) {}
    }
    } finally {
      this.bulkLoading = false;
    }
    if (this.currentThreadId === threadId && this.dag.getCount() > 0) {
      this.notify();
      this.refreshEmptyStatus();
      // 読み込んだ分のうち表示されるものがあれば、最後の書き込みの時刻を DB に反映する
      const last = this.stateSnapshot.lastPostAt;
      if (last !== null) {
        try { void Promise.resolve(this.db.touchThread(boardId, threadId, last)).catch(() => {}); } catch { /* 同上 */ }
      }
    }
  }


  /**
   * メモリ状態をリセットする
   */
  public clear() {
    this.firstPeerAt = null;
    if (this.emptyVerdictTimer) {
      clearTimeout(this.emptyVerdictTimer);
      this.emptyVerdictTimer = null;
    }
    if (this.syncDebounce) {
      clearTimeout(this.syncDebounce);
      this.syncDebounce = null;
    }
    if (this.expiryTimer) {
      clearTimeout(this.expiryTimer);
      this.expiryTimer = null;
    }
    if (this.isListening) {
      this.unsubCatchup?.();
      this.unsubCatchup = null;
      this.router.offMessage(this.onGossipPacket);
      this.pm.off('peer:connect', this.onPeerConnect);
      this.isListening = false;
    }

    this.historySession.reset();
    this.dag = new ThreadDAGManager('');
    this.seenPacketIds.clear();
    this.currentBoardId = null;
    this.currentBoardKey = null;
    this.currentThreadId = null;
    this.currentThreadKey = null;
    this.updateStatus('idle', '');

    this.notify();
  }

}

/** ログ用の短縮表示。undefined でも落ちないようにしておく */
function short(id: string | undefined | null): string {
  return id ? id.substring(0, 8) : '?';
}

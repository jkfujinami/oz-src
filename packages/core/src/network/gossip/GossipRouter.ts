import type { IPeerManager, PeerId, GossipPacket, IMessageDispatcher } from '../../types';
import type { RecentBuffer } from '../history/RecentBuffer';
import { SeenCache } from './SeenCache';
import { PacketValidator } from './PacketValidator';
import { EffortAdvisor } from './EffortAdvisor';
import { RelayQueue, type RelayQueueOptions } from './RelayQueue';
import type { DandelionRouter } from './DandelionRouter';
import type { OnionCircuit } from '../onion/OnionCircuit';
import { WireType } from '../wire/WireTypes';
import { createLogger } from '../../common/Logger';

const log = createLogger('net.gossip');

/**
 * GossipRouter
 *
 * ★ 購読宣言の撤去 (本家 OZ 18.6.2)
 *
 * 旧実装は 2 つの経路でゾーン購読を漏らしていた:
 *
 *   1. flood() が `peer.zones.has(zone_id)` で送信先を絞っていた。
 *      つまり全隣人に「自分がどのゾーンを購読しているか」を申告し、
 *      JOIN / PEX / トラッカーがその配列を運んでいた。
 *   2. 購読外のパケットを中継せずに握り潰していた。攻撃者はゾーン Z の
 *      プローブパケットを送り、それが転送されるかどうかを観察するだけで
 *      「この隣人は Z を購読しているか」を判定できた。
 *
 *   ZoneManager は購読セットを localStorage に永続化しているため、
 *   この情報はセッションを跨いで不変であり、長期の交差攻撃で
 *   「誰がどのスレッドを読んでいるか」が特定できた。
 *   設計書が「購読宣言の完全廃止」と書いている内容と実装が真逆だった。
 *
 * 現在の挙動 (Broadcast Veil):
 *   - 中継は無条件に全隣人へ行う。転送するかどうかが購読状態に依存しない。
 *   - (v5 以降) ゾーンによる絞り込みは無い。検証を通った全パケットを読み手へ渡し、
 *     読み手が tag (鍵を持つ者だけが照合できる) で自分の板・スレを選ぶ。
 *
 *
 * ★ パケット単位の状態は用途ごとに分けて持つ (旧実装は 1 つに混ぜていた)
 *
 * 旧実装は `seenCache` ひとつで「中継したか」「Stem を裁いたか」
 * 「UI に届けたか」の 3 つを兼用しており、これが小規模網で
 * ゴシップが一切画面に出ない原因になっていた。実際の壊れ方:
 *
 *   1. A が broadcast → 自分の packet_id を seenCache に入れる
 *   2. A --stem--> B --stem--> C --stem--> A  (小規模網では必ず発信元へ戻る)
 *   3. A は「もう seenCache にある」として **黙って捨てる**
 *      → 誰も Fluff しない → ネットワークに一度も広まらない
 *   4. エコーが返らないので A は 5 秒ごとに再送するが、
 *      B も C も already-seen で捨てるため、Stem は 1 ホップも進まない
 *   5. 15 秒かけてリトライを使い切り、ようやく publish() が false を返し
 *      broadcast() の fallback flood で GOSSIP が直送される
 *
 * 現在は用途ごとに分離してある:
 *   - `flooded`   … 全隣人へ中継済みか (フラッディングの増幅を止める)
 *   - `delivered` … UI へ渡し済みか (中継の可否とは独立)
 *
 * ★ 平文 Stem は廃止した。作者の発信は {@link OnionCircuit} の固定長セルで M1 まで運ばれ、
 *   M1 から先は WireType.STEM で数歩あるいたのち、Fluff を決めたノードが exit_fluff として
 *   Fluff に入る (M1 自身は Fluff しない。歩きの規則は OnionCircuit を参照)。
 *   この STEM は回路が受け持ち、このクラスは Fluff の瞬間 (handleExitFluff) だけを担う。
 */
export class GossipRouter {
  /** 全隣人へ中継 (flood) 済みか。フラッディングの増幅を止める。 */
  private flooded = new SeenCache();
  /** UI (onMessage リスナー) へ渡し済みか。中継の可否とは独立に判定する。 */
  private delivered = new SeenCache();

  /**
   * 推奨 effort (A3)。受理した live の投稿 (自分の発信を含む) を数え、全員が同じ flood から手元で計算する。
   * 追いつき (catchup) は数えない: 過去の投稿であって、今の混雑ではない。
   */
  private readonly advisor: EffortAdvisor;
  /** 中継の優先度キュー (A3)。予算内は即時、超えたら effort の高い順。ローカル配信は通らない */
  private readonly relayQueue: RelayQueue;

  private listeners: Array<(packet: GossipPacket) => void> = [];
  /** 新しく受け取った (または自分が発信した) 投稿ごとに呼ぶ。lastSeen の更新・保管担当の保存用 */
  private storedCandidateListeners: Array<(packet: GossipPacket, source: 'live' | 'catchup' | 'self' | 'fetch') => void> = [];

  constructor(
    private peerManager: IPeerManager,
    dispatcher: IMessageDispatcher,
    /** OnionCircuit と**同じインスタンス**を渡すこと (エコーと Guard を共有する) */
    private dandelion: DandelionRouter,
    /** 作者の発信はすべてこの回路に載せる */
    private circuit: OnionCircuit,
    /**
     * 直近に見た投稿の入れ物 (追いつきの配信元・板を開いたときの流し込み)。
     * 省略すると持たない (単体テスト用)。本番 (OzNode) は必ず渡す。
     */
    private buffer: RecentBuffer | null = null,
    /** 推奨 effort と中継キューの差し替え (テスト・シミュレーション用)。省略時は既定の設定で自前に持つ */
    opts: { advisor?: EffortAdvisor; relayQueue?: RelayQueueOptions } = {},
  ) {
    this.advisor = opts.advisor ?? new EffortAdvisor();
    this.relayQueue = new RelayQueue((packet, exclude) => this.sendToNeighbours(packet, exclude), opts.relayQueue);
    dispatcher.register(WireType.GOSSIP, (senderId, msg) => this.handleGossip(senderId, msg));
    circuit.onExit(
      'exit_fluff',
      (payload) => {
        if (payload.type === 'exit_fluff') this.handleExitFluff(payload.packet);
      },
      // Stem を歩いてきた投稿の検証と重複排除は、回路が次の 2 つで行う
      {
        inspect: (payload) =>
          payload.type === 'exit_fluff' && PacketValidator.validate(payload.packet) ? payload.packet.packet_id : null,
        isFlooded: (id) => this.flooded.has(id),
      },
    );
  }

  public onMessage(handler: (packet: GossipPacket) => void) {
    this.listeners.push(handler);
  }

  public offMessage(handler: (packet: GossipPacket) => void) {
    this.listeners = this.listeners.filter(h => h !== handler);
  }

  /**
   * 保管候補のフック。この端末が**初めて**手にした検証済みの投稿ごとに 1 回呼ぶ
   * (live の flood・自分の発信・Guard の追いつきのどれでも)。保管担当 (B2) の保存はここにつなぐ。
   * source で経路が分かる。
   */
  public onStoredCandidate(handler: (packet: GossipPacket, source: 'live' | 'catchup' | 'self' | 'fetch') => void): () => void {
    this.storedCandidateListeners.push(handler);
    return () => {
      this.storedCandidateListeners = this.storedCandidateListeners.filter(h => h !== handler);
    };
  }

  /** 1 セルあたりの推奨 effort (量子化済み、最小 1)。PacketBuilder へ渡す (× セル数) */
  public suggestedEffortPerCell(): number {
    return this.advisor.suggestedPerCell();
  }

  /** セル数 cells の投稿に勧める effort の合計 */
  public suggestedEffortFor(cells: number): number {
    return this.advisor.suggestedFor(cells);
  }

  /** 中継キューの状態 (診断用) */
  public relayQueueStats(): { queued: number; queuedBytes: number; dropped: number } {
    return { queued: this.relayQueue.size, queuedBytes: this.relayQueue.queuedBytes, dropped: this.relayQueue.dropped };
  }

  /** 直近に見た投稿 (受け取った順)。板・スレを開いたとき、まだ画面に出していない分を流し込むのに使う */
  public recentPackets(): GossipPacket[] {
    return this.buffer?.packets() ?? [];
  }

  /**
   * Guard の追いつきで届いた投稿を、手元へ配る。**flood しない**。
   *
   * ★ 古い投稿を流し直すと、全員が全員に何時間分も送り直す嵐になる。さらに SeenCache は 15 分しか覚えて
   *   いないので、重複排除をすり抜けて何度でも回り続ける。追いつきは「この端末だけが取り逃した分」を
   *   手元に入れる操作で、網には何も出さない。
   * ★ 検証 (PoW・時刻 72 時間 + 15 分まで) は呼び出し側 (CatchupClient) が済ませている。
   * @returns 新しく配ったら true、既に持っていたら false
   */
  public deliverCatchup(packet: GossipPacket): boolean {
    if (this.delivered.has(packet.packet_id) || this.buffer?.has(packet.packet_id)) return false;
    this.deliverLocal(packet, 'catchup');
    return true;
  }

  /**
   * 保管担当から取ってきた (FETCH_BUCKET) 過去ログの投稿を、手元へ配る。**flood しない**。
   *
   * ★ 追いつき (deliverCatchup) との違い: 直近の入れ物 (RecentBuffer) には入れない。取ってくるのは最大 90 日前までの
   *   投稿で、入れると Guard の追いつき (72 時間) の応答や「板を開いたときの流し込み」に古い投稿が混ざる。
   *   推奨 effort の観測にも数えない (過去の投稿であって、今の混雑ではない)。
   * ★ 保管候補のフックには回す (読み手が同時に保持者でもあるとき、担当の分を預かる)。lastSeen (追いつきの起点) は動かさない。
   * ★ 検証 (PoW・id・時刻 = 91 日 + 15 分まで) は呼び出し側 (HistoryClient) が済ませている。
   * ★ 画面側 (onMessage) へは**毎回**配る (直近に配っていても)。同じバケットに別のスレ・板の投稿が混ざる (tag は 12 ビット) ので、
   *   最初に取った時点で開いていなかった画面が、あとで同じバケットを取り直したとき届かなくなってはいけない。
   *   読み手 (オーケストレータ) が packet_id で重複を落とす。保管の保存だけは、直近に見ていれば省く。
   */
  public deliverFetched(packet: GossipPacket): void {
    if (!this.delivered.has(packet.packet_id)) {
      this.delivered.add(packet.packet_id);
      this.storedCandidateListeners.forEach(cb => cb(packet, 'fetch'));
    }
    this.listeners.forEach(cb => cb(packet));
  }

  /**
   * 自己発信。
   *
   * ★ オニオン回路以外の経路は持たない (Fail-Closed)。
   *
   *   旧実装は「匿名化フラグ無しなら平文 flood」「隣人が 2 人未満なら平文 Stem」
   *   「失敗したら Guard を交代して再試行」という分岐を持っていた。どれも
   *   攻撃者が隣人を減らす・セルを捨てるだけで誘発でき、作者の IP から
   *   平文を出させるか、Guard の座を回させる手段になっていた。
   *
   * @returns 網に現れたこと (エコー) を確認できたか
   */
  public async broadcast(packet: GossipPacket): Promise<boolean> {
    // ネットワークに流す前に、まず自分のUIに即座に通知する
    // (ゾーン購読に関係なく、自分の投稿は必ず自分に見える)
    if (!this.delivered.has(packet.packet_id)) {
      this.delivered.add(packet.packet_id);
      this.buffer?.add(packet);
      this.storedCandidateListeners.forEach(cb => cb(packet, 'self'));
      this.advisor.observe(packet);
    }
    this.listeners.forEach(cb => cb(packet));

    log.debug(() => `originating broadcast ${short(packet.packet_id)} via onion circuit`);
    const ok = await this.circuit.send(
      { type: 'exit_fluff', packet },
      packet.packet_id,
    );
    if (!ok) {
      log.error(`onion delivery failed for ${short(packet.packet_id)}; dropped (fail-closed, no plaintext fallback)`);
    }
    return ok;
  }

  /**
   * Stem を歩いた末に Fluff を決めたノードとして、パケットを全体配信する。
   */
  private handleExitFluff(packet: GossipPacket): void {
    if (!PacketValidator.validate(packet)) {
      log.debug(() => `stem fluff REJECTED (validate) ${short(packet?.packet_id)}`);
      return;
    }
    log.debug(() => `stem end -> FLUFF ${short(packet.packet_id)}`);
    this.dandelion.notifyEcho(packet.packet_id);
    this.deliverLocal(packet);
    this.flood(packet, this.peerManager.myPeerId);
  }

  /**
   * ローカル配信。検証を通ったパケットはすべて、鍵を持つ読み手 (オーケストレータ) へ渡す。
   *
   * ★ v5 でゾーンの購読による絞り込みをやめた。パケットのヘッダの tag は「板 / スレの日替わりの目印」
   *   (12 ビット、鍵を持つ者だけが照合できる) で、ゾーン番号ではない。ゾーンは深さ 0 (全員が同じ
   *   ゾーン) のまま眠っていたので、挙動は変わらない。振り分けは読み手が tag で行う (復号の前の足切り)。
   *   ZoneManager は撤去した。
   */
  private deliverLocal(packet: GossipPacket, source: 'live' | 'catchup' = 'live'): void {
    if (this.delivered.has(packet.packet_id)) {
      log.trace(() => `deliver SKIP (already delivered) ${short(packet.packet_id)}`);
      return;
    }
    this.delivered.add(packet.packet_id);
    this.buffer?.add(packet);
    if (source === 'live') this.advisor.observe(packet);
    this.storedCandidateListeners.forEach(cb => cb(packet, source));
    log.debug(() => `deliver -> ${this.listeners.length} listener(s) ${short(packet.packet_id)}`);
    this.listeners.forEach(cb => cb(packet));
  }

  /** ── Dispatcher Handlers ── */

  private handleGossip(senderId: PeerId, msg: any) {
    const packet = msg?.packet;
    log.trace(() => `GOSSIP from=${short(senderId)} ${short(packet?.packet_id)}`);

    // 1. 基本検証 (CHK + PoW + サイズ + 時刻)。同期実行。
    if (!PacketValidator.validate(packet)) {
      log.debug(() => `GOSSIP REJECTED (validate) from=${short(senderId)} ${short(packet?.packet_id)}`);
      return;
    }

    // エコー通知は何よりも先に。ここで発信元の待ち合わせが解ける。
    this.dandelion.notifyEcho(packet.packet_id);

    // 2. ローカル配信。中継状態とは独立に必ず試みる。
    this.deliverLocal(packet);

    // 3. 中継は購読状態に関係なく全隣人へ。
    //    ここを購読で分岐させると、その分岐自体が購読宣言になる。
    this.flood(packet, senderId);
  }

  /**
   * フラッディング。全隣人へ転送する。
   *
   * 送信先をゾーンで絞らないのが要点 (Broadcast Veil)。
   * 同じパケットを二度中継しないための判定はここだけが行う (flooded)。
   *
   * ★ hop_count は持たない (H6)。
   *
   *   旧実装は中継のたびに +1 していたため、hop_count=1 を受け取れば
   *   「送ってきた隣人が Fluff 地点 (出口)」と確定し、複数のスパイが値を
   *   突き合わせれば出口の位置を三角測量できた。出口が分かれば作者の候補は
   *   その周辺に絞られる。後に常に 0 を載せる形になり、コンパクト形式でフィールド自体を廃止した。
   *   停止性は flooded (重複排除) と PacketValidator の時刻検査 (15 分) が担う。
   */
  private flood(packet: GossipPacket, excludePeerId: PeerId) {
    if (this.flooded.has(packet.packet_id)) {
      log.trace(() => `flood SKIP (already flooded) ${short(packet.packet_id)}`);
      return;
    }

    this.flooded.add(packet.packet_id);
    // ★ 実際の送信は中継キューを通す。予算内なら同じ呼び出しの中で即座に sendToNeighbours へ来る。
    //   混雑時だけ、effort の高い順に待たされる (RelayQueue)。
    this.relayQueue.offer(packet, excludePeerId);
  }

  /** 全隣人 (検証済み・接続中) へ送る。送ってきた隣人には返さない */
  private sendToNeighbours(packet: GossipPacket, excludePeerId: PeerId | null) {
    const payload = { packet };
    for (const peer of this.peerManager.peers.values()) {
      if (peer.peerId === excludePeerId) continue;
      if (!peer.isConnected || !peer.isVerified) continue;
      this.peerManager.sendMessage(peer.peerId, WireType.GOSSIP, payload);
    }
  }

  public destroy() {
    this.relayQueue.destroy();
    this.flooded.destroy();
    this.delivered.destroy();
  }
}

/** ログ用の短縮表示。undefined でも落ちないようにしておく */
function short(id: string | undefined | null): string {
  return id ? id.substring(0, 8) : '?';
}

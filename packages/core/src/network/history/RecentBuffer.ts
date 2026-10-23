import type { GossipPacket } from '../../types';
import { decodePacket, encodePacket } from '../../crypto/PacketCodec';
import { POW_POLICY } from '../../crypto/PowPolicy';

/**
 * RecentBuffer — 検証を通った投稿を、受け取った順にしばらく持っておく入れ物 (history v2 §3)。
 *
 * 全ノードが持つ (live の flood で受け取ったもの・自分が発信したもの・追いつきで受け取ったもの)。
 * 使い道は 2 つ:
 *   1. {@link CatchupServer}: 再接続してきた隣人 (クライアント) に、取り逃した分を古い順に流す。
 *   2. 板・スレを開いたとき、まだ画面に出していない直近の分を流し込む (GossipRouter.recentPackets)。
 *      追いつきは起動直後 (まだ板を開く前) に届くことが多いので、この入れ物が無いと取りこぼす。
 *
 * ★ 持つ長さは役割で変える。Guard (role 'guard') は 72 時間・256MiB、それ以外は 1 時間・16MiB。
 *   72 時間は「夜だけ閉じていた」程度の再接続の大半を Guard だけで埋める長さ (それより古い分は保管担当)。
 *   一般ノードに長く持たせないのは、押収された端末に「見た投稿」の記録が残るのを減らすため
 *   (メモリだけ。端末には書かない)。
 * ★ メモリ上だけ。暗号化 DB には書かない (Guard の再起動で消えてよい。消えた分は coverageStartMs が
 *   「ここから先は持っている」を正直に申告し、足りなければクライアントは partial として扱う)。
 * ★ 保持は「受け取った時刻」で数える (投稿の時刻ではない)。投稿の時刻は最大 15 分遅れて届くので、
 *   投稿の時刻で数えると、遅れて届いた分が入れた直後に消える。
 * ★ 上限を超えたら古い順に捨てる。捨てたら coverageStart をそこまで進める (その時刻より前の分は欠けている)。
 */
export const RECENT_BUFFER = {
  /** Guard の保持時間とメモリ上限 */
  GUARD_WINDOW_MS: 72 * 60 * 60 * 1000,
  GUARD_MAX_BYTES: 256 * 1024 * 1024,
  /** 一般ノードの保持時間とメモリ上限 */
  NODE_WINDOW_MS: 60 * 60 * 1000,
  NODE_MAX_BYTES: 16 * 1024 * 1024,
} as const;

/**
 * 追いつきで受け付ける投稿の古さの上限 (Guard の保持時間 + 時刻ドリフト 15 分)。
 * 受け取った時刻で 72 時間持つので、投稿の時刻は最大で 72 時間 + 15 分前になり得る。
 */
export const CATCHUP_MAX_PAST_MS = RECENT_BUFFER.GUARD_WINDOW_MS + POW_POLICY.MAX_TIME_DRIFT;

export interface RecentBufferOptions {
  windowMs: number;
  maxBytes: number;
  /** テスト用の時計 */
  now?: () => number;
}

export interface BufferedPacket {
  id: string;
  /** 投稿の時刻 (ms。分に丸めてある) */
  time: number;
  /** encodePacket 済みのバイト列 (そのまま CATCHUP_DATA に載せる) */
  bytes: Uint8Array;
}

interface Entry extends BufferedPacket {
  /** 受け取った時刻 (ms) */
  at: number;
}

export class RecentBuffer {
  /** 挿入順 = 受け取った順 (Map は挿入順を保つ。先頭が最も古い) */
  private entries = new Map<string, Entry>();
  private totalBytes = 0;
  private readonly now: () => number;
  /** この入れ物を作った時刻。これより前に流れた投稿は、そもそも見ていない */
  private readonly createdAt: number;
  /** 上限で捨てたものの受け取り時刻の最大。これ以前に受け取った分は欠けているかもしれない */
  private evictedUpToAt = 0;

  public readonly windowMs: number;
  public readonly maxBytes: number;

  constructor(opts: RecentBufferOptions) {
    this.windowMs = opts.windowMs;
    this.maxBytes = opts.maxBytes;
    this.now = opts.now ?? Date.now;
    this.createdAt = this.now();
  }

  /** 役割に応じた既定の大きさで作る */
  public static forRole(role: 'client' | 'guard', now?: () => number): RecentBuffer {
    return role === 'guard'
      ? new RecentBuffer({ windowMs: RECENT_BUFFER.GUARD_WINDOW_MS, maxBytes: RECENT_BUFFER.GUARD_MAX_BYTES, now })
      : new RecentBuffer({ windowMs: RECENT_BUFFER.NODE_WINDOW_MS, maxBytes: RECENT_BUFFER.NODE_MAX_BYTES, now });
  }

  public get size(): number {
    return this.entries.size;
  }

  /** 持っているバイト数 (パケットの符号化後の長さの合計) */
  public get bytes(): number {
    return this.totalBytes;
  }

  public has(id: string): boolean {
    return this.entries.has(id);
  }

  /**
   * 検証済みのパケットを入れる。新しく入れたら true、既に持っていれば false。
   * ★ 検証は呼び出し側の責任 (PacketValidator を通ったものだけを渡す)。
   */
  public add(packet: GossipPacket): boolean {
    if (this.entries.has(packet.packet_id)) return false;
    let bytes: Uint8Array;
    try {
      bytes = encodePacket(packet);
    } catch {
      return false;
    }
    const at = this.now();
    this.entries.set(packet.packet_id, { id: packet.packet_id, time: packet.timestamp, bytes, at });
    this.totalBytes += bytes.length;
    this.evict(at);
    return true;
  }

  /**
   * 時間切れと上限超過のものを捨てる。add / 読み出しのたびに呼ぶのでタイマーは持たない
   * (止め忘れてリークするものを作らない)。
   */
  public prune(): void {
    this.evict(this.now());
  }

  private evict(now: number): void {
    const horizon = now - this.windowMs;
    for (const [id, e] of this.entries) {
      const expired = e.at < horizon;
      const overCap = this.totalBytes > this.maxBytes;
      if (!expired && !overCap) break;
      this.entries.delete(id);
      this.totalBytes -= e.bytes.length;
      if (!expired) this.evictedUpToAt = Math.max(this.evictedUpToAt, e.at);
    }
  }

  /**
   * 「この時刻以降に受け取った投稿はすべて持っている」の境目 (ms)。
   * 保持時間の外・上限で捨てた分・入れ物を作る前の分は含まない。
   * 追いつきの要求の since がこれより古ければ、全部は返せない (status = partial)。
   */
  public coverageStartMs(): number {
    const now = this.now();
    return Math.max(this.createdAt, now - this.windowMs, this.evictedUpToAt + 1);
  }

  /**
   * sinceMs 以降 (投稿の時刻) のものを、投稿の時刻の古い順に返す。保持時間の外のものは返さない。
   * 同じ時刻 (分単位) のものは受け取った順。
   */
  public entriesSince(sinceMs: number): BufferedPacket[] {
    this.prune();
    const out: Entry[] = [];
    for (const e of this.entries.values()) if (e.time >= sinceMs) out.push(e);
    // Array.prototype.sort は安定。入力が受け取り順なので、同じ時刻は受け取り順のまま残る
    out.sort((a, b) => a.time - b.time);
    return out.map(({ id, time, bytes }) => ({ id, time, bytes }));
  }

  /** 持っているパケットを受け取った順に復元する (板・スレを開いたときの流し込み用) */
  public packets(): GossipPacket[] {
    this.prune();
    const out: GossipPacket[] = [];
    for (const e of this.entries.values()) {
      const p = decodePacket(e.bytes);
      if (p) out.push(p);
    }
    return out;
  }

  public clear(): void {
    this.entries.clear();
    this.totalBytes = 0;
  }
}

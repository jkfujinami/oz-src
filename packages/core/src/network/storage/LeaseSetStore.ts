import { Encoding } from '../../common/Encoding';
import { minutesToMs } from '../../crypto/PowPolicy';
import { slotPosition } from './SlotPow';
import { LEASESET_MIN_REPLACE_MS, leaseSetId, type LeaseSet } from './LeaseSet';

/** 手元に持つ leaseSet の上限。超えたら期限の近いものから捨てる */
export const LEASESET_STORE_MAX = 50_000;

/** リング上の 1 枠 (担当の計算の単位) */
export interface SlotEntry {
  /** SID の hex ‖ 枠番号 (2 桁 hex)。同順位の決着に使う id */
  key: string;
  id: Uint8Array;
  position: bigint;
  /** SID の hex (自分の枠かの判定・重複除去に使う) */
  sid: string;
  index: number;
}

interface Entry {
  ls: LeaseSet;
  /** 受け付けた時刻 (ms)。置き換えの間隔 (LEASESET_MIN_REPLACE_MS) の起点 */
  acceptedAt: number;
  expiresMs: number;
  id: string;
  slots: SlotEntry[];
}

/** 'too-soon': 期限は新しいが、前に受け付けてから LEASESET_MIN_REPLACE_MS (10 分) が経っていない */
export type LeaseSetAddResult = 'added' | 'updated' | 'stale' | 'too-soon';

/**
 * LeaseSetStore — 全員が持つ leaseSet の手元の集合 (メモリだけ)。
 *
 * ★ SID ごとに**最新 1 件**だけ持つ。期限 (expires) が今ある物より新しいものだけが置き換える。
 *   同じ期限や古い期限の再送は 'stale' (relay しない = 古い leaseSet を回し続けさせない)。
 * ★ さらに、置き換えは**前に受け付けてから 10 分以上**経っているときだけ ('too-soon' は入れず、中継もしない)。
 *   保持者が分単位で署名し直して flood を水増しするのを止める。最初の 1 件は常に受け付ける。
 *   起点は受け手の時計 (受け付けた時刻) で、leaseSet の中の時刻 (署名者が決められる値) ではない。
 * ★ 上限 50,000 件。超えたら**期限が最も近い**ものから捨てる (更新されなかった = もう居ない可能性が高い)。
 * ★ 枠の位置は追加時に 1 回だけ計算してしまっておく (担当の計算は投稿ごとに走る)。
 */
export class LeaseSetStore {
  private bySid = new Map<string, Entry>();
  private version_ = 0;

  constructor(
    private readonly now: () => number = Date.now,
    private readonly max: number = LEASESET_STORE_MAX,
  ) {}

  /** 内容が変わるたびに増える。担当の索引の作り直しの合図 */
  public get version(): number {
    return this.version_;
  }

  public get size(): number {
    return this.bySid.size;
  }

  /**
   * 検証済みの leaseSet を入れる。検証 (署名・PoW・期限・受け口) は呼び出し側が済ませていること。
   */
  public add(ls: LeaseSet): LeaseSetAddResult {
    const sidHex = Encoding.toHex(ls.sid);
    const expiresMs = minutesToMs(ls.expiresMin);
    if (expiresMs <= this.now()) return 'stale';
    const prev = this.bySid.get(sidHex);
    if (prev && prev.expiresMs >= expiresMs) return 'stale';
    const nowMs = this.now();
    if (prev && nowMs - prev.acceptedAt < LEASESET_MIN_REPLACE_MS) return 'too-soon';

    const slots: SlotEntry[] = ls.slots.map((s, i) => {
      const index = i;
      return {
        key: `${sidHex}${index.toString(16).padStart(2, '0')}`,
        id: Uint8Array.of(...ls.sid, index),
        position: slotPosition(ls.sid, index, s.solution),
        sid: sidHex,
        index,
      };
    });
    this.bySid.set(sidHex, { ls, acceptedAt: nowMs, expiresMs, id: leaseSetId(ls.bytes), slots });
    this.version_++;
    if (this.bySid.size > this.max) this.evict(this.bySid.size - Math.floor(this.max * 0.95));
    return prev ? 'updated' : 'added';
  }

  public get(sidHex: string): LeaseSet | undefined {
    const e = this.bySid.get(sidHex);
    return e && e.expiresMs > this.now() ? e.ls : undefined;
  }

  /** 期限切れを捨てる。捨てた件数 */
  public prune(): number {
    const now = this.now();
    let n = 0;
    for (const [sid, e] of this.bySid) {
      if (e.expiresMs <= now) {
        this.bySid.delete(sid);
        n++;
      }
    }
    if (n > 0) this.version_++;
    return n;
  }

  /** 期限内の leaseSet のバイト列すべて (SYNC の送り元)。新しい順 */
  public allBytes(): Uint8Array[] {
    const now = this.now();
    const out: Entry[] = [];
    for (const e of this.bySid.values()) if (e.expiresMs > now) out.push(e);
    out.sort((a, b) => b.expiresMs - a.expiresMs);
    return out.map(e => e.ls.bytes);
  }

  /** 期限内の全枠。担当の計算 (Duty) が使う。順序は不定 */
  public allSlots(): SlotEntry[] {
    const now = this.now();
    const out: SlotEntry[] = [];
    for (const e of this.bySid.values()) {
      if (e.expiresMs <= now) continue;
      for (const s of e.slots) out.push(s);
    }
    return out;
  }

  public clear(): void {
    this.bySid.clear();
    this.version_++;
  }

  /**
   * ★ 上限ちょうどまでではなく 5% 余裕を空けるまで捨てる。上限に張り付いた状態で 1 件ごとに
   *   全件を並べ替えると、leaseSet の洪水が CPU を食う (償却して 5% 分に 1 回で済ませる)。
   */
  private evict(count: number): void {
    const order = Array.from(this.bySid.entries()).sort((a, b) => a[1].expiresMs - b[1].expiresMs);
    for (let i = 0; i < count && i < order.length; i++) this.bySid.delete(order[i][0]);
  }
}

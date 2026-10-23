import { positionOf, ringDistance } from '../../common/Ring';
import { DAY_MS, u16be, u32be } from '../../crypto/PowPolicy';
import { chunkPositions } from '../../files/FileCodec';
import { CHUNK_DUTY_SLOTS, R_FILE } from './ChunkProtocol';
import type { LeaseSetStore, SlotEntry } from './LeaseSetStore';

/** 取りに行くのは近い 64 枠。保存は近い 72 枠まで (見え方のずれの余裕 8 枠) */
export const R_QUERY = 64;
export const R_STORE = 72;

export const BUCKET_DOMAIN = 'oz/v5/bucket';

/** birthDay = floor(time / 1 日) − age (UTC の日番号。age = スレ立てからの日数) */
export function birthDayOf(timestampMs: number, age: number): number {
  return Math.floor(timestampMs / DAY_MS) - age;
}

/** バケット (birthDay, tag) のリング上の位置。tag は 12 ビット */
export function bucketPosition(birthDay: number, tag: number): bigint {
  return positionOf(BUCKET_DOMAIN, u32be(birthDay), u16be(tag));
}

function cmp(target: bigint, a: SlotEntry, b: SlotEntry): number {
  const da = ringDistance(target, a.position);
  const db = ringDistance(target, b.position);
  if (da !== db) return da < db ? -1 : 1;
  if (a.position !== b.position) return a.position < b.position ? -1 : 1;
  return a.key < b.key ? -1 : a.key > b.key ? 1 : 0;
}

/**
 * SlotIndex — 位置で整列した枠の並び。target に近い k 枠を O(log n + k) で返す。
 *
 * ★ Ring.closest は全件を並べ替える (O(n log n))。担当の判定は投稿ごとに走り、枠は最大 数十万 (3 万人 × 数枠)
 *   になりうるので、整列済みの配列の二分探索 + 両側へ広げる方式にする。結果の順序は Ring.closest と同じ
 *   (距離 → 位置 → key)。tests/network/Duty.test.ts が乱数で突き合わせている。
 */
export class SlotIndex {
  private readonly sorted: SlotEntry[];

  constructor(entries: readonly SlotEntry[]) {
    this.sorted = entries.slice().sort((a, b) =>
      a.position !== b.position ? (a.position < b.position ? -1 : 1) : a.key < b.key ? -1 : a.key > b.key ? 1 : 0);
  }

  public get size(): number {
    return this.sorted.length;
  }

  public nearest(target: bigint, k: number): SlotEntry[] {
    const n = this.sorted.length;
    const want = Math.min(k, n);
    if (want <= 0) return [];
    // target 以上で最初の添字
    let lo = 0;
    let hi = n;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (this.sorted[mid].position < target) lo = mid + 1;
      else hi = mid;
    }
    let r = lo % n;
    let l = (lo - 1 + n) % n;
    const out: SlotEntry[] = [];
    const take = (): SlotEntry => {
      const L = this.sorted[l];
      const R = this.sorted[r];
      if (cmp(target, L, R) <= 0) {
        l = (l - 1 + n) % n;
        return L;
      }
      r = (r + 1) % n;
      return R;
    };
    while (out.length < want) out.push(take());
    // ★ 境目で距離が同じ枠 (位置が完全に一致する枠が並ぶ極端な場合) は、規則 (距離 → 位置 → key) で選び直す。
    //   整列配列を片側から歩くだけだと、同じ位置の並びの中の取り出し順が key の順にならない。
    //   端末ごとに境目の選び方が違うと、置いた先と取りに行く先が食い違う。
    const limit = ringDistance(target, out[out.length - 1].position);
    while (out.length < n) {
      const L = this.sorted[l];
      const R = this.sorted[r];
      const next = cmp(target, L, R) <= 0 ? L : R;
      if (ringDistance(target, next.position) !== limit) break;
      out.push(take());
    }
    // 同じ位置が並ぶ極端な場合に備えて、結果の並びを規則どおりに揃える
    return out.sort((a, b) => cmp(target, a, b)).slice(0, want);
  }
}

export interface DutyOptions {
  /** 索引の作り直しの最短間隔 (ms)。leaseSet は流れ込み続けるので、変わるたびには作り直さない */
  minRebuildMs?: number;
  now?: () => number;
}

/**
 * Duty — どのバケットを自分が持つか (history v2 §4.3)。
 *
 *   B = bucketPosition(birthDay, tag)
 *   保存するのは「自分の枠のどれかが、B に近い R_STORE (72) 枠に入る」とき。取りに行くのは近い R_QUERY (64) 枠。
 *   既知の枠が R_QUERY 未満の小さな網では、誰もが全部を持つ。
 *
 * ★ 見え方は端末ごとに少しずれる (leaseSet の到着順・取りこぼし)。保存を 72 枠まで広げておけば、
 *   他の端末が見た「近い 64 枠」の持ち主は、ずれがあっても (近い 72 枠のうちに入っていて) 保存している。
 *   その確率は tests/network/Duty.test.ts で実測する。
 * ★ 自分の枠は、leaseSet を出す前 (Guard 未接続・まだ他人に見えていない) でも数に入れる。
 */
export class Duty {
  private index: SlotIndex | null = null;
  private builtAt = 0;
  private builtVersion = -1;
  private builtOwnKey = '';
  private ownKeys = new Set<string>();
  private readonly minRebuildMs: number;
  private readonly now: () => number;

  constructor(
    private readonly store: LeaseSetStore,
    /** 自分の SID (hex) と、いま受け持つ枠 (容量の範囲内で解き終わったもの) */
    private readonly own: () => { sid: string; slots: SlotEntry[] } | null,
    options: DutyOptions = {},
  ) {
    this.minRebuildMs = options.minRebuildMs ?? 2000;
    this.now = options.now ?? Date.now;
  }

  private snapshot(): SlotIndex {
    const mine = this.own();
    const ownKey = mine ? `${mine.sid}:${mine.slots.length}` : '';
    const t = this.now();
    const stale = !this.index
      || ownKey !== this.builtOwnKey
      || (this.store.version !== this.builtVersion && t - this.builtAt >= this.minRebuildMs);
    if (stale) {
      const entries = this.store.allSlots().filter(s => !mine || s.sid !== mine.sid);
      if (mine) for (const s of mine.slots) entries.push(s);
      this.index = new SlotIndex(entries);
      this.ownKeys = new Set(mine ? mine.slots.map(s => s.key) : []);
      this.builtAt = t;
      this.builtVersion = this.store.version;
      this.builtOwnKey = ownKey;
    }
    return this.index!;
  }

  /** 既知の枠の数 (自分を含む) */
  public get knownSlots(): number {
    return this.snapshot().size;
  }

  /** バケットに近い順の枠 (保存側の範囲 R_STORE か、取りに行く範囲 R_QUERY) */
  public closestSlots(birthDay: number, tag: number, k: number = R_QUERY): SlotEntry[] {
    return this.snapshot().nearest(bucketPosition(birthDay, tag), k);
  }

  /** 任意の位置に近い順の枠 (大容量ファイルのチャンクの置き場所・取りに行く先) */
  public closestSlotsAt(position: bigint, k: number): SlotEntry[] {
    return this.snapshot().nearest(position, k);
  }

  /**
   * このチャンクの PUT を自分が受けてよいか。
   *
   * ★ 複製 j の位置 (chunkPositions) のどれかについて、**近い CHUNK_DUTY_SLOTS (3) 枠のうちに自分の枠がある**とき。
   *   置く側は最も近い保持者から順に頼む。見え方のずれ (leaseSet の到着順) と、先に断られて次に近い保持者へ回る場合のために、
   *   最も近い 1 枠でなく 3 枠まで受ける。取りに行く側は近い順に CHUNK_READ_SLOTS 枠まで探すので、置かれた先に必ず当たる。
   * ★ 投稿 (shouldStore) と違い、枠が少ない網でも「誰でも受ける」にはしない: 枠が 3 つ以下なら 3 枠が全部入るので結果として受けるが、
   *   それ以外では位置に近くなければ断る (無関係な保持者に任意のチャンクを押し込めない)。
   */
  public shouldStoreChunk(chunkId: Uint8Array): boolean {
    if (chunkId.length !== 16) return false;
    const idx = this.snapshot();
    if (this.ownKeys.size === 0) return false;
    for (const pos of chunkPositions(chunkId, R_FILE)) {
      for (const s of idx.nearest(pos, CHUNK_DUTY_SLOTS)) {
        if (this.ownKeys.has(s.key)) return true;
      }
    }
    return false;
  }

  /** このバケットを自分が保存すべきか */
  public shouldStore(birthDay: number, tag: number): boolean {
    if (!Number.isInteger(birthDay) || birthDay < 0 || birthDay > 0xffffffff) return false;
    if (!Number.isInteger(tag) || tag < 0 || tag > 0xffff) return false;
    const idx = this.snapshot();
    if (this.ownKeys.size === 0) return false;
    if (idx.size < R_QUERY) return true;
    for (const s of idx.nearest(bucketPosition(birthDay, tag), R_STORE)) {
      if (this.ownKeys.has(s.key)) return true;
    }
    return false;
  }
}

import type { PeerId } from '../../types';
import { Encoding } from '../../common/Encoding';
import { MAX_FRAGMENTS, OnionRouter, type ExitPayload } from '../../crypto/OnionRouter';

export type Fragment = Extract<ExitPayload, { type: 'frag' }>;

/** 再構成の既定値 (全ノード共通。変える必要があるのはテストだけ) */
export const REASSEMBLY_LIMITS = {
  /** 1 人の送り主 (Guard) が同時に持てる未完成の item 数 */
  MAX_PARTIAL_PER_SENDER: 4,
  /** 全体で同時に持てる未完成の item 数 */
  MAX_PARTIAL_TOTAL: 64,
  /** 最初の断片から全部揃うまでの猶予 (ms)。超えたら捨てる */
  TIMEOUT_MS: 10_000,
} as const;

interface Partial {
  sender: PeerId;
  total: number;
  parts: Array<Uint8Array | undefined>;
  count: number;
  startedAt: number;
}

/**
 * FragmentReassembler — M1 で、同じ Guard から届いた断片を item に戻す。
 *
 * ★ 鍵は (送り主 = セルを中継してきた Guard, 断片 id)。別の隣人が同じ id を名乗って
 *   他人の断片に割り込むことはできない。
 * ★ 隣人 1 人がメモリを使い切れないように、送り主ごと・全体の未完成数と猶予を限る。
 *   上限に達したら**新しい** item を拒否する (既に集めているものは追い出さない)。
 * ★ 不整合 (total の食い違い・idx の重複・断片長の不正) を見たら、その item を丸ごと捨てる。
 *   途中の item は作者のエコー待ちが切れて、別の M1 への再送で救われる。
 */
export class FragmentReassembler {
  private partials = new Map<string, Partial>();
  private perSender = new Map<PeerId, number>();

  constructor(
    private limits: { MAX_PARTIAL_PER_SENDER: number; MAX_PARTIAL_TOTAL: number; TIMEOUT_MS: number } = REASSEMBLY_LIMITS,
  ) {}

  get size(): number {
    return this.partials.size;
  }

  /** @returns 全断片が揃って整合したときだけ、連結したバイト列 */
  public add(sender: PeerId, frag: Fragment, now: number = Date.now()): Uint8Array | null {
    this.sweep(now);

    if (!this.wellFormed(frag)) return null;
    const key = `${sender}:${Encoding.toHex(frag.id)}`;
    let p = this.partials.get(key);

    if (!p) {
      if (this.partials.size >= this.limits.MAX_PARTIAL_TOTAL) return null;
      if ((this.perSender.get(sender) ?? 0) >= this.limits.MAX_PARTIAL_PER_SENDER) return null;
      p = { sender, total: frag.total, parts: new Array(frag.total).fill(undefined), count: 0, startedAt: now };
      this.partials.set(key, p);
      this.perSender.set(sender, (this.perSender.get(sender) ?? 0) + 1);
    }

    if (p.total !== frag.total || p.parts[frag.idx] !== undefined) {
      this.drop(key);
      return null;
    }
    p.parts[frag.idx] = frag.data;
    p.count++;
    if (p.count < p.total) return null;

    this.drop(key);
    // 先頭から total-1 枚目までは満杯、最後は 1..満杯。splitIntoFragments が作る形だけを受け付ける
    for (let i = 0; i < p.total - 1; i++) {
      if (p.parts[i]!.length !== OnionRouter.FRAG_DATA_MAX) return null;
    }
    let len = 0;
    for (const part of p.parts) len += part!.length;
    const out = new Uint8Array(len);
    let o = 0;
    for (const part of p.parts) {
      out.set(part!, o);
      o += part!.length;
    }
    return out;
  }

  /** 猶予を過ぎた未完成の item を捨てる */
  public sweep(now: number = Date.now()): void {
    for (const [key, p] of this.partials) {
      if (now - p.startedAt > this.limits.TIMEOUT_MS) this.drop(key);
    }
  }

  public clear(): void {
    this.partials.clear();
    this.perSender.clear();
  }

  private wellFormed(f: Fragment): boolean {
    return (
      Number.isInteger(f.total) && f.total >= 1 && f.total <= MAX_FRAGMENTS &&
      Number.isInteger(f.idx) && f.idx >= 0 && f.idx < f.total &&
      f.data.length >= 1 && f.data.length <= OnionRouter.FRAG_DATA_MAX
    );
  }

  private drop(key: string): void {
    const p = this.partials.get(key);
    if (!p) return;
    this.partials.delete(key);
    const n = (this.perSender.get(p.sender) ?? 1) - 1;
    if (n > 0) this.perSender.set(p.sender, n);
    else this.perSender.delete(p.sender);
  }
}

import type { IPeerManager, PeerId } from '../../types';
import type { OnionHop } from '../../crypto/OnionRouter';
import type { GuardPolicy } from '../../trust/GuardManager';

/**
 * DandelionRouter — 発信経路の「状態」だけを持つ。
 *
 * ★ 平文 Stem による発信は撤去した (C2 / C3 / C4)。
 *
 *   旧実装は Gossip 本体をオニオンで送る一方、同じ投稿の Slot (DHT_PUT_STEM) と
 *   索引 (HINT_STEM) を平文 Stem で並行に送っており、隣人 1 人がオニオンを
 *   丸ごと迂回して発信元を推定できた。Stem の失敗時には平文 flood へ
 *   落ちる経路も残っていた。
 *
 *   現在、作者が網へ出すものはすべて {@link ../onion/OnionCircuit} が
 *   cover traffic に混ぜた固定長セルとして運ぶ。このクラスに残っているのは
 *     - Guard の固定 (Guard Pinning)
 *     - エコー (自分の発信が網に現れたか) の待ち合わせ
 *   だけである。
 */
export const DANDELION_CONFIG = {
  /**
   * Guard を固定する期間。
   *
   * ★ 旧実装は 15 分で交代させていた。隣人 16 人のうち 1 人が攻撃者なら、
   *   数時間以内に必ず Guard の座が回ってくる。Guard は「誰が作者か」を
   *   最も知りやすい位置なので、交代は少ないほどよい。
   *   切断されるまで同じ Guard を使い続ける (Tor の Entry Guard と同じ考え方)。
   */
  GUARD_PIN_DURATION: Number.POSITIVE_INFINITY,
};

type EchoCallback = () => void;

export class DandelionRouter {
  private pinnedGuardId: PeerId | null = null;
  private pinnedGuardExpiry: number = 0;
  private listeners: Map<string, Array<EchoCallback>> = new Map();
  private guardListeners: Array<(guard: PeerId | null) => void> = [];

  /**
   * @param policy Guard の方針 (信頼 Guard の優先・起動直後の選択待ち)。
   *   省略すると、従来どおり「候補から重みづけで即決」になる。
   *   ★ 本番 (OzNode) は必ず渡す。省略はテストの単純化のためだけにある。
   */
  constructor(private peerManager: IPeerManager, private policy: GuardPolicy | null = null) {}

  /**
   * エコーを通知 (自分の発信したものが網に現れた)
   */
  public notifyEcho(id: string): void {
    const key = `echo:${id}`;
    const callbacks = this.listeners.get(key);
    if (callbacks) {
      this.listeners.delete(key);
      callbacks.forEach(cb => cb());
    }
  }

  /**
   * エコーを待つ。届けば true、timeoutMs を過ぎれば false。
   */
  public awaitEcho(id: string, timeoutMs: number): Promise<boolean> {
    const key = `echo:${id}`;
    return new Promise((resolve) => {
      const callback = () => {
        clearTimeout(timeout);
        resolve(true);
      };
      const timeout = setTimeout(() => {
        // 自分のコールバックだけを外す。キーごと消すと、同じ id を待つ
        // 他の待機者のエコーまで取りこぼす。
        const remaining = (this.listeners.get(key) ?? []).filter(cb => cb !== callback);
        if (remaining.length > 0) this.listeners.set(key, remaining);
        else this.listeners.delete(key);
        resolve(false);
      }, timeoutMs);

      const list = this.listeners.get(key) ?? [];
      list.push(callback);
      this.listeners.set(key, list);
    });
  }

  /**
   * Guard Sticky Pinning:
   * 直結隣人から第1ホップ (Guard) を選定し、切断されるまで固定する。
   *
   * ★ 送信の失敗では Guard を交代させない。
   *   旧実装は配送失敗のたびに resetPinnedGuard() で Guard を引き直していたため、
   *   下流でセルを捨てるだけで作者に Guard を何度でも選び直させられた
   *   (= 攻撃者が Guard の座を取るまで抽選を回させる)。
   */
  public getPinnedGuard(candidates: OnionHop[]): OnionHop | null {
    if (this.policy) return this.getPinnedGuardWithPolicy(candidates);

    const now = Date.now();
    const isLive = this.isPinnedLive(candidates, now);

    if (isLive) {
      return candidates.find(c => c.peerId === this.pinnedGuardId)!;
    }

    if (candidates.length === 0) {
      if (this.pinnedGuardId !== null && !this.peerManager.peers.has(this.pinnedGuardId)) {
        this.setGuard(null, 0);
      }
      return null;
    }
    const selected = candidates[secureWeightedIndex(candidates.map(c => guardWeight(this.peerManager.peers, c.peerId, now)))];
    this.setGuard(selected.peerId, now + DANDELION_CONFIG.GUARD_PIN_DURATION);
    return selected;
  }

  private isPinnedLive(candidates: OnionHop[], now: number): boolean {
    return (
      this.pinnedGuardId !== null &&
      now < this.pinnedGuardExpiry &&
      this.peerManager.peers.has(this.pinnedGuardId) &&
      candidates.some(c => c.peerId === this.pinnedGuardId)
    );
  }

  /**
   * 方針つきの Guard 選択。選ぶ規則は {@link GuardPolicy} が持ち、ここでは
   * 固定の状態 (pin) の更新と、変更の通知だけを行う。
   *
   * 方針が null を返したら (待機中・条件未達・失効された Guard)、固定は外す。
   * 送信側 (OnionCircuit) は null を見て送らない (fail-closed)。
   */
  private getPinnedGuardWithPolicy(candidates: OnionHop[]): OnionHop | null {
    const policy = this.policy!;
    const now = policy.now();
    const livePinned = this.isPinnedLive(candidates, now) ? this.pinnedGuardId : null;
    const selected = policy.select(candidates, this.peerManager.peers, now, livePinned);
    if (!selected) {
      if (this.pinnedGuardId !== null) this.setGuard(null, 0);
      return null;
    }
    // 同じ Guard のままなら pin は触らない。替わるとき (信頼 Guard への乗り換えを含む) は
    // setGuard が onGuardChange を発火し、OnionCircuit が前の Guard の隣人表を捨てる。
    if (selected.peerId !== this.pinnedGuardId) {
      this.setGuard(selected.peerId, now + DANDELION_CONFIG.GUARD_PIN_DURATION);
    }
    return selected;
  }

  public getPinnedGuardId(): PeerId | null {
    return this.pinnedGuardId;
  }

  /** 明示的な Guard の破棄 (Guard 本人の不正が確定した場合など)。配送失敗では呼ばない */
  public resetPinnedGuard(): void {
    this.setGuard(null, 0);
  }

  /** Guard が変わったときの通知 (Guard の隣人表を作り直すため) */
  public onGuardChange(cb: (guard: PeerId | null) => void): void {
    this.guardListeners.push(cb);
  }

  private setGuard(id: PeerId | null, expiry: number): void {
    const changed = id !== this.pinnedGuardId;
    this.pinnedGuardId = id;
    this.pinnedGuardExpiry = expiry;
    if (changed) this.guardListeners.forEach(cb => cb(id));
  }
}

/** 観測期間による重みが飽和するまでの時間 (Guard / 出口の選択で共通) */
export const OBSERVATION_SATURATION_MS = 30 * 60 * 1000;

/**
 * Guard 候補の重み (A3)。拒否はせず、選ばれやすさだけを変える。
 *
 * - 自分で選んで張った接続 (outbound) を 3 倍に重くする。Sybil は inbound なら
 *   好きなだけ送り込めるが、こちらが選ぶ outbound の相手は自由にできない。
 *   起動直後はどの隣人も観測期間がほぼ 0 なので、ここが主な効き目になる。
 * - 本人確認からの経過時間 (最大 30 分) で最大 2 倍まで重くする。
 *   作ったばかりの Sybil は Guard に選ばれにくくなる。
 *
 * 観測履歴は端末に保存しない (どのノードとつながっていたかが押収時の痕跡になる)。
 */
export function guardWeight(peers: IPeerManager['peers'], peerId: PeerId, now: number): number {
  const peer: any = peers.get(peerId);
  const directionWeight = peer?.direction === 'outbound' ? 3 : 1;
  const age = typeof peer?.verifiedAt === 'number' ? Math.max(0, now - peer.verifiedAt) : 0;
  return directionWeight * (1 + Math.min(age, OBSERVATION_SATURATION_MS) / OBSERVATION_SATURATION_MS);
}

/** 重みに比例した暗号論的乱数インデックス。重みはすべて正であること */
export function secureWeightedIndex(weights: number[]): number {
  const total = weights.reduce((a, w) => a + w, 0);
  if (!(total > 0)) return secureRandomIndex(weights.length);
  const r = (crypto.getRandomValues(new Uint32Array(1))[0] / 0x100000000) * total;
  let acc = 0;
  for (let i = 0; i < weights.length; i++) {
    acc += weights[i];
    if (r < acc) return i;
  }
  return weights.length - 1;
}

/** 偏りの無い暗号論的乱数インデックス */
export function secureRandomIndex(n: number): number {
  if (n <= 1) return 0;
  const limit = Math.floor(0x100000000 / n) * n;
  const buf = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buf);
    if (buf[0] < limit) return buf[0] % n;
  }
}

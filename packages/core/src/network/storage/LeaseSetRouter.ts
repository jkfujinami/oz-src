import type { IMessageDispatcher, IPeerManager, PeerId } from '../../types';
import type { DandelionRouter } from '../gossip/DandelionRouter';
import { SeenCache } from '../gossip/SeenCache';
import { WireType } from '../wire/WireTypes';
import { MAX_LEASESET_FRAME_BYTES } from '../wire/WireCodec';
import { MINUTE_MS, msToMinutes } from '../../crypto/PowPolicy';
import sodium from '../../crypto/sodium';
import { createLogger } from '../../common/Logger';
import {
  LEASESET_LIFETIME_MS, LEASESET_PUBLISH_GAP_MS, LEASESET_REPUBLISH_MS, decodeLeaseSet, leaseSetId, signLeaseSet, verifyLeaseSet,
  type LeaseSetRejection,
} from './LeaseSet';
import type { LeaseSetStore } from './LeaseSetStore';
import type { SlotSolution } from './SlotPow';

const log = createLogger('net.storage.leaseset');

export const LEASESET_ROUTER_LIMITS = {
  /** 同じ相手の SYNC_REQ を受け付ける最短間隔 (ms)。1 回の応答は 数 MB になりうる */
  SYNC_MIN_INTERVAL_MS: 60_000,
  /** SYNC の送出間隔 (ms)。1 フレーム 16KiB × 約 16 回/秒 = 約 256KiB/秒。受け手の枠 (RATE_LIMITS.leaseset) に収まる */
  SYNC_FRAME_INTERVAL_MS: 60,
  /** 同時に応答する相手の数。超えたら無視する (相手は次の機会に頼み直す) */
  MAX_SYNC_SESSIONS: 8,
  /** SYNC を待つ時間 (最後のフレームまたは要求から)。過ぎたら以後の SYNC は受け付けない */
  SYNC_WAIT_MS: 5 * MINUTE_MS,
  /** 期限切れの掃除の間隔 */
  PRUNE_INTERVAL_MS: MINUTE_MS,
} as const;

/** 自分の leaseSet の材料 (StorageService が与える) */
export interface LeaseSetSource {
  readonly publicKey: Uint8Array;
  sign(message: Uint8Array): Uint8Array;
  /** いま公開する枠 (容量の範囲内で解き終わったもの) */
  slots(): SlotSolution[];
}

export interface LeaseSetRouterOptions {
  now?: () => number;
  /** ★ テスト専用 */
  slotEffort?: number;
  syncMinIntervalMs?: number;
  syncFrameIntervalMs?: number;
}

interface SyncSession {
  items: Uint8Array[];
  next: number;
  timer: ReturnType<typeof setTimeout> | null;
}

/**
 * LeaseSetRouter — leaseSet の配布 (flood と新参者への一括送信) と、自分の leaseSet の発行 (history v2 §4.2)。
 *
 *   LEASESET            flood。新しく (より遅い期限で) 入ったものだけ、送ってきた相手以外の全隣人へ中継する
 *   LEASESET_SYNC_REQ   1 ホップ目 (固定した Guard) が検証済みになったら 1 回。「手持ちを全部ください」
 *   LEASESET_SYNC       応答。期限内の全 leaseSet を 16KiB 未満のフレームに分けて、間隔を空けて送る
 *
 * ★ GossipRouter を通さない。投稿の flood と状態 (SeenCache・レート制限の枠) を分け、leaseSet の洪水が
 *   投稿の中継を詰まらせない・その逆も起きないようにする。SeenCache は leaseSet のバイト列の hash を id にする。
 * ★ SYNC で届いたものは**中継しない** (追いつきと同じ。全員が自分で頼むので、中継すると嵐になる)。
 *   検証は flood と同じ。頼んでいない相手からの SYNC は無視する。
 * ★ 受け口 (gateway) = 自分の 1 ホップ目に固定した Guard。信頼 Guard のリストが有効なら、信頼 Guard でない
 *   1 ホップ目 (警告状態) では**発行しない** (他の端末が受け付けないので無意味。IP の無い宣言だが、
 *   信頼できない相手を受け口にしたことを網に宣言させない)。
 * ★ tunnelId は (SID, gateway) の組ごとの乱数 8 バイト。Guard が替わったら別の tunnelId にする
 *   (組を跨いで紐付けられない)。受け口への登録 (TUNNEL_REGISTER) は TunnelHolder が、発行のたびに行う。
 * ★ 出し直しは**最短 LEASESET_PUBLISH_GAP_MS (10 分 30 秒) ごと**。受け手は同じ SID の置き換えを 10 分に 1 回しか
 *   受け付けない (LeaseSetStore) ので、それより速く出しても捨てられるだけで、flood を水増しする (オープンの網では
 *   受け口を毎回変えて出せてしまう)。間隔が足りないときは**遅らせて 1 本にまとめる** (枠が 1 つ解けるたび・
 *   Guard の交代のたびに出さない)。待つ間の leaseSet は古い受け口を指すが、読み手は別の保持者へ回る (hedge)。
 */
export class LeaseSetRouter {
  private readonly seen = new SeenCache();
  private readonly now: () => number;
  private readonly opts: Required<Omit<LeaseSetRouterOptions, 'now' | 'slotEffort'>> & { slotEffort?: number };
  private sessions = new Map<PeerId, SyncSession>();
  private lastSyncServed = new Map<PeerId, number>();
  /** SYNC を頼んだ相手 → 受け付ける期限 */
  private awaiting = new Map<PeerId, number>();
  /** 頼み済みの相手 (切れるまで頼み直さない) */
  private requested = new Set<PeerId>();
  private tunnelIds = new Map<string, Uint8Array>();
  private lastExpiresMin = 0;
  private lastPublishedGateway: string | null = null;
  /** 最後に出した時刻 (ms)。出したことがなければ null (最初の 1 件は待たない) */
  private lastPublishedAt: number | null = null;
  private deferTimer: ReturnType<typeof setTimeout> | null = null;
  private publishListeners: Array<(tunnel: { gateway: string; tunnelId: Uint8Array }) => void> = [];
  private publishTimer: ReturnType<typeof setInterval> | null = null;
  private pruneTimer: ReturnType<typeof setInterval> | null = null;
  private started = false;
  private destroyed = false;

  /** 診断・テスト用: 受け付けた / 拒否した件数 */
  public readonly stats = { accepted: 0, stale: 0, tooSoon: 0, deferred: 0, rejected: new Map<LeaseSetRejection | 'malformed', number>(), published: 0 };

  private readonly onVerified = (peer: { peerId: PeerId }) => {
    if (peer?.peerId === this.dandelion.getPinnedGuardId()) this.maybeRequestSync();
  };
  private readonly onDisconnect = (peerId: PeerId) => {
    this.forgetPeer(peerId);
  };
  private readonly onGuardChange = () => {
    this.maybeRequestSync();
    if (this.started) this.publish();
  };

  constructor(
    private readonly peerManager: IPeerManager,
    dispatcher: IMessageDispatcher,
    private readonly dandelion: DandelionRouter,
    private readonly store: LeaseSetStore,
    private readonly source: LeaseSetSource | null,
    /** 受け口として認める peerId か (信頼リスト有効なら信頼 Guard のみ。open なら誰でも) */
    private readonly gatewayAllowed: (peerId: string) => boolean,
    options: LeaseSetRouterOptions = {},
  ) {
    this.now = options.now ?? Date.now;
    this.opts = {
      syncMinIntervalMs: options.syncMinIntervalMs ?? LEASESET_ROUTER_LIMITS.SYNC_MIN_INTERVAL_MS,
      syncFrameIntervalMs: options.syncFrameIntervalMs ?? LEASESET_ROUTER_LIMITS.SYNC_FRAME_INTERVAL_MS,
      slotEffort: options.slotEffort,
    };
    dispatcher.register(WireType.LEASESET, (peerId, msg) => this.handleLeaseSet(peerId, msg));
    dispatcher.register(WireType.LEASESET_SYNC_REQ, (peerId) => this.handleSyncReq(peerId));
    dispatcher.register(WireType.LEASESET_SYNC, (peerId, msg) => this.handleSync(peerId, msg));
    peerManager.on('peer:verified', this.onVerified);
    peerManager.on('peer:disconnect', this.onDisconnect);
    dandelion.onGuardChange(this.onGuardChange);
  }

  /** 発行と掃除のタイマーを動かす。2 時間ごとに leaseSet を出し直す */
  public start(): void {
    if (this.started || this.destroyed) return;
    this.started = true;
    this.publishTimer = setInterval(() => this.publish(), LEASESET_REPUBLISH_MS);
    this.pruneTimer = setInterval(() => this.store.prune(), LEASESET_ROUTER_LIMITS.PRUNE_INTERVAL_MS);
    this.maybeRequestSync();
    this.publish();
  }

  // ── 自分の leaseSet ──

  /**
   * 自分の leaseSet を作って、手元に入れて、flood する。受け口が無い・認められない・枠が無いときは何もしない。
   * 枠が増えた / 受け口が替わった / 2 時間経った、のどれでも呼ぶ。
   * 前に出してから LEASESET_PUBLISH_GAP_MS 経っていなければ、その時刻まで遅らせる (戻り値は null。重ねて呼んでも 1 本)。
   * @returns 発行したバイト列 (しなかったら null)
   */
  public publish(): Uint8Array | null {
    if (this.destroyed || !this.source) return null;
    const gateway = this.dandelion.getPinnedGuardId();
    if (!gateway) return null;
    if (!this.gatewayAllowed(gateway)) {
      log.debug(() => 'not publishing: the first hop is not an accepted gateway (warning state)');
      return null;
    }
    const slots = this.source.slots();
    if (slots.length === 0) return null;

    const nowMs = this.now();
    if (this.lastPublishedAt !== null && nowMs - this.lastPublishedAt < LEASESET_PUBLISH_GAP_MS) {
      if (!this.deferTimer) {
        this.stats.deferred++;
        const wait = Math.max(1, LEASESET_PUBLISH_GAP_MS - (nowMs - this.lastPublishedAt));
        this.deferTimer = setTimeout(() => {
          this.deferTimer = null;
          this.publish();
        }, wait);
      }
      return null;
    }
    // 期限は分単位。同じ分に 2 回出すと「より新しい」にならず他の端末が捨てるので、必ず前より進める
    const nowMin = msToMinutes(nowMs);
    const expiresMin = Math.max(nowMin + LEASESET_LIFETIME_MS / MINUTE_MS, this.lastExpiresMin + 1);
    // 受け手の許容 (6 時間 + 時計のずれ 15 分) を超える連続発行は黙って見送る
    if (expiresMin > nowMin + LEASESET_LIFETIME_MS / MINUTE_MS + 15) return null;

    let tunnelId = this.tunnelIds.get(gateway);
    if (!tunnelId) {
      tunnelId = sodium.randombytes_buf(8);
      this.tunnelIds.set(gateway, tunnelId);
    }
    const bytes = signLeaseSet(
      { sid: this.source.publicKey, slots, gateway, tunnelId, expiresMin },
      (m) => this.source!.sign(m),
    );
    const ls = decodeLeaseSet(bytes)!;
    this.lastExpiresMin = expiresMin;
    this.lastPublishedGateway = gateway;
    this.lastPublishedAt = nowMs;
    if (this.deferTimer) {
      clearTimeout(this.deferTimer);
      this.deferTimer = null;
    }
    this.seen.add(leaseSetId(bytes));
    this.store.add(ls);
    this.stats.published++;
    this.flood(bytes, null);
    log.debug(() => `published a leaseSet (${slots.length} slot(s))`);
    for (const cb of this.publishListeners) {
      try { cb({ gateway, tunnelId }); } catch (e) { log.warn('publish listener failed', e); }
    }
    return bytes;
  }

  /** leaseSet を出すたびに呼ぶ (受け口と tunnelId)。TunnelHolder が受け口へ登録するのに使う */
  public onPublished(cb: (tunnel: { gateway: string; tunnelId: Uint8Array }) => void): void {
    this.publishListeners.push(cb);
  }

  /** 発行済みの受け口。B-b2 が tunnelId を登録するのに使う */
  public get currentTunnel(): { gateway: string; tunnelId: Uint8Array } | null {
    const g = this.lastPublishedGateway;
    const t = g ? this.tunnelIds.get(g) : undefined;
    return g && t ? { gateway: g, tunnelId: t } : null;
  }

  // ── 受信 ──

  private reject(reason: LeaseSetRejection | 'malformed'): void {
    this.stats.rejected.set(reason, (this.stats.rejected.get(reason) ?? 0) + 1);
  }

  /** 検証して手元に入れる。新しく入ったら true (中継してよい) */
  private accept(bytes: Uint8Array): boolean {
    const ls = decodeLeaseSet(bytes);
    if (!ls) { this.reject('malformed'); return false; }
    const verdict = verifyLeaseSet(ls, {
      nowMs: this.now(),
      gatewayAllowed: this.gatewayAllowed,
      slotEffort: this.opts.slotEffort,
    });
    if (!verdict.ok) { this.reject(verdict.reason); return false; }
    const res = this.store.add(ls);
    if (res === 'stale') { this.stats.stale++; return false; }
    // ★ 前に受け付けてから 10 分未満の置き換え: 入れず、中継もしない (署名し直しによる flood の水増しを止める)
    if (res === 'too-soon') { this.stats.tooSoon++; return false; }
    this.stats.accepted++;
    return true;
  }

  private handleLeaseSet(senderId: PeerId, msg: any): void {
    if (this.destroyed) return;
    const bytes: unknown = msg?.leaseSet;
    if (!(bytes instanceof Uint8Array)) return;
    const id = leaseSetId(bytes);
    // ★ 検証の前に「見た」ことにする。同じ不正なバイト列を何度送られても、署名検証と PoW 検証は 1 回で済む
    if (this.seen.has(id)) return;
    this.seen.add(id);
    if (this.accept(bytes)) this.flood(bytes, senderId);
  }

  private flood(bytes: Uint8Array, exclude: PeerId | null): void {
    for (const peer of this.peerManager.peers.values()) {
      if (peer.peerId === exclude) continue;
      if (!peer.isConnected || !peer.isVerified) continue;
      this.peerManager.sendMessage(peer.peerId, WireType.LEASESET, { leaseSet: bytes });
    }
  }

  // ── 新参者への一括送信 ──

  private maybeRequestSync(): void {
    if (this.destroyed) return;
    const id = this.dandelion.getPinnedGuardId();
    if (!id || this.requested.has(id)) return;
    const peer = this.peerManager.peers.get(id);
    if (!peer || !peer.isConnected || !peer.isVerified) return;
    this.requested.add(id);
    this.awaiting.set(id, this.now() + LEASESET_ROUTER_LIMITS.SYNC_WAIT_MS);
    this.peerManager.sendMessage(id, WireType.LEASESET_SYNC_REQ, {});
  }

  private handleSyncReq(peerId: PeerId): void {
    if (this.destroyed) return;
    const peer = this.peerManager.peers.get(peerId);
    if (!peer || !peer.isConnected || !peer.isVerified) return;
    const now = this.now();
    const last = this.lastSyncServed.get(peerId);
    if (this.sessions.has(peerId) || (last !== undefined && now - last < this.opts.syncMinIntervalMs)) return;
    if (this.sessions.size >= LEASESET_ROUTER_LIMITS.MAX_SYNC_SESSIONS) return;
    this.lastSyncServed.set(peerId, now);
    const items = this.store.allBytes();
    if (items.length === 0) return;
    this.sessions.set(peerId, { items, next: 0, timer: null });
    this.pump(peerId);
  }

  /** 1 フレーム (16KiB 未満) ずつ、間隔を空けて送る */
  private pump(peerId: PeerId): void {
    const s = this.sessions.get(peerId);
    if (!s || this.destroyed) return;
    s.timer = null;
    const peer = this.peerManager.peers.get(peerId);
    if (!peer || !peer.isConnected) {
      this.forgetPeer(peerId);
      return;
    }
    // type 1 + 件数 2 を除いた本体に、(長さ 2 + 本体) を詰められるだけ詰める
    let used = 3;
    const batch: Uint8Array[] = [];
    while (s.next < s.items.length) {
      const cost = 2 + s.items[s.next].length;
      if (used + cost > MAX_LEASESET_FRAME_BYTES) break;
      used += cost;
      batch.push(s.items[s.next++]);
    }
    if (batch.length > 0) this.peerManager.sendMessage(peerId, WireType.LEASESET_SYNC, { leaseSets: batch });
    if (s.next >= s.items.length) {
      this.sessions.delete(peerId);
      return;
    }
    s.timer = setTimeout(() => this.pump(peerId), this.opts.syncFrameIntervalMs);
  }

  private handleSync(senderId: PeerId, msg: any): void {
    if (this.destroyed) return;
    const until = this.awaiting.get(senderId);
    if (until === undefined) return; // 頼んでいない相手からは受け取らない
    const now = this.now();
    if (now > until) {
      this.awaiting.delete(senderId);
      return;
    }
    const sets: unknown = msg?.leaseSets;
    if (!Array.isArray(sets)) return;
    this.awaiting.set(senderId, now + LEASESET_ROUTER_LIMITS.SYNC_WAIT_MS);
    for (const bytes of sets) {
      if (!(bytes instanceof Uint8Array)) continue;
      const id = leaseSetId(bytes);
      if (this.seen.has(id)) continue;
      this.seen.add(id);
      this.accept(bytes); // 中継はしない
    }
  }

  private forgetPeer(peerId: PeerId): void {
    const s = this.sessions.get(peerId);
    if (s?.timer) clearTimeout(s.timer);
    this.sessions.delete(peerId);
    this.lastSyncServed.delete(peerId);
    this.awaiting.delete(peerId);
    this.requested.delete(peerId);
  }

  public destroy(): void {
    this.destroyed = true;
    if (this.publishTimer) clearInterval(this.publishTimer);
    if (this.pruneTimer) clearInterval(this.pruneTimer);
    if (this.deferTimer) clearTimeout(this.deferTimer);
    this.deferTimer = null;
    this.publishTimer = null;
    this.pruneTimer = null;
    for (const id of Array.from(this.sessions.keys())) this.forgetPeer(id);
    this.peerManager.off('peer:verified', this.onVerified);
    this.peerManager.off('peer:disconnect', this.onDisconnect);
    this.seen.destroy();
  }
}

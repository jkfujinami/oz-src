import type { GossipPacket, IPeerManager, PeerId } from '../../types';
import { createLogger } from '../../common/Logger';
import { decodePacket } from '../../crypto/PacketCodec';
import { DAY_MS, POW_POLICY } from '../../crypto/PowPolicy';
import { PacketValidator } from '../gossip/PacketValidator';
import { R_QUERY, birthDayOf, type Duty } from '../storage/Duty';
import type { LeaseSetStore } from '../storage/LeaseSetStore';
import { TUNNEL_KIND, decryptChunk, newRespKey, sealRequest } from '../tunnel/TunnelCrypto';
import type { TunnelClient } from '../tunnel/TunnelClient';
import {
  FETCH_MAX_ACCEPT_BYTES, FETCH_STATUS, decodeFetchResponse, encodeFetchRequest, type FetchResponse,
} from './FetchBucket';

const log = createLogger('net.history.client');

export const HISTORY_LIMITS = {
  /** 最初の 2 台へ頼んでから、遅ければ次の 1 台へ回すまで (hedged request) */
  HEDGE_MS: 4_000,
  /** 1 回の要求で、応答の片が 1 つも届かないまま待つ上限 */
  INACTIVITY_MS: 15_000,
  /** 1 回の取得で頼む保持者の数の上限 */
  MAX_ATTEMPTS: 8,
  /** 最初に同時に頼む数と、同時に頼む数の上限 (hedge を含む) */
  INITIAL_PARALLEL: 2,
  MAX_PARALLEL: 3,
  /** 1 台の保持者に続きを頼む回数の上限 (1 回 4MiB まで) */
  MAX_PAGES: 8,
  /** 1 回の応答で受け付ける片の数 (4MiB / 15KiB ≒ 274 に余裕) */
  MAX_CHUNKS: 320,
  /** 復号できない片がこれだけ来たら、その要求は諦める (経路の途中で改ざんされている) */
  MAX_BAD_CHUNKS: 3,
  /** 1 ホップ目がつながるのを待つ上限 */
  READY_WAIT_MS: 60_000,
  /** 保持者の leaseSet が手元に届くのを待つ上限 (新しい端末は 1 ホップ目からの一括送信 (SYNC) を待つ) */
  HOLDERS_WAIT_MS: 15_000,
  HOLDERS_POLL_MS: 1_000,
  /** 同時に走らせる取得の数 (板の週別 + スレ) */
  MAX_CONCURRENT_FETCHES: 4,
  /** 速さの記録の上限 (メモリだけ) */
  SPEED_MEMORY: 2048,
  /** 失敗した保持者に付ける、速さの代わりの値 (ms)。次回から後回しになる */
  FAIL_PENALTY_MS: 60_000,
} as const;

/**
 * 受け付ける投稿の古さの上限。保持は 90 日 (スレ立てから) で、バケットの birthDay の日の 0 時から数えて
 * 最大 90 日 + その日の残り (1 日) + 時刻のずれ。追いつき (72 時間 + 15 分) より広い。
 */
export const FETCH_MAX_PAST_MS = (POW_POLICY.MAX_AGE_DAYS + 1) * DAY_MS + POW_POLICY.MAX_TIME_DRIFT;

export interface FetchOptions {
  /** この時刻 (OZ_EPOCH からの分) 以降を取る。省略は 0 (全部) */
  since?: number;
  /** 投稿が届くたびに (これまでに受け取った件数) */
  onProgress?: (received: number) => void;
  /** 中止 (画面を閉じた・別のスレに移った) */
  signal?: AbortSignal;
}

export type FetchReason = 'ok' | 'no-first-hop' | 'no-holders' | 'exhausted' | 'aborted';

export interface FetchResult {
  /** どれかの保持者から、最後まで受け取れた */
  completed: boolean;
  /** 検証を通って手元へ配った投稿の数 (重複を除く) */
  packets: number;
  /** 頼んだ保持者の数 */
  attempts: number;
  reason: FetchReason;
}

/** オーケストレータが必要とする窓口 (HistoryClient の一部。テストでは差し替える) */
export type HistoryFetcher = Pick<HistoryClient, 'fetchBucket' | 'onReady'>;

export interface HistoryClientParts {
  tunnel: Pick<TunnelClient, 'request' | 'firstHop'>;
  peerManager: Pick<IPeerManager, 'on' | 'off'>;
  dandelion: { getPinnedGuardId(): PeerId | null; onGuardChange(cb: (g: PeerId | null) => void): void };
  duty: Pick<Duty, 'closestSlots'>;
  leaseSets: Pick<LeaseSetStore, 'get'>;
  /** 検証を通った投稿を手元へ配る (GossipRouter.deliverFetched)。flood しない */
  deliver: (packet: GossipPacket) => void;
  /** 自分の SID (hex)。自分自身には頼まない (自分の保管は deliver のフックが担う) */
  ownSid: () => string | null;
  now?: () => number;
  /** 乱数 [0,1)。速さの記録がない保持者の順番に使う */
  random?: () => number;
  /** ★ テスト専用 */
  limits?: Partial<{ hedgeMs: number; inactivityMs: number; readyWaitMs: number; holdersWaitMs: number; holdersPollMs: number; maxAttempts: number }>;
}

interface Candidate {
  sid: string;
  sidBytes: Uint8Array;
  gateway: PeerId;
  tunnelId: Uint8Array;
}

/** 1 回の取得の状態 */
interface Ctx {
  birthDay: number;
  tag: number;
  since: number;
  seen: Set<string>;
  received: number;
  rejected: number;
  done: boolean;
  onProgress?: (n: number) => void;
  /** 走っている要求の取り消し */
  cancels: Set<() => void>;
}

/**
 * HistoryClient — 保管担当 (保持者) から過去ログのバケットを取る (history v2 §4.5)。
 *
 *   (birthDay, tag, since) → バケットに近い 64 枠 → 保持者 (SID で重複を除く) → 速い順 (記録が無ければ乱数)
 *   → 2 台へ同時に頼む → 4 秒たっても完了しなければ 3 台目へ (hedged request) → どれかが最後まで返したら止める
 *
 * ★ 要求は自分の 1 ホップ目へだけ送る (TunnelClient)。保持者の受け口 (leaseSet の gateway) への経路は 1 ホップ目の仕事。
 *   保持者の IP は見えず、保持者にも自分の peerId は渡らない。要求と応答は保持者の鍵で端から端まで暗号化される。
 * ★ 届いた投稿は**手元で検証**してから配る: PoW・packet_id・時刻 (未来は 15 分まで、過去は 91 日 + 15 分まで)・
 *   要求したバケット (birthDay・tag) に属すること。1 件でも通らない保持者は偽物として、その保持者の応答を打ち切る。
 *   再 flood はしない (GossipRouter.deliverFetched)。
 * ★ 完了の判定: 状態 OK (since 以降を全部送った) で、かつ since = 0 (全部取る) なら 1 件以上あること。since = 0 で空の OK は、
 *   担当のふりをして黙っている保持者かもしれないので、次の保持者へ回る。状態 NOT_HELD も次へ。
 * ★ 速さは手元のメモリだけに記録する (保持者の SID → 完了までの ms の移動平均)。ディスクには書かない。
 *   失敗は大きな値を付けて後回しにする。
 * ★ 残る弱点: 1 台が「OK」で一部だけ返しても検出できない (最も速い 1 台を信じる)。担当は 64 枠で、枠の PoW が
 *   Sybil の費用になる (docs/design/history-v2.md §5)。
 */
export class HistoryClient {
  private readonly now: () => number;
  private readonly random: () => number;
  private readonly lim: { hedgeMs: number; inactivityMs: number; readyWaitMs: number; holdersWaitMs: number; holdersPollMs: number; maxAttempts: number };
  private speeds = new Map<string, number>();
  private readyListeners = new Set<() => void>();
  private waiters: Array<() => void> = [];
  private running = 0;
  private destroyed = false;

  /** 診断・テスト用 */
  public readonly stats = { fetches: 0, attempts: 0, rejectedPackets: 0, badChunks: 0 };

  private readonly onVerified = (peer: { peerId: PeerId }) => {
    if (peer?.peerId && peer.peerId === this.parts.dandelion.getPinnedGuardId()) this.fireReady();
  };

  constructor(private readonly parts: HistoryClientParts) {
    this.now = parts.now ?? Date.now;
    this.random = parts.random ?? Math.random;
    const l = parts.limits ?? {};
    this.lim = {
      hedgeMs: l.hedgeMs ?? HISTORY_LIMITS.HEDGE_MS,
      inactivityMs: l.inactivityMs ?? HISTORY_LIMITS.INACTIVITY_MS,
      readyWaitMs: l.readyWaitMs ?? HISTORY_LIMITS.READY_WAIT_MS,
      holdersWaitMs: l.holdersWaitMs ?? HISTORY_LIMITS.HOLDERS_WAIT_MS,
      holdersPollMs: l.holdersPollMs ?? HISTORY_LIMITS.HOLDERS_POLL_MS,
      maxAttempts: l.maxAttempts ?? HISTORY_LIMITS.MAX_ATTEMPTS,
    };
    parts.peerManager.on('peer:verified', this.onVerified);
    parts.dandelion.onGuardChange((g) => { if (g && parts.tunnel.firstHop === g) this.fireReady(); });
  }

  // ── 1 ホップ目の準備 ──

  /** 1 ホップ目が使えるようになったとき (最初・再接続・Guard の交代) に呼ぶ。戻り値は購読解除 */
  public onReady(cb: () => void): () => void {
    this.readyListeners.add(cb);
    return () => { this.readyListeners.delete(cb); };
  }

  private fireReady(): void {
    for (const w of this.waiters.splice(0)) w();
    for (const cb of Array.from(this.readyListeners)) {
      try { cb(); } catch (e) { log.warn('ready listener failed', e); }
    }
  }

  private waitReady(signal?: AbortSignal): Promise<boolean> {
    if (this.parts.tunnel.firstHop) return Promise.resolve(true);
    return new Promise<boolean>((resolve) => {
      let settled = false;
      const done = (ok: boolean) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener('abort', onAbort);
        this.waiters = this.waiters.filter(w => w !== wake);
        resolve(ok);
      };
      const wake = () => done(!!this.parts.tunnel.firstHop);
      const onAbort = () => done(false);
      const timer = setTimeout(() => done(!!this.parts.tunnel.firstHop), this.lim.readyWaitMs);
      this.waiters.push(wake);
      signal?.addEventListener('abort', onAbort, { once: true });
    });
  }

  // ── 保持者の候補 ──

  private candidates(birthDay: number, tag: number): Candidate[] {
    const own = this.parts.ownSid();
    const seen = new Set<string>();
    const out: Candidate[] = [];
    for (const slot of this.parts.duty.closestSlots(birthDay, tag, R_QUERY)) {
      if (slot.sid === own || seen.has(slot.sid)) continue;
      seen.add(slot.sid);
      const ls = this.parts.leaseSets.get(slot.sid);
      if (!ls) continue;
      out.push({ sid: slot.sid, sidBytes: ls.sid, gateway: ls.gateway, tunnelId: ls.tunnelId });
    }
    return out;
  }

  /** 速さの記録がある保持者を速い順に、無い保持者を乱数の順にその後ろへ */
  private rank(cands: Candidate[]): Candidate[] {
    const known = cands.filter(c => this.speeds.has(c.sid)).sort((a, b) => this.speeds.get(a.sid)! - this.speeds.get(b.sid)!);
    const unknown = cands.filter(c => !this.speeds.has(c.sid));
    for (let i = unknown.length - 1; i > 0; i--) {
      const j = Math.floor(this.random() * (i + 1));
      [unknown[i], unknown[j]] = [unknown[j], unknown[i]];
    }
    return [...known, ...unknown];
  }

  /** 保持者 1 台の完了までの時間 (ms) を記録する (移動平均。メモリだけ)。失敗は FAIL_PENALTY_MS を渡す */
  public recordSpeed(sid: string, ms: number): void {
    const prev = this.speeds.get(sid);
    const next = prev === undefined ? ms : Math.round((prev + ms) / 2);
    this.speeds.delete(sid); // 末尾へ (新しい順を保つ)
    this.speeds.set(sid, next);
    if (this.speeds.size > HISTORY_LIMITS.SPEED_MEMORY) {
      const oldest = this.speeds.keys().next().value;
      if (oldest !== undefined) this.speeds.delete(oldest);
    }
  }

  /** この保持者の、手元で観測した速さ (ms)。記録が無ければ undefined (診断・テスト用) */
  public speedOf(sidHex: string): number | undefined {
    return this.speeds.get(sidHex);
  }

  // ── 取得 ──

  /** 同時に走らせる取得の数を絞る (板の週別 13 本 + スレを一度に 1 ホップ目へ浴びせない) */
  private async acquire(): Promise<void> {
    if (this.running < HISTORY_LIMITS.MAX_CONCURRENT_FETCHES) {
      this.running++;
      return;
    }
    await new Promise<void>((resolve) => { this.queue.push(resolve); });
  }
  private queue: Array<() => void> = [];
  private release(): void {
    const next = this.queue.shift();
    if (next) next(); // 枠はそのまま次の取得へ
    else this.running--;
  }

  /**
   * バケット (birthDay, tag) の since 以降の投稿を保持者から取り、手元へ配る。
   * 失敗 (1 ホップ目が無い・保持者が無い・全員が失敗) は例外にせず結果で返す。
   */
  public async fetchBucket(birthDay: number, tag: number, opts: FetchOptions = {}): Promise<FetchResult> {
    const aborted = (): FetchResult => ({ completed: false, packets: 0, attempts: 0, reason: 'aborted' });
    if (this.destroyed || opts.signal?.aborted) return aborted();
    await this.acquire();
    try {
      if (this.destroyed || opts.signal?.aborted) return aborted();
      this.stats.fetches++;
      return await this.run(birthDay, tag, opts);
    } finally {
      this.release();
    }
  }

  private async run(birthDay: number, tag: number, opts: FetchOptions): Promise<FetchResult> {
    const signal = opts.signal;
    if (!(await this.waitReady(signal))) {
      return { completed: false, packets: 0, attempts: 0, reason: signal?.aborted ? 'aborted' : 'no-first-hop' };
    }
    // 新しい端末は、1 ホップ目からの leaseSet の一括送信 (SYNC) が届くまで保持者を知らない。少し待つ
    let cands = this.candidates(birthDay, tag);
    const holdersDeadline = this.now() + this.lim.holdersWaitMs;
    while (cands.length === 0 && this.now() < holdersDeadline && !signal?.aborted && !this.destroyed) {
      await new Promise<void>(r => setTimeout(r, this.lim.holdersPollMs));
      cands = this.candidates(birthDay, tag);
    }
    if (signal?.aborted) return { completed: false, packets: 0, attempts: 0, reason: 'aborted' };
    if (cands.length === 0) return { completed: false, packets: 0, attempts: 0, reason: 'no-holders' };

    const ordered = this.rank(cands);
    const ctx: Ctx = {
      birthDay, tag, since: opts.since ?? 0, seen: new Set(), received: 0, rejected: 0, done: false,
      onProgress: opts.onProgress, cancels: new Set(),
    };

    return new Promise<FetchResult>((resolve) => {
      let next = 0;
      let active = 0;
      let attempts = 0;
      let hedge: ReturnType<typeof setTimeout> | null = null;

      const finish = (completed: boolean, reason: FetchReason) => {
        if (ctx.done) return;
        ctx.done = true;
        if (hedge) clearTimeout(hedge);
        signal?.removeEventListener('abort', onAbort);
        for (const c of Array.from(ctx.cancels)) c();
        resolve({ completed, packets: ctx.received, attempts, reason });
      };
      const onAbort = () => finish(false, 'aborted');
      signal?.addEventListener('abort', onAbort, { once: true });

      const canLaunch = () => next < ordered.length && attempts < this.lim.maxAttempts;

      const launch = (): void => {
        if (ctx.done || !canLaunch()) return;
        const c = ordered[next++];
        attempts++;
        active++;
        this.stats.attempts++;
        void this.attempt(c, ctx).then((ok) => {
          active--;
          if (ctx.done) return;
          if (ok) return finish(true, 'ok');
          // 失敗 (空・未保有・不正・時間切れ): すぐ次の保持者へ
          if (canLaunch() && active < HISTORY_LIMITS.INITIAL_PARALLEL) launch();
          else if (active === 0 && !canLaunch()) finish(false, 'exhausted');
        });
      };

      const armHedge = () => {
        hedge = setTimeout(() => {
          hedge = null;
          if (ctx.done) return;
          if (active < HISTORY_LIMITS.MAX_PARALLEL) launch();
          if (canLaunch()) armHedge();
        }, this.lim.hedgeMs);
      };

      for (let i = 0; i < HISTORY_LIMITS.INITIAL_PARALLEL; i++) launch();
      armHedge();
    });
  }

  /** 1 台の保持者から、続きを含めて最後まで取る。完了したら true */
  private async attempt(c: Candidate, ctx: Ctx): Promise<boolean> {
    const t0 = this.now();
    let since = ctx.since;
    try {
      for (let page = 0; page < HISTORY_LIMITS.MAX_PAGES; page++) {
        const res = await this.requestOnce(c, ctx, since);
        if (ctx.done) return false;
        if (!res) {
          this.recordSpeed(c.sid, HISTORY_LIMITS.FAIL_PENALTY_MS);
          return false;
        }
        if (res.status === FETCH_STATUS.NOT_HELD) return false; // 持っていないだけ。罰は付けない
        const before = ctx.rejected;
        const gotNow = this.ingest(res, ctx);
        if (ctx.rejected > before) {
          // 検証を通らない投稿を返した: 偽物。後回しにして次へ
          this.recordSpeed(c.sid, HISTORY_LIMITS.FAIL_PENALTY_MS);
          return false;
        }
        if (res.status === FETCH_STATUS.OK) {
          // 全部取るのに空 (保持者が持っていると言ったのに 1 件も無い) は信用しない
          if (ctx.since === 0 && page === 0 && gotNow === 0 && ctx.received === 0) return false;
          this.recordSpeed(c.sid, this.now() - t0);
          return true;
        }
        since = res.nextSince;
        if (since < ctx.since) return false;
      }
      return false;
    } catch (e) {
      log.warn('fetch attempt failed', e);
      return false;
    }
  }

  /** 要求 1 回。完全な応答 (全部の片が揃い、最後の片が平文の final) か、失敗なら null */
  private requestOnce(c: Candidate, ctx: Ctx, since: number): Promise<FetchResponse | null> {
    return new Promise((resolve) => {
      const respKey = newRespKey();
      let payload: Uint8Array;
      try {
        payload = encodeFetchRequest({ birthDay: ctx.birthDay, tag: ctx.tag, since });
      } catch {
        return resolve(null);
      }
      const sealed = sealRequest(c.sidBytes, TUNNEL_KIND.FETCH_BUCKET, respKey, payload);
      if (!sealed) return resolve(null);

      const parts = new Map<number, Uint8Array>();
      let finalSeq = -1;
      let bytes = 0;
      let bad = 0;
      let settled = false;
      let timer: ReturnType<typeof setTimeout> | null = null;
      let handle: { cancel(): void } | null = null;

      const end = (res: FetchResponse | null) => {
        if (settled) return;
        settled = true;
        if (timer) clearTimeout(timer);
        handle?.cancel();
        ctx.cancels.delete(cancel);
        respKey.fill(0);
        resolve(res);
      };
      const cancel = () => end(null);
      ctx.cancels.add(cancel);
      const arm = () => {
        if (timer) clearTimeout(timer);
        timer = setTimeout(() => end(null), this.lim.inactivityMs);
      };

      handle = this.parts.tunnel.request({ gateway: c.gateway, tunnelId: c.tunnelId, body: sealed }, (ev) => {
        if (settled) return;
        if (ev.type === 'error') return end(null);
        // ★ フレームの final (平文) ではなく、復号した中身の final を使う。途中の片を黙って落とされても完結と見なさない
        const dec = decryptChunk(respKey, TUNNEL_KIND.FETCH_BUCKET, ev.seq, ev.body);
        if (!dec) {
          this.stats.badChunks++;
          if (++bad >= HISTORY_LIMITS.MAX_BAD_CHUNKS) end(null);
          return;
        }
        if (parts.has(ev.seq)) return;
        if (parts.size >= HISTORY_LIMITS.MAX_CHUNKS) return end(null);
        if (finalSeq >= 0 && ev.seq > finalSeq) return end(null);
        if (dec.final) {
          if (finalSeq >= 0 && finalSeq !== ev.seq) return end(null);
          finalSeq = ev.seq;
          if ([...parts.keys()].some(s => s > finalSeq)) return end(null);
        }
        parts.set(ev.seq, dec.data);
        bytes += dec.data.length;
        if (bytes > FETCH_MAX_ACCEPT_BYTES) return end(null);
        arm();
        if (finalSeq >= 0 && parts.size === finalSeq + 1) {
          const out = new Uint8Array(bytes);
          let o = 0;
          for (let i = 0; i <= finalSeq; i++) {
            const p = parts.get(i);
            if (!p) return end(null); // 到達済みの数は合うが、番号に穴がある
            out.set(p, o);
            o += p.length;
          }
          end(decodeFetchResponse(out));
        }
      });
      if (handle) arm();
      else end(null);
    });
  }

  /** 応答の投稿を検証して手元へ配る。配った件数 (このページ)。通らないものは ctx.rejected に数える */
  private ingest(res: FetchResponse, ctx: Ctx): number {
    const now = this.now();
    let delivered = 0;
    for (const bytes of res.packets) {
      const packet = decodePacket(bytes);
      if (!packet) { ctx.rejected++; this.stats.rejectedPackets++; continue; }
      if (ctx.seen.has(packet.packet_id)) continue;
      // 要求したバケットの投稿か (別のバケットの有効な投稿を混ぜて押し込まれない)
      if (birthDayOf(packet.timestamp, packet.age) !== ctx.birthDay || packet.tag !== ctx.tag) {
        ctx.rejected++; this.stats.rejectedPackets++;
        continue;
      }
      const v = PacketValidator.check(packet, { now, maxPastMs: FETCH_MAX_PAST_MS });
      if (!v.ok) { ctx.rejected++; this.stats.rejectedPackets++; continue; }
      ctx.seen.add(packet.packet_id);
      ctx.received++;
      delivered++;
      try {
        this.parts.deliver(packet);
      } catch (e) {
        log.warn('deliver failed', e);
      }
    }
    if (delivered > 0) {
      try { ctx.onProgress?.(ctx.received); } catch (e) { log.warn('progress listener failed', e); }
    }
    return delivered;
  }

  public destroy(): void {
    this.destroyed = true;
    this.parts.peerManager.off('peer:verified', this.onVerified);
    this.readyListeners.clear();
    for (const w of this.waiters.splice(0)) w();
    for (const q of this.queue.splice(0)) q();
  }
}

import sodium from '../crypto/sodium';
import type { OnionHop } from '../crypto/OnionRouter';
import type { IPeerConnection, PeerId } from '../types';
import { createLogger } from '../common/Logger';
import { guardWeight, secureRandomIndex, secureWeightedIndex } from '../network/gossip/DandelionRouter';
import type { NodeIdPowParams } from '../crypto/NodeIdentity';
import {
  readGuardListUnverified,
  verifyGuardList,
  type GuardListResult,
  type MaintainerKeySet,
  type TrustedGuard,
} from './TrustedGuards';

const log = createLogger('trust.guard');

/**
 * Guard の方針 (どの隣人を 1 ホップ目にするか) を持つ。
 *
 * ★ なぜ要るか
 *
 *   Guard は利用者の IP を見る位置にある。これまでは「最初に握手を終えた隣人」が
 *   そのまま Guard になっていた。トラッカーに居座る攻撃者 (Sybil) は、新参のノードが
 *   最初に出会う隣人になれるので、Guard の座を取れてしまう。
 *   審査済みメンバーの署名つきリスト ({@link verifyGuardList}) に載った Guard だけを
 *   使うことで、これを防ぐ。
 *
 * ★ 何を保存し、何を保存しないか
 *
 *   保存するのは「受け入れたリストの文字列と版」と「Guard サンプル (信頼 Guard の peerId と失効時刻)」だけ。
 *   フォールバック / オープンで選んだ隣人は決して保存しない。保存すると、
 *   「この端末が過去にどの素性の知れない隣人を Guard にしたか」が押収時の痕跡になり、
 *   かつ次回起動時にその隣人を優先する足掛かりを攻撃者に与える。
 *   (ストアは利用者のパスフレーズで暗号化されている。)
 */

export type GuardMode = 'trusted' | 'fallback' | 'open' | 'none';

export interface GuardStatus {
  /**
   * trusted : 検証済みリストの Guard に固定している
   * fallback: リストはあるが、載っている Guard につながっていないので普通の隣人を使っている (警告状態)
   * open    : リストが無く、普通の隣人を使っている (警告状態)
   * none    : まだ Guard が無い。送信はできない (fail-closed)
   */
  mode: GuardMode;
  guardId: string | null;
  listVersion: number | null;
  listExpiresAt: number | null;
  /**
   * 状態の理由 (UI の表示用)。
   *   'list-expired'              : 受け入れ済みのリストが失効している
   *   'no-list'                   : リストが設定されていない
   *   'waiting-for-trusted-guard' : リストの Guard につながるのを待っている (猶予期間)
   *   'waiting-for-candidates'    : 普通の隣人を選ぶための条件 (人数・待ち時間) を満たすのを待っている
   *   'no-trusted-guard-connected': 猶予を過ぎても信頼 Guard につながらない
   */
  reason?: string;
}

/** 保存先。本番では IndexedDBStore.getSetting / setSetting (パスフレーズで暗号化済み) */
export interface GuardStore {
  get(name: string): Promise<unknown>;
  set(name: string, value: unknown): Promise<void>;
}

/** DandelionRouter が使う方針の窓口 */
export interface GuardPolicy {
  now(): number;
  /**
   * @param pinnedId 現在固定している Guard (つながっていて候補に居るときだけ渡す)
   * @returns 使う Guard。選べなければ null (呼び出し側は送信を止める)
   */
  select(
    candidates: OnionHop[],
    peers: ReadonlyMap<PeerId, IPeerConnection>,
    now: number,
    pinnedId: PeerId | null,
  ): OnionHop | null;
}

export const GUARD_SAMPLE_SIZE = 3;
/** 信頼 Guard につながるのを待ってから、普通の隣人にフォールバックするまでの猶予 */
export const FALLBACK_GRACE_MS = 30_000;
/** リスト無し / フォールバックで Guard を選ぶのに必要な、検証済み隣人の最少人数 */
export const MIN_OPEN_CANDIDATES = 4;
/** 同じく、最初の検証済み隣人が現れてから選ぶまでの待ち時間 */
export const OPEN_SELECTION_DELAY_MS = 20_000;
/** サンプルの各 Guard の有効期間 (この範囲で一様に引く) */
export const GUARD_SAMPLE_MIN_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000;
export const GUARD_SAMPLE_MAX_LIFETIME_MS = 60 * 24 * 60 * 60 * 1000;

const KEY_LIST = 'guard.list';
const KEY_SAMPLE = 'guard.sample';
const PEER_ID_RE = /^[0-9a-f]{32}$/;

export interface GuardManagerOptions {
  /** メンテナの公開鍵の組。無ければリストは常に拒否され、オープン動作になる */
  keyset?: MaintainerKeySet;
  /** 設定で与えるリスト (保存済みのものより版が高ければ採用) */
  guardList?: string;
  store?: GuardStore;
  /** 現在時刻 (ms)。テスト用 */
  now?: () => number;
  /** [0, n) の一様な整数。既定は CSPRNG。テスト用 */
  randomIndex?: (n: number) => number;
  powParams?: NodeIdPowParams;
  // ── 時間定数 (テストで縮める。本番は既定値) ──
  sampleSize?: number;
  fallbackGraceMs?: number;
  minOpenCandidates?: number;
  openSelectionDelayMs?: number;
}

interface AcceptedList {
  version: number;
  issuedAt: number;
  expiresAt: number;
  guards: Map<PeerId, TrustedGuard>;
  revoked: Set<PeerId>;
}

interface SampleEntry {
  peerId: PeerId;
  expiresAt: number;
}

export class GuardManager implements GuardPolicy {
  private readonly keyset?: MaintainerKeySet;
  private readonly store?: GuardStore;
  private readonly clock: () => number;
  private readonly randomIndex: (n: number) => number;
  private readonly powParams?: NodeIdPowParams;
  private readonly sampleSize: number;
  private readonly fallbackGraceMs: number;
  private readonly minOpenCandidates: number;
  private readonly openSelectionDelayMs: number;
  private readonly configList?: string;

  private list: AcceptedList | null = null;
  /** 失効していて使えないが、状態表示のために覚えている最新のリスト */
  private expiredInfo: { version: number; expiresAt: number } | null = null;
  /** これまでに受け入れた最大の版 (巻き戻し防止) */
  private highestVersion = 0;
  private sample: SampleEntry[] = [];

  private startedAt: number | null = null;
  private firstVerifiedAt: number | null = null;
  /** 最後に信頼 Guard (どれでも) が候補に居た時刻。失った直後の猶予の起点 */
  private lastTrustedAt: number | null = null;
  /** 最後にサンプルの Guard が候補に居た時刻 */
  private lastSampleAt: number | null = null;

  private current: GuardStatus = {
    mode: 'none', guardId: null, listVersion: null, listExpiresAt: null,
  };
  private listeners = new Set<(s: GuardStatus) => void>();
  private persistChain: Promise<void> = Promise.resolve();

  constructor(options: GuardManagerOptions = {}) {
    this.keyset = options.keyset;
    this.configList = options.guardList;
    this.store = options.store;
    this.clock = options.now ?? (() => Date.now());
    this.randomIndex = options.randomIndex ?? secureRandomIndex;
    this.powParams = options.powParams;
    this.sampleSize = options.sampleSize ?? GUARD_SAMPLE_SIZE;
    this.fallbackGraceMs = options.fallbackGraceMs ?? FALLBACK_GRACE_MS;
    this.minOpenCandidates = options.minOpenCandidates ?? MIN_OPEN_CANDIDATES;
    this.openSelectionDelayMs = options.openSelectionDelayMs ?? OPEN_SELECTION_DELAY_MS;
  }

  public now(): number {
    return this.clock();
  }

  // ── 初期化 / リストの取り込み ──

  /**
   * 保存済みのリストとサンプルを読み込む。回路が Guard を選び始める前に呼ぶこと。
   * 保存してから時間が経っていて失効しているかもしれないので、必ず検証し直す。
   */
  public async init(): Promise<void> {
    const now = this.clock();
    let stored: { text: string; version: number } | null = null;
    try {
      const raw: any = await this.store?.get(KEY_LIST);
      if (raw && typeof raw.text === 'string' && Number.isSafeInteger(raw.version) && raw.version >= 1) {
        stored = { text: raw.text, version: raw.version };
      }
    } catch {
      log.warn('could not read the saved guard list');
    }
    // 版の高水位は、検証が通らなくても保存済みの値を採る (失効したリストの後に古い版を入れさせない)
    this.highestVersion = stored?.version ?? 0;

    const consider = (text: string, minVersion?: number): { text: string; res: GuardListResult } =>
      ({ text, res: this.verify(text, now, minVersion) });

    const results: Array<{ text: string; res: GuardListResult; fromConfig: boolean }> = [];
    if (stored) results.push({ ...consider(stored.text), fromConfig: false });
    if (this.configList) results.push({ ...consider(this.configList, this.highestVersion || undefined), fromConfig: true });

    let best: (typeof results)[number] | null = null;
    let expired: { version: number; expiresAt: number } | null = null;
    for (const r of results) {
      if (r.res.ok) {
        if (!best || (r.res as any).version > (best.res as any).version) best = r;
      } else if (r.res.reason === 'expired') {
        // 'expired' は署名の検証を通ったあとにだけ返る。中身は表示にだけ使う。
        const c = readGuardListUnverified(r.text);
        if (c && (!expired || c.version > expired.version)) expired = { version: c.version, expiresAt: c.expiresAt };
      }
    }

    if (best && best.res.ok) {
      this.accept(best.res);
      if (best.fromConfig) await this.persistList(best.text, best.res.version);
    } else if (expired) {
      this.expiredInfo = expired;
    }

    await this.loadSample(now);
    this.maintainSample(now);
    this.publishStatus(
      'none',
      null,
      this.list ? 'waiting-for-trusted-guard' : (this.expiredInfo ? 'list-expired' : 'no-list'),
    );
  }

  /**
   * リストを取り込む。署名・期間・版 (巻き戻し) を検証し、通ったときだけ保存して差し替える。
   * 失敗は状態を一切変えない。
   */
  public async importList(text: string): Promise<GuardListResult> {
    const now = this.clock();
    const res = this.verify(text, now, this.highestVersion || undefined);
    if (!res.ok) return res;
    this.accept(res);
    this.maintainSample(now);
    await this.persistList(text, res.version);
    this.publishStatus();
    return res;
  }

  private verify(text: string, now: number, minVersion?: number): GuardListResult {
    return verifyGuardList(text, this.keyset as MaintainerKeySet, {
      now,
      minVersion,
      powParams: this.powParams,
    });
  }

  private accept(res: Extract<GuardListResult, { ok: true }>): void {
    this.list = {
      version: res.version,
      issuedAt: res.issuedAt,
      expiresAt: res.expiresAt,
      guards: new Map(res.guards.map(g => [g.peerId, g])),
      revoked: new Set(res.revoked),
    };
    this.expiredInfo = null;
    this.highestVersion = Math.max(this.highestVersion, res.version);
  }

  // ── 参照 ──

  /** 今使えるリスト。失効していれば null (失効は選択のうえでは「リスト無し」と同じ) */
  private usable(now: number): AcceptedList | null {
    if (this.list && now < this.list.expiresAt) return this.list;
    return null;
  }

  public get hasUsableList(): boolean {
    return this.usable(this.clock()) !== null;
  }

  /**
   * peerId がリストにあり、かつ公開鍵がリストのものとバイト単位で一致するときだけ true。
   * (peerId は公開鍵に束縛されているが、ここでも直接照合して二重に確かめる。)
   */
  public isTrusted(peerId: PeerId, pubkey: Uint8Array | null | undefined): boolean {
    const list = this.usable(this.clock());
    if (!list || !pubkey) return false;
    const g = list.guards.get(peerId);
    if (!g || g.pubkey.length !== pubkey.length) return false;
    return sodium.memcmp(g.pubkey, pubkey);
  }

  /**
   * peerId だけで照合する版 (公開鍵を持たない場面用。leaseSet の受け口 = Guard の peerId は 16 バイトの生 ID だけ)。
   * ★ peerId は公開鍵から導出される束縛なので、リストに載っている peerId に化けるには
   *   その公開鍵の秘密鍵が要る。接続を張る側は isTrusted (鍵の照合) を使うこと。
   */
  public isTrustedPeerId(peerId: PeerId): boolean {
    return this.usable(this.clock())?.guards.has(peerId) === true;
  }

  /**
   * リストに載っている信頼 Guard すべての peerId (失効したものを除く。リストが使えなければ空)。
   * Guard 役のノードが、他の Guard すべてとつなぎ続ける (バックボーン) ための一覧。自分自身は呼び出し側が除く。
   */
  public trustedGuardIds(): PeerId[] {
    const list = this.usable(this.clock());
    if (!list) return [];
    return Array.from(list.guards.keys()).filter(id => !list.revoked.has(id));
  }

  /** 失効 (revoke) された Guard か */
  public isRevoked(peerId: PeerId): boolean {
    return this.usable(this.clock())?.revoked.has(peerId) === true;
  }

  /** 接続を保っておきたい Guard (サンプル順 = 優先順)。リストが使えないときは空 */
  public wantedGuardIds(): PeerId[] {
    const now = this.clock();
    if (!this.usable(now)) return [];
    this.maintainSample(now);
    return this.sample.map(e => e.peerId);
  }

  public get status(): GuardStatus {
    return this.current;
  }

  public onStatus(cb: (s: GuardStatus) => void): () => void {
    this.listeners.add(cb);
    return () => { this.listeners.delete(cb); };
  }

  // ── Guard サンプル ──

  /**
   * サンプルを整える: リストに無い・期限切れのものを外し、足りない分を一様乱数で補う。
   * リストが使えない間は何もしない (一時的な失効でサンプルを捨てない)。
   */
  private maintainSample(now: number): void {
    const list = this.usable(now);
    if (!list) return;
    const before = this.sample.map(e => `${e.peerId}:${e.expiresAt}`).join(',');

    this.sample = this.sample.filter(e => list.guards.has(e.peerId) && e.expiresAt > now);
    while (this.sample.length < this.sampleSize) {
      const taken = new Set(this.sample.map(e => e.peerId));
      const pool = [...list.guards.keys()].filter(id => !taken.has(id));
      if (pool.length === 0) break;
      const peerId = pool[this.randomIndex(pool.length)];
      const span = GUARD_SAMPLE_MAX_LIFETIME_MS - GUARD_SAMPLE_MIN_LIFETIME_MS;
      const expiresAt = now + GUARD_SAMPLE_MIN_LIFETIME_MS + this.randomIndex(span + 1);
      this.sample.push({ peerId, expiresAt });
    }

    if (before !== this.sample.map(e => `${e.peerId}:${e.expiresAt}`).join(',')) {
      this.enqueue(() => this.store?.set(KEY_SAMPLE, this.sample.map(e => ({ ...e }))));
    }
  }

  private async loadSample(now: number): Promise<void> {
    try {
      const raw: any = await this.store?.get(KEY_SAMPLE);
      if (!Array.isArray(raw)) return;
      const seen = new Set<string>();
      for (const e of raw) {
        if (typeof e?.peerId !== 'string' || !PEER_ID_RE.test(e.peerId) || seen.has(e.peerId)) continue;
        if (!Number.isFinite(e.expiresAt) || e.expiresAt <= now) continue;
        seen.add(e.peerId);
        this.sample.push({ peerId: e.peerId, expiresAt: e.expiresAt });
        if (this.sample.length >= this.sampleSize) break;
      }
    } catch {
      log.warn('could not read the saved guard sample');
    }
  }

  // ── 保存 ──

  private async persistList(text: string, version: number): Promise<void> {
    await this.enqueue(() => this.store?.set(KEY_LIST, { text, version }));
  }

  /** 保存は順番に行う (古い値が後から書き込まれないように)。失敗しても動作は続ける */
  private enqueue(job: () => Promise<void> | undefined): Promise<void> {
    this.persistChain = this.persistChain.then(async () => {
      try {
        await job();
      } catch {
        log.warn('could not save guard settings');
      }
    });
    return this.persistChain;
  }

  /** 保存の完了を待つ (テスト・停止用) */
  public flush(): Promise<void> {
    return this.persistChain;
  }

  // ── 選択 ──

  public select(
    candidates: OnionHop[],
    peers: ReadonlyMap<PeerId, IPeerConnection>,
    now: number,
    pinnedId: PeerId | null = null,
  ): OnionHop | null {
    if (this.startedAt === null) this.startedAt = now;
    if (candidates.length > 0 && this.firstVerifiedAt === null) this.firstVerifiedAt = now;

    const list = this.usable(now);
    if (list) this.maintainSample(now);
    // 失効 (revoke) された peerId は、リストが期限切れになった後も Guard にしない。
    // メンテナが「使うな」と判断した相手なので、フォールバックの候補にも入れない。
    const revoked = (list ?? this.list)?.revoked;
    const eligible = revoked ? candidates.filter(c => !revoked.has(c.peerId)) : candidates;
    const livePinned = pinnedId !== null ? eligible.find(c => c.peerId === pinnedId) ?? null : null;

    // 1. リストが使えるなら、信頼 Guard を最優先する (固定中の普通の隣人からも乗り換える)
    if (list) {
      const trusted = eligible.filter(c => this.isTrusted(c.peerId, c.pubkey));
      const sampleTrusted = this.sample
        .map(e => trusted.find(t => t.peerId === e.peerId))
        .filter((t): t is OnionHop => t !== undefined);
      if (trusted.length > 0) this.lastTrustedAt = now;
      if (sampleTrusted.length > 0) this.lastSampleAt = now;

      // (a) サンプルの Guard。固定中ならそれを替えず、無ければサンプルの順 (優先順) で選ぶ
      if (sampleTrusted.length > 0) {
        const keep = livePinned ? sampleTrusted.find(t => t.peerId === livePinned.peerId) : undefined;
        return this.report('trusted', keep ?? sampleTrusted[0], undefined);
      }

      // (b) サンプル外の信頼 Guard。
      //   ★ 信頼 Guard はトラッカーに常駐しているので、起動直後にサンプル外の Guard と
      //     たまたまつながることはよくある。そこで即座に固定すると、使う Guard の数が
      //     起動のたびに増え、サンプル (少数の Guard を長く使う) の意味が無くなる。
      //     サンプルの Guard を待つ猶予を置き、それでもつながらなければ使う。
      //     ただし普通の隣人で fallback 中なら、待たずに信頼 Guard へ乗り換える。
      const pinnedTrusted = livePinned ? trusted.find(t => t.peerId === livePinned.peerId) : undefined;
      if (pinnedTrusted) return this.report('trusted', pinnedTrusted, undefined);
      if (trusted.length > 0) {
        const inFallback = livePinned !== null; // ここに来る固定は信頼 Guard ではない
        if (!inFallback && this.withinGrace(now, this.lastSampleAt)) {
          return this.report('none', null, 'waiting-for-trusted-guard');
        }
        const choice = trusted[secureWeightedIndex(trusted.map(t => guardWeight(peers, t.peerId, now)))];
        return this.report('trusted', choice, undefined);
      }

      // (c) 信頼 Guard が 1 台もつながっていない。起動直後と、信頼 Guard を失った直後は
      //   つながるのを待つ (送信は止まる)。
      //   ★ 猶予を起動直後だけにすると、信頼 Guard との接続を一度切らせるだけで、
      //     即座に普通の隣人 (攻撃者かもしれない) へ乗り換えさせられる。
      if (!livePinned && this.withinGrace(now, this.lastTrustedAt)) {
        return this.report('none', null, 'waiting-for-trusted-guard');
      }
    }

    // 2. 普通の隣人 (リスト無し = open / リストはあるが信頼 Guard 不在 = fallback)
    const mode: GuardMode = list ? 'fallback' : 'open';
    const reason = list ? 'no-trusted-guard-connected' : (this.listExpired(now) ? 'list-expired' : 'no-list');
    if (livePinned) return this.report(mode, livePinned, reason);

    // ★ 起動直後の「最初の 1 人」を Guard にしない。候補が 1 人だと重みづけが効かず、
    //   最初に握手を終えた隣人 (= トラッカーに居座る攻撃者) がそのまま Guard になる。
    //   ある程度の人数が揃い、少し時間が経ってから、重みづけで選ぶ。
    if (
      eligible.length < this.minOpenCandidates ||
      this.firstVerifiedAt === null ||
      now - this.firstVerifiedAt < this.openSelectionDelayMs
    ) {
      return this.report('none', null, this.listExpired(now) ? 'list-expired' : 'waiting-for-candidates');
    }
    const picked = eligible[secureWeightedIndex(eligible.map(c => guardWeight(peers, c.peerId, now)))];
    return this.report(mode, picked, reason);
  }

  /**
   * 猶予の中か。起点は「起動 (最初の select)」と「最後にその種類の Guard が見えていた時刻」の遅い方。
   */
  private withinGrace(now: number, lastSeenAt: number | null): boolean {
    const from = Math.max(this.startedAt ?? now, lastSeenAt ?? Number.NEGATIVE_INFINITY);
    return now - from < this.fallbackGraceMs;
  }

  private report(mode: GuardMode, hop: OnionHop | null, reason: string | undefined): OnionHop | null {
    this.publishStatus(mode, hop?.peerId ?? null, reason);
    return hop;
  }

  private publishStatus(mode?: GuardMode, guardId?: string | null, reason?: string): void {
    const now = this.clock();
    const list = this.usable(now);
    const prev = this.current;
    const shown = list ?? this.list ?? this.expiredInfo;
    const next: GuardStatus = {
      mode: mode ?? prev.mode,
      guardId: guardId === undefined ? prev.guardId : guardId,
      listVersion: shown?.version ?? null,
      listExpiresAt: shown?.expiresAt ?? null,
    };
    const r = mode === undefined ? prev.reason : reason;
    if (r !== undefined) next.reason = r;

    if (
      prev.mode === next.mode && prev.guardId === next.guardId && prev.listVersion === next.listVersion &&
      prev.listExpiresAt === next.listExpiresAt && prev.reason === next.reason
    ) return;
    this.current = next;
    for (const cb of this.listeners) {
      try { cb(next); } catch { /* 通知先の失敗で選択を止めない */ }
    }
  }

  /** 受け入れ済みのリストが失効しているか (使えるリストが無い理由の区別用) */
  private listExpired(now: number): boolean {
    return this.expiredInfo !== null || (this.list !== null && now >= this.list.expiresAt);
  }
}

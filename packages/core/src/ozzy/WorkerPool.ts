/**
 * WorkerPool — 参加者全員が出す Ozzy の中継 Worker (packages/r2-worker) を、PEX と同じ要領で隣人と交換し続け、
 * 中継にはそこから適当に選んだ「他人の」Worker を使う。
 *
 *   Ozzy を使う人は全員、自分の Worker をデプロイして設定する (設定するまで Ozzy の画面と M1 の役は動かない)。
 *   自分の Worker は広告 (身元の鍵で署名した URL) として網に流し、自分の通信には他人の Worker を使う。
 *   → 自分のロッカー通信 (アップロード・M1 としての代理取得) が、自分の Cloudflare アカウントに記録されない。
 *     ロッカーには Cloudflare の IP しか見えない。
 *
 * ★ 中継の持ち主には、中継を使った人の IP と行き先の URL が見える (Worker は CF-Connecting-IP を知る)。
 *   1 人の持ち主に通信が集まらないよう、要求ごとに選び直す。広告で網を埋めて中継を独占されないよう:
 *   - 広告は身元 (NodeId PoW 付きの鍵) で署名させ、1 つの身元に 1 つの Worker だけ持つ
 *   - URL は `https://<name>.<sub>.workers.dev` だけ (Cloudflare の Worker。任意のサーバーで IP を集めさせない)
 *   - 観測期間の長い広告ほど選ばれやすくする (新しく現れた大量の広告は選ばれにくい)
 *   - 同じ URL を複数の身元が出していても 1 つとして数える
 *
 *   OZZY_WORKER_REQ   (本体なし) 「知っている Worker の広告をください」
 *   OZZY_WORKER_ADS   count u8 ‖ { pubkey 32 ‖ powCounter u32 ‖ expiresMin u32 ‖ lp8(url) ‖ sig 64 } × count
 */
import sodium from '../crypto/sodium';
import { Encoding } from '../common/Encoding';
import { createLogger } from '../common/Logger';
import { NodeIdentity, NODE_ID_POW, ozzyWorkerAdMessage, type NodeIdPowParams } from '../crypto/NodeIdentity';
import type { IMessageDispatcher, IPeerManager, PeerId } from '../types';
import { WireType } from '../network/wire/WireTypes';
import { secureRandomIndex, secureWeightedIndex } from '../network/gossip/DandelionRouter';

const log = createLogger('ozzy.workers');

export const WORKER_POOL_LIMITS = {
  /** 隣人 1 人に広告を問い合わせる間隔 */
  EXCHANGE_INTERVAL_MS: 60_000,
  /** 1 回の応答に載せる広告の数 */
  ADS_PER_MESSAGE: 16,
  /** 手元に持つ広告の数の上限 (超えたら期限の近いものから捨てる) */
  MAX_ADS: 2048,
  /** 自分の広告の有効期間と出し直しの間隔 */
  AD_LIFETIME_MS: 24 * 60 * 60_000,
  AD_REFRESH_MS: 6 * 60 * 60_000,
  /** 期限がこれより先の広告は受け付けない */
  MAX_AD_LIFETIME_MS: 48 * 60 * 60_000,
  /** 中継に失敗した Worker を選ばないでおく時間 */
  FAILURE_COOLDOWN_MS: 30 * 60_000,
  /** 観測期間による重み付けが飽和する時間 (これだけ見続けた広告は新しい広告の 5 倍選ばれやすい) */
  OBSERVATION_SATURATION_MS: 60 * 60_000,
} as const;

const WORKERS_DEV_RE = /^https:\/\/[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+\.workers\.dev$/;

/** Worker の URL を正規の形 (`https://<name>.<sub>.workers.dev`、末尾の / なし) にする。使えない URL なら null */
export function normalizeOzzyWorkerUrl(raw: string): string | null {
  if (typeof raw !== 'string') return null;
  let u: URL;
  try {
    u = new URL(raw.trim());
  } catch {
    return null;
  }
  if (u.protocol !== 'https:' || u.port !== '' || u.username !== '' || u.password !== '') return null;
  if (u.search !== '' || u.hash !== '' || (u.pathname !== '/' && u.pathname !== '')) return null;
  const url = `https://${u.hostname.toLowerCase()}`;
  return url.length <= 200 && WORKERS_DEV_RE.test(url) ? url : null;
}

/**
 * Worker が今の版の Ozzy 中継かを確かめる (`/ozzy/v2/status` が { ok: true, relay: true } を返すか)。
 * 自分の Worker を設定するときに使う (他人の Worker は中継の応答で確かめる)。
 */
export async function checkOzzyWorker(
  url: string, fetchFn: (req: Request) => Promise<Response> = (req) => fetch(req, { cache: 'no-store' }),
): Promise<{ ok: true } | { ok: false; reason: 'bad-url' | 'unreachable' | 'not-ozzy' | 'outdated' }> {
  const base = normalizeOzzyWorkerUrl(url);
  if (!base) return { ok: false, reason: 'bad-url' };
  try {
    const res = await fetchFn(new Request(`${base}/ozzy/v2/status`, { method: 'GET' }));
    if (!res.ok) return { ok: false, reason: 'not-ozzy' };
    const body = (await res.json()) as { ok?: boolean; relay?: boolean };
    if (body?.ok !== true) return { ok: false, reason: 'not-ozzy' };
    if (body.relay !== true) return { ok: false, reason: 'outdated' };
    return { ok: true };
  } catch {
    return { ok: false, reason: 'unreachable' };
  }
}

export interface WorkerAd {
  pubkey: Uint8Array;
  powCounter: number;
  expiresMin: number;
  url: string;
  signature: Uint8Array;
}

interface PoolEntry {
  ad: WorkerAd;
  firstSeen: number;
}

/**
 * OzzyWorkerPool — 全ノードが持つ。自分の Worker の広告を出し、隣人と広告を交換し続け、中継に使う Worker を選ぶ。
 * ★ 広告・失敗の記録はメモリだけ (ディスクに「どの Worker を知っていたか」を残さない)。
 */
export class OzzyWorkerPool {
  private readonly now: () => number;
  private readonly powParams: NodeIdPowParams;
  private readonly exchangeIntervalMs: number;
  private ads = new Map<PeerId, PoolEntry>();
  /** PoW を確かめ済みの公開鍵 (Argon2id は重いので 1 回だけ) */
  private verifiedKeys = new Set<string>();
  private failedUntil = new Map<string, number>();
  private ownAd: WorkerAd | null = null;
  private exchangeTimer: ReturnType<typeof setInterval> | null = null;
  private refreshTimer: ReturnType<typeof setInterval> | null = null;
  private destroyed = false;
  private readonly onReq = (from: PeerId) => this.handleRequest(from);
  private readonly onAds = (from: PeerId, msg: any) => this.handleAds(from, msg);
  private readonly onVerified = (peer: { peerId?: PeerId }) => {
    if (peer?.peerId && this.exchangeTimer) this.peerManager.sendMessage(peer.peerId, WireType.OZZY_WORKER_REQ, {});
  };

  /** 診断・テスト用 */
  public readonly stats = { accepted: 0, rejected: 0, requestsSent: 0 };

  constructor(
    private readonly peerManager: Pick<IPeerManager, 'peers' | 'sendMessage' | 'on' | 'off' | 'myPeerId'>,
    private readonly dispatcher: IMessageDispatcher & { unregister?(type: number, handler: (peerId: PeerId, payload: any) => void): void },
    private readonly identity: Pick<NodeIdentity, 'pubkey' | 'powCounter' | 'signOzzyWorkerAd'>,
    opts: { powParams?: NodeIdPowParams; now?: () => number; exchangeIntervalMs?: number } = {},
  ) {
    this.now = opts.now ?? Date.now;
    this.powParams = opts.powParams ?? NODE_ID_POW;
    this.exchangeIntervalMs = opts.exchangeIntervalMs ?? WORKER_POOL_LIMITS.EXCHANGE_INTERVAL_MS;
    dispatcher.register(WireType.OZZY_WORKER_REQ, this.onReq);
    dispatcher.register(WireType.OZZY_WORKER_ADS, this.onAds);
    peerManager.on('peer:verified', this.onVerified);
  }

  /** 自分の Worker (設定済みなら URL) */
  public get own(): string | null {
    return this.ownAd?.url ?? null;
  }

  /** 中継に使える他人の Worker の数 (URL で数える。失敗して休ませている分を除く) */
  public get size(): number {
    return this.candidates().size;
  }

  /** 自分の Worker を設定する (null で外す)。広告に署名して、交換の応答に載せる */
  public setOwn(url: string | null): void {
    if (url === null) {
      this.ownAd = null;
      return;
    }
    const norm = normalizeOzzyWorkerUrl(url);
    if (!norm) throw new RangeError('not a workers.dev URL');
    const expiresMin = Math.floor((this.now() + WORKER_POOL_LIMITS.AD_LIFETIME_MS) / 60_000);
    this.ownAd = {
      pubkey: this.identity.pubkey,
      powCounter: this.identity.powCounter,
      expiresMin,
      url: norm,
      signature: this.identity.signOzzyWorkerAd(norm, expiresMin),
    };
  }

  public start(): void {
    if (this.exchangeTimer || this.destroyed) return;
    const tick = () => {
      const peers = Array.from(this.peerManager.peers.values()).filter(p => p.isConnected && p.isVerified);
      if (peers.length === 0) return;
      const target = peers[secureRandomIndex(peers.length)].peerId;
      this.stats.requestsSent++;
      this.peerManager.sendMessage(target, WireType.OZZY_WORKER_REQ, {});
    };
    this.exchangeTimer = setInterval(tick, this.exchangeIntervalMs);
    this.refreshTimer = setInterval(() => {
      if (this.ownAd) this.setOwn(this.ownAd.url);
      this.prune();
    }, WORKER_POOL_LIMITS.AD_REFRESH_MS);
    tick();
  }

  /** 中継が失敗した Worker をしばらく選ばない */
  public reportFailure(url: string): void {
    this.failedUntil.set(url, this.now() + WORKER_POOL_LIMITS.FAILURE_COOLDOWN_MS);
  }

  /** URL → 最初に見た時刻 (同じ URL を複数の身元が出していれば最も古いもの) */
  private candidates(): Map<string, number> {
    const t = this.now();
    const nowMin = Math.floor(t / 60_000);
    const out = new Map<string, number>();
    for (const e of this.ads.values()) {
      if (e.ad.expiresMin <= nowMin) continue;
      if (e.ad.url === this.ownAd?.url) continue; // 自分の通信には自分の Worker を使わない
      const until = this.failedUntil.get(e.ad.url);
      if (until !== undefined && until > t) continue;
      const prev = out.get(e.ad.url);
      out.set(e.ad.url, prev === undefined ? e.firstSeen : Math.min(prev, e.firstSeen));
    }
    return out;
  }

  /**
   * 中継に使う Worker を選ぶ (要求ごとに呼ぶ)。他人の Worker から、観測期間の長いものほど選ばれやすく。
   * 他人の Worker をまだ知らなければ自分の Worker (起動直後)。どちらも無ければ null。
   */
  public pickRelay(): string | null {
    const cands = Array.from(this.candidates());
    if (cands.length === 0) return this.ownAd?.url ?? null;
    const t = this.now();
    const weights = cands.map(([, firstSeen]) =>
      0.25 + Math.min(t - firstSeen, WORKER_POOL_LIMITS.OBSERVATION_SATURATION_MS) / WORKER_POOL_LIMITS.OBSERVATION_SATURATION_MS);
    return cands[secureWeightedIndex(weights)][0];
  }

  private handleRequest(from: PeerId): void {
    if (this.destroyed) return;
    const nowMin = Math.floor(this.now() / 60_000);
    const pool = Array.from(this.ads.values()).map(e => e.ad).filter(a => a.expiresMin > nowMin);
    for (let i = pool.length - 1; i > 0; i--) {
      const j = secureRandomIndex(i + 1);
      [pool[i], pool[j]] = [pool[j], pool[i]];
    }
    const ads = (this.ownAd ? [this.ownAd, ...pool] : pool).slice(0, WORKER_POOL_LIMITS.ADS_PER_MESSAGE);
    if (ads.length === 0) return;
    this.peerManager.sendMessage(from, WireType.OZZY_WORKER_ADS, { ads });
  }

  /** 広告を確かめて取り込む。形・URL・期限・身元 (PoW)・署名のどれかが合わなければ捨てる */
  private handleAds(_from: PeerId, msg: any): void {
    if (this.destroyed || !Array.isArray(msg?.ads)) return;
    const t = this.now();
    const nowMin = Math.floor(t / 60_000);
    const maxMin = Math.floor((t + WORKER_POOL_LIMITS.MAX_AD_LIFETIME_MS) / 60_000);
    for (const ad of msg.ads.slice(0, WORKER_POOL_LIMITS.ADS_PER_MESSAGE) as WorkerAd[]) {
      if (!this.acceptAd(ad, nowMin, maxMin, t)) this.stats.rejected++;
    }
    if (this.ads.size > WORKER_POOL_LIMITS.MAX_ADS) this.prune();
  }

  private acceptAd(ad: WorkerAd, nowMin: number, maxMin: number, t: number): boolean {
    if (!(ad?.pubkey instanceof Uint8Array) || !(ad.signature instanceof Uint8Array)) return false;
    if (!Number.isInteger(ad.expiresMin) || ad.expiresMin <= nowMin || ad.expiresMin > maxMin) return false;
    if (normalizeOzzyWorkerUrl(ad.url) !== ad.url) return false;
    let peerId: PeerId;
    try {
      peerId = NodeIdentity.derivePeerId(ad.pubkey);
    } catch {
      return false;
    }
    if (peerId === this.peerManager.myPeerId) return true; // 自分の広告が戻ってきた
    const prev = this.ads.get(peerId);
    if (prev && prev.ad.expiresMin >= ad.expiresMin) return true; // 同じか古い
    try {
      if (!sodium.crypto_sign_verify_detached(ad.signature, ozzyWorkerAdMessage(ad.pubkey, ad.url, ad.expiresMin), ad.pubkey)) return false;
    } catch {
      return false;
    }
    const keyHex = Encoding.toHex(ad.pubkey);
    if (!this.verifiedKeys.has(keyHex)) {
      // ★ 身元の PoW (Argon2id) は重いので、署名が通ったものだけ・鍵ごとに 1 回だけ確かめる
      if (!NodeIdentity.verifyClaim({ peerId, pubkey: ad.pubkey, powCounter: ad.powCounter }, this.powParams)) return false;
      this.verifiedKeys.add(keyHex);
      if (this.verifiedKeys.size > WORKER_POOL_LIMITS.MAX_ADS * 2) this.verifiedKeys.delete(this.verifiedKeys.values().next().value!);
    }
    // 同じ身元が URL を替えたら、観測期間は数え直す (古い URL の実績を新しい URL に引き継がせない)
    const firstSeen = prev && prev.ad.url === ad.url ? prev.firstSeen : t;
    this.ads.set(peerId, { ad, firstSeen });
    this.stats.accepted++;
    return true;
  }

  private prune(): void {
    const nowMin = Math.floor(this.now() / 60_000);
    for (const [id, e] of this.ads) if (e.ad.expiresMin <= nowMin) this.ads.delete(id);
    if (this.ads.size > WORKER_POOL_LIMITS.MAX_ADS) {
      const order = Array.from(this.ads.entries()).sort((a, b) => a[1].ad.expiresMin - b[1].ad.expiresMin);
      for (let i = 0; i < order.length - WORKER_POOL_LIMITS.MAX_ADS; i++) this.ads.delete(order[i][0]);
    }
  }

  public destroy(): void {
    this.destroyed = true;
    if (this.exchangeTimer) clearInterval(this.exchangeTimer);
    if (this.refreshTimer) clearInterval(this.refreshTimer);
    this.exchangeTimer = null;
    this.refreshTimer = null;
    this.ads.clear();
    this.peerManager.off('peer:verified', this.onVerified);
    this.dispatcher.unregister?.(WireType.OZZY_WORKER_REQ, this.onReq);
    this.dispatcher.unregister?.(WireType.OZZY_WORKER_ADS, this.onAds);
    log.debug(() => 'worker pool destroyed');
  }
}

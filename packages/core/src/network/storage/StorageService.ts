import type { IMessageDispatcher, IPeerManager, GossipPacket } from '../../types';
import type { DandelionRouter } from '../gossip/DandelionRouter';
import type { GossipRouter } from '../gossip/GossipRouter';
import type { HolderDB } from '../../storage/HolderDB';
import { Encoding } from '../../common/Encoding';
import { createLogger } from '../../common/Logger';
import { Duty, birthDayOf, type DutyOptions } from './Duty';
import { HolderStore } from './HolderStore';
import { ChunkStore } from './ChunkStore';
import { LeaseSetRouter, type LeaseSetRouterOptions } from './LeaseSetRouter';
import { LeaseSetStore, type SlotEntry } from './LeaseSetStore';
import { TunnelHolder, type TunnelHolderOptions } from './TunnelHolder';
import { MAX_SLOTS, SLOT_BYTES, SLOT_EFFORT } from './SlotPow';
import { StorageIdentity, type StorageIdentityStore } from './StorageIdentity';

const log = createLogger('net.storage');

/** 容量 (枠の数) を置く kv の名前 */
export const STORAGE_CAPACITY_KEY = 'storage.capacity';
/**
 * 容量 (枠の数 × 256MiB) のうち、投稿のバケット (過去ログ) が使える割合。残りは大容量ファイルのチャンク。
 * ★ 別枠にする理由: 大容量が過去ログを押し出さない (docs/design/file-sharing.md §6-3)。投稿は 90 日 × 全板でも
 *   1 日あたり数 MiB 〜 数十 MiB なので 25% (1 枠なら 64MiB) で足りる。余った分は流用しない (流用すると押し出しが起きる)。
 */
export const POST_QUOTA_SHARE = 0.25;
/** 保持期限切れの掃除の間隔 */
const RETENTION_INTERVAL_MS = 60 * 60 * 1000;

export interface StorageServiceParts {
  peerManager: IPeerManager;
  dispatcher: IMessageDispatcher;
  dandelion: DandelionRouter;
  gossipRouter: GossipRouter;
  /** 暗号化 DB の kv */
  settings: StorageIdentityStore;
  /** 預かり先。null なら leaseSet の配布と枠だけ動かし、保存はしない */
  holderDb: HolderDB | null;
  /** 受け口として認める peerId (信頼リスト有効なら信頼 Guard のみ) */
  gatewayAllowed: (peerId: string) => boolean;
  /** 設定が無いときの枠の数。デスクトップ 4、ブラウザ 1 (呼び出し側が決める) */
  defaultSlots: number;
  now?: () => number;
  /** ★ テスト専用 */
  slotEffort?: number;
  /** ★ テスト専用 (チャンクの保存の PoW を軽くする。本番は CHUNK_EFFORT = 全ノードで同じ) */
  chunkEffort?: number;
  duty?: DutyOptions;
  router?: LeaseSetRouterOptions;
  tunnel?: TunnelHolderOptions;
}

function clampSlots(n: unknown, fallback: number): number {
  const v = typeof n === 'number' && Number.isFinite(n) ? Math.floor(n) : fallback;
  return Math.max(1, Math.min(MAX_SLOTS, v));
}

/**
 * StorageService — 保管担当の部品 (SID・枠・leaseSet・担当の判定・預かり) をつなぐ (history v2 §4)。
 *
 *   投稿 (live / 追いつき / 自分の発信) ─ GossipRouter.onStoredCandidate ─ Duty ─(担当なら)─ HolderStore
 *   SID の枠を裏で解く ─ 解けるたびに leaseSet を出し直す ─ LeaseSetRouter が flood
 *
 * ★ 取りに行く側 (HistoryClient) は OzNode が別に配線する。ここは「持つ」側: 預かりと、受け口 (トンネル) への登録・要求への応答。
 * ★ 容量は枠の数で決める (1 枠 = 256MiB、最小 1)。変更は setCapacity。UI は後続。
 */
export class StorageService {
  public readonly leaseSets: LeaseSetStore;
  public readonly duty: Duty;
  public readonly router: LeaseSetRouter;
  /** 受け口 (トンネル) への登録と、FETCH_BUCKET への応答。預かり先 (holderDb) が無ければ null */
  public readonly tunnel: TunnelHolder | null;
  /** 大容量ファイルのチャンクの預かり (投稿とは別の容量・別のストア)。預かり先が無ければ null */
  public readonly chunks: ChunkStore | null;
  private ownEntries: SlotEntry[] = [];
  private ownCount = -1;
  private retentionTimer: ReturnType<typeof setInterval> | null = null;
  private unsubscribe: (() => void) | null = null;
  private started = false;
  private stopped = false;

  private constructor(
    public readonly identity: StorageIdentity,
    private readonly settings: StorageIdentityStore,
    public readonly holder: HolderStore | null,
    chunks: ChunkStore | null,
    private capacity: number,
    parts: StorageServiceParts,
  ) {
    const now = parts.now ?? Date.now;
    this.leaseSets = new LeaseSetStore(now);
    this.duty = new Duty(this.leaseSets, () => this.own(), { now, ...parts.duty });
    this.router = new LeaseSetRouter(
      parts.peerManager, parts.dispatcher, parts.dandelion, this.leaseSets,
      {
        publicKey: identity.publicKey,
        sign: (m) => identity.sign(m),
        slots: () => this.activeSlots().map(s => ({ nonce: s.nonce, solution: s.solution })),
      },
      parts.gatewayAllowed,
      { now, slotEffort: parts.slotEffort, ...parts.router },
    );
    this.chunks = chunks;
    this.tunnel = holder
      ? new TunnelHolder(parts.peerManager, parts.dispatcher, this.router, identity, holder, {
        now,
        chunks: chunks ? { store: chunks, shouldStore: (id) => this.duty.shouldStoreChunk(id), effort: parts.chunkEffort } : undefined,
        ...parts.tunnel,
      })
      : null;
    this.unsubscribe = parts.gossipRouter.onStoredCandidate((packet) => this.onPacket(packet));
  }

  public static async create(parts: StorageServiceParts): Promise<StorageService> {
    const effort = parts.slotEffort ?? SLOT_EFFORT;
    const identity = await StorageIdentity.loadOrCreate(parts.settings, effort);
    const saved = await parts.settings.get(STORAGE_CAPACITY_KEY);
    const capacity = clampSlots(saved, parts.defaultSlots);
    // quotaBytes は作成後の最新の枠の数を見る (setCapacity で変わる)
    let svc: StorageService | null = null;
    const total = () => (svc?.capacity ?? capacity) * SLOT_BYTES;
    const holder = parts.holderDb
      ? await HolderStore.open(parts.holderDb, { quotaBytes: () => Math.floor(total() * POST_QUOTA_SHARE), now: parts.now })
      : null;
    const chunks = parts.holderDb
      ? await ChunkStore.open(parts.holderDb.openChunkDb(), { quotaBytes: () => total() - Math.floor(total() * POST_QUOTA_SHARE), now: parts.now })
      : null;
    svc = new StorageService(identity, parts.settings, holder, chunks, capacity, parts);
    return svc;
  }

  /** 枠の数 (容量。1 枠 = 256MiB) */
  public get capacitySlots(): number {
    return this.capacity;
  }

  /** いま受け持っている枠 (容量の範囲内で解き終わったもの) */
  public activeSlots() {
    return this.identity.slots.slice(0, this.capacity);
  }

  private own(): { sid: string; slots: SlotEntry[] } | null {
    const active = this.activeSlots();
    if (active.length === 0) return null;
    if (active.length !== this.ownCount) {
      const sid = Encoding.toHex(this.identity.publicKey);
      this.ownEntries = active.map(s => ({
        key: `${sid}${s.index.toString(16).padStart(2, '0')}`,
        id: Uint8Array.of(...this.identity.publicKey, s.index),
        position: s.position,
        sid,
        index: s.index,
      }));
      this.ownCount = active.length;
    }
    return { sid: Encoding.toHex(this.identity.publicKey), slots: this.ownEntries };
  }

  /** 動かす: leaseSet の配布、枠の計算 (裏で)、保持期限の掃除 */
  public start(): void {
    if (this.started || this.stopped) return;
    this.started = true;
    this.router.start();
    if (this.holder) {
      const prune = () => {
        void this.holder!.prune().catch(e => log.warn('retention failed', e));
        void this.chunks?.prune().catch(e => log.warn('chunk retention failed', e));
      };
      prune();
      this.retentionTimer = setInterval(prune, RETENTION_INTERVAL_MS);
    }
    this.solveInBackground();
  }

  private solveInBackground(): void {
    void this.identity
      .ensureSlots(this.capacity, () => {
        // 枠が 1 つ解けるたびに、公開する枠を増やして出し直す
        this.router.publish();
      })
      .catch(e => log.warn('slot solving failed', e));
  }

  /**
   * 容量を変える (枠の数、最小 1)。増やすと裏で枠を解き足して leaseSet を出し直し、
   * 減らすと預かり量を新しい容量に収める。
   */
  public async setCapacity(slots: number): Promise<void> {
    const next = clampSlots(slots, this.capacity);
    if (next === this.capacity) return;
    const grew = next > this.capacity;
    this.capacity = next;
    await this.settings.set(STORAGE_CAPACITY_KEY, next);
    if (this.started) {
      if (grew) this.solveInBackground();
      this.router.publish();
    }
    if (!grew && this.holder) await this.holder.enforceQuota();
    if (!grew && this.chunks) await this.chunks.enforceQuota();
  }

  /** 検証済みの投稿が手元に届いたとき (live・追いつき・自分の発信) */
  private onPacket(packet: GossipPacket): void {
    if (!this.holder || this.stopped) return;
    const birthDay = birthDayOf(packet.timestamp, packet.age);
    if (!this.duty.shouldStore(birthDay, packet.tag)) return;
    void this.holder.put(packet).catch(e => log.warn('store failed', e));
  }

  /** 止める。預かりの書き込みを流し、鍵を消す。DB を lock する前に待つこと */
  public async stop(): Promise<void> {
    if (this.stopped) return;
    this.stopped = true;
    this.unsubscribe?.();
    this.unsubscribe = null;
    if (this.retentionTimer) clearInterval(this.retentionTimer);
    this.retentionTimer = null;
    this.tunnel?.destroy();
    this.router.destroy();
    await this.identity.destroy();
    // ★ 封印の鍵 (HolderDB の vault) は投稿とチャンクで共有する。投稿側の close が鍵を消すので、チャンク側を先に閉じる
    await this.chunks?.close();
    await this.holder?.close();
  }
}

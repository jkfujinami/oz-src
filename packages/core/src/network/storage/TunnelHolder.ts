import type { IMessageDispatcher, IPeerManager, PeerId } from '../../types';
import { createLogger } from '../../common/Logger';
import { Encoding } from '../../common/Encoding';
import { WireType } from '../wire/WireTypes';
import { TUNNEL_ERROR_CODE } from '../wire/WireCodec';
import {
  TUNNEL_CHUNK_DATA_BYTES, TUNNEL_KIND, encryptChunk, parseRequestPlain, sealedRequestBytes,
} from '../tunnel/TunnelCrypto';
import {
  FETCH_MAX_RESPONSE_BYTES, FETCH_STATUS, buildFetchResponse, decodeFetchRequest, encodeFetchResponse,
} from '../history/FetchBucket';
import { bytesEqual, idOf, TAG_BYTES } from '../../files/FileFormat';
import type { HolderStore } from './HolderStore';
import type { ChunkStore } from './ChunkStore';
import { CHUNK_EFFORT, verifyChunkPow } from './ChunkPow';
import {
  CHUNK_MAX_CIPHER_BYTES, CHUNK_STATUS, PUT_HEADER_BYTES, decodeGetRequest, decodePutFragment,
  encodeGetResponse, encodeStatusResponse, type ChunkStatus,
} from './ChunkProtocol';

import { timeMinOf } from './HolderStore';
import type { LeaseSetRouter } from './LeaseSetRouter';
import type { StorageIdentity } from './StorageIdentity';

const log = createLogger('net.storage.tunnel');

export const TUNNEL_HOLDER_LIMITS = {
  /** 1 つの返しのホップ (fromHop) からの要求の頻度と同時数。fromHop は利用者を束ねる Guard なので、ある程度広く取る */
  PER_HOP_REQ_PER_SEC: 10,
  PER_HOP_BURST: 20,
  PER_HOP_CONCURRENT: 16,
  /** 同時に応答する数 (全体)。応答 1 つは最大 4MiB (約 270 片) */
  MAX_CONCURRENT: 24,
  /**
   * 応答の片の送出間隔 (全応答の合計で 1 本)。10ms = 100 フレーム/秒 = 約 1.5MiB/秒。
   * ★ 中継の枠 (TunnelRelay.PEER の帯域 2MiB/秒・RATE_LIMITS.tunnel の 200 フレーム/秒) に収まる。
   */
  CHUNK_INTERVAL_MS: 10,
  /**
   * ── C4: 預け入れ (PUT_CHUNK) の押し流し対策 (docs/design/file-sharing.md §6) ──
   * ★ PUT の断片は大きい (約 15KiB) ので、小さな要求 (FETCH_BUCKET・GET_CHUNK) の枠 (PER_HOP_REQ_PER_SEC = 10/秒) とは**別の枠**で数える。
   *   同じ枠にすると、1 チャンク (18 断片) の預け入れで読み出しが締め出され、逆に読み出しが多いと預け入れが進まない。
   *   区別は封印後の本体の大きさ (BULK_BODY_BYTES 以上なら断片) で、封印を開ける前にできる (開けるのは CPU を使う)。
   * ★ 返しのホップ (fromHop) ごと。fromHop は利用者を束ねる Guard なので、1 人の押し流しはその Guard の利用者全員の枠を食う。
   *   Guard 側の上り制限 (TUNNEL_LIMITS.CLIENT_SEND) が先に 1 人あたりを絞っているので、ここは「1 つの Guard 経由の合計」の天井。
   */
  /** 断片の到着の頻度 (件/秒)。100/秒 × 15KiB = 約 1.5MiB/秒 (応答の送出と同じ桁) */
  PER_HOP_PUT_FRAG_PER_SEC: 100,
  PER_HOP_PUT_FRAG_BURST: 200,
  /**
   * 1 つのホップが完成させて預けられるチャンクの数 (個/秒)。0.5/秒 = 1 分に 30 個 = 約 7.5MiB/分。
   * 正直な利用者の上げ方 (1MiB/秒 × 複製 5 か所を保持者の数で割る) はこれより桁違いに少ない。バーストは 1 ファイルの先頭の固まり用。
   */
  PER_HOP_PUTS_PER_SEC: 0.5,
  PER_HOP_PUTS_BURST: 32,
  /** 1 つのホップが同時に集めてよいチャンク (断片の組み立て中) の数と、全体の数。256KiB × 32 = 8MiB まで */
  PER_HOP_ASSEMBLIES: 8,
  MAX_ASSEMBLIES: 32,
  /** 断片を集めている途中のチャンクを捨てるまで (ms)。最後の断片から数える */
  ASSEMBLY_TTL_MS: 60_000,
  /** 同時に「検証して書き込んでいる」チャンクの数 (全体)。書き込みの待ちに 256KiB ずつ溜まるのを防ぐ */
  MAX_STORING: 8,
  /** 封印後の本体がこの大きさ以上なら、PUT の断片の枠で数える (最小の断片 = ヘッダ + データ 1 バイト) */
  BULK_BODY_BYTES: sealedRequestBytes(PUT_HEADER_BYTES + 1),
  /** 受け口への登録が確認できないときの再送の間隔 (ms)。最後の値を繰り返す */
  REGISTER_RETRY_MS: [15_000, 30_000, 60_000, 300_000],
} as const;

export interface TunnelHolderOptions {
  now?: () => number;
  /** ★ テスト専用 */
  limits?: Partial<{
    perHopReqPerSec: number; perHopBurst: number; perHopConcurrent: number; maxConcurrent: number; chunkIntervalMs: number; maxResponseBytes: number;
    perHopPutFragPerSec: number; perHopPutFragBurst: number; perHopPutsPerSec: number; perHopPutsBurst: number;
    perHopAssemblies: number; maxAssemblies: number; assemblyTtlMs: number; maxStoring: number;
  }>;
  /**
   * 大容量ファイルのチャンクの預かり (PUT_CHUNK / GET_CHUNK)。省略なら、その種別の要求は BAD_REQUEST で断る。
   * `effort` は ★ テスト専用 (保存の PoW を軽くする。本番は CHUNK_EFFORT = 全ノードで同じ)。
   */
  chunks?: { store: ChunkStore; shouldStore: (chunkId: Uint8Array) => boolean; effort?: number };
}

interface Bucket { tokens: number; last: number }

/** 断片を集めている途中のチャンク (キー = 返しのホップ ‖ チャンク ID) */
interface Assembly {
  hop: PeerId;
  chunkId: Uint8Array;
  fragCount: number;
  parts: Array<Uint8Array | undefined>;
  got: number;
  bytes: number;
  lastAt: number;
}

interface Response {
  gateway: PeerId;
  returnTag: number;
  hop: PeerId;
  chunks: Uint8Array[];
  next: number;
  /** 全部送り終えた・取り消されたときに、同時数の枠を返す */
  release: () => void;
}

/**
 * TunnelHolder — 保持者 H の側: 受け口の Guard に登録し、届いた要求 (FETCH_BUCKET) に答える (history v2 §4.4)。
 *
 *   登録  leaseSet を出すたび / 受け口が (再) 接続して検証済みになるたびに、TUNNEL_REGISTER{tunnelId} を受け口へ送る。
 *         受け口は tunnelId → この接続を覚える (接続が切れれば消える)。応答 (REGISTERED) が来なければ間隔を空けて再送する。
 *   応答  TUNNEL_DELIVER{returnTag, fromHop, body} を受け取り、body を SID の鍵で開く (sealed box)。中身は
 *         { kind, respKey, payload }。FETCH_BUCKET なら HolderStore から取り、respKey で 1 片ずつ暗号化して
 *         TUNNEL_REPLY で返す (最大 4MiB。1 片 15KiB。10ms 間隔)。
 *
 * ★ H が知るのは「受け口 (自分の Guard) と、その先の返しのホップ (fromHop)」だけ。要求者の peerId は渡ってこない。
 *   開けた要求の中身 (どのバケットか) は、応答を返したあと残さない。
 * ★ 返しのホップごとに、頻度・同時数を絞る (fromHop が 1 つの Guard に偏っていても、その Guard の利用者全員ぶん)。
 * ★ 受け口として認めるのは**自分が最後に出した leaseSet の受け口**だけ。他の接続から来た DELIVER は無視する。
 */
export class TunnelHolder {
  private readonly now: () => number;
  private readonly lim: {
    perHopReqPerSec: number; perHopBurst: number; perHopConcurrent: number; maxConcurrent: number; chunkIntervalMs: number; maxResponseBytes: number;
    perHopPutFragPerSec: number; perHopPutFragBurst: number; perHopPutsPerSec: number; perHopPutsBurst: number;
    perHopAssemblies: number; maxAssemblies: number; assemblyTtlMs: number; maxStoring: number;
  };
  private readonly chunks: TunnelHolderOptions['chunks'] | null;
  private readonly chunkEffort: number;
  private fragBuckets = new Map<PeerId, Bucket>();
  private putBuckets = new Map<PeerId, Bucket>();
  private assemblies = new Map<string, Assembly>();
  private assemblyTimer: ReturnType<typeof setInterval> | null = null;
  private storing = 0;
  /** 最後に出した leaseSet の受け口。DELIVER はここからだけ受け付ける */
  private want: { gateway: PeerId; tunnelId: Uint8Array } | null = null;
  private confirmed = false;
  private retries = 0;
  private retryTimer: ReturnType<typeof setTimeout> | null = null;
  private hopBuckets = new Map<PeerId, Bucket>();
  private hopActive = new Map<PeerId, number>();
  private active: Response[] = [];
  private activeCount = 0;
  private pumpTimer: ReturnType<typeof setTimeout> | null = null;
  private lastSendAt = 0;
  private destroyed = false;

  /** 診断・テスト用 */
  public readonly stats = {
    served: 0,
    notHeld: 0,
    chunksSent: 0,
    registerSent: 0,
    rejected: { source: 0, rate: 0, concurrent: 0, badRequest: 0 },
    /** チャンクの預け入れ・読み出し (診断・テスト用) */
    chunks: { stored: 0, fragments: 0, served: 0, notHeld: 0, rejected: { pow: 0, duty: 0, id: 0, full: 0, rate: 0, request: 0 } },
  };
  /** 直近に受け取った要求の返しのホップ (テストが「H が知るのは fromHop だけ」を確かめるのに使う) */
  public readonly seenHops = new Set<PeerId>();

  private readonly onVerified = (peer: { peerId: PeerId }) => {
    if (this.want && peer?.peerId === this.want.gateway) this.sendRegister();
  };
  private readonly onDisconnect = (peerId: PeerId) => {
    if (this.want && peerId === this.want.gateway) {
      this.confirmed = false;
      this.dropResponses(peerId);
    }
  };

  constructor(
    private readonly peerManager: IPeerManager,
    dispatcher: IMessageDispatcher,
    leaseRouter: LeaseSetRouter,
    private readonly identity: StorageIdentity,
    private readonly holder: HolderStore | null,
    options: TunnelHolderOptions = {},
  ) {
    this.now = options.now ?? Date.now;
    const l = options.limits ?? {};
    this.lim = {
      perHopReqPerSec: l.perHopReqPerSec ?? TUNNEL_HOLDER_LIMITS.PER_HOP_REQ_PER_SEC,
      perHopBurst: l.perHopBurst ?? TUNNEL_HOLDER_LIMITS.PER_HOP_BURST,
      perHopConcurrent: l.perHopConcurrent ?? TUNNEL_HOLDER_LIMITS.PER_HOP_CONCURRENT,
      maxConcurrent: l.maxConcurrent ?? TUNNEL_HOLDER_LIMITS.MAX_CONCURRENT,
      chunkIntervalMs: l.chunkIntervalMs ?? TUNNEL_HOLDER_LIMITS.CHUNK_INTERVAL_MS,
      maxResponseBytes: l.maxResponseBytes ?? FETCH_MAX_RESPONSE_BYTES,
      perHopPutFragPerSec: l.perHopPutFragPerSec ?? TUNNEL_HOLDER_LIMITS.PER_HOP_PUT_FRAG_PER_SEC,
      perHopPutFragBurst: l.perHopPutFragBurst ?? TUNNEL_HOLDER_LIMITS.PER_HOP_PUT_FRAG_BURST,
      perHopPutsPerSec: l.perHopPutsPerSec ?? TUNNEL_HOLDER_LIMITS.PER_HOP_PUTS_PER_SEC,
      perHopPutsBurst: l.perHopPutsBurst ?? TUNNEL_HOLDER_LIMITS.PER_HOP_PUTS_BURST,
      perHopAssemblies: l.perHopAssemblies ?? TUNNEL_HOLDER_LIMITS.PER_HOP_ASSEMBLIES,
      maxAssemblies: l.maxAssemblies ?? TUNNEL_HOLDER_LIMITS.MAX_ASSEMBLIES,
      assemblyTtlMs: l.assemblyTtlMs ?? TUNNEL_HOLDER_LIMITS.ASSEMBLY_TTL_MS,
      maxStoring: l.maxStoring ?? TUNNEL_HOLDER_LIMITS.MAX_STORING,
    };
    this.chunks = options.chunks ?? null;
    this.chunkEffort = options.chunks?.effort ?? CHUNK_EFFORT;
    dispatcher.register(WireType.TUNNEL_DELIVER, (from, msg) => this.handleDeliver(from, msg));
    dispatcher.register(WireType.TUNNEL_REGISTERED, (from, msg) => this.handleRegistered(from, msg));
    peerManager.on('peer:verified', this.onVerified);
    peerManager.on('peer:disconnect', this.onDisconnect);
    leaseRouter.onPublished((t) => this.setTunnel(t));
  }

  /** 登録されているか (受け口が確認した) */
  public get registered(): boolean {
    return this.confirmed;
  }

  // ── 登録 ──

  private setTunnel(t: { gateway: PeerId; tunnelId: Uint8Array }): void {
    if (this.destroyed || !this.holder) return;
    const same = this.want && this.want.gateway === t.gateway && Encoding.toHex(this.want.tunnelId) === Encoding.toHex(t.tunnelId);
    this.want = t;
    if (!same) {
      this.confirmed = false;
      this.retries = 0;
    }
    this.sendRegister();
  }

  private sendRegister(): void {
    if (this.destroyed || !this.want) return;
    if (this.retryTimer) clearTimeout(this.retryTimer);
    this.retryTimer = null;
    const peer = this.peerManager.peers.get(this.want.gateway);
    if (peer && peer.isConnected && peer.isVerified) {
      this.stats.registerSent++;
      this.peerManager.sendMessage(this.want.gateway, WireType.TUNNEL_REGISTER, { tunnelId: this.want.tunnelId });
    }
    // 確認が来なければ (接続がまだ・拒否・取りこぼし) 間隔を空けて再送する
    const delays = TUNNEL_HOLDER_LIMITS.REGISTER_RETRY_MS;
    const delay = delays[Math.min(this.retries, delays.length - 1)];
    this.retries++;
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null;
      if (!this.confirmed) this.sendRegister();
    }, delay);
  }

  private handleRegistered(from: PeerId, msg: any): void {
    if (!this.want || from !== this.want.gateway) return;
    const id = msg?.tunnelId;
    if (!(id instanceof Uint8Array) || Encoding.toHex(id) !== Encoding.toHex(this.want.tunnelId)) return;
    if (msg.ok === true) {
      this.confirmed = true;
      this.retries = 0;
      if (this.retryTimer) clearTimeout(this.retryTimer);
      this.retryTimer = null;
    } else {
      this.confirmed = false;
      log.debug(() => 'gateway refused the tunnel registration');
    }
  }

  // ── 要求 ──

  private takeFrom(buckets: Map<PeerId, Bucket>, hop: PeerId, perSec: number, burst: number): boolean {
    let b = buckets.get(hop);
    const t = this.now();
    if (!b) {
      b = { tokens: burst, last: t };
      buckets.set(hop, b);
    }
    b.tokens = Math.min(burst, b.tokens + (Math.max(0, t - b.last) / 1000) * perSec);
    b.last = t;
    if (b.tokens < 1) return false;
    b.tokens -= 1;
    return true;
  }

  private takeHop(hop: PeerId): boolean {
    return this.takeFrom(this.hopBuckets, hop, this.lim.perHopReqPerSec, this.lim.perHopBurst);
  }

  private error(gateway: PeerId, returnTag: number, code: number): void {
    this.peerManager.sendMessage(gateway, WireType.TUNNEL_ERROR, { id: returnTag, code });
  }

  private handleDeliver(from: PeerId, msg: any): void {
    if (this.destroyed || !this.holder) return;
    const { returnTag, fromHop, body } = msg ?? {};
    if (!Number.isInteger(returnTag) || typeof fromHop !== 'string' || !(body instanceof Uint8Array)) return;
    if (!this.want || from !== this.want.gateway) {
      this.stats.rejected.source++;
      return;
    }
    // ★ 封印を開ける (CPU を使う) 前に、本体の大きさで枠を分ける: 大きいものは PUT の断片、小さいものは FETCH / GET の要求
    const bulk = body.length >= TUNNEL_HOLDER_LIMITS.BULK_BODY_BYTES;
    if (bulk) {
      if (!this.takeFrom(this.fragBuckets, fromHop, this.lim.perHopPutFragPerSec, this.lim.perHopPutFragBurst)) {
        this.stats.rejected.rate++;
        return this.error(from, returnTag, TUNNEL_ERROR_CODE.BUSY);
      }
    } else {
      if (!this.takeHop(fromHop)) {
        this.stats.rejected.rate++;
        return this.error(from, returnTag, TUNNEL_ERROR_CODE.BUSY);
      }
      if (this.activeCount >= this.lim.maxConcurrent || (this.hopActive.get(fromHop) ?? 0) >= this.lim.perHopConcurrent) {
        this.stats.rejected.concurrent++;
        return this.error(from, returnTag, TUNNEL_ERROR_CODE.BUSY);
      }
    }
    const plain = this.identity.openSealed(body);
    const req = plain ? parseRequestPlain(plain) : null;
    plain?.fill(0);
    let job: (() => Promise<Uint8Array>) | null = null;
    if (req && !bulk) {
      if (req.kind === TUNNEL_KIND.FETCH_BUCKET) {
        const fetch = decodeFetchRequest(req.payload);
        if (fetch) job = () => this.serveFetch(fetch);
      } else if (req.kind === TUNNEL_KIND.GET_CHUNK && this.chunks) {
        const id = decodeGetRequest(req.payload);
        if (id) job = () => this.serveGetChunk(id);
      }
    } else if (req && bulk && req.kind === TUNNEL_KIND.PUT_CHUNK && this.chunks) {
      const frag = decodePutFragment(req.payload);
      if (frag) job = async () => encodeStatusResponse(await this.servePutFragment(fromHop, frag));
    }
    if (!req || !job) {
      this.stats.rejected.badRequest++;
      req?.respKey.fill(0);
      return this.error(from, returnTag, TUNNEL_ERROR_CODE.BAD_REQUEST);
    }
    if (this.seenHops.size < 64) this.seenHops.add(fromHop);
    // 預け入れの断片は短時間で終わる (同期で集めるだけ。揃った 1 通だけが書き込みを待つ) ので、同時数の枠には数えない
    const counted = !bulk;
    if (counted) {
      this.activeCount++;
      this.hopActive.set(fromHop, (this.hopActive.get(fromHop) ?? 0) + 1);
    }
    const release = () => {
      if (!counted) return;
      this.activeCount--;
      const n = (this.hopActive.get(fromHop) ?? 1) - 1;
      if (n <= 0) this.hopActive.delete(fromHop);
      else this.hopActive.set(fromHop, n);
    };
    void this.respond(from, returnTag, fromHop, req.kind, req.respKey, job, release).catch((e) => {
      log.warn('serving a request failed', e);
      release();
      this.error(from, returnTag, TUNNEL_ERROR_CODE.BAD_REQUEST);
    });
  }

  private async serveFetch(req: { birthDay: number; tag: number; since: number }): Promise<Uint8Array> {
    const store = this.holder!;
    if (!store.hasBucket(req.birthDay, req.tag)) {
      this.stats.notHeld++;
      return encodeFetchResponse({ status: FETCH_STATUS.NOT_HELD, nextSince: 0, packets: [] });
    }
    const packets = await store.getBucket(req.birthDay, req.tag, req.since);
    return encodeFetchResponse(buildFetchResponse(packets, timeMinOf, req.since, this.lim.maxResponseBytes));
  }

  // ── 大容量ファイルのチャンク (docs/design/file-sharing.md §3・§4・§5) ──

  /** GET_CHUNK: 持っていれば暗号文を返す (最後に取られた日を今日にする)。担当かどうかは見ない (持っているものは返す) */
  private async serveGetChunk(chunkId: Uint8Array): Promise<Uint8Array> {
    const data = await this.chunks!.store.get(chunkId);
    if (!data) {
      this.stats.chunks.notHeld++;
      return encodeGetResponse(CHUNK_STATUS.NOT_HELD);
    }
    this.stats.chunks.served++;
    return encodeGetResponse(CHUNK_STATUS.OK, data);
  }

  private dropAssembly(key: string): void {
    this.assemblies.delete(key);
    if (this.assemblies.size === 0 && this.assemblyTimer) {
      clearInterval(this.assemblyTimer);
      this.assemblyTimer = null;
    }
  }

  private sweepAssemblies(): void {
    const horizon = this.now() - this.lim.assemblyTtlMs;
    for (const [key, a] of Array.from(this.assemblies)) if (a.lastAt <= horizon) this.dropAssembly(key);
  }

  /**
   * PUT_CHUNK の断片 1 つ。最初の断片で PoW と担当を確かめ (不正ならバッファを取らない)、揃ったらハッシュを確かめて預かる。
   *
   * ★ 断片を集める処理は**同期**で行い (await の前に揃ったかを決める)、揃える 1 通だけが STORED / 失敗を返す。
   *   他の断片は OK (途中)。同じ断片の再送・保存済みのチャンクへの再送は冪等 (保存済みなら STORED)。
   * ★ 集める途中の状態の数を、ホップごと・全体で絞る。メモリは最大 MAX_ASSEMBLIES × 256KiB。
   */
  private async servePutFragment(hop: PeerId, f: ReturnType<typeof decodePutFragment> & {}): Promise<ChunkStatus> {
    const store = this.chunks!.store;
    const st = this.stats.chunks;
    if (store.has(f.chunkId)) return CHUNK_STATUS.STORED;
    const key = `${hop}:${Encoding.toHex(f.chunkId)}`;
    let a = this.assemblies.get(key);
    if (!a) {
      if (!verifyChunkPow(f.chunkId, { nonce: f.powNonce, solution: f.powSolution }, this.chunkEffort)) {
        st.rejected.pow++;
        return CHUNK_STATUS.BAD_POW;
      }
      if (!this.chunks!.shouldStore(f.chunkId)) {
        st.rejected.duty++;
        return CHUNK_STATUS.NOT_DUTY;
      }
      this.sweepAssemblies();
      let mine = 0;
      for (const x of this.assemblies.values()) if (x.hop === hop) mine++;
      if (mine >= this.lim.perHopAssemblies || this.assemblies.size >= this.lim.maxAssemblies) {
        st.rejected.full++;
        return CHUNK_STATUS.FULL;
      }
      a = { hop, chunkId: f.chunkId, fragCount: f.fragCount, parts: new Array(f.fragCount), got: 0, bytes: 0, lastAt: this.now() };
      this.assemblies.set(key, a);
      if (!this.assemblyTimer) {
        this.assemblyTimer = setInterval(() => this.sweepAssemblies(), Math.max(1000, Math.floor(this.lim.assemblyTtlMs / 4)));
        (this.assemblyTimer as any).unref?.();
      }
    } else if (a.fragCount !== f.fragCount) {
      this.dropAssembly(key);
      st.rejected.request++;
      return CHUNK_STATUS.BAD_REQUEST;
    }
    st.fragments++;
    a.lastAt = this.now();
    if (!a.parts[f.fragIndex]) {
      a.parts[f.fragIndex] = f.data;
      a.got++;
      a.bytes += f.data.length;
      // 断片の大きさの合計が、チャンクの最大を超えたら破棄 (fragCount の検査で 276KiB まで入りうる)
      if (a.bytes > CHUNK_MAX_CIPHER_BYTES) {
        this.dropAssembly(key);
        st.rejected.request++;
        return CHUNK_STATUS.BAD_REQUEST;
      }
    }
    if (a.got < a.fragCount) return CHUNK_STATUS.OK;

    // ── 揃った (以降は 1 通だけがここに来る: 組み立てをすぐ外すので) ──
    this.dropAssembly(key);
    if (a.bytes <= TAG_BYTES) {
      st.rejected.request++;
      return CHUNK_STATUS.BAD_REQUEST;
    }
    const data = new Uint8Array(a.bytes);
    let o = 0;
    for (const p of a.parts) {
      data.set(p!, o);
      o += p!.length;
    }
    if (!bytesEqual(idOf(data), f.chunkId)) {
      st.rejected.id++;
      return CHUNK_STATUS.BAD_ID;
    }
    // ★ 預けるチャンクの数もホップごとに絞る (PoW を解いた正当な形のチャンクでも、毎秒大量には預けさせない)
    if (!this.takeFrom(this.putBuckets, hop, this.lim.perHopPutsPerSec, this.lim.perHopPutsBurst) || this.storing >= this.lim.maxStoring) {
      st.rejected.rate++;
      return CHUNK_STATUS.FULL;
    }
    this.storing++;
    try {
      const r = await store.put(f.chunkId, data);
      if (r === 'full') {
        st.rejected.full++;
        return CHUNK_STATUS.FULL;
      }
      st.stored++;
      return CHUNK_STATUS.STORED;
    } finally {
      this.storing--;
    }
  }

  /** 応答を作って返す。ジョブの結果を 15KiB ずつの片にして respKey で暗号化する (最後の片に final) */
  private async respond(
    gateway: PeerId, returnTag: number, hop: PeerId, kind: number, respKey: Uint8Array,
    job: () => Promise<Uint8Array>, release: () => void,
  ): Promise<void> {
    const payload = await job();
    if (this.destroyed) {
      respKey.fill(0);
      return release();
    }
    const chunks: Uint8Array[] = [];
    const n = Math.max(1, Math.ceil(payload.length / TUNNEL_CHUNK_DATA_BYTES));
    for (let i = 0; i < n; i++) {
      const part = payload.subarray(i * TUNNEL_CHUNK_DATA_BYTES, (i + 1) * TUNNEL_CHUNK_DATA_BYTES);
      chunks.push(encryptChunk(respKey, kind, i, i === n - 1, part));
    }
    respKey.fill(0);
    this.stats.served++;
    if (kind === TUNNEL_KIND.PUT_CHUNK && n === 1) {
      // 預け入れの返事 (数バイト) は間隔を空けずにすぐ返す: 送出の間隔 (全応答で 1 本) に並べると、断片の数だけ待たされる
      this.stats.chunksSent++;
      this.peerManager.sendMessage(gateway, WireType.TUNNEL_REPLY, { returnTag, toHop: hop, seq: 0, final: true, body: chunks[0] });
      return release();
    }
    this.active.push({ gateway, returnTag, hop, chunks, next: 0, release });
    this.pump();
  }

  /** 応答の片を 1 つずつ、間隔を空けて送る。複数の応答は順番に 1 片ずつ (1 つの大きい応答が他を待たせない) */
  private pump(): void {
    if (this.pumpTimer || this.active.length === 0 || this.destroyed) return;
    const wait = Math.max(0, this.lastSendAt + this.lim.chunkIntervalMs - this.now());
    this.pumpTimer = setTimeout(() => {
      this.pumpTimer = null;
      const r = this.active.shift();
      if (!r) return;
      const seq = r.next++;
      const final = r.next >= r.chunks.length;
      this.lastSendAt = this.now();
      this.stats.chunksSent++;
      this.peerManager.sendMessage(r.gateway, WireType.TUNNEL_REPLY, {
        returnTag: r.returnTag, toHop: r.hop, seq, final, body: r.chunks[seq],
      });
      if (final) r.release();
      else this.active.push(r);
      this.pump();
    }, wait);
  }

  private dropResponses(gateway: PeerId): void {
    this.active = this.active.filter((r) => {
      if (r.gateway !== gateway) return true;
      r.release();
      return false;
    });
  }

  public destroy(): void {
    this.destroyed = true;
    if (this.retryTimer) clearTimeout(this.retryTimer);
    if (this.pumpTimer) clearTimeout(this.pumpTimer);
    this.retryTimer = null;
    this.pumpTimer = null;
    if (this.assemblyTimer) clearInterval(this.assemblyTimer);
    this.assemblyTimer = null;
    this.assemblies.clear();
    for (const r of this.active) r.release();
    this.active = [];
    this.peerManager.off('peer:verified', this.onVerified);
    this.peerManager.off('peer:disconnect', this.onDisconnect);
  }
}

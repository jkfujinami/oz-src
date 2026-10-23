import { sodiumReady } from '../crypto/sodium';
import { equixReady } from '../crypto/equix/EquiX';
import { createLogger } from '../common/Logger';
import type { TunnelClient } from '../network/tunnel/TunnelClient';
import { callTunnel } from '../network/tunnel/TunnelCall';
import { TUNNEL_ERROR_CODE } from '../network/wire/WireCodec';
import { TUNNEL_KIND } from '../network/tunnel/TunnelCrypto';
import { CHUNK_EFFORT, type ChunkPowSolution } from '../network/storage/ChunkPow';
import { computeChunkPow } from '../network/storage/ChunkPowEngine';
import {
  CHUNK_STATUS, FRAG_DATA_BYTES, R_FILE, R_MIN_OK, decodeStatusResponse, encodePutFragment, fragmentCountFor,
} from '../network/storage/ChunkProtocol';
import { encodeFile, chunkPositions, type EncodeOptions, type FileSource } from './FileCodec';
import { TAG_BYTES } from './FileFormat';
import { placementCandidates, type RoutingParts } from './ChunkRouting';
import {
  FileTransferError, Pacer, PauseGate, Semaphore, linkedController, sleep, waitForFirstHop,
} from './FileTransfer';

const log = createLogger('files.upload');

export const UPLOAD_LIMITS = {
  /** 同時に置いているチャンクの数。★ 手元に持つ暗号文は最大この数 + 1 チャンク (256KiB × 5 = 1.25MiB) */
  CHUNKS_IN_FLIGHT: 4,
  /**
   * 同時に出す断片 (PUT_CHUNK の要求 1 本 = 15KiB) の数。TunnelClient の手元の上限 (30) と Guard の上り枠の同時数 (32) より内側。
   * 1 本の往復が 0.3 秒なら 24 × 15KiB / 0.3 秒 = 約 1.2MiB/秒で、Guard の上り枠 (1MiB/秒) とほぼ釣り合う。
   */
  FRAGMENTS_IN_FLIGHT: 24,
  /** 断片 1 本が失敗 (時間切れ・経路の失敗) したときの再送の回数 */
  FRAGMENT_RETRIES: 2,
  RETRY_BACKOFF_MS: 150,
  /**
   * 断片を出す速さの上限 (本/秒)。★ Guard の上り枠 (TUNNEL_LIMITS.CLIENT_SEND.reqPerSec = 60/秒、帯域 1MiB/秒) より手前に置く:
   * 50 本/秒 × 15KiB = 750KiB/秒。Guard に断られてから遅くするのでなく、断られない速さで送る。
   */
  FRAGMENTS_PER_SEC: 50,
  /** Guard や保持者が BUSY (制限に当たった) と返したとき、待って同じ断片を送り直す回数の上限。待ちは 200ms から倍々 (上限 2 秒) */
  BUSY_RETRIES: 10,
  /** 応答が 1 片も来ないまま待つ上限 (ms) */
  INACTIVITY_MS: 15_000,
  /** 1 ホップ目がつながるのを待つ上限 */
  READY_WAIT_MS: 60_000,
  /** 複製を R_MIN_OK 個置けなかったチャンクを置き直す回数と、その前の待ち (保持者の leaseSet が増えるのを待つ) */
  ROUNDS: 3,
  ROUND_DELAY_MS: [1_000, 4_000],
} as const;

export interface UploadProgress {
  /** chunks: チャンクを置いている / manifest: Manifest を置いている / done: 全部置き終えた */
  phase: 'chunks' | 'manifest' | 'done';
  /** 置き終えた (R_MIN_OK 個以上の複製が確認できた) チャンクの平文の合計 */
  bytesPlaced: number;
  /** ファイルの大きさ。入力の大きさが分からない (ストリーム) ときは 0 */
  totalBytes: number;
  chunksPlaced: number;
  /** 保持者が受け取ったと確認できた複製の延べ数 (チャンク × 複製) */
  replicasAcked: number;
  /** 複製が R_FILE に満たないまま (R_MIN_OK 以上で) 置き終えたチャンクの数 */
  degradedChunks: number;
}

export interface FileUploaderParts {
  tunnel: Pick<TunnelClient, 'request' | 'firstHop'>;
  routing: RoutingParts;
  /** ★ テスト専用 (保存の PoW を軽くする。保持者側も同じ値で検証する。本番は CHUNK_EFFORT) */
  chunkEffort?: number;
  /** PoW の解き方。省略は computeChunkPow (Worker があれば Worker、無ければ同じスレッド) */
  solvePow?: (chunkId: Uint8Array, effort: number, shouldStop: () => boolean) => Promise<ChunkPowSolution | null>;
  /** ★ テスト専用 */
  limits?: Partial<{
    chunksInFlight: number; fragmentsInFlight: number; fragmentRetries: number; retryBackoffMs: number; inactivityMs: number;
    readyWaitMs: number; rounds: number; roundDelayMs: readonly number[]; fragmentsPerSec: number; busyRetries: number;
  }>;
}

export type UploadSource = FileSource;

/**
 * FileUploader — ファイルを暗号化し、チャンクごとに PoW を解いて、保持者へトンネル経由で置き、最後に取得用のリンクを返す
 * (docs/design/file-sharing.md §3)。
 *
 *   encodeFile (チャンク 1 つずつ) → 保存の PoW (1 チャンク 1 回。全複製で使い回す) → R_FILE (5) 個の複製を 5 台の保持者へ
 *   (複製 j の位置に近い 3 枠の保持者を近い順に。断られたら次) → R_MIN_OK (3) 個以上が確認できたらそのチャンクは完了
 *   → 全チャンクと Manifest が完了したらリンクを返す。
 *
 * ★ **全チャンクを置き終えてからリンクを返す**: 置いている途中に投稿が出ると、上げている時刻と投稿の時刻が結び付く。
 *   リンクを返すのは run() の最後の 1 か所だけ。途中で失敗・中止したらリンクは出ない (置いたチャンクは 90 日で消える)。
 * ★ **ディスクに何も書かない**: 進み具合も、平文も暗号文のチャンクも、メモリの外へ出さない。アプリを閉じたらアップロードは
 *   失われ、最初からやり直す (部分的な再開の情報は、「何を上げていたか」の痕跡になる)。
 * ★ 上げた端末は自分ではチャンクを配らない: 自分の SID には預けず、他の保持者へ 1 度ずつ送るだけ。
 * ★ 要求は自分の 1 ホップ目の Guard へだけ送る (TunnelClient)。保持者には Guard が転送し、保持者に見えるのは Guard だけ
 *   (自分の peerId は渡らない)。Guard には上りの量と時刻が見える (設計 §8: 利用者に説明する)。
 * ★ 一時停止は「次の断片・次のチャンクを出さない」。途中の要求は完了まで待つ。
 */
export class FileUploader {
  /** 取得用のリンク (`[[file:...]]`)。全チャンクを置き終えたときだけ解決し、失敗・中止なら拒否される */
  public readonly link: Promise<string>;

  private readonly ac = new AbortController();
  private readonly gate = new PauseGate();
  private readonly fragments: Semaphore;
  private readonly pacer: Pacer;
  private readonly lim: Required<NonNullable<FileUploaderParts['limits']>>;
  private readonly effort: number;
  private started = false;
  private finished = false;
  private cancelled = false;
  private failure: unknown = null;
  private powChain: Promise<unknown> = Promise.resolve();
  private progress: UploadProgress;
  private resolveLink!: (token: string) => void;
  private rejectLink!: (e: unknown) => void;

  constructor(
    private readonly parts: FileUploaderParts,
    private readonly source: UploadSource,
    private readonly meta: EncodeOptions,
    private readonly onProgress?: (p: UploadProgress) => void,
  ) {
    const l = parts.limits ?? {};
    this.lim = {
      chunksInFlight: l.chunksInFlight ?? UPLOAD_LIMITS.CHUNKS_IN_FLIGHT,
      fragmentsInFlight: l.fragmentsInFlight ?? UPLOAD_LIMITS.FRAGMENTS_IN_FLIGHT,
      fragmentRetries: l.fragmentRetries ?? UPLOAD_LIMITS.FRAGMENT_RETRIES,
      retryBackoffMs: l.retryBackoffMs ?? UPLOAD_LIMITS.RETRY_BACKOFF_MS,
      inactivityMs: l.inactivityMs ?? UPLOAD_LIMITS.INACTIVITY_MS,
      readyWaitMs: l.readyWaitMs ?? UPLOAD_LIMITS.READY_WAIT_MS,
      rounds: l.rounds ?? UPLOAD_LIMITS.ROUNDS,
      roundDelayMs: l.roundDelayMs ?? UPLOAD_LIMITS.ROUND_DELAY_MS,
      fragmentsPerSec: l.fragmentsPerSec ?? UPLOAD_LIMITS.FRAGMENTS_PER_SEC,
      busyRetries: l.busyRetries ?? UPLOAD_LIMITS.BUSY_RETRIES,
    };
    this.pacer = new Pacer(this.lim.fragmentsPerSec);
    this.effort = parts.chunkEffort ?? CHUNK_EFFORT;
    this.fragments = new Semaphore(this.lim.fragmentsInFlight);
    this.progress = {
      phase: 'chunks', bytesPlaced: 0, totalBytes: sizeOf(source), chunksPlaced: 0, replicasAcked: 0, degradedChunks: 0,
    };
    this.link = new Promise<string>((resolve, reject) => {
      this.resolveLink = resolve;
      this.rejectLink = reject;
    });
    // 誰も待っていなくても「未処理の拒否」にしない (結果は link を待つ側が受け取る)
    this.link.catch(() => undefined);
  }

  /** 始める (一度だけ)。link が解決・拒否されるまで裏で動く */
  public start(): this {
    if (this.started) return this;
    this.started = true;
    void this.run().then(
      (token) => { this.finished = true; this.resolveLink(token); },
      (e) => {
        this.finished = true;
        this.rejectLink(this.cancelled ? new FileTransferError('cancelled') : e);
      },
    );
    return this;
  }

  public pause(): void {
    if (!this.finished) this.gate.pause();
  }

  public resume(): void {
    this.gate.resume();
  }

  public get paused(): boolean {
    return this.gate.isPaused;
  }

  /** 中止。途中の要求は捨てる (保持者に置かれた分は 90 日で消える)。link は 'cancelled' で拒否される */
  public cancel(): void {
    if (this.finished) return;
    this.cancelled = true;
    this.ac.abort();
    this.gate.resume(); // 一時停止中でも抜けられるように
  }

  public get snapshot(): UploadProgress {
    return { ...this.progress };
  }

  private emit(): void {
    try {
      this.onProgress?.({ ...this.progress });
    } catch (e) {
      log.warn('progress listener failed', e);
    }
  }

  private alive(): boolean {
    return !this.ac.signal.aborted && this.failure === null;
  }

  private fail(e: unknown): void {
    if (this.failure === null) this.failure = e;
    this.ac.abort(); // ほかの途中の要求も止める
  }

  // ── 本体 ──

  private async run(): Promise<string> {
    await sodiumReady;
    await equixReady;
    if (!(await waitForFirstHop(this.parts.tunnel, this.lim.readyWaitMs, this.ac.signal))) {
      throw this.cancelled ? new FileTransferError('cancelled') : new FileTransferError('no-first-hop');
    }
    const inflight = new Set<Promise<void>>();
    const gen = encodeFile(this.source, this.meta);
    try {
      for await (const ev of gen) {
        if (!this.alive()) break;
        if (ev.kind === 'chunk') {
          await this.gate.wait(this.ac.signal);
          // 手元に持つチャンクの数を絞る (次のチャンクの暗号化は、枠が空いてから)
          while (inflight.size >= this.lim.chunksInFlight && this.alive()) await Promise.race(inflight);
          if (!this.alive()) break;
          const task: Promise<void> = this.placeChunk(ev.id, ev.ciphertext)
            .then((replicas) => this.chunkDone(ev.ciphertext.length - TAG_BYTES, replicas))
            .catch((e) => this.fail(e))
            .finally(() => { inflight.delete(task); });
          inflight.add(task);
        } else {
          await Promise.all(inflight);
          if (!this.alive()) break;
          this.progress.phase = 'manifest';
          this.emit();
          const replicas = await this.placeChunk(ev.id, ev.ciphertext);
          this.progress.replicasAcked += replicas;
          if (replicas < R_FILE) this.progress.degradedChunks++;
          this.progress.phase = 'done';
          this.emit();
          return ev.token;
        }
      }
    } catch (e) {
      this.fail(e);
    } finally {
      // 途中で抜けたら、生成器を閉じて手元の暗号化の続きをやめる
      await gen.return(undefined).catch(() => undefined);
      await Promise.allSettled(inflight);
    }
    if (this.cancelled) throw new FileTransferError('cancelled');
    throw this.failure ?? new FileTransferError('cancelled');
  }

  private chunkDone(plainBytes: number, replicas: number): void {
    this.progress.bytesPlaced += plainBytes;
    this.progress.chunksPlaced++;
    this.progress.replicasAcked += replicas;
    if (replicas < R_FILE) this.progress.degradedChunks++;
    this.emit();
  }

  /** 保存の PoW を解く。1 本の列に並べる (Worker は 1 つ。同時に 4 チャンクが解き始めても順に解く) */
  private pow(chunkId: Uint8Array): Promise<ChunkPowSolution> {
    const run = this.powChain.then(async () => {
      if (!this.alive()) throw new FileTransferError('cancelled');
      const solve = this.parts.solvePow ?? ((id, effort, stop) => computeChunkPow(id, { effort, shouldStop: stop }));
      const sol = await solve(chunkId, this.effort, () => !this.alive());
      if (!sol) throw new FileTransferError('cancelled');
      return sol;
    });
    this.powChain = run.catch(() => undefined);
    return run;
  }

  /**
   * 1 つのチャンク (Manifest も同じ) を R_FILE 個の複製に置く。置けた複製の数 (R_MIN_OK 以上) を返す。
   * 足りなければ待って置き直し (保持者の leaseSet が増える・一時的な失敗)、それでも足りなければ 'insufficient-replicas'。
   */
  private async placeChunk(chunkId: Uint8Array, data: Uint8Array): Promise<number> {
    const pow = await this.pow(chunkId);
    const positions = chunkPositions(chunkId, R_FILE).length;
    const placed = new Set<string>(); // 置けた保持者 (SID)。★ 同じ保持者に 2 つ置いても複製の数に入れない
    const reserved = new Set<string>(); // 置いている最中の保持者 (並行する複製が同じ保持者を選ばないように)
    const done = new Array<boolean>(positions).fill(false);

    for (let round = 0; round < this.lim.rounds && this.alive(); round++) {
      if (round > 0) await sleep(this.lim.roundDelayMs[Math.min(round - 1, this.lim.roundDelayMs.length - 1)], this.ac.signal);
      await this.gate.wait(this.ac.signal);
      if (!this.alive()) break;
      const candidates = placementCandidates(this.parts.routing, chunkId, R_FILE);
      await Promise.all(candidates.map(async (list, j) => {
        if (done[j]) return;
        for (const cand of list) {
          if (!this.alive()) return;
          if (placed.has(cand.sid) || reserved.has(cand.sid)) continue;
          reserved.add(cand.sid);
          let outcome: 'stored' | 'refused' | 'failed';
          try {
            outcome = await this.putToHolder(cand, chunkId, data, pow);
          } finally {
            reserved.delete(cand.sid);
          }
          if (outcome === 'stored') {
            placed.add(cand.sid);
            done[j] = true;
            return;
          }
        }
      }));
      // 1 周で足りた (R_MIN_OK 以上) なら置き直さない。足りない分は最大 R_FILE に近づける努力をここでは続けない
      if (placed.size >= R_MIN_OK) break;
    }
    if (!this.alive()) throw this.cancelled ? new FileTransferError('cancelled') : (this.failure ?? new FileTransferError('cancelled'));
    if (placed.size < R_MIN_OK) {
      throw new FileTransferError('insufficient-replicas', `only ${placed.size} of ${R_MIN_OK} replicas could be placed`);
    }
    return placed.size;
  }

  /**
   * 1 台の保持者にチャンク 1 つを断片で送る。
   * ★ 最初の断片を**先に 1 本だけ**送って様子を見る: 保持者は最初の断片で PoW と担当を確かめるので、断られる (NOT_DUTY・BAD_POW・
   *   FULL) なら残りの 17 本を無駄に送らない。受け付けられたら残りを並行して送る。
   */
  private async putToHolder(
    cand: { sidBytes: Uint8Array; gateway: string; tunnelId: Uint8Array },
    chunkId: Uint8Array, data: Uint8Array, pow: ChunkPowSolution,
  ): Promise<'stored' | 'refused' | 'failed'> {
    const count = fragmentCountFor(data.length);
    const local = linkedController(this.ac.signal);
    const send = async (i: number): Promise<number | null> => {
      const payload = encodePutFragment({
        chunkId, powNonce: pow.nonce, powSolution: pow.solution, fragIndex: i, fragCount: count,
        data: data.subarray(i * FRAG_DATA_BYTES, Math.min(data.length, (i + 1) * FRAG_DATA_BYTES)),
      });
      let busy = 0;
      for (let attempt = 0; attempt <= this.lim.fragmentRetries;) {
        await this.gate.wait(local.signal);
        if (!(await this.fragments.acquire(local.signal))) return null;
        let r: Awaited<ReturnType<typeof callTunnel>>;
        try {
          await this.pacer.wait(local.signal);
          if (local.signal.aborted) return null;
          r = await callTunnel(this.parts.tunnel, cand, TUNNEL_KIND.PUT_CHUNK, payload, {
            inactivityMs: this.lim.inactivityMs, maxBytes: 16, maxPieces: 2, signal: local.signal,
          });
        } finally {
          this.fragments.release();
        }
        if (local.signal.aborted) return null;
        const st = r.data ? decodeStatusResponse(r.data) : null;
        if (st !== null) return st;
        if (r.error?.code === TUNNEL_ERROR_CODE.BUSY || r.error?.local === 'too-many') {
          // 制限に当たった (Guard の上り枠・保持者のホップごとの枠): 失敗でなく「待て」。待って同じ断片を送り直す
          if (++busy > this.lim.busyRetries) return null;
          await sleep(Math.min(2000, 200 * 2 ** (busy - 1)), local.signal);
          continue;
        }
        attempt++;
        await sleep(this.lim.retryBackoffMs * attempt, local.signal);
      }
      return null;
    };
    try {
      const probe = await send(0);
      if (probe === null) return 'failed';
      if (probe === CHUNK_STATUS.STORED) return 'stored';
      if (probe !== CHUNK_STATUS.OK) return 'refused';
      let stored = false;
      let refused = false;
      await Promise.all(Array.from({ length: count - 1 }, (_, k) => k + 1).map(async (i) => {
        const st = await send(i);
        if (st === CHUNK_STATUS.STORED) stored = true;
        else if (st !== null && st !== CHUNK_STATUS.OK) {
          refused = true;
          local.abort(); // 断られた: 残りの断片は送らない
        }
      }));
      if (stored) return 'stored';
      return refused ? 'refused' : 'failed';
    } finally {
      local.abort();
    }
  }
}

function sizeOf(source: UploadSource): number {
  if (source instanceof Uint8Array) return source.length;
  const s = source as { size?: unknown };
  return typeof s.size === 'number' ? s.size : 0;
}

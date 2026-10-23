import { createLogger } from '../common/Logger';
import type { TunnelClient } from '../network/tunnel/TunnelClient';
import { callTunnel } from '../network/tunnel/TunnelCall';
import { TUNNEL_KIND } from '../network/tunnel/TunnelCrypto';
import {
  CHUNK_MAX_CIPHER_BYTES, CHUNK_STATUS, decodeGetResponse, encodeGetRequest,
} from '../network/storage/ChunkProtocol';
import { readTiers, type HolderRoute, type RoutingParts } from './ChunkRouting';
import { sleep } from './FileTransfer';

const log = createLogger('files.reader');

export const READER_LIMITS = {
  /** 最初の保持者に頼んでから、まだ届かなければ次の保持者へも頼むまで (hedged request) */
  HEDGE_MS: 3_000,
  /** 応答が 1 片も来ないまま待つ上限 */
  INACTIVITY_MS: 15_000,
  /** 同時に頼む保持者の数の上限 (保険を含む) */
  MAX_PARALLEL: 3,
  /** 1 チャンクで頼む保持者の数の上限 */
  MAX_ATTEMPTS: 12,
  /** 全員が失敗したあと、leaseSet の更新を待って候補を作り直す回数と待ち */
  ROUNDS: 2,
  ROUND_DELAY_MS: 2_000,
  /** 応答 (15KiB ごとの片) の片の数の上限: (256KiB + 16) / 15KiB = 18 に余裕 */
  MAX_PIECES: 24,
  /** 速さの記録の上限 (メモリだけ) */
  SPEED_MEMORY: 2048,
  /** 失敗・偽物を返した保持者に付ける、速さの代わりの値 (ms)。次回から後回しになる */
  FAIL_PENALTY_MS: 60_000,
} as const;

export interface ChunkReaderParts {
  tunnel: Pick<TunnelClient, 'request' | 'firstHop'>;
  routing: RoutingParts;
  now?: () => number;
  /** 乱数 [0,1)。速さの記録がない保持者の順番に使う */
  random?: () => number;
  /** ★ テスト専用 */
  limits?: Partial<{
    hedgeMs: number; inactivityMs: number; maxParallel: number; maxAttempts: number; rounds: number; roundDelayMs: number;
  }>;
}

export type ReadResult = { ok: true; sid: string } | { ok: false; reason: 'aborted' | 'unavailable' };

/**
 * ChunkReader — チャンク 1 つを保持者から取る (GET_CHUNK)。速い保持者から、遅ければ別の複製へ (hedged)、
 * 偽物を返した保持者は後回しにして取り直す。
 *
 *   候補 = 各複製の位置に近い保持者 (ChunkRouting.readTiers)。近さの順位の束ごとに、速さの記録のある相手を速い順、無い相手を乱数の順
 *   → 1 台目に頼む → HEDGE_MS 待っても終わらなければ 2 台目にも → 失敗したらすぐ次へ → どれかが `accept` を通したら止める
 *
 * ★ **取ったデータの検証は呼び出し側の accept**: チャンク ID (暗号文のハッシュ) と復号の両方を通ったものだけを true にする
 *   (FileAssembler.accept)。通らなければ、その保持者は偽物を返したものとして後回しにし、別の保持者から取り直す。
 * ★ 速さは手元のメモリだけに記録する (保持者の SID → 完了までの ms の移動平均)。ディスクには書かない・保持者の自己申告は使わない。
 *   失敗・偽物は FAIL_PENALTY_MS を付けて後回し。
 */
export class ChunkReader {
  private readonly now: () => number;
  private readonly random: () => number;
  private readonly lim: { hedgeMs: number; inactivityMs: number; maxParallel: number; maxAttempts: number; rounds: number; roundDelayMs: number };
  private speeds = new Map<string, number>();

  /** 診断・テスト用 */
  public readonly stats = { reads: 0, attempts: 0, hedges: 0, notHeld: 0, rejected: 0, failed: 0 };

  constructor(private readonly parts: ChunkReaderParts) {
    this.now = parts.now ?? Date.now;
    this.random = parts.random ?? Math.random;
    const l = parts.limits ?? {};
    this.lim = {
      hedgeMs: l.hedgeMs ?? READER_LIMITS.HEDGE_MS,
      inactivityMs: l.inactivityMs ?? READER_LIMITS.INACTIVITY_MS,
      maxParallel: l.maxParallel ?? READER_LIMITS.MAX_PARALLEL,
      maxAttempts: l.maxAttempts ?? READER_LIMITS.MAX_ATTEMPTS,
      rounds: l.rounds ?? READER_LIMITS.ROUNDS,
      roundDelayMs: l.roundDelayMs ?? READER_LIMITS.ROUND_DELAY_MS,
    };
  }

  public recordSpeed(sid: string, ms: number): void {
    const prev = this.speeds.get(sid);
    const next = prev === undefined ? ms : Math.round((prev + ms) / 2);
    this.speeds.delete(sid); // 末尾へ (新しい順を保つ)
    this.speeds.set(sid, next);
    if (this.speeds.size > READER_LIMITS.SPEED_MEMORY) {
      const oldest = this.speeds.keys().next().value;
      if (oldest !== undefined) this.speeds.delete(oldest);
    }
  }

  /** この保持者の、手元で観測した速さ (ms)。記録が無ければ undefined (診断・テスト用) */
  public speedOf(sid: string): number | undefined {
    return this.speeds.get(sid);
  }

  /** 束の中を、速さの記録がある相手は速い順に、無い相手は乱数の順にその後ろへ */
  private rank(tier: HolderRoute[]): HolderRoute[] {
    const known = tier.filter(c => this.speeds.has(c.sid)).sort((a, b) => this.speeds.get(a.sid)! - this.speeds.get(b.sid)!);
    const unknown = tier.filter(c => !this.speeds.has(c.sid));
    for (let i = unknown.length - 1; i > 0; i--) {
      const j = Math.floor(this.random() * (i + 1));
      [unknown[i], unknown[j]] = [unknown[j], unknown[i]];
    }
    return [...known, ...unknown];
  }

  private order(chunkId: Uint8Array): HolderRoute[] {
    return readTiers(this.parts.routing, chunkId).flatMap(t => this.rank(t));
  }

  /**
   * チャンクを取る。`accept(data)` が true を返したら完了 (その暗号文を呼び出し側が使う)。
   * 全員が失敗しても、候補を作り直して ROUNDS 回まで試す。
   */
  public async read(
    chunkId: Uint8Array, accept: (data: Uint8Array) => Promise<boolean>, signal?: AbortSignal,
  ): Promise<ReadResult> {
    this.stats.reads++;
    for (let round = 0; round < this.lim.rounds; round++) {
      if (signal?.aborted) return { ok: false, reason: 'aborted' };
      if (round > 0) await sleep(this.lim.roundDelayMs, signal);
      const ordered = this.order(chunkId);
      if (ordered.length === 0) continue;
      const r = await this.readFrom(ordered, chunkId, accept, signal);
      if (r.ok || r.reason === 'aborted') return r;
    }
    this.stats.failed++;
    return { ok: false, reason: signal?.aborted ? 'aborted' : 'unavailable' };
  }

  private readFrom(
    ordered: HolderRoute[], chunkId: Uint8Array, accept: (data: Uint8Array) => Promise<boolean>, signal?: AbortSignal,
  ): Promise<ReadResult> {
    return new Promise<ReadResult>((resolve) => {
      let next = 0;
      let active = 0;
      let attempts = 0;
      let done = false;
      let hedge: ReturnType<typeof setTimeout> | null = null;
      const ac = new AbortController();

      const finish = (res: ReadResult) => {
        if (done) return;
        done = true;
        if (hedge) clearTimeout(hedge);
        signal?.removeEventListener('abort', onAbort);
        ac.abort(); // 走っている要求をやめる
        resolve(res);
      };
      const onAbort = () => finish({ ok: false, reason: 'aborted' });
      signal?.addEventListener('abort', onAbort, { once: true });
      if (signal?.aborted) return finish({ ok: false, reason: 'aborted' });

      const canLaunch = () => next < ordered.length && attempts < this.lim.maxAttempts;
      const launch = (): void => {
        if (done || !canLaunch()) return;
        const c = ordered[next++];
        attempts++;
        active++;
        this.stats.attempts++;
        void this.attempt(c, chunkId, accept, ac.signal, () => done).then((ok) => {
          active--;
          if (done) return;
          if (ok) return finish({ ok: true, sid: c.sid });
          // 失敗 (持っていない・偽物・時間切れ): すぐ次の保持者へ
          if (canLaunch() && active < 1) launch();
          else if (active === 0 && !canLaunch()) finish({ ok: false, reason: 'unavailable' });
        });
      };
      const armHedge = () => {
        hedge = setTimeout(() => {
          hedge = null;
          if (done) return;
          if (active < this.lim.maxParallel && canLaunch()) {
            this.stats.hedges++;
            launch();
          }
          if (canLaunch()) armHedge();
        }, this.lim.hedgeMs);
      };
      launch();
      armHedge();
    });
  }

  /** 1 台の保持者から取って検証する。通ったら true */
  private async attempt(
    c: HolderRoute, chunkId: Uint8Array, accept: (data: Uint8Array) => Promise<boolean>,
    signal: AbortSignal, isDone: () => boolean,
  ): Promise<boolean> {
    const t0 = this.now();
    try {
      const { data: res } = await callTunnel(this.parts.tunnel, c, TUNNEL_KIND.GET_CHUNK, encodeGetRequest(chunkId), {
        inactivityMs: this.lim.inactivityMs, maxBytes: 1 + CHUNK_MAX_CIPHER_BYTES, maxPieces: READER_LIMITS.MAX_PIECES, signal,
      });
      if (signal.aborted || isDone()) return false;
      if (!res) {
        this.recordSpeed(c.sid, READER_LIMITS.FAIL_PENALTY_MS);
        return false;
      }
      const dec = decodeGetResponse(res);
      if (!dec) {
        this.recordSpeed(c.sid, READER_LIMITS.FAIL_PENALTY_MS);
        return false;
      }
      if (dec.status === CHUNK_STATUS.NOT_HELD) {
        this.stats.notHeld++; // 持っていないだけ。罰は付けない
        return false;
      }
      if (dec.status !== CHUNK_STATUS.OK) return false;
      if (isDone()) return false;
      if (!(await accept(dec.data))) {
        // ★ ID が合わない・復号できない: 偽物 (改ざん) を返した保持者。後回しにして別の保持者から取り直す
        this.stats.rejected++;
        this.recordSpeed(c.sid, READER_LIMITS.FAIL_PENALTY_MS);
        return false;
      }
      this.recordSpeed(c.sid, this.now() - t0);
      return true;
    } catch (e) {
      log.warn('chunk attempt failed', e);
      return false;
    }
  }
}

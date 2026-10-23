import type { IMessageDispatcher, IPeerManager, PeerId } from '../../types';
import { WireType } from '../wire/WireTypes';
import { CATCHUP_STATUS, MAX_CATCHUP_FRAME_BYTES } from '../wire/WireCodec';
import { minutesToMs, msToMinutes } from '../../crypto/PowPolicy';
import type { BufferedPacket, RecentBuffer } from './RecentBuffer';
import { createLogger } from '../../common/Logger';

const log = createLogger('net.catchup.server');

export const CATCHUP_SERVER_LIMITS = {
  /** 1 相手あたりの定常の送出量 (バイト/秒) とバースト */
  PER_PEER_BYTES_PER_SEC: 256 * 1024,
  PER_PEER_BURST_BYTES: 1024 * 1024,
  /**
   * 全相手の合計の上限。Guard は最大 256 人を受け入れるので、全員が同時に再接続すると
   * 256 × 256KiB/秒 = 64MiB/秒 になり、ライブの中継 (本来の仕事) の帯域を食う。
   */
  GLOBAL_BYTES_PER_SEC: 4 * 1024 * 1024,
  GLOBAL_BURST_BYTES: 8 * 1024 * 1024,
  /** 同じ相手の追いつきの開始の最短間隔 (ms)。要求のたびにバッファを走査するので、連打させない */
  MIN_INTERVAL_MS: 5_000,
} as const;

export interface CatchupServerOptions {
  perPeerBytesPerSec?: number;
  perPeerBurstBytes?: number;
  globalBytesPerSec?: number;
  globalBurstBytes?: number;
  minIntervalMs?: number;
  /** テスト用の時計 */
  now?: () => number;
}

/** CATCHUP_DATA の本体に使える大きさ: フレーム 16KiB − type 1 − 件数 2 */
const DATA_BODY_MAX = MAX_CATCHUP_FRAME_BYTES - 1 - 2;
/** 1 件の前置き (u16 の長さ) */
const PER_PACKET_OVERHEAD = 2;

/** トークンバケット (バイト単位) */
class ByteBucket {
  private tokens: number;
  private last: number;
  constructor(private rate: number, private burst: number, now: number) {
    this.tokens = burst;
    this.last = now;
  }
  private refill(now: number): void {
    const dt = Math.max(0, now - this.last) / 1000;
    this.tokens = Math.min(this.burst, this.tokens + dt * this.rate);
    this.last = now;
  }
  /** n バイト出せるまでの待ち時間 (ms)。0 なら今すぐ出せる (消費はしない) */
  public waitMs(n: number, now: number): number {
    this.refill(now);
    if (this.tokens >= n) return 0;
    return Math.ceil(((n - this.tokens) / this.rate) * 1000);
  }
  public take(n: number): void {
    this.tokens -= n;
  }
}

interface Session {
  packets: BufferedPacket[];
  next: number;
  partial: boolean;
  timer: ReturnType<typeof setTimeout> | null;
}

/**
 * CatchupServer — 直接つながっている隣人からの CATCHUP_REQ に、{@link RecentBuffer} の中身を返す (history v2 §3)。
 *
 *   CATCHUP_REQ{since} → CATCHUP_DATA × N (古い順) → CATCHUP_END{status, nextSince}
 *
 * ★ Guard (72 時間) でも一般ノード (1 時間) でも同じ実装。持っている長さが違うだけ。
 * ★ 返すものは「since 以降の全部」。相手が何を読むかで絞らない。だから Guard には誰が何を読むかが分からない
 *   (分かるのはオフラインだった時間だけで、これは接続の記録から元々分かる)。
 * ★ 1 相手につき同時に 1 本。進行中にまた要求が来たら BUSY を返して何も送らない。
 * ★ 帯域は 1 相手 256KiB/秒 (バースト 1MiB) と、全相手の合計 4MiB/秒の 2 段で絞る。
 *   送り終わるのが遅くなるだけで、ライブの流れを邪魔しない。
 * ★ バッファの保持時間より古い since は、持っている分を全部返して status = PARTIAL。
 *   バッファの外 (保持時間より前) は決して返さない。
 */
export class CatchupServer {
  private sessions = new Map<PeerId, Session>();
  private perPeer = new Map<PeerId, ByteBucket>();
  private lastStartAt = new Map<PeerId, number>();
  private readonly global: ByteBucket;
  private readonly opts: Required<Omit<CatchupServerOptions, 'now'>>;
  private readonly now: () => number;
  private destroyed = false;
  private readonly onDisconnect = (peerId: PeerId) => this.forget(peerId);

  constructor(
    private peerManager: IPeerManager,
    dispatcher: IMessageDispatcher,
    private buffer: RecentBuffer,
    options: CatchupServerOptions = {},
  ) {
    this.now = options.now ?? Date.now;
    this.opts = {
      perPeerBytesPerSec: options.perPeerBytesPerSec ?? CATCHUP_SERVER_LIMITS.PER_PEER_BYTES_PER_SEC,
      perPeerBurstBytes: options.perPeerBurstBytes ?? CATCHUP_SERVER_LIMITS.PER_PEER_BURST_BYTES,
      globalBytesPerSec: options.globalBytesPerSec ?? CATCHUP_SERVER_LIMITS.GLOBAL_BYTES_PER_SEC,
      globalBurstBytes: options.globalBurstBytes ?? CATCHUP_SERVER_LIMITS.GLOBAL_BURST_BYTES,
      minIntervalMs: options.minIntervalMs ?? CATCHUP_SERVER_LIMITS.MIN_INTERVAL_MS,
    };
    this.global = new ByteBucket(this.opts.globalBytesPerSec, this.opts.globalBurstBytes, this.now());
    dispatcher.register(WireType.CATCHUP_REQ, (peerId, msg) => this.handleReq(peerId, msg));
    peerManager.on('peer:disconnect', this.onDisconnect);
  }

  /** 進行中の追いつきの数 (テスト・診断用) */
  public get activeSessions(): number {
    return this.sessions.size;
  }

  private handleReq(peerId: PeerId, msg: any): void {
    if (this.destroyed) return;
    const since = msg?.since;
    if (!Number.isInteger(since) || since < 0 || since > 0xffffff) return;
    const peer = this.peerManager.peers.get(peerId);
    if (!peer || !peer.isConnected || !peer.isVerified) return;

    const now = this.now();
    const nowMinute = clampMinute(now);

    // 同時に 1 本。進行中、または開始の間隔が短すぎるなら断る (何も送らない)
    const last = this.lastStartAt.get(peerId);
    if (this.sessions.has(peerId) || (last !== undefined && now - last < this.opts.minIntervalMs)) {
      this.peerManager.sendMessage(peerId, WireType.CATCHUP_END, { status: CATCHUP_STATUS.BUSY, nextSince: nowMinute });
      return;
    }
    this.lastStartAt.set(peerId, now);

    const sinceMs = minutesToMs(since);
    // ★ since がバッファの範囲より古い = 持っていない分がある。持っている分は全部返して partial
    const partial = sinceMs < this.buffer.coverageStartMs();
    const packets = this.buffer.entriesSince(sinceMs);
    log.debug(() => `catch-up ${peerId.substring(0, 8)}: ${packets.length} packet(s)${partial ? ' (partial)' : ''}`);

    const session: Session = { packets, next: 0, partial, timer: null };
    this.sessions.set(peerId, session);
    this.pump(peerId);
  }

  /** 送れるだけ送り、帯域が足りなければ待ってから続きを送る */
  private pump(peerId: PeerId): void {
    const session = this.sessions.get(peerId);
    if (!session || this.destroyed) return;
    session.timer = null;
    const peer = this.peerManager.peers.get(peerId);
    if (!peer || !peer.isConnected) {
      this.forget(peerId);
      return;
    }

    let bucket = this.perPeer.get(peerId);
    if (!bucket) {
      bucket = new ByteBucket(this.opts.perPeerBytesPerSec, this.opts.perPeerBurstBytes, this.now());
      this.perPeer.set(peerId, bucket);
    }

    while (session.next < session.packets.length) {
      // 1 フレームに詰められるだけ詰める (本体が 16KiB − 3 バイトに収まる分)
      let end = session.next;
      let used = 0;
      while (end < session.packets.length) {
        const cost = PER_PACKET_OVERHEAD + session.packets[end].bytes.length;
        if (used + cost > DATA_BODY_MAX) break;
        used += cost;
        end++;
      }
      if (end === session.next) {
        // 1 件で入りきらない (パケットは最大 約 2.3KB なので起きない)。飛ばす
        session.next++;
        continue;
      }
      const frameBytes = 1 + 2 + used;

      const now = this.now();
      const wait = Math.max(bucket.waitMs(frameBytes, now), this.global.waitMs(frameBytes, now));
      if (wait > 0) {
        session.timer = setTimeout(() => this.pump(peerId), wait);
        return;
      }
      bucket.take(frameBytes);
      this.global.take(frameBytes);
      this.peerManager.sendMessage(peerId, WireType.CATCHUP_DATA, {
        packets: session.packets.slice(session.next, end).map(p => p.bytes),
      });
      session.next = end;
    }

    this.sessions.delete(peerId);
    this.peerManager.sendMessage(peerId, WireType.CATCHUP_END, {
      status: session.partial ? CATCHUP_STATUS.PARTIAL : CATCHUP_STATUS.OK,
      // ★ 「ここまで送った」の時刻。ここから先はライブの flood で届く (相手はつながっているので)
      nextSince: clampMinute(this.now()),
    });
  }

  private forget(peerId: PeerId): void {
    const s = this.sessions.get(peerId);
    if (s?.timer) clearTimeout(s.timer);
    this.sessions.delete(peerId);
    this.perPeer.delete(peerId);
    this.lastStartAt.delete(peerId);
  }

  public destroy(): void {
    this.destroyed = true;
    this.peerManager.off('peer:disconnect', this.onDisconnect);
    for (const id of Array.from(this.sessions.keys())) this.forget(id);
    this.perPeer.clear();
    this.lastStartAt.clear();
  }
}

function clampMinute(ms: number): number {
  try {
    return msToMinutes(ms);
  } catch {
    return 0;
  }
}

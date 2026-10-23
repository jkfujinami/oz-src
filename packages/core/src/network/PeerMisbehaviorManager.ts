import { createLogger } from '../common/Logger';

const log = createLogger('net.misbehavior');

export enum ViolationType {
  /** 即時BAN (100): Ed25519不正署名、JOINチャレンジ不一致 */
  INVALID_SIGNATURE = 100,
  /** 即時BAN (100): 不正なNodeId PoW、または改ざんされたGossip PoW */
  INVALID_POW = 100,
  /** 即時BAN (100): パース不能な不正ワイヤフォーマット、ヘッダ改ざん */
  MALFORMED_WIRE = 100,
  /** 段階ペナルティ (25): トークンバケット枯渇後の過剰送信 */
  RATE_LIMIT_EXCEEDED = 25,
  /** 段階ペナルティ (25): Stemパケットを委託したがFluffエコーが戻らず消失 */
  STEM_DROP_SUSPECTED = 25,
  /** 段階ペナルティ (15): 同一パケットの連続・異常再送 */
  DUPLICATE_FLOOD = 15,
  /** 段階ペナルティ (10): データチャンネル応答タイムアウト */
  TIMEOUT = 10,
}

export interface MisbehaviorOptions {
  /** BAN閾値 (デフォルト: 100) */
  banThreshold?: number;
  /** BAN継続時間 (ミリ秒、デフォルト: 1時間) */
  banDurationMs?: number;
  /** スコアの半減期 (ミリ秒、デフォルト: 10分) */
  decayIntervalMs?: number;
}

interface PeerScoreRecord {
  score: number;
  lastUpdated: number;
}

export class PeerMisbehaviorManager {
  private readonly banThreshold: number;
  private readonly banDurationMs: number;
  private readonly decayIntervalMs: number;

  private scores: Map<string, PeerScoreRecord> = new Map();
  private bannedPeers: Map<string, number> = new Map(); // peerId -> expiryTimestamp

  constructor(options: MisbehaviorOptions = {}) {
    this.banThreshold = options.banThreshold ?? 100;
    this.banDurationMs = options.banDurationMs ?? 60 * 60 * 1000;
    this.decayIntervalMs = options.decayIntervalMs ?? 10 * 60 * 1000;
  }

  /**
   * 違反を記録し、閾値を超えた場合は自動的にピアをBANする。
   * @returns ピアがBANされた（または既にBAN中）なら true
   */
  public recordViolation(peerId: string, violation: ViolationType | number, reason?: string): boolean {
    if (this.isBanned(peerId)) {
      return true;
    }

    const currentScore = this.getScore(peerId);
    const newScore = currentScore + violation;
    this.scores.set(peerId, { score: newScore, lastUpdated: Date.now() });

    log.warn(
      `Violation recorded for ${peerId.substring(0, 8)}: +${violation} (total: ${newScore}/${this.banThreshold}) reason=${reason ?? 'unknown'}`,
    );

    if (newScore >= this.banThreshold) {
      this.banPeer(peerId, this.banDurationMs, reason ?? `Score exceeded threshold (${newScore})`);
      return true;
    }

    return false;
  }

  /**
   * ピアが現在BANされているかを判定する。期限切れなら自動的に解除する。
   */
  public isBanned(peerId: string): boolean {
    const expiry = this.bannedPeers.get(peerId);
    if (expiry === undefined) {
      return false;
    }

    if (Date.now() >= expiry) {
      log.info(`BAN expired for peer ${peerId.substring(0, 8)}`);
      this.bannedPeers.delete(peerId);
      this.scores.delete(peerId);
      return false;
    }

    return true;
  }

  /**
   * 半減期による減衰を適用した実効スコアを取得する。
   */
  public getScore(peerId: string): number {
    const record = this.scores.get(peerId);
    if (!record) {
      return 0;
    }

    const now = Date.now();
    const elapsed = now - record.lastUpdated;
    if (elapsed < this.decayIntervalMs) {
      return record.score;
    }

    const halfLifeCount = Math.floor(elapsed / this.decayIntervalMs);
    const decayedScore = Math.floor(record.score / Math.pow(2, halfLifeCount));

    // 減衰後の値でキャッシュを更新
    if (decayedScore <= 0) {
      this.scores.delete(peerId);
      return 0;
    }

    this.scores.set(peerId, { score: decayedScore, lastUpdated: now });
    return decayedScore;
  }

  /**
   * ピアを手動または即時BANする。
   */
  public banPeer(peerId: string, durationMs: number = this.banDurationMs, reason?: string): void {
    const expiry = Date.now() + durationMs;
    this.bannedPeers.set(peerId, expiry);
    this.scores.delete(peerId);
    log.error(`[PEER BANNED] ${peerId.substring(0, 8)} banned for ${durationMs}ms. Reason: ${reason ?? 'manual'}`);
  }

  /**
   * ピアのBANを解除する。
   */
  public unbanPeer(peerId: string): void {
    this.bannedPeers.delete(peerId);
    this.scores.delete(peerId);
  }

  /**
   * 全記録を初期化する（テスト用）。
   */
  public clear(): void {
    this.scores.clear();
    this.bannedPeers.clear();
  }
}

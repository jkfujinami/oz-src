import { WebSocket } from 'ws';
import { createHash } from 'node:crypto';
import { selectJoinPeers, type RingCandidate } from './RingSelect';

const POSITION_DOMAIN = Buffer.from('OZ/v3/position', 'utf8');

/** NodeIdentity.derivePosition と同じ式: SHA-256(domain || peerIdBytes) の先頭 8 バイト / 2^64 */
export function ringPosition(peerIdHex: string): number {
  const h = createHash('sha256').update(POSITION_DOMAIN).update(Buffer.from(peerIdHex, 'hex')).digest();
  return Number(h.readBigUInt64BE(0)) / 18446744073709551616;
}

export interface PeerSession {
  peerId: string;
  ws: WebSocket;
  lastActive: number;
  /** peerId から導出したリング座標 (保持するのは導出値だけ) */
  position: number;
  joinedAt: number;
}

export type RegisterResult = { ok: true; replaced: WebSocket | null } | { ok: false; reason: 'capacity' };

export interface SessionManagerOptions {
  /** 同時に登録できるセッション数の上限 (メモリ枯渇の防止) */
  maxSessions?: number;
  /** 応答の無い接続を切るまでの時間 */
  idleTimeoutMs?: number;
  /** 生存確認の間隔 */
  pingIntervalMs?: number;
}

/**
 * SessionManager — 登録済みのノード (peerId → 接続)。
 *
 * ★ 同じ peerId の新しい登録は、古い接続を置き換える。
 *   登録には所有証明 (この接続の nonce への署名) が要るので、新しい登録をしてきたのは
 *   その peerId の秘密鍵の持ち主本人である。本人の再接続 (古い接続が半開きのまま残った
 *   場合など) を、古い接続が切れるまで待たせない。
 *   (所有証明が無かった頃は、ここで上書きを許すと他人のセッションを奪えたので拒否していた。)
 *
 * peerId 以外 (IP アドレス・位置・購読ゾーン) は保持しない。
 */
export class SessionManager {
  private sessions: Map<string, PeerSession> = new Map();
  private cleanupTimer: ReturnType<typeof setInterval>;
  private readonly maxSessions: number;
  private readonly idleTimeoutMs: number;

  constructor(options: SessionManagerOptions = {}) {
    this.maxSessions = options.maxSessions ?? 5000;
    this.idleTimeoutMs = options.idleTimeoutMs ?? 120_000;
    this.cleanupTimer = setInterval(() => this.cleanupPings(), options.pingIntervalMs ?? 60_000);
  }

  public registerSession(ws: WebSocket, peerId: string): RegisterResult {
    const existing = this.sessions.get(peerId);
    if (existing?.ws === ws) {
      existing.lastActive = Date.now();
      return { ok: true, replaced: null };
    }
    if (!existing && this.sessions.size >= this.maxSessions) {
      return { ok: false, reason: 'capacity' };
    }

    const now = Date.now();
    this.sessions.set(peerId, { peerId, ws, lastActive: now, position: ringPosition(peerId), joinedAt: now });

    ws.on('close', () => {
      // 自分が登録した接続のときだけ消す。
      // 再接続で別の ws が同じ peerId を持っている場合に、
      // 古い ws の close で新しいセッションを消してしまわないようにする。
      const current = this.sessions.get(peerId);
      if (current && current.ws === ws) this.sessions.delete(peerId);
    });
    ws.on('pong', () => {
      const session = this.sessions.get(peerId);
      if (session && session.ws === ws) session.lastActive = Date.now();
    });

    return { ok: true, replaced: existing ? existing.ws : null };
  }

  public getSession(peerId: string): PeerSession | undefined {
    return this.sessions.get(peerId);
  }

  public get size(): number {
    return this.sessions.size;
  }

  /**
   * ブートストラップ候補をランダムに返す。
   *
   * position も zones も返さない。前者は peerId から導出でき、
   * 後者はそもそも受け取っていない。
   */
  public getRandomPeers(excludeId: string, maxPeers: number, randomInt: (n: number) => number): { peerId: string }[] {
    // 先頭 N 件固定だと、早期に接続した攻撃者ノードが永久に紹介され続ける。
    // 近傍・新着以外の枠は CSPRNG でシャッフルして選ぶ (RingSelect)。
    const self = this.sessions.get(excludeId);
    const candidates: RingCandidate<string>[] = [];
    for (const s of this.sessions.values()) {
      if (s.peerId === excludeId) continue;
      candidates.push({ item: s.peerId, position: s.position, joinedAt: s.joinedAt });
    }
    const selfPosition = self ? self.position : ringPosition(excludeId);
    return selectJoinPeers(selfPosition, candidates, maxPeers, randomInt).map((peerId) => ({ peerId }));
  }

  private cleanupPings(): void {
    const now = Date.now();
    for (const [peerId, session] of this.sessions.entries()) {
      if (now - session.lastActive > this.idleTimeoutMs) {
        session.ws.terminate();
        this.sessions.delete(peerId);
      } else {
        session.ws.ping();
      }
    }
  }

  public destroy(): void {
    clearInterval(this.cleanupTimer);
    for (const session of this.sessions.values()) {
      session.ws.terminate();
    }
    this.sessions.clear();
  }
}

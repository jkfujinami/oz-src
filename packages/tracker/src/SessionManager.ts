import { WebSocket } from 'ws';

export interface PeerSession {
  peerId: string;
  ws: WebSocket;
  lastActive: number;
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

    this.sessions.set(peerId, { peerId, ws, lastActive: Date.now() });

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
    const allIds = Array.from(this.sessions.keys()).filter((id) => id !== excludeId);

    // Fisher-Yates shuffle (CSPRNG)。先頭 N 件固定だと、早期に接続した攻撃者ノードが
    // 永久に紹介され続ける。
    for (let i = allIds.length - 1; i > 0; i--) {
      const j = randomInt(i + 1);
      [allIds[i], allIds[j]] = [allIds[j], allIds[i]];
    }

    return allIds.slice(0, maxPeers).map((peerId) => ({ peerId }));
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

import { WebSocket } from 'ws';

export interface PeerSession {
  peerId: string;
  position: number;
  zones: number[];
  ws: WebSocket;
  lastActive: number;
  isSeed: boolean;
  isCache: boolean;
}

export class SessionManager {
  private sessions: Map<string, PeerSession> = new Map();

  // 古いセッションのクリーンアップ用
  private cleanupTimer: NodeJS.Timeout;

  constructor() {
    this.cleanupTimer = setInterval(() => this.cleanupPings(), 60_000);
  }

  public registerSession(
    ws: WebSocket,
    peerId: string,
    position: number,
    zones: number[],
    isSeed: boolean = false,
    isCache: boolean = false
  ): void {
    // 既存セッションが存在すれば上書き
    this.sessions.set(peerId, {
      peerId,
      position,
      zones,
      ws,
      lastActive: Date.now(),
      isSeed,
      isCache
    });

    console.log(`[SessionManager] Registered ${isSeed ? 'Seed' : (isCache ? 'Cache' : 'Peer')}: ${peerId} (pos: ${position})`);

    ws.on('close', () => {
      this.unregisterSession(peerId);
    });

    // 簡単なping/pong対応（必要に応じて拡張）
    ws.on('pong', () => {
      const session = this.sessions.get(peerId);
      if (session) session.lastActive = Date.now();
    });
  }

  public unregisterSession(peerId: string): void {
    if (this.sessions.has(peerId)) {
      this.sessions.delete(peerId);
      console.log(`[SessionManager] Unregistered peer: ${peerId}`);
    }
  }

  public getSession(peerId: string): PeerSession | undefined {
    return this.sessions.get(peerId);
  }

  public getRandomPeers(excludeId: string, maxPeers: number = 6): { peerId: string; position: number; zones: number[] }[] {
    const allIds = Array.from(this.sessions.keys()).filter((id) => id !== excludeId);
    
    // Fisher-Yates shuffle
    for (let i = allIds.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [allIds[i], allIds[j]] = [allIds[j], allIds[i]];
    }

    const selectedIds = allIds.slice(0, maxPeers);
    return selectedIds.map((id) => {
      const s = this.sessions.get(id)!;
      return { peerId: s.peerId, position: s.position, zones: s.zones };
    });
  }

  public getSeedCount(): number {
    let count = 0;
    for (const session of this.sessions.values()) {
      if (session.isSeed) count++;
    }
    return count;
  }

  private cleanupPings(): void {
    const now = Date.now();
    for (const [peerId, session] of this.sessions.entries()) {
      // 2分応答がなければ切断
      if (now - session.lastActive > 120_000) {
        session.ws.terminate();
        this.sessions.delete(peerId);
        console.log(`[SessionManager] Terminated inactive peer: ${peerId}`);
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

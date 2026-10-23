import { WebSocketServer, WebSocket } from 'ws';
import { Server } from 'http';
import { SessionManager } from './SessionManager';

export class TrackerServer {
  private wss: WebSocketServer;
  private sessionManager: SessionManager;
  // WebSocket → peerId の逆引き（relay で「誰から来たか」を特定するため）
  private wsToPeerId: Map<WebSocket, string> = new Map();

  constructor(server: Server) {
    this.sessionManager = new SessionManager();
    this.wss = new WebSocketServer({ server });

    this.wss.on('connection', (ws: WebSocket) => {
      ws.on('message', (message: Buffer | string) => this.handleMessage(ws, message));
      ws.on('close', () => {
        this.wsToPeerId.delete(ws);
      });
    });

    console.log(`[TrackerServer] Attached to provided HTTP server`);
  }

  private handleMessage(ws: WebSocket, raw: Buffer | string): void {
    try {
      const data = JSON.parse(raw.toString());

      if (data.type === 'join') {
        const { peerId, position, zones, isSeed, isCache } = data;

        if (typeof peerId !== 'string' || typeof position !== 'number') {
          return this.sendError(ws, 'Invalid join format');
        }

        // --- Seed 上限の管理 ---
        if (isSeed) {
          const MAX_SEEDS = 10;
          if (this.sessionManager.getSeedCount() >= MAX_SEEDS) {
            console.warn(`[TrackerServer] Seed limit reached (${MAX_SEEDS}). Rejecting ${peerId}`);
            return this.sendError(ws, 'Seed limit reached');
          }
        }

        // ws → peerId の逆引きを登録
        this.wsToPeerId.set(ws, peerId);

        // SessionManagerへの登録
        this.sessionManager.registerSession(ws, peerId, position, zones || [], !!isSeed, !!isCache);

        // 他のピア（最大8人）の情報をランダムに返す
        const peers = this.sessionManager.getRandomPeers(peerId, 8);
        console.log(`[TrackerServer] Sending ${peers.length} peers to ${peerId}`);
        ws.send(JSON.stringify({ type: 'peers', peers }));

      } else if (data.type === 'relay') {
        // SDP / ICE Candidate の中継
        const { targetPeerId, payload } = data;

        // ★ 送信元の peerId を WebSocket から逆引きする
        const senderPeerId = this.wsToPeerId.get(ws);
        if (!senderPeerId) {
          console.warn(`[TrackerServer] Relay from unknown ws (not joined yet)`);
          return;
        }

        if (typeof targetPeerId !== 'string') {
          return this.sendError(ws, 'Invalid relay target');
        }

        const targetSession = this.sessionManager.getSession(targetPeerId);
        if (targetSession) {
          // ★ データを展開（Flatten）せず、構造を維持したまま senderId を添えて転送する
          // これにより Rust 側が sdp/candidate キーを正しく認識できる
          const forwarded = { 
            ...payload, 
            senderId: senderPeerId,
            from: senderPeerId // 仕様書との互換性のため
          };
          
          console.log(`[TrackerServer] Relaying ${payload.type || 'signal'} from ${senderPeerId} -> ${targetPeerId}`);
          targetSession.ws.send(JSON.stringify(forwarded));
        } else {
          console.warn(`[TrackerServer] Target peer not found for relay: ${targetPeerId}`);
        }
      }
    } catch (e) {
      console.warn(`[TrackerServer] Failed to handle message`, e);
      this.sendError(ws, 'Message parsing failed');
    }
  }

  private sendError(ws: WebSocket, message: string): void {
    ws.send(JSON.stringify({ type: 'error', message }));
  }

  public shutdown(): void {
    this.sessionManager.destroy();
    this.wss.close();
  }
}

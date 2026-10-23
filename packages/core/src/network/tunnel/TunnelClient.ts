import type { IMessageDispatcher, IPeerManager, PeerId } from '../../types';
import sodium from '../../crypto/sodium';
import { createLogger } from '../../common/Logger';
import { WireType } from '../wire/WireTypes';

const log = createLogger('net.tunnel.client');

/** 利用者 (R) 側の、1 つの要求の経過 */
export type TunnelEvent =
  /** 応答の 1 片 (暗号文のまま。復号は呼び出し側が respKey で行う) */
  | { type: 'chunk'; seq: number; final: boolean; body: Uint8Array }
  /** 経路上の失敗 (TUNNEL_ERROR_CODE) または手元の失敗 (local) */
  | { type: 'error'; code: number; local?: 'no-first-hop' | 'first-hop-lost' | 'too-many' };

export interface TunnelRequest {
  /** 受け口 (保持者の leaseSet の gateway) と tunnelId */
  gateway: PeerId;
  tunnelId: Uint8Array;
  /** 封印済みの本体 (TunnelCrypto.sealRequest) */
  body: Uint8Array;
}

interface Pending {
  via: PeerId;
  handler: (ev: TunnelEvent) => void;
}

export const TUNNEL_CLIENT_LIMITS = {
  /**
   * 同時に出せる要求の数 (手元の上限。1 ホップ目の枠 (TunnelRelay.CLIENT_SEND.concurrent = 32) より内側に置く)。
   * ★ 大容量ファイルの預け入れは 1 チャンクが 18 本の断片の要求になる (ChunkProtocol)。過去ログの読み出し (最大 4 本) と
   *   ファイルの取得 (6 チャンク + 遅い相手への保険) が同時に走っても詰まらない数にする。
   */
  MAX_CONCURRENT: 30,
} as const;

/**
 * TunnelClient — 取りに行く側 (R) の窓口。要求を**自分の 1 ホップ目 (G_R)** へ送り、戻ってくる応答の片を配る。
 *
 * ★ 要求は必ず 1 ホップ目 (DandelionRouter が固定した Guard。信頼 Guard か、警告状態では一般の隣人) へだけ送る。
 *   受け口 (保持者の Guard) へ直接つなぐのは G_R の仕事で、R は保持者の Guard に IP を見せない。
 * ★ 応答は、要求を送った相手 (1 ホップ目) からだけ受け付ける。reqId は要求ごとの乱数 (u32)。
 * ★ ここは運ぶだけ。応答の暗号・完結の判定・再試行は HistoryClient が行う。
 */
export class TunnelClient {
  private pending = new Map<number, Pending>();
  private destroyed = false;

  private readonly onDisconnect = (peerId: PeerId) => {
    for (const [id, p] of Array.from(this.pending)) {
      if (p.via !== peerId) continue;
      this.pending.delete(id);
      this.fire(p, { type: 'error', code: 0, local: 'first-hop-lost' });
    }
  };

  constructor(
    private readonly peerManager: IPeerManager,
    dispatcher: IMessageDispatcher,
    private readonly dandelion: { getPinnedGuardId(): PeerId | null },
    private readonly options: { maxConcurrent?: number } = {},
  ) {
    dispatcher.register(WireType.TUNNEL_RESULT, (from, msg) => this.handleResult(from, msg));
    dispatcher.register(WireType.TUNNEL_ERROR, (from, msg) => this.handleError(from, msg));
    peerManager.on('peer:disconnect', this.onDisconnect);
  }

  /** 1 ホップ目が使えるか (固定した Guard が接続中で検証済み) */
  public get firstHop(): PeerId | null {
    const id = this.dandelion.getPinnedGuardId();
    if (!id) return null;
    const p = this.peerManager.peers.get(id);
    return p && p.isConnected && p.isVerified ? id : null;
  }

  public get inFlight(): number {
    return this.pending.size;
  }

  /**
   * 要求を出す。戻り値は取り消し用のハンドル。1 ホップ目が無い・同時数の上限なら、すぐ error を 1 回だけ返す (null)。
   * 取り消すと以後の片は捨てる (経路の状態は途中の Guard が 60 秒で捨てる)。
   */
  public request(req: TunnelRequest, handler: (ev: TunnelEvent) => void): { reqId: number; cancel(): void } | null {
    const via = this.firstHop;
    if (!via || this.destroyed) {
      queueMicrotask(() => handler({ type: 'error', code: 0, local: 'no-first-hop' }));
      return null;
    }
    if (this.pending.size >= (this.options.maxConcurrent ?? TUNNEL_CLIENT_LIMITS.MAX_CONCURRENT)) {
      queueMicrotask(() => handler({ type: 'error', code: 0, local: 'too-many' }));
      return null;
    }
    let reqId = 0;
    for (let i = 0; i < 16 && (reqId === 0 || this.pending.has(reqId)); i++) reqId = sodium.randombytes_random() >>> 0;
    if (reqId === 0 || this.pending.has(reqId)) {
      queueMicrotask(() => handler({ type: 'error', code: 0, local: 'too-many' }));
      return null;
    }
    this.pending.set(reqId, { via, handler });
    this.peerManager.sendMessage(via, WireType.TUNNEL_SEND, {
      reqId, gateway: req.gateway, tunnelId: req.tunnelId, body: req.body,
    });
    return { reqId, cancel: () => { this.pending.delete(reqId); } };
  }

  private fire(p: Pending, ev: TunnelEvent): void {
    try {
      p.handler(ev);
    } catch (e) {
      log.warn('tunnel handler failed', e);
    }
  }

  private handleResult(from: PeerId, msg: any): void {
    const p = this.pending.get(msg?.reqId);
    if (!p || p.via !== from) return; // 頼んでいない相手・知らない要求は無視
    const { seq, final, body } = msg;
    if (!Number.isInteger(seq) || !(body instanceof Uint8Array)) return;
    this.fire(p, { type: 'chunk', seq, final: final === true, body });
  }

  private handleError(from: PeerId, msg: any): void {
    const p = this.pending.get(msg?.id);
    if (!p || p.via !== from) return;
    this.pending.delete(msg.id);
    this.fire(p, { type: 'error', code: msg.code });
  }

  public destroy(): void {
    this.destroyed = true;
    this.pending.clear();
    this.peerManager.off('peer:disconnect', this.onDisconnect);
  }
}

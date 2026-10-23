import type { IMessageDispatcher, PeerId } from '../types';
import { createLogger } from '../common/Logger';

const log = createLogger('net.dispatch');

/**
 * MessageDispatcher: WireType に基づいてメッセージを適切なハンドラに配信する。
 * P2P プロトコルのルーティング層（L5/L6）として機能する。
 */
export class MessageDispatcher implements IMessageDispatcher {
  private handlers = new Map<number, Set<(peerId: PeerId, payload: any) => void>>();

  /**
   * 指定した WireType のメッセージが届いた際のコールバックを登録する。
   */
  public register(type: number, handler: (peerId: PeerId, payload: any) => void): void {
    if (!this.handlers.has(type)) {
      this.handlers.set(type, new Set());
    }
    this.handlers.get(type)!.add(handler);
  }

  /**
   * 受信したメッセージを登録済みのハンドラに配信する。
   */
  public dispatch(peerId: PeerId, type: number, payload: any): void {
    const typeHandlers = this.handlers.get(type);
    // 全受信メッセージが通る最ホットパス。遅延評価にして、
    // レベルが届かない限り文字列を組み立てないようにする。
    log.trace(() => `recv type=0x${type.toString(16)} from=${peerId.substring(0, 8)} handlers=${typeHandlers?.size ?? 0}`);

    if (!typeHandlers || typeHandlers.size === 0) {
      // 未登録のメッセージ種別が届いた場合はデバッグ用に記録（必要に応じて）
      return;
    }

    for (const handler of typeHandlers) {
      try {
        handler(peerId, payload);
      } catch (err) {
        log.error(`Error in handler for WireType 0x${type.toString(16)} from ${peerId}:`, err);
      }
    }
  }

  /**
   * ハンドラの登録解除 (クリーンアップ用)
   */
  public unregister(type: number, handler: (peerId: PeerId, payload: any) => void): void {
    const typeHandlers = this.handlers.get(type);
    if (typeHandlers) {
      typeHandlers.delete(handler);
    }
  }
}

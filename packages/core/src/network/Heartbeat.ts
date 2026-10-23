import type { IPeerManager, PeerId, IMessageDispatcher } from '../types';
import { WireType } from './wire/WireTypes';

/**
 * Heartbeat Module
 * 全ピアへの定期的な Ping 送信、Pong 応答、および RTT (往復遅延) の計測を担当する。
 */
export class Heartbeat {
  private peerManager: IPeerManager;
  private interval: number = 8_000; // 8秒 (CGNAT/厳格ルーターの 15〜30 秒 NAT バインディング消滅を防止)
  private timer: any = null;

  constructor(peerManager: IPeerManager, dispatcher: IMessageDispatcher) {
    this.peerManager = peerManager;

    dispatcher.register(WireType.PING, (peerId, msg) => this.handlePing(peerId, msg));
    dispatcher.register(WireType.PONG, (peerId, msg) => this.handlePong(peerId, msg));
  }

  /**
   * ハートビートを開始
   */
  public start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => this.pingAll(), this.interval);
  }

  /**
   * ハートビートを停止
   */
  public stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  /**
   * 全ピアに対して Ping を送信する
   */
  /**
   * ★ ping に自分の時計の値を載せない (A5)。
   *   旧実装は Date.now() をそのまま送っており、全隣人が端末の時計のずれ
   *   (クロックスキュー) を精密に測れた。これはセッションや ID を変えても
   *   同じ端末だと結び付ける指紋になる。乱数の nonce を送り、往復時間は
   *   手元の送信時刻表から求める (ワイヤでは u32 の nonce 1 つ)。
   */
  private pingAll(): void {
    const now = Date.now();
    for (const [peerId, peer] of this.peerManager.peers) {
      if (peer.isConnected) {
        const nonce = crypto.getRandomValues(new Uint32Array(1))[0];
        this.sent.set(`${peerId}:${nonce}`, now);
        this.peerManager.sendMessage(peerId, WireType.PING, { nonce });
      }
    }
    // 返事の来なかった古い記録を捨てる
    for (const [key, at] of this.sent) {
      if (now - at > this.interval * 2) this.sent.delete(key);
    }
  }

  /** 送った ping の nonce → 送信時刻 */
  private sent = new Map<string, number>();

  /** ── Dispatcher Handlers ── */

  private handlePing(peerId: PeerId, msg: any): void {
    // 相手の値は u32 の数値だけ echo する (任意のオブジェクトを反射させない)
    if (typeof msg?.nonce !== 'number' || !Number.isInteger(msg.nonce)) return;
    this.peerManager.sendMessage(peerId, WireType.PONG, { nonce: msg.nonce });
  }

  private handlePong(peerId: PeerId, msg: any): void {
    const key = `${peerId}:${msg?.nonce}`;
    const sentAt = this.sent.get(key);
    if (sentAt === undefined) return; // 自分が送っていない値は信用しない
    this.sent.delete(key);
    const peer = this.peerManager.peers.get(peerId);
    if (peer) (peer as any).rtt = Date.now() - sentAt;
  }
}

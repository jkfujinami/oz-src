import type { IPeerManager } from '../types';
import { PEXHandler } from './PEXHandler';
import { RING_MESH } from '../constants';
import { createLogger } from '../common/Logger';

const log = createLogger('net.ring');

export class RingMaintainer {
  private timer: ReturnType<typeof setInterval>;
  private peerManager: IPeerManager;
  private pexHandler: PEXHandler;

  constructor(
    peerManager: IPeerManager,
    pexHandler: PEXHandler
  ) {
    this.peerManager = peerManager;
    this.pexHandler = pexHandler;
    this.peerManager.on('peer:connect', () => this.evaluateTopology());
    this.peerManager.on('peer:disconnect', () => this.evaluateTopology());

    this.timer = setInterval(() => {
      this.evaluateTopology();
      
      // MAX_DEGREE (8本) に満たない場合はPEXを発行して、トラッカー無しに自力で新規ピアを探す
      const outbound = this.peerManager.outboundCount ?? RING_MESH.OUTBOUND_TARGET;
      if (this.peerManager.degree < RING_MESH.MAX_DEGREE || outbound < RING_MESH.OUTBOUND_TARGET) {
         if (this.peerManager.degree > 0) {
           // 🟡 Issue 2: 全員にPEX要求を送るとフラッドするので、ランダムな1人のみに依頼
           const connectedPeers = Array.from(this.peerManager.peers.values()).filter(p => p.isConnected);
           if (connectedPeers.length > 0) {
             const target = connectedPeers[Math.floor(Math.random() * connectedPeers.length)];
             log.debug(`Only ${this.peerManager.degree} peers. Requesting PEX from ${target.peerId.substring(0,8)}...`);
             this.pexHandler.requestPeers(target.peerId);
           }
         }
      }
    }, RING_MESH.REPAIR_CHECK_INTERVAL);
  }

  /**
   * 次数の調整は PeerManager.rebalance() に一本化した。
   * 旧実装はここでも独自に「遠いロングレンジリンク」を切っており、
   * 自分で選んだ outbound の接続まで落としていた。
   */
  public evaluateTopology() {
    this.peerManager.rebalance?.();
  }

  public destroy() {
    clearInterval(this.timer);
  }
}

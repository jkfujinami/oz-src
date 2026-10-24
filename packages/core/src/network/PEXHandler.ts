import type { PeerId, IPeerManager, IMessageDispatcher } from '../types';
import { RING_MESH } from '../constants';
import { WireType } from './wire/WireTypes';
import { MAX_PEX_ENTRIES } from './wire/WireCodec';
import { createLogger } from '../common/Logger';
import { secureRandomIndex } from './gossip/DandelionRouter';
import { sameOrigin } from './NetGroup';

const log = createLogger('net.pex');

const PEER_ID_RE = /^[0-9a-f]{32}$/;


/**
 * PEXHandler — トラッカーに頼らないピア発見。
 *
 * 変更点:
 *   - position と zones を載せない。position は peerId から導出でき、
 *     zones は購読宣言そのものなので流してはいけない (本家 18.6.2)。
 *   - 応答件数に上限を設ける。旧実装は隣人全員をそのまま返しており、
 *     応答サイズが接続数に比例して膨らんだ。
 *   - peerId の形式を検証する。Bound Identity では hex 32 文字に固定される。
 */
export class PEXHandler {
  private peerManager: IPeerManager;

  constructor(peerManager: IPeerManager, dispatcher: IMessageDispatcher) {
    this.peerManager = peerManager;
    dispatcher.register(WireType.PEX_REQUEST, (peerId, msg) => this.handlePexRequest(peerId, msg));
    dispatcher.register(WireType.PEX_RESPONSE, (peerId, msg) => this.handlePexResponse(peerId, msg));
  }

  public requestPeers(targetPeerId?: PeerId) {
    // ★ 要求は本体が空 (旧実装は未使用の minDistance を送っていた)
    if (targetPeerId) {
      this.peerManager.sendMessage(targetPeerId, WireType.PEX_REQUEST, {});
    } else {
      for (const peerId of this.peerManager.peers.keys()) {
        this.peerManager.sendMessage(peerId, WireType.PEX_REQUEST, {});
      }
    }
  }

  /** ── Dispatcher Handlers ── */

  private handlePexRequest(senderPeerId: PeerId, _msg: any) {
    // 検証済みの claim (pubkey + NodeId PoW) を添える。受け手はこれで
    // 「自分の隣人の隣人」をオニオンの出口候補として検証付きで知る。
    // pubkey と powCounter はどちらも JOIN で誰にでも開示している公開情報。
    // ★ ワイヤの項目は pubkey + powCounter だけ (peerId は pubkey から導出される)。claim を持たない
    //   相手は WireCodec が運ばない (受け手が検証できないものは紹介しない)。検証済みの隣人は必ず持っている。
    // ★ 相手と同じ出所 (同じ LAN・同じ公開 IP) の隣人は紹介しない。紹介した隣人は相手の回路の
    //   M1 の候補になり、M1 が出す要求や投稿が相手と同じ IP から出てしまう (OnionCircuit の relayAllowed)。
    const pm = this.peerManager;
    const filterOrigin = !!pm.originOf && !pm.sameOriginHopsAllowed;
    const requesterOrigin = filterOrigin ? pm.originOf!(senderPeerId) : '';
    const candidates = Array.from(this.peerManager.peers.values())
      .filter(p => p.peerId !== senderPeerId && p.isConnected && p.isVerified)
      .filter(p => !filterOrigin || !sameOrigin(requesterOrigin, pm.originOf!(p.peerId)))
      .map(p => {
        const peer = p as any;
        return peer.pubkey instanceof Uint8Array && typeof peer.powCounter === 'number'
          ? { id: p.peerId, pubkey: peer.pubkey as Uint8Array, powCounter: peer.powCounter as number }
          : { id: p.peerId };
      });

    // ランダムに間引いてから上限で切る。先頭 N 件固定だと、
    // 早期に接続した攻撃者ノードが永久に紹介され続ける
    // (本家 18.7-④ が Rust 側で指摘したのと同じ罠)。
    for (let i = candidates.length - 1; i > 0; i--) {
      const j = secureRandomIndex(i + 1);
      [candidates[i], candidates[j]] = [candidates[j], candidates[i]];
    }

    this.peerManager.sendMessage(senderPeerId, WireType.PEX_RESPONSE, {
      peers: candidates.slice(0, MAX_PEX_ENTRIES),
    });
  }

  private handlePexResponse(senderPeerId: PeerId, msg: any) {
    if (!msg || !Array.isArray(msg.peers)) {
      log.warn(`Invalid PEX_RESPONSE from ${senderPeerId.substring(0, 8)}`);
      return;
    }

    // 相手が何件返してこようと、こちらが処理する件数は自分で決める
    for (const p of msg.peers.slice(0, MAX_PEX_ENTRIES)) {
      const id = p?.id;
      if (typeof id !== 'string' || !PEER_ID_RE.test(id)) continue;
      if (id === this.peerManager.myPeerId) continue;

      const existing = this.peerManager.peers.get(id);
      if (existing && (existing.isConnected || (existing as any).isConnecting)) continue;
      // 次数に空きがあるか、自分で選んだ (outbound) 接続が目標に満たない間は張りに行く。
      // 後者は枠が埋まっていても行う (検証後に inbound と入れ替わる)。
      const outbound = this.peerManager.outboundCount ?? 0;
      if (this.peerManager.degree >= RING_MESH.MAX_DEGREE && outbound >= RING_MESH.OUTBOUND_TARGET) break;

      // position は渡さない。PeerManager が peerId から導出する。
      this.peerManager.connect(id, true, senderPeerId);
    }
  }
}

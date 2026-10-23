import type {
  PeerId,
  ISignalingClient,
  WireNodeClaim,
} from '../../src/types';

export class SignalingHub {
  private clients = new Map<PeerId, HubSignalingClient>();
  public relayed: Array<{ from: PeerId; to: PeerId; payload: any }> = [];

  register(peerId: PeerId, client: HubSignalingClient): void {
    this.clients.set(peerId, client);
  }

  route(from: PeerId, to: PeerId, payload: any): void {
    this.relayed.push({ from, to, payload });
    const target = this.clients.get(to);
    if (!target) return;
    target.deliverRelay(from, { ...payload, senderId: from });
  }
}

export class HubSignalingClient implements ISignalingClient {
  public connectedWith: { claim: WireNodeClaim } | null = null;
  private peersCb?: (peers: Array<{ peerId: PeerId }>) => void;
  private relayCb?: (senderId: PeerId, payload: any) => void;

  constructor(private hub: SignalingHub, private myPeerId: PeerId) {
    hub.register(myPeerId, this);
  }

  async connect(options: { claim: WireNodeClaim }): Promise<void> {
    this.connectedWith = { claim: options.claim };
  }

  sendRelay(targetPeerId: PeerId, payload: any): void {
    this.hub.route(this.myPeerId, targetPeerId, payload);
  }

  disconnect(): void {}

  on(event: 'peers' | 'relay', cb: any): void {
    if (event === 'peers') this.peersCb = cb;
    if (event === 'relay') this.relayCb = cb;
  }

  deliverRelay(senderId: PeerId, payload: any): void {
    this.relayCb?.(senderId, payload);
  }

  emitPeers(peers: Array<{ peerId: PeerId }>): void {
    this.peersCb?.(peers);
  }
}

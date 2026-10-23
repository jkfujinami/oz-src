import { vi } from 'vitest';
import type { IPeerManager, IPeerConnection, PeerId } from '../../src/types';
import { MessageDispatcher } from '../../src/network/MessageDispatcher';

/**
 * Heartbeat / PEXHandler / RingMaintainer 用の最小の IPeerManager。
 * 送信は `sent` に記録するだけで、ネットワークには何も出さない。
 */
export interface FakePeer extends IPeerConnection {
  rtt: number;
  isConnected: boolean;
  isVerified: boolean;
  isConnecting?: boolean;
  pubkey?: Uint8Array;
  powCounter?: number;
}

export class FakeNetworkPeerManager implements IPeerManager {
  public readonly _peers = new Map<PeerId, FakePeer>();
  public sent: Array<{ to: PeerId; type: number; payload: any }> = [];
  public degreeOverride: number | null = null;
  public outboundCount?: number;
  public readonly connect = vi.fn((_id: PeerId, _initiator?: boolean, _via?: PeerId) => undefined);
  public readonly disconnect = vi.fn((id: PeerId) => { this._peers.delete(id); });
  public readonly rebalance = vi.fn((_newcomer?: PeerId) => {});
  private listeners = new Map<string, Array<(...a: any[]) => void>>();

  constructor(public myPeerId: PeerId = 'f'.repeat(32), public myPosition = 0.5) {}

  get peers(): ReadonlyMap<PeerId, IPeerConnection> {
    return this._peers;
  }

  get degree(): number {
    return this.degreeOverride ?? Array.from(this._peers.values()).filter(p => p.isConnected).length;
  }

  addPeer(peerId: PeerId, over: Partial<FakePeer> = {}): FakePeer {
    const peer: FakePeer = {
      peerId, position: 0, rtt: 0, isConnected: true, isVerified: true,
      send: vi.fn(), close: vi.fn(),
      ...over,
    };
    this._peers.set(peerId, peer);
    return peer;
  }

  sendMessage(peerId: PeerId, type: number, payload: any): void {
    this.sent.push({ to: peerId, type, payload });
  }

  on(event: string, handler: (...args: any[]) => void): void {
    const hs = this.listeners.get(event) ?? [];
    hs.push(handler);
    this.listeners.set(event, hs);
  }

  off(event: string, handler: (...args: any[]) => void): void {
    this.listeners.set(event, (this.listeners.get(event) ?? []).filter(h => h !== handler));
  }

  emit(event: string, ...args: any[]): void {
    for (const h of this.listeners.get(event) ?? []) h(...args);
  }

  listenerCount(event: string): number {
    return this.listeners.get(event)?.length ?? 0;
  }
}

/** hex 32 文字の peerId を作る */
export function pid(n: number): PeerId {
  return n.toString(16).padStart(32, '0');
}

export function newDispatcher() {
  return new MessageDispatcher();
}

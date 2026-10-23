import { TunnelRelay, type TunnelRelayOptions } from '../../src/network/tunnel/TunnelRelay';
import { TunnelClient } from '../../src/network/tunnel/TunnelClient';
import { HistoryClient, type HistoryClientParts } from '../../src/network/history/HistoryClient';
import { Encoding } from '../../src/common/Encoding';
import { announceVerified, link, sleep, type SimNode } from './onionNet';
import { attachStorage, type StorageSimNode } from './storageNet';
import type { StorageServiceParts } from '../../src/network/storage/StorageService';

/** 保管担当 + トンネルの中継 + 取りに行く側 (HistoryClient) をつけたシミュレーション用ノード (OzNode の配線と同じ) */
export interface TunnelSimNode extends StorageSimNode {
  relay: TunnelRelay;
  tunnel: TunnelClient;
  history: HistoryClient;
  /** このノードの SID (hex) */
  sid: string;
}

export interface AttachTunnelOptions {
  storage?: Partial<StorageServiceParts> & { slots?: number; wait?: boolean };
  relay?: TunnelRelayOptions;
  history?: HistoryClientParts['limits'];
  random?: () => number;
}

/** StorageService (本物の暗号化 DB + HolderStore) に、TunnelRelay・TunnelClient・HistoryClient をつなぐ */
export async function attachTunnel(node: SimNode, opts: AttachTunnelOptions = {}): Promise<TunnelSimNode> {
  const sn = await attachStorage(node, opts.storage);
  const relay = new TunnelRelay(sn.peerManager, sn.dispatcher, opts.relay);
  const tunnel = new TunnelClient(sn.peerManager, sn.dispatcher, sn.dandelion);
  const sid = Encoding.toHex(sn.storage.identity.publicKey);
  const history = new HistoryClient({
    tunnel,
    peerManager: sn.peerManager,
    dandelion: sn.dandelion,
    duty: sn.storage.duty,
    leaseSets: sn.storage.leaseSets,
    deliver: (p) => sn.gossip.deliverFetched(p),
    ownSid: () => sid,
    random: opts.random,
    limits: { hedgeMs: 150, inactivityMs: 2000, readyWaitMs: 500, holdersWaitMs: 300, holdersPollMs: 20, ...opts.history },
  });
  return Object.assign(sn, { relay, tunnel, history, sid });
}

export function stopTunnel(nodes: TunnelSimNode[]): void {
  for (const n of nodes) {
    n.history.destroy();
    n.tunnel.destroy();
    n.relay.destroy();
  }
}

export const pinTo = (n: SimNode, guard: SimNode) =>
  n.dandelion.getPinnedGuard([{ peerId: guard.identity.peerId, pubkey: guard.identity.pubkey }]);

/** n を guard の下につなぎ (1 ホップ目に固定)、握手が済んだことにする */
export function attachBehind(n: SimNode, guard: SimNode): void {
  link(n, guard);
  pinTo(n, guard);
  announceVerified(n, guard);
}

export async function until(cond: () => boolean | Promise<boolean>, timeoutMs = 5000, what = 'condition'): Promise<void> {
  const end = performance.now() + timeoutMs;
  while (!(await cond()) && performance.now() < end) await sleep(10);
  if (!(await cond())) throw new Error(`until: ${what} not met`);
}

import { OzNode, IndexedDBStore, createGuardString, sodiumReady } from '@oz/core';
import { DEFAULT_TRACKER_URL, GUARD_TRUST, ICE_SERVERS } from './appConfig';
import type { GuardReport, GuardStartConfig } from './guardProtocol';

/**
 * この端末で動かす信頼 Guard (見えないウィンドウ guard.html の中身)。
 *
 * 画面のノードとは別の DB (OzGuardDB) と別の身元で動く。身元は固定 (信頼リストに載る)。
 * 状態は件数だけをメインへ送る (利用者の peerId や IP は送らない)。
 */

/** Guard の暗号化 DB の名前 (画面のノードの OzLiteDB とは別) */
export const DESKTOP_GUARD_DB_NAME = 'OzGuardDB';
const REPORT_INTERVAL_MS = 5000;

interface GuardBridge {
  getStartConfig(): Promise<GuardStartConfig>;
  reportStatus(report: GuardReport): void;
  reportError(message: string): void;
  onStop(cb: () => void): void;
  stopped(): void;
}

const bridge = (window as unknown as { ozGuard?: GuardBridge }).ozGuard;

async function run(b: GuardBridge): Promise<void> {
  await sodiumReady;
  const cfg = await b.getStartConfig();
  if (!cfg || typeof cfg.passphrase !== 'string' || cfg.passphrase.length < 16 || !Number.isInteger(cfg.slots)) {
    throw new Error('起動の設定を受け取れませんでした');
  }
  const { passphrase, slots } = cfg;
  if (!DEFAULT_TRACKER_URL) throw new Error('トラッカーが設定されていません');
  const node = await OzNode.create({
    db: new IndexedDBStore(DESKTOP_GUARD_DB_NAME),
    role: 'guard',
    identityMode: 'persistent',
    passphrase,
    trackerUrl: DEFAULT_TRACKER_URL,
    ...(ICE_SERVERS && ICE_SERVERS.length > 0 ? { iceServers: ICE_SERVERS } : {}),
    ...(GUARD_TRUST ? { trust: GUARD_TRUST } : {}),
    storage: { defaultSlots: slots },
  });
  const self = node.peerId;
  const guardString = createGuardString(node.nodeIdentity);

  const report = (): void => {
    const verified = node.peerManager.verifiedPeers;
    let backbone = 0;
    for (const p of verified) if (node.peerManager.isTrustedGuard(p.peerId)) backbone++;
    b.reportStatus({
      peerId: self,
      guardString,
      hasList: node.guards.hasUsableList,
      listed: node.guards.hasUsableList && node.guards.isTrustedPeerId(self),
      listVersion: node.guardStatus.listVersion ?? null,
      counts: { degree: node.degree, clients: verified.length - backbone, backbone, tunnels: node.tunnelRelay.tunnelCount },
    });
  };

  let stopping = false;
  let timer: ReturnType<typeof setInterval> | null = null;
  b.onStop(() => {
    if (stopping) return;
    stopping = true;
    if (timer) clearInterval(timer);
    // 保留中の書き込み (預かり物・追いつきの位置) を流してから知らせる
    void node.stop().catch(() => {}).finally(() => b.stopped());
  });

  await node.start();
  if (stopping) return;
  report();
  timer = setInterval(report, REPORT_INTERVAL_MS);
}

if (bridge) {
  run(bridge).catch((err) => bridge.reportError(err instanceof Error ? err.message : String(err)));
}

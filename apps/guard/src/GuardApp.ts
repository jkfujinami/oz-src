import { OzNode, IndexedDBStore, createGuardString, createLogger, type OzNodeConfig } from '@oz/core';
import { createIndexedDbFactory, installNodeGlobals } from './env';
import { SnapshotStore } from './snapshot';
import type { GuardConfig } from './config';

const log = createLogger('guard.app');

/** 暗号化 DB の名前 (スナップショットにも記録され、別の DB のものを読ませないための照合に使う) */
export const GUARD_DB_NAME = 'OzGuardDB';

export const STATUS_INTERVAL_MS = 5 * 60_000;

export interface StartOptions {
  /** 出力先 (既定 console.log)。peerId と鍵を出すのは起動時の案内だけ */
  print?: (line: string) => void;
  statusIntervalMs?: number;
  /** ★ テスト専用: OzNode への上書き (KDF や PoW を軽くする、回路のタイマーを縮める等) */
  nodeOverrides?: Partial<OzNodeConfig>;
}

export interface GuardCounts {
  degree: number;
  clients: number;
  backbone: number;
  catchupPackets: number;
  catchupBytes: number;
  tunnels: number;
  tunnelRoutes: number;
}

export interface GuardHandle {
  node: OzNode;
  /** guard-maintainer の guards ファイルに 1 行で書ける文字列 */
  guardString: string;
  /** 新規に身元を作ったか (false = スナップショットから復元) */
  createdIdentity: boolean;
  counts(): GuardCounts;
  statusLine(): string;
  /** 今すぐスナップショットを書く */
  snapshotNow(): Promise<void>;
  stop(): Promise<void>;
}

export async function startGuard(config: GuardConfig, opts: StartOptions = {}): Promise<GuardHandle> {
  const print = opts.print ?? ((l: string) => console.log(l));

  // 1. 保存先を用意し、あればスナップショットを戻す (壊れていれば例外 = 起動しない)
  const factory = createIndexedDbFactory();
  const snapshots = new SnapshotStore(config.dataDir, factory, GUARD_DB_NAME);
  const restored = await snapshots.restore();
  await installNodeGlobals(factory);

  // 2. ノード。初回はここで peerId を採掘して暗号化 DB に書く (数秒かかる)
  const db = new IndexedDBStore(GUARD_DB_NAME);
  if (!restored) print('初回起動です。身元 (peerId) を作っています。数十秒かかることがあります...');
  const node = await OzNode.create({
    db,
    role: 'guard',
    identityMode: 'persistent',
    passphrase: config.passphrase,
    trackerUrl: config.trackerUrl,
    ...(config.iceServers.length > 0 ? { iceServers: config.iceServers } : {}),
    ...(config.trust ? { trust: config.trust } : {}),
    storage: { defaultSlots: config.storageSlots },
    ...opts.nodeOverrides,
  });

  // ★ 身元を作った直後に必ず 1 回書く。以降の定期スナップショットの前に落ちても、peerId だけは失わない
  //   (失うと署名済みの Guard リストの peerId が無効になる)。
  await snapshots.save();

  const self = node.peerId;
  const guardString = createGuardString(node.nodeIdentity);

  const counts = (): GuardCounts => {
    const verified = node.peerManager.verifiedPeers;
    let backbone = 0;
    for (const p of verified) if (node.peerManager.isTrustedGuard(p.peerId)) backbone++;
    return {
      degree: node.degree,
      clients: verified.length - backbone,
      backbone,
      catchupPackets: node.recent.size,
      catchupBytes: node.recent.bytes,
      tunnels: node.tunnelRelay.tunnelCount,
      tunnelRoutes: node.tunnelRelay.routeCount,
    };
  };

  // ★ 件数だけ。クライアントの peerId や IP は出さない
  const statusLine = (): string => {
    const c = counts();
    const mib = (c.catchupBytes / (1024 * 1024)).toFixed(1);
    return (
      `接続 ${c.degree} (利用者 ${c.clients} / バックボーン ${c.backbone}), ` +
      `追いつきバッファ ${c.catchupPackets} 件 ${mib}MiB, トンネル ${c.tunnels} 本 / 経路 ${c.tunnelRoutes}`
    );
  };

  // 3. 起動
  await node.start();

  const trustedOthers = node.guards.trustedGuardIds().filter((id) => id !== self);
  print('--- Guard を起動しました ---');
  print(`peerId:      ${self}`);
  print(`公開鍵:      ${Buffer.from(node.nodeIdentity.pubkey).toString('base64url')} (Ed25519, base64url)`);
  print('Guard 文字列 (guard-maintainer の --guards ファイルに 1 行で追加します):');
  print(guardString);
  print('  検証: npm --workspace=@oz/core run guard-maintainer -- check <上の文字列>');
  if (node.guards.hasUsableList) {
    const listed = node.guards.isTrustedPeerId(self);
    print(`信頼リスト:  読み込み済み (v${node.guardStatus.listVersion ?? '?'})。この Guard は${listed ? 'リストに載っています' : 'まだリストに載っていません'}`);
    print(`バックボーン: 見えている他の信頼 Guard は ${trustedOthers.length} 台`);
  } else if (config.trust) {
    print('信頼リスト:  メンテナ鍵はありますが、使えるリストがありません (未指定・期限切れ・署名不正)');
  } else {
    print('信頼リスト:  なし (メンテナ鍵が未設定。バックボーンは作られません)');
  }

  // 4. 定期処理
  const timers: Array<ReturnType<typeof setInterval>> = [];
  const snapshotTimer = setInterval(() => {
    snapshots.save().catch(() => log.warn(() => 'periodic snapshot failed; will retry'));
  }, config.snapshotIntervalMs);
  const statusTimer = setInterval(() => log.info(() => statusLine()), opts.statusIntervalMs ?? STATUS_INTERVAL_MS);
  timers.push(snapshotTimer, statusTimer);
  // ★ タイマーだけでプロセスを生かさない (停止はシグナルと node.stop が決める)
  for (const t of timers) t.unref();

  let stopping: Promise<void> | null = null;
  const stop = (): Promise<void> => {
    stopping ??= (async () => {
      for (const t of timers) clearInterval(t);
      // 先にノードを止める: 保留中の書き込み (預かり・追いつきの位置) を流してから最終スナップショット
      await node.stop();
      await snapshots.save();
    })();
    return stopping;
  };

  return {
    node,
    guardString,
    createdIdentity: !restored,
    counts,
    statusLine,
    snapshotNow: async () => {
      await snapshots.save();
    },
    stop,
  };
}

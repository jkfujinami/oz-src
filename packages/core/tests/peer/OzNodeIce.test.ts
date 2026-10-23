import { describe, it, expect } from 'vitest';
import 'fake-indexeddb/auto';
import { OzNode } from '../../src/node/OzNode';
import { IndexedDBStore } from '../../src/storage/IndexedDBStore';
import { VAULT_PARAMS_FAST } from '../../src/storage/SecretVault';

async function makeNode(iceServers?: string[]) {
  const db = new IndexedDBStore(`ice_${Date.now()}_${Math.random()}`);
  await db.init();
  return OzNode.create({
    storage: { slotEffort: 1, chunkEffort: 1 },
    db,
    trackerUrl: 'wss://tracker.example.org/ws',
    autoStart: false,
    passphrase: 'test-passphrase',
    vaultParams: VAULT_PARAMS_FAST,
    ...(iceServers ? { iceServers } : {}),
  });
}

describe('STUN の選択 (OzNode)', () => {
  const multiAsCluster = [
    'stun:stun.l.google.com:19302',
    'stun:stun.cloudflare.com:3478',
  ];

  it('既定は Multi-AS STUN クラスタ。好きな STUN を選べて、null で既定に戻る', async () => {
    const node = await makeNode();
    expect(node.iceServers).toEqual([]);
    expect(node.defaultStunServer).toBe('stun:stun.l.google.com:19302');
    expect(node.effectiveIceServers).toEqual(multiAsCluster);

    const r = node.setIceServers('stun:stun.example.org:3478, stun:[2001:db8::1]:19302');
    expect(r.ok).toBe(true);
    expect(node.iceServers).toEqual(['stun:stun.example.org:3478', 'stun:[2001:db8::1]:19302']);
    expect(node.effectiveIceServers).toEqual(['stun:stun.example.org:3478', 'stun:[2001:db8::1]:19302']);

    expect(node.setIceServers(null).ok).toBe(true);
    expect(node.effectiveIceServers).toEqual(multiAsCluster);
    await node.stop();
  });

  it('不正な入力 (turn: / 5 つ以上 / 形の違う URL) は拒否し、設定は変わらない', async () => {
    const node = await makeNode(['stun:stun.example.org:3478']);
    for (const bad of ['turn:relay.example.org', 'stun:a,stun:b,stun:c,stun:d,stun:e', 'http://example.org', 'stun:bad host']) {
      expect(node.setIceServers(bad).ok).toBe(false);
    }
    expect(node.iceServers).toEqual(['stun:stun.example.org:3478']);
    await node.stop();
  });

  it('選び直した STUN は、次に張る接続 (PeerManager が接続ごとに読む) から使われる', async () => {
    const node = await makeNode();
    const provider = (node.peerManager as any).iceServersProvider as () => RTCIceServer[];
    expect(provider()).toEqual([{ urls: multiAsCluster }]);
    node.setIceServers('stun:stun.example.org:3478');
    expect(provider()).toEqual([{ urls: 'stun:stun.example.org:3478' }]);
    await node.stop();
  });
});

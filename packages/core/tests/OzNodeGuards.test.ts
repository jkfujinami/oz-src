import 'fake-indexeddb/auto';
import { describe, it, expect, beforeAll } from 'vitest';
import { OzNode } from '../src/node/OzNode';
import { IndexedDBStore } from '../src/storage/IndexedDBStore';
import { VAULT_PARAMS_FAST } from '../src/storage/SecretVault';
import { GUARD_MAX_DEGREE, RING_MESH } from '../src/constants';
import { sodiumReady } from '../src/crypto/sodium';
import { makeList, makeMaintainer, type Maintainer } from './helpers/guardFixtures';

let seq = 0;
async function makeDb(): Promise<IndexedDBStore> {
  const db = new IndexedDBStore(`GuardNodeDB_${Date.now()}_${seq++}`);
  await db.init();
  return db;
}

describe('OzNode: 信頼 Guard の配線と Guard 役', () => {
  let m: Maintainer;

  beforeAll(async () => {
    await sodiumReady;
    m = await makeMaintainer();
  });

  it("role 'guard' は identityMode 'persistent' が必須 (満たさなければ明確なエラー)", async () => {
    const db = await makeDb();
    await expect(
      OzNode.create({ db, role: 'guard', passphrase: 'pw', vaultParams: VAULT_PARAMS_FAST }),
    ).rejects.toThrow(/persistent/);
    await expect(
      OzNode.create({ db, role: 'guard', identityMode: 'ephemeral', passphrase: 'pw', vaultParams: VAULT_PARAMS_FAST }),
    ).rejects.toThrow(/persistent/);
  });

  it('Guard 役は次数の上限を広げ、トラッカーから切り離さない。リストの取り込みと状態の通知もできる', async () => {
    // Guard 役 (固定の peerId を採掘する)
    const guardNode = await OzNode.create({
      storage: { slotEffort: 1, chunkEffort: 1 }, // ★ 保管の PoW は軽く (CPU を食って他のテストの時間を乱さないように)
      db: await makeDb(),
      role: 'guard',
      identityMode: 'persistent',
      passphrase: 'guard-pw',
      vaultParams: VAULT_PARAMS_FAST,
    });
    expect((guardNode.peerManager as any).maxDegreeLimit).toBe(GUARD_MAX_DEGREE);
    expect((guardNode.peerManager as any).keepTrackerAttached).toBe(true);
    expect(GUARD_MAX_DEGREE).toBeGreaterThan(RING_MESH.MAX_DEGREE);
    // 過去ログ v2: Guard は 72 時間・256MiB のバッファを持つ
    expect([guardNode.recent.windowMs, guardNode.recent.maxBytes]).toEqual([72 * 3600_000, 256 * 1024 * 1024]);

    // 利用者: 設定にリストを持つ
    const v1 = makeList(m, [guardNode.nodeIdentity], { version: 1, now: Date.now() });
    const clientDb = await makeDb();
    const client = await OzNode.create({
      storage: { slotEffort: 1, chunkEffort: 1 }, // ★ 保管の PoW は軽く (CPU を食って他のテストの時間を乱さないように)
      db: clientDb,
      passphrase: 'client-pw',
      vaultParams: VAULT_PARAMS_FAST,
      trust: { maintainerKeys: m.keyset, guardList: v1 },
    });
    expect((client.peerManager as any).maxDegreeLimit).toBe(RING_MESH.MAX_DEGREE);
    expect([client.recent.windowMs, client.recent.maxBytes]).toEqual([3600_000, 16 * 1024 * 1024]);
    expect(client.guardStatus).toMatchObject({ mode: 'none', listVersion: 1, reason: 'waiting-for-trusted-guard' });
    expect(client.guards.wantedGuardIds()).toEqual([guardNode.peerId]);

    // 新しい版は受け入れ、保存される。古い版は拒否
    const seen: number[] = [];
    const off = client.onGuardStatus(s => { if (s.listVersion !== null) seen.push(s.listVersion); });
    const ok = await client.importGuardList(makeList(m, [guardNode.nodeIdentity], { version: 2, now: Date.now() }));
    expect(ok.ok).toBe(true);
    expect(client.guardStatus.listVersion).toBe(2);
    expect(seen).toContain(2);
    expect(await client.importGuardList(v1)).toMatchObject({ ok: false, reason: 'rollback' });
    expect((await clientDb.getSetting<{ version: number }>('guard.list'))?.version).toBe(2);
    off();

    // リストを持たない利用者は open 動作
    const plain = await OzNode.create({
      storage: { slotEffort: 1, chunkEffort: 1 }, // ★ 保管の PoW は軽く (CPU を食って他のテストの時間を乱さないように)
      db: await makeDb(), passphrase: 'plain-pw', vaultParams: VAULT_PARAMS_FAST,
    });
    expect(plain.guardStatus).toMatchObject({ mode: 'none', reason: 'no-list', listVersion: null });
    expect(await plain.importGuardList(v1)).toMatchObject({ ok: false, reason: 'no-keyset' });

    for (const n of [guardNode, client, plain]) await n.stop();
    await expect(client.importGuardList(v1)).rejects.toThrow(/stopped/);
  }, 60_000);
});

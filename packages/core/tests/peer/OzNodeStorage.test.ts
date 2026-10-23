import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest';
import 'fake-indexeddb/auto';
import { sodiumReady } from '../../src/crypto/sodium';
import { OzNode } from '../../src/node/OzNode';
import { IndexedDBStore } from '../../src/storage/IndexedDBStore';
import { VAULT_PARAMS_FAST } from '../../src/storage/SecretVault';
import { NodeIdentity } from '../../src/crypto/NodeIdentity';
import { NodeIdentityStore } from '../../src/crypto/NodeIdentityStore';
import { STORAGE_CAPACITY_KEY } from '../../src/network/storage/StorageService';
import { SLOT_BYTES } from '../../src/network/storage/SlotPow';

const FAST = { difficulty: 0, opsLimit: 1, memLimit: 8192 };
const PASS = 'storage-node-pass';
let seq = 0;

const signalingMock = () => ({
  connect: vi.fn().mockResolvedValue(undefined), disconnect: vi.fn(), sendRelay: vi.fn(), on: vi.fn(), isConnected: false,
});

async function makeNode(name: string, storage?: { defaultSlots?: number; slotEffort?: number }) {
  return OzNode.create({
    db: new IndexedDBStore(name),
    signalingClient: signalingMock(),
    passphrase: PASS,
    vaultParams: VAULT_PARAMS_FAST,
    circuit: { coverIntervalMs: 50, relayDelayMs: 1, echoTimeoutMs: 1000 },
    storage,
  });
}

async function until(cond: () => boolean, ms = 8000) {
  const end = performance.now() + ms;
  while (!cond() && performance.now() < end) await new Promise(r => setTimeout(r, 10));
  if (!cond()) throw new Error('until: condition not met');
}

describe('OzNode: 保管担当の配線', () => {
  beforeAll(async () => { await sodiumReady; });
  beforeEach(() => {
    vi.spyOn(NodeIdentityStore, 'mineEphemeral').mockImplementation(() => NodeIdentity.mine(FAST));
  });
  afterEach(() => { vi.restoreAllMocks(); });

  it('★既定は 1 枠 (ブラウザ相当)。start で裏で枠を解き、stop で全部止まる', async () => {
    const node = await makeNode(`stor_${Date.now()}_${seq++}`, { slotEffort: 1 });
    expect(node.storageCapacity).toBe(1);
    expect(node.storage.activeSlots()).toHaveLength(0); // 起動前は解いていない
    await node.start();
    await until(() => node.storage.activeSlots().length === 1);
    expect(node.storage.holder).not.toBeNull();
    await node.stop();
    expect(node.db.isUnlocked).toBe(false);
  });

  it('★defaultSlots (デスクトップ 4) で起動すると 4 枠。SID と枠は暗号化 DB に残り、次の起動では解き直さない', async () => {
    const name = `stor_${Date.now()}_${seq++}`;
    const a = await makeNode(name, { defaultSlots: 4, slotEffort: 1 });
    const sid = Buffer.from(a.storage.identity.publicKey).toString('hex');
    await a.start();
    await until(() => a.storage.activeSlots().length === 4);
    const positions = a.storage.activeSlots().map(s => s.position);
    await a.stop();

    const b = await makeNode(name, { defaultSlots: 4, slotEffort: 1 });
    expect(Buffer.from(b.storage.identity.publicKey).toString('hex')).toBe(sid);
    expect(b.storage.identity.slots.map(s => s.position)).toEqual(positions); // start 前から揃っている
    await b.stop();
  });

  it('★容量の変更: 設定は暗号化 DB に保存され、最小 1・最大 16。増やすと枠が増え、再起動後も保たれる', async () => {
    const name = `stor_${Date.now()}_${seq++}`;
    const a = await makeNode(name, { slotEffort: 1 });
    await a.start();
    await until(() => a.storage.activeSlots().length === 1);
    await a.setStorageCapacity(3);
    expect(a.storageCapacity).toBe(3);
    await until(() => a.storage.activeSlots().length === 3);
    await a.setStorageCapacity(0); // 最小 1
    expect(a.storageCapacity).toBe(1);
    expect(a.storage.activeSlots()).toHaveLength(1); // 解いた枠は取っておくが、受け持つのは容量の範囲だけ
    expect(a.storage.identity.slots).toHaveLength(3);
    await a.setStorageCapacity(99); // 最大 16
    expect(a.storageCapacity).toBe(16);
    await a.setStorageCapacity(2);
    expect(await a.db.getSetting(STORAGE_CAPACITY_KEY)).toBe(2);
    await a.stop();

    const b = await makeNode(name, { defaultSlots: 4, slotEffort: 1 }); // 保存済みの設定が既定より優先
    expect(b.storageCapacity).toBe(2);
    expect(b.storage.activeSlots()).toHaveLength(2);
    await b.stop();
  });

  it('容量は預かり量の上限 (枠 × 256MiB) になる', async () => {
    const node = await makeNode(`stor_${Date.now()}_${seq++}`, { defaultSlots: 4, slotEffort: 1 });
    expect(node.storageCapacity * SLOT_BYTES).toBe(1024 * 1024 * 1024);
    await node.stop();
  });

  it('★ファイル API: uploadFile は link / cancel / pause / resume を返す。中止すると cancelled。不正なリンクは bad-link。停止後は使えない', async () => {
    const node = await makeNode(`stor_${Date.now()}_${seq++}`, { slotEffort: 1 });
    await node.start();
    const up = node.uploadFile(new Uint8Array(5000).fill(7), { name: 'a.bin', mime: 'application/octet-stream' });
    expect(typeof up.pause).toBe('function');
    expect(typeof up.resume).toBe('function');
    up.pause();
    up.resume();
    up.cancel(); // 1 ホップ目の無い単独ノード: 待っている間に中止
    await expect(up.link).rejects.toMatchObject({ code: 'cancelled' });

    const dl = node.downloadFile('[[file:garbage]]');
    await expect((async () => { for await (const _ of dl) void _; })()).rejects.toMatchObject({ code: 'bad-link' });
    await expect(dl.manifest).rejects.toMatchObject({ code: 'bad-link' });
    expect(typeof dl.cancel).toBe('function');

    await node.stop();
    expect(() => node.uploadFile(new Uint8Array(1), { name: 'a', mime: 'text/plain' })).toThrow();
    expect(() => node.downloadFile('x')).toThrow();
  });

  it('停止後は設定できない', async () => {
    const node = await makeNode(`stor_${Date.now()}_${seq++}`, { slotEffort: 1 });
    await node.stop();
    await expect(node.setStorageCapacity(2)).rejects.toThrow();
  });
});

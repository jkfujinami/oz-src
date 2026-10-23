import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import sodium, { sodiumReady } from '../../src/crypto/sodium';
import { NodeIdentityStore } from '../../src/crypto/NodeIdentityStore';
import { NodeIdentity, type NodeIdPowParams } from '../../src/crypto/NodeIdentity';
import { meetsDifficulty } from '../../src/crypto/PowPolicy';
import { memorySealedStore, captureLogSink, containsBytes } from '../helpers/cryptoStorageFixtures';

const FREE: NodeIdPowParams = { difficulty: 0, opsLimit: 1, memLimit: 8192 };
const P4: NodeIdPowParams = { difficulty: 4, opsLimit: 1, memLimit: 8192 };
const PASS = 'node passphrase';

beforeAll(async () => {
  await sodiumReady;
});

let log: ReturnType<typeof captureLogSink>;
beforeEach(() => {
  log = captureLogSink();
});
afterEach(() => {
  log.restore();
});

/** 鍵ペアを "privkey ‖ pubkey" の形で保存する (NodeIdentityStore の保存形式) */
async function storeKeypair(store: ReturnType<typeof memorySealedStore>, seed: number, powCounter: unknown) {
  const kp = sodium.crypto_sign_seed_keypair(new Uint8Array(32).fill(seed));
  const blob = new Uint8Array(96);
  blob.set(kp.privateKey, 0);
  blob.set(kp.publicKey, 64);
  await store.saveSecret('node', blob, { powCounter });
  return kp;
}

describe('NodeIdentityStore.loadOrMine: 保存形式', () => {
  it('store には privkey ‖ pubkey が渡る (暗号化は store の DEK)。meta には公開情報だけを置く', async () => {
    const store = memorySealedStore();
    const id = await NodeIdentityStore.loadOrMine(store, PASS, FREE);
    const rec = store.slots.get('node')!;
    const { privkey, pubkey } = id.exportSecret();
    expect(rec.meta).toEqual({ powCounter: id.powCounter, peerId: id.peerId });
    expect(Array.from(rec.secret)).toEqual([...privkey, ...pubkey]);
    // パスフレーズ自体はどこにも渡らない
    expect(JSON.stringify(rec.meta)).not.toContain(PASS);
  });

  it('復元した identity は同じ秘密鍵で署名できる', async () => {
    const store = memorySealedStore();
    const first = await NodeIdentityStore.loadOrMine(store, PASS, FREE);
    const again = await NodeIdentityStore.loadOrMine(store, PASS, FREE);
    expect(again.peerId).toBe(first.peerId);
    expect(again.position).toBe(first.position);
    const c = NodeIdentity.newChallenge();
    const b = { verifierId: 'x', signerFingerprint: 'a', verifierFingerprint: 'b' };
    expect(NodeIdentity.verifySignedClaim(again.signClaim(c, b), c, b, FREE)).toBe(true);
  });

  it('PoW 付きの identity も保存・復元できる', async () => {
    const store = memorySealedStore();
    const first = await NodeIdentityStore.loadOrMine(store, PASS, P4);
    expect(NodeIdentity.verifyClaim(first.claim(), P4)).toBe(true);
    const again = await NodeIdentityStore.loadOrMine(store, PASS, P4);
    expect(again.peerId).toBe(first.peerId);
    expect(again.powCounter).toBe(first.powCounter);
  });

  it('パスフレーズが文字列でない・空なら拒否し、何も保存しない', async () => {
    const store = memorySealedStore();
    for (const p of ['', undefined, null, 123]) {
      await expect(NodeIdentityStore.loadOrMine(store, p as any, FREE)).rejects.toThrow(RangeError);
    }
    expect(store.slots.size).toBe(0);
  });
});

describe('NodeIdentityStore.loadOrMine: 復元できない場合', () => {
  it('保存された中身の長さが違えば採掘し直す', async () => {
    const store = memorySealedStore();
    await store.saveSecret('node', new Uint8Array(95), { powCounter: 0 });
    const id = await NodeIdentityStore.loadOrMine(store, PASS, FREE);
    expect(NodeIdentity.verifyClaim(id.claim(), FREE)).toBe(true);
    expect(store.slots.get('node')!.secret).toHaveLength(96);
  });

  it('meta の powCounter が不正なら採掘し直す', async () => {
    for (const bad of [undefined, -1, 1.5, '0', NaN]) {
      const store = memorySealedStore();
      const kp = await storeKeypair(store, 7, bad);
      const id = await NodeIdentityStore.loadOrMine(store, PASS, FREE);
      expect(id.peerId).not.toBe(NodeIdentity.derivePeerId(kp.publicKey));
      expect(store.slots.get('node')!.meta.powCounter).toBe(id.powCounter);
    }
  });

  it('meta そのものが無くても例外を投げずに採掘し直す', async () => {
    const store = memorySealedStore();
    const kp = sodium.crypto_sign_seed_keypair(new Uint8Array(32).fill(3));
    await store.saveSecret('node', new Uint8Array([...kp.privateKey, ...kp.publicKey]));
    const id = await NodeIdentityStore.loadOrMine(store, PASS, FREE);
    expect(id.peerId).not.toBe(NodeIdentity.derivePeerId(kp.publicKey));
  });

  it('保存済みの解が現在の難易度を満たさなければ採掘し直し、新しい解を保存する', async () => {
    const store = memorySealedStore();
    const kp = sodium.crypto_sign_seed_keypair(new Uint8Array(32).fill(9));
    let bad = 0;
    while (meetsDifficulty(NodeIdentity.nodeIdPowHash(kp.publicKey, bad, P4), 4)) bad++;
    await storeKeypair(store, 9, bad);

    // 旧ポリシー (難易度 0) なら復元できる
    const old = await NodeIdentityStore.loadOrMine(store, PASS, FREE);
    expect(old.peerId).toBe(NodeIdentity.derivePeerId(kp.publicKey));

    // 新ポリシーでは捨てて採掘し直す
    const fresh = await NodeIdentityStore.loadOrMine(store, PASS, P4);
    expect(fresh.peerId).not.toBe(old.peerId);
    expect(NodeIdentity.verifyClaim(fresh.claim(), P4)).toBe(true);
    const again = await NodeIdentityStore.loadOrMine(store, PASS, P4);
    expect(again.peerId).toBe(fresh.peerId);
  });

  it('ストアの読み出しが失敗したら例外を伝え、採掘して上書きしない', async () => {
    const store = memorySealedStore({ failGet: true });
    await expect(NodeIdentityStore.loadOrMine(store, PASS, FREE)).rejects.toThrow();
    expect(store.slots.has('node')).toBe(false);
  });

  it('保存に失敗したら例外を伝える (保存されたと誤認させない)', async () => {
    const store = memorySealedStore({ failSave: true });
    await expect(NodeIdentityStore.loadOrMine(store, PASS, FREE)).rejects.toThrow('save failed');
  });
});

describe('NodeIdentityStore.mineEphemeral', () => {
  it('保存しない。ストアの読み出しが失敗しても採掘して続行する', async () => {
    const a = memorySealedStore({ failGet: true });
    const id = await NodeIdentityStore.mineEphemeral(a, FREE);
    expect(NodeIdentity.verifyClaim(id.claim(), FREE)).toBe(true);
    expect(a.slots.size).toBe(0);

  });

  it('毎回の採掘結果は PoW を満たす', async () => {
    const id = await NodeIdentityStore.mineEphemeral(memorySealedStore(), P4);
    expect(NodeIdentity.verifyClaim(id.claim(), P4)).toBe(true);
  });
});

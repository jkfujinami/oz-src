import { describe, it, expect, beforeAll } from 'vitest';
import { sodiumReady } from '../../src/crypto/sodium';
import { NodeIdentityStore } from '../../src/crypto/NodeIdentityStore';
import { Identity, type SealedStore } from '../../src/crypto/Identity';

const FAST = { difficulty: 0, opsLimit: 1, memLimit: 8192 };

function memoryStore(): SealedStore & { slots: Map<string, any> } {
  const slots = new Map<string, any>();
  return {
    slots,
    async getSecret(slot) { return slots.get(slot); },
    async saveSecret(slot, secret, meta) { slots.set(slot, { secret, meta }); },
    async deleteSecret(slot) { slots.delete(slot); },
  };
}

describe('端末に残す秘密の扱い (H4)', () => {
  beforeAll(async () => {
    await sodiumReady;
  });

  it('既定 (ephemeral) ではノード鍵を保存せず、起動ごとに別の peerId になる', async () => {
    const store = memoryStore();
    const a = await NodeIdentityStore.mineEphemeral(store, FAST);
    const b = await NodeIdentityStore.mineEphemeral(store, FAST);
    expect(a.peerId).not.toBe(b.peerId);
    expect(store.slots.size).toBe(0);
  });

  it('保存済みの鍵は ephemeral 起動でも消さない (旧形式の行はアンロック時に store が DEK 配下へ移す)', async () => {
    const store = memoryStore();
    await store.saveSecret('node', new Uint8Array(96), { powCounter: 0 });
    await NodeIdentityStore.mineEphemeral(store, FAST);
    expect(store.slots.has('node')).toBe(true);
  });

  it('永続化にはパスフレーズが必須で、保存済みなら同じ peerId に戻る', async () => {
    const store = memoryStore();
    await expect(NodeIdentityStore.loadOrMine(store, '', FAST)).rejects.toThrow(RangeError);

    const first = await NodeIdentityStore.loadOrMine(store, 'correct horse', FAST);
    expect(store.slots.get('node').secret).toHaveLength(96);
    const again = await NodeIdentityStore.loadOrMine(store, 'correct horse', FAST);
    expect(again.peerId).toBe(first.peerId);
  });

  it('トリップは生成すると秘密がそのまま store に渡る (封印は store 側の DEK)', async () => {
    const store = memoryStore();
    const id = new Identity();
    await id.generateTrip(store);
    expect(store.slots.get('trip').secret).toHaveLength(96);
  });
});

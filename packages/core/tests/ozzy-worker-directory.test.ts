import { describe, it, expect, beforeAll } from 'vitest';
import { sodiumReady } from '../src/crypto/sodium';

/**
 * 中継 Worker (packages/r2-worker/worker.js) の Durable Object と入口を直接呼んで、
 *   - 共通の Lease のディレクトリは廃止されていること (置き場所は Manifest に入れ、Manifest は P2P に置く)
 *   - IAS3 互換の Slab は、置いた本人の資格情報でしか上書き・削除できないこと
 * を確かめる (KV なし・メモリだけの状態)。
 */
let SlabVaultDO: any;
let workerEntry: any;
beforeAll(async () => {
  await sodiumReady;
  const workerPath = new URL('../../r2-worker/worker.js', import.meta.url).href;
  const mod = await import(/* @vite-ignore */ workerPath);
  SlabVaultDO = mod.OzzySlabVaultDO;
  workerEntry = mod.default;
});

const BASE = 'https://ozzy-relay.test';

describe('中継 Worker: 共通の Lease のディレクトリは無い', () => {
  it('★/ozzy/v2/leaseset は読み書きとも 410 (誰が何をいつ出し入れしたかを共通のサーバーに残さない)', async () => {
    const id = 'ab'.repeat(16);
    const vault = new SlabVaultDO({}, {});
    for (const method of ['GET', 'POST']) {
      const init: RequestInit = method === 'POST' ? { method, body: JSON.stringify({ leaseBase64: 'AAAA' }) } : { method };
      expect((await vault.fetch(new Request(`${BASE}/ozzy/v2/leaseset/${id}`, init))).status).toBe(410);
      if (workerEntry?.fetch) {
        const res = await workerEntry.fetch(new Request(`${BASE}/ozzy/v2/leaseset/${id}`, init), {}, { waitUntil() {} });
        expect(res.status).toBe(410);
      }
    }
  });
});

describe('中継 Worker: IAS3 互換の Slab', () => {
  const put = (vault: any, auth: string, body: Uint8Array) => vault.fetch(new Request(`${BASE}/ias3/item/slab_a.bin`, {
    method: 'PUT', headers: { Authorization: auth, 'x-archive-queue-derive': '0', 'x-archive-meta-noindex': 'true' }, body: body as Uint8Array<ArrayBuffer>,
  }));
  const del = (vault: any, auth: string) => vault.fetch(new Request(`${BASE}/ias3/item/slab_a.bin`, { method: 'DELETE', headers: { Authorization: auth } }));
  const get = (vault: any) => vault.fetch(new Request(`${BASE}/download/item/slab_a.bin`, { headers: { Range: 'bytes=0-3' } }));

  it('★置いた本人の資格情報でしか上書き・削除できない (旧版は LOW で始まれば誰でも消せた)', async () => {
    const vault = new SlabVaultDO({}, {});
    expect((await put(vault, 'LOW owner:secret', new Uint8Array([1, 2, 3, 4, 5]))).status).toBe(200);
    expect((await put(vault, 'LOW attacker:x', new Uint8Array([9, 9, 9, 9]))).status).toBe(403);
    expect((await del(vault, 'LOW attacker:x')).status).toBe(403);
    const r = await get(vault);
    expect(r.status).toBe(206);
    expect(Array.from(new Uint8Array(await r.arrayBuffer()))).toEqual([1, 2, 3, 4]);
    expect((await del(vault, 'LOW owner:secret')).status).toBe(204);
    expect((await get(vault)).status).toBe(404);
  });
});

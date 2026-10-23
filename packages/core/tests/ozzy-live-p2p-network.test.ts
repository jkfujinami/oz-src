import { describe, expect, it } from 'vitest';
import { sodiumReady } from '../src/crypto/sodium';
import { checkOzzyWorker, normalizeOzzyWorkerUrl } from '../src/ozzy';

/**
 * 実機の中継 Worker (各自が packages/r2-worker をデプロイしたもの) を叩く試験。
 *   OZZY_LIVE_WORKER=https://ozzy.<あなた>.workers.dev npx vitest run tests/ozzy-live-p2p-network.test.ts
 *
 * ★ 旧版はみんなで 1 つの Worker (Lease のディレクトリ・IAS3 互換の置き場所) を使う前提だった。今は
 *   - Worker は各自の中継 (/ozzy/v2/locker-proxy) だけ。中継には交換で集めた他人の Worker を使う
 *   - 置き場所は Manifest v4 に入れ、Manifest は P2P のファイル保管に置く (共通のディレクトリは無い)
 *   - アップロードもオニオン回路の M1 に頼む (OnionLockers)
 */
const LIVE = process.env.OZZY_LIVE_WORKER ?? '';

describe.skipIf(!LIVE)('Ozzy: 実機の中継 Worker', () => {
  it('中継として応え、共通の Lease のディレクトリは持たない', async () => {
    await sodiumReady;
    const base = normalizeOzzyWorkerUrl(LIVE);
    expect(base, 'OZZY_LIVE_WORKER must be https://<name>.<account>.workers.dev').not.toBeNull();
    expect(await checkOzzyWorker(base!)).toEqual({ ok: true });
    const res = await fetch(`${base}/ozzy/v2/leaseset/${'ab'.repeat(16)}`, { cache: 'no-store' });
    expect(res.status).toBe(410);
  }, 30_000);

  it('許可リスト外のホストへは中継しない', async () => {
    const base = normalizeOzzyWorkerUrl(LIVE)!;
    const res = await fetch(`${base}/ozzy/v2/locker-proxy`, {
      method: 'POST',
      headers: { 'X-Ozzy-Target-Url': 'https://example.com/', 'X-Ozzy-Target-Method': 'GET' },
    });
    expect(res.status).toBe(403);
  }, 30_000);
});

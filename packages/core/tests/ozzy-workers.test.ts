import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import 'fake-indexeddb/auto';
import { sodiumReady } from '../src/crypto/sodium';
import { NodeIdentity, ozzyWorkerAdMessage } from '../src/crypto/NodeIdentity';
import { WireType } from '../src/network/wire/WireTypes';
import { WireCodec } from '../src/network/wire/WireCodec';
import { OzNode } from '../src/node/OzNode';
import { IndexedDBStore } from '../src/storage/IndexedDBStore';
import { VAULT_PARAMS_FAST } from '../src/storage/SecretVault';
import { createSimNode, link, announceVerified, stopAll, sleep, FAST_POW, type SimNode } from './helpers/onionNet';
import {
  OzzyWorkerPool,
  createPooledRelayTransport,
  normalizeOzzyWorkerUrl,
  OZZY_MESH_STATUS,
  decodeRangeResponse,
  encodeRangeRequest,
} from '../src/ozzy';

/**
 * Ozzy の中継 Worker: 全員が自分の Worker を設定し、広告を PEX のように交換し、中継には他人の Worker を使う。
 */
beforeAll(async () => { await sodiumReady; });

let nodes: SimNode[] = [];
const pools: OzzyWorkerPool[] = [];
afterEach(() => {
  for (const p of pools.splice(0)) p.destroy();
  stopAll(nodes);
  nodes = [];
});

const poolFor = (n: SimNode) => {
  const p = new OzzyWorkerPool(n.peerManager, n.dispatcher, n.identity, { powParams: FAST_POW, exchangeIntervalMs: 20 });
  pools.push(p);
  return p;
};

describe('Worker の URL', () => {
  it('workers.dev の https の起点だけを受け付ける', () => {
    expect(normalizeOzzyWorkerUrl('https://ozzy.alice-7f.workers.dev/')).toBe('https://ozzy.alice-7f.workers.dev');
    expect(normalizeOzzyWorkerUrl('HTTPS://Ozzy.Alice.workers.dev')).toBe('https://ozzy.alice.workers.dev');
    for (const bad of [
      'http://ozzy.alice.workers.dev',
      'https://attacker.example',
      'https://ozzy.alice.workers.dev.attacker.example',
      'https://ozzy.alice.workers.dev:8443',
      'https://ozzy.alice.workers.dev/ozzy/v2/status',
      'https://ozzy.alice.workers.dev/?x=1',
      'https://workers.dev',
      'https://127.0.0.1',
    ]) expect(normalizeOzzyWorkerUrl(bad), bad).toBeNull();
  });
});

describe('Worker の広告の交換 (PEX と同じ要領)', () => {
  it('★隣人の隣人の Worker まで広告が届き、中継には自分以外の Worker を選ぶ', async () => {
    const a = await createSimNode('a');
    const b = await createSimNode('b');
    const c = await createSimNode('c');
    nodes = [a, b, c];
    link(a, b);
    link(b, c);
    const [pa, pb, pc] = [poolFor(a), poolFor(b), poolFor(c)];
    pa.setOwn('https://ozzy.a.workers.dev');
    pb.setOwn('https://ozzy.b.workers.dev');
    pc.setOwn('https://ozzy.c.workers.dev');
    expect(pa.pickRelay()).toBe('https://ozzy.a.workers.dev'); // まだ他人を知らない: 自分の Worker
    for (const p of [pa, pb, pc]) p.start();
    announceVerified(a, b);
    announceVerified(b, c);
    const end = Date.now() + 3000;
    while ((pa.size < 2 || pc.size < 2) && Date.now() < end) await sleep(20);
    expect(pa.size).toBe(2); // b と c (c の広告は b 経由)
    expect(pc.size).toBe(2);
    for (let i = 0; i < 50; i++) expect(pa.pickRelay()).not.toBe('https://ozzy.a.workers.dev');

    // 失敗を報告した Worker はしばらく選ばない
    pa.reportFailure('https://ozzy.b.workers.dev');
    for (let i = 0; i < 30; i++) expect(pa.pickRelay()).toBe('https://ozzy.c.workers.dev');
  });

  it('★署名が合わない・身元の PoW が無い・期限切れ・workers.dev でない広告は捨てる', async () => {
    const a = await createSimNode('a');
    nodes = [a];
    const pa = poolFor(a);
    const id = await NodeIdentity.mine(FAST_POW);
    const nowMin = Math.floor(Date.now() / 60_000);
    const good = (url: string, expiresMin = nowMin + 60) => ({
      pubkey: id.pubkey, powCounter: id.powCounter, expiresMin, url, signature: id.signOzzyWorkerAd(url, expiresMin),
    });
    const deliver = (ads: unknown[]) => (a.dispatcher as any).dispatch('f'.repeat(32), WireType.OZZY_WORKER_ADS, { ads });

    deliver([{ ...good('https://ozzy.x.workers.dev'), url: 'https://ozzy.y.workers.dev' }]); // URL を差し替え
    deliver([good('https://ozzy.x.workers.dev', nowMin - 1)]); // 期限切れ
    deliver([good('https://ozzy.x.workers.dev', nowMin + 60 * 24 * 30)]); // 期限が遠すぎる
    expect(pa.size).toBe(0);
    // workers.dev 以外は署名が正しくても捨てる (形が違えば WireCodec を通る前に弾かれるが、ここでは直接渡す)
    const sig = id.signOzzyWorkerAd('https://attacker.example', nowMin + 60);
    deliver([{ pubkey: id.pubkey, powCounter: id.powCounter, expiresMin: nowMin + 60, url: 'https://attacker.example', signature: sig }]);
    expect(pa.size).toBe(0);
    deliver([good('https://ozzy.x.workers.dev')]);
    expect(pa.size).toBe(1);
    // 同じ身元は Worker を 1 つしか持てない (新しい広告が古い広告を置き換える)
    deliver([good('https://ozzy.z.workers.dev', nowMin + 120)]);
    expect(pa.size).toBe(1);
    expect(pa.pickRelay()).toBe('https://ozzy.z.workers.dev');
    expect(pa.stats.rejected).toBeGreaterThanOrEqual(4);
    // 署名対象は URL と期限と鍵に縛られている
    expect(ozzyWorkerAdMessage(id.pubkey, 'https://ozzy.x.workers.dev', 1).length).toBeGreaterThan(0);
  });

  it('★身元の PoW が足りない鍵の広告は捨てる (身元を大量に作って広告で網を埋めるのを高くつかせる)', async () => {
    const a = await createSimNode('a');
    nodes = [a];
    const strict = new OzzyWorkerPool(a.peerManager, a.dispatcher, a.identity, { powParams: { difficulty: 16, opsLimit: 1, memLimit: 8192 } });
    pools.push(strict);
    const cheap = await NodeIdentity.mine(FAST_POW); // PoW を解いていない身元
    const expiresMin = Math.floor(Date.now() / 60_000) + 60;
    const url = 'https://ozzy.cheap.workers.dev';
    (a.dispatcher as any).dispatch('f'.repeat(32), WireType.OZZY_WORKER_ADS, {
      ads: [{ pubkey: cheap.pubkey, powCounter: cheap.powCounter, expiresMin, url, signature: cheap.signOzzyWorkerAd(url, expiresMin) }],
    });
    expect(strict.size).toBe(0);
    expect(strict.stats.rejected).toBe(1);
  });

  it('広告は WireCodec を往復する', async () => {
    const id = await NodeIdentity.mine(FAST_POW);
    const ad = { pubkey: id.pubkey, powCounter: id.powCounter, expiresMin: 123456, url: 'https://ozzy.q.workers.dev', signature: id.signOzzyWorkerAd('https://ozzy.q.workers.dev', 123456) };
    const dec = WireCodec.decode(WireCodec.encode(WireType.OZZY_WORKER_ADS, { ads: [ad, ad] }));
    expect(dec.type).toBe(WireType.OZZY_WORKER_ADS);
    expect(dec.payload.ads[1]).toMatchObject({ url: ad.url, expiresMin: 123456, powCounter: id.powCounter });
  });
});

describe('他人の Worker を中継に使う (createPooledRelayTransport)', () => {
  it('★中継として応えない Worker は報告して別の Worker で取り直し、ロッカーへは中継経由でしか行かない', async () => {
    const seen: string[] = [];
    const failures: string[] = [];
    let i = 0;
    const order = ['https://ozzy.bad.workers.dev', 'https://ozzy.good.workers.dev'];
    const inner = async (req: Request) => {
      seen.push(req.url);
      if (req.url.startsWith('https://ozzy.bad.workers.dev')) return new Response('not found', { status: 404 });
      expect(req.headers.get('X-Ozzy-Target-Url')).toBe('https://files.catbox.moe/a.bin');
      return new Response(new Uint8Array([1, 2, 3]), { status: 206, headers: { 'X-Ozzy-Proxied-Status': '206' } });
    };
    const t = createPooledRelayTransport(() => order[Math.min(i++, 1)], (u) => failures.push(u), inner);
    const res = await t(new Request('https://files.catbox.moe/a.bin', { headers: { Range: 'bytes=0-2' } }));
    expect(res.status).toBe(206);
    expect(failures).toEqual(['https://ozzy.bad.workers.dev']);
    expect(seen.every(u => u.endsWith('/ozzy/v2/locker-proxy'))).toBe(true); // ロッカーへ直接は 1 度も行っていない
  });

  it('中継が 1 つも無ければ例外 (生 IP で直接ロッカーへ行かない)', async () => {
    const t = createPooledRelayTransport(() => null, () => undefined, async () => { throw new Error('must not fetch'); });
    await expect(t(new Request('https://files.catbox.moe/a.bin'))).rejects.toThrow(/no ozzy relay/);
  });
});

describe('OzNode: 自分の Worker を設定するまで Ozzy は使えない', () => {
  it('★未設定なら M1 の役は REFUSED を返し、設定すると取得役として動き、設定は暗号化 DB に残る', async () => {
    const db = new IndexedDBStore('OzzyWorkerGate_' + Date.now());
    await db.init();
    const node = await OzNode.create({
      storage: { slotEffort: 1, chunkEffort: 1 }, db, autoStart: false, passphrase: 'test-passphrase', vaultParams: VAULT_PARAMS_FAST,
    });
    try {
      expect(node.ozzyReady).toBe(false);
      expect(node.ozzyExit.serving).toBe(false);
      expect(await node.setOzzyWorker('https://attacker.example', async () => ({ ok: true }))).toEqual({ ok: false, reason: 'bad-url' });
      expect(await node.setOzzyWorker('https://ozzy.me.workers.dev', async () => ({ ok: false, reason: 'not-ozzy' }))).toEqual({ ok: false, reason: 'not-ozzy' });
      expect(node.ozzyReady).toBe(false);
      expect(await node.setOzzyWorker('https://ozzy.me.workers.dev/', async () => ({ ok: true }))).toEqual({ ok: true });
      expect(node.ozzyReady).toBe(true);
      expect(node.ozzyWorkerUrl).toBe('https://ozzy.me.workers.dev');
      expect(node.ozzyExit.serving).toBe(true);
      expect(await db.getSetting('ozzy.workerUrl')).toBe('https://ozzy.me.workers.dev');
      await node.setOzzyWorker(null);
      expect(node.ozzyReady).toBe(false);
      expect(node.ozzyExit.serving).toBe(false);
    } finally {
      await node.stop();
    }
    void OZZY_MESH_STATUS; void decodeRangeResponse; void encodeRangeRequest;
  }, 60_000);
});

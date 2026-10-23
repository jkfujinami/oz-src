import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { sodiumReady } from '../../src/crypto/sodium';
import { Encoding } from '../../src/common/Encoding';
import { WireType } from '../../src/network/wire/WireTypes';
import { TUNNEL_ERROR_CODE } from '../../src/network/wire/WireCodec';
import { FileUploader, type UploadProgress } from '../../src/files/FileUploader';
import { FileDownloader, parseLinkToken, type DownloadProgress } from '../../src/files/FileDownloader';
import { FileTransferError } from '../../src/files/FileTransfer';
import { idOf } from '../../src/files/FileFormat';
import { R_FILE, R_MIN_OK, CHUNK_STATUS, type ChunkStatus } from '../../src/network/storage/ChunkProtocol';
import { stopAll } from '../helpers/onionNet';
import { stopStorage, rawDump, latin1 } from '../helpers/storageNet';
import { stopTunnel, until } from '../helpers/tunnelNet';
import { disconnectNodes } from '../helpers/onionNet';
import {
  buildFileNet, concatBytes, dutyChunk, hasSubarray, peerIdRaw, randBytes, rawPut, rowCounts, LOOSE_CLIENT_SEND, TEST_CHUNK_EFFORT,
  type FileNet,
} from '../helpers/fileNet';
import { fakeLeaseSet } from '../helpers/storageNet';
import { solveChunkPowSync } from '../../src/network/storage/ChunkPow';

/**
 * 大容量ファイル (C2 + C4): 複数ノードの上での端から端まで。本物の PeerManager・WireCodec・TunnelRelay・TunnelHolder・
 * StorageService (暗号化 DB + HolderStore + ChunkStore)・FileUploader・FileDownloader を通す。
 *
 *      u ─┐                    ┌─ d          u = 上げる側 (g1 の後ろ)、d = 取る側 (g2 の後ろ)。どちらも保持者ではない
 *   h1x ──┤ g1 ═══(backbone)═══ g2 ├── h2x   g1・g2 = 信頼 Guard、h = 保持者 8 台 (leaseSet を出して受け口に登録済み)
 */
beforeAll(async () => { await sodiumReady; });

let net: FileNet | null = null;
afterEach(async () => {
  if (!net) return;
  stopTunnel(net.all);
  await stopStorage(net.all);
  stopAll(net.all);
  net = null;
});

const sum = (xs: number[]) => xs.reduce((a, b) => a + b, 0);

describe('アップロード → ダウンロード (3MiB, 別の Guard の後ろ)', () => {
  it('★往復: 別の Guard の後ろの端末から取って、バイト列が一致。全チャンクが R_MIN_OK 以上の複製を持つ', async () => {
    net = await buildFileNet();
    const { u, d, holders } = net;
    const data = randBytes(3 * 1024 * 1024 + 123);
    const before = { u: await rowCounts(u.dbName), d: await rowCounts(d.dbName) };

    const ups: UploadProgress[] = [];
    const t0 = performance.now();
    const up = new FileUploader(net.uploaderParts(), data, { name: 'secret.bin', mime: 'application/octet-stream' }, p => ups.push(p)).start();
    const token = await up.link;
    const uploadMs = performance.now() - t0;
    expect(token).toMatch(/^\[\[file:[A-Za-z0-9_-]{74}\]\]$/);

    // 進み具合: 単調に増え、最後は done で全部置けている (チャンク 13 個 = 3MiB / 256KiB の切り上げ)
    expect(ups.length).toBeGreaterThan(5);
    for (let i = 1; i < ups.length; i++) expect(ups[i].bytesPlaced).toBeGreaterThanOrEqual(ups[i - 1].bytesPlaced);
    expect(ups.at(-1)).toMatchObject({ phase: 'done', bytesPlaced: data.length, totalBytes: data.length, chunksPlaced: 13 });
    expect(ups.some(p => p.phase === 'chunks')).toBe(true);
    expect(ups.some(p => p.phase === 'manifest')).toBe(true);

    const dls: DownloadProgress[] = [];
    const t1 = performance.now();
    const dl = new FileDownloader(net.downloaderParts(), token, p => dls.push(p));
    const pieces: Uint8Array[] = [];
    for await (const piece of dl) pieces.push(piece);
    const downloadMs = performance.now() - t1;
    const got = concatBytes(pieces);
    expect(Buffer.from(got).equals(Buffer.from(data))).toBe(true);
    const mf = await dl.manifest;
    expect(mf).toMatchObject({ name: 'secret.bin', mime: 'application/octet-stream', size: data.length });
    expect(dls.at(-1)).toMatchObject({ phase: 'done', bytesDone: data.length, chunksDone: 13, chunkCount: 13 });
    console.log(`[files] 3MiB: upload ${(uploadMs / 1000).toFixed(1)}s (chunk 13 + manifest × ${R_FILE} 複製)、download ${(downloadMs / 1000).toFixed(1)}s`);

    // 複製の数: 全チャンク (Manifest も) が 3〜5 台の保持者にある
    const link = parseLinkToken(token)!;
    const ids = [link.manifestId, ...mf.chunkIds];
    const counts = ids.map(id => holders.filter(h => h.storage.chunks!.has(id)).length);
    for (const c of counts) {
      expect(c).toBeGreaterThanOrEqual(R_MIN_OK);
      expect(c).toBeLessThanOrEqual(R_FILE);
    }
    console.log(`[files] 複製の数 (14 個のチャンク): ${counts.join(',')}`);

    // ★上げた側・取った側のディスクには何も書かれない (どのストアの行数も変わらない)。平文・暗号文・鍵・チャンク ID も現れない
    expect(await rowCounts(u.dbName)).toEqual(before.u);
    expect(await rowCounts(d.dbName)).toEqual(before.d);
    for (const node of [u, d]) {
      const dump = await rawDump(node.dbName);
      expect(dump.includes(latin1(link.key))).toBe(false);
      expect(dump.includes(latin1(link.manifestId))).toBe(false);
      expect(dump.includes(latin1(mf.chunkIds[0]))).toBe(false);
      expect(dump.includes(latin1(data.subarray(1_000_000, 1_000_032)))).toBe(false);
    }
    expect(u.storage.chunks!.count).toBe(0); // 上げた端末は自分ではチャンクを預からない・配らない
    // 保持者のディスクにも、平文・チャンク ID・鍵は現れない (封印されている)
    for (const h of holders) {
      const dump = await rawDump(h.dbName);
      expect(dump.includes(latin1(link.key))).toBe(false);
      expect(dump.includes(latin1(mf.chunkIds[0]))).toBe(false);
      expect(dump.includes(latin1(data.subarray(1_000_000, 1_000_032)))).toBe(false);
    }
  }, 120_000);

  it('★上げた側の peerId は保持者にも、保持者側の Guard (g2) にも渡らない。保持者に見えるのは Guard だけ', async () => {
    net = await buildFileNet();
    const { u, d, g1, g2, holders } = net;
    const data = randBytes(600 * 1024);
    const token = await new FileUploader(net.uploaderParts(), data, { name: 'a', mime: 'text/plain' }).start().link;
    for await (const _ of new FileDownloader(net.downloaderParts(), token)) void _;

    const guardIds = new Set([g1.identity.peerId, g2.identity.peerId]);
    const uRaw = peerIdRaw(u.identity.peerId);
    const dRaw = peerIdRaw(d.identity.peerId);
    let delivers = 0;
    for (const h of holders) {
      for (const m of h.inbox) {
        // 保持者に届いた全フレームのどこにも、上げた側・取った側の peerId (16 バイト) は現れない
        expect(hasSubarray(m.raw, uRaw), 'u peerId in a frame to a holder').toBe(false);
        expect(hasSubarray(m.raw, dRaw), 'd peerId in a frame to a holder').toBe(false);
        if (m.type === WireType.TUNNEL_DELIVER) {
          delivers++;
          expect(guardIds.has(m.payload.fromHop)).toBe(true); // 返しのホップ = Guard だけ
        }
      }
    }
    expect(delivers).toBeGreaterThan(30);
    // 経路上の全ノード (Guard・保持者) が受け取った全フレームのどこにも、ファイルの鍵 K_f もチャンク ID (Manifest ID) も平文では現れない
    const link = parseLinkToken(token)!;
    for (const n of net.all) {
      for (const m of n.inbox) {
        expect(hasSubarray(m.raw, link.key), 'K_f in a frame').toBe(false);
        expect(hasSubarray(m.raw, link.manifestId), 'manifest id in a frame').toBe(false);
        expect(hasSubarray(m.raw, data.subarray(300_000, 300_032)), 'plaintext in a frame').toBe(false);
      }
    }
    // g2 (保持者側の Guard) が g1 から受け取ったバックボーンのフレームにも、u / d の peerId は無い
    for (const m of g2.inbox.filter(m => m.from === g1.identity.peerId)) {
      expect(hasSubarray(m.raw, uRaw)).toBe(false);
      expect(hasSubarray(m.raw, dRaw)).toBe(false);
    }
    // 他の保持者の間でも、保持者同士のやり取りは無い (保持者は上げる側にも取る側にも接続されていない)
    for (const h of holders) {
      const from = new Set(h.inbox.filter(m => m.type === WireType.TUNNEL_DELIVER).map(m => m.from));
      for (const f of from) expect(guardIds.has(f)).toBe(true);
    }
  }, 120_000);

  it('★リンクは全チャンクを置き終えてから: 一時停止中は解決せず何も置かれない。再開すると置いて解決する', async () => {
    net = await buildFileNet();
    const data = randBytes(1024 * 1024);
    const up = new FileUploader(net.uploaderParts(), data, { name: 'p', mime: 'text/plain' });
    up.start();
    up.pause();
    let resolved = false;
    up.link.then(() => { resolved = true; });
    await new Promise(r => setTimeout(r, 400));
    expect(resolved).toBe(false);
    expect(sum(net.holders.map(h => h.storage.chunks!.count))).toBe(0);
    expect(up.paused).toBe(true);
    up.resume();
    const token = await up.link;
    expect(parseLinkToken(token)).not.toBeNull();
    // 全部置けてから初めてリンクが出た
    const link = parseLinkToken(token)!;
    expect(net.holders.filter(h => h.storage.chunks!.has(link.manifestId)).length).toBeGreaterThanOrEqual(R_MIN_OK);
  }, 60_000);

  it('★中止: link は cancelled で拒否される。以後は何も置かれない', async () => {
    net = await buildFileNet();
    const data = randBytes(3 * 1024 * 1024);
    const progress: UploadProgress[] = [];
    const up = new FileUploader(net.uploaderParts(), data, { name: 'c', mime: 'text/plain' }, p => progress.push(p)).start();
    await until(() => progress.length >= 1, 20_000, 'first chunk placed');
    up.cancel();
    await expect(up.link).rejects.toMatchObject({ code: 'cancelled' });
    await new Promise(r => setTimeout(r, 300)); // 途中の要求が落ち着くのを待つ
    const placed = sum(net.holders.map(h => h.storage.chunks!.count));
    await new Promise(r => setTimeout(r, 500));
    expect(sum(net.holders.map(h => h.storage.chunks!.count))).toBe(placed);
    expect(placed).toBeLessThan(14 * R_FILE); // 全部は置かれていない
  }, 60_000);
});

/** 読み手 dl が Manifest を最初に頼む保持者 (近さの束の先頭)。必ず Manifest の複製を持っている */
function firstHolderOf(dl: FileDownloader, manifestId: Uint8Array) {
  const first = (dl as any).reader.order(manifestId)[0] as { sid: string };
  return net!.holders.find(h => h.sid === first.sid)!;
}

describe('取得: 偽物・保持者の脱落', () => {
  async function uploaded(bytes = 1024 * 1024) {
    const n = net!;
    const data = randBytes(bytes);
    const token = await new FileUploader(n.uploaderParts(), data, { name: 'f.bin', mime: 'application/octet-stream' }).start().link;
    const link = parseLinkToken(token)!;
    return { data, token, link };
  }

  it('★改ざんしたチャンクを返す悪意の保持者は弾かれ、別の保持者から取り直す (偽物を返した保持者は後回しになる)', async () => {
    net = await buildFileNet();
    const { data, token, link } = await uploaded();
    const dl = new FileDownloader(net.downloaderParts(), token);
    // 全チャンクの置き先 (複製を持つ保持者) のうち 1 台を悪意にする: 取得のたびに別の中身を返す
    const evil = firstHolderOf(dl, link.manifestId);
    const store = evil.storage.chunks!;
    const realGet = store.get.bind(store);
    let served = 0;
    store.get = async (id: Uint8Array) => {
      const real = await realGet(id);
      if (!real) return real;
      served++;
      const bad = real.slice();
      bad[bad.length >> 1] ^= 0x55; // 1 ビット相当の改ざん
      return bad;
    };
    // この保持者を一番先に試す (速い保持者として記録しておく)
    (dl as any).reader.recordSpeed(evil.sid, 1);
    const pieces: Uint8Array[] = [];
    for await (const p of dl) pieces.push(p);
    expect(Buffer.from(concatBytes(pieces)).equals(Buffer.from(data))).toBe(true);
    expect(served).toBeGreaterThanOrEqual(1);
    expect(dl.readerStats.rejected).toBeGreaterThanOrEqual(1); // 偽物を捨てた
    expect(dl.speedOf(evil.sid)).toBeGreaterThanOrEqual(30_000); // 罰の値 (後回し)
  }, 90_000);

  it('★偽の Manifest (ID は合うが復号できない・別のファイルの Manifest) を返す保持者は弾かれる', async () => {
    net = await buildFileNet();
    const { data, token, link } = await uploaded(300 * 1024);
    const dl = new FileDownloader(net.downloaderParts(), token);
    const evil = firstHolderOf(dl, link.manifestId);
    const store = evil.storage.chunks!;
    const realGet = store.get.bind(store);
    store.get = async (id: Uint8Array) => {
      const real = await realGet(id);
      return real ? randBytes(real.length) : real; // 長さだけ同じ乱数
    };
    (dl as any).reader.recordSpeed(evil.sid, 1);
    const pieces: Uint8Array[] = [];
    for await (const p of dl) pieces.push(p);
    expect(Buffer.from(concatBytes(pieces)).equals(Buffer.from(data))).toBe(true);
    expect(dl.readerStats.rejected).toBeGreaterThanOrEqual(1);
  }, 60_000);

  it('★保持者が取得の途中で落ちる (Guard との接続が切れる): 別の複製へ回って最後まで取れる', async () => {
    net = await buildFileNet();
    const { data, token } = await uploaded(2 * 1024 * 1024);
    const dl = new FileDownloader(net.downloaderParts({ downloadLimits: { window: 3 } }), token);
    const pieces: Uint8Array[] = [];
    const n = net;
    const guardOf = (h: (typeof n.holders)[number]) => (n.holders.indexOf(h) < 4 ? n.g1 : n.g2);
    let killed = false;
    for await (const p of dl) {
      pieces.push(p);
      if (pieces.length === 2 && !killed) {
        killed = true;
        // 両側の Guard の後ろの保持者を 1 台ずつ落とす (読み手が既に速さを覚えている保持者の可能性が高い)
        for (const h of [n.holders[0], n.holders[5]]) {
          h.storage.tunnel!.destroy();
          disconnectNodes(h, guardOf(h));
        }
      }
    }
    expect(killed).toBe(true);
    expect(Buffer.from(concatBytes(pieces)).equals(Buffer.from(data))).toBe(true);
  }, 90_000);

  it('★遅い保持者 (応答が来ない) には HEDGE_MS 後に別の複製へも頼む (hedged)。先に返った方を使う', async () => {
    net = await buildFileNet();
    const { data, token, link } = await uploaded(512 * 1024);
    // マニフェストの置き先のうち、先頭に試される 1 台を黙らせる (永久に応答しない)
    const dl = new FileDownloader(net.downloaderParts({ limits: { hedgeMs: 150, inactivityMs: 10_000 } }), token);
    const slow = firstHolderOf(dl, link.manifestId);
    slow.storage.chunks!.get = () => new Promise<Uint8Array | null>(() => undefined);
    (dl as any).reader.recordSpeed(slow.sid, 1);
    const t0 = performance.now();
    const pieces: Uint8Array[] = [];
    for await (const p of dl) pieces.push(p);
    expect(Buffer.from(concatBytes(pieces)).equals(Buffer.from(data))).toBe(true);
    expect(dl.readerStats.hedges).toBeGreaterThanOrEqual(1);
    expect(performance.now() - t0).toBeLessThan(8000); // inactivity (10 秒) を待たずに済んだ
  }, 60_000);

  it('取得の中止: cancel すると iterator が cancelled で終わる。リンクが不正なら bad-link', async () => {
    net = await buildFileNet();
    const { token } = await uploaded(1024 * 1024);
    const dl = new FileDownloader(net.downloaderParts(), token);
    const it = dl[Symbol.asyncIterator]();
    await it.next();
    dl.cancel();
    await expect(it.next()).rejects.toMatchObject({ code: 'cancelled' });

    const bad = new FileDownloader(net.downloaderParts(), '[[file:xyz]]');
    await expect((async () => { for await (const _ of bad) void _; })()).rejects.toMatchObject({ code: 'bad-link' });
    await expect(bad.manifest).rejects.toBeInstanceOf(FileTransferError);
  }, 60_000);

  it('どの保持者も持っていないファイル: unavailable (manifest)', async () => {
    net = await buildFileNet();
    const { token } = await uploaded(300 * 1024);
    // 別のファイルのリンク (置いていない)
    const other = parseLinkToken(token)!;
    other.manifestId = randBytes(16);
    const { formatFileLink } = await import('../../src/files/FileLink');
    const dl = new FileDownloader(net.downloaderParts({ limits: { hedgeMs: 100, roundDelayMs: 20 } }), formatFileLink(other));
    await expect((async () => { for await (const _ of dl) void _; })()).rejects.toMatchObject({ code: 'unavailable' });
  }, 60_000);
});

describe('保持者の受け入れ検査 (PUT_CHUNK)', () => {
  it('★有効な PoW・担当・ハッシュなら預かる。同じチャンクの再送は冪等 (STORED)', async () => {
    net = await buildFileNet();
    const { u, holders } = net;
    const h = holders[0];
    const { data, id } = dutyChunk(h, 40_000); // 3 断片
    const r1 = await rawPut(u, h, id, data);
    expect(r1).toEqual([CHUNK_STATUS.OK, CHUNK_STATUS.OK, CHUNK_STATUS.STORED]);
    expect(h.storage.chunks!.has(id)).toBe(true);
    expect(await rawPut(u, h, id, data)).toEqual([CHUNK_STATUS.STORED, CHUNK_STATUS.STORED, CHUNK_STATUS.STORED]);
    expect(h.storage.chunks!.count).toBe(1);
  }, 30_000);

  it('★PoW が不正: BAD_POW。最初の断片で断るのでバッファを取らず、何も預からない', async () => {
    net = await buildFileNet();
    const { u, holders } = net;
    const h = holders[1];
    const data = randBytes(40_000);
    const id = idOf(data);
    const r = await rawPut(u, h, id, data, { nonce: 1, solution: new Uint8Array(16) });
    expect(r[0]).toBe(CHUNK_STATUS.BAD_POW);
    expect(h.storage.chunks!.has(id)).toBe(false);
    expect(h.storage.tunnel!.stats.chunks.rejected.pow).toBeGreaterThanOrEqual(1);
    // 別のチャンクの PoW の使い回しも不可 (PoW はチャンク ID に結び付く)
    const other = solveChunkPowSync(idOf(randBytes(100)), TEST_CHUNK_EFFORT)!;
    expect((await rawPut(u, h, id, data, other))[0]).toBe(CHUNK_STATUS.BAD_POW);
  }, 30_000);

  it('★担当の外: NOT_DUTY。複製の位置に近い 3 枠に自分の枠が無いチャンクは預からない (密な環で)', async () => {
    net = await buildFileNet();
    const { u, holders } = net;
    const h = holders[2];
    // 環を密にする (他に 300 枠が居るように見せる)。h の見え方だけが変わる
    for (let i = 1; i <= 300; i++) h.storage.leaseSets.add(fakeLeaseSet(i, 1));
    let data: Uint8Array;
    let id: Uint8Array;
    do {
      data = randBytes(500);
      id = idOf(data);
    } while (h.storage.duty.shouldStoreChunk(id));
    const r = await rawPut(u, h, id, data);
    expect(r).toEqual([CHUNK_STATUS.NOT_DUTY]);
    expect(h.storage.chunks!.has(id)).toBe(false);
    expect(h.storage.tunnel!.stats.chunks.rejected.duty).toBe(1);
  }, 30_000);

  it('★ハッシュが合わない (別のデータ): BAD_ID。預からない。断片の数が食い違う・大きすぎるのは BAD_REQUEST', async () => {
    net = await buildFileNet();
    const { u, holders } = net;
    const h = holders[3];
    const { id } = dutyChunk(h, 40_000);
    const fake = randBytes(40_000);
    const r = await rawPut(u, h, id, fake);
    expect(r.at(-1)).toBe(CHUNK_STATUS.BAD_ID);
    expect(h.storage.chunks!.has(id)).toBe(false);
    // 小さすぎる (タグ以下) データ
    let tiny: Uint8Array;
    let tinyId: Uint8Array;
    do { tiny = randBytes(10); tinyId = idOf(tiny); } while (!h.storage.duty.shouldStoreChunk(tinyId));
    expect((await rawPut(u, h, tinyId, tiny))[0]).toBe(CHUNK_STATUS.BAD_REQUEST);
  }, 30_000);

  it('★ホップごとの預け入れの上限 (C4): 短時間に完成させられるチャンク数に天井。超えると FULL', async () => {
    net = await buildFileNet({ holderTunnel: { limits: { perHopPutsBurst: 2, perHopPutsPerSec: 0.0001 } } });
    const { u, holders } = net;
    const h = holders[0];
    const results: Array<ChunkStatus | null> = [];
    for (let i = 0; i < 4; i++) {
      const { data, id } = dutyChunk(h, 300 + i);
      results.push((await rawPut(u, h, id, data)).at(-1) ?? null);
    }
    expect(results).toEqual([CHUNK_STATUS.STORED, CHUNK_STATUS.STORED, CHUNK_STATUS.FULL, CHUNK_STATUS.FULL]);
    expect(h.storage.chunks!.count).toBe(2);
  }, 30_000);

  it('★集め中の数の上限 (C4): ホップごとの同時の組み立て数を超えると FULL (メモリを食わせない)', async () => {
    net = await buildFileNet({ holderTunnel: { limits: { perHopAssemblies: 2 } } });
    const { u, holders } = net;
    const h = holders[0];
    // 断片を 1 つだけ送って放置したチャンクを 3 つ
    const { encodePutFragment } = await import('../../src/network/storage/ChunkProtocol');
    const { callTunnel } = await import('../../src/network/tunnel/TunnelCall');
    const { TUNNEL_KIND } = await import('../../src/network/tunnel/TunnelCrypto');
    const { targetOf } = await import('../helpers/fileNet');
    const statuses: Array<number | null> = [];
    for (let i = 0; i < 3; i++) {
      const id = dutyChunk(h, 50 + i).id;
      const sol = solveChunkPowSync(id, TEST_CHUNK_EFFORT)!;
      const payload = encodePutFragment({ chunkId: id, powNonce: sol.nonce, powSolution: sol.solution, fragIndex: 0, fragCount: 3, data: new Uint8Array(15 * 1024).fill(i) });
      const r = await callTunnel(u.tunnel, targetOf(u, h), TUNNEL_KIND.PUT_CHUNK, payload, { inactivityMs: 3000, maxBytes: 16, maxPieces: 2 });
      statuses.push(r.data ? r.data[0] : null);
    }
    expect(statuses).toEqual([CHUNK_STATUS.OK, CHUNK_STATUS.OK, CHUNK_STATUS.FULL]);
  }, 30_000);
});

describe('C4: Guard の上り制限 (TUNNEL_SEND)', () => {
  it('★帯域の枠 (バースト) が小さいと、アップロードは BUSY で止められ、置き終えられない (リンクは出ない)', async () => {
    net = await buildFileNet({
      guardRelay: { limits: { clientSend: { ...LOOSE_CLIENT_SEND, bytesBurst: 200_000, bytesPerSec: 1000 } } },
    });
    const data = randBytes(1024 * 1024);
    const up = new FileUploader(net.uploaderParts({ limits: { busyRetries: 0, rounds: 1, fragmentRetries: 0 } }), data, { name: 'x', mime: 'text/plain' }).start();
    await expect(up.link).rejects.toMatchObject({ code: 'insufficient-replicas' });
    expect(net.g1.relay.stats.dropped.bytes).toBeGreaterThan(0);
    // 枠を超えた分は保持者まで届いていない: g1 が受け口へ流した量は 枠 (200KB) + 補充の分だけ
    const forwarded = net.g1.relay.stats.forwarded.requests;
    expect(forwarded).toBeLessThan(40);
  }, 60_000);

  it('★1 日の上限: 超えた分は BUSY (stats.dropped.daily)。要求が小さければ通る', async () => {
    net = await buildFileNet({
      guardRelay: { limits: { clientSend: { ...LOOSE_CLIENT_SEND, bytesPerDay: 300_000 } } },
    });
    const up = new FileUploader(net.uploaderParts({ limits: { busyRetries: 0, rounds: 1, fragmentRetries: 0 } }), randBytes(1024 * 1024), { name: 'x', mime: 'text/plain' }).start();
    await expect(up.link).rejects.toBeInstanceOf(FileTransferError);
    expect(net.g1.relay.stats.dropped.daily).toBeGreaterThan(0);
  }, 60_000);

  it('★同時数: 利用者 1 人が握れる応答待ちの経路は 32 本まで (stats.dropped.concurrent)', async () => {
    net = await buildFileNet({ holderTunnel: { limits: { chunkIntervalMs: 1, perHopConcurrent: 100, maxConcurrent: 100, perHopBurst: 100 } } });
    const { u, holders, g1 } = net;
    // 応答しない保持者へ 40 本の要求を一度に出す
    const h = holders[0];
    h.storage.chunks!.get = () => new Promise<Uint8Array | null>(() => undefined);
    const { callTunnel } = await import('../../src/network/tunnel/TunnelCall');
    const { TUNNEL_KIND } = await import('../../src/network/tunnel/TunnelCrypto');
    const { targetOf } = await import('../helpers/fileNet');
    const { encodeGetRequest } = await import('../../src/network/storage/ChunkProtocol');
    // TunnelClient の手元の上限 (30) を上げて、Guard 側の上限に当てる
    (u.tunnel as any).options = { maxConcurrent: 100 };
    const calls = Array.from({ length: 40 }, () =>
      callTunnel(u.tunnel, targetOf(u, h), TUNNEL_KIND.GET_CHUNK, encodeGetRequest(randBytes(16)), { inactivityMs: 800, maxBytes: 100, maxPieces: 2 }));
    const results = await Promise.all(calls);
    const busy = results.filter(r => r.error?.code === TUNNEL_ERROR_CODE.BUSY);
    expect(busy.length).toBe(8);
    expect(g1.relay.stats.dropped.concurrent).toBe(8);
  }, 30_000);
});

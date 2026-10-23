import { describe, it, expect, beforeAll } from 'vitest';
import sodium, { sodiumReady } from '../../src/crypto/sodium';
import {
  CHUNK_SIZE,
  MAX_CHUNKS,
  MAX_FILE_BYTES,
  decodeManifest,
  decryptChunk,
  encodeManifest,
  encryptChunk,
  idOf,
  sanitizeFileName,
} from '../../src/files/FileFormat';
import { FileAssembler, chunkPositions, decryptManifest, encodeFile, type EncodeEvent } from '../../src/files/FileCodec';
import { decodeFileLinkBody, formatFileLink, parseFileLinks, MAX_LINKS_PER_POST } from '../../src/files/FileLink';

beforeAll(async () => {
  await sodiumReady;
});

function rand(n: number): Uint8Array {
  const out = new Uint8Array(n);
  for (let o = 0; o < n; o += 65536) out.set(sodium.randombytes_buf(Math.min(65536, n - o)), o);
  return out;
}

async function encodeAll(data: Uint8Array, name = 'a.bin', mime = 'application/octet-stream') {
  const chunks: Extract<EncodeEvent, { kind: 'chunk' }>[] = [];
  let manifest!: Extract<EncodeEvent, { kind: 'manifest' }>;
  for await (const ev of encodeFile(data, { name, mime })) {
    if (ev.kind === 'chunk') chunks.push(ev);
    else manifest = ev;
  }
  return { chunks, manifest };
}

async function roundTrip(data: Uint8Array): Promise<Uint8Array> {
  const { chunks, manifest } = await encodeAll(data);
  const m = await decryptManifest(manifest.ciphertext, manifest.link);
  expect(m).not.toBeNull();
  const asm = new FileAssembler(m!, manifest.link.key);
  // 逆順で受けても番号順に出る
  for (const c of [...chunks].reverse()) expect(await asm.accept(c.index, c.ciphertext)).toEqual({ ok: true });
  expect(asm.isComplete).toBe(true);
  const parts = [...asm.drain()].map(x => x.plaintext);
  expect(asm.isFullyDrained).toBe(true);
  const out = new Uint8Array(parts.reduce((a, p) => a + p.length, 0));
  let o = 0;
  for (const p of parts) (out.set(p, o), (o += p.length));
  return out;
}

describe('往復', () => {
  for (const size of [1, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1, 3 * 1024 * 1024 + 123]) {
    it(`${size} バイト`, async () => {
      const data = rand(size);
      // ★ 大きな配列への toEqual は遅い (要素ごとの比較) ので Buffer で比べる
      expect(Buffer.from(await roundTrip(data)).equals(Buffer.from(data))).toBe(true);
    });
  }

  it('Blob 風の入力', async () => {
    const data = rand(CHUNK_SIZE + 5);
    const blob = { size: data.length, slice: (a?: number, b?: number) => ({ arrayBuffer: async () => data.slice(a, b).buffer }) };
    const evs: EncodeEvent[] = [];
    for await (const e of encodeFile(blob, { name: 'x', mime: 'a/b' })) evs.push(e);
    expect(evs).toHaveLength(3);
  });

  it('空・上限超は例外', async () => {
    await expect(encodeAll(new Uint8Array(0))).rejects.toThrow();
  });

  it('同じファイルでも毎回 ID が違う (収束暗号でない)', async () => {
    const data = rand(1000);
    const a = await encodeAll(data);
    const b = await encodeAll(data);
    expect(a.chunks[0].id).not.toEqual(b.chunks[0].id);
  });
});

describe('改ざん', () => {
  it('チャンクの任意の 1 バイトを変えると拒否 (ID で弾かれる)', async () => {
    const { chunks, manifest } = await encodeAll(rand(500));
    const m = (await decryptManifest(manifest.ciphertext, manifest.link))!;
    for (let i = 0; i < chunks[0].ciphertext.length; i += 37) {
      const bad = chunks[0].ciphertext.slice();
      bad[i] ^= 1;
      const asm = new FileAssembler(m, manifest.link.key);
      expect((await asm.accept(0, bad)).ok).toBe(false);
    }
  });

  it('ID が合っても K_f が違えば復号できない', async () => {
    const { chunks, manifest } = await encodeAll(rand(500));
    const m = (await decryptManifest(manifest.ciphertext, manifest.link))!;
    const asm = new FileAssembler(m, rand(32));
    expect(await asm.accept(0, chunks[0].ciphertext)).toEqual({ ok: false, reason: 'decrypt' });
  });

  it('別の番号への差し替えは通らない (AAD が番号を縛る)', async () => {
    const key = rand(32);
    const a = await encryptChunk(rand(100), 0, key);
    expect(await decryptChunk(a.ciphertext, 1, key)).toBeNull();
    const { chunks, manifest } = await encodeAll(rand(CHUNK_SIZE * 2));
    const m = (await decryptManifest(manifest.ciphertext, manifest.link))!;
    const asm = new FileAssembler(m, manifest.link.key);
    expect((await asm.accept(1, chunks[0].ciphertext)).ok).toBe(false);
    expect((await asm.accept(5, chunks[0].ciphertext)).ok).toBe(false);
  });

  it('Manifest の改ざん・リンク不一致・鍵違いは null', async () => {
    const { manifest } = await encodeAll(rand(500));
    for (let i = 0; i < manifest.ciphertext.length; i += 7) {
      const bad = manifest.ciphertext.slice();
      bad[i] ^= 1;
      expect(await decryptManifest(bad, manifest.link)).toBeNull();
    }
    const other = await encodeAll(rand(500));
    expect(await decryptManifest(other.manifest.ciphertext, manifest.link)).toBeNull();
    expect(await decryptManifest(manifest.ciphertext, { ...manifest.link, key: rand(32) })).toBeNull();
    expect(await decryptManifest(manifest.ciphertext, { ...manifest.link, size: 501 })).toBeNull();
    expect(await decryptManifest(new Uint8Array(3), manifest.link)).toBeNull();
  });

  it('重複・範囲外', async () => {
    const { chunks, manifest } = await encodeAll(rand(10));
    const m = (await decryptManifest(manifest.ciphertext, manifest.link))!;
    const asm = new FileAssembler(m, manifest.link.key);
    expect((await asm.accept(-1, chunks[0].ciphertext)).ok).toBe(false);
    expect(await asm.accept(0, chunks[0].ciphertext)).toEqual({ ok: true });
    expect(await asm.accept(0, chunks[0].ciphertext)).toEqual({ ok: false, reason: 'duplicate' });
  });
});

describe('再開', () => {
  it('completed を渡すと欠けだけを求める', async () => {
    const data = rand(CHUNK_SIZE * 3 + 1);
    const { chunks, manifest } = await encodeAll(data);
    const m = (await decryptManifest(manifest.ciphertext, manifest.link))!;
    const asm = new FileAssembler(m, manifest.link.key, [0, 1]);
    expect(asm.missing()).toEqual([2, 3]);
    expect(asm.doneIndices()).toEqual([0, 1]);
    await asm.accept(3, chunks[3].ciphertext);
    expect([...asm.drain()]).toHaveLength(0); // 2 が欠けているので出ない
    await asm.accept(2, chunks[2].ciphertext);
    expect([...asm.drain()].map(x => x.index)).toEqual([2, 3]);
    expect(asm.isFullyDrained).toBe(true);
  });
});

describe('Manifest 形式', () => {
  const ids = (n: number) => Array.from({ length: n }, () => rand(16));

  it('上限 2GiB の Manifest は 1 チャンクに収まる', async () => {
    expect(MAX_CHUNKS).toBe(8192);
    const enc = encodeManifest({ size: MAX_FILE_BYTES, mime: 'm'.repeat(100), name: 'あ'.repeat(85), chunkIds: ids(MAX_CHUNKS) });
    expect(enc.length).toBeLessThanOrEqual(CHUNK_SIZE);
    expect(decodeManifest(enc)).not.toBeNull();
  });

  it('厳格な復号', () => {
    const good = encodeManifest({ size: 10, mime: 'text/plain', name: 'n.txt', chunkIds: ids(1) });
    expect(decodeManifest(good)?.name).toBe('n.txt');
    expect(decodeManifest(Uint8Array.of(...good, 0))).toBeNull(); // 余りバイト
    expect(decodeManifest(good.slice(0, -1))).toBeNull();
    const v = good.slice();
    v[0] = 2;
    expect(decodeManifest(v)).toBeNull();
    const lg = good.slice();
    lg[7] = 17;
    expect(decodeManifest(lg)).toBeNull(); // chunkSizeLog2
    expect(decodeManifest(new Uint8Array(0))).toBeNull();
    // 大きさとチャンク数の不整合
    const big = good.slice();
    big[4] = 0xff; // size を大きくする
    expect(decodeManifest(big)).toBeNull();
    expect(() => encodeManifest({ size: CHUNK_SIZE + 1, mime: 'a/b', name: 'n', chunkIds: ids(1) })).toThrow();
    expect(() => encodeManifest({ size: MAX_FILE_BYTES + 1, mime: 'a/b', name: 'n', chunkIds: ids(MAX_CHUNKS + 1) })).toThrow();
  });

  it('不正な UTF-8 の名前・無害化されていない名前は拒否', () => {
    const good = encodeManifest({ size: 10, mime: 'a/b', name: 'abc', chunkIds: ids(1) });
    // header: ver1 size6 log2 1 mimeLen1 mime3 nameLen1 -> name は offset 13
    const bad = good.slice();
    bad[13] = 0xff;
    expect(decodeManifest(bad)).toBeNull();
    const slash = good.slice();
    slash[13] = 0x2f;
    expect(decodeManifest(slash)).toBeNull();
    const ctl = good.slice();
    ctl[13] = 0x07;
    expect(decodeManifest(ctl)).toBeNull();
  });
});

describe('名前の無害化', () => {
  it('区切り文字・制御文字・双方向制御を除く', () => {
    expect(sanitizeFileName('../../etc/passwd')).toBe('....etcpasswd');
    expect(sanitizeFileName('C:\\win\\x.txt')).toBe('Cwinx.txt');
    expect(sanitizeFileName('a\u0000b\nc\u202etxt.exe')).toBe('abctxt.exe');
    expect(sanitizeFileName('..')).toBe('file');
    expect(sanitizeFileName('')).toBe('file');
    expect(sanitizeFileName('  レポート.pdf ')).toBe('レポート.pdf');
  });

  it('255 バイトまでで、コードポイントの途中では切らず、冪等', () => {
    const s = sanitizeFileName('あ'.repeat(200));
    expect(new TextEncoder().encode(s).length).toBeLessThanOrEqual(255);
    expect(s).toBe('あ'.repeat(85));
    expect(sanitizeFileName(s)).toBe(s);
    const emoji = sanitizeFileName('😀'.repeat(100));
    expect(sanitizeFileName(emoji)).toBe(emoji);
  });

  it('エンコード時に適用される', async () => {
    const { manifest } = await encodeAll(rand(5), '../x/y.txt', 'bad mime!');
    const m = (await decryptManifest(manifest.ciphertext, manifest.link))!;
    expect(m.name).toBe('..xy.txt');
    expect(m.mime).toBe('application/octet-stream');
  });
});

describe('FileLink', () => {
  const link = { manifestId: rand(16), key: rand(32), size: 123456 };

  it('往復と長さ', () => {
    const t = formatFileLink(link);
    expect(t).toMatch(/^\[\[file:[A-Za-z0-9_-]{74}\]\]$/);
    const [p] = parseFileLinks(t);
    expect(p.link).toEqual(link);
    expect([p.start, p.end]).toEqual([0, t.length]);
  });

  it('日本語の文中から取り出せて位置が合う', () => {
    const t = formatFileLink(link);
    const text = `資料です。${t}確認お願いします。\n${t}`;
    const r = parseFileLinks(text);
    expect(r).toHaveLength(2);
    expect(text.slice(r[0].start, r[0].end)).toBe(t);
  });

  it('壊れたトークンは無視し、投げない', () => {
    const t = formatFileLink(link);
    const body = t.slice(7, -2);
    const cases = [
      '[[file:]]',
      '[[file:abc]]',
      `[[file:${body}A]]`,
      `[[file:${body.slice(1)}]]`,
      `[[file:${body.slice(0, -1)}+]]`,
      `[[file:${'A'.repeat(74)}]]`, // version 0
      `[[file:${body} ]]`,
      '[[file:\u3042]]',
    ];
    for (const c of cases) expect(() => parseFileLinks(c)).not.toThrow();
    for (const c of cases) expect(parseFileLinks(c)).toEqual([]);
    expect(decodeFileLinkBody(body)).not.toBeNull();
    // 末尾の余りビットを変えた別表記
    const last = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const alt = body.slice(0, -1) + last[(last.indexOf(body.at(-1)!) + 1) % 64];
    expect(decodeFileLinkBody(alt)).toBeNull();
  });

  it('1 投稿 4 件まで', () => {
    const t = formatFileLink(link);
    expect(parseFileLinks(Array(10).fill(t).join(' '))).toHaveLength(MAX_LINKS_PER_POST);
  });

  it('範囲外の大きさは作れず、読めない', () => {
    expect(() => formatFileLink({ ...link, size: 0 })).toThrow();
    expect(() => formatFileLink({ ...link, size: MAX_FILE_BYTES + 1 })).toThrow();
  });
});

describe('chunkPositions', () => {
  it('決定的で j ごとに違い、重複は除く', () => {
    const id = rand(16);
    const a = chunkPositions(id, 5);
    expect(a).toEqual(chunkPositions(id, 5));
    expect(new Set(a).size).toBe(a.length);
    expect(a).toHaveLength(5);
    expect(chunkPositions(rand(16), 5)).not.toEqual(a);
    expect(() => chunkPositions(id, 0)).toThrow();
  });
});

describe('ストリーミング', () => {
  it('20MiB を非同期イテラブルから流しても同時に持つチャンクは数個', async () => {
    const TOTAL = 20 * 1024 * 1024;
    const PIECE = 100_000; // チャンクと揃わない大きさ
    let produced = 0;
    let consumed = 0; // 出力されたチャンク分の入力バイト
    let maxAhead = 0;
    async function* src(): AsyncGenerator<Uint8Array> {
      while (produced < TOTAL) {
        const n = Math.min(PIECE, TOTAL - produced);
        produced += n;
        maxAhead = Math.max(maxAhead, produced - consumed);
        yield new Uint8Array(n);
      }
    }
    let chunks = 0;
    let manifest: EncodeEvent | undefined;
    for await (const ev of encodeFile(src(), { name: 'big', mime: 'a/b' })) {
      if (ev.kind === 'chunk') {
        chunks++;
        consumed += CHUNK_SIZE;
        expect(ev.ciphertext.length).toBeLessThanOrEqual(CHUNK_SIZE + 16);
      } else manifest = ev;
    }
    expect(chunks).toBe(80);
    expect(manifest?.kind).toBe('manifest');
    // 入力を先読みした量が 2 チャンク分 (+ 1 ピース) を超えない
    expect(maxAhead).toBeLessThanOrEqual(2 * CHUNK_SIZE + PIECE);
  });

  it('chunk id は暗号文の SHA-256 先頭 16 バイト', async () => {
    const { chunks } = await encodeAll(rand(100));
    expect(chunks[0].id).toEqual(idOf(chunks[0].ciphertext));
    expect(chunks[0].id).toHaveLength(16);
  });
});

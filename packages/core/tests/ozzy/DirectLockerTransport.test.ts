import { describe, it, expect, vi } from 'vitest';
import {
  OZZY_LOCKER_SCHEME, createSchemeLockerTransport, fromLockerSchemeUrl, toLockerSchemeUrl,
} from '../../src/ozzy/DirectLockerTransport';

describe('DirectLockerTransport: デスクトップがロッカーへ直接つなぐ通信路 (ozlocker://)', () => {
  it('https の URL を独自スキームに書き換え、戻せる (パスとクエリは保つ。https 以外・資格情報入りは断る)', () => {
    const https = 'https://files.catbox.moe/abc.bin?x=1';
    const scheme = toLockerSchemeUrl(https);
    expect(scheme).toBe(`${OZZY_LOCKER_SCHEME}://files.catbox.moe/abc.bin?x=1`);
    expect(fromLockerSchemeUrl(scheme!)).toBe(https);
    expect(toLockerSchemeUrl('http://files.catbox.moe/abc.bin')).toBeNull();
    expect(toLockerSchemeUrl('https://user:pw@files.catbox.moe/abc.bin')).toBeNull();
    expect(toLockerSchemeUrl('not a url')).toBeNull();
    expect(fromLockerSchemeUrl('https://files.catbox.moe/abc.bin')).toBeNull();
    expect(fromLockerSchemeUrl('ozlocker://user:pw@files.catbox.moe/a')).toBeNull();
  });

  it('要求を独自スキームへ送る: 方法・ヘッダ・本体はそのまま、Cookie は付けない', async () => {
    const inner = vi.fn(async (_url: string, _init: RequestInit) => new Response('ok', { status: 206 }));
    const transport = createSchemeLockerTransport(OZZY_LOCKER_SCHEME, inner);

    const get = await transport(new Request('https://d.uguu.se/x.bin', { headers: { Range: 'bytes=0-9' } }));
    expect(get.status).toBe(206);
    const [url, init] = inner.mock.calls[0];
    expect(url).toBe('ozlocker://d.uguu.se/x.bin');
    expect(init).toMatchObject({ method: 'GET', credentials: 'omit', body: undefined });
    expect(new Headers(init.headers).get('range')).toBe('bytes=0-9');

    const form = new FormData();
    form.append('file', new Blob([new Uint8Array([1, 2, 3])]), 'a.bin');
    await transport(new Request('https://catbox.moe/user/api.php', { method: 'POST', body: form }));
    const [postUrl, postInit] = inner.mock.calls[1];
    expect(postUrl).toBe('ozlocker://catbox.moe/user/api.php');
    expect(postInit.method).toBe('POST');
    expect((postInit.body as ArrayBuffer).byteLength).toBeGreaterThan(3);
    expect(new Headers(postInit.headers).get('content-type')).toMatch(/^multipart\/form-data; boundary=/);

    await expect(transport(new Request('http://x0.at/a.bin'))).rejects.toThrow(/https/);
  });
});

import { describe, it, expect, vi } from 'vitest';

vi.mock('electron', () => ({ protocol: {}, session: {} }));

const { handleLockerRequest, plainUserAgent } = await import('../electron/ozlocker');

type Call = { url: string; init: RequestInit };

/** ロッカー側の代わり。URL ごとに応答を決める */
function egressOf(routes: Record<string, () => Response>) {
  const calls: Call[] = [];
  const egress = async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    const r = routes[url];
    if (!r) throw new Error(`unexpected ${url}`);
    return r();
  };
  return { egress, calls };
}

describe('ozlocker:// (デスクトップがロッカーへ直接つなぐ口)', () => {
  it('★許可したロッカーへだけ行く: 攻撃者のサーバー・LAN・http は 403 で、外へは何も送らない', async () => {
    const { egress, calls } = egressOf({});
    for (const url of ['ozlocker://attacker.example/x', 'ozlocker://192.168.1.1/x', 'ozlocker://localhost/x', 'ozlocker://files.catbox.moe:8080/x']) {
      const res = await handleLockerRequest(new Request(url), egress);
      expect(res.status, url).toBe(403);
    }
    expect(calls).toHaveLength(0);
  });

  it('★Range など決めたヘッダだけを送り、Cookie・Referer・Origin は送らない。応答の Set-Cookie は画面へ返さず、CORS の印を付ける', async () => {
    const { egress, calls } = egressOf({
      'https://files.catbox.moe/abc.bin': () => new Response(new Uint8Array([1, 2, 3]), {
        status: 206, headers: { 'Content-Range': 'bytes 0-2/10', 'Set-Cookie': 'track=1' },
      }),
    });
    const res = await handleLockerRequest(new Request('ozlocker://files.catbox.moe/abc.bin', {
      headers: { Range: 'bytes=0-2', Cookie: 'a=b', Referer: 'https://oz.example/', 'X-Forwarded-For': '1.2.3.4' },
    }), egress);
    expect(res.status).toBe(206);
    expect(new Uint8Array(await res.arrayBuffer())).toEqual(new Uint8Array([1, 2, 3]));
    expect(res.headers.get('content-range')).toBe('bytes 0-2/10');
    expect(res.headers.get('set-cookie')).toBeNull();
    expect(res.headers.get('access-control-allow-origin')).toBe('*');
    const sent = new Headers(calls[0].init.headers);
    expect([...sent.keys()]).toEqual(['range']);
    expect(calls[0].init).toMatchObject({ method: 'GET', credentials: 'omit', redirect: 'manual' });
  });

  it('アップロード (POST) は本体をそのまま送る', async () => {
    const { egress, calls } = egressOf({ 'https://catbox.moe/user/api.php': () => new Response('https://files.catbox.moe/zz.bin') });
    const form = new FormData();
    form.append('fileToUpload', new Blob([new Uint8Array(100)]), 'a.bin');
    const res = await handleLockerRequest(new Request('ozlocker://catbox.moe/user/api.php', { method: 'POST', body: form }), egress);
    expect(await res.text()).toBe('https://files.catbox.moe/zz.bin');
    expect(calls[0].init.method).toBe('POST');
    expect((calls[0].init.body as ArrayBuffer).byteLength).toBeGreaterThan(100);
    expect(new Headers(calls[0].init.headers).get('content-type')).toMatch(/^multipart\/form-data/);
  });

  it('★リダイレクトは 1 段ずつ確かめる: 許可したロッカーへは付いていき、それ以外へ向けられたら 403', async () => {
    const ok = egressOf({
      'https://x0.at/a.bin': () => new Response(null, { status: 302, headers: { Location: 'https://d.uguu.se/a.bin' } }),
      'https://d.uguu.se/a.bin': () => new Response('data', { status: 200 }),
    });
    expect(await (await handleLockerRequest(new Request('ozlocker://x0.at/a.bin'), ok.egress)).text()).toBe('data');
    expect(ok.calls.map(c => c.url)).toEqual(['https://x0.at/a.bin', 'https://d.uguu.se/a.bin']);

    const bad = egressOf({
      'https://x0.at/a.bin': () => new Response(null, { status: 302, headers: { Location: 'http://192.168.0.1/admin' } }),
    });
    expect((await handleLockerRequest(new Request('ozlocker://x0.at/a.bin'), bad.egress)).status).toBe(403);
    expect(bad.calls).toHaveLength(1);
  });

  it('CORS の事前確認 (OPTIONS) には外へ出ずに答える。ロッカーに届かなければ 502', async () => {
    const { egress, calls } = egressOf({});
    const pre = await handleLockerRequest(new Request('ozlocker://files.catbox.moe/abc.bin', { method: 'OPTIONS' }), egress);
    expect(pre.status).toBe(204);
    expect(pre.headers.get('access-control-allow-headers')).toContain('range');
    expect(calls).toHaveLength(0);
    const down = await handleLockerRequest(new Request('ozlocker://files.catbox.moe/abc.bin'), egress);
    expect(down.status).toBe(502);
  });

  it('User-Agent から Electron とアプリの名前を外す (Ozzy の通信だと名乗らない)', () => {
    const ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) oz-desktop/1.0.9 Chrome/132.0.6834.83 Electron/34.2.0 Safari/537.36';
    expect(plainUserAgent(ua)).toBe('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.6834.83 Safari/537.36');
  });
});

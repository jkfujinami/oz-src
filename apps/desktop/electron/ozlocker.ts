import { protocol, session, type Session } from 'electron';
import { OZZY_LOCKER_SCHEME, fromLockerSchemeUrl, isAllowedOzzyLockerRequestUrl } from '@oz/core';

/**
 * ozlocker:// — 画面 (レンダラー) の Ozzy が、Worker を通さずにロッカーへつなぐ口 (core の ozzy/DirectLockerTransport)。
 *
 *   画面  fetch('ozlocker://files.catbox.moe/x.bin', { headers: { Range } })
 *   main  許可したロッカーか確かめ、https://files.catbox.moe/x.bin へ取りに行って、CORS の印を付けて返す
 *
 * ★ main には CORS が無いので Worker が要らない。ロッカーに見えるのはこの端末の IP
 *   (M1 の役で他人のために取りに行くときも。読み手の IP は届かない)。
 * ★ 他人に頼まれた作業 (M1) で、攻撃者のサーバーや LAN へ行かされないよう、行き先は core の許可リスト
 *   (isAllowedOzzyLockerRequestUrl) に限る。リダイレクト先も 1 段ずつ確かめる。
 * ★ この端末だと分かる印を付けない: Cookie を持たない専用のセッション (メモリだけ)、Referer / Origin は送らない、
 *   User-Agent から Electron とアプリの名前を外す。
 */

/** 転送する要求のヘッダ (ほかは送らない) */
const FORWARD_REQUEST_HEADERS = ['range', 'if-range', 'content-type', 'accept'];
/** 画面へ返さない応答のヘッダ */
const DROP_RESPONSE_HEADERS = new Set(['set-cookie', 'set-cookie2']);
const MAX_REDIRECTS = 5;

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Expose-Headers': '*',
} as const;

export type EgressFetch = (url: string, init: RequestInit) => Promise<Response>;

function refuse(status: number, error: string): Response {
  return new Response(JSON.stringify({ error }), { status, headers: { ...CORS, 'Content-Type': 'application/json' } });
}

/**
 * ozlocker:// の要求 1 つを、許可したロッカーへの https の要求にして返す (Electron に依らない部分。テストする)。
 */
export async function handleLockerRequest(req: Request, egress: EgressFetch): Promise<Response> {
  if (req.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        ...CORS,
        'Access-Control-Allow-Methods': 'GET, HEAD, POST, PUT, DELETE',
        'Access-Control-Allow-Headers': FORWARD_REQUEST_HEADERS.join(', '),
        'Access-Control-Max-Age': '600',
      },
    });
  }
  let target = fromLockerSchemeUrl(req.url, OZZY_LOCKER_SCHEME);
  if (!target || !isAllowedOzzyLockerRequestUrl(target)) return refuse(403, 'DISALLOWED_LOCKER_HOST');

  const headers = new Headers();
  for (const name of FORWARD_REQUEST_HEADERS) {
    const v = req.headers.get(name);
    if (v !== null) headers.set(name, v);
  }
  let method = req.method;
  let body: ArrayBuffer | undefined = method === 'GET' || method === 'HEAD' ? undefined : await req.arrayBuffer();

  for (let hop = 0; ; hop++) {
    let res: Response;
    try {
      res = await egress(target, { method, headers, body, redirect: 'manual', credentials: 'omit', cache: 'no-store', signal: req.signal });
    } catch {
      return refuse(502, 'LOCKER_UNREACHABLE');
    }
    const location = res.status >= 300 && res.status < 400 ? res.headers.get('location') : null;
    if (location === null) {
      const out = new Headers(CORS);
      res.headers.forEach((value, name) => {
        if (!DROP_RESPONSE_HEADERS.has(name.toLowerCase())) out.set(name, value);
      });
      return new Response(method === 'HEAD' ? null : res.body, { status: res.status, statusText: res.statusText, headers: out });
    }
    if (hop >= MAX_REDIRECTS) return refuse(502, 'TOO_MANY_REDIRECTS');
    let next: string;
    try {
      next = new URL(location, target).href;
    } catch {
      return refuse(502, 'BAD_REDIRECT');
    }
    // ★ リダイレクト先も許可したロッカーだけ (行き先を書き換えて LAN や攻撃者のサーバーへ向けさせない)
    if (!isAllowedOzzyLockerRequestUrl(next)) return refuse(403, 'DISALLOWED_REDIRECT');
    if (res.status === 303 || ((res.status === 301 || res.status === 302) && method === 'POST')) {
      method = 'GET';
      body = undefined;
      headers.delete('content-type');
    }
    target = next;
  }
}

/** app の ready より前に呼ぶ: 独自スキームを fetch で使え、CORS を通せるものとして登録する */
export function registerOzLockerScheme(): void {
  protocol.registerSchemesAsPrivileged([{
    scheme: OZZY_LOCKER_SCHEME,
    privileges: { standard: true, secure: true, supportFetchAPI: true, corsEnabled: true, stream: true },
  }]);
}

/** User-Agent から Electron とアプリの名前を外す (普通の Chromium に見せる。Ozzy の通信だと名乗らない) */
export function plainUserAgent(ua: string): string {
  return ua.replace(/\s+(Electron|oz[\w-]*|OZ)\/\S+/g, '').trim();
}

/** app の ready の後に呼ぶ: 画面のセッションに ozlocker:// の受け口を付ける */
export function installOzLockerHandler(target: Session = session.defaultSession): void {
  // ★ ロッカーへの通信だけのセッション (partition に persist: を付けないのでメモリだけ。Cookie もキャッシュも残らない)
  const egressSession = session.fromPartition('ozzy-lockers', { cache: false });
  egressSession.setUserAgent(plainUserAgent(egressSession.getUserAgent()));
  egressSession.setPermissionRequestHandler((_wc, _permission, callback) => callback(false));
  const egress: EgressFetch = (url, init) => egressSession.fetch(url, init);
  target.protocol.handle(OZZY_LOCKER_SCHEME, (req) => handleLockerRequest(req, egress));
}

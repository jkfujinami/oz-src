import type { HttpTransportFn } from './OverseasLockers';

/**
 * DirectLockerTransport — デスクトップ (Electron) で、Worker を通さずにロッカーへつなぐ通信路。
 *
 *   画面 (レンダラー)  fetch('ozlocker://files.catbox.moe/x.bin')
 *   main プロセス       https://files.catbox.moe/x.bin へ取りに行く (apps/desktop/electron/ozlocker.ts)
 *
 * ★ 画面からロッカーへは CORS で直接読めないが、main には CORS が無い。だから Worker が要らない。
 * ★ ロッカーに見えるのはこの端末の IP。M1 の役で他人のために取りに行くときも同じ (読み手の IP は届かない)。
 * ★ 行き先の確認 (許可したロッカーだけ・リダイレクト先も)・Cookie / Referer / Origin を付けないことは main がする。
 *   ここは URL を書き換えて渡すだけ。
 */
export const OZZY_LOCKER_SCHEME = 'ozlocker';

/** https の URL を独自スキームの URL にする。https でなければ null */
export function toLockerSchemeUrl(httpsUrl: string, scheme: string = OZZY_LOCKER_SCHEME): string | null {
  let u: URL;
  try {
    u = new URL(httpsUrl);
  } catch {
    return null;
  }
  if (u.protocol !== 'https:' || u.username !== '' || u.password !== '') return null;
  return `${scheme}://${u.host}${u.pathname}${u.search}`;
}

/** 独自スキームの URL を https の URL に戻す (main 側で使う)。形が違えば null */
export function fromLockerSchemeUrl(url: string, scheme: string = OZZY_LOCKER_SCHEME): string | null {
  const prefix = `${scheme}://`;
  if (typeof url !== 'string' || !url.toLowerCase().startsWith(prefix)) return null;
  let u: URL;
  try {
    u = new URL(`https://${url.slice(prefix.length)}`);
  } catch {
    return null;
  }
  if (u.username !== '' || u.password !== '') return null;
  return `https://${u.host}${u.pathname}${u.search}`;
}

/**
 * ロッカーへの要求を独自スキームへ書き換えて送る通信路。OzNode の `ozzy.lockerTransport` に渡す。
 * ★ 本体 (アップロードの Slab は 64MiB まで) は読み切ってから渡す (独自スキームへの本体の流し込みは実装ごとの差が大きい)。
 */
export function createSchemeLockerTransport(
  scheme: string = OZZY_LOCKER_SCHEME,
  innerFetch: (url: string, init: RequestInit) => Promise<Response> = (url, init) => fetch(url, init),
): HttpTransportFn {
  return async (request: Request): Promise<Response> => {
    const target = toLockerSchemeUrl(request.url, scheme);
    if (!target) throw new Error('locker request must be https');
    const hasBody = request.method !== 'GET' && request.method !== 'HEAD';
    return innerFetch(target, {
      method: request.method,
      headers: request.headers,
      body: hasBody ? await request.arrayBuffer() : undefined,
      signal: request.signal,
      redirect: 'follow',
      credentials: 'omit',
      cache: 'no-store',
    });
  };
}

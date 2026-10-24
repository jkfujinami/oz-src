/**
 * トラッカー (シグナリングサーバ) の URL の検証と正規化。
 *
 * 公式のトラッカーは存在しないため、URL は利用者が設定する。
 * 打ち間違いや貼り付けミスで、意図しない相手に peerId と IP を晒さないよう、
 * 受け付ける形を狭くしておく。
 *
 *   - wss:// のみ。ws:// (平文) は自分の端末 (localhost / 127.0.0.0/8 / ::1) に限る。
 *     平文だと、通信路上の誰でも peerId と SDP (候補 IP を含む) を読めて、書き換えもできる。
 *   - URL に認証情報 (user:pass@) を含めない。設定画面やログから漏れる。
 *   - クエリとフラグメントを含めない。追跡用の値が紛れ込む余地を残さない。
 *   - パスを省略した場合は /ws とする (トラッカーの既定のパス)。
 */

export const TRACKER_URL_MAX_LENGTH = 512;
export const DEFAULT_TRACKER_PATH = '/ws';

export type TrackerUrlError =
  | 'empty'
  | 'too-long'
  | 'invalid'
  | 'insecure'
  | 'credentials'
  | 'query'
  | 'fragment';

export type TrackerUrlResult = { ok: true; url: string } | { ok: false; reason: TrackerUrlError };

function isLoopbackHost(hostname: string): boolean {
  const h = hostname.toLowerCase();
  if (h === 'localhost' || h === '[::1]') return true;
  // WHATWG URL は IPv4 を正規化する (例: 127.1 → 127.0.0.1) ので、4 つ組だけ見ればよい
  return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h);
}

/**
 * トラッカーが自分の端末か (開発用の網)。この網に限り、経路の各段が同じ端末でもよいことにする
 * (1 台で複数のノードを立てて試すため。PeerManager の allowSameOriginHops)。
 */
export function isLoopbackTrackerUrl(url: string | null | undefined): boolean {
  if (!url) return false;
  try {
    return isLoopbackHost(new URL(url).hostname);
  } catch {
    return false;
  }
}

export function parseTrackerUrl(input: string): TrackerUrlResult {
  const raw = typeof input === 'string' ? input.trim() : '';
  if (raw.length === 0) return { ok: false, reason: 'empty' };
  if (raw.length > TRACKER_URL_MAX_LENGTH) return { ok: false, reason: 'too-long' };

  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, reason: 'invalid' };
  }
  if (!url.hostname) return { ok: false, reason: 'invalid' };

  if (url.protocol === 'ws:') {
    if (!isLoopbackHost(url.hostname)) return { ok: false, reason: 'insecure' };
  } else if (url.protocol !== 'wss:') {
    return { ok: false, reason: 'invalid' };
  }

  if (url.username || url.password) return { ok: false, reason: 'credentials' };
  // 空の "?" や "#" も拒否する (URL は空なら search / hash を "" にしてしまう)
  if (url.search || raw.includes('?')) return { ok: false, reason: 'query' };
  if (url.hash || raw.includes('#')) return { ok: false, reason: 'fragment' };

  if (url.pathname === '' || url.pathname === '/') url.pathname = DEFAULT_TRACKER_PATH;
  return { ok: true, url: url.toString() };
}

/** 画面表示用の説明 */
export function describeTrackerUrlError(reason: TrackerUrlError): string {
  switch (reason) {
    case 'empty': return 'URL を入力してください';
    case 'too-long': return 'URL が長すぎます';
    case 'invalid': return 'wss:// で始まる URL を入力してください';
    case 'insecure': return '暗号化されていない ws:// は、この端末 (localhost) 以外には使えません';
    case 'credentials': return 'URL にユーザー名やパスワードを含めないでください';
    case 'query': return 'URL に ? 以降 (クエリ) を含めないでください';
    case 'fragment': return 'URL に # 以降を含めないでください';
  }
}

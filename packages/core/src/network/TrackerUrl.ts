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

import { encode as msgpackEncode, decode as msgpackDecode } from '@msgpack/msgpack';

export const TRACKER_URL_MAX_LENGTH = 512;
export const DEFAULT_TRACKER_PATH = '/ws';
export const TRACKER_STRING_PREFIX = 'oz-tracker:';

export interface TrackerEndpoint {
  host: string;
  port: number;
  tls?: boolean;
  path?: string;
}

export type TrackerUrlError =
  | 'empty'
  | 'too-long'
  | 'invalid'
  | 'insecure'
  | 'credentials'
  | 'query'
  | 'fragment';

export type TrackerUrlResult = { ok: true; url: string } | { ok: false; reason: TrackerUrlError };

const TRACKER_TOKEN_VERSION = 1;
const TRACKER_SALT_BYTES = 8;
const TRACKER_TAG_BYTES = 8;
const TRACKER_DOMAIN_KEY = new Uint32Array([0x6f7a2d74, 0x7261636b, 0x65722d76, 0x312d6d61]);

function rotl32(x: number, n: number): number {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

function mixBlock(salt: Uint8Array, counter: number): Uint8Array {
  let s0 = TRACKER_DOMAIN_KEY[0] ^ ((salt[0] | (salt[1] << 8) | (salt[2] << 16) | (salt[3] << 24)) >>> 0);
  let s1 = TRACKER_DOMAIN_KEY[1] ^ ((salt[4] | (salt[5] << 8) | (salt[6] << 16) | (salt[7] << 24)) >>> 0);
  let s2 = TRACKER_DOMAIN_KEY[2] ^ (counter >>> 0);
  let s3 = TRACKER_DOMAIN_KEY[3] ^ 0x9e3779b9;
  for (let i = 0; i < 12; i++) {
    s0 = (s0 + s1) >>> 0; s3 = rotl32(s3 ^ s0, 16);
    s2 = (s2 + s3) >>> 0; s1 = rotl32(s1 ^ s2, 12);
    s0 = (s0 + s1) >>> 0; s3 = rotl32(s3 ^ s0, 8);
    s2 = (s2 + s3) >>> 0; s1 = rotl32(s1 ^ s2, 7);
  }
  const out = new Uint8Array(16);
  const words = [s0, s1, s2, s3];
  for (let w = 0; w < 4; w++) {
    out[w * 4] = words[w] & 0xff;
    out[w * 4 + 1] = (words[w] >>> 8) & 0xff;
    out[w * 4 + 2] = (words[w] >>> 16) & 0xff;
    out[w * 4 + 3] = (words[w] >>> 24) & 0xff;
  }
  return out;
}

function xorStream(salt: Uint8Array, data: Uint8Array): Uint8Array {
  const out = new Uint8Array(data.length);
  for (let offset = 0, blockIdx = 1; offset < data.length; offset += 16, blockIdx++) {
    const keyBlock = mixBlock(salt, blockIdx);
    const end = Math.min(16, data.length - offset);
    for (let i = 0; i < end; i++) {
      out[offset + i] = data[offset + i] ^ keyBlock[i];
    }
  }
  return out;
}

function computeTrackerTag(salt: Uint8Array, plain: Uint8Array): Uint8Array {
  const macSalt = new Uint8Array(TRACKER_SALT_BYTES);
  for (let i = 0; i < TRACKER_SALT_BYTES; i++) macSalt[i] = salt[i] ^ 0x5c;
  const state = mixBlock(macSalt, plain.length ^ 0xa5a5a5a5);
  for (let i = 0; i < plain.length; i++) {
    state[i & 15] = (state[i & 15] + plain[i] + ((i + 1) * 17)) & 0xff;
    if ((i & 15) === 15 || i === plain.length - 1) {
      const mixed = mixBlock( state.subarray(0, 8), i + 0x1000 );
      for (let j = 0; j < 16; j++) state[j] ^= mixed[j];
    }
  }
  return state.slice(0, TRACKER_TAG_BYTES);
}

const B64U_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

function toBase64Url(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    const rem = bytes.length - i;
    out += B64U_CHARS[b0 >>> 2];
    out += B64U_CHARS[((b0 & 3) << 4) | (b1 >>> 4)];
    if (rem > 1) out += B64U_CHARS[((b1 & 15) << 2) | (b2 >>> 6)];
    if (rem > 2) out += B64U_CHARS[b2 & 63];
  }
  return out;
}

function fromBase64Url(str: string): Uint8Array | null {
  if (!/^[A-Za-z0-9\-_]+$/.test(str) || str.length % 4 === 1) return null;
  const outLen = Math.floor((str.length * 3) / 4);
  const out = new Uint8Array(outLen);
  let outIdx = 0;
  for (let i = 0; i < str.length; i += 4) {
    const c0 = B64U_CHARS.indexOf(str[i]);
    const c1 = B64U_CHARS.indexOf(str[i + 1]);
    const c2 = i + 2 < str.length ? B64U_CHARS.indexOf(str[i + 2]) : 0;
    const c3 = i + 3 < str.length ? B64U_CHARS.indexOf(str[i + 3]) : 0;
    if (c0 < 0 || c1 < 0 || c2 < 0 || c3 < 0) return null;
    out[outIdx++] = (c0 << 2) | (c1 >>> 4);
    if (outIdx < outLen) out[outIdx++] = ((c1 & 15) << 4) | (c2 >>> 2);
    if (outIdx < outLen) out[outIdx++] = ((c2 & 3) << 6) | c3;
  }
  return out;
}

function normalizeEndpointHost(rawHost: string): string | null {
  const trimmed = rawHost.trim();
  if (!trimmed || trimmed.length > 253) return null;
  const bracketed = trimmed.startsWith('[') && trimmed.endsWith(']') ? trimmed : trimmed.includes(':') ? `[${trimmed}]` : trimmed;
  try {
    const u = new URL(`http://${bracketed}:80/`);
    if (!u.hostname) return null;
    return u.hostname.startsWith('[') && u.hostname.endsWith(']')
      ? u.hostname.slice(1, -1)
      : u.hostname;
  } catch {
    return null;
  }
}

/**
 * ポート開放トラッカーの接続先 (IP / ホスト名・ポート番号・TLS 有無・パス) から
 * 難読化・改ざん検知タグ付きの `oz-tracker:...` トークンを生成する。
 */
export function createTrackerString(endpoint: TrackerEndpoint): string {
  const host = normalizeEndpointHost(endpoint.host);
  if (!host) throw new Error('createTrackerString: invalid host');
  const port = endpoint.port;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('createTrackerString: port must be 1..65535');
  }
  const tls = endpoint.tls === true ? 1 : 0;
  const path = endpoint.path && endpoint.path.length > 0 ? endpoint.path : DEFAULT_TRACKER_PATH;
  if (!path.startsWith('/') || path.includes('?') || path.includes('#')) {
    throw new Error('createTrackerString: invalid path');
  }

  const plain = msgpackEncode([TRACKER_TOKEN_VERSION, host, port, tls, path]);
  const salt = new Uint8Array(TRACKER_SALT_BYTES);
  if (globalThis.crypto?.getRandomValues) {
    globalThis.crypto.getRandomValues(salt);
  } else {
    for (let i = 0; i < TRACKER_SALT_BYTES; i++) salt[i] = (Math.random() * 256) | 0;
  }
  const masked = xorStream(salt, plain);
  const tag = computeTrackerTag(salt, plain);

  const wire = new Uint8Array(TRACKER_SALT_BYTES + masked.length + TRACKER_TAG_BYTES);
  wire.set(salt, 0);
  wire.set(masked, TRACKER_SALT_BYTES);
  wire.set(tag, TRACKER_SALT_BYTES + masked.length);
  return TRACKER_STRING_PREFIX + toBase64Url(wire);
}

/**
 * `oz-tracker:...` トークンを検証・展開して接続先情報を返す。不正・改ざん時は null。
 */
export function parseTrackerString(input: string): { host: string; port: number; tls: boolean; path: string } | null {
  const raw = typeof input === 'string' ? input.trim() : '';
  if (!raw.startsWith(TRACKER_STRING_PREFIX) || raw.length > TRACKER_URL_MAX_LENGTH) return null;
  const body = raw.slice(TRACKER_STRING_PREFIX.length);
  const wire = fromBase64Url(body);
  if (!wire || wire.length <= TRACKER_SALT_BYTES + TRACKER_TAG_BYTES) return null;

  const salt = wire.subarray(0, TRACKER_SALT_BYTES);
  const masked = wire.subarray(TRACKER_SALT_BYTES, wire.length - TRACKER_TAG_BYTES);
  const tag = wire.subarray(wire.length - TRACKER_TAG_BYTES);
  const plain = xorStream(salt, masked);
  const expectedTag = computeTrackerTag(salt, plain);

  let diff = 0;
  for (let i = 0; i < TRACKER_TAG_BYTES; i++) diff |= tag[i] ^ expectedTag[i];
  if (diff !== 0) return null;

  let decoded: unknown;
  try {
    decoded = msgpackDecode(plain);
  } catch {
    return null;
  }
  if (!Array.isArray(decoded) || decoded.length !== 5) return null;
  const [ver, hostRaw, port, tlsFlag, path] = decoded;
  if (ver !== TRACKER_TOKEN_VERSION) return null;
  if (typeof hostRaw !== 'string') return null;
  const host = normalizeEndpointHost(hostRaw);
  if (!host) return null;
  if (typeof port !== 'number' || !Number.isInteger(port) || port < 1 || port > 65535) return null;
  if (tlsFlag !== 0 && tlsFlag !== 1) return null;
  if (typeof path !== 'string' || !path.startsWith('/') || path.includes('?') || path.includes('#')) return null;

  return { host, port, tls: tlsFlag === 1, path };
}

/**
 * 設定文字列 (`wss://...`, `ws://localhost:...`, または `oz-tracker:...`) を
 * 実際に WebSocket が接続する URL (`ws://...` / `wss://...`) に解決する。
 */
export function resolveTrackerWebSocketUrl(urlOrToken: string): string {
  const raw = typeof urlOrToken === 'string' ? urlOrToken.trim() : '';
  if (raw.startsWith(TRACKER_STRING_PREFIX)) {
    const ep = parseTrackerString(raw);
    if (!ep) throw new Error('invalid tracker token');
    const hostPart = ep.host.includes(':') ? `[${ep.host}]` : ep.host;
    const scheme = ep.tls ? 'wss' : 'ws';
    return `${scheme}://${hostPart}:${ep.port}${ep.path}`;
  }
  const parsed = parseTrackerUrl(raw);
  if (parsed.ok && !parsed.url.startsWith(TRACKER_STRING_PREFIX)) {
    return parsed.url;
  }
  return raw;
}

function isLoopbackHost(hostname: string): boolean {
  const h = hostname.toLowerCase();
  if (h === 'localhost' || h === '[::1]' || h === '::1') return true;
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
    const resolved = resolveTrackerWebSocketUrl(url);
    return isLoopbackHost(new URL(resolved).hostname);
  } catch {
    return false;
  }
}

export function parseTrackerUrl(input: string): TrackerUrlResult {
  const raw = typeof input === 'string' ? input.trim() : '';
  if (raw.length === 0) return { ok: false, reason: 'empty' };
  if (raw.length > TRACKER_URL_MAX_LENGTH) return { ok: false, reason: 'too-long' };

  if (raw.startsWith(TRACKER_STRING_PREFIX)) {
    const ep = parseTrackerString(raw);
    if (!ep) return { ok: false, reason: 'invalid' };
    return { ok: true, url: raw };
  }

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
    case 'empty': return 'URL または oz-tracker:... を入力してください';
    case 'too-long': return 'URL が長すぎます';
    case 'invalid': return 'wss:// で始まる URL または有効な oz-tracker:... を入力してください';
    case 'insecure': return '暗号化されていない ws:// は、この端末 (localhost) 以外には使えません (ポート開放トラッカーは oz-tracker:... を使用してください)';
    case 'credentials': return 'URL にユーザー名やパスワードを含めないでください';
    case 'query': return 'URL に ? 以降 (クエリ) を含めないでください';
    case 'fragment': return 'URL に # 以降を含めないでください';
  }
}

/**
 * ICE (STUN) サーバの決め方。
 *
 * ★ トラッカー（Deno Deploy 等）は UDP 3478 をリッスンしないため、
 *   世界規模で常時稼働する Google の Anycast STUN クラスタ (IPv4/IPv6 両対応) を
 *   既定値として使用する。STUN は自ノードの外向きポートを調べるだけの 1 パケット通信であり、
 *   通信相手やデータ本体は一切送信されない。
 *
 *   - 明示の設定があればそれ (`stun:` の URL のみ。TURN は資格情報の扱いが決まるまで受け付けない)
 *   - 無ければ Google Anycast STUN クラスタ (`stun.l.google.com:19302` 等) を使う
 */

export const DEFAULT_STUN_PORT = 3478;
export const ICE_SERVERS_MAX = 4;
const ICE_URL_MAX_LENGTH = 256;

export type IceServersResult = { ok: true; servers: string[] } | { ok: false; reason: string };

/**
 * 異なる AS (Google AS15169 / Cloudflare AS13335) かつ別ポートの厳選 2 重 Anycast STUN。
 * 3 個以上は候補ペア数が二乗で増え、RFC 8445 Ta タイマー遅延と NAT テーブル枯渇を招くため、
 * 研究知見に基づく最適解として 2 系統を指定する。
 */
export const DEFAULT_PUBLIC_STUN_SERVERS = [
  'stun:stun.l.google.com:19302',
  'stun:stun.cloudflare.com:3478',
] as const;

export const GOOGLE_STUN_SERVERS = DEFAULT_PUBLIC_STUN_SERVERS;

export const DEFAULT_STUN_SERVER = 'stun:stun.l.google.com:19302';

/** `stun:host[:port]` だけを通す。turn: / turns: / stuns: とクエリ付きは拒否 */
export function parseIceServerUrl(input: string): string | null {
  const raw = input.trim();
  if (raw.length === 0 || raw.length > ICE_URL_MAX_LENGTH) return null;
  const m = /^stun:(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.-]+)(?::(\d{1,5}))?$/.exec(raw);
  if (!m) return null;
  if (m[2] !== undefined) {
    const port = Number(m[2]);
    if (port < 1 || port > 65535) return null;
  }
  return raw;
}

/** カンマ区切りの `stun:` URL 列を検証する。空文字・未指定は「設定なし」(servers: []) */
export function parseIceServers(input: string | readonly string[] | null | undefined): IceServersResult {
  if (input === null || input === undefined) return { ok: true, servers: [] };
  const parts = (typeof input === 'string' ? input.split(',') : [...input]).map((s) => s.trim()).filter((s) => s.length > 0);
  if (parts.length > ICE_SERVERS_MAX) return { ok: false, reason: `ICE servers: at most ${ICE_SERVERS_MAX}` };
  const servers: string[] = [];
  for (const p of parts) {
    if (/^turns?:/i.test(p)) return { ok: false, reason: 'ICE servers: turn: is not supported (stun: only)' };
    const ok = parseIceServerUrl(p);
    if (!ok) return { ok: false, reason: `ICE servers: invalid stun URL "${p.slice(0, 64)}"` };
    servers.push(ok);
  }
  return { ok: true, servers };
}

import { resolveTrackerWebSocketUrl } from './TrackerUrl';

/** トラッカー URL (wss://host:443/ws または oz-tracker:...) から stun:host:3478 を導く。URL が無い・不正なら null */
export function deriveStunFromTracker(trackerUrl: string | null | undefined, port: number = DEFAULT_STUN_PORT): string | null {
  if (!trackerUrl) return null;
  try {
    const resolved = resolveTrackerWebSocketUrl(trackerUrl);
    const host = new URL(resolved).hostname; // IPv6 は "[::1]" の形で返る
    return host ? `stun:${host}:${port}` : null;
  } catch {
    return null;
  }
}

/** 実際に RTCPeerConnection へ渡す一覧。明示設定があればそれを使い、無ければ Google STUN クラスタを使用 */
export function resolveIceServers(
  explicit: readonly string[] | null | undefined,
  _trackerUrl?: string | null | undefined,
): RTCIceServer[] {
  if (explicit && explicit.length > 0) return explicit.map((urls) => ({ urls }));
  return [{ urls: [...GOOGLE_STUN_SERVERS] }];
}

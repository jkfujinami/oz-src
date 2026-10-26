import { parseIceServers, parseTrackerUrl, type IndexedDBStore } from '@oz/core';

/**
 * トラッカー URL の保存。
 *
 * 公式のトラッカーは無いので、利用者が設定した値を暗号化された端末 DB に保存する
 * (どのネットワークに参加しているかの手掛かりになるため、平文では置かない)。
 *
 *   - 保存値が { url: 文字列 } → その URL
 *   - 保存値が { url: null }   → 利用者が明示的に消した。既定値にも戻さない
 *   - 保存値が無い             → アプリが渡した既定値 (fallback) があればそれ、無ければ未設定
 *
 * 既定値はアプリごとに決める (OzApp の defaultTrackerUrl):
 *   - Desktop: ビルド時の VITE_OZ_TRACKER_URL (開発用。配布物に入れると全利用者が
 *     その相手に接続するので、入れるなら運営者と配布元を明示すること)
 *   - Web: ページを配信したサーバ自身の /ws (ページの取得時点でそのサーバには IP が見えている)
 * どちらも検証を通らなければ使わない。
 */
export const TRACKER_SETTING = 'trackerUrl';

/**
 * 用意してあるトラッカー。標準は Deno Deploy (複数の Isolate を BroadcastChannel で同期する)。
 * 利用者が自分で設定したトラッカーがあれば、そちらが優先される。
 */
export const STANDARD_TRACKERS = {
  cloudflare: 'wss://ozzy-r2-gatekeeper.jkfujinamis.workers.dev/ws',
  deno: 'wss://ozzy-tracker.jkfujinami.deno.net/ws',
} as const;

/** 利用者がトラッカーを設定していないときの既定 */
export const DEFAULT_TRACKER_URL = STANDARD_TRACKERS.cloudflare;

function validOrNull(url: unknown): string | null {
  if (typeof url !== 'string') return null;
  const parsed = parseTrackerUrl(url);
  return parsed.ok ? parsed.url : null;
}

/** 保存形式。null をそのまま保存すると「未保存」と区別できないので包む */
interface StoredTracker {
  url: string | null;
}

export async function loadTrackerUrl(
  db: Pick<IndexedDBStore, 'getSetting'>,
  fallback: string | null = null,
): Promise<string | null> {
  const saved = await db.getSetting<StoredTracker>(TRACKER_SETTING);
  if (saved === undefined) return validOrNull(fallback);
  return typeof saved === 'object' && saved !== null ? validOrNull(saved.url) : null;
}

export async function saveTrackerUrl(db: Pick<IndexedDBStore, 'setSetting'>, url: string | null): Promise<void> {
  const value: StoredTracker = { url };
  await db.setSetting(TRACKER_SETTING, value);
}

/**
 * ビルド時の環境変数 (VITE_OZ_ICE_SERVERS / NEXT_PUBLIC_OZ_ICE_SERVERS) から STUN の一覧を作る。
 * カンマ区切りの `stun:host[:port]` のみ。未設定なら null (= Google と Cloudflare の公開 STUN)。
 *
 * ★ 不正な値 (turn: を含む等) は黙って捨てて null (既定の公開 STUN) に戻す。TURN は資格情報の扱いが決まるまで未対応。
 */
export function iceServersFromEnv(raw: string | undefined): string[] | null {
  if (!raw || raw.trim() === '') return null;
  const parsed = parseIceServers(raw);
  if (!parsed.ok) {
    console.warn(`[oz] ICE servers setting ignored: ${parsed.reason}`);
    return null;
  }
  return parsed.servers.length > 0 ? parsed.servers : null;
}

/**
 * 利用者が設定画面で選んだ STUN の保存 (暗号化された端末 DB)。
 *
 *   - 保存値が { servers: [...] } → その一覧 (stun: のみ、4 つまで)
 *   - 保存値が { servers: null } か、保存値が無い → 既定 (ビルド時の指定、無ければ公開 STUN)
 *
 * ★ どの STUN を使うかは、どのネットワークに参加しているかの手掛かりになるので平文では置かない。
 */
export const ICE_SETTING = 'iceServers';

interface StoredIce {
  servers: string[] | null;
}

/** 保存された STUN の一覧。保存が無い・既定に戻した・壊れている → null (既定を使う) */
export async function loadIceServers(db: Pick<IndexedDBStore, 'getSetting'>): Promise<string[] | null> {
  const saved = await db.getSetting<StoredIce>(ICE_SETTING);
  if (!saved || typeof saved !== 'object' || !Array.isArray(saved.servers)) return null;
  const parsed = parseIceServers(saved.servers);
  return parsed.ok && parsed.servers.length > 0 ? parsed.servers : null;
}

export async function saveIceServers(db: Pick<IndexedDBStore, 'setSetting'>, servers: string[] | null): Promise<void> {
  const value: StoredIce = { servers: servers && servers.length > 0 ? servers : null };
  await db.setSetting(ICE_SETTING, value);
}

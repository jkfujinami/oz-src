import { DEFAULT_TRACKER_URL as STANDARD_DEFAULT_TRACKER, guardTrustFromEnv, iceServersFromEnv } from '@oz/ui';

/*
 * デスクトップ版の画面 (main.tsx) と、この端末で動かす Guard (guard.ts) で共通の設定。
 * どれもビルド時の値 (秘密ではない)。
 */

/**
 * トラッカーの既定値 (標準は Deno Deploy。ビルド時に VITE_OZ_TRACKER_URL で差し替えられる)。
 * 配布物に入れると全利用者がその相手に接続するので、運営者と配布元を明示すること。検証を通らない値は使われない。
 */
export const DEFAULT_TRACKER_URL: string | null =
  import.meta.env.VITE_OZ_TRACKER_URL || STANDARD_DEFAULT_TRACKER;

/**
 * 信頼 Guard の設定 (ビルド時の環境変数)。
 *
 * メンテナの公開鍵を組み込むと、審査済みの Guard だけを 1 ホップ目に使う。
 * 未設定・不正なら信頼設定なしで起動し、画面に「信頼 Guard 未設定」の警告を出す。
 * 公開鍵は秘密ではないので平文で良い。鍵の組み方は guard-maintainer の pubkey コマンドを参照。
 */
export const GUARD_TRUST = guardTrustFromEnv({
  maintainerKeys: import.meta.env.VITE_OZ_MAINTAINER_KEYS,
  maintainerThreshold: import.meta.env.VITE_OZ_MAINTAINER_THRESHOLD,
  guardList: import.meta.env.VITE_OZ_GUARD_LIST,
});

/**
 * STUN サーバ (ビルド時の環境変数。カンマ区切りの stun: URL)。未設定なら Google と Cloudflare の公開 STUN
 * (core の DEFAULT_PUBLIC_STUN_SERVERS)。★ STUN の運営者には利用者の IP と接続の時刻が伝わる。
 */
export const ICE_SERVERS = iceServersFromEnv(import.meta.env.VITE_OZ_ICE_SERVERS);


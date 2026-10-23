/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_OZ_TRACKER_URL?: string;
  /** STUN サーバ (カンマ区切りの stun: URL)。未設定なら Google と Cloudflare の公開 STUN。turn: は不可 */
  readonly VITE_OZ_ICE_SERVERS?: string;
  /** メンテナの公開鍵 (カンマ区切り、base64url)。未設定なら信頼 Guard 無効 (オープン動作) */
  readonly VITE_OZ_MAINTAINER_KEYS?: string;
  /** 必要な署名の数。未設定なら 1 */
  readonly VITE_OZ_MAINTAINER_THRESHOLD?: string;
  /** 初期の Guard リスト (任意) */
  readonly VITE_OZ_GUARD_LIST?: string;
}

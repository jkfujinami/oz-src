import { createLogger, type MaintainerKeySet } from '@oz/core';

const log = createLogger('ui.guard');

/**
 * 信頼 Guard の設定 (ビルド時に与える)。
 *
 * ★ メンテナの公開鍵はアプリに組み込む。鍵を組み込まなければ、リストは常に拒否され
 *   Guard はオープン動作 (警告表示) になる。公開鍵は秘密ではないので平文で良い。
 */
export interface GuardTrustConfig {
  maintainerKeys: MaintainerKeySet;
  /** 設定で与える Guard リスト (保存済みのものより版が高ければ採用される) */
  guardList?: string;
}

/** ビルド時の環境変数の値。未設定は undefined */
export interface GuardEnv {
  /** カンマ区切りの公開鍵 (base64url、パディングなし、各 32 バイト) */
  maintainerKeys?: string;
  /** 必要な署名の数。未設定なら 1 */
  maintainerThreshold?: string;
  /** 初期の Guard リスト (任意) */
  guardList?: string;
}

const PUBKEY_BYTES = 32;
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

/** base64url (パディングなし) を解く。形式が違えば null */
function decodeBase64Url(text: string): Uint8Array | null {
  if (!BASE64URL_RE.test(text)) return null;
  // atob は標準の base64 だけを受けるので、記号を戻してパディングを付ける
  const std = text.replace(/-/g, '+').replace(/_/g, '/');
  const padded = std + '='.repeat((4 - (std.length % 4)) % 4);
  try {
    const bin = atob(padded);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

/**
 * 環境変数から公開鍵の組を作る。
 *
 * 鍵が未設定、または形式・閾値が不正なら null (信頼設定なし = オープン動作)。
 * 不正な値を黙って捨てると運用者が気付けないので、理由をログに残す。
 */
export function parseMaintainerKeySet(keysText: string | undefined, thresholdText: string | undefined): MaintainerKeySet | null {
  const raw = keysText?.trim();
  if (!raw) return null;

  const keys: Uint8Array[] = [];
  for (const part of raw.split(',')) {
    const key = decodeBase64Url(part.trim());
    if (!key || key.length !== PUBKEY_BYTES) {
      log.warn('maintainer key is malformed; trusted guards are disabled');
      return null;
    }
    keys.push(key);
  }
  if (keys.length === 0) return null;

  // 閾値は未設定なら 1。指定されたのに整数でない、範囲外なら設定を無効にする
  const thresholdRaw = thresholdText?.trim();
  const threshold = thresholdRaw ? Number(thresholdRaw) : 1;
  if (!Number.isInteger(threshold) || threshold < 1 || threshold > keys.length) {
    log.warn('maintainer threshold is out of range; trusted guards are disabled');
    return null;
  }
  return { threshold, keys };
}

/** 環境変数から信頼設定を作る。鍵が無い・不正なら null (そのときはオープン動作) */
export function guardTrustFromEnv(env: GuardEnv): GuardTrustConfig | null {
  const maintainerKeys = parseMaintainerKeySet(env.maintainerKeys, env.maintainerThreshold);
  if (!maintainerKeys) return null;
  const guardList = env.guardList?.trim();
  return guardList ? { maintainerKeys, guardList } : { maintainerKeys };
}

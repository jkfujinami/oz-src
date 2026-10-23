/**
 * この端末で動かす Guard の、ウィンドウ (guard.ts)・メインプロセス (electron/guardHost.ts)・画面の間のやり取り。
 */

/** Guard のウィンドウがメインへ送る状態。★ 件数だけ。利用者の peerId や IP は含めない */
export interface GuardReport {
  /** この Guard の peerId (信頼リストに載る公開の値) */
  peerId: string;
  /** メンテナに渡す Guard 文字列 (oz-guard:...) */
  guardString: string;
  /** 使える信頼リストを持っているか */
  hasList: boolean;
  /** この Guard が信頼リストに載っているか */
  listed: boolean;
  listVersion: number | null;
  counts: { degree: number; clients: number; backbone: number; tunnels: number };
}

/** Guard のウィンドウを始めるときにメインから渡すもの */
export interface GuardStartConfig {
  /** 身元 (Guard の DB) を封印するパスフレーズ。OS の鍵の保管庫で守ったものを、起動のたびに渡す */
  passphrase: string;
  /** 預かる枠の数 (1 枠 = 256MiB) */
  slots: number;
}

/** 画面に見せる、この端末の Guard の状態 */
export interface DesktopGuardStatus {
  /** この端末で Guard を動かせるか (OS の鍵の保管庫が使えるか) */
  available: boolean;
  unavailableReason: string | null;
  enabled: boolean;
  starting: boolean;
  running: boolean;
  openAtLogin: boolean;
  slots: number;
  report: GuardReport | null;
  error: string | null;
}

export const GUARD_SLOTS_MIN = 1;
export const GUARD_SLOTS_MAX = 64;

const isCount = (v: unknown): v is number => typeof v === 'number' && Number.isInteger(v) && v >= 0;

/** Guard のウィンドウから届いた状態の形を確かめる (メインは渡されたものをそのまま信じない) */
export function isGuardReport(x: unknown): x is GuardReport {
  if (!x || typeof x !== 'object') return false;
  const r = x as Record<string, unknown>;
  const c = r.counts as Record<string, unknown> | undefined;
  return (
    typeof r.peerId === 'string' && /^[0-9a-f]{32}$/.test(r.peerId) &&
    typeof r.guardString === 'string' && r.guardString.startsWith('oz-guard:') && r.guardString.length < 4096 &&
    typeof r.hasList === 'boolean' && typeof r.listed === 'boolean' &&
    (r.listVersion === null || isCount(r.listVersion)) &&
    !!c && isCount(c.degree) && isCount(c.clients) && isCount(c.backbone) && isCount(c.tunnels)
  );
}

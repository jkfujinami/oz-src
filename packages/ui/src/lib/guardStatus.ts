import type { GuardStatus, GuardListResult } from '@oz/core';
import { t } from '../i18n';

/**
 * Guard (1 ホップ目) の状態を、画面に出す文言に変える。
 *
 * ★ 表示は利用者が判断できる言葉にする。警告状態 (fallback / open) は匿名性が弱いことを
 *   隠さず、通常状態 (trusted) と待ち状態 (none + waiting-*) は警告に見えないようにする。
 */

export type GuardTone = 'calm' | 'warn' | 'pending';

export interface GuardView {
  tone: GuardTone;
  /** ヘッダーのボタンに出す短い文言 */
  label: string;
  /** パネルの見出し */
  headline: string;
  /** パネルの説明 (1 文ずつ) */
  details: string[];
}

/** 送信を待たせている「準備中」の理由。これ以外の none は警告として扱う */
const WAITING_REASONS = new Set(['waiting-for-trusted-guard', 'waiting-for-candidates']);

export function describeGuardStatus(status: GuardStatus): GuardView {
  switch (status.mode) {
    case 'trusted':
      return {
        tone: 'calm',
        label: t('guard.trusted.label'),
        headline: t('guard.trusted.headline'),
        details: [
          t('guard.trusted.detail1'),
        ],
      };

    case 'fallback':
      return {
        tone: 'warn',
        label: t('guard.fallback.label'),
        headline: t('guard.fallback.headline'),
        details: [
          t('guard.fallback.detail1'),
          reasonText(status.reason) ?? t('guard.fallback.detail2'),
        ],
      };

    case 'open':
      return {
        tone: 'warn',
        label: t('guard.open.label'),
        headline: t('guard.open.headline'),
        details: [
          t('guard.open.detail1'),
          t('guard.open.detail2'),
        ],
      };

    case 'none':
    default: {
      // リストの期限切れ: 信頼 Guard は使えず、普通の隣人での経路を準備している。
      // ★ 「送信されません」と書かない。準備が整えば送信される (送信元を隠す力が弱い状態で)。
      if (status.reason === 'list-expired') {
        return {
          tone: 'warn',
          label: t('guard.expired.label'),
          headline: t('guard.expired.headline'),
          details: [
            reasonText(status.reason)!,
            t('guard.expired.detail2'),
          ],
        };
      }
      // 起動直後の待ち (正常)。待ちの理由が無い、または待ち以外の理由なら警告にする
      if (status.reason && !WAITING_REASONS.has(status.reason)) {
        return {
          tone: 'warn',
          label: t('guard.noRoute.label'),
          headline: t('guard.noRoute.headline'),
          details: [reasonText(status.reason) ?? t('guard.noRoute.detail1')],
        };
      }
      return {
        tone: 'pending',
        label: t('guard.pending.label'),
        headline: t('guard.pending.headline'),
        details: [
          t('guard.pending.detail1'),
          t('guard.pending.detail2'),
        ],
      };
    }
  }
}

/** 状態の理由 (GuardStatus.reason) の説明。知らない値なら null */
export function reasonText(reason: string | undefined): string | null {
  switch (reason) {
    case 'list-expired':
      return t('guard.reason.listExpired');
    case 'no-list':
      return t('guard.reason.noList');
    case 'waiting-for-trusted-guard':
      return t('guard.reason.waitingTrusted');
    case 'waiting-for-candidates':
      return t('guard.reason.waitingCandidates');
    case 'no-trusted-guard-connected':
      return t('guard.reason.noTrustedConnected');
    default:
      return null;
  }
}

/** リストの取り込み失敗の理由を、利用者向けの日本語にする */
export function importFailureText(reason: Extract<GuardListResult, { ok: false }>['reason']): string {
  switch (reason) {
    case 'malformed':
      return t('guard.import.malformed');
    case 'too-large':
      return t('guard.import.tooLarge');
    case 'no-keyset':
      return t('guard.import.noKeyset');
    case 'insufficient-signatures':
      return t('guard.import.insufficientSignatures');
    case 'rollback':
      return t('guard.import.rollback');
    case 'expired':
      return t('guard.import.expired');
    case 'not-yet-valid':
      return t('guard.import.notYetValid');
    case 'validity-too-long':
      return t('guard.import.validityTooLong');
    case 'bad-guard':
      return t('guard.import.badGuard');
    case 'too-many-guards':
      return t('guard.import.tooManyGuards');
    default:
      return t('guard.import.default');
  }
}

/**
 * 投稿の前に確認を挟むべき状態か。
 *
 * ★ 最初の中継が審査されていない普通の隣人になる状態 (fallback / open) では、投稿の送信元が
 *   辿られやすい。利用者が知らないまま書き込まないよう、送る前に明示して選ばせる。
 *   準備中 (none + 待ちの理由) は対象外: 信頼 Guard が整うまで自動で待つので、弱い経路では出ない。
 *   リスト期限切れ (none + list-expired) は、準備が整うと普通の隣人経由で送られるので対象にする。
 */
export function needsWeakRouteConfirmation(status: GuardStatus): boolean {
  if (status.mode === 'fallback' || status.mode === 'open') return true;
  return status.mode === 'none' && status.reason === 'list-expired';
}

/** 確認ダイアログの文言 (平易な日本語)。言語に合わせて引くので getter */
export const WEAK_ROUTE_CONFIRM_TEXT = {
  get title() { return t('guard.weakConfirm.title'); },
  get body() {
    return [t('guard.weakConfirm.body1'), t('guard.weakConfirm.body2'), t('guard.weakConfirm.body3')];
  },
  get proceed() { return t('guard.weakConfirm.proceed'); },
  get cancel() { return t('guard.weakConfirm.cancel'); },
};

import type { GuardStatus, GuardListResult } from '@oz/core';

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
        label: '信頼 Guard 経由',
        headline: '信頼 Guard 経由で接続しています。',
        details: [
          '最初の中継は、メンテナが審査したリストに載っている Guard です。',
        ],
      };

    case 'fallback':
      return {
        tone: 'warn',
        label: '警告: 信頼 Guard に未接続',
        headline: '信頼 Guard に接続できていません。',
        details: [
          '最初の中継は審査されていない普通の隣人です。送信元を隠す力が弱くなっています。',
          reasonText(status.reason) ?? '信頼 Guard への接続が戻れば、自動で切り替わります。',
        ],
      };

    case 'open':
      return {
        tone: 'warn',
        label: '警告: 信頼 Guard 未設定',
        headline: '信頼 Guard のリストが設定されていません。',
        details: [
          '最初の中継は審査されていない普通の隣人です。送信元を隠す力が弱くなっています。',
          'この版のアプリにはメンテナの公開鍵が組み込まれていないか、リストが取り込まれていません。',
        ],
      };

    case 'none':
    default: {
      // リストの期限切れ: 信頼 Guard は使えず、普通の隣人での経路を準備している。
      // ★ 「送信されません」と書かない。準備が整えば送信される (送信元を隠す力が弱い状態で)。
      if (status.reason === 'list-expired') {
        return {
          tone: 'warn',
          label: '警告: 信頼リストが期限切れ',
          headline: '信頼リストが期限切れのため、普通の隣人での匿名経路を準備しています。',
          details: [
            reasonText(status.reason)!,
            '準備が整うと投稿は送信されますが、送信元を隠す力は弱い状態です。',
          ],
        };
      }
      // 起動直後の待ち (正常)。待ちの理由が無い、または待ち以外の理由なら警告にする
      if (status.reason && !WAITING_REASONS.has(status.reason)) {
        return {
          tone: 'warn',
          label: '警告: 匿名経路を確立できません',
          headline: '匿名経路を作れていないため、投稿は送信されません。',
          details: [reasonText(status.reason) ?? '原因が解消されるまでお待ちください。'],
        };
      }
      return {
        tone: 'pending',
        label: '匿名経路を準備中…',
        headline: '匿名経路を準備しています。',
        details: [
          '起動直後は数十秒ほどかかることがあります。通常の準備で、エラーではありません。',
          '準備が整うまで、投稿は送信されずに待ちます。',
        ],
      };
    }
  }
}

/** 状態の理由 (GuardStatus.reason) の説明。知らない値なら null */
export function reasonText(reason: string | undefined): string | null {
  switch (reason) {
    case 'list-expired':
      return '受け入れていた信頼リストが期限切れです。新しいリストを取り込んでください。';
    case 'no-list':
      return '信頼リストがまだありません。';
    case 'waiting-for-trusted-guard':
      return '信頼 Guard への接続を待っています。';
    case 'waiting-for-candidates':
      return '接続先の候補を集めています。';
    case 'no-trusted-guard-connected':
      return '信頼リストに載っている Guard に、いま接続できていません。';
    default:
      return null;
  }
}

/** リストの取り込み失敗の理由を、利用者向けの日本語にする */
export function importFailureText(reason: Extract<GuardListResult, { ok: false }>['reason']): string {
  switch (reason) {
    case 'malformed':
      return 'リストの形式が正しくありません';
    case 'too-large':
      return 'リストが大きすぎます';
    case 'no-keyset':
      return 'この版のアプリにはメンテナの公開鍵が組み込まれていません';
    case 'insufficient-signatures':
      return 'メンテナの署名が足りません';
    case 'rollback':
      return '手元のリストより古い版です';
    case 'expired':
      return '期限切れのリストです';
    case 'not-yet-valid':
      return 'まだ有効になっていないリストです (発行時刻が未来です)';
    case 'validity-too-long':
      return '有効期間が長すぎるリストです';
    case 'bad-guard':
      return 'Guard の記述に問題があります (署名か形式を確認してください)';
    case 'too-many-guards':
      return 'Guard の数が上限を超えています';
    default:
      return 'リストを取り込めませんでした';
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

/** 確認ダイアログの文言 (平易な日本語) */
export const WEAK_ROUTE_CONFIRM_TEXT = {
  title: '送信元が特定されやすい状態です',
  body: [
    '今は、最初の中継が審査されていない普通の相手になっています (信頼できる中継に接続できていません)。',
    'この状態で書き込むと、悪意のある相手に当たった場合、この投稿があなたから送られたと突き止められやすくなります。',
    '信頼できる中継に接続できるまで待つと、より安全に投稿できます。',
  ],
  proceed: 'それでも投稿する',
  cancel: 'やめる',
} as const;

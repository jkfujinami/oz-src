import { POW_POLICY, ThreadClosedError, createLogger } from '@oz/core';

const log = createLogger('ui.postLimit');

/**
 * 本文 1 件の上限 (UTF-8 バイト)。core が送信時にも同じ値で弾く (RangeError) ので、
 * ここでは入力中に見せて、送信前に止めるためだけに使う。
 */
export const MAX_POST_BYTES: number = POW_POLICY.MAX_CONTENT_BYTES;

/** 残りがこの割合を下回ったら、残量を目立たせる */
const NEAR_LIMIT_RATIO = 0.1;

const encoder = new TextEncoder();

export interface ByteBudget {
  /** UTF-8 のバイト数 */
  used: number;
  /** 残りバイト数 (超えているときは負の値) */
  remaining: number;
  /** 上限を超えている */
  over: boolean;
  /** 残りが少ない (超過も含む) */
  nearLimit: boolean;
}

/**
 * 入力文字列のバイト数を数える。日本語は 1 文字 3 バイトなので、文字数では数えない。
 */
export function byteBudget(text: string): ByteBudget {
  const used = encoder.encode(text).length;
  const remaining = MAX_POST_BYTES - used;
  return {
    used,
    remaining,
    over: remaining < 0,
    nearLimit: remaining < MAX_POST_BYTES * NEAR_LIMIT_RATIO,
  };
}

/** 残りバイトの表示文言。例: 「残り 1,234 バイト」 */
export function remainingLabel(budget: ByteBudget): string {
  if (budget.over) return `上限を ${(-budget.remaining).toLocaleString('ja-JP')} バイト超えています`;
  return `残り ${budget.remaining.toLocaleString('ja-JP')} バイト`;
}

/**
 * 送信が失敗したときに画面へ出す文言。入力内容は呼び出し側が残すこと。
 * 上限超過は core が RangeError で投げるので、それだけは理由を具体的に言う。
 */
export function describeSubmitError(err: unknown, subject: string): string {
  log.error('submit failed:', err);
  if (err instanceof ThreadClosedError) return describeThreadClosed(err.reason);
  if (err instanceof RangeError) {
    return `${subject}は ${MAX_POST_BYTES} バイトまでです。送信されていません。内容は残してあります。`;
  }
  return '送信できませんでした。内容は残してあります。少し待ってから、もう一度お試しください。';
}

/** スレッドに書けないときの文言 (ThreadClosedError の理由ごと) */
export function describeThreadClosed(reason: ThreadClosedError['reason']): string {
  switch (reason) {
    case 'closed':
    case 'full-posts':
      return 'このスレッドは上限に達したので、書き込めませんでした。内容は残してあります。新しいスレッドを立ててください。';
    case 'full-bytes':
      return 'この書き込みを足すと、スレッドの容量の上限を超えます。送信されていません。内容を短くするか、新しいスレッドに書いてください。';
    case 'expired':
      return 'このスレッドは落ちているので、書き込めませんでした。内容は残してあります。';
  }
}

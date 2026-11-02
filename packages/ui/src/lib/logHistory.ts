import { LogHistory, resetLevels } from '@oz/core';

/**
 * 画面の「状態とログ」が見せるログ (直近 5,000 行・メモリだけ)。
 *
 * ★ 起動したときから集める (画面を開く前に出た警告も見られるように)。端末には書かない。
 * ★ ロック (画面が消える) で行を消し、画面から変えた記録の細かさも既定に戻す (forgetLogs)。
 */
export const appLogHistory = new LogHistory();

export function startLogHistory(): void {
  appLogHistory.start();
}

export function forgetLogs(): void {
  appLogHistory.clear();
  resetLevels();
}

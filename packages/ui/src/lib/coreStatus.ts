import type { StatusParams } from '@oz/core';
import { t } from '../i18n';

/** core の状態 (BoardStatus / ThreadStatus)。core は画面の文を作らず、種類 (code) と数 (params) を返す */
export interface CoreStatusLike {
  code: string;
  params?: StatusParams;
  /** 日本語の既定文。code を知らないときだけ使う */
  message: string;
}

/** 過去ログの取得中の文。進み具合 (done/total) と件数 (count) があれば添える */
function historyText(params: StatusParams | undefined): string {
  const hasStep = params?.done !== undefined && params?.total !== undefined;
  const hasCount = params?.count !== undefined;
  if (hasStep && hasCount) return t('core.common.historyStepCount', { done: params.done, total: params.total, count: params.count });
  if (hasStep) return t('core.common.historyStep', { done: params.done, total: params.total });
  if (hasCount) return t('core.common.historyCount', { count: params.count });
  return t('core.common.historyFetching');
}

/**
 * core の状態を、画面に出す文にする。知らない code は core の message (日本語の既定文) をそのまま出す。
 * ★ core の message と同じ文を ja.yaml の core.* に置いてある (core の文面を変えたら、ここも直す)。
 */
export function describeCoreStatus(s: CoreStatusLike): string {
  const p = s.params;
  switch (s.code) {
    case 'none': return '';
    case 'initializing': return t('core.common.initializing');
    case 'history-fetching': return historyText(p);
    case 'congestion': return t('core.common.congestion');
    case 'no-anonymous-route': return t('core.common.noAnonymousRoute');
    // 板
    case 'connecting-neighbors': return t('core.board.connectingNeighbors');
    case 'syncing-neighbors': return t('core.board.syncingNeighbors', { degree: p?.degree ?? 0 });
    case 'board-empty': return t('core.board.empty');
    case 'latest-failed': return t('core.board.latestFailed');
    case 'building-thread': return t('core.board.buildingThread');
    case 'spreading': return t('core.board.spreading');
    case 'create-failed': return t('core.board.createFailed');
    // スレッド
    case 'waiting-network': return t('core.thread.waitingNetwork');
    case 'syncing-peers': return t('core.thread.syncingPeers');
    case 'thread-empty': return t('core.thread.empty');
    case 'history-loading': return t('core.thread.historyLoading');
    case 'finding-neighbors': return t('core.thread.findingNeighbors');
    case 'sync-error': return t('core.thread.syncError');
    case 'pow-running': return t('core.thread.powRunning');
    case 'sent-waiting': return t('core.thread.sentWaiting');
    case 'computed-sending': return t('core.thread.computedSending');
    case 'send-failed': return t('core.thread.sendFailed', { error: p?.error ?? '' });
    default: return s.message;
  }
}

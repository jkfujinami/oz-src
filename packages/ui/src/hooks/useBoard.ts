"use client";

import { useEffect, useCallback, useSyncExternalStore } from 'react';
import { useP2P } from '../providers/P2PProvider';
import { type ThreadMeta, type BoardStatus, createLogger } from '@oz/core';
import { shareCode } from '../lib/boardKeys';
import { useBoardKey } from './useBoardKey';
import type { BoardSort } from '../lib/boardSort';
import { sortThreads } from '../lib/threadOrder';
import { navigate } from '../lib/route';
import { describeCoreStatus } from '../lib/coreStatus';
import { t, useLocale } from '../i18n';

const log = createLogger('ui.board');

const EMPTY_THREADS: ThreadMeta[] = [];
const IDLE_STATUS: BoardStatus = { phase: 'idle', code: 'initializing', message: '', isSubmitting: false, powProgress: 0 };

/**
 * useBoard
 *
 * ★ 購読を useSyncExternalStore に置き換えてある。
 *
 * 以前は `useEffect(() => orchestrator.subscribe(setThreads), [...])` という
 * 形だったが、これは React の外にあるストアを繋ぐ方法として取りこぼしが起きる。
 *
 *   - レンダーが走ってから effect が張られるまでの間に来た通知は失われる
 *   - StrictMode の二重実行や、購読の張り直しと通知の順序に結果が依存する
 *   - setState を「Reactの外」から呼ぶため、更新が落ちても何も警告が出ない
 *
 * useSyncExternalStore は購読直後にスナップショットを読み直すので、この窓が
 * 構造的に消える。代わりに getSnapshot は「変わらない限り同じ参照」を返す
 * 必要があり、その責任は BoardOrchestrator 側のキャッシュが負っている。
 */
export function useBoard(boardId: string, sort: BoardSort = 'heat') {
  useLocale(); // 言語が変わったら状態の文も作り直す
  const { boardOrchestrator, isReady, db } = useP2P();

  const boardKey = useBoardKey(boardId, db);

  const subscribeThreads = useCallback(
    (onChange: () => void) => {
      const wrapped = () => {
        log.trace('store changed -> re-render');
        onChange();
      };
      const unsub = boardOrchestrator?.subscribe(wrapped) ?? (() => {});
      return () => {
        unsub();
      };
    },
    [boardOrchestrator],
  );
  const getThreads = useCallback(
    () => {
      const t = boardOrchestrator?.getThreads() ?? EMPTY_THREADS;
      return t;
    },
    [boardOrchestrator],
  );

  const subscribeStatus = useCallback(
    (onChange: () => void) => boardOrchestrator?.subscribeStatus(onChange) ?? (() => {}),
    [boardOrchestrator],
  );
  const getStatus = useCallback(
    () => boardOrchestrator?.getStatus() ?? IDLE_STATUS,
    [boardOrchestrator],
  );

  const threads = useSyncExternalStore(subscribeThreads, getThreads, () => EMPTY_THREADS);
  const status = useSyncExternalStore(subscribeStatus, getStatus, () => IDLE_STATUS);

  // 板の活性化。アンマウント時に購読を畳む。
  useEffect(() => {
    if (!isReady || !boardOrchestrator || !boardKey) return;
    boardOrchestrator.activate(boardId, boardKey);
    return () => {
      boardOrchestrator.clear();
    };
  }, [boardId, boardOrchestrator, isReady, boardKey]);

  const submitThread = async (title: string, onFail?: (m: string) => void) => {
    if (!boardOrchestrator || !boardKey) return;

    const threadId = await boardOrchestrator.submitThread(boardId, boardKey, title);

    if (threadId) {
      // ★ 経路は URL に出さない (閲覧履歴に残るため)
      navigate({ board: boardId, thread: threadId });
    } else if (onFail) {
      onFail(t('core.board.createFailed'));
    }
  };

  const sortedThreads = sortThreads(threads, sort);

  return {
    threads: sortedThreads,
    status: describeCoreStatus(status),
    phase: status.phase,
    isSubmitting: status.isSubmitting ?? false,
    powProgress: status.powProgress ?? 0,
    submitThread,
    /** この板の鍵を持っているか (無ければ読めない) */
    hasKey: boardKey !== null,
    /** 他の人に渡す共有コード (利用者が明示的にコピーしたときだけ使う) */
    shareCode: boardKey ? shareCode(boardId, boardKey) : null,
  };
}

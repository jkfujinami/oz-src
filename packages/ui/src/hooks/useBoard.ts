"use client";

import { useEffect, useState, useCallback, useSyncExternalStore } from 'react';
import { useP2P } from '../providers/P2PProvider';
import { ThreadRanker, type ThreadMeta, type BoardStatus, createLogger } from '@oz/core';
import { resolveBoardKey, shareCode } from '../lib/boardKeys';
import { navigate } from '../lib/route';

const log = createLogger('ui.board');

const EMPTY_THREADS: ThreadMeta[] = [];
const IDLE_STATUS: BoardStatus = { phase: 'idle', message: '初期化中...', isSubmitting: false, powProgress: 0 };

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
export function useBoard(boardId: string) {
  const { boardOrchestrator, isReady, db } = useP2P();

  const [boardKey, setBoardKey] = useState<Uint8Array | null>(null);

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

  // 板の鍵の解決。鍵は URL ではなく、暗号化された端末 DB から引く。
  useEffect(() => {
    let cancelled = false;
    setBoardKey(null);
    resolveBoardKey(boardId, db).then((key) => {
      if (!cancelled) setBoardKey(key);
    });
    return () => { cancelled = true; };
  }, [boardId, db]);

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
      onFail('スレッドの作成に失敗しました');
    }
  };

  const sortedThreads = [...threads].sort((a, b) => {
    const scoreA = ThreadRanker.calculateScore(a.max_pow || 0, a.created_at);
    const scoreB = ThreadRanker.calculateScore(b.max_pow || 0, b.created_at);
    return scoreB - scoreA;
  });

  return {
    threads: sortedThreads,
    status: status.message,
    isSubmitting: status.isSubmitting ?? false,
    powProgress: status.powProgress ?? 0,
    submitThread,
    /** この板の鍵を持っているか (無ければ読めない) */
    hasKey: boardKey !== null,
    /** 他の人に渡す共有コード (利用者が明示的にコピーしたときだけ使う) */
    shareCode: boardKey ? shareCode(boardId, boardKey) : null,
  };
}

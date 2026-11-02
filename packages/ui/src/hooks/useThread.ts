"use client";

import { useEffect, useCallback, useSyncExternalStore } from 'react';
import { useP2P } from '../providers/P2PProvider';
import { type DAGPost, type ThreadStatus, type ThreadState, createLogger } from '@oz/core';
import { useBoardKey } from './useBoardKey';
import { markThreadRead } from '../lib/readThreads';
import { describeCoreStatus } from '../lib/coreStatus';
import { useLocale } from '../i18n';

const log = createLogger('ui.thread');

const EMPTY_POSTS: DAGPost[] = [];
const EMPTY_STATE: ThreadState = {
  visibleCount: 0, hiddenCount: 0, contentBytes: 0, closed: false,
  birthAt: null, lastPostAt: null, expiresAt: null, expired: false,
};
const IDLE_STATUS: ThreadStatus = { phase: 'idle', code: 'initializing', message: '', isSubmitting: false, powProgress: 0 };

/**
 * useThread
 *
 * ★ 購読を useSyncExternalStore に置き換えてある (理由は useBoard 参照)。
 *
 * 以前の `useEffect + subscribe(setPosts)` は、レンダーから effect が
 * 張られるまでの間に来た通知を取りこぼす。ゴシップは非同期にいつでも来るので、
 * 「受信はできているのに画面が更新されない」という形で表面化する。
 */
export function useThread(boardId: string, threadId: string) {
  useLocale(); // 言語が変わったら状態の文も作り直す
  const { isReady, threadOrchestrator, db } = useP2P();

  const subscribePosts = useCallback(
    (onChange: () => void) => {
      const wrapped = () => {
        log.trace('store changed -> re-render');
        onChange();
      };
      const unsub = threadOrchestrator?.subscribe(wrapped) ?? (() => {});
      return () => {
        unsub();
      };
    },
    [threadOrchestrator],
  );
  const getPosts = useCallback(
    () => {
      const p = threadOrchestrator?.getPosts() ?? EMPTY_POSTS;
      return p;
    },
    [threadOrchestrator],
  );

  const subscribeStatus = useCallback(
    (onChange: () => void) => threadOrchestrator?.subscribeStatus(onChange) ?? (() => {}),
    [threadOrchestrator],
  );
  const getStatus = useCallback(
    () => threadOrchestrator?.getStatus() ?? IDLE_STATUS,
    [threadOrchestrator],
  );

  // スレッドの状態 (埋まった・落ちた等)。通知は posts と共通 (notify で両方作り直す)
  const getThreadState = useCallback(
    () => threadOrchestrator?.getThreadState() ?? EMPTY_STATE,
    [threadOrchestrator],
  );
  const threadState = useSyncExternalStore(subscribePosts, getThreadState, () => EMPTY_STATE);

  const posts = useSyncExternalStore(subscribePosts, getPosts, () => EMPTY_POSTS);
  const statusObj = useSyncExternalStore(subscribeStatus, getStatus, () => IDLE_STATUS);

  // 板の鍵 (いまの boardId のものだけ。切り替えた直後に前の板の鍵で開かない: useBoardKey)
  const boardKey = useBoardKey(boardId, db);

  // スレッドの活性化。アンマウント時に購読を畳む。
  useEffect(() => {
    if (!isReady || !threadOrchestrator || !boardKey) return;
    threadOrchestrator.activate(boardId, threadId, boardKey);
    // 一覧で「開いたことのあるスレ」として扱う (暗号化された端末 DB にだけ)
    void markThreadRead(db, boardId, threadId);

    return () => {
      threadOrchestrator.clear();
    };
  }, [boardId, threadId, isReady, threadOrchestrator, boardKey, db]);

  const submitReply = async (text: string) => {
    if (!text || !threadOrchestrator) return;
    await threadOrchestrator.submitReply(text);
  };

  /** `>>n` が指すレスの packet_id。書き手が見ていた範囲で解決する (core 参照) */
  const resolveAnchor = useCallback(
    (fromPacketId: string, n: number) => threadOrchestrator?.resolveAnchor(fromPacketId, n) ?? null,
    [threadOrchestrator],
  );

  const isSubmittingNow = statusObj.phase === 'submitting';

  return {
    posts,
    status: isSubmittingNow ? '' : describeCoreStatus(statusObj),
    postStatus: isSubmittingNow ? describeCoreStatus(statusObj) : '',
    isSubmitting: statusObj.isSubmitting ?? false,
    powProgress: statusObj.powProgress ?? 0,
    submitReply,
    threadState,
    resolveAnchor,
  };
}

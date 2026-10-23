"use client";

import { useEffect, useState, useCallback, useSyncExternalStore } from 'react';
import { useP2P } from '../providers/P2PProvider';
import { type DAGPost, type ThreadStatus, type ThreadState, createLogger } from '@oz/core';
import { resolveBoardKey } from '../lib/boardKeys';

const log = createLogger('ui.thread');

const EMPTY_POSTS: DAGPost[] = [];
const EMPTY_STATE: ThreadState = {
  visibleCount: 0, hiddenCount: 0, contentBytes: 0, closed: false,
  birthAt: null, lastPostAt: null, expiresAt: null, expired: false,
};
const IDLE_STATUS: ThreadStatus = { phase: 'idle', message: '初期化中...', isSubmitting: false, powProgress: 0 };

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

  // 板の鍵の解決。鍵は URL ではなく、暗号化された端末 DB から引く。
  const [boardKey, setBoardKey] = useState<Uint8Array | null>(null);
  useEffect(() => {
    let cancelled = false;
    setBoardKey(null);
    resolveBoardKey(boardId, db).then((key) => {
      if (!cancelled) setBoardKey(key);
    });
    return () => { cancelled = true; };
  }, [boardId, db]);

  // スレッドの活性化。アンマウント時に購読を畳む。
  useEffect(() => {
    if (!isReady || !threadOrchestrator || !boardKey) return;
    threadOrchestrator.activate(boardId, threadId, boardKey);

    return () => {
      threadOrchestrator.clear();
    };
  }, [boardId, threadId, isReady, threadOrchestrator, boardKey]);

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
    status: isSubmittingNow ? '' : statusObj.message,
    postStatus: isSubmittingNow ? statusObj.message : '',
    isSubmitting: statusObj.isSubmitting ?? false,
    powProgress: statusObj.powProgress ?? 0,
    submitReply,
    threadState,
    resolveAnchor,
  };
}

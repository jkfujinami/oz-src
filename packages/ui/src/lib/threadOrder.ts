import { ThreadRanker, type ThreadMeta } from '@oz/core';
import type { BoardSort } from './boardSort';

/** スレの最後の動き (端末が知っている最後の投稿。無ければスレ立て) */
export function lastActivity(t: ThreadMeta): number {
  return Math.max(t.last_post_at ?? 0, t.created_at || 0);
}

/** 勢い: PoW と新しさのスコア順。新着: 最後の動きの新しい順 */
export function sortThreads(threads: readonly ThreadMeta[], sort: BoardSort): ThreadMeta[] {
  if (sort === 'new') return [...threads].sort((a, b) => lastActivity(b) - lastActivity(a));
  const score = (t: ThreadMeta) => ThreadRanker.calculateScore(t.max_pow || 0, t.created_at);
  return [...threads].sort((a, b) => score(b) - score(a));
}

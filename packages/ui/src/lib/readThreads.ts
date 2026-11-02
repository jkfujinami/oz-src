import type { IndexedDBStore } from '@oz/core';

/** 板ごとに覚える「開いたスレ」の数の上限。超えたら古く開いたものから忘れる */
export const READ_THREADS_MAX = 2000;

const keyOf = (boardId: string) => `board.read.${boardId}`;

/**
 * 開いたことのあるスレ (一覧で開いていないスレを目立たせる)。
 * ★ 暗号化された端末 DB にだけ置く (網には出ない)。緊急消去で他のデータと一緒に消える。
 */
export async function loadReadThreads(db: IndexedDBStore | null, boardId: string): Promise<Set<string>> {
  if (!db) return new Set();
  try {
    const list = await db.getSetting<string[]>(keyOf(boardId));
    return new Set(Array.isArray(list) ? list.filter((x) => typeof x === 'string') : []);
  } catch {
    return new Set();
  }
}

export async function markThreadRead(db: IndexedDBStore | null, boardId: string, threadId: string): Promise<void> {
  if (!db) return;
  try {
    const prev = await db.getSetting<string[]>(keyOf(boardId));
    const list = (Array.isArray(prev) ? prev : []).filter((x) => x !== threadId);
    list.push(threadId);
    await db.setSetting(keyOf(boardId), list.slice(-READ_THREADS_MAX));
  } catch {
    // ロック中など: 印が付かないだけ
  }
}

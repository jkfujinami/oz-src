"use client";

import { useEffect, useState } from 'react';
import type { IndexedDBStore } from '@oz/core';
import { resolveBoardKey } from '../lib/boardKeys';

/**
 * 板の鍵を解決する。鍵は URL ではなく、暗号化された端末 DB から引く (公開板は ID から決まる)。
 *
 * ★ 返すのは**いまの boardId の**鍵だけ。解決した鍵を板 ID と組で持ち、組が合わなければ null を返す。
 *   鍵だけを state に持つと、板を切り替えた直後の 1 回の描画で「新しい板 ID + 前の板の鍵」になり、
 *   その組で板を開いてしまう。前の板の鍵では新しい板の投稿を復号できず、しかも「見た」印だけが残って
 *   正しい鍵で開き直しても一覧が空になっていた (雑談 → ファイル共有の切り替えでスレッドが出ない)。
 */
export function useBoardKey(boardId: string, db: IndexedDBStore | null): Uint8Array | null {
  const [resolved, setResolved] = useState<{ boardId: string; key: Uint8Array | null } | null>(null);
  useEffect(() => {
    let cancelled = false;
    resolveBoardKey(boardId, db).then((key) => {
      if (!cancelled) setResolved({ boardId, key });
    });
    return () => { cancelled = true; };
  }, [boardId, db]);
  return resolved !== null && resolved.boardId === boardId ? resolved.key : null;
}

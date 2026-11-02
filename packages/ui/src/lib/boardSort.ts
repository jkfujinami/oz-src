/** 板の一覧の並び順。この起動の間だけ覚える (板を移っても同じ並びで開く) */
export type BoardSort = 'heat' | 'new';

let current: BoardSort = 'heat';

export function getBoardSort(): BoardSort {
  return current;
}

export function setBoardSort(s: BoardSort): void {
  current = s;
}

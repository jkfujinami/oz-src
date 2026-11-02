/**
 * この起動中に作ったファイル共有のリンク (ファイル共有の画面を離れても一覧に残す)。
 * ★ メモリだけに持つ (端末に書かない)。リンクには復号の鍵が入るので、ロック (画面が消える) で消す (forgetOzzySession)。
 */
let items: readonly unknown[] = [];

export function getOzzySessionItems<T>(): T[] {
  return items.slice() as T[];
}

export function setOzzySessionItems<T>(next: readonly T[]): void {
  items = next;
}

export function forgetOzzySession(): void {
  items = [];
}

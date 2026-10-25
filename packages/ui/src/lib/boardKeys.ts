import { KeyManager, type IndexedDBStore } from '@oz/core';

/**
 * 鍵を共有しなくても誰でも読める公開板 (サイドバーに並べる順)。
 * 鍵は ID から決まる ({@link publicBoardKey}) ので、全員が同じ板を読み書きできる。
 * ★ ID を変えると別の板になる (前の ID の板の投稿は見えなくなる)。
 */
export const PUBLIC_BOARDS: ReadonlyArray<{ readonly id: string; readonly name: string }> = [
  { id: 'zatsudan', name: '雑談' },
  { id: 'files', name: 'ファイル共有スレッド' },
];

/** 起動したとき・板が分からないときに開く板 */
export const DEFAULT_BOARD_ID = PUBLIC_BOARDS[0].id;

const BOARD_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

/** 板 ID として使える形式か */
export function isBoardId(id: unknown): id is string {
  return typeof id === 'string' && BOARD_ID_RE.test(id);
}

/** 公開板か */
export function isPublicBoardId(id: string): boolean {
  return PUBLIC_BOARDS.some((b) => b.id === id);
}

/** 公開板の鍵 (`OZ/v1/public-board/<ID>` のハッシュの先頭 32 バイト)。公開板でなければ null */
export function publicBoardKey(id: string): Uint8Array | null {
  if (!isPublicBoardId(id)) return null;
  return KeyManager.cryptoHash(new TextEncoder().encode(`OZ/v1/public-board/${id}`)).slice(0, 32);
}

/** 画面に出す板の名前。公開板は名前、秘密の板は ID */
export function boardDisplayName(id: string): string {
  return PUBLIC_BOARDS.find((b) => b.id === id)?.name ?? id;
}

/** 新しい板 ID (暗号論的乱数) */
export function newBoardId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(6));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * 板の共有コード。受け取った人が貼り付けると、その板の鍵が端末の暗号化 DB に入る。
 *
 * ★ 鍵は URL に載せない。共有コードは利用者が明示的にコピーして渡すものだけ。
 */
export function shareCode(boardId: string, key: Uint8Array): string {
  return `board=${boardId}&key=${KeyManager.toBase64(key)}`;
}

/**
 * 共有コード (`board=..&key=..`) を解析する。不正なら null。
 * 先頭の `#` や、リンク全体 (`https://.../#board=..&key=..`) を貼られても、`#` より後ろだけを見る。
 */
export function parseShareCode(text: string): { boardId: string; key: Uint8Array } | null {
  const trimmed = text.trim();
  const hashAt = trimmed.indexOf('#');
  const params = new URLSearchParams(hashAt >= 0 ? trimmed.slice(hashAt + 1) : trimmed);
  const boardId = params.get('board');
  const keyB64 = params.get('key');
  if (!boardId || !keyB64 || !BOARD_ID_RE.test(boardId)) return null;
  try {
    const key = KeyManager.fromBase64(keyB64);
    return key.length === 32 ? { boardId, key } : null;
  } catch {
    return null;
  }
}

/**
 * 板の鍵を解決する。公開板は公開の鍵、それ以外は暗号化 DB に保存したもの。
 *
 * ★ 公開板は、端末に同じ ID の鍵が保存されていても公開の鍵を使う。
 *   公開板の ID を持つ共有コードを読み込ませて、公開板を別の板にすり替えさせないため。
 */
export async function resolveBoardKey(boardId: string, db: IndexedDBStore | null): Promise<Uint8Array | null> {
  const pub = publicBoardKey(boardId);
  if (pub) return pub;
  if (!db) return null;
  return db.getBoardKey(boardId).catch(() => null);
}

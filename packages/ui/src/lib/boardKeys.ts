import { KeyManager, type IndexedDBStore } from '@oz/core';

/** 鍵を共有しなくても誰でも読める公開板 */
export const DEFAULT_BOARD_ID = 'vip';

const BOARD_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

/** 板 ID として使える形式か */
export function isBoardId(id: unknown): id is string {
  return typeof id === 'string' && BOARD_ID_RE.test(id);
}

export function defaultBoardKey(): Uint8Array {
  return KeyManager.cryptoHash(new TextEncoder().encode('OZ_LITE_VIP_DEFAULT_SEED')).slice(0, 32);
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
 * 板の鍵を解決する。暗号化 DB に保存したもの → 公開板の既定鍵、の順に探す。
 */
export async function resolveBoardKey(boardId: string, db: IndexedDBStore | null): Promise<Uint8Array | null> {
  if (db) {
    const saved = await db.getBoardKey(boardId).catch(() => null);
    if (saved) return saved;
  }
  return boardId === DEFAULT_BOARD_ID ? defaultBoardKey() : null;
}

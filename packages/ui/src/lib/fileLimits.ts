/**
 * 添付ファイルの上限と表示まわり。
 *
 * ★ 上限はデスクトップ 2GiB、ブラウザ 512MiB (docs/design/file-sharing.md §7)。
 *   ブラウザは受け取ったファイルを Blob としてメモリに持つので、端末を固めないよう小さくしてある。
 *   デスクトップかどうかは P2PProvider と同じく Electron のプリロード (window.electronAPI) で見分ける。
 */
const MIB = 1024 ** 2;
const GIB = 1024 ** 3;

export const WEB_MAX_FILE_BYTES = 512 * MIB;
export const DESKTOP_MAX_FILE_BYTES = 2 * GIB;
/** 保管に出す枠の数 (1 枠 = 256MiB) の選べる範囲 */
export const WEB_MAX_SLOTS = 4;
export const DESKTOP_MAX_SLOTS = 16;
export const SLOT_BYTES = 256 * MIB;

/** 画面内に表示してよい画像の MIME と、その最大サイズ (取得後のみ) */
export const PREVIEW_MIMES: readonly string[] = ['image/png', 'image/jpeg', 'image/gif', 'image/webp'];
export const PREVIEW_MAX_BYTES = 8 * MIB;

export function isDesktop(): boolean {
  return typeof window !== 'undefined' && !!(window as any).electronAPI;
}
export const maxFileBytes = () => (isDesktop() ? DESKTOP_MAX_FILE_BYTES : WEB_MAX_FILE_BYTES);
export const maxSlots = () => (isDesktop() ? DESKTOP_MAX_SLOTS : WEB_MAX_SLOTS);

/** 例: 「12.3 MiB」 */
export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < MIB) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < GIB) return `${(n / MIB).toFixed(1)} MiB`;
  return `${(n / GIB).toFixed(2)} GiB`;
}

export function canPreview(mime: string, size: number): boolean {
  return PREVIEW_MIMES.includes(mime) && size <= PREVIEW_MAX_BYTES;
}

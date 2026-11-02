import { t } from '../i18n';

/**
 * 進行中の転送 (アップロード・ダウンロード) の数。
 *
 * ★ 転送の状態はディスクに残さない (docs/design/file-sharing.md §9)。画面を離れると取りかけは捨てられるので、
 *   動いているあいだは離れる前に確認する。画面を閉じる・リロードはブラウザの確認 (beforeunload) に任せる。
 */
let active = 0;

export function beginTransfer(): () => void {
  active++;
  syncUnload();
  let ended = false;
  return () => { if (!ended) { ended = true; active--; syncUnload(); } };
}

export const activeTransfers = () => active;

export function confirmLeave(): boolean {
  if (active === 0) return true;
  return window.confirm(t('transfer.confirmLeave'));
}

const onBeforeUnload = (e: BeforeUnloadEvent) => { e.preventDefault(); e.returnValue = ''; };
let installed = false;
function syncUnload() {
  if (typeof window === 'undefined') return;
  if (active > 0 && !installed) { window.addEventListener('beforeunload', onBeforeUnload); installed = true; }
  if (active === 0 && installed) { window.removeEventListener('beforeunload', onBeforeUnload); installed = false; }
}

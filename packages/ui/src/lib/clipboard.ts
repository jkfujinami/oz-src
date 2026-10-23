/**
 * 秘密 (板の共有コード = 板の鍵) をクリップボードに書き、しばらくしたら消す。
 *
 * ★ クリップボードに残ると、押収された端末や、OS・他のアプリが同期するクリップボード履歴から板を読まれる。
 *   30 秒後に、まだそのコードが入っていれば空にする (ベストエフォート)。
 * ★ タイマーは画面 (コンポーネント) ではなくこのモジュールに持つ。画面ごとに持つと、コピーしてすぐ別の画面へ
 *   移ったときにタイマーが外れ、鍵がクリップボードに残り続けた。
 * ★ 読み取り (readText) はウィンドウにフォーカスが無いと失敗する。フォーカスが無ければ、次に戻ったときに確かめる。
 */
export const SECRET_CLIPBOARD_MS = 30_000;

let timer: ReturnType<typeof setTimeout> | null = null;
let pendingSecret: string | null = null;
let focusListener: (() => void) | null = null;

async function clearIfStillThere(): Promise<void> {
  const secret = pendingSecret;
  if (secret === null) return;
  if (typeof document !== 'undefined' && typeof document.hasFocus === 'function' && !document.hasFocus()) {
    if (!focusListener && typeof window !== 'undefined') {
      focusListener = () => {
        window.removeEventListener('focus', focusListener!);
        focusListener = null;
        void clearIfStillThere();
      };
      window.addEventListener('focus', focusListener);
    }
    return;
  }
  pendingSecret = null;
  try {
    if ((await navigator.clipboard.readText()) === secret) await navigator.clipboard.writeText('');
  } catch {
    // 権限が無い環境では諦める
  }
}

/** text をクリップボードに書く。clearAfterMs 後に、まだ同じ内容なら消す */
export async function copySecret(text: string, clearAfterMs: number = SECRET_CLIPBOARD_MS): Promise<void> {
  await navigator.clipboard.writeText(text);
  pendingSecret = text;
  if (timer) clearTimeout(timer);
  timer = setTimeout(() => {
    timer = null;
    void clearIfStillThere();
  }, clearAfterMs);
}

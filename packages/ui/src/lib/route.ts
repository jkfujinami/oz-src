import { useSyncExternalStore } from 'react';
import { DEFAULT_BOARD_ID, isBoardId } from './boardKeys';

/**
 * 画面の経路 (どの板・どのスレッドを開いているか)。
 *
 * ★ なぜ URL に置かないのか
 *
 *   旧実装は経路を `location.hash` (`#board=..&thread=..`) に置いていた。
 *   ハッシュの変更はブラウザの履歴に 1 件ずつ積まれ、セッション復元・アドレスバーの
 *   補完・同期されたプロファイルに残る。押収された端末では、パスワードを入れなくても
 *   「どの板・どのスレッドを、いつ読んだか」が履歴から読める (スレッド ID には生まれた日も入っている)。
 *
 *   そこで経路はメモリ (このモジュールの変数) だけに持ち、URL には一切出さない。
 *   このモジュールが触る履歴 API は `history.replaceState` だけで、`pushState` も
 *   `location.hash` への代入も使わない (履歴の項目を増やさない)。
 *   戻るボタンで板に戻る動きは失われるが、画面内の「← 板に戻る」を使う。
 */
export interface Route {
  board: string;
  thread?: string;
}

interface RouteState {
  route: Route;
  /** 鍵つきの共有リンクで開かれ、鍵を捨てた (画面でコードの貼り付けを案内する) */
  droppedKeyLink: boolean;
}

const DEFAULT_ROUTE: Route = { board: DEFAULT_BOARD_ID };

let state: RouteState = { route: DEFAULT_ROUTE, droppedKeyLink: false };
const listeners = new Set<() => void>();

function set(next: RouteState): void {
  state = next;
  for (const fn of Array.from(listeners)) fn();
}

/** アドレスバーを素のパスに戻す。履歴の項目は増やさない (置き換えるだけ) */
export function scrubLocation(): void {
  if (typeof window === 'undefined') return;
  try {
    window.history.replaceState(null, '', window.location.pathname);
  } catch {
    // 履歴 API が使えない環境 (サンドボックス化された iframe など) は無視
  }
}

export function getRoute(): Route {
  return state.route;
}

export function subscribeRoute(fn: () => void): () => void {
  listeners.add(fn);
  return () => { listeners.delete(fn); };
}

/**
 * 板・スレッドを開く。URL は変えない。
 * 板 ID の形式が正しくなければ既定の板に戻す。
 */
export function navigate(to: Route): void {
  const board = isBoardId(to.board) ? to.board : DEFAULT_BOARD_ID;
  const thread = typeof to.thread === 'string' && to.thread.length > 0 ? to.thread : undefined;
  set({ ...state, route: thread ? { board, thread } : { board } });
  scrubLocation();
}

/** 既定の経路に戻し、URL も素のパスにする (ロック・消去のとき) */
export function resetRoute(): void {
  set({ route: DEFAULT_ROUTE, droppedKeyLink: false });
  scrubLocation();
}

export function dismissKeyLinkNotice(): void {
  if (state.droppedKeyLink) set({ ...state, droppedKeyLink: false });
}

/**
 * 起動時・URL が外から書き換えられたときに、ハッシュを取り除く。
 *
 * ★ 板の鍵つきのリンク (`#board=..&key=..`) は受け付けない。ハッシュは開いた時点で
 *   既に履歴に入っているので、取り込んで消す手順では間に合わない。鍵は共有コードを
 *   アプリ内の入力欄に貼り付けてもらう (履歴に載らない)。ここでは鍵を読まずに捨てる。
 *
 * @param adopt true なら、鍵の無い `#board=..&thread=..` を経路として採用する
 *   (まだ `location.hash` を書き換える画面部品が残っている間の互換。履歴の項目は
 *   その代入で既に 1 件できるが、置き換えて以後の項目が URL を持たないようにする)
 */
export function absorbLocationHash(adopt: boolean): void {
  if (typeof window === 'undefined') return;
  const hash = window.location.hash;
  if (!hash || hash === '#') return;
  const params = new URLSearchParams(hash.replace(/^#/, ''));
  const hadKey = params.has('key');
  const board = params.get('board');
  const thread = params.get('thread') ?? undefined;
  scrubLocation();
  if (hadKey) set({ ...state, droppedKeyLink: true });
  if (adopt && board && !hadKey) navigate({ board, thread });
  else if (adopt && hadKey && board) navigate({ board });
}

/** 現在の経路を購読する。 */
export function useRoute(): RouteState {
  return useSyncExternalStore(subscribeRoute, () => state, () => state);
}

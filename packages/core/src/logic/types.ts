/**
 * Oz Web-Lite: Shared logic types and constants.
 */

export const BOARD_META_THREAD_ID = '__board_meta__';

export interface ThreadMeta {
  thread_id: string;
  packet_id: string;
  content: string;
  created_at: number;
  max_pow: number;
  /** この端末が知っている最後の投稿の時刻 (スレを開いたときに更新される。知らなければ無い) */
  last_post_at?: number;
  [key: string]: any;
}

/** 状態の値 (画面は code と params から、その言語の文を作る) */
export type StatusParams = Record<string, number | string>;

/** 状態の文 (種類 + 数 + 日本語の既定文)。message は code を知らない画面のための既定文 */
export interface StatusText {
  /** 機械が読む種類 (例: 'history-fetching')。画面はこれで文を選ぶ */
  code: string;
  /** code に付く数や文字列 (文に差し込む) */
  params?: StatusParams;
  /** 日本語の既定文 (code を知らない画面だけが使う) */
  message: string;
}

/** 文の無い状態 (空) */
export const NO_STATUS: StatusText = { code: 'none', message: '' };

export interface BoardStatus {
  phase: 'idle' | 'loading' | 'syncing' | 'submitting' | 'error';
  /** 状態の種類。画面はこれから文を作る (message は日本語の既定文) */
  code: string;
  /** code に付く数や文字列 */
  params?: StatusParams;
  message: string;
  isSubmitting?: boolean;
  powProgress?: number;
}

export interface ThreadStatus extends BoardStatus {}



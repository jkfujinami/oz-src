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
  [key: string]: any;
}

export interface BoardStatus {
  phase: 'idle' | 'loading' | 'syncing' | 'submitting' | 'error';
  message: string;
  isSubmitting?: boolean;
  powProgress?: number;
}

export interface ThreadStatus extends BoardStatus {}



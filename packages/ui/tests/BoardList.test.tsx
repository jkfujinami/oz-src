// @vitest-environment jsdom
import React from 'react';
import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react';
import type { ThreadMeta } from '@oz/core';

const NOW = Date.now();
const t = (id: string, o: Partial<ThreadMeta> = {}): ThreadMeta =>
  ({ thread_id: id.padEnd(10, '0'), packet_id: 'p' + id, content: `title ${id}`, created_at: NOW - 3_600_000, max_pow: 0, ...o });

const state = {
  threads: [] as ThreadMeta[], status: '', phase: 'idle' as string,
  submitThread: vi.fn().mockResolvedValue(undefined), powProgress: 0, isSubmitting: false, shareCode: null,
};
vi.mock('../src/hooks/useBoard', () => ({ useBoard: () => state }));
vi.mock('../src/lib/readThreads', () => ({ loadReadThreads: async () => new Set(['read000000']) }));

import BoardView from '../src/components/BoardView';
import { P2PContextForTest } from '../src/providers/P2PProvider';
import { sortThreads } from '../src/lib/threadOrder';
import { relativeTime } from '../src/lib/relativeTime';

const TRUSTED = { mode: 'trusted', listVersion: 1, listExpiresAt: null, guardId: null };
const wrap = () => render(<P2PContextForTest.Provider value={{ guardStatus: TRUSTED, db: null } as any}><BoardView boardId="zatsudan" /></P2PContextForTest.Provider>);

beforeEach(() => {
  Object.assign(state, { threads: [], status: '', phase: 'idle', powProgress: 0, isSubmitting: false });
  state.submitThread.mockClear();
});
afterEach(() => cleanup());

describe('板の一覧', () => {
  it('並び順: 勢いはスコア順、新着は最後の投稿 (無ければスレ立て) の新しい順', () => {
    const hot = t('hot', { max_pow: 50, created_at: NOW - 3 * 3_600_000 });
    const fresh = t('fresh', { created_at: NOW - 60_000 });
    const replied = t('replied', { created_at: NOW - 10 * 3_600_000, last_post_at: NOW - 1000 });
    expect(sortThreads([fresh, replied, hot], 'new').map(x => x.content)).toEqual(['title replied', 'title fresh', 'title hot']);
    // 作成時刻が同じなら PoW の大きい方が上
    const cold = t('cold', { created_at: hot.created_at });
    expect(sortThreads([cold, hot], 'heat').map(x => x.content)).toEqual(['title hot', 'title cold']);
  });

  it('相対時刻', () => {
    expect(relativeTime(NOW - 3 * 60_000, NOW)).toBe('3 分前');
    expect(relativeTime(NOW - 20_000, NOW)).toBe('今');
  });

  it('★開いたことのないスレは is-unread。列は 題名 / 最終更新 / 勢い', async () => {
    state.threads = [t('read'), t('new')];
    wrap();
    await waitFor(() => expect(document.querySelectorAll('.thread-row.is-unread')).toHaveLength(1));
    expect(document.querySelector('.thread-row.is-unread .thread-title')?.textContent).toBe('title new');
    expect(document.querySelector('.thread-row .thread-col-time')?.textContent).toBe('1 時間前');
  });

  it('★取得中の文は一覧の上の 1 行に出し、届いたスレは並べたまま。取り終わって空なら 1 回だけ言い、その場で立てられる', () => {
    state.threads = [t('a')];
    state.status = '過去ログを取得中... (6/13・1件)';
    state.phase = 'syncing';
    const { unmount } = wrap();
    expect(screen.getByRole('status').textContent).toBe('過去ログを取得中... (6/13・1件)');
    expect(document.querySelectorAll('.thread-row')).toHaveLength(1);
    unmount();

    // 取得中で空: 「無い」とは言わない
    Object.assign(state, { threads: [], status: '過去ログを取得中...', phase: 'syncing' });
    const second = wrap();
    expect(document.querySelector('.empty')).toBeNull();
    second.unmount();

    Object.assign(state, { status: 'スレッドが見つかりませんでした。一番乗りで立ててみませんか？', phase: 'idle' });
    wrap();
    expect(document.querySelector('.empty')?.textContent).toContain('見つかりませんでした');
    // 取得の 1 行は空のまま残る (高さが変わらない)
    expect(screen.getByRole('status').textContent).toBe('');
    fireEvent.click(screen.getAllByText('新スレを立てる')[1]);
    expect(screen.getByPlaceholderText('スレッドタイトル...')).toBeTruthy();
  });

  it('★作成欄: Ctrl+Enter で作成、Esc で閉じる。作成中は PoW の進みをボタンの中に出す', async () => {
    wrap();
    fireEvent.click(screen.getAllByText('新スレを立てる')[0]);
    const box = screen.getByPlaceholderText('スレッドタイトル...');
    fireEvent.change(box, { target: { value: 'スレ' } });
    fireEvent.keyDown(box, { key: 'Enter', ctrlKey: true });
    await waitFor(() => expect(state.submitThread).toHaveBeenCalledWith('スレ'));
    fireEvent.keyDown(box, { key: 'Escape' });
    expect(screen.queryByPlaceholderText('スレッドタイトル...')).toBeNull();
    cleanup();

    Object.assign(state, { isSubmitting: true, powProgress: 42 });
    wrap();
    fireEvent.click(screen.getAllByText('新スレを立てる')[0]);
    const btn = screen.getByText('PoW計算中... 42%') as HTMLButtonElement;
    expect(btn.disabled).toBe(true);
    expect(btn.style.backgroundImage).toContain('42%');
  });
});

// @vitest-environment jsdom
import React from 'react';
import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { render, screen, cleanup, fireEvent } from '@testing-library/react';
import { ThreadClosedError, THREAD_LIMITS } from '@oz/core';

const base = {
  visibleCount: 3, hiddenCount: 0, contentBytes: 100, closed: false, birthAt: 1, lastPostAt: 2, expiresAt: 3, expired: false,
} as any;
const mock = {
  posts: [] as any[],
  threadState: base,
  submitReply: vi.fn().mockResolvedValue(undefined),
  resolveAnchor: vi.fn(),
};

vi.mock('../src/hooks/useThread', () => ({
  useThread: () => ({
    posts: mock.posts, status: '', submitReply: mock.submitReply, powProgress: 0, isSubmitting: false, postStatus: '',
    threadState: mock.threadState, resolveAnchor: mock.resolveAnchor,
  }),
}));

import ThreadView from '../src/components/ThreadView';
import { P2PContextForTest } from '../src/providers/P2PProvider';

const post = (id: string, content: string) => ({
  packet_id: id, content, post_number: 0, created_at: 1_700_000_000_000, board_id: 'b', thread_id: 't', parents: [], cumulative_pow: 0, thread_root: 't',
});

const renderView = () => render(
  <P2PContextForTest.Provider value={{ guardStatus: { mode: 'trusted', listVersion: 1, listExpiresAt: null, guardId: null } } as any}>
    <ThreadView boardId="b" threadId="t0000001" />
  </P2PContextForTest.Provider>,
);
const setState = (patch: object) => { mock.threadState = { ...base, ...patch }; };

beforeEach(() => {
  mock.posts = [];
  mock.threadState = { ...base };
  mock.submitReply.mockReset().mockResolvedValue(undefined);
  mock.resolveAnchor.mockReset();
});
afterEach(() => cleanup());

describe('ThreadView: 上限と寿命', () => {
  it('通常は書き込み欄が出て、お知らせは出ない', () => {
    renderView();
    expect(screen.getByPlaceholderText(/レスを入力/)).toBeTruthy();
    expect(screen.queryByText(/これ以上書き込めません/)).toBeNull();
    expect(screen.queryByText(/レスで埋まります/)).toBeNull();
  });

  it('1000 レスで埋まったら、お知らせを出して書き込み欄を隠す', () => {
    setState({ visibleCount: 1000, closed: true, closeReason: 'posts' });
    renderView();
    expect(screen.getByText('このスレッドは 1000 レスに達したので、これ以上書き込めません。新しいスレッドを立ててください。')).toBeTruthy();
    expect(screen.queryByPlaceholderText(/レスを入力/)).toBeNull();
    expect(screen.queryByText('書き込む')).toBeNull();
  });

  it('容量で埋まったときは容量の文言', () => {
    setState({ closed: true, closeReason: 'bytes' });
    renderView();
    expect(screen.getByText(/容量の上限 \(512KB\) に達したので/)).toBeTruthy();
  });

  it('落ちたスレは、落ちた旨を出す', () => {
    setState({ expired: true });
    renderView();
    expect(screen.getByText(/このスレッドは落ちました。最後の書き込みから 30 日、またはスレッドを立ててから 90 日が過ぎると落ちます。/)).toBeTruthy();
    expect(screen.queryByPlaceholderText(/レスを入力/)).toBeNull();
  });

  it('表示していない書き込みがあれば件数を小さく知らせる', () => {
    setState({ hiddenCount: 4 });
    renderView();
    expect(screen.getByText('スレッドが埋まった後や落ちた後の書き込み 4 件は表示していません。')).toBeTruthy();
  });

  it('900 レスを過ぎたら残りレス数、容量 90% を過ぎたら残り容量を出す', () => {
    setState({ visibleCount: 950, contentBytes: THREAD_LIMITS.MAX_CONTENT_BYTES * 0.95 });
    renderView();
    expect(screen.getByText('あと 50 レスで埋まります')).toBeTruthy();
    expect(screen.getByText(/スレッドの残り容量: 約 25 KB/)).toBeTruthy();
  });

  it('入力が残り容量を超えるときは、ボタンを無効にして理由を出す', () => {
    setState({ contentBytes: THREAD_LIMITS.MAX_CONTENT_BYTES - 10 });
    renderView();
    fireEvent.change(screen.getByPlaceholderText(/レスを入力/), { target: { value: 'a'.repeat(11) } });
    expect((screen.getByText('書き込む') as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText('スレッドの残り容量を超えています')).toBeTruthy();
    fireEvent.change(screen.getByPlaceholderText(/レスを入力/), { target: { value: 'a'.repeat(10) } });
    expect((screen.getByText('書き込む') as HTMLButtonElement).disabled).toBe(false);
  });

  it('送信が ThreadClosedError で断られたら、理由を出して入力を残す', async () => {
    mock.submitReply.mockRejectedValue(new ThreadClosedError('closed'));
    renderView();
    const box = screen.getByPlaceholderText(/レスを入力/) as HTMLTextAreaElement;
    fireEvent.change(box, { target: { value: '本文' } });
    fireEvent.click(screen.getByText('書き込む'));
    expect(await screen.findByRole('alert')).toBeTruthy();
    expect(screen.getByRole('alert').textContent).toContain('上限に達した');
    expect(box.value).toBe('本文');
  });
});

describe('ThreadView: >>N アンカー', () => {
  it('クリックで該当レスへスクロールして強調する。解決できなければ何もしない', () => {
    const scroll = vi.fn();
    (Element.prototype as any).scrollIntoView = scroll;
    mock.posts = [post('aa', '最初'), post('bb', '二つ目'), post('cc', '>>1 を見て <script>')];
    mock.resolveAnchor.mockImplementation((_from: string, n: number) => (n === 1 ? 'aa' : null));
    const { container } = renderView();

    const anchor = container.querySelector('[data-anchor="1"]') as HTMLElement;
    expect(anchor).toBeTruthy();
    expect(container.innerHTML).not.toContain('<script>');
    fireEvent.click(anchor);
    expect(mock.resolveAnchor).toHaveBeenCalledWith('cc', 1);
    expect(scroll).toHaveBeenCalledTimes(1);
    expect(scroll.mock.contexts[0]).toBe(document.getElementById('post-aa'));
    expect((document.getElementById('post-aa') as HTMLElement).style.outline).not.toBe('');

    scroll.mockClear();
    mock.posts = [post('aa', '最初'), post('cc', '>>9')];
    cleanup();
    const second = renderView();
    fireEvent.click(second.container.querySelector('[data-anchor="9"]') as HTMLElement);
    expect(scroll).not.toHaveBeenCalled();
  });

  it('アンカー以外の場所のクリックは何もしない', () => {
    mock.posts = [post('aa', '本文')];
    const { container } = renderView();
    fireEvent.click(container.querySelector('.post-body') as HTMLElement);
    expect(mock.resolveAnchor).not.toHaveBeenCalled();
  });
});

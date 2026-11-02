// @vitest-environment jsdom
import React from 'react';
import { describe, it, expect, afterEach, vi } from 'vitest';
import { render, screen, cleanup, fireEvent, act } from '@testing-library/react';

const post = (n: number, content = `レス ${n}`) =>
  ({ packet_id: `p${n}`.padEnd(16, '0'), content, created_at: 1_700_000_000_000 + n * 60_000, trip_pubkey: null, author_pubkey: new Uint8Array(32).fill(n) });

const state: any = {
  posts: [post(1), post(2, '>>1 に返事')], status: '', submitReply: vi.fn(), powProgress: 0, isSubmitting: false, postStatus: '',
  threadState: null, resolveAnchor: (_from: string, n: number) => (n === 1 ? post(1).packet_id : null),
};
vi.mock('../src/hooks/useThread', () => ({ useThread: () => state }));
vi.mock('@oz/core', async (orig) => ({ ...(await orig<any>()), posterId: () => 'abcd' }));

import ThreadView from '../src/components/ThreadView';
import { P2PContextForTest } from '../src/providers/P2PProvider';

const TRUSTED = { mode: 'trusted', listVersion: 1, listExpiresAt: null, guardId: null };
const view = () => <P2PContextForTest.Provider value={{ guardStatus: TRUSTED } as any}><ThreadView boardId="zatsudan" threadId="0g0abcdefg" /></P2PContextForTest.Provider>;

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe('スレッド: 新着と >>n の小窓', () => {
  it('★一覧の最後が見えていない間に届いたレスは「新着 N 件」に数え、押すとそこへ移って消える。見えている間は数えない', () => {
    let report: (v: boolean) => void = () => {};
    vi.stubGlobal('IntersectionObserver', class {
      constructor(cb: (e: Array<{ isIntersecting: boolean }>) => void) { report = (v) => cb([{ isIntersecting: v }]); }
      observe() {}
      disconnect() {}
    });
    const scrolled = vi.fn();
    (Element.prototype as any).scrollIntoView = scrolled;
    const { rerender } = render(view());
    expect(screen.queryByText(/新着/)).toBeNull();

    act(() => report(false)); // 上の方を読んでいる
    state.posts = [...state.posts, post(3), post(4)];
    rerender(view());
    fireEvent.click(screen.getByText('新着 2 件'));
    expect(scrolled).toHaveBeenCalledTimes(1);
    expect(screen.queryByText(/新着/)).toBeNull();

    act(() => report(true)); // 最後まで見ている: 届いても数えない
    state.posts = [...state.posts, post(5)];
    rerender(view());
    expect(screen.queryByText(/新着/)).toBeNull();
  });

  it('★取得の文は題名の下の 1 行に出す。文が無くなっても行は残り、レスの上に箱を出さない (位置が動かない)', () => {
    state.posts = [post(1)];
    state.status = '過去ログを取得中... (2/13・1件)';
    const { rerender } = render(view());
    const line = screen.getByRole('status');
    expect(line.textContent).toBe('過去ログを取得中... (2/13・1件)');
    expect(document.querySelector('#posts-container .empty')).toBeNull();
    state.status = '';
    rerender(view());
    expect(screen.getByRole('status')).toBe(line);
    expect(line.textContent).toBe('');
  });

  it('★レス番を押すと、書き込み欄の末尾にアンカー (>>番号) と改行が入り、書き込み欄に移る', async () => {
    state.posts = [post(1), post(2), post(3)];
    state.status = '';
    render(view());
    const box = document.querySelector('#reply-input') as HTMLTextAreaElement;
    fireEvent.click(screen.getByRole('button', { name: '#2' }));
    expect(box.value).toBe('>>2\n');
    fireEvent.click(screen.getByRole('button', { name: '#3' }));
    expect(box.value).toBe('>>2\n>>3\n');
    // 書きかけの本文の後ろには、改行をはさんで足す
    fireEvent.change(box, { target: { value: '本文' } });
    fireEvent.click(screen.getByRole('button', { name: '#1' }));
    expect(box.value).toBe('本文\n>>1\n');
    await act(async () => { await new Promise(r => requestAnimationFrame(() => r(null))); });
    expect(document.activeElement).toBe(box);
    expect(box.selectionStart).toBe(box.value.length);
  });

  it('★>>n に乗せると、指しているレスを小窓で見せ、離れると消える', () => {
    state.posts = [post(1), post(2, '>>1 に返事')];
    render(view());
    const anchor = document.querySelector('[data-anchor="1"]') as HTMLElement;
    fireEvent.mouseOver(anchor);
    const tip = screen.getByRole('tooltip');
    expect(tip.textContent).toContain('#1');
    expect(tip.textContent).toContain('レス 1');
    // 小窓を出しても本文の DOM は作り直さない (乗せている要素がそのまま残る)
    expect(anchor.isConnected).toBe(true);
    fireEvent.mouseOut(anchor);
    expect(screen.queryByRole('tooltip')).toBeNull();
    // 書き込み欄に打っても作り直さない
    fireEvent.change(document.querySelector('#reply-input')!, { target: { value: 'x' } });
    expect(anchor.isConnected).toBe(true);
  });
});

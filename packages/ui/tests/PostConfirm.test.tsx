// @vitest-environment jsdom
import React from 'react';
import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react';

const board = { submitThread: vi.fn().mockResolvedValue(undefined) };
const thread = { submitReply: vi.fn().mockResolvedValue(undefined) };

vi.mock('../src/hooks/useBoard', () => ({
  useBoard: () => ({
    threads: [], status: '', submitThread: board.submitThread, powProgress: 0, isSubmitting: false, shareCode: null,
  }),
}));
vi.mock('../src/hooks/useThread', () => ({
  useThread: () => ({
    posts: [], status: '', submitReply: thread.submitReply, powProgress: 0, isSubmitting: false, postStatus: '',
  }),
}));

import BoardView from '../src/components/BoardView';
import ThreadView from '../src/components/ThreadView';
import { P2PContextForTest } from '../src/providers/P2PProvider';
import { needsWeakRouteConfirmation } from '../src/lib/guardStatus';

const base = { listVersion: 1, listExpiresAt: null, guardId: null };
const STATUS = {
  trusted: { ...base, mode: 'trusted' },
  fallback: { ...base, mode: 'fallback', reason: 'no-trusted-guard-connected' },
  open: { ...base, mode: 'open', reason: 'no-list' },
  waiting: { ...base, mode: 'none', reason: 'waiting-for-trusted-guard' },
  starting: { ...base, mode: 'none' },
  expired: { ...base, mode: 'none', reason: 'list-expired' },
} as const;

const wrap = (status: any, ui: React.ReactNode) =>
  render(<P2PContextForTest.Provider value={{ guardStatus: status } as any}>{ui}</P2PContextForTest.Provider>);

beforeEach(() => { board.submitThread.mockClear(); thread.submitReply.mockClear(); });
afterEach(() => cleanup());

describe('needsWeakRouteConfirmation', () => {
  it('fallback / open / リスト期限切れは確認が要り、信頼 Guard と準備中は要らない', () => {
    expect(needsWeakRouteConfirmation(STATUS.fallback as any)).toBe(true);
    expect(needsWeakRouteConfirmation(STATUS.open as any)).toBe(true);
    expect(needsWeakRouteConfirmation(STATUS.expired as any)).toBe(true);
    expect(needsWeakRouteConfirmation(STATUS.trusted as any)).toBe(false);
    expect(needsWeakRouteConfirmation(STATUS.waiting as any)).toBe(false);
    expect(needsWeakRouteConfirmation(STATUS.starting as any)).toBe(false);
  });
});

function openThreadForm() {
  fireEvent.click(screen.getByText('新スレを立てる'));
  fireEvent.change(screen.getByPlaceholderText('スレッドタイトル...'), { target: { value: 'タイトル' } });
}

describe('新スレ作成の確認', () => {
  for (const key of ['fallback', 'open'] as const) {
    it(`${key}: 作成を押すと確認が出て、送信はまだされない。「やめる」で送られない`, () => {
      wrap(STATUS[key], <BoardView boardId="b" />);
      openThreadForm();
      fireEvent.click(screen.getByText('作成'));
      expect(screen.getByRole('alertdialog')).toBeTruthy();
      expect(screen.getByText(/審査されていない普通の相手/)).toBeTruthy();
      expect(board.submitThread).not.toHaveBeenCalled();
      fireEvent.click(screen.getByText('やめる'));
      expect(screen.queryByRole('alertdialog')).toBeNull();
      expect(board.submitThread).not.toHaveBeenCalled();
    });
  }

  it('fallback: 「それでも投稿する」で初めて送信される', () => {
    wrap(STATUS.fallback, <BoardView boardId="b" />);
    openThreadForm();
    fireEvent.click(screen.getByText('作成'));
    fireEvent.click(screen.getByText('それでも投稿する'));
    expect(board.submitThread).toHaveBeenCalledWith('タイトル');
  });

  for (const key of ['trusted', 'waiting', 'starting'] as const) {
    it(`${key}: 確認なしで送信される (準備中は自動で待つ)`, () => {
      wrap(STATUS[key], <BoardView boardId="b" />);
      openThreadForm();
      fireEvent.click(screen.getByText('作成'));
      expect(screen.queryByRole('alertdialog')).toBeNull();
      expect(board.submitThread).toHaveBeenCalledWith('タイトル');
    });
  }
});

describe('返信の確認', () => {
  const typeReply = () => fireEvent.change(screen.getByPlaceholderText(/レスを入力/), { target: { value: 'こんにちは' } });

  it('fallback: 書き込むを押すと確認が出る。やめれば送られず、入力も残る', async () => {
    wrap(STATUS.fallback, <ThreadView boardId="b" threadId="t0000000" />);
    typeReply();
    fireEvent.click(screen.getByText('書き込む'));
    expect(screen.getByRole('alertdialog')).toBeTruthy();
    expect(thread.submitReply).not.toHaveBeenCalled();
    fireEvent.click(screen.getByText('やめる'));
    expect(thread.submitReply).not.toHaveBeenCalled();
    expect((screen.getByPlaceholderText(/レスを入力/) as HTMLTextAreaElement).value).toBe('こんにちは');
  });

  it('open: Ctrl+Enter でも確認が出て、それでも投稿するで送信される', async () => {
    wrap(STATUS.open, <ThreadView boardId="b" threadId="t0000000" />);
    typeReply();
    fireEvent.keyDown(screen.getByPlaceholderText(/レスを入力/), { key: 'Enter', ctrlKey: true });
    expect(screen.getByRole('alertdialog')).toBeTruthy();
    expect(thread.submitReply).not.toHaveBeenCalled();
    fireEvent.click(screen.getByText('それでも投稿する'));
    await waitFor(() => expect(thread.submitReply).toHaveBeenCalledWith('こんにちは'));
  });

  for (const key of ['trusted', 'waiting'] as const) {
    it(`${key}: 確認なしで送信される`, async () => {
      wrap(STATUS[key], <ThreadView boardId="b" threadId="t0000000" />);
      typeReply();
      fireEvent.click(screen.getByText('書き込む'));
      expect(screen.queryByRole('alertdialog')).toBeNull();
      await waitFor(() => expect(thread.submitReply).toHaveBeenCalledWith('こんにちは'));
    });
  }
});

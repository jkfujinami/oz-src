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
import { byteBudget } from '../src/lib/postLimit';

const base = { listVersion: 1, listExpiresAt: null, guardId: null };
const TRUSTED = { ...base, mode: 'trusted' } as any;
const FALLBACK = { ...base, mode: 'fallback', reason: 'no-trusted-guard-connected' } as any;

const wrap = (status: any, ui: React.ReactNode) =>
  render(<P2PContextForTest.Provider value={{ guardStatus: status } as any}>{ui}</P2PContextForTest.Provider>);

const LIMIT = 2048;
// 日本語 1 文字は 3 バイト。682 文字 = 2046 バイト
const JA = (n: number) => 'あ'.repeat(n);

beforeEach(() => { board.submitThread.mockClear(); thread.submitReply.mockClear(); });
afterEach(() => cleanup());

const replyBox = () => screen.getByPlaceholderText(/レスを入力/) as HTMLTextAreaElement;
const sendButton = () => screen.getByText('書き込む') as HTMLButtonElement;
const titleBox = () => screen.getByPlaceholderText('スレッドタイトル...') as HTMLTextAreaElement;
const createButton = () => screen.getByText('作成') as HTMLButtonElement;
const openThreadForm = () => fireEvent.click(screen.getByText('新スレを立てる'));

describe('byteBudget', () => {
  it('ASCII は 1 文字 1 バイト、日本語は 1 文字 3 バイトで数える', () => {
    expect(byteBudget('abc').used).toBe(3);
    expect(byteBudget('あいう').used).toBe(9);
    expect(byteBudget('').remaining).toBe(LIMIT);
  });

  it('ちょうど上限は許し、1 バイトでも超えると over になる', () => {
    expect(byteBudget('a'.repeat(LIMIT)).over).toBe(false);
    expect(byteBudget('a'.repeat(LIMIT + 1)).over).toBe(true);
    expect(byteBudget(JA(682) + 'ab').remaining).toBe(0);
    expect(byteBudget(JA(683)).over).toBe(true);
  });
});

describe('残りバイト数の表示', () => {
  it('ASCII の入力で残りを表示する', () => {
    wrap(TRUSTED, <ThreadView boardId="b" threadId="t0000000" />);
    fireEvent.change(replyBox(), { target: { value: 'abc' } });
    expect(screen.getByText('残り 2,045 バイト')).toBeTruthy();
  });

  it('日本語の入力はバイト数で減る (3 文字 = 9 バイト)', () => {
    wrap(TRUSTED, <ThreadView boardId="b" threadId="t0000000" />);
    fireEvent.change(replyBox(), { target: { value: 'あいう' } });
    expect(screen.getByText('残り 2,039 バイト')).toBeTruthy();
  });

  it('スレッドタイトルも同じ数え方で表示する', () => {
    wrap(TRUSTED, <BoardView boardId="b" />);
    openThreadForm();
    fireEvent.change(titleBox(), { target: { value: JA(10) } });
    expect(screen.getByText('残り 2,018 バイト')).toBeTruthy();
  });
});

describe('上限超過', () => {
  it('返信: 上限を超えると書き込むが無効になり、理由を出す', () => {
    wrap(TRUSTED, <ThreadView boardId="b" threadId="t0000000" />);
    fireEvent.change(replyBox(), { target: { value: JA(683) } });
    expect(sendButton().disabled).toBe(true);
    expect(screen.getByText('1 レスは 2048 バイトまでです')).toBeTruthy();
  });

  it('返信: 超えている間は Ctrl+Enter でも送られない', () => {
    wrap(TRUSTED, <ThreadView boardId="b" threadId="t0000000" />);
    fireEvent.change(replyBox(), { target: { value: 'a'.repeat(LIMIT + 1) } });
    fireEvent.keyDown(replyBox(), { key: 'Enter', ctrlKey: true });
    expect(thread.submitReply).not.toHaveBeenCalled();
  });

  it('返信: 上限ちょうど (2048 バイト) は送れる', async () => {
    wrap(TRUSTED, <ThreadView boardId="b" threadId="t0000000" />);
    const exact = JA(682) + 'ab';
    fireEvent.change(replyBox(), { target: { value: exact } });
    expect(sendButton().disabled).toBe(false);
    fireEvent.click(sendButton());
    await waitFor(() => expect(thread.submitReply).toHaveBeenCalledWith(exact));
  });

  it('スレ立て: 上限を超えると作成が無効になり、送信されない', () => {
    wrap(TRUSTED, <BoardView boardId="b" />);
    openThreadForm();
    fireEvent.change(titleBox(), { target: { value: JA(683) } });
    expect(createButton().disabled).toBe(true);
    expect(screen.getByText('スレッドタイトルは 2048 バイトまでです')).toBeTruthy();
    fireEvent.click(createButton());
    expect(board.submitThread).not.toHaveBeenCalled();
  });

  it('スレ立て: ちょうど上限は作成できる', async () => {
    wrap(TRUSTED, <BoardView boardId="b" />);
    openThreadForm();
    const exact = 'a'.repeat(LIMIT);
    fireEvent.change(titleBox(), { target: { value: exact } });
    expect(createButton().disabled).toBe(false);
    fireEvent.click(createButton());
    await waitFor(() => expect(board.submitThread).toHaveBeenCalledWith(exact));
  });

  it('警告状態で確認を開いたあと上限を超えても、それでも投稿で送られない', () => {
    wrap(FALLBACK, <ThreadView boardId="b" threadId="t0000000" />);
    fireEvent.change(replyBox(), { target: { value: 'こんにちは' } });
    fireEvent.click(sendButton());
    expect(screen.getByRole('alertdialog')).toBeTruthy();
    fireEvent.change(replyBox(), { target: { value: JA(683) } });
    fireEvent.click(screen.getByText('それでも投稿する'));
    expect(thread.submitReply).not.toHaveBeenCalled();
  });
});

describe('送信エラー', () => {
  it('返信: 失敗を表示し、入力は残る', async () => {
    thread.submitReply.mockRejectedValueOnce(new Error('boom'));
    wrap(TRUSTED, <ThreadView boardId="b" threadId="t0000000" />);
    fireEvent.change(replyBox(), { target: { value: 'こんにちは' } });
    fireEvent.click(sendButton());
    expect(await screen.findByRole('alert')).toBeTruthy();
    expect(screen.getByText(/送信できませんでした/)).toBeTruthy();
    expect(replyBox().value).toBe('こんにちは');
  });

  it('返信: core の RangeError は上限の理由を出し、入力は残る', async () => {
    thread.submitReply.mockRejectedValueOnce(new RangeError('too long'));
    wrap(TRUSTED, <ThreadView boardId="b" threadId="t0000000" />);
    fireEvent.change(replyBox(), { target: { value: 'こんにちは' } });
    fireEvent.click(sendButton());
    expect(await screen.findByText(/2048 バイトまでです/)).toBeTruthy();
    expect(replyBox().value).toBe('こんにちは');
  });

  it('スレ立て: 失敗を表示し、タイトルは残る', async () => {
    board.submitThread.mockRejectedValueOnce(new Error('boom'));
    wrap(TRUSTED, <BoardView boardId="b" />);
    openThreadForm();
    fireEvent.change(titleBox(), { target: { value: 'タイトル' } });
    fireEvent.click(createButton());
    expect(await screen.findByRole('alert')).toBeTruthy();
    expect(titleBox().value).toBe('タイトル');
  });
});

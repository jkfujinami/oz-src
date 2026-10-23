// @vitest-environment jsdom
import React from 'react';
import fs from 'node:fs';
import path from 'node:path';
import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react';

import { TermsGate } from '../src/components/TermsGate';
import App from '../src/App';
import { TERMS_VERSION, termsMarkdown, loadAcceptedTermsVersion, saveTermsAccepted, clearTermsAccepted } from '../src/lib/terms';

const KEY = 'oz.termsAccepted';

beforeEach(() => localStorage.clear());
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  localStorage.clear();
});

describe('利用規約', () => {
  it('リポジトリの TERMS.md はアプリの文面と同じ (違えば npm run terms で作り直す)', () => {
    const md = fs.readFileSync(path.resolve(__dirname, '../../../TERMS.md'), 'utf8');
    expect(md).toBe(termsMarkdown());
  });

  it('同意するまでは中身を出さない。チェックを入れるまで「同意して始める」は押せない', () => {
    render(<TermsGate><div>中身</div></TermsGate>);
    expect(screen.getByRole('heading', { name: 'OZ 利用規約' })).toBeTruthy();
    expect(screen.getByText(/著作権、著作隣接権、商標権/)).toBeTruthy();
    expect(screen.queryByText('中身')).toBeNull();

    const agree = screen.getByRole('button', { name: '同意して始める' }) as HTMLButtonElement;
    expect(agree.disabled).toBe(true);
    fireEvent.click(screen.getByLabelText('利用規約を読み、内容に同意します'));
    expect(agree.disabled).toBe(false);
    fireEvent.click(agree);

    expect(screen.getByText('中身')).toBeTruthy();
    expect(localStorage.getItem(KEY)).toBe(TERMS_VERSION);
  });

  it('同意しなければ使えないことを伝え、中身は出さない', () => {
    render(<TermsGate><div>中身</div></TermsGate>);
    fireEvent.click(screen.getByRole('button', { name: '同意しない' }));
    expect(screen.getByRole('alert').textContent).toMatch(/ご利用いただけません/);
    expect(screen.queryByText('中身')).toBeNull();
  });

  it('今の版に同意済みなら、そのまま中身を出す', () => {
    saveTermsAccepted();
    render(<TermsGate><div>中身</div></TermsGate>);
    expect(screen.getByText('中身')).toBeTruthy();
    expect(screen.queryByRole('button', { name: '同意して始める' })).toBeNull();
  });

  it('前の版に同意していた人には、更新されたことを伝えてもう一度尋ねる', () => {
    localStorage.setItem(KEY, '2000-01-01');
    render(<TermsGate><div>中身</div></TermsGate>);
    expect(screen.getByText(/利用規約が更新されました/)).toBeTruthy();
    expect(screen.queryByText('中身')).toBeNull();
  });

  it('同意を残せないブラウザでも、この起動中は同意して進める', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new Error('denied'); });
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('denied'); });
    render(<TermsGate><div>中身</div></TermsGate>);
    fireEvent.click(screen.getByLabelText('利用規約を読み、内容に同意します'));
    fireEvent.click(screen.getByRole('button', { name: '同意して始める' }));
    expect(screen.getByText('中身')).toBeTruthy();
    expect(loadAcceptedTermsVersion()).toBeNull();
  });

  it('消去すると同意の記録も消える', () => {
    saveTermsAccepted();
    clearTermsAccepted();
    expect(localStorage.getItem(KEY)).toBeNull();
  });

  it('アプリは利用規約を先に出し、同意してからパスワード画面へ進む', async () => {
    render(<App />);
    expect(screen.getByRole('heading', { name: 'OZ 利用規約' })).toBeTruthy();
    expect(screen.queryByText('パスワードを設定')).toBeNull();
    fireEvent.click(screen.getByLabelText('利用規約を読み、内容に同意します'));
    fireEvent.click(screen.getByRole('button', { name: '同意して始める' }));
    await waitFor(() => expect(screen.getByText('パスワードを設定')).toBeTruthy());
  });
});

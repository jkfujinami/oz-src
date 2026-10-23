// @vitest-environment jsdom
import React from 'react';
import { describe, it, expect, afterEach } from 'vitest';
import { render, screen, cleanup, waitFor, fireEvent } from '@testing-library/react';
import Page from '../src/app/page';

afterEach(() => {
  cleanup();
  localStorage.clear();
});

describe('Web: 起動', () => {
  it('起動直後は利用規約への同意を求め、同意するとパスワード画面だけを出す', async () => {
    render(<Page />);
    await waitFor(() => expect(screen.getByRole('heading', { name: 'OZ 利用規約' })).toBeTruthy());
    expect(screen.queryByLabelText('パスワード')).toBeNull();
    fireEvent.click(screen.getByLabelText('利用規約を読み、内容に同意します'));
    fireEvent.click(screen.getByRole('button', { name: '同意して始める' }));
    await waitFor(() => expect(screen.getByLabelText('パスワード')).toBeTruthy());
    expect(screen.queryByText(/Peers:/)).toBeNull();
  });
});

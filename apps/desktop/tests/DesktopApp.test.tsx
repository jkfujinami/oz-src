// @vitest-environment jsdom
import React from 'react';
import { describe, it, expect, afterEach } from 'vitest';
import { render, screen, cleanup, waitFor, fireEvent } from '@testing-library/react';
import { OzApp } from '@oz/ui';

afterEach(() => {
  cleanup();
  localStorage.clear();
});

describe('Desktop: アプリの起動', () => {
  it('起動直後は利用規約への同意を求め、同意するとパスワード画面だけを出す (ノードは起動しない)', async () => {
    render(<OzApp badge="Desktop Full Node" defaultTrackerUrl={null} />);
    expect(screen.getByRole('heading', { name: 'OZ 利用規約' })).toBeTruthy();
    expect(screen.queryByLabelText('パスワード')).toBeNull();
    fireEvent.click(screen.getByLabelText('利用規約を読み、内容に同意します'));
    fireEvent.click(screen.getByRole('button', { name: '同意して始める' }));
    await waitFor(() => expect(screen.getByLabelText('パスワード')).toBeTruthy());
    expect(screen.queryByText(/Peers:/)).toBeNull();
  });
});
